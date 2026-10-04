package inventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// The websites a binding may be given (the binding dialog's list, carry 6): certificate locations
// of Nginx servers that are live and whose provider deploys, that the last scan found and that Alice
// can deploy to (supported, a path the helper takes). Servers that are not connected right now are
// listed too: readiness is checked by every deployment.

// LocationFilter selects deployable locations. KeyType is "", "rsa" or "ecdsa" (the key type of the
// certificate the location holds; locations of an unknown type match "" only); Unbound hides the
// websites that already belong to a binding; Query is a case-insensitive substring of the server's
// name, the certificate path or a server name of the location (% and _ are literal); Limit is
// 1..200 (0 = 50).
type LocationFilter struct {
	Query, KeyType string
	Unbound        bool
	Cursor         string
	Limit          int
}

// DeployableLocation is one website that can be connected.
type DeployableLocation struct {
	ID, TargetID      uuid.UUID
	TargetName        string
	CertPath, KeyPath string
	KeyType           string
	ServerNames       []string
	BindingID         *uuid.UUID // the live binding the website belongs to
}

// DeployableLocationPage is one page of deployable locations.
type DeployableLocationPage struct {
	Items      []DeployableLocation
	NextCursor string
}

// deployPathSQL is deployPathRE for PostgreSQL (the CHECK of deployments.cert_path and key_path), applied
// to a value in the C collation so that the character ranges are the ASCII ones.
const deployPathSQL = `^/[A-Za-z0-9._/@:+-]+$`

type locationCursor struct {
	name, path string
	id         uuid.UUID
}

func encodeLocationCursor(name, path string, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x00" + path + "\x00" + id.String()))
}

func decodeLocationCursor(c string) (locationCursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || !utf8.Valid(raw) {
		return locationCursor{}, false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		return locationCursor{}, false
	}
	id, err := uuid.Parse(parts[2])
	if err != nil || id.String() != parts[2] {
		return locationCursor{}, false
	}
	return locationCursor{name: parts[0], path: parts[1], id: id}, true
}

// ListDeployableLocations lists websites ordered by server name (ASCII-folded), certificate path
// and id; the cursor is the last row's key.
func (s *Service) ListDeployableLocations(ctx context.Context, f LocationFilter) (DeployableLocationPage, error) {
	var errs validate.Errors
	limit := f.Limit
	switch {
	case limit == 0:
		limit = 50
	case limit < 1 || limit > 200:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
	}
	if f.KeyType != "" && f.KeyType != "rsa" && f.KeyType != "ecdsa" {
		errs.Add("key_type", validate.OneOf, map[string]string{"values": "rsa, ecdsa"})
	}
	pattern := ""
	switch {
	case !utf8.ValidString(f.Query) || strings.ContainsRune(f.Query, 0):
		errs.Add("q", validate.Pattern, nil)
	case utf8.RuneCountInString(f.Query) > maxQueryRunes:
		errs.Add("q", validate.TooLong, map[string]string{"max": fmt.Sprint(maxQueryRunes)})
	default:
		if q := strings.TrimSpace(f.Query); q != "" {
			pattern = likePattern(foldASCII(q))
		}
	}
	var after *locationCursor
	if f.Cursor != "" {
		c, ok := decodeLocationCursor(f.Cursor)
		if !ok {
			errs.Add("cursor", validate.Pattern, nil)
		} else {
			after = &c
		}
	}
	if len(errs) > 0 {
		return DeployableLocationPage{}, errs
	}
	var cName, cPath *string
	cID := uuid.Nil
	if after != nil {
		cName, cPath, cID = &after.name, &after.path, after.id
	}
	rows, err := s.pool.Query(ctx, `SELECT l.id, l.target_id, t.name::text, lower(t.name::text COLLATE "C"), l.cert_path, l.key_path, l.key_type, l.servers, l.binding_id
FROM certificate_locations l
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL AND t.type = 'nginx'
WHERE l.supported AND l.missing_since IS NULL
  AND length(l.cert_path) <= 4096 AND length(l.key_path) <= 4096
  AND l.cert_path COLLATE "C" ~ $1 AND l.key_path COLLATE "C" ~ $1
  AND ($2 = '' OR l.key_type = $2)
  AND (NOT $3 OR l.binding_id IS NULL)
  AND ($4 = '' OR lower(t.name::text COLLATE "C") LIKE $4 ESCAPE '\'
       OR lower(l.cert_path COLLATE "C") LIKE $4 ESCAPE '\'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(l.servers) s, jsonb_array_elements_text(s->'names') n
                  WHERE lower(n COLLATE "C") LIKE $4 ESCAPE '\'))
  AND ($5::text IS NULL OR (lower(t.name::text COLLATE "C"), l.cert_path COLLATE "C", l.id) > ($5::text COLLATE "C", $6::text COLLATE "C", $7::uuid))
ORDER BY lower(t.name::text COLLATE "C"), l.cert_path COLLATE "C", l.id
LIMIT $8`, deployPathSQL, f.KeyType, f.Unbound, pattern, cName, cPath, cID, limit+1)
	if err != nil {
		return DeployableLocationPage{}, fmt.Errorf("inventory: list deployable locations: %w", err)
	}
	defer rows.Close()
	page := DeployableLocationPage{Items: []DeployableLocation{}}
	var folded []string
	for rows.Next() {
		var (
			l       DeployableLocation
			fold    string
			servers []byte
		)
		if err := rows.Scan(&l.ID, &l.TargetID, &l.TargetName, &fold, &l.CertPath, &l.KeyPath, &l.KeyType, &servers, &l.BindingID); err != nil {
			return DeployableLocationPage{}, fmt.Errorf("inventory: read a deployable location: %w", err)
		}
		var certServers []providers.CertServer
		if err := json.Unmarshal(servers, &certServers); err != nil {
			return DeployableLocationPage{}, fmt.Errorf("inventory: decode location servers: %w", err)
		}
		l.ServerNames = serverNames(certServers)
		page.Items = append(page.Items, l)
		folded = append(folded, fold)
	}
	if err := rows.Err(); err != nil {
		return DeployableLocationPage{}, fmt.Errorf("inventory: list deployable locations: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeLocationCursor(folded[limit-1], last.CertPath, last.ID)
	}
	return page, nil
}

// serverNames is the distinct server names of a location's server blocks, in order of appearance.
func serverNames(servers []providers.CertServer) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range servers {
		for _, n := range s.Names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}
