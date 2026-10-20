package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
)

// The resource kinds an Administrator can move to another service (design §8.1 assign).
const (
	KindTarget          = "target" // a server or a Key Vault
	KindCertificate     = "certificate"
	KindCSR             = "csr"
	KindSSHKey          = "ssh_key"
	KindACMECertificate = "acme_certificate"
	KindDiscoveryScope  = "discovery_scope"
)

// AssignKinds lists the kinds in the order they are locked and moved.
var AssignKinds = []string{KindTarget, KindCertificate, KindCSR, KindSSHKey, KindACMECertificate, KindDiscoveryScope}

// MaxAssign is the most resources one assignment moves.
const MaxAssign = 500

// Resource names one resource to move.
type Resource struct {
	Type string
	ID   uuid.UUID
}

// Move is what an assignment does to one resource: its name and the service it leaves (Changed false: it is in the
// destination already).
type Move struct {
	Type    string
	ID      uuid.UUID
	Name    string
	From    authz.ServiceRef
	Changed bool
}

// UntrustedBinding is a binding location whose source and destination are in different services without a trust
// after the move: its automatic deployments stop there (design §5.6), and a person's deployment is refused.
type UntrustedBinding struct {
	Kind       string // "key_vault" (a Key Vault binding) or "acme" (an ACME certificate's binding)
	SourceID   uuid.UUID
	SourceName string
	LocationID uuid.UUID
	TargetID   uuid.UUID
	TargetName string
	Source     authz.ServiceRef
	Target     authz.ServiceRef
}

// AssignResult is the answer to an assignment or its dry run.
type AssignResult struct {
	DryRun      bool
	Destination authz.ServiceRef
	Moves       []Move
	Untrusted   []UntrustedBinding
}

// errDryRun rolls a dry run's transaction back after its answer was computed.
var errDryRun = errors.New("services: dry run")

// assignTable is where each kind lives: its table, whether rows are soft-deleted, and the name a person knows it by.
var assignTable = map[string]struct {
	table   string
	deleted bool
	name    string
}{
	KindTarget:          {"targets", true, "name::text"},
	KindCertificate:     {"certificates", false, "coalesce(nullif(label, ''), nullif(subject_cn, ''), left(fingerprint_sha256, 16))"},
	KindCSR:             {"csr_requests", false, "common_name"},
	KindSSHKey:          {"ssh_keys", false, "coalesce(nullif(label, ''), fingerprint_sha256)"},
	KindACMECertificate: {"acme_certificates", true, "coalesce(names[1], '')"},
	KindDiscoveryScope:  {"discovery_scopes", true, "name::text"},
}

func checkAssign(resources []Resource) validate.Errors {
	var v validate.Errors
	if n := len(resources); n < 1 || n > MaxAssign {
		v.Add("resources", validate.OutOfRange, map[string]string{"min": "1", "max": strconv.Itoa(MaxAssign)})
		return v
	}
	seen := map[Resource]bool{}
	for i, r := range resources {
		field := "resources." + strconv.Itoa(i)
		switch {
		case !slices.Contains(AssignKinds, r.Type):
			v.Add(field+".type", validate.OneOf, map[string]string{"values": strings.Join(AssignKinds, ", ")})
		case r.ID == uuid.Nil:
			v.Add(field+".id", validate.Required, nil)
		case seen[r]:
			v.Add(field, validate.Duplicate, nil)
		}
		seen[r] = true
	}
	return v
}

// Assign moves resources to the service dest (design §8.1): each row is locked (FOR UPDATE: a write to it waits, and a
// write that ran first is followed by the move), moved, and the binding locations that end up crossing services
// without a trust are listed. One audit row service.assigned names every resource moved. With dryRun nothing is
// changed or audited: the answer says what the move would do. An unknown, deleted or repeated resource is a validation
// error on resources.N; ErrNotFound for dest.
func (s *Store) Assign(ctx context.Context, a Actor, dest uuid.UUID, resources []Resource, dryRun bool) (AssignResult, error) {
	if v := checkAssign(resources); len(v) > 0 {
		return AssignResult{}, v
	}
	var out AssignResult
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out = AssignResult{DryRun: dryRun}
		var one int
		err := tx.QueryRow(ctx, "SELECT 1 FROM services WHERE id = $1 FOR KEY SHARE", dest).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("services: read the destination: %w", err)
		}
		refs, err := readRefs(ctx, tx)
		if err != nil {
			return err
		}
		out.Destination = refs[dest]
		index := map[Resource]int{}
		for i, r := range resources {
			index[r] = i
		}
		moved := map[string][]uuid.UUID{}
		var audited []string
		for _, kind := range AssignKinds {
			var ids []uuid.UUID
			for _, r := range resources {
				if r.Type == kind {
					ids = append(ids, r.ID)
				}
			}
			if len(ids) == 0 {
				continue
			}
			t := assignTable[kind]
			live := ""
			if t.deleted {
				live = " AND deleted_at IS NULL"
			}
			rows, err := tx.Query(ctx, "SELECT id, service_id, "+t.name+" FROM "+t.table+" WHERE id = ANY($1)"+live+" ORDER BY id FOR UPDATE", ids)
			if err != nil {
				return fmt.Errorf("services: lock the %s rows: %w", kind, err)
			}
			found := map[uuid.UUID]Move{}
			for rows.Next() {
				m := Move{Type: kind}
				var from uuid.UUID
				if err := rows.Scan(&m.ID, &from, &m.Name); err != nil {
					rows.Close()
					return fmt.Errorf("services: read a %s row: %w", kind, err)
				}
				m.From, m.Changed = refs[from], from != dest
				found[m.ID] = m
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("services: lock the %s rows: %w", kind, err)
			}
			for _, id := range ids {
				m, ok := found[id]
				if !ok {
					return validate.Errors{{Field: "resources." + strconv.Itoa(index[Resource{Type: kind, ID: id}]) + ".id", Code: validate.Required}}
				}
				out.Moves = append(out.Moves, m)
				if m.Changed {
					moved[kind] = append(moved[kind], id)
					audited = append(audited, kind+":"+id.String())
				}
			}
			if len(moved[kind]) > 0 {
				if _, err := tx.Exec(ctx, "UPDATE "+t.table+" SET service_id = $2 WHERE id = ANY($1)", moved[kind], dest); err != nil {
					return fmt.Errorf("services: move the %s rows: %w", kind, err)
				}
			}
		}
		if out.Untrusted, err = untrustedAfter(ctx, tx, refs, moved); err != nil {
			return err
		}
		if dryRun {
			return errDryRun
		}
		if len(audited) == 0 {
			return nil
		}
		return s.appendAudit(ctx, tx, a, "service.assigned", "service", dest, map[string]string{"resources": strings.Join(audited, ","),
			"moved_count": strconv.Itoa(len(audited)), "untrusted_count": strconv.Itoa(len(out.Untrusted))})
	})
	if errors.Is(err, errDryRun) {
		err = nil
	}
	if err != nil {
		return AssignResult{}, err
	}
	return out, nil
}

// untrustedAfter lists the live binding locations that touch a moved server, Key Vault or ACME certificate and now
// cross services without a trust: a Key Vault binding (the vault's service to the location's server's) and an ACME
// binding (the ACME certificate's service to the server's).
func untrustedAfter(ctx context.Context, tx pgx.Tx, refs map[uuid.UUID]authz.ServiceRef, moved map[string][]uuid.UUID) ([]UntrustedBinding, error) {
	targets, acme := moved[KindTarget], moved[KindACMECertificate]
	if len(targets) == 0 && len(acme) == 0 {
		return []UntrustedBinding{}, nil
	}
	rows, err := tx.Query(ctx, `SELECT 'key_vault', kc.id, kc.name, l.id, t.id, t.name::text, v.service_id, t.service_id
FROM bindings b
JOIN kv_certificates kc ON kc.id = b.kv_certificate_id
JOIN targets v ON v.id = b.kv_target_id
JOIN certificate_locations l ON l.binding_id = b.id
JOIN targets t ON t.id = l.target_id
WHERE b.deleted_at IS NULL AND t.deleted_at IS NULL AND v.service_id <> t.service_id AND (v.id = ANY($1) OR t.id = ANY($1))
  AND NOT EXISTS (SELECT 1 FROM service_trusts st WHERE st.source_service_id = v.service_id AND st.target_service_id = t.service_id)
UNION ALL
SELECT 'acme', ac.id, coalesce(ac.names[1], ''), l.id, t.id, t.name::text, ac.service_id, t.service_id
FROM acme_bindings ab
JOIN acme_certificates ac ON ac.id = ab.acme_certificate_id
JOIN certificate_locations l ON l.id = ab.location_id
JOIN targets t ON t.id = l.target_id
WHERE ac.deleted_at IS NULL AND t.deleted_at IS NULL AND ac.service_id <> t.service_id AND (ac.id = ANY($2) OR t.id = ANY($1))
  AND NOT EXISTS (SELECT 1 FROM service_trusts st WHERE st.source_service_id = ac.service_id AND st.target_service_id = t.service_id)
ORDER BY 1, 3, 6, 4`, targets, acme)
	if err != nil {
		return nil, fmt.Errorf("services: read the bindings across services: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (UntrustedBinding, error) {
		var (
			u        UntrustedBinding
			from, to uuid.UUID
		)
		err := r.Scan(&u.Kind, &u.SourceID, &u.SourceName, &u.LocationID, &u.TargetID, &u.TargetName, &from, &to)
		u.Source, u.Target = refs[from], refs[to]
		return u, err
	})
}
