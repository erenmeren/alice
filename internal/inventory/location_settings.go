package inventory

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

// LocationPatch is the input of UpdateLocation: a location's verification settings (R38 item 6).
// nil fields stay unchanged.
type LocationPatch struct {
	VerifyPort *int    // 1..65535; 0 clears (the port of the location's server blocks is probed)
	VerifySNI  *string // a DNS name; "" clears (the location's first server name is sent)
	SkipVerify *bool
	// VerifyAddress (R59 G4) is where Alice's probe reaches the location's endpoints: a DNS name or an IP literal; ""
	// clears. Only a location that is not a certificate file takes one (validate.Pattern on a file): the web-server
	// providers keep probing the server's own address.
	VerifyAddress *string
}

// validProbeAddress is certificate_locations.verify_address's CHECK in its stored form: an IP literal without a zone (no
// route domain), or a DNS name as validSNI takes it.
func validProbeAddress(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == ""
	}
	return validSNI(s)
}

// validSNI mirrors helperproto.ValidSNI, which inventory may not import (archtest): a DNS name of
// 1..253 bytes of lower-case labels without a wildcard, and not an IP address literal. It is also
// certificate_locations.verify_sni's CHECK. A test asserts both agree.
func validSNI(s string) bool {
	if strings.HasPrefix(s, "*") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return certs.ValidDNSName(s)
}

// UpdateLocation changes a location's verification settings. ifVersion must be the version the
// caller read (If-Match); a scan bumps it only when it changes what it stores. Cleared values are
// stored as NULL.
func (s *Service) UpdateLocation(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, p LocationPatch) (CertificateLocation, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return CertificateLocation{}, err
	}
	var errs validate.Errors
	if p.VerifyPort == nil && p.VerifySNI == nil && p.SkipVerify == nil && p.VerifyAddress == nil {
		// Nothing to change: refused, so an empty edit neither bumps the version nor is audited.
		errs.Add("verify_port", validate.Required, nil)
		errs.Add("verify_sni", validate.Required, nil)
		errs.Add("skip_verify", validate.Required, nil)
	}
	if p.VerifyPort != nil && (*p.VerifyPort < 0 || *p.VerifyPort > 65535) {
		errs.Add("verify_port", validate.OutOfRange, map[string]string{"min": "0", "max": "65535"})
	}
	sni := ""
	if p.VerifySNI != nil {
		sni = foldASCII(strings.TrimSpace(*p.VerifySNI))
		if sni != "" && !validSNI(sni) {
			errs.Add("verify_sni", validate.Pattern, nil)
		}
	}
	address := ""
	if p.VerifyAddress != nil {
		address = foldASCII(strings.TrimSpace(*p.VerifyAddress))
		if a, err := netip.ParseAddr(address); err == nil && a.Zone() == "" {
			address = a.String() // one form per address (2001:DB8::0:7 is 2001:db8::7)
		}
		if address != "" && !validProbeAddress(address) {
			errs.Add("verify_address", validate.Pattern, nil)
		}
	}
	if len(errs) > 0 {
		return CertificateLocation{}, errs
	}
	var out CertificateLocation
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// Only the location row is locked (a scan locks its target first, then its locations), and
		// FOR NO KEY UPDATE: a deployment inserted meanwhile that references it is not blocked.
		var (
			version           int
			port              *int
			curSNI, curAddr   *string
			skip, targetAlive bool
			kind              providers.LocationKind
		)
		err := tx.QueryRow(ctx, `SELECT l.version, l.verify_port, l.verify_sni, l.skip_verify, t.deleted_at IS NULL, l.verify_address, l.kind
FROM certificate_locations l JOIN targets t ON t.id = l.target_id WHERE l.id = $1 FOR NO KEY UPDATE OF l`, id).
			Scan(&version, &port, &curSNI, &skip, &targetAlive, &curAddr, &kind)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !targetAlive) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: read certificate location: %w", err)
		}
		if version != ifVersion {
			return ErrVersionMismatch
		}
		if p.VerifyPort != nil {
			port = nil
			if *p.VerifyPort != 0 {
				port = p.VerifyPort
			}
		}
		if p.VerifySNI != nil {
			curSNI = nil
			if sni != "" {
				curSNI = &sni
			}
		}
		if p.SkipVerify != nil {
			skip = *p.SkipVerify
		}
		if p.VerifyAddress != nil {
			if address != "" && kind.IsFile() {
				return validate.Errors{{Field: "verify_address", Code: validate.Pattern}}
			}
			curAddr = nil
			if address != "" {
				curAddr = &address
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE certificate_locations SET verify_port = $2, verify_sni = $3, skip_verify = $4, verify_address = $5,
    version = version + 1
WHERE id = $1`, id, port, curSNI, skip, curAddr); err != nil {
			return fmt.Errorf("inventory: update certificate location: %w", err)
		}
		if out, err = s.scanCertLocation(tx.QueryRow(ctx, certLocationSelect+" WHERE l.id = $1", id)); err != nil {
			return err
		}
		d := map[string]string{"location_id": id.String(), "verify_port": "", "verify_sni": "", "skip_verify": strconv.FormatBool(skip)}
		if port != nil {
			d["verify_port"] = strconv.Itoa(*port)
		}
		if curSNI != nil {
			d["verify_sni"] = *curSNI
		}
		if !kind.IsFile() {
			d["verify_address"] = ""
			if curAddr != nil {
				d["verify_address"] = *curAddr
			}
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "location.updated", ObjectType: "certificate_location",
			ObjectID: id.String(), Result: audit.Success, Details: d})
		return err
	})
	if err != nil {
		return CertificateLocation{}, err
	}
	return out, nil
}
