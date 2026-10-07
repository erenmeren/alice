package reports

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/alerts/expiry"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/csvx"
	"alice/internal/platform/db"
)

// Limits and errors of the exports and the saved views.
const (
	MaxExportRows    = 50000
	MaxViewsPerUser  = 50
	PageCertificates = "certificates"
	PageSSHKeys      = "ssh_keys"

	// exportPage is the page size an export reads the list with (the list's own largest page).
	exportPage = 200
)

var (
	ErrTooLarge   = errors.New("reports: more rows than an export may hold") // more than MaxExportRows rows: nothing written
	ErrExportBusy = errors.New("reports: this user already has an export running")
	ErrViewLimit  = errors.New("reports: too many saved views")
	ErrViewName   = errors.New("reports: a saved view of that name exists")
	ErrNotFound   = errors.New("reports: not found")
)

var certificateColumns = []string{"id", "subject_cn", "label", "sans", "issuer", "serial", "not_before", "not_after", "days_left",
	"source", "key_algorithm", "key_bits", "self_signed", "chain_complete", "fingerprint", "location_count"}

var sshKeyColumns = []string{"id", "fingerprint", "key_type", "bits", "comment", "managed", "platform_key", "weak",
	"location_count", "target_count", "missing", "retired", "first_seen_at"}

// ExportCertificates writes the CSV of every certificate the list shows for f (R42 row 16): it reads the list page by
// page (so the export is the list), counts first and refuses more than MaxExportRows before anything is written,
// commits one inventory.exported audit row, then streams the BOM, the header and the rows through csvx (S-10: no more
// than one page of rows is held; one export at a time per user).
func (s *Service) ExportCertificates(ctx context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error) {
	details := map[string]string{"kind": "certificates", "format": "csv"}
	for k, v := range map[string]string{"source": f.Source, "q": f.Query, "expiry": f.Expiry} {
		if v != "" {
			details[k] = v
		}
	}
	if f.TargetID != uuid.Nil {
		details["target_id"] = f.TargetID.String()
	}
	now := s.clock.Now()
	page := func(cursor string) ([][]string, string, error) {
		g := f
		g.Cursor, g.Limit = cursor, exportPage
		p, err := s.inventory.ListCertificates(ctx, g)
		if err != nil {
			return nil, "", err
		}
		rows := make([][]string, 0, len(p.Items))
		for _, c := range p.Items {
			rows = append(rows, []string{c.ID.String(), c.SubjectCN, c.Label, strings.Join(c.SANs, " "), c.Issuer, c.Serial,
				c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), strconv.Itoa(expiry.DaysLeft(c.NotAfter, now)),
				c.Source, c.KeyAlgorithm, strconv.Itoa(c.KeyBits), strconv.FormatBool(c.SelfSigned), strconv.FormatBool(c.ChainComplete),
				c.Fingerprint, strconv.Itoa(c.LocationCount)})
		}
		return rows, p.NextCursor, nil
	}
	return s.export(ctx, a, details, certificateColumns, page, w)
}

// ExportSSHKeys is ExportCertificates for the SSH key list.
func (s *Service) ExportSSHKeys(ctx context.Context, a audit.Actor, f inventory.KeyFilter, w io.Writer) (int, error) {
	details := map[string]string{"kind": "ssh_keys", "format": "csv"}
	for k, v := range map[string]string{"os_user": f.OSUser, "q": f.Query, "flag": f.Flag} {
		if v != "" {
			details[k] = v
		}
	}
	if f.TargetID != uuid.Nil {
		details["target_id"] = f.TargetID.String()
	}
	if f.IncludeMissing {
		details["missing"] = "true"
	}
	page := func(cursor string) ([][]string, string, error) {
		g := f
		g.Cursor, g.Limit = cursor, exportPage
		p, err := s.inventory.ListSSHKeys(ctx, g)
		if err != nil {
			return nil, "", err
		}
		rows := make([][]string, 0, len(p.Items))
		for _, k := range p.Items {
			rows = append(rows, []string{k.ID.String(), k.Fingerprint, k.KeyType, strconv.Itoa(k.Bits), k.Comment,
				strconv.FormatBool(k.Managed), strconv.FormatBool(k.IsPlatformKey), strconv.FormatBool(k.Weak),
				strconv.Itoa(k.LocationCount), strconv.Itoa(k.TargetCount), strconv.FormatBool(k.Missing), strconv.FormatBool(k.Retired),
				k.FirstSeenAt.UTC().Format(time.RFC3339)})
		}
		return rows, p.NextCursor, nil
	}
	return s.export(ctx, a, details, sshKeyColumns, page, w)
}

// acquire takes the user's export slot (S-10); the returned function gives it back.
func (s *Service) acquire(user uuid.UUID) (func(), bool) {
	s.exportMu.Lock()
	defer s.exportMu.Unlock()
	if s.exporting[user] {
		return nil, false
	}
	s.exporting[user] = true
	return func() {
		s.exportMu.Lock()
		delete(s.exporting, user)
		s.exportMu.Unlock()
	}, true
}

func (s *Service) export(ctx context.Context, a audit.Actor, details map[string]string, header []string,
	page func(cursor string) ([][]string, string, error), w io.Writer) (int, error) {
	release, ok := s.acquire(a.ID)
	if !ok {
		return 0, ErrExportBusy
	}
	defer release()
	// Pass 1 counts; nothing is written and nothing is audited when the export is refused.
	count := 0
	for cursor := ""; ; {
		rows, next, err := page(cursor)
		if err != nil {
			return 0, err
		}
		if count += len(rows); count > MaxExportRows {
			return 0, ErrTooLarge
		}
		if next == "" {
			break
		}
		cursor = next
	}
	details["row_count"] = strconv.Itoa(count) // what pass 1 counted; rows added since may be cut at the cap
	if err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "inventory.exported", ObjectType: details["kind"],
			Result: audit.Success, Details: details})
		return err
	}); err != nil {
		return 0, err
	}
	cw, err := csvx.NewWriter(w)
	if err != nil {
		return 0, err
	}
	if err := cw.Write(header); err != nil {
		return 0, err
	}
	// Pass 2 streams page by page; rows that appeared since the count are cut at the cap.
	written := 0
	for cursor := ""; ; {
		rows, next, err := page(cursor)
		if err != nil {
			return written, err
		}
		for _, r := range rows {
			if written == MaxExportRows {
				break
			}
			if err := cw.Write(r); err != nil {
				return written, err
			}
			written++
		}
		if err := cw.Flush(); err != nil {
			return written, err
		}
		if next == "" || written == MaxExportRows {
			break
		}
		cursor = next
	}
	return written, nil
}
