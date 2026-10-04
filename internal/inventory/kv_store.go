package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// Rows of one transaction while a poll's result is stored (ruling S12). Variables so that tests can
// make the batches small.
var (
	kvBatchCerts   = 200
	kvBatchKeys    = 500
	kvBatchSecrets = 1000
	// kvBatchHook runs after each batch committed (tests: what a reader sees between batches).
	kvBatchHook func(kind string, batch int)
)

// kvDropped is the reason a result is dropped: the vault was deleted or disabled while the poll ran.
type kvDropped string

func (d kvDropped) Error() string { return "inventory: the vault is " + string(d) }

// kvTarget is what a poll needs of its vault, read with deleted and disabled vaults included.
type kvTarget struct {
	name, url, status string
	deleted           bool
}

func (t kvTarget) dropped() string {
	switch {
	case t.deleted:
		return "deleted"
	case t.status == StatusDisabled:
		return "disabled"
	}
	return ""
}

// readKVTarget reads the vault (ErrNotFound for an unknown id, ErrNotAVault for a server) and, with
// lock ("FOR NO KEY UPDATE" or "FOR UPDATE"), locks its row. A fixed list of clauses: the text is
// never built from input.
func readKVTarget(ctx context.Context, q db.Querier, id uuid.UUID, lock string) (kvTarget, error) {
	var typ string
	var deleted *time.Time
	var t kvTarget
	var row pgx.Row
	switch lock {
	case "FOR UPDATE":
		row = q.QueryRow(ctx, `SELECT name::text, type, status, deleted_at, coalesce(config->>'vault_url', '') FROM targets WHERE id = $1 FOR UPDATE`, id)
	case "FOR NO KEY UPDATE":
		row = q.QueryRow(ctx, `SELECT name::text, type, status, deleted_at, coalesce(config->>'vault_url', '') FROM targets WHERE id = $1 FOR NO KEY UPDATE`, id)
	default:
		row = q.QueryRow(ctx, `SELECT name::text, type, status, deleted_at, coalesce(config->>'vault_url', '') FROM targets WHERE id = $1`, id)
	}
	err := row.Scan(&t.name, &typ, &t.status, &deleted, &t.url)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return kvTarget{}, ErrNotFound
	case err != nil:
		return kvTarget{}, fmt.Errorf("inventory: read the vault: %w", err)
	case typ != TypeAzureKeyVault:
		return kvTarget{}, ErrNotAVault
	}
	t.deleted = deleted != nil
	return t, nil
}

// kvStored counts what the batches wrote.
type kvStored struct {
	newCerts, newVersions, heldVersions, conflicts int
	newKeys, newSecrets                            int
}

// batch runs fn in one transaction that holds the vault's row (a poll's batches of one vault
// serialise there, so a repeated or concurrent poll finds what the other stored), only while the
// job run holds its job. A vault that was deleted or disabled meanwhile ends the poll (kvDropped).
func (s *Service) batch(ctx context.Context, id uuid.UUID, kind string, n int, fn func(tx pgx.Tx, t kvTarget) error) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		t, err := readKVTarget(ctx, tx, id, "FOR NO KEY UPDATE")
		if err != nil {
			return err
		}
		if d := t.dropped(); d != "" {
			return kvDropped(d)
		}
		return fn(tx, t)
	})
	if err == nil && kvBatchHook != nil {
		kvBatchHook(kind, n)
	}
	return err
}

func chunks[T any](items []T, size int) [][]T {
	var out [][]T
	for len(items) > 0 {
		n := min(size, len(items))
		out = append(out, items[:n])
		items = items[n:]
	}
	return out
}

// storeKV stores the prepared result in batches: certificates (with their versions), then keys,
// then secrets. A reader sees, between batches, only whole certificates (the row, its version rows
// and its leaf together); status, last success and every missing mark change afterwards, in the
// final transaction of ReconcileKV. It returns the reason the result was dropped ("" when stored).
func (s *Service) storeKV(ctx context.Context, id uuid.UUID, p *preparedKV, now time.Time, hold kvHold, st *kvStored) (string, error) {
	run := func(kind string, n int, fn func(tx pgx.Tx, t kvTarget) error) (string, error) {
		err := s.batch(ctx, id, kind, n, fn)
		var d kvDropped
		if errors.As(err, &d) {
			return string(d), nil
		}
		return "", err
	}
	for i, items := range chunks(p.certs, kvBatchCerts) {
		if d, err := run(kvCertificates, i+1, func(tx pgx.Tx, t kvTarget) error {
			return s.storeCertBatch(ctx, tx, id, t, items, now, hold, st)
		}); d != "" || err != nil {
			return d, err
		}
	}
	for i, items := range chunks(p.keys, kvBatchKeys) {
		if d, err := run(kvKeys, i+1, func(tx pgx.Tx, _ kvTarget) error {
			n, err := storeKeyBatch(ctx, tx, id, items, now)
			st.newKeys += n
			return err
		}); d != "" || err != nil {
			return d, err
		}
	}
	for i, items := range chunks(p.secrets, kvBatchSecrets) {
		if d, err := run(kvSecrets, i+1, func(tx pgx.Tx, _ kvTarget) error {
			n, err := storeSecretBatch(ctx, tx, id, items, now)
			st.newSecrets += n
			return err
		}); d != "" || err != nil {
			return d, err
		}
	}
	return "", nil
}

type kvExisting struct {
	id             uuid.UUID
	currentVersion string
	currentThumb   string
}

// storeCertBatch stores one batch of certificates under the vault's lock. Certificates without
// details (the listing alone) are one multi-row upsert; those with details are handled one by one
// (the row, the leaf in certificates, the current version's row and the older versions), and a
// version that is new on a known certificate is audited in the same transaction.
func (s *Service) storeCertBatch(ctx context.Context, tx pgx.Tx, vault uuid.UUID, t kvTarget, items []kvCert, now time.Time, hold kvHold, st *kvStored) error {
	var detailed []kvCert
	var listed []kvCert
	for _, c := range items {
		if c.details != nil {
			detailed = append(detailed, c)
		} else {
			listed = append(listed, c)
		}
	}
	var events []audit.Event
	if len(detailed) > 0 {
		moved, err := s.storeDetailedCerts(ctx, tx, vault, t, detailed, now, hold, st, &events)
		if err != nil {
			return err
		}
		listed = append(listed, moved...)
	}
	if len(listed) > 0 {
		n, err := upsertListedCerts(ctx, tx, vault, listed, now)
		if err != nil {
			return err
		}
		st.newCerts += n
	}
	for _, e := range events { // audit takes the chain lock: last
		if _, err := s.audit.Append(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// upsertListedCerts stores what the listing alone says about certificates (names in fold order):
// attributes, the listed thumbprint and update time, the sighting. A certificate whose listing
// differs from its read details is marked details_pending. The current version, its details and
// kv_created_at are not touched. It returns the number of new certificates. A row another poll saw
// later (last_seen_at) is left as it is, and a "missing" mark of a later poll is not cleared by an
// older sighting.
func upsertListedCerts(ctx context.Context, tx pgx.Tx, vault uuid.UUID, items []kvCert, now time.Time) (int, error) {
	n := len(items)
	ids, names, thumbs := make([]string, n), make([]string, n), make([]string, n)
	updated, nbf, exp, created := make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n)
	enabled := make([]bool, n)
	for i, c := range items {
		ids[i], names[i], thumbs[i] = uuid.Must(uuid.NewV7()).String(), c.name, c.thumb
		updated[i], nbf[i], exp[i], created[i], enabled[i] = c.updated, c.notBefore, c.expires, c.created, c.enabled
	}
	rows, err := tx.Query(ctx, `INSERT INTO kv_certificates AS k (id, target_id, name, listed_thumbprint, listed_updated_at, enabled,
    not_before, expires, kv_created_at, details_pending, first_seen_at, last_seen_at)
SELECT u.id::uuid, $1, u.name, u.thumb, u.updated, u.enabled, u.nbf, u.exp, u.created, true, $2, $2
FROM unnest($3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::boolean[], $8::timestamptz[], $9::timestamptz[], $10::timestamptz[])
     AS u(id, name, thumb, updated, enabled, nbf, exp, created)
ON CONFLICT (target_id, lower(name COLLATE "C")) DO UPDATE SET
    listed_thumbprint = EXCLUDED.listed_thumbprint, listed_updated_at = EXCLUDED.listed_updated_at, enabled = EXCLUDED.enabled,
    not_before = EXCLUDED.not_before, expires = EXCLUDED.expires,
    details_pending = k.current_version = '' OR k.current_thumbprint <> EXCLUDED.listed_thumbprint
                      OR EXCLUDED.listed_updated_at IS DISTINCT FROM k.kv_updated_at,
    removed_notified_at = CASE WHEN k.missing_since IS NOT NULL AND EXCLUDED.last_seen_at >= k.missing_since THEN NULL ELSE k.removed_notified_at END,
    missing_since = CASE WHEN k.missing_since IS NOT NULL AND EXCLUDED.last_seen_at >= k.missing_since THEN NULL ELSE k.missing_since END,
    last_seen_at = GREATEST(k.last_seen_at, EXCLUDED.last_seen_at)
WHERE k.last_seen_at <= EXCLUDED.last_seen_at
RETURNING (xmax = 0)`, vault, now, ids, names, thumbs, updated, enabled, nbf, exp, created)
	if err != nil {
		return 0, fmt.Errorf("inventory: store the listed certificates: %w", err)
	}
	defer rows.Close()
	inserted := 0
	for rows.Next() {
		var isNew bool
		if err := rows.Scan(&isNew); err != nil {
			return 0, fmt.Errorf("inventory: read the stored certificates: %w", err)
		}
		if isNew {
			inserted++
		}
	}
	return inserted, rows.Err()
}

// storeDetailedCerts stores the certificates whose details were read (see storeCertBatch). It
// returns the ones that must be stored from their listing alone instead: a version ID that Alice
// knows with another thumbprint is never silently replaced (the stored row is kept, the conflict
// is counted and, when the listing is new, audited).
func (s *Service) storeDetailedCerts(ctx context.Context, tx pgx.Tx, vault uuid.UUID, t kvTarget, items []kvCert, now time.Time,
	hold kvHold, st *kvStored, events *[]audit.Event) ([]kvCert, error) {
	folds := make([]string, len(items))
	for i, c := range items {
		folds[i] = c.fold
	}
	existing := map[string]kvExisting{}
	listed := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT lower(name COLLATE "C"), id, current_version, current_thumbprint, listed_thumbprint FROM kv_certificates
WHERE target_id = $1 AND lower(name COLLATE "C") = ANY($2) ORDER BY lower(name COLLATE "C") FOR UPDATE`, vault, folds)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the stored certificates: %w", err)
	}
	for rows.Next() {
		var fold string
		var e kvExisting
		var lt string
		if err := rows.Scan(&fold, &e.id, &e.currentVersion, &e.currentThumb, &lt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("inventory: read a stored certificate: %w", err)
		}
		existing[fold], listed[fold] = e, lt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The thumbprints Alice stored for the versions this batch mentions.
	ids, versions := []string{}, []string{}
	for _, c := range items {
		e, ok := existing[c.fold]
		if !ok {
			continue
		}
		ids = append(ids, e.id.String())
		versions = append(versions, c.details.version)
		if e.currentVersion != "" {
			ids = append(ids, e.id.String())
			versions = append(versions, e.currentVersion)
		}
		for _, h := range c.details.history {
			ids = append(ids, e.id.String())
			versions = append(versions, h.version)
		}
	}
	stored := map[[2]string]string{}       // (certificate id, version) -> thumbprint
	storedAt := map[[2]string]*time.Time{} // (certificate id, version) -> kv_created_at
	rows, err = tx.Query(ctx, `SELECT v.kv_certificate_id::text, v.version, v.thumbprint, v.kv_created_at FROM kv_certificate_versions v
JOIN unnest($1::text[], $2::text[]) AS u(id, version) ON v.kv_certificate_id = u.id::uuid AND v.version = u.version`, ids, versions)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the stored versions: %w", err)
	}
	for rows.Next() {
		var id, v, th string
		var created *time.Time
		if err := rows.Scan(&id, &v, &th, &created); err != nil {
			rows.Close()
			return nil, fmt.Errorf("inventory: read a stored version: %w", err)
		}
		stored[[2]string{id, v}], storedAt[[2]string{id, v}] = th, created
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var moved []kvCert
	var ok []kvCert
	conflictEvents := []audit.Event{}
	for _, c := range items {
		e, known := existing[c.fold]
		if known {
			// A version Alice already has that is not the stored current one moves the pointer only
			// when it is provably newer (created later than the current version): an older read that
			// was reconciled later must not move it back (M1). The listing is stored as it is.
			key := [2]string{e.id.String(), c.details.version}
			if _, has := stored[key]; has && e.currentVersion != "" && c.details.version != e.currentVersion {
				cur := storedAt[[2]string{e.id.String(), e.currentVersion}]
				if at := storedAt[key]; at == nil || cur == nil || !at.After(*cur) {
					moved = append(moved, kvCert{name: c.name, fold: c.fold, thumb: c.thumb, enabled: c.enabled, notBefore: c.notBefore,
						expires: c.expires, created: c.created, updated: c.updated})
					continue
				}
			}
			if th, has := stored[[2]string{e.id.String(), c.details.version}]; has && th != c.details.thumb {
				st.conflicts++
				if listed[c.fold] != c.thumb { // audited when the listing is new, not at every poll
					conflictEvents = append(conflictEvents, audit.Event{Actor: audit.SystemActor("jobs"), Action: "kv.certificate.version_conflict",
						ObjectType: "kv_certificate", ObjectID: e.id.String(), Result: audit.Success, Details: map[string]string{
							"kv_certificate_id": e.id.String(), "certificate_name": c.name, "version": c.details.version, "thumbprint": th,
							"reported_thumbprint": c.details.thumb, "vault_url": t.url}})
				}
				moved = append(moved, kvCert{name: c.name, fold: c.fold, thumb: c.thumb, enabled: c.enabled, notBefore: c.notBefore,
					expires: c.expires, created: c.created, updated: c.updated})
				continue
			}
		}
		ok = append(ok, c)
	}
	*events = append(*events, conflictEvents...)

	// The leaves, in fingerprint order (as every writer of certificates does).
	found := map[string]discoveredCertificate{}
	for _, c := range ok {
		found[c.details.leaf.Fingerprint] = discoveredCertificate{p: c.details.leaf, complete: c.details.complete}
	}
	certIDs, err := upsertCertificates(ctx, tx, found, "azure_kv", now)
	if err != nil {
		return nil, err
	}

	for _, c := range ok {
		d := c.details
		prev, known := existing[c.fold]
		certID := prev.id
		if !known {
			certID = uuid.Must(uuid.NewV7())
			if _, err := tx.Exec(ctx, `INSERT INTO kv_certificates (id, target_id, name, current_version, current_thumbprint, kv_updated_at,
    listed_thumbprint, listed_updated_at, enabled, not_before, expires, kv_created_at, exportable, key_type, key_size, content_type, issuer_name,
    auto_renew, details_pending, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, false, $19, $19)`,
				certID, vault, c.name, d.version, d.thumb, firstTime(d.updated, c.updated), c.thumb, c.updated, c.enabled, c.notBefore, c.expires,
				d.attrs.created, d.exportable, d.keyType, d.keySize, d.contentType, d.issuer, d.autoRenew, now); err != nil {
				return nil, fmt.Errorf("inventory: store a certificate: %w", err)
			}
			st.newCerts++
		} else {
			tag, err := tx.Exec(ctx, `UPDATE kv_certificates SET current_version = $2, current_thumbprint = $3, kv_updated_at = $4,
    listed_thumbprint = $5, listed_updated_at = $6, enabled = $7, not_before = $8, expires = $9, kv_created_at = $10,
    exportable = coalesce($11, exportable), key_type = $12, key_size = $13, content_type = $14, issuer_name = $15, auto_renew = $16,
    details_pending = false, last_seen_at = GREATEST(last_seen_at, $17),
    removed_notified_at = CASE WHEN missing_since IS NOT NULL AND $17 >= missing_since THEN NULL ELSE removed_notified_at END,
    missing_since = CASE WHEN missing_since IS NOT NULL AND $17 >= missing_since THEN NULL ELSE missing_since END
WHERE id = $1 AND last_seen_at <= $17`,
				certID, d.version, d.thumb, firstTime(d.updated, c.updated), c.thumb, c.updated, c.enabled, c.notBefore, c.expires,
				d.attrs.created, d.exportable, d.keyType, d.keySize, d.contentType, d.issuer, d.autoRenew, now)
			if err != nil {
				return nil, fmt.Errorf("inventory: update a certificate: %w", err)
			}
			if tag.RowsAffected() == 0 {
				continue // a later poll already stored newer knowledge
			}
		}
		// New on a certificate Alice already had a current version of (rule kvHold); else a baseline.
		held := hold.held(known && prev.currentVersion != "", d.attrs.created)
		heldReason := ""
		if held {
			heldReason = "license"
		}
		certRef := certIDs[d.leaf.Fingerprint]
		var versionID uuid.UUID
		var inserted bool
		err := tx.QueryRow(ctx, `INSERT INTO kv_certificate_versions AS v (id, kv_certificate_id, version, thumbprint, certificate_id, enabled,
    not_before, expires, kv_created_at, exportable, key_type, content_type, detected_at, held, held_reason)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (kv_certificate_id, version) DO UPDATE SET certificate_id = coalesce(v.certificate_id, EXCLUDED.certificate_id),
    enabled = EXCLUDED.enabled, not_before = EXCLUDED.not_before, expires = EXCLUDED.expires,
    exportable = coalesce(EXCLUDED.exportable, v.exportable),
    key_type = CASE WHEN EXCLUDED.key_type <> '' THEN EXCLUDED.key_type ELSE v.key_type END,
    content_type = CASE WHEN EXCLUDED.content_type <> '' THEN EXCLUDED.content_type ELSE v.content_type END
WHERE v.thumbprint = EXCLUDED.thumbprint
RETURNING id, (xmax = 0)`, uuid.Must(uuid.NewV7()), certID, d.version, d.thumb, certRef, d.attrs.enabled, d.attrs.notBefore, d.attrs.expires,
			d.attrs.created, d.exportable, d.keyType, d.contentType, now, held, heldReason).Scan(&versionID, &inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			st.conflicts++ // cannot be reached with the vault locked; kept as the guard it is
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inventory: store a certificate version: %w", err)
		}
		if inserted && held {
			st.heldVersions++
		}
		if inserted && known && prev.currentVersion != "" {
			st.newVersions++
			*events = append(*events, audit.Event{Actor: audit.SystemActor("jobs"), Action: "kv.certificate.new_version",
				ObjectType: "kv_certificate", ObjectID: certID.String(), Result: audit.Success, Details: map[string]string{
					"kv_certificate_id": certID.String(), "certificate_name": c.name, "version": d.version, "thumbprint": d.thumb,
					"fingerprint": d.leaf.Fingerprint, "held": fmt.Sprint(held), "vault_url": t.url}})
		}
		hist := d.history[:0:0]
		for _, h := range d.history {
			if known {
				if th, has := stored[[2]string{certID.String(), h.version}]; has && th != h.thumb {
					st.conflicts++
					continue
				}
			}
			hist = append(hist, h)
		}
		if err := upsertHistory(ctx, tx, certID, hist, now); err != nil {
			return nil, err
		}
	}
	return moved, nil
}

// firstTime is a when the details say, else when the listing says.
func firstTime(a, b *time.Time) *time.Time {
	if a != nil {
		return a
	}
	return b
}

// upsertHistory stores the older versions a poll listed: no leaf, never held, never announced.
func upsertHistory(ctx context.Context, tx pgx.Tx, cert uuid.UUID, items []kvVersion, now time.Time) error {
	if len(items) == 0 {
		return nil
	}
	n := len(items)
	ids, versions, thumbs := make([]string, n), make([]string, n), make([]string, n)
	enabled := make([]bool, n)
	nbf, exp, created := make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n)
	for i, v := range items {
		ids[i], versions[i], thumbs[i], enabled[i] = uuid.Must(uuid.NewV7()).String(), v.version, v.thumb, v.enabled
		nbf[i], exp[i], created[i] = v.notBefore, v.expires, v.created
	}
	if _, err := tx.Exec(ctx, `INSERT INTO kv_certificate_versions AS v (id, kv_certificate_id, version, thumbprint, enabled, not_before, expires,
    kv_created_at, detected_at)
SELECT u.id::uuid, $1, u.version, u.thumb, u.enabled, u.nbf, u.exp, u.created, $2
FROM unnest($3::text[], $4::text[], $5::text[], $6::boolean[], $7::timestamptz[], $8::timestamptz[], $9::timestamptz[])
     AS u(id, version, thumb, enabled, nbf, exp, created)
ON CONFLICT (kv_certificate_id, version) DO UPDATE SET enabled = EXCLUDED.enabled, not_before = EXCLUDED.not_before, expires = EXCLUDED.expires
WHERE v.thumbprint = EXCLUDED.thumbprint`, cert, now, ids, versions, thumbs, enabled, nbf, exp, created); err != nil {
		return fmt.Errorf("inventory: store the older versions: %w", err)
	}
	return nil
}

// storeKeyBatch updates the known keys of the batch and inserts the new ones (the vault's lock is
// held, so nothing else inserts in between); details are written only for keys that came with them.
// It returns the number of new keys.
func storeKeyBatch(ctx context.Context, tx pgx.Tx, vault uuid.UUID, items []kvKeyItem, now time.Time) (int, error) {
	n := len(items)
	folds, names, versions, ktypes, curves, problems := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	enabled, managed, hasDetails, hsm := make([]bool, n), make([]bool, n), make([]bool, n), make([]bool, n)
	sizes := make([]int32, n)
	nbf, exp, created, updated := make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n)
	for i, k := range items {
		folds[i], names[i], versions[i], ktypes[i], curves[i], problems[i] = k.fold, k.name, k.version, k.keyType, k.curve, k.problem
		enabled[i], managed[i], hasDetails[i], hsm[i], sizes[i] = k.enabled, k.managed, k.hasDetails, k.hsm, int32(k.size) //nolint:gosec // G115: bounded to 0..16384 by prepareKV
		nbf[i], exp[i], created[i], updated[i] = k.notBefore, k.expires, k.created, k.updated
	}
	args := []any{vault, now, folds, names, enabled, managed, nbf, exp, created, updated, hasDetails, versions, ktypes, hsm, sizes, curves, problems}
	const source = `unnest($3::text[], $4::text[], $5::boolean[], $6::boolean[], $7::timestamptz[], $8::timestamptz[], $9::timestamptz[],
    $10::timestamptz[], $11::boolean[], $12::text[], $13::text[], $14::boolean[], $15::integer[], $16::text[], $17::text[])
    AS u(fold, name, enabled, managed, nbf, exp, created, updated, has_details, version, ktype, hsm, size, curve, problem)`
	if _, err := tx.Exec(ctx, `UPDATE kv_keys k SET enabled = u.enabled, managed = u.managed, not_before = u.nbf, expires = u.exp,
    kv_created_at = u.created, kv_updated_at = u.updated,
    version = CASE WHEN u.has_details THEN u.version ELSE k.version END,
    key_type = CASE WHEN u.has_details THEN u.ktype ELSE k.key_type END,
    hsm = CASE WHEN u.has_details THEN u.hsm ELSE k.hsm END,
    key_size = CASE WHEN u.has_details THEN u.size ELSE k.key_size END,
    curve = CASE WHEN u.has_details THEN u.curve ELSE k.curve END,
    details_updated_at = CASE WHEN u.has_details THEN u.updated ELSE k.details_updated_at END,
    details_problem = CASE WHEN u.has_details THEN '' WHEN u.problem <> '' THEN u.problem ELSE k.details_problem END,
    last_seen_at = GREATEST(k.last_seen_at, $2),
    missing_since = CASE WHEN k.missing_since IS NOT NULL AND $2 >= k.missing_since THEN NULL ELSE k.missing_since END
FROM `+source+`
WHERE k.target_id = $1 AND lower(k.name COLLATE "C") = u.fold AND k.last_seen_at <= $2`, args...); err != nil {
		return 0, fmt.Errorf("inventory: update the keys: %w", err)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO kv_keys (id, target_id, name, version, key_type, hsm, key_size, curve, details_updated_at, details_problem,
    enabled, managed, not_before, expires, kv_created_at, kv_updated_at, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), $1, u.name, CASE WHEN u.has_details THEN u.version ELSE '' END, CASE WHEN u.has_details THEN u.ktype ELSE '' END,
    CASE WHEN u.has_details THEN u.hsm ELSE false END, CASE WHEN u.has_details THEN u.size ELSE 0 END,
    CASE WHEN u.has_details THEN u.curve ELSE '' END, CASE WHEN u.has_details THEN u.updated END,
    CASE WHEN u.has_details THEN '' ELSE u.problem END, u.enabled, u.managed, u.nbf, u.exp, u.created, u.updated, $2, $2
FROM `+source+`
WHERE NOT EXISTS (SELECT 1 FROM kv_keys k WHERE k.target_id = $1 AND lower(k.name COLLATE "C") = u.fold)
ON CONFLICT (target_id, lower(name COLLATE "C")) DO NOTHING`, args...)
	if err != nil {
		return 0, fmt.Errorf("inventory: insert the keys: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// storeSecretBatch is storeKeyBatch for secret metadata (a secret's value is never read).
func storeSecretBatch(ctx context.Context, tx pgx.Tx, vault uuid.UUID, items []kvSecretItem, now time.Time) (int, error) {
	n := len(items)
	folds, names, types := make([]string, n), make([]string, n), make([]string, n)
	enabled, managed := make([]bool, n), make([]bool, n)
	nbf, exp, created, updated := make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n), make([]*time.Time, n)
	for i, s := range items {
		folds[i], names[i], types[i], enabled[i], managed[i] = s.fold, s.name, s.contentType, s.enabled, s.managed
		nbf[i], exp[i], created[i], updated[i] = s.notBefore, s.expires, s.created, s.updated
	}
	args := []any{vault, now, folds, names, types, enabled, managed, nbf, exp, created, updated}
	const source = `unnest($3::text[], $4::text[], $5::text[], $6::boolean[], $7::boolean[], $8::timestamptz[], $9::timestamptz[],
    $10::timestamptz[], $11::timestamptz[]) AS u(fold, name, ctype, enabled, managed, nbf, exp, created, updated)`
	if _, err := tx.Exec(ctx, `UPDATE kv_secrets k SET content_type = u.ctype, enabled = u.enabled, managed = u.managed, not_before = u.nbf,
    expires = u.exp, kv_created_at = u.created, kv_updated_at = u.updated, last_seen_at = GREATEST(k.last_seen_at, $2),
    missing_since = CASE WHEN k.missing_since IS NOT NULL AND $2 >= k.missing_since THEN NULL ELSE k.missing_since END
FROM `+source+`
WHERE k.target_id = $1 AND lower(k.name COLLATE "C") = u.fold AND k.last_seen_at <= $2`, args...); err != nil {
		return 0, fmt.Errorf("inventory: update the secrets: %w", err)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO kv_secrets (id, target_id, name, content_type, enabled, managed, not_before, expires, kv_created_at,
    kv_updated_at, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), $1, u.name, u.ctype, u.enabled, u.managed, u.nbf, u.exp, u.created, u.updated, $2, $2
FROM `+source+`
WHERE NOT EXISTS (SELECT 1 FROM kv_secrets k WHERE k.target_id = $1 AND lower(k.name COLLATE "C") = u.fold)
ON CONFLICT (target_id, lower(name COLLATE "C")) DO NOTHING`, args...)
	if err != nil {
		return 0, fmt.Errorf("inventory: insert the secrets: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// markMissingNames marks the keys or secrets a complete listing did not contain (never deleted); the names are the
// folded names the listing held. An object a newer poll saw (last_seen_at later than this poll's
// time) is left alone.
func markMissingNames(ctx context.Context, tx pgx.Tx, table string, vault uuid.UUID, seen []string, now time.Time) (int, error) {
	var sql string
	switch table {
	case "kv_keys":
		sql = `UPDATE kv_keys SET missing_since = $2 WHERE target_id = $1 AND missing_since IS NULL AND last_seen_at <= $2
AND NOT (lower(name COLLATE "C") = ANY($3))`
	case "kv_secrets":
		sql = `UPDATE kv_secrets SET missing_since = $2 WHERE target_id = $1 AND missing_since IS NULL AND last_seen_at <= $2
AND NOT (lower(name COLLATE "C") = ANY($3))`
	default:
		return 0, errors.New("inventory: unknown vault table")
	}
	tag, err := tx.Exec(ctx, sql, vault, now, seen)
	if err != nil {
		return 0, fmt.Errorf("inventory: mark missing %s: %w", table, err)
	}
	return int(tag.RowsAffected()), nil
}

type removedCert struct {
	id    uuid.UUID
	name  string
	bound bool
}

// markMissingCerts marks the vault's certificates the listing did not contain and returns them
// (name order) with whether a live binding names them.
func markMissingCerts(ctx context.Context, tx pgx.Tx, vault uuid.UUID, seen []string, now time.Time) ([]removedCert, error) {
	rows, err := tx.Query(ctx, `UPDATE kv_certificates k SET missing_since = $2
WHERE k.target_id = $1 AND k.missing_since IS NULL AND k.last_seen_at <= $2 AND NOT (lower(k.name COLLATE "C") = ANY($3))
RETURNING k.id, k.name, EXISTS (SELECT 1 FROM bindings b WHERE b.kv_certificate_id = k.id AND b.deleted_at IS NULL)`, vault, now, seen)
	if err != nil {
		return nil, fmt.Errorf("inventory: mark missing certificates: %w", err)
	}
	defer rows.Close()
	var out []removedCert
	for rows.Next() {
		var r removedCert
		if err := rows.Scan(&r.id, &r.name, &r.bound); err != nil {
			return nil, fmt.Errorf("inventory: read a missing certificate: %w", err)
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b removedCert) int { return compareStrings(foldASCII(a.name), foldASCII(b.name)) })
	return out, rows.Err()
}
