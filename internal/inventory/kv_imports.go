package inventory

// Imports of a certificate Alice holds into a Key Vault (spec §11.8; R40 row 25; rulings S6, S9, S14).
// The private key leaves Alice here, so an import is an Administrator's act with the license gate open;
// the vault has no idempotency key, so an import is sent at most once.
//
// State machine (kv_imports.state; the schema's trigger kv_imports_history_frozen is the backstop):
//
//	queued     --MarkImportSent-->   running (sent: sent_at is set once, before the provider is called)
//	queued     --FinishImport(refused) | FailQueuedImport--> failed (nothing was sent)
//	running    --FinishImport(created)-->   succeeded (the version is stored in the vault's rows at once)
//	running    --FinishImport(refused)-->   failed (a well-formed refusal; azure.unreachable means nothing
//	                                        reached the vault: CanRetry, and a new request is accepted)
//	running    --FinishImport(uncertain)--> uncertain (never sent again, never built again)
//	uncertain  --a poll stores a version of that name with the thumbprint, created in the request's second or
//	             later--> succeeded
//	uncertain  --24 hours after the send, a complete listing and still no such version--> failed with
//	             kv.import_outcome_unknown
//	uncertain  --72 hours after the send, whatever the listings (SweepImports, also for an unreachable
//	             vault)--> failed with kv.import_outcome_unknown
//	any active --the vault is deleted--> failed: kv.import_vault_deleted when queued, else
//	             kv.import_outcome_unknown (endVaultImports)
//
// Every other step is ErrImportState and changes nothing. One import per vault and ASCII-folded name is
// active (queued, running or uncertain) at a time.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/audit"
	"alice/internal/authz"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
)

// Import states (kv_imports.state). ImportRunning is the state "sent": the request was handed to the
// provider (sent_at is set) and nothing is known yet.
const (
	ImportQueued    = "queued"
	ImportRunning   = "running"
	ImportSucceeded = "succeeded"
	ImportFailed    = "failed"
	ImportUncertain = "uncertain"
)

// Closed reasons of an import (kv_imports.error_code) that Alice itself decides.
const (
	ReasonImportOutcomeUnknown = "kv.import_outcome_unknown"
	ReasonImportConfirmNeeded  = "kv.import_confirm_needed"
	ReasonImportVaultDeleted   = "kv.import_vault_deleted"
	// ReasonImportCancelled: the import's job ended (cancelled, dead, failed or gone) before anything was sent.
	ReasonImportCancelled = "kv.import_cancelled"
)

// ImportOutcomeUnknownAfter is how long after the send an uncertain import waits for a poll to settle it.
const ImportOutcomeUnknownAfter = 24 * time.Hour

// ImportOutcomeUnknownCap is how long after the send an uncertain import may stay uncertain at most: after
// it, SweepImports (or any poll of the vault) ends it as outcome unknown whatever the listings said.
const ImportOutcomeUnknownCap = 72 * time.Hour

// importSweepBatch bounds the imports one SweepImports call changes (the next call continues; a variable for tests).
var importSweepBatch = 200

// ImportInput asks for a certificate Alice holds to be imported into a vault under Name. ConfirmExisting is
// the Administrator's confirmation that Name may already exist (a new version, ruling S9).
type ImportInput struct {
	VaultID, CertificateID uuid.UUID
	Name                   string
	ConfirmExisting        bool
}

// KVImport is one import.
type KVImport struct {
	ID, CertificateID, VaultID uuid.UUID
	Name                       string
	// NewVersion records the person's CONFIRMATION (ConfirmExisting, or the name was known to exist), not
	// that the name existed: a confirmation for a name the inventory does not know is kept (the vault may
	// have it). It is what ReplaceExisting is sent as. The audit detail "new_version" of kv.import.requested
	// has the same meaning.
	NewVersion          bool
	State               string
	Thumbprint, Version string
	ErrorCode           string
	ErrorParams         map[string]string
	CanRetry            bool // failed before anything reached the vault: a new request is safe
	JobID, RequestedBy  *uuid.UUID
	CreatedAt           time.Time
	SentAt, FinishedAt  *time.Time
}

// ImportMaterial is what the job sends: the request with the PFX in it. The caller zeroes Request.PFX as
// soon as the provider returned (or on any path that does not send it).
type ImportMaterial struct {
	Request providers.ImportRequest
	VaultID uuid.UUID
}

// importMaterialHook observes the buffers ImportMaterial wipes: "der" (the stored key, decrypted) and
// "pfx" (the PFX handed to the caller). Tests only.
var importMaterialHook func(stage string, b []byte)

const importColumns = `i.id, i.certificate_id, i.target_id, i.name, i.new_version, i.state, i.thumbprint, i.version, i.error_code, i.error_params,
i.job_id, i.requested_by, i.created_at, i.sent_at, i.finished_at`

func scanImport(row pgx.Row) (KVImport, error) {
	var im KVImport
	var params []byte
	err := row.Scan(&im.ID, &im.CertificateID, &im.VaultID, &im.Name, &im.NewVersion, &im.State, &im.Thumbprint, &im.Version, &im.ErrorCode, &params,
		&im.JobID, &im.RequestedBy, &im.CreatedAt, &im.SentAt, &im.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return KVImport{}, ErrNotFound
	}
	if err != nil {
		return KVImport{}, fmt.Errorf("inventory: read the import: %w", err)
	}
	im.ErrorParams = map[string]string{}
	if err := json.Unmarshal(params, &im.ErrorParams); err != nil {
		return KVImport{}, fmt.Errorf("inventory: read the import's params: %w", err)
	}
	im.CreatedAt, im.SentAt, im.FinishedAt = im.CreatedAt.UTC(), utcPtr(im.SentAt), utcPtr(im.FinishedAt)
	im.CanRetry = im.State == ImportFailed && (im.ErrorCode == "azure.unreachable" || im.ErrorCode == ReasonImportCancelled)
	return im, nil
}

// readImport reads an import; lock takes its row lock.
func readImport(ctx context.Context, q db.Querier, id uuid.UUID, lock bool) (KVImport, error) {
	if lock {
		return scanImport(q.QueryRow(ctx, "SELECT "+importColumns+" FROM kv_imports i WHERE i.id = $1 FOR UPDATE", id))
	}
	return scanImport(q.QueryRow(ctx, "SELECT "+importColumns+" FROM kv_imports i WHERE i.id = $1", id))
}

// Import reads one import of a live vault (ErrNotFound for an unknown or deleted vault, ErrNotAVault for a
// server, ErrNotFound for another vault's or an unknown id).
//
// The job run that owns the import (a claim naming the import's job) reads it of a vault that was deleted
// or disabled meanwhile too: the handler must see it to end it; the check is for every other read.
func (s *Service) Import(ctx context.Context, vault, id uuid.UUID) (KVImport, error) {
	im, err := readImport(ctx, s.pool, id, false)
	if err != nil {
		if _, job := ClaimFrom(ctx); !job {
			if verr := s.liveVault(ctx, vault); verr != nil {
				return KVImport{}, verr
			}
		}
		return KVImport{}, err
	}
	// Only the claim of the import's own job skips the vault check: an invented claim reads nothing of a
	// vault that is gone.
	if c, job := ClaimFrom(ctx); !job || im.JobID == nil || c.JobID != *im.JobID {
		if err := s.liveVault(ctx, vault); err != nil {
			return KVImport{}, err
		}
	}
	if im.VaultID != vault {
		return KVImport{}, ErrNotFound
	}
	return im, nil
}

// ImportFilter selects imports of one vault, newest first. CertificateID is the certificate Alice holds
// (kv_imports.certificate_id); CertificateName is the name in the vault, folded with lower(name COLLATE "C");
// both are applied in SQL before the limit. Cursor is the NextCursor of the previous page, bound to the vault
// it came from (another vault's cursor is a validation error); Limit is 1..200 (0 = 50).
type ImportFilter struct {
	CertificateID   uuid.UUID
	CertificateName string
	Cursor          string
	Limit           int
}

// ImportPage is one page of imports.
type ImportPage struct {
	Items      []KVImport
	NextCursor string
}

func encodeImportCursor(vault uuid.UUID, at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(vault.String() + "|" + at.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeImportCursor(c string, vault uuid.UUID) (time.Time, uuid.UUID, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || parts[0] != vault.String() {
		return time.Time{}, uuid.Nil, false
	}
	at, err1 := time.Parse(time.RFC3339Nano, parts[1])
	id, err2 := uuid.Parse(parts[2])
	if err1 != nil || err2 != nil {
		return time.Time{}, uuid.Nil, false
	}
	return at, id, true
}

// ListImportsPage lists the imports of a live vault (liveVault: ErrNotFound / ErrNotAVault), filtered in SQL
// and paged by keyset on (created_at, id), newest first.
func (s *Service) ListImportsPage(ctx context.Context, vault uuid.UUID, f ImportFilter) (ImportPage, error) {
	var errs validate.Errors
	limit := f.Limit
	switch {
	case limit == 0:
		limit = 50
	case limit < 1 || limit > 200:
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
	}
	if f.CertificateName != "" && !azureid.ValidObjectName(f.CertificateName) {
		errs.Add("certificate_name", validate.Pattern, nil)
	}
	var cAt *time.Time
	cID := uuid.Nil
	if f.Cursor != "" {
		at, id, ok := decodeImportCursor(f.Cursor, vault)
		if !ok {
			errs.Add("cursor", validate.Pattern, nil)
		} else {
			cAt, cID = &at, id
		}
	}
	if len(errs) > 0 {
		return ImportPage{}, errs
	}
	if err := s.liveVault(ctx, vault); err != nil {
		return ImportPage{}, err
	}
	rows, err := s.pool.Query(ctx, "SELECT "+importColumns+` FROM kv_imports i WHERE i.target_id = $1
  AND ($2::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR i.certificate_id = $2)
  AND ($3 = '' OR lower(i.name COLLATE "C") = lower($3::text COLLATE "C"))
  AND ($4::timestamptz IS NULL OR (i.created_at, i.id) < ($4, $5::uuid))
ORDER BY i.created_at DESC, i.id DESC LIMIT $6`, vault, f.CertificateID, f.CertificateName, cAt, cID, limit+1)
	if err != nil {
		return ImportPage{}, fmt.Errorf("inventory: list the imports: %w", err)
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (KVImport, error) { return scanImport(r) })
	if err != nil {
		return ImportPage{}, err
	}
	page := ImportPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = encodeImportCursor(vault, last.CreatedAt, last.ID)
	}
	return page, nil
}

// ListImports lists the vault's imports, newest first (limit 1..200): ListImportsPage without a filter or a
// cursor. It checks the vault like every vault-scoped read.
func (s *Service) ListImports(ctx context.Context, vault uuid.UUID, limit int) ([]KVImport, error) {
	if limit < 1 || limit > 200 {
		var errs validate.Errors
		errs.Add("limit", validate.OutOfRange, map[string]string{"min": "1", "max": "200"})
		return nil, errs
	}
	p, err := s.ListImportsPage(ctx, vault, ImportFilter{Limit: limit})
	return p.Items, err
}

// mapImportError turns the database's refusals into closed errors: the history trigger (Z1007) and the
// one-active-import index.
func mapImportError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "Z1007":
			return ErrImportState
		case pgErr.Code == "23505" && pgErr.ConstraintName == "kv_imports_one_active":
			return ErrImportInProgress
		}
	}
	return err
}

// RequestImport queues the import of a certificate Alice holds, with its key, into a vault under name.
// Only an Administrator may (ErrAdminRequired: a private key leaves Alice, ruling S6); the license gate must
// be open (license.ErrLocked, L-26). Refusals, in this order, each audited kv.import.denied after the
// rollback (nothing is stored): validate.Errors on name; ErrNotFound (unknown vault or certificate),
// ErrNotAVault, ErrVaultUnavailable (disabled vault); ErrNoPrivateKey; ErrUnsupportedKey;
// ErrCertificateExpired (the leaf must be valid now: an expired leaf is refused before any PFX is built);
// ErrImportInProgress (an import of that name, ASCII-folded, is queued, sent or not confirmed yet);
// *ImportConfirmError / ErrImportConfirmNeeded (the vault's stored inventory has that name and the request
// does not confirm a new version, ruling S9). The stored import records NewVersion (the confirmation was
// needed and given) and the leaf's SHA-1 thumbprint, which is how a poll recognises it. One
// kv.import job is queued in the same transaction (target the vault, payload import_id, dedupe
// "kv.import:<id>"). Audited kv.import.requested.
func (s *Service) RequestImport(ctx context.Context, a Actor, in ImportInput) (KVImport, error) {
	details := func() map[string]string {
		d := map[string]string{"certificate_id": in.CertificateID.String()}
		if azureid.ValidObjectName(in.Name) {
			d["certificate_name"] = in.Name
		}
		return d
	}
	deny := func(reason string, err error) (KVImport, error) {
		s.auditBindingDenial(ctx, a, "kv.import.denied", "target", in.VaultID, denialDetails(bindingDenial{reason: reason}, details()))
		return KVImport{}, err
	}
	if a.Role != rbac.Admin {
		return deny("admin_required", ErrAdminRequired)
	}
	var errs validate.Errors
	if in.VaultID == uuid.Nil {
		errs.Add("vault_id", validate.Required, nil)
	}
	if in.CertificateID == uuid.Nil {
		errs.Add("certificate_id", validate.Required, nil)
	}
	if !azureid.ValidObjectName(in.Name) {
		errs.Add("name", validate.Pattern, nil)
	}
	if len(errs) > 0 {
		_, _ = deny("invalid_request", nil)
		return KVImport{}, errs
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return KVImport{}, s.auditLicenseRefusal(ctx, a, err, "kv.import.denied", "target", in.VaultID, details())
	}
	var (
		out    KVImport
		denial *bindingDenial
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		out, denial = KVImport{}, nil
		t, err := readKVTarget(ctx, tx, in.VaultID, "FOR NO KEY UPDATE")
		switch {
		case errors.Is(err, ErrNotFound):
			return denyWith(&denial, "vault_not_found", uuid.Nil, ErrNotFound)
		case errors.Is(err, ErrNotAVault):
			return denyWith(&denial, "not_a_vault", uuid.Nil, ErrNotAVault)
		case err != nil:
			return err
		case t.deleted:
			return denyWith(&denial, "vault_not_found", uuid.Nil, ErrNotFound)
		case t.status == StatusDisabled:
			return denyWith(&denial, "vault_unavailable", uuid.Nil, ErrVaultUnavailable)
		}
		c, err := readImportCertificate(ctx, tx, in.CertificateID)
		if errors.Is(err, ErrNotFound) {
			return denyWith(&denial, "certificate_not_found", uuid.Nil, ErrNotFound)
		}
		if err != nil {
			return err
		}
		// The private key leaves the certificate's service for the vault's (R49, design §5.6 (c)).
		if err := authz.CheckTrust(ctx, tx, c.service, t.service); errors.Is(err, ErrServiceUntrusted) {
			return denyWith(&denial, ReasonServiceUntrusted, uuid.Nil, err)
		} else if err != nil {
			return err
		}
		now := s.clock.Now().UTC()
		switch {
		case c.keyID == nil:
			return denyWith(&denial, "no_private_key", uuid.Nil, ErrNoPrivateKey)
		case c.algorithm != "rsa" && c.algorithm != "ecdsa":
			return denyWith(&denial, "unsupported_key", uuid.Nil, ErrUnsupportedKey)
		case !now.Before(c.notAfter):
			return denyWith(&denial, "expired", uuid.Nil, ErrCertificateExpired)
		case now.Before(c.notBefore):
			return denyWith(&denial, "not_yet_valid", uuid.Nil, ErrCertificateNotYetValid)
		}
		parsed, err := parseImportLeaf(c)
		if err != nil {
			return denyWith(&denial, "certificate_invalid", uuid.Nil, err)
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM kv_imports WHERE target_id = $1 AND lower(name COLLATE "C") = lower($2::text COLLATE "C")
AND state IN ('queued', 'running', 'uncertain'))`, in.VaultID, in.Name).Scan(&active); err != nil {
			return fmt.Errorf("inventory: look for an open import: %w", err)
		}
		if active {
			return denyWith(&denial, "in_progress", uuid.Nil, ErrImportInProgress)
		}
		// A stored certificate of that name needs the confirmation whether or not the vault lists it now (a
		// missing certificate can come back, and a live binding would deploy what is imported).
		var (
			existing         string
			bound, autoDeply bool
		)
		err = tx.QueryRow(ctx, `SELECT kc.name, b.id IS NOT NULL, coalesce(b.auto_deploy, false) FROM kv_certificates kc
LEFT JOIN bindings b ON b.kv_certificate_id = kc.id AND b.deleted_at IS NULL
WHERE kc.target_id = $1 AND lower(kc.name COLLATE "C") = lower($2::text COLLATE "C")`, in.VaultID, in.Name).Scan(&existing, &bound, &autoDeply)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: look for the certificate name: %w", err)
		}
		if existing != "" && !in.ConfirmExisting {
			return denyWith(&denial, "confirm_needed", uuid.Nil, &ImportConfirmError{CertificateName: existing, Bound: bound, AutoDeploy: autoDeply})
		}
		// The confirmation is recorded as the user gave it, also for a name the inventory does not know: the
		// vault may have it (an import refused with "the name exists" is then asked again, not looped).
		confirmed := existing != "" || in.ConfirmExisting
		thumb := azureid.ThumbprintOf(parsed.Leaf.Raw)
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, requested_by, created_at)
VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8)`, id, in.CertificateID, in.VaultID, in.Name, confirmed, thumb, nullableUser(a.UserID), now); err != nil {
			if mapped := mapImportError(err); errors.Is(mapped, ErrImportInProgress) {
				return denyWith(&denial, "in_progress", uuid.Nil, mapped)
			}
			return fmt.Errorf("inventory: store the import: %w", err)
		}
		jobID, err := s.jobs.EnqueueTx(ctx, tx, JobRequest{Type: JobKVImport, TargetID: in.VaultID, Payload: map[string]string{"import_id": id.String()},
			Kind: a.jobKind(), CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: "kv.import:" + id.String()})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE kv_imports SET job_id = $2 WHERE id = $1", id, jobID); err != nil {
			return fmt.Errorf("inventory: link the import's job: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "kv.import.requested", ObjectType: "kv_import", ObjectID: id.String(),
			Result: audit.Success, Details: map[string]string{"import_id": id.String(), "certificate_id": in.CertificateID.String(), "certificate_name": in.Name,
				"thumbprint": thumb, "new_version": strconv.FormatBool(confirmed), "vault_url": t.url, "job_id": jobID.String()}}); err != nil {
			return err
		}
		out, err = readImport(ctx, tx, id, false)
		return err
	})
	if err != nil {
		return KVImport{}, s.finishDenial(ctx, a, err, denial, "kv.import.denied", "target", in.VaultID, details())
	}
	return out, nil
}

// importCertificate is the stored certificate an import sends.
type importCertificate struct {
	id          uuid.UUID
	keyID       *uuid.UUID
	notBefore   time.Time
	notAfter    time.Time
	pemChain    string
	fingerprint string
	algorithm   string
	bits        int
	service     uuid.UUID // the owning service (R49): the source of the key an import moves into a vault
}

func readImportCertificate(ctx context.Context, tx pgx.Tx, id uuid.UUID) (importCertificate, error) {
	c := importCertificate{id: id}
	err := tx.QueryRow(ctx, `SELECT private_key_id, not_before, not_after, pem_chain, fingerprint_sha256, key_algorithm, key_bits, service_id
FROM certificates WHERE id = $1 FOR SHARE`, id).
		Scan(&c.keyID, &c.notBefore, &c.notAfter, &c.pemChain, &c.fingerprint, &c.algorithm, &c.bits, &c.service)
	if errors.Is(err, pgx.ErrNoRows) {
		return importCertificate{}, ErrNotFound
	}
	if err != nil {
		return importCertificate{}, fmt.Errorf("inventory: read the certificate: %w", err)
	}
	c.notBefore, c.notAfter = c.notBefore.UTC(), c.notAfter.UTC()
	return c, nil
}

// parseImportLeaf parses the stored chain; its leaf must be the row's certificate.
func parseImportLeaf(c importCertificate) (certs.Parsed, error) {
	p, err := certs.ParseChainPEM([]byte(c.pemChain))
	if err != nil {
		return certs.Parsed{}, ErrCertificateInvalid
	}
	if p.Fingerprint != c.fingerprint {
		return certs.Parsed{}, ErrCertificateInvalid
	}
	return p, nil
}

// ImportMaterial builds the provider request of a queued import: the stored chain and key as a PFX
// (certs.ExportPFX, empty password) with KeyType, KeySize and LeafThumbprint taken from the same leaf and
// key that go into it. Fenced by the job's claim (ErrClaimLost); only a queued import (ErrImportState: an
// import that was sent is never built again); ErrNotFound for an unknown import or a deleted vault,
// ErrVaultUnavailable for a disabled one; ErrAdminRequired (the requester is no longer an enabled
// Administrator); ErrCertificateExpired and ErrCertificateNotYetValid (the leaf is judged again now, before the
// key is read); ErrImportChanged (the stored leaf is no longer the request's thumbprint). The decrypted key
// and every intermediate buffer are wiped on every path, a panic included; the PFX is the caller's to zero
// (Request.PFX) and is never stored, logged or audited.
func (s *Service) ImportMaterial(ctx context.Context, id uuid.UUID) (ImportMaterial, error) {
	var (
		im    KVImport
		c     importCertificate
		vault kvTarget
	)
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		var err error
		if im, err = readImport(ctx, tx, id, false); err != nil {
			return err
		}
		if im.State != ImportQueued {
			return ErrImportState
		}
		if vault, err = readKVTarget(ctx, tx, im.VaultID, ""); err != nil {
			return err
		}
		if vault.deleted {
			return ErrNotFound
		}
		if vault.status == StatusDisabled {
			return ErrVaultUnavailable
		}
		// The requester must still be an enabled Administrator: a queued import survives a licence lock, so
		// days can pass between the request and the job.
		var admin bool
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT role = 'admin' AND disabled_at IS NULL FROM users WHERE id = $1), false)`,
			im.RequestedBy).Scan(&admin); err != nil {
			return fmt.Errorf("inventory: read the requester: %w", err)
		}
		if !admin {
			return ErrAdminRequired
		}
		if c, err = readImportCertificate(ctx, tx, im.CertificateID); err != nil {
			return err
		}
		// Judged again before the vault is called: a trust removed since the request stops the import (R49).
		return authz.CheckTrust(ctx, tx, c.service, vault.service)
	})
	if err != nil {
		return ImportMaterial{}, err
	}
	if c.keyID == nil {
		return ImportMaterial{}, ErrNoPrivateKey
	}
	now := s.clock.Now().UTC()
	if !now.Before(c.notAfter) {
		return ImportMaterial{}, ErrCertificateExpired
	}
	if now.Before(c.notBefore) {
		return ImportMaterial{}, ErrCertificateNotYetValid
	}
	parsed, err := parseImportLeaf(c)
	if err != nil {
		return ImportMaterial{}, err
	}
	if azureid.ThumbprintOf(parsed.Leaf.Raw) != im.Thumbprint {
		return ImportMaterial{}, ErrImportChanged
	}
	der, err := s.loadKey(ctx, s.pool, *c.keyID)
	if err != nil {
		return ImportMaterial{}, err
	}
	defer der.Zero()
	if importMaterialHook != nil {
		importMaterialHook("der", der.Bytes())
	}
	info, err := certs.KeyInfoOf(der)
	if err != nil {
		return ImportMaterial{}, err
	}
	pfx, err := certs.ExportPFX(der, parsed)
	if err != nil {
		return ImportMaterial{}, err
	}
	handedOut := false
	defer func() {
		if !handedOut { // a panic, or a later failure: the PFX never leaves
			pfx.Zero()
		}
	}()
	if importMaterialHook != nil {
		importMaterialHook("pfx", pfx.Bytes())
	}
	handedOut = true
	return ImportMaterial{VaultID: im.VaultID, Request: providers.ImportRequest{OperationID: im.ID, Name: im.Name, PFX: pfx,
		KeyType: info.Algorithm, KeySize: info.Bits, LeafThumbprint: im.Thumbprint, ReplaceExisting: im.NewVersion}}, nil
}

// MarkImportSent records, fenced by the job's claim, that the request is about to be handed to the
// provider: queued becomes running and sent_at is set (once). It must be called right before the provider
// is, and the provider is called only when it returned nil: an import that was marked is never sent again.
// ErrImportState for an import that is not queued.
func (s *Service) MarkImportSent(ctx context.Context, id uuid.UUID) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "UPDATE kv_imports SET state = 'running', sent_at = $2 WHERE id = $1 AND state = 'queued'", id, s.clock.Now().UTC())
		if err != nil {
			return mapImportError(fmt.Errorf("inventory: mark the import sent: %w", err))
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		if _, err := readImport(ctx, tx, id, false); err != nil {
			return err
		}
		return ErrImportState
	})
}

// importFailure reads a provider's refusal or cause as a closed code and allowlisted params (D5: the
// Azure params the deployment records keep, bounded; the text of a cause is never read).
func importFailure(cause error) (string, map[string]string) {
	var pe *providers.Error
	if !errors.As(cause, &pe) || !errorCodeRE.MatchString(pe.Code) {
		return "", map[string]string{}
	}
	if pe.Code == providers.CodeKVImportNameExists {
		return ReasonImportConfirmNeeded, map[string]string{}
	}
	return pe.Code, boundParams(pe.Params, errorParamKeys)
}

// FinishImport records what the provider returned, fenced by the job's claim; the import must be running
// (refused is also accepted for a queued one). A result that breaks the provider contract
// (providers.CheckImportReturn), or a "created" for another leaf than the request's, is uncertain. The
// outcomes: created -> succeeded, the version stored in the vault's rows in this transaction (the
// certificate row and the version row, its pointer moved to it, details known, as a poll would store
// them; the version is held only if the license gate is closed), audited kv.import.succeeded (and the
// vault's new-version row audit when the name existed); refused -> failed with the provider's closed code
// (kv.import_name_exists becomes kv.import_confirm_needed) and allowlisted params, audited
// kv.import.failed, one kv.import_failed mail; uncertain -> uncertain, audited kv.import.uncertain, no
// mail (a poll settles it, or after ImportOutcomeUnknownAfter it fails as outcome unknown). A finished
// import, or any other state, is ErrImportState. The returned import is its state afterwards.
func (s *Service) FinishImport(ctx context.Context, id uuid.UUID, res providers.ImportResult, cause error) (KVImport, error) {
	if err := providers.CheckImportReturn(res, cause); err != nil {
		res, cause = providers.ImportResult{Outcome: providers.ImportUncertain}, err
	}
	var out KVImport
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		im, err := readImport(ctx, tx, id, false)
		if err != nil {
			return err
		}
		vault, err := readKVTarget(ctx, tx, im.VaultID, "FOR NO KEY UPDATE")
		if err != nil {
			return err
		}
		if im, err = readImport(ctx, tx, id, true); err != nil {
			return err
		}
		if res.Outcome == providers.ImportCreated && res.Thumbprint != im.Thumbprint {
			res, cause = providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("the vault created another certificate than the one sent")
		}
		allowed := im.State == ImportRunning || (res.Outcome == providers.ImportRefused && im.State == ImportQueued)
		if !allowed {
			return ErrImportState
		}
		now := s.clock.Now().UTC()
		code, params := importFailure(cause)
		rawParams, err := json.Marshal(params)
		if err != nil {
			return err
		}
		details := map[string]string{"import_id": id.String(), "certificate_id": im.CertificateID.String(), "certificate_name": im.Name,
			"thumbprint": im.Thumbprint, "vault_url": vault.url}
		var event audit.Event
		switch res.Outcome {
		case providers.ImportCreated:
			if !vault.deleted {
				if err := s.storeImported(ctx, tx, im, vault, res, now); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE kv_imports SET state = 'succeeded', version = $2, error_code = '', error_params = '{}', finished_at = $3
WHERE id = $1 AND state = 'running' AND finished_at IS NULL`, id, res.Version, now); err != nil {
				return mapImportError(fmt.Errorf("inventory: finish the import: %w", err))
			}
			details["version"] = res.Version
			event = audit.Event{Action: "kv.import.succeeded", Result: audit.Success}
		case providers.ImportRefused:
			if code == "" {
				code = ReasonInternal
			}
			if _, err := tx.Exec(ctx, `UPDATE kv_imports SET state = 'failed', error_code = $2, error_params = $3, finished_at = $4
WHERE id = $1 AND state IN ('queued', 'running') AND finished_at IS NULL`, id, code, rawParams, now); err != nil {
				return mapImportError(fmt.Errorf("inventory: finish the import: %w", err))
			}
			details["reason"] = code
			event = audit.Event{Action: "kv.import.failed", Result: audit.Failure}
			if err := s.mailImport(ctx, tx, id, TemplateKVImportFailed, vault.name, im.Name); err != nil {
				return err
			}
		default: // uncertain
			if _, err := tx.Exec(ctx, `UPDATE kv_imports SET state = 'uncertain', error_code = $2, error_params = $3
WHERE id = $1 AND state = 'running' AND finished_at IS NULL`, id, code, rawParams); err != nil {
				return mapImportError(fmt.Errorf("inventory: finish the import: %w", err))
			}
			if code != "" {
				details["reason"] = code
			}
			event = audit.Event{Action: "kv.import.uncertain", Result: audit.Success}
		}
		event.Actor, event.ObjectType, event.ObjectID, event.Details = jobsActor, "kv_import", id.String(), details
		if _, err := s.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		out, err = readImport(ctx, tx, id, false)
		return err
	})
	return out, err
}

// FailQueuedImport ends a queued import that will not be sent (its vault was disabled or deleted before
// the job ran) as failed with the closed code, fenced by the job's claim: audited kv.import.failed, one
// kv.import_failed mail. ErrImportState for an import that is not queued; code must be a closed reason.
func (s *Service) FailQueuedImport(ctx context.Context, id uuid.UUID, code string) (KVImport, error) {
	if !errorCodeRE.MatchString(code) {
		var errs validate.Errors
		errs.Add("code", validate.Pattern, nil)
		return KVImport{}, errs
	}
	var out KVImport
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		im, err := readImport(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if im.State != ImportQueued {
			return ErrImportState
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE kv_imports SET state = 'failed', error_code = $2, finished_at = $3
WHERE id = $1 AND state = 'queued' AND finished_at IS NULL`, id, code, now); err != nil {
			return mapImportError(fmt.Errorf("inventory: fail the import: %w", err))
		}
		var name, url string
		if err := tx.QueryRow(ctx, "SELECT name::text, coalesce(config->>'vault_url', '') FROM targets WHERE id = $1", im.VaultID).Scan(&name, &url); err != nil {
			return fmt.Errorf("inventory: read the import's vault: %w", err)
		}
		if err := s.mailImport(ctx, tx, id, TemplateKVImportFailed, name, im.Name); err != nil {
			return err
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.import.failed", ObjectType: "kv_import", ObjectID: id.String(),
			Result: audit.Failure, Details: map[string]string{"import_id": id.String(), "certificate_id": im.CertificateID.String(), "certificate_name": im.Name,
				"thumbprint": im.Thumbprint, "vault_url": url, "reason": code}}); err != nil {
			return err
		}
		out, err = readImport(ctx, tx, id, false)
		return err
	})
	return out, err
}

// mailImport queues an import's e-mail for its vault's service (R56).
func (s *Service) mailImport(ctx context.Context, tx pgx.Tx, importID uuid.UUID, template, vaultName, certificateName string) error {
	if s.notifier == nil {
		return nil
	}
	svcs, err := servicesOf(ctx, tx, "SELECT t.service_id FROM kv_imports i JOIN targets t ON t.id = i.target_id WHERE i.id = $1", importID)
	if err != nil {
		return err
	}
	if err := s.notifier.NotifyServices(ctx, tx, svcs, template, map[string]string{"target_name": vaultName, "certificate_name": certificateName}); err != nil {
		return fmt.Errorf("inventory: queue the import's email: %w", err)
	}
	return nil
}

// storeImported writes the vault's rows for a version the vault created, in the transaction of the
// import's outcome and with the vault row locked: the same rows the next poll will store (the certificate
// row, its current version, the leaf row of the certificate Alice holds), through the poll's own code.
// The vault gives no creation time, so the version's kv_created_at stays NULL (the planner then judges it
// by its detection time, now) and its listing time unknown: the next poll reads the details again and
// finds the version stored, so nothing is announced twice.
func (s *Service) storeImported(ctx context.Context, tx pgx.Tx, im KVImport, vault kvTarget, res providers.ImportResult, now time.Time) error {
	leaf, err := certs.ParseChainPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.CER}))
	if err != nil {
		return fmt.Errorf("inventory: read the imported leaf: %w", err)
	}
	var keyType string
	var keySize int
	if err := tx.QueryRow(ctx, "SELECT key_algorithm, key_bits FROM certificates WHERE id = $1", im.CertificateID).Scan(&keyType, &keySize); err != nil {
		return fmt.Errorf("inventory: read the imported certificate's key type: %w", err)
	}
	nb, exp := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	item := kvCert{name: im.Name, fold: foldASCII(im.Name), thumb: res.Thumbprint, enabled: true, notBefore: &nb, expires: &exp,
		details: &kvDetails{version: res.Version, thumb: res.Thumbprint, leaf: leaf, complete: certs.ChainComplete(leaf, s.roots, now),
			exportable: ptrBool(true), keyType: keyType, keySize: keySize, contentType: "pkcs12", issuer: "Unknown",
			attrs: kvVersion{version: res.Version, thumb: res.Thumbprint, enabled: true, notBefore: &nb, expires: &exp}}}
	var (
		st     kvStored
		events []audit.Event
	)
	moved, err := s.storeDetailedCerts(ctx, tx, im.VaultID, vault, []kvCert{item}, now, kvHold{closed: s.gateClosedNow()}, &st, &events)
	if err != nil {
		return err
	}
	if len(moved) > 0 { // a version id Alice knows with another thumbprint: keep what is stored, the poll will say
		if _, err := upsertListedCerts(ctx, tx, im.VaultID, moved, now); err != nil {
			return err
		}
	}
	for _, e := range events {
		if _, err := s.audit.Append(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

func ptrBool(b bool) *bool { return &b }

// resolveImports settles the uncertain imports of the vault from what the poll stored (S14), in the
// poll's final transaction (the vault's row is locked): an uncertain import becomes succeeded, with that
// version, when a stored version of a certificate of that name (ASCII-folded) has the import's thumbprint
// and an Azure creation time, in whole seconds, not earlier than the request's second; a version without
// a creation time cannot settle it, and a certificate with that thumbprint that existed before the request
// does not: neither does a version Alice stored before the import was sent (detected_at, Alice's own clock, so
// an Azure clock ahead of Alice's cannot make an older version match) nor one another import of the name
// already settled on. Azure's clock behind Alice's by a second or more still keeps the real version from
// matching (documented). ImportOutcomeUnknownAfter after the send, a poll whose certificate listing was complete
// (complete) and that found no such version ends the import failed with kv.import_outcome_unknown, one
// mail (not while a certificate of that name still waits for its details). Audited kv.import.settled /
// kv.import.failed. Finished imports are never touched (WHERE finished_at IS NULL). An import whose vault
// is unreachable for the whole time is ended by SweepImports ImportOutcomeUnknownCap after its send; one whose
// vault is deleted is ended by the deletion (endVaultImports).
func (s *Service) resolveImports(ctx context.Context, tx pgx.Tx, vault uuid.UUID, now time.Time, complete bool) error {
	rows, err := tx.Query(ctx, `SELECT id, certificate_id, name, thumbprint, created_at, sent_at FROM kv_imports
WHERE target_id = $1 AND state = 'uncertain' AND finished_at IS NULL ORDER BY id FOR UPDATE`, vault)
	if err != nil {
		return fmt.Errorf("inventory: read the uncertain imports: %w", err)
	}
	type open struct {
		id, certificate uuid.UUID
		name, thumb     string
		created         time.Time
		sent            *time.Time
	}
	pending, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (open, error) {
		var o open
		return o, r.Scan(&o.id, &o.certificate, &o.name, &o.thumb, &o.created, &o.sent)
	})
	if err != nil {
		return fmt.Errorf("inventory: read the uncertain imports: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	var vaultName, vaultURL string
	if err := tx.QueryRow(ctx, "SELECT name::text, coalesce(config->>'vault_url', '') FROM targets WHERE id = $1", vault).Scan(&vaultName, &vaultURL); err != nil {
		return fmt.Errorf("inventory: read the vault: %w", err)
	}
	for _, o := range pending {
		var version string
		err := tx.QueryRow(ctx, `SELECT v.version FROM kv_certificate_versions v JOIN kv_certificates kc ON kc.id = v.kv_certificate_id
WHERE kc.target_id = $1 AND lower(kc.name COLLATE "C") = lower($2::text COLLATE "C") AND v.thumbprint = $3
  AND v.kv_created_at IS NOT NULL AND v.kv_created_at >= date_trunc('second', $4::timestamptz)
  AND v.detected_at >= coalesce($6::timestamptz, $4::timestamptz)
  AND NOT EXISTS (SELECT 1 FROM kv_imports o2 WHERE o2.target_id = $1 AND o2.id <> $5 AND o2.state = 'succeeded' AND o2.version = v.version
    AND lower(o2.name COLLATE "C") = lower($2::text COLLATE "C"))
ORDER BY v.kv_created_at, v.id LIMIT 1`, vault, o.name, o.thumb, o.created, o.id, o.sent).Scan(&version)
		details := map[string]string{"import_id": o.id.String(), "certificate_id": o.certificate.String(), "certificate_name": o.name,
			"thumbprint": o.thumb, "vault_url": vaultURL}
		switch {
		case err == nil:
			tag, err := tx.Exec(ctx, `UPDATE kv_imports SET state = 'succeeded', version = $2, error_code = '', error_params = '{}', finished_at = $3
WHERE id = $1 AND state = 'uncertain' AND finished_at IS NULL`, o.id, version, now)
			if err != nil {
				return mapImportError(fmt.Errorf("inventory: settle the import: %w", err))
			}
			if tag.RowsAffected() == 1 {
				details["version"] = version
				if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.import.settled", ObjectType: "kv_import", ObjectID: o.id.String(),
					Result: audit.Success, Details: details}); err != nil {
					return err
				}
			}
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("inventory: look for the imported version: %w", err)
		case o.sent != nil && !now.Before(o.sent.Add(ImportOutcomeUnknownCap)):
			// Whatever the listings looked like: an import cannot stay uncertain for ever.
			if err := s.endImport(ctx, tx, o.id, o.certificate, o.name, o.thumb, ReasonImportOutcomeUnknown, now, vaultName, vaultURL, TemplateKVImportOutcomeUnknown); err != nil {
				return err
			}
		case complete && o.sent != nil && !now.Before(o.sent.Add(ImportOutcomeUnknownAfter)):
			var waiting bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM kv_certificates WHERE target_id = $1 AND lower(name COLLATE "C") = lower($2::text COLLATE "C")
AND missing_since IS NULL AND details_pending)`, vault, o.name).Scan(&waiting); err != nil {
				return fmt.Errorf("inventory: look for pending details: %w", err)
			}
			if waiting {
				continue
			}
			if err := s.endImport(ctx, tx, o.id, o.certificate, o.name, o.thumb, ReasonImportOutcomeUnknown, now, vaultName, vaultURL, TemplateKVImportOutcomeUnknown); err != nil {
				return err
			}
		}
	}
	return nil
}

// endImport ends an active import (queued, running or uncertain) as failed with the closed code, in the
// caller's transaction: one audit row kv.import.failed and, when template is not empty, one mail. Nothing
// happens when the import was finished meanwhile (WHERE finished_at IS NULL).
func (s *Service) endImport(ctx context.Context, tx pgx.Tx, id, certificate uuid.UUID, name, thumb, code string, now time.Time, vaultName, vaultURL, template string) error {
	tag, err := tx.Exec(ctx, `UPDATE kv_imports SET state = 'failed', error_code = $2, finished_at = $3
WHERE id = $1 AND state IN ('queued', 'running', 'uncertain') AND finished_at IS NULL`, id, code, now)
	if err != nil {
		return mapImportError(fmt.Errorf("inventory: end the import: %w", err))
	}
	if tag.RowsAffected() != 1 {
		return nil
	}
	if template != "" {
		if err := s.mailImport(ctx, tx, id, template, vaultName, name); err != nil {
			return err
		}
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.import.failed", ObjectType: "kv_import", ObjectID: id.String(),
		Result: audit.Failure, Details: map[string]string{"import_id": id.String(), "certificate_id": certificate.String(), "certificate_name": name,
			"thumbprint": thumb, "vault_url": vaultURL, "reason": code}})
	return err
}

// endVaultImports ends every active import of a vault that is being deleted, in the deleting transaction:
// a queued one failed with kv.import_vault_deleted (nothing was sent), a running or uncertain one as outcome
// unknown (with its mail). No active import outlives its vault.
func (s *Service) endVaultImports(ctx context.Context, tx pgx.Tx, vault uuid.UUID, vaultName, vaultURL string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT id, certificate_id, name, thumbprint, state FROM kv_imports
WHERE target_id = $1 AND state IN ('queued', 'running', 'uncertain') AND finished_at IS NULL ORDER BY id FOR UPDATE`, vault)
	if err != nil {
		return fmt.Errorf("inventory: read the vault's active imports: %w", err)
	}
	type active struct {
		id, certificate    uuid.UUID
		name, thumb, state string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (active, error) {
		var a active
		return a, r.Scan(&a.id, &a.certificate, &a.name, &a.thumb, &a.state)
	})
	if err != nil {
		return fmt.Errorf("inventory: read the vault's active imports: %w", err)
	}
	for _, a := range list {
		code, tpl := ReasonImportOutcomeUnknown, TemplateKVImportOutcomeUnknown
		if a.state == ImportQueued {
			code, tpl = ReasonImportVaultDeleted, ""
		}
		if err := s.endImport(ctx, tx, a.id, a.certificate, a.name, a.thumb, code, now, vaultName, vaultURL, tpl); err != nil {
			return err
		}
	}
	return nil
}

// SweepImports ends the imports nothing else will end, for the job layer to call periodically (about every
// minute; it needs no poll): an uncertain import ImportOutcomeUnknownCap after its send fails as outcome
// unknown (with its mail), whatever the vault's state; a queued import whose job is succeeded, failed, dead, cancelled or
// gone fails with kv.import_cancelled (nothing was sent); a running one whose job ended becomes uncertain
// (a send may have happened: it is never sent again). It returns how many imports it changed; each ending
// has its audit row; every import is handled in its own transaction under the vault's lock and fenced to the
// job's claim when the context has one.
func (s *Service) SweepImports(ctx context.Context) (int, error) {
	now := s.clock.Now().UTC()
	rows, err := s.pool.Query(ctx, `SELECT i.id, i.target_id FROM kv_imports i LEFT JOIN jobs j ON j.id = i.job_id
WHERE i.finished_at IS NULL AND (
    (i.state = 'uncertain' AND i.sent_at <= $1)
 OR (i.state IN ('queued', 'running') AND (i.job_id IS NULL OR j.id IS NULL OR j.status IN ('succeeded', 'failed', 'cancelled', 'dead'))))
ORDER BY i.id LIMIT $2`, now.Add(-ImportOutcomeUnknownCap), importSweepBatch)
	if err != nil {
		return 0, fmt.Errorf("inventory: find the imports to sweep: %w", err)
	}
	type found struct{ id, vault uuid.UUID }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (found, error) {
		var f found
		return f, r.Scan(&f.id, &f.vault)
	})
	if err != nil {
		return 0, fmt.Errorf("inventory: find the imports to sweep: %w", err)
	}
	changed := 0
	var errs []error
	for _, f := range list {
		did := false
		err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
			did = false
			if err := checkClaim(ctx, tx); err != nil {
				return err
			}
			t, err := readKVTarget(ctx, tx, f.vault, "FOR NO KEY UPDATE")
			if err != nil {
				return err
			}
			var im KVImport
			if im, err = readImport(ctx, tx, f.id, true); err != nil {
				return err
			}
			if im.FinishedAt != nil {
				return nil
			}
			switch {
			case im.State == ImportUncertain && im.SentAt != nil && !now.Before(im.SentAt.Add(ImportOutcomeUnknownCap)):
				did = true
				return s.endImport(ctx, tx, im.ID, im.CertificateID, im.Name, im.Thumbprint, ReasonImportOutcomeUnknown, now, t.name, t.url, TemplateKVImportOutcomeUnknown)
			case im.State == ImportQueued:
				did = true
				return s.endImport(ctx, tx, im.ID, im.CertificateID, im.Name, im.Thumbprint, ReasonImportCancelled, now, t.name, t.url, TemplateKVImportFailed)
			case im.State == ImportRunning:
				did = true
				if _, err := tx.Exec(ctx, "UPDATE kv_imports SET state = 'uncertain' WHERE id = $1 AND state = 'running' AND finished_at IS NULL", im.ID); err != nil {
					return mapImportError(fmt.Errorf("inventory: end the import: %w", err))
				}
				_, err := s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.import.uncertain", ObjectType: "kv_import", ObjectID: im.ID.String(),
					Result: audit.Success, Details: map[string]string{"import_id": im.ID.String(), "certificate_id": im.CertificateID.String(), "certificate_name": im.Name,
						"thumbprint": im.Thumbprint, "vault_url": t.url, "reason": ReasonImportCancelled}})
				return err
			}
			return nil
		})
		if errors.Is(err, ErrClaimLost) {
			return changed, err
		}
		if err != nil && !errors.Is(err, ErrNotFound) { // a vault deleted meanwhile ended its imports already
			errs = append(errs, err)
			continue
		}
		if did && err == nil {
			changed++
		}
	}
	return changed, errors.Join(errs...)
}
