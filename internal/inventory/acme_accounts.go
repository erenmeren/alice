package inventory

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/acme"
	"alice/internal/acme/keygen"
	"alice/internal/acme/transport"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
)

// ACME accounts (plan 2026-10-13 Task 9; design row 4; amendments A6, A10).
//
// One account per provider: an ECDSA P-256 key Alice generates, sealed in acme_accounts.key_* (AAD
// acme_accounts/<id>/key) and never updated: a key rollover is a new row. Registration, rollover and deactivation
// talk to the CA, so each first asks the license gate (Allow(ClassChange): in lock nothing is sent) and then goes
// through the guarded transport built from the provider's own CA bundle.
//
// Rollover (A6): (1) the new key is committed as a pending_rollover row, (2) the CA is asked (keyChange), (3) the old
// row becomes retired and the new one active in one transaction. A rollover the CA did not take deletes its pending
// row (the only account row that is ever deleted, trigger Z1018). When the CA's answer is lost (RolloverUnknown) the
// pending row stays and RecoverACMERollover settles it by asking the CA which key it knows, once the pending key is
// older (database time) than any CA call that may still switch to it (ACMERolloverSettleAge). A settled rollover also
// moves the provider's ACME certificates to the new account row. Registration, rollover, recovery and deactivation of
// one provider are serialized across processes by a PostgreSQL advisory lock held for the whole operation; while a
// rollover is unsettled ACMEAccountSigner signs nothing (ErrACMERolloverPending).
//
// Secrets (A10): the PKCS#8 DER of an account key is plaintext only inside the function that seals or opens it and
// is zeroed before it returns; the crypto.Signer (an *ecdsa.PrivateKey, which Go cannot zero) lives only for the CA
// call. The EAB HMAC text is opened for the registration and zeroed after it. The contact address is personal data:
// it is stored in the account row and never written to an audit row. CA errors reach callers only as *ACMEError (a
// registered reason, never the CA's text).

// Account states (acme_accounts.state).
const (
	ACMEAccountActive          = "active"
	ACMEAccountPendingRollover = "pending_rollover"
	ACMEAccountRetired         = "retired"
	ACMEAccountDeactivated     = "deactivated"
)

const maxACMEContactLen = 254

// Refusals of the account operations.
var (
	// ErrACMEAccountExists: the provider already has an active account (one per provider).
	ErrACMEAccountExists = errors.New("inventory: the ACME provider already has an account")
	// ErrACMEAccountState: the account is not active (retired, deactivated or a pending key), so the operation
	// does not apply to it.
	ErrACMEAccountState = errors.New("inventory: the ACME account is not in a state that allows this")
	// ErrACMERolloverPending: a key rollover of the provider's account is unsettled (the CA's answer was lost, or a
	// rollover is running); RecoverACMERollover settles it.
	ErrACMERolloverPending = errors.New("inventory: a key change of the ACME account is not settled")
	// ErrACMEProviderBusy: another account operation of the provider (in this or another process) holds its lock;
	// nothing was done. The API answers it with ALC-ACM-0024 (acme.rollover_pending, retryable): try again shortly.
	ErrACMEProviderBusy = errors.New("inventory: another change of the ACME account is running")
)

// ACMEError is a failure of a CA exchange: Reason is one of acme.Reasons() (the ALC-ACM reasons the API maps),
// RetryAfter the CA's capped Retry-After of a rate limit. Its text never holds a CA body, URL or secret.
type ACMEError struct {
	Reason     string
	RetryAfter time.Duration
	cause      error // the *acme.Error (whose text is closed) or a transport sentinel
}

func (e *ACMEError) Error() string {
	return "inventory: the certificate authority exchange failed: " + e.Reason
}

// Unwrap gives the *acme.Error (or transport sentinel) behind it.
func (e *ACMEError) Unwrap() error { return e.cause }

// acmeFailure is the single mapping of a CA exchange's error to an *ACMEError: an *acme.Error keeps its reason (one
// outside acme.Reasons() becomes directory_invalid), an unusable CA bundle is tls_trust_failed, a dead context
// stays the context's error, anything else (a client that cannot be built) is directory_invalid.
func acmeFailure(err error) error {
	if err == nil {
		return nil
	}
	var ie *ACMEError
	if errors.As(err, &ie) {
		return ie
	}
	var ae *acme.Error
	if errors.As(err, &ae) {
		reason := ae.Reason
		if !slices.Contains(acme.Reasons(), reason) {
			reason = acme.ReasonDirectoryInvalid
		}
		return &ACMEError{Reason: reason, RetryAfter: ae.RetryAfter(), cause: ae}
	}
	if errors.Is(err, transport.ErrCABundle) {
		return &ACMEError{Reason: acme.ReasonTLSTrustFailed, cause: transport.ErrCABundle}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &ACMEError{Reason: acme.ReasonDirectoryInvalid}
}

// ACMEAccount is the view of an account. It has no secret.
type ACMEAccount struct {
	ID              uuid.UUID  `json:"id"`
	ProviderID      uuid.UUID  `json:"provider_id"`
	ContactEmail    string     `json:"contact_email"`
	AccountURL      string     `json:"account_url"`
	TermsURL        string     `json:"tos_url"`
	TermsAcceptedBy *uuid.UUID `json:"tos_accepted_by,omitempty"`
	TermsAcceptedAt *time.Time `json:"tos_accepted_at,omitempty"`
	State           string     `json:"state"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// accountKeyLocation binds a sealed account key to its row.
func accountKeyLocation(id uuid.UUID) secrets.Location {
	return secrets.Location{Table: "acme_accounts", RowID: id.String(), Column: "key"}
}

// normContact checks an optional contact address: a plain e-mail address (a "mailto:" prefix is dropped), the
// domain in lower case. "" is allowed (some CAs need no contact).
func normContact(raw string) (string, *validate.FieldError) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "mailto:")
	if s == "" {
		return "", nil
	}
	at := strings.IndexByte(s, '@')
	if len(s) > maxACMEContactLen || at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 ||
		strings.ContainsFunc(s, func(r rune) bool { return r <= 0x20 || r >= 0x7f || strings.ContainsRune(",;<>?&%\"'\\()[]:", r) }) {
		return "", &validate.FieldError{Field: "contact_email", Code: validate.Email}
	}
	domain, ok := normDNSSuffix(s[at+1:])
	if !ok || strings.HasPrefix(domain, ".") || !strings.Contains(domain, ".") {
		return "", &validate.FieldError{Field: "contact_email", Code: validate.Email}
	}
	return s[:at+1] + domain, nil
}

const accountColumns = `id, provider_id, contact_email, account_url, tos_url, tos_accepted_by, tos_accepted_at, state, created_by, created_at, updated_at`

func scanAccount(row pgx.Row) (ACMEAccount, error) {
	var a ACMEAccount
	err := row.Scan(&a.ID, &a.ProviderID, &a.ContactEmail, &a.AccountURL, &a.TermsURL, &a.TermsAcceptedBy, &a.TermsAcceptedAt, &a.State,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	if a.TermsAcceptedAt != nil {
		t := a.TermsAcceptedAt.UTC()
		a.TermsAcceptedAt = &t
	}
	return a, err
}

func getACMEAccount(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (ACMEAccount, error) {
	sql := "SELECT " + accountColumns + " FROM acme_accounts WHERE id = $1"
	if forUpdate {
		sql += " FOR UPDATE"
	}
	a, err := scanAccount(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEAccount{}, ErrNotFound
	}
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("inventory: read the ACME account: %w", err)
	}
	return a, nil
}

// GetACMEAccount returns an account (any state).
func (s *Service) GetACMEAccount(ctx context.Context, id uuid.UUID) (ACMEAccount, error) {
	return getACMEAccount(ctx, s.pool, id, false)
}

// ListACMEAccounts returns the accounts of a provider, newest first (ErrNotFound for a provider that is not live).
func (s *Service) ListACMEAccounts(ctx context.Context, providerID uuid.UUID) ([]ACMEAccount, error) {
	if _, err := getACMEProvider(ctx, s.pool, providerID, false); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, "SELECT "+accountColumns+" FROM acme_accounts WHERE provider_id = $1 ORDER BY created_at DESC, id DESC", providerID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list the ACME accounts: %w", err)
	}
	defer rows.Close()
	out := []ACMEAccount{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: read an ACME account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// acmeLockBudget bounds the release of a provider's lock (a stuck database closes the session instead).
const acmeLockBudget = 10 * time.Second

// acmeLockWait is how long a caller tries to take a busy provider's lock, and acmeLockRetry the pause between two
// tries. No connection is held between tries: a waiter never takes a pool connection the holder needs.
const (
	acmeLockWait  = 2 * time.Second
	acmeLockRetry = 100 * time.Millisecond
)

// lockACMEProvider serializes the CA operations of one provider's account (a registration, a rollover, its recovery, a
// deactivation) ACROSS processes: a PostgreSQL session advisory lock, held on a dedicated connection for the whole
// operation, CA calls included. It never blocks inside the database: pg_try_advisory_lock, retried for at most
// acmeLockWait with the connection given back between tries, then ErrACMEProviderBusy. So the holder needs at most one
// more connection for its own work and waiters cannot starve it. release must be called; a lock that cannot be
// released cleanly (or whose session was lost meanwhile) closes its session and logs acme_provider_lock_lost.
func (s *Service) lockACMEProvider(ctx context.Context, id uuid.UUID) (release func(), err error) {
	key := "acme.provider." + id.String()
	for try := 1; ; try++ {
		conn, err := s.pool.Acquire(ctx)
		if err != nil {
			return nil, fmt.Errorf("inventory: database connection for the ACME provider lock: %w", err)
		}
		var got bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1, 0))", key).Scan(&got); err != nil {
			// The lock may have been granted as the query failed: closing the session drops it either way.
			closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), acmeLockBudget)
			_ = conn.Conn().Close(closeCtx)
			cancel()
			conn.Release()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("inventory: take the ACME provider lock: %w", err)
		}
		if got {
			return func() { s.releaseACMEProviderLock(ctx, conn, id, key) }, nil
		}
		conn.Release()
		if try >= int(acmeLockWait/acmeLockRetry) {
			return nil, ErrACMEProviderBusy
		}
		t := time.NewTimer(acmeLockRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// releaseACMEProviderLock gives a provider's lock back. An unlock that fails or finds no lock means the session was
// lost while the operation ran (another process may have overlapped it): WARN acme_provider_lock_lost, and the session
// is closed so nothing stays locked.
func (s *Service) releaseACMEProviderLock(ctx context.Context, conn *pgxpool.Conn, id uuid.UUID, key string) {
	relCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), acmeLockBudget)
	defer cancel()
	var unlocked bool
	if err := conn.QueryRow(relCtx, "SELECT pg_advisory_unlock(hashtextextended($1, 0))", key).Scan(&unlocked); err != nil || !unlocked {
		s.log.Warn("an ACME account operation lost its provider lock while it ran; another process may have overlapped it",
			"provider_id", id.String(), "event", "acme_provider_lock_lost")
		_ = conn.Conn().Close(relCtx)
	}
	conn.Release()
}

// acmeClientFor builds a client of the provider's directory through the guarded transport with the provider's CA
// bundle. key may be nil (Discover only).
func (s *Service) acmeClientFor(p ACMEProvider, key crypto.Signer, accountURL string) (*acme.Client, error) {
	hc, err := s.acmeTransport(p.CABundlePEM)
	if err != nil {
		return nil, acmeFailure(err)
	}
	c, err := acme.New(acme.Config{DirectoryURL: p.DirectoryURL, Key: key, AccountURL: accountURL, HTTPClient: hc, Now: s.clock.Now})
	if err != nil {
		return nil, acmeFailure(err)
	}
	return c, nil
}

// acmeBaseRoots is Config.ACMERoots' pool (nil: the system roots). A trust file that cannot be read fails closed
// as an unusable CA bundle (tls_trust_failed).
func (s *Service) acmeBaseRoots() (*x509.CertPool, error) {
	if s.acmeRoots == nil {
		return nil, nil
	}
	pool, err := s.acmeRoots()
	if err != nil {
		return nil, transport.ErrCABundle
	}
	return pool, nil
}

// acmeTransport is the guarded transport with bundle added to the CA trust (Config.ACMERoots or the system roots).
func (s *Service) acmeTransport(bundle string) (*http.Client, error) {
	base, err := s.acmeBaseRoots()
	if err != nil {
		return nil, err
	}
	return transport.NewWithRoots(bundle, base)
}

// newAccountKey generates an ECDSA P-256 account key and seals it for row id; the DER is zeroed before it returns.
func (s *Service) newAccountKey(id uuid.UUID) (crypto.Signer, secrets.Envelope, error) {
	k, err := keygen.Generate(keygen.ECDSAP256)
	if err != nil {
		return nil, secrets.Envelope{}, fmt.Errorf("inventory: generate the ACME account key: %w", err)
	}
	defer k.Zero()
	env, err := s.keyring.Seal(accountKeyLocation(id), k.DER.Bytes())
	if err != nil {
		return nil, secrets.Envelope{}, fmt.Errorf("inventory: seal the ACME account key: %w", err)
	}
	return k.Signer, env, nil
}

// openAccountKey opens account id's sealed key; the DER is zeroed before it returns (the Signer outlives it, A10).
func (s *Service) openAccountKey(ctx context.Context, q db.Querier, id uuid.UUID) (crypto.Signer, error) {
	var env secrets.Envelope
	err := q.QueryRow(ctx, "SELECT key_ct, key_nonce, key_wrapped_dek, key_version FROM acme_accounts WHERE id = $1", id).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("inventory: read the ACME account key: %w", err)
	}
	der, err := s.keyring.Open(accountKeyLocation(id), env)
	if err != nil {
		return nil, ErrACMESecretUnreadable
	}
	defer der.Zero()
	k, err := keygen.ParsePKCS8(der)
	if err != nil {
		return nil, ErrACMESecretUnreadable
	}
	return k.Signer, nil
}

// ACMEAccountSigner opens the key of an active account for an order (Task 10): the signer and the account URL (the
// JWS kid). ErrNotFound, ErrACMEAccountState for an account that is not active or whose provider is deleted,
// ErrACMERolloverPending while a key rollover of the provider is unsettled, ErrACMESecretUnreadable. The DER is zeroed before it returns; the caller keeps the signer only for its CA calls.
func (s *Service) ACMEAccountSigner(ctx context.Context, accountID uuid.UUID) (crypto.Signer, string, error) {
	var state, url string
	var live, pending bool
	err := s.pool.QueryRow(ctx, `SELECT a.state, a.account_url, p.deleted_at IS NULL,
EXISTS (SELECT 1 FROM acme_accounts n WHERE n.provider_id = a.provider_id AND n.state = 'pending_rollover')
FROM acme_accounts a JOIN acme_providers p ON p.id = a.provider_id WHERE a.id = $1`, accountID).Scan(&state, &url, &live, &pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("inventory: read the ACME account: %w", err)
	}
	if state != ACMEAccountActive || !live || url == "" {
		return nil, "", ErrACMEAccountState
	}
	if pending {
		return nil, "", ErrACMERolloverPending // the CA may already hold the new key: sign nothing until it is settled
	}
	signer, err := s.openAccountKey(ctx, s.pool, accountID)
	if err != nil {
		return nil, "", err
	}
	return signer, url, nil
}

// checkNoAccount refuses a registration while the provider has an active account or an unsettled rollover.
func checkNoAccount(p ACMEProvider) error {
	switch {
	case p.PendingRollover:
		return ErrACMERolloverPending
	case p.ActiveAccountID != nil:
		return ErrACMEAccountExists
	}
	return nil
}

// RegisterACMEAccount creates the provider's account at the CA. Order: validation of the contact (validate.Errors),
// the license gate (license.ErrLocked and the like: nothing is sent to the CA), the provider (ErrNotFound) without
// an account (ErrACMEAccountExists, ErrACMERolloverPending), the CA's directory: when it has terms of service and
// tosAccepted is false, ACMEError terms_not_accepted (nothing is registered); a new P-256 key, sealed; the
// registration with the provider's EAB binding when it has one; then the active row and the audit row
// acme.account.registered (provider id, ToS URL, whether a binding was used; never the contact) in one transaction.
// A concurrent registration that won is ErrACMEAccountExists (the account this call made at the CA is deactivated,
// best effort). CA failures are *ACMEError.
func (s *Service) RegisterACMEAccount(ctx context.Context, a Actor, providerID uuid.UUID, contactEmail string, tosAccepted bool) (ACMEAccount, error) {
	return s.RegisterACMEAccountTerms(ctx, a, providerID, contactEmail, tosAccepted, "")
}

// RegisterACMEAccountTerms is RegisterACMEAccount bound to the terms the Administrator was shown (PreviewACMEProvider):
// when acceptedTermsURL is not empty and the CA's terms URL now differs from it (other terms, or none any more), the
// registration is refused with ACMEError terms_not_accepted before anything is registered, so the acceptance recorded
// (tos_url, the audit row) is always of the terms that were displayed. "" binds nothing (RegisterACMEAccount).
func (s *Service) RegisterACMEAccountTerms(ctx context.Context, a Actor, providerID uuid.UUID, contactEmail string, tosAccepted bool,
	acceptedTermsURL string) (ACMEAccount, error) {
	contact, fe := normContact(contactEmail)
	if fe != nil {
		return ACMEAccount{}, validate.Errors{*fe}
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMEAccount{}, err
	}
	release, err := s.lockACMEProvider(ctx, providerID)
	if err != nil {
		return ACMEAccount{}, err
	}
	defer release()
	p, err := getACMEProvider(ctx, s.pool, providerID, false)
	if err != nil {
		return ACMEAccount{}, err
	}
	if err := checkNoAccount(p); err != nil {
		return ACMEAccount{}, err
	}
	id := uuid.Must(uuid.NewV7())
	signer, env, err := s.newAccountKey(id)
	if err != nil {
		return ACMEAccount{}, err
	}
	client, err := s.acmeClientFor(p, signer, "")
	if err != nil {
		return ACMEAccount{}, err
	}
	d, err := client.Discover(ctx)
	if err != nil {
		return ACMEAccount{}, acmeFailure(err)
	}
	if (d.TermsOfService != "" && !tosAccepted) || (acceptedTermsURL != "" && d.TermsOfService != acceptedTermsURL) {
		return ACMEAccount{}, &ACMEError{Reason: acme.ReasonTermsNotAccepted, cause: acme.ErrTermsNotAccepted}
	}
	kid, hmac, err := s.openEAB(ctx, s.pool, providerID)
	if err != nil {
		return ACMEAccount{}, err
	}
	defer hmac.Zero()
	var eab *acme.EAB
	if kid != "" {
		eab = &acme.EAB{KID: kid, HMACKey: hmac.Bytes()}
	}
	acct, err := client.RegisterAccount(ctx, contact, eab, tosAccepted)
	if err != nil {
		return ACMEAccount{}, acmeFailure(err)
	}
	now := s.clock.Now().UTC()
	var by *uuid.UUID
	var at *time.Time
	if acct.TermsOfService != "" {
		by, at = actorRef(a), &now
	}
	var out ACMEAccount
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		// The provider must still be live and point at the CA the account was made at (FOR SHARE: a delete or an
		// update of the provider waits for this transaction).
		var dir string
		err := tx.QueryRow(ctx, "SELECT directory_url FROM acme_providers WHERE id = $1 AND deleted_at IS NULL FOR SHARE", providerID).Scan(&dir)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("inventory: read the ACME provider: %w", err)
		}
		if dir != p.DirectoryURL {
			return ErrACMEDirectoryChange
		}
		_, err = tx.Exec(ctx, `INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, tos_url, tos_accepted_by, tos_accepted_at,
key_ct, key_nonce, key_wrapped_dek, key_version, state, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active', $12, $13, $13)`,
			id, providerID, contact, acct.URL, acct.TermsOfService, by, at, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, actorRef(a), now)
		if db.IsUniqueViolationOn(err, "acme_accounts_one_active") {
			return ErrACMEAccountExists
		}
		if err != nil {
			return fmt.Errorf("inventory: store the ACME account: %w", err)
		}
		if out, err = getACMEAccount(ctx, tx, id, false); err != nil {
			return err
		}
		details := map[string]string{"provider_id": providerID.String(), "eab_used": fmt.Sprint(acct.UsedEAB)}
		if acct.TermsOfService != "" {
			details["tos_url"] = acct.TermsOfService
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.account.registered", ObjectType: "acme_account",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		if errors.Is(err, ErrACMEAccountExists) || errors.Is(err, ErrACMEDirectoryChange) || errors.Is(err, ErrNotFound) {
			s.deactivateOrphan(ctx, client)
		}
		return ACMEAccount{}, err
	}
	return out, nil
}

// orphanBudget bounds the best-effort deactivation of an account Alice made at a CA but could not store.
const orphanBudget = 30 * time.Second

// deactivateOrphan deactivates, best effort, an account this process registered and then could not keep.
func (s *Service) deactivateOrphan(ctx context.Context, c *acme.Client) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orphanBudget)
	defer cancel()
	if err := c.Deactivate(ctx); err != nil {
		s.log.Warn("could not deactivate an ACME account that was not stored", "reason", acme.ReasonOf(err))
	}
}

// accountProvider reads an account and its live provider, both unlocked.
func (s *Service) accountProvider(ctx context.Context, accountID uuid.UUID) (ACMEAccount, ACMEProvider, error) {
	acct, err := getACMEAccount(ctx, s.pool, accountID, false)
	if err != nil {
		return ACMEAccount{}, ACMEProvider{}, err
	}
	p, err := getACMEProvider(ctx, s.pool, acct.ProviderID, false)
	if errors.Is(err, ErrNotFound) {
		return ACMEAccount{}, ACMEProvider{}, ErrACMEAccountState
	}
	return acct, p, err
}

// rolloverOutcome is the seam of the integration tests' crash simulation (nil in production): it may replace the
// outcome of the CA's keyChange, as a crash between the CA's answer and the commit would.
type rolloverOutcome func(acme.RolloverOutcome) acme.RolloverOutcome

// RolloverACMEAccount replaces the key of an active account (A6). It returns the new active account. The license
// gate first; ErrACMEAccountState for an account that is not active; ErrACMERolloverPending when a rollover of the
// provider is unsettled (also when this one's outcome is unknown: RecoverACMERollover settles it); a CA without
// keyChange gives ACMEError rollover_unsupported (ALC-ACM-0014) and the pending key is discarded, as for any refusal.
// Audit acme.account.rolled_over (provider id, previous account id).
func (s *Service) RolloverACMEAccount(ctx context.Context, a Actor, accountID uuid.UUID) (ACMEAccount, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMEAccount{}, err
	}
	acct, p, err := s.accountProvider(ctx, accountID)
	if err != nil {
		return ACMEAccount{}, err
	}
	release, err := s.lockACMEProvider(ctx, p.ID)
	if err != nil {
		return ACMEAccount{}, err
	}
	defer release()
	// (1) The new key, committed as the pending row before the CA hears of it.
	pendingID := uuid.Must(uuid.NewV7())
	newKey, env, err := s.newAccountKey(pendingID)
	if err != nil {
		return ACMEAccount{}, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getACMEAccount(ctx, tx, accountID, true)
		if err != nil {
			return err
		}
		if cur.State == ACMEAccountPendingRollover {
			return ErrACMERolloverPending
		}
		if cur.State != ACMEAccountActive || cur.AccountURL == "" {
			return ErrACMEAccountState
		}
		_, err = tx.Exec(ctx, `INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, tos_url, tos_accepted_by, tos_accepted_at,
key_ct, key_nonce, key_wrapped_dek, key_version, state, pending_since, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending_rollover', now(), $12, $13, $13)`,
			pendingID, cur.ProviderID, cur.ContactEmail, cur.AccountURL, cur.TermsURL, cur.TermsAcceptedBy, cur.TermsAcceptedAt,
			env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, actorRef(a), s.clock.Now().UTC())
		if db.IsUniqueViolationOn(err, "acme_accounts_one_pending") {
			return ErrACMERolloverPending
		}
		if err != nil {
			return fmt.Errorf("inventory: store the pending ACME account key: %w", err)
		}
		acct = cur
		return nil
	})
	if err != nil {
		return ACMEAccount{}, err
	}
	// (2) The CA.
	oldKey, err := s.openAccountKey(ctx, s.pool, accountID)
	if err != nil {
		return ACMEAccount{}, s.discardPendingOr(ctx, pendingID, err)
	}
	client, err := s.acmeClientFor(p, oldKey, acct.AccountURL)
	if err != nil {
		return ACMEAccount{}, s.discardPendingOr(ctx, pendingID, err)
	}
	outcome, cerr := client.Rollover(ctx, newKey)
	if s.rolloverSeam != nil {
		outcome = s.rolloverSeam(outcome)
	}
	// (3) Settle.
	switch outcome {
	case acme.RolloverSwitched:
		return s.settleRollover(ctx, a, accountID, pendingID, acct.AccountURL, false)
	case acme.RolloverUnknown:
		s.log.Warn("the outcome of an ACME account key change is unknown; the pending key is kept", "account_id", accountID.String(),
			"reason", acme.ReasonOf(cerr))
		return ACMEAccount{}, ErrACMERolloverPending
	default:
		if cerr == nil {
			cerr = &ACMEError{Reason: acme.ReasonAccountRejected}
		}
		return ACMEAccount{}, s.discardPendingOr(ctx, pendingID, acmeFailure(cerr))
	}
}

// settleRollover makes the pending row the active account, retires the old one and moves the ACME certificates of
// the old row to the new one, in one transaction, with the audit row. accountURL is the account's URL at the CA (unchanged by a rollover).
func (s *Service) settleRollover(ctx context.Context, a Actor, oldID, pendingID uuid.UUID, accountURL string, recovered bool) (ACMEAccount, error) {
	var out ACMEAccount
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		old, err := getACMEAccount(ctx, tx, oldID, true)
		if err != nil {
			return err
		}
		pending, err := getACMEAccount(ctx, tx, pendingID, true)
		if err != nil {
			return err
		}
		if old.State != ACMEAccountActive || pending.State != ACMEAccountPendingRollover {
			return ErrACMEAccountState
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, "UPDATE acme_accounts SET state = 'retired', updated_at = $2 WHERE id = $1", oldID, now); err != nil {
			return fmt.Errorf("inventory: retire the old ACME account key: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE acme_accounts SET state = 'active', account_url = $3, updated_at = $2 WHERE id = $1", pendingID, now, accountURL); err != nil {
			return fmt.Errorf("inventory: activate the new ACME account key: %w", err)
		}
		// The certificates follow their account to its new key (they never name a retired or pending row).
		if _, err := tx.Exec(ctx, "UPDATE acme_certificates SET account_id = $2, updated_at = $3 WHERE account_id = $1", oldID, pendingID, now); err != nil {
			return fmt.Errorf("inventory: move the ACME certificates to the new account key: %w", err)
		}
		if out, err = getACMEAccount(ctx, tx, pendingID, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.account.rolled_over", ObjectType: "acme_account",
			ObjectID: pendingID.String(), Result: audit.Success, Details: map[string]string{"provider_id": old.ProviderID.String(),
				"previous_account_id": oldID.String(), "recovered": fmt.Sprint(recovered)}})
		return err
	})
	return out, err
}

// discardPending deletes a pending key the CA did not take, detached from the caller's context (the row must not
// outlive a refusal because the request was cancelled). Only a pending row is deleted (the database refuses any other,
// Z1018).
func (s *Service) discardPending(ctx context.Context, pendingID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	if _, err := s.pool.Exec(ctx, "DELETE FROM acme_accounts WHERE id = $1 AND state = 'pending_rollover'", pendingID); err != nil {
		return fmt.Errorf("inventory: discard the pending ACME account key: %w", err)
	}
	return nil
}

// discardPendingOr discards a pending key after a refusal and returns the refusal (a failed delete is logged: the row
// is then a stale pending key that RecoverACMERollover settles).
func (s *Service) discardPendingOr(ctx context.Context, pendingID uuid.UUID, cause error) error {
	if err := s.discardPending(ctx, pendingID); err != nil {
		s.log.Error("could not discard a pending ACME account key", "account_id", pendingID.String(), "error_type", fmt.Sprintf("%T", err))
	}
	return cause
}

// ACMERolloverSettleAge is how old (by database time) a pending key must be before a recovery may touch it: longer than
// the CA calls of the rollover that inserted it can run (its directory read and its keyChange, each bounded by the
// client's call timeout), plus a margin. A younger pending key may still be switched to by a request in flight.
const ACMERolloverSettleAge = 2*acme.DefaultCallTimeout + time.Minute

// RecoverACMERollover settles an unsettled rollover of the provider of accountID (the active account or its pending
// key). It asks the CA with the new key first: if the CA knows it, the new key becomes active (audit
// acme.account.rolled_over, recovered true); if the CA does not know it but knows the old key, the pending key is
// discarded and the active account returned unchanged. Any other answer leaves the pending key in place and is
// returned as *ACMEError. ErrACMEAccountState when nothing is pending; ErrACMERolloverPending while the pending key is
// younger than ACMERolloverSettleAge (database time). License gate first; under the provider's cross-process lock.
func (s *Service) RecoverACMERollover(ctx context.Context, a Actor, accountID uuid.UUID) (ACMEAccount, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMEAccount{}, err
	}
	_, p, err := s.accountProvider(ctx, accountID)
	if err != nil {
		return ACMEAccount{}, err
	}
	release, err := s.lockACMEProvider(ctx, p.ID)
	if err != nil {
		return ACMEAccount{}, err
	}
	defer release()
	var activeID, pendingID uuid.UUID
	var accountURL string
	var young bool
	err = s.pool.QueryRow(ctx, `SELECT a.id, a.account_url, n.id, n.pending_since > now() - make_interval(secs => $2)
FROM acme_accounts a JOIN acme_accounts n ON n.provider_id = a.provider_id
WHERE a.provider_id = $1 AND a.state = 'active' AND n.state = 'pending_rollover'`, p.ID, ACMERolloverSettleAge.Seconds()).Scan(&activeID, &accountURL, &pendingID, &young)
	if errors.Is(err, pgx.ErrNoRows) {
		return ACMEAccount{}, ErrACMEAccountState
	}
	if err != nil {
		return ACMEAccount{}, fmt.Errorf("inventory: read the pending ACME account key: %w", err)
	}
	if young {
		// The keyChange that inserted it may still reach the CA: deciding now could discard the only key the CA will
		// accept. Try again once ACMERolloverSettleAge has passed.
		return ACMEAccount{}, ErrACMERolloverPending
	}
	newKey, err := s.openAccountKey(ctx, s.pool, pendingID)
	if err != nil {
		return ACMEAccount{}, err
	}
	withNew, err := s.acmeClientFor(p, newKey, "")
	if err != nil {
		return ACMEAccount{}, err
	}
	u, nerr := withNew.Lookup(ctx)
	if nerr == nil {
		if u == "" {
			u = accountURL
		}
		return s.settleRollover(ctx, a, activeID, pendingID, u, true)
	}
	if !errors.Is(nerr, acme.ErrNoAccount) {
		return ACMEAccount{}, acmeFailure(nerr)
	}
	oldKey, err := s.openAccountKey(ctx, s.pool, activeID)
	if err != nil {
		return ACMEAccount{}, err
	}
	withOld, err := s.acmeClientFor(p, oldKey, "")
	if err != nil {
		return ACMEAccount{}, err
	}
	if _, oerr := withOld.Lookup(ctx); oerr != nil {
		return ACMEAccount{}, acmeFailure(oerr)
	}
	if err := s.discardPending(ctx, pendingID); err != nil {
		return ACMEAccount{}, err
	}
	return getACMEAccount(ctx, s.pool, activeID, false)
}

// DeactivateACMEAccount deactivates an active account at the CA (RFC 8555 7.3.6; permanent) and marks it
// deactivated, with the audit row acme.account.deactivated. License gate first; ErrACMEAccountState for an account
// that is not active; ErrACMERolloverPending while a rollover is unsettled (checked under the provider's cross-process
// lock). A CA failure changes nothing, except an answer that the account is already gone (a retry after a lost answer):
// then the record is finished (audit detail already_deactivated).
func (s *Service) DeactivateACMEAccount(ctx context.Context, a Actor, accountID uuid.UUID) (ACMEAccount, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMEAccount{}, err
	}
	acct, p, err := s.accountProvider(ctx, accountID)
	if err != nil {
		return ACMEAccount{}, err
	}
	release, err := s.lockACMEProvider(ctx, p.ID)
	if err != nil {
		return ACMEAccount{}, err
	}
	defer release()
	if p, err = getACMEProvider(ctx, s.pool, p.ID, false); err != nil {
		return ACMEAccount{}, err
	}
	if acct, err = getACMEAccount(ctx, s.pool, accountID, false); err != nil {
		return ACMEAccount{}, err
	}
	if acct.State != ACMEAccountActive || acct.AccountURL == "" {
		return ACMEAccount{}, ErrACMEAccountState
	}
	if p.PendingRollover {
		return ACMEAccount{}, ErrACMERolloverPending
	}
	key, err := s.openAccountKey(ctx, s.pool, accountID)
	if err != nil {
		return ACMEAccount{}, err
	}
	client, err := s.acmeClientFor(p, key, acct.AccountURL)
	if err != nil {
		return ACMEAccount{}, err
	}
	already := false
	if err := client.Deactivate(ctx); err != nil {
		if !accountGone(err) {
			return ACMEAccount{}, acmeFailure(err)
		}
		// A retry after a deactivation whose answer was lost: the CA no longer accepts the account. Finish the record.
		already = true
	}
	var out ACMEAccount
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE acme_accounts SET state = 'deactivated', updated_at = $2 WHERE id = $1 AND state = 'active'",
			accountID, s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("inventory: mark the ACME account deactivated: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrACMEAccountState
		}
		if out, err = getACMEAccount(ctx, tx, accountID, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "acme.account.deactivated", ObjectType: "acme_account",
			ObjectID: accountID.String(), Result: audit.Success, Details: map[string]string{"provider_id": p.ID.String(),
				"already_deactivated": fmt.Sprint(already)}})
		return err
	})
	return out, err
}

// accountGone reports a CA answer that says the account no longer exists or is no longer authorized (a deactivated
// account): RFC 8555 unauthorized or accountDoesNotExist, or the library's no-account answer.
func accountGone(err error) bool {
	if errors.Is(err, acme.ErrNoAccount) {
		return true
	}
	var ae *acme.Error
	return errors.As(err, &ae) && ae.Reason == acme.ReasonAccountRejected &&
		(ae.ProblemType == acme.ProblemPrefix+"unauthorized" || ae.ProblemType == acme.ProblemPrefix+"accountDoesNotExist")
}

// ACMEProviderPreview is what a provider's CA directory says before an account exists (PreviewACMEProvider): the
// terms of service the Administrator must accept, whether an external account binding is required, and the optional
// resources. Only these closed fields of the directory are kept; no other text of the CA is passed on.
type ACMEProviderPreview struct {
	// TermsOfServiceURL is the CA's terms URL when it is a safe https URL ("" when the CA publishes none or when it is
	// unsafe: TermsURLUnsafe then says so and the registration should not be offered).
	TermsOfServiceURL       string `json:"terms_of_service_url"`
	TermsURLUnsafe          bool   `json:"terms_url_unsafe"`
	ExternalAccountRequired bool   `json:"external_account_required"`
	KeyChangeSupported      bool   `json:"key_change_supported"`
	RenewalInfoSupported    bool   `json:"renewal_info_supported"`
	// Website is the CA's website when it is a safe https URL, else "".
	Website string `json:"website"`
}

// safeACMEWebURL reports whether u, a URL the directory published to be shown to a person, is safe to show as a link:
// https, a host, no user information, at most maxACMEURLLen, printable ASCII only (acme.ParseDirectory already
// dropped anything that is not an http(s) URL).
func safeACMEWebURL(u string) bool {
	if u == "" || len(u) > maxACMEURLLen {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] <= ' ' || u[i] >= 0x7f {
			return false
		}
	}
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Host != "" && p.User == nil
}

// PreviewACMEProvider reads the live provider's CA directory (one GET through the guarded transport with the
// provider's CA bundle; no key, no nonce, no account, no record written) for the registration form. The licence gate
// is asked first (license.ErrLocked and its kin: the CA is not contacted). ErrNotFound for an unknown or deleted
// provider. CA failures are *ACMEError (provider_unreachable, directory_invalid, tls_trust_failed, a rate limit with
// its Retry-After). It takes no provider lock: it never contends with an account operation.
func (s *Service) PreviewACMEProvider(ctx context.Context, providerID uuid.UUID) (ACMEProviderPreview, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return ACMEProviderPreview{}, err
	}
	p, err := getACMEProvider(ctx, s.pool, providerID, false)
	if err != nil {
		return ACMEProviderPreview{}, err
	}
	client, err := s.acmeClientFor(p, nil, "")
	if err != nil {
		return ACMEProviderPreview{}, err
	}
	d, err := client.Discover(ctx)
	if err != nil {
		return ACMEProviderPreview{}, acmeFailure(err)
	}
	out := ACMEProviderPreview{ExternalAccountRequired: d.ExternalAccountRequired, KeyChangeSupported: d.SupportsRollover(),
		RenewalInfoSupported: d.SupportsARI()}
	switch {
	case safeACMEWebURL(d.TermsOfService):
		out.TermsOfServiceURL = d.TermsOfService
	case d.TermsOfService != "":
		out.TermsURLUnsafe = true
	}
	if safeACMEWebURL(d.Website) {
		out.Website = d.Website
	}
	return out, nil
}
