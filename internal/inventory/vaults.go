package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/certs"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/db"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// Key Vault targets (spec §7.2, §7.3, §11.1, §11.3; R40 rows 5, 6, 9-13; F-43). A vault is added only
// after a pre-flight: Alice signs in and makes the vault's first call with the credential that is
// about to be stored (ruling S5). A wrong name, an unreachable vault, a refused sign-in, a tenant
// mismatch: nothing is stored and no license slot is used. A vault that answers "forbidden" (a role
// is missing) or "firewall" (the caller's address is not allowed) is added in the degraded status
// with the access check, because the Administrator fixes that on Azure's side.

const (
	// vaultPreflightBudget bounds the sign-in and the first call of a pre-flight.
	vaultPreflightBudget = 45 * time.Second
	// defaultPollMinutes is the poll interval of a vault added without one (R40 row 13).
	defaultPollMinutes = 15
	minPollMinutes     = 5
	maxPollMinutes     = 24 * 60
	// maxClientSecretLen bounds a client secret (Azure's are about 40 characters).
	maxClientSecretLen = 1024
	// maxAccessChecks bounds the rows of a stored access check.
	maxAccessChecks = 16
)

// Preflight results that degrade a vault instead of refusing it (ruling S5).
const (
	reasonForbidden = "azure.forbidden"
	reasonFirewall  = "azure.firewall"
	// reasonInternal is the stable reason of a provider answer Alice cannot use (a report without an
	// access check, a failure row with an unsafe reason): never Azure's text.
	reasonInternal = "internal.unexpected"
)

// VaultCredentialInput is how Alice signs in to a vault: the method and what it needs. Client
// secrets and private keys are consumed by the call that receives them: CreateVault and
// ReplaceVaultCredentials zero ClientSecret and the byte slices of Certificate before they return,
// whatever the outcome (the caller's copy must not be used afterwards).
type VaultCredentialInput struct {
	Auth            string // providers.AzureAuth*
	TenantID        string // a GUID; not for a managed identity
	ClientID        string // a GUID; optional for a managed identity (the user-assigned identity)
	ClientSecret    secrets.Plaintext
	SecretExpiresOn *time.Time   // client secret only: when Azure expires it
	Certificate     certs.Upload // certificate only: the certificate registered with the application and its RSA key
}

// NewVault is the input of CreateVault.
type NewVault struct {
	Name                string
	VaultURL            string // https://<name>.vault.azure.net (or just <name>), see azureid.ParseVault
	Auth                string
	TenantID            string
	ClientID            string
	ClientSecret        secrets.Plaintext
	SecretExpiresOn     *time.Time
	Certificate         certs.Upload
	PollIntervalMinutes int // 0 = 15; 5..1440
}

func (n NewVault) credential() VaultCredentialInput {
	return VaultCredentialInput{Auth: n.Auth, TenantID: n.TenantID, ClientID: n.ClientID, ClientSecret: n.ClientSecret,
		SecretExpiresOn: n.SecretExpiresOn, Certificate: n.Certificate}
}

// clear zeroes the secrets of the request (the PFX password is a string and cannot be).
func (c VaultCredentialInput) clear() {
	c.ClientSecret.Zero()
	clear(c.Certificate.PrivateKeyPEM)
	clear(c.Certificate.PFX)
}

func (n NewVault) clear() { n.credential().clear() }

func validPollMinutes(m int) *validate.FieldError {
	if m < minPollMinutes || m > maxPollMinutes {
		return &validate.FieldError{Field: "poll_interval_minutes", Code: validate.OutOfRange,
			Params: map[string]string{"min": strconv.Itoa(minPollMinutes), "max": strconv.Itoa(maxPollMinutes)}}
	}
	return nil
}

// guidOrEmpty is the canonical form of a GUID, "" for anything else.
func guidOrEmpty(s string) string {
	g, ok := azureid.NormalizeGUID(s)
	if !ok {
		return ""
	}
	return g
}

func hasCertificate(u certs.Upload) bool {
	return len(u.CertificatePEM) > 0 || len(u.PrivateKeyPEM) > 0 || len(u.PFX) > 0
}

func authValues() map[string]string {
	return map[string]string{"values": strings.Join([]string{providers.AzureAuthClientSecret, providers.AzureAuthCertificate,
		providers.AzureAuthManagedIdentity}, ", ")}
}

// validateVaultCredential checks a sign-in credential and returns its normalized form (GUIDs in
// canonical lower case).
func validateVaultCredential(in VaultCredentialInput) (VaultCredentialInput, validate.Errors) {
	var errs validate.Errors
	out := in
	switch in.Auth {
	case providers.AzureAuthClientSecret, providers.AzureAuthCertificate, providers.AzureAuthManagedIdentity:
	default:
		errs.Add("auth", validate.OneOf, authValues())
		return out, errs
	}
	managed := in.Auth == providers.AzureAuthManagedIdentity
	switch tenant := guidOrEmpty(in.TenantID); {
	case managed && strings.TrimSpace(in.TenantID) != "":
		errs.Add("tenant_id", validate.Pattern, nil)
	case managed:
		out.TenantID = ""
	case strings.TrimSpace(in.TenantID) == "":
		errs.Add("tenant_id", validate.Required, nil)
	case tenant == "":
		errs.Add("tenant_id", validate.Pattern, nil)
	default:
		out.TenantID = tenant
	}
	switch client := guidOrEmpty(in.ClientID); {
	case strings.TrimSpace(in.ClientID) == "" && !managed:
		errs.Add("client_id", validate.Required, nil)
	case strings.TrimSpace(in.ClientID) == "":
		out.ClientID = ""
	case client == "":
		errs.Add("client_id", validate.Pattern, nil)
	default:
		out.ClientID = client
	}
	secretLen := len(in.ClientSecret.Bytes())
	switch {
	case in.Auth == providers.AzureAuthClientSecret && secretLen == 0:
		errs.Add("client_secret", validate.Required, nil)
	case in.Auth == providers.AzureAuthClientSecret && secretLen > maxClientSecretLen:
		errs.Add("client_secret", validate.TooLong, map[string]string{"max": strconv.Itoa(maxClientSecretLen)})
	case in.Auth != providers.AzureAuthClientSecret && secretLen > 0:
		errs.Add("client_secret", validate.Pattern, nil)
	}
	switch {
	case in.Auth == providers.AzureAuthCertificate && !hasCertificate(in.Certificate):
		errs.Add("certificate", validate.Required, nil)
	case in.Auth != providers.AzureAuthCertificate && hasCertificate(in.Certificate):
		errs.Add("certificate", validate.Pattern, nil)
	}
	if in.SecretExpiresOn != nil && in.Auth != providers.AzureAuthClientSecret {
		errs.Add("secret_expires_on", validate.Pattern, nil)
	}
	return out, errs
}

// validateNewVault normalizes and checks a new vault; it returns the stored form and the vault's
// canonical address.
func validateNewVault(in NewVault) (NewVault, azureid.Vault, validate.Errors) {
	var errs validate.Errors
	out := in
	if name, fe := validName("name", in.Name); fe != nil {
		errs = append(errs, *fe)
	} else {
		out.Name = name
	}
	var vault azureid.Vault
	if strings.TrimSpace(in.VaultURL) == "" {
		errs.Add("vault_url", validate.Required, nil)
	} else if v, err := azureid.ParseVault(in.VaultURL); err != nil {
		errs.Add("vault_url", validate.Pattern, nil)
	} else {
		vault = v
	}
	cred, cerrs := validateVaultCredential(in.credential())
	errs = append(errs, cerrs...)
	out.Auth, out.TenantID, out.ClientID = cred.Auth, cred.TenantID, cred.ClientID
	if out.PollIntervalMinutes == 0 {
		out.PollIntervalMinutes = defaultPollMinutes
	} else if fe := validPollMinutes(out.PollIntervalMinutes); fe != nil {
		errs = append(errs, *fe)
	}
	return out, vault, errs
}

// vaultIdentity builds the identity of a request (what the pre-flight signs in with), the public
// information to store and the bytes to seal. cleanup zeroes the decoded private key; the caller
// defers it. An unreadable sign-in certificate is refused here, before anything is sent to Azure.
func (s *Service) vaultIdentity(c VaultCredentialInput, now time.Time) (providers.AzureIdentity, vaultInfo, []byte, func(), error) {
	info := vaultInfo{Auth: c.Auth, TenantID: c.TenantID, ClientID: c.ClientID}
	id := providers.AzureIdentity{Auth: c.Auth, TenantID: c.TenantID, ClientID: c.ClientID}
	switch c.Auth {
	case providers.AzureAuthClientSecret:
		id.ClientSecret = c.ClientSecret
		info.SecretExpiresOn = utcPtr(c.SecretExpiresOn)
		return id, info, c.ClientSecret.Bytes(), func() {}, nil
	case providers.AzureAuthCertificate:
		cc, err := certs.ParseClientCertificate(c.Certificate, now, s.roots)
		if err != nil {
			return id, info, nil, nil, err // the certs sentinels, as for an upload; no key comes back with one
		}
		if now.Before(cc.NotBefore) {
			cc.PrivateKeyDER.Zero()
			return id, info, nil, nil, ErrCertificateNotYetValid
		}
		id.CertificateDER, id.PrivateKeyDER = cc.CertificateDER, cc.PrivateKeyDER
		notAfter := cc.NotAfter.UTC()
		info.CertificateDER, info.CertThumbprint, info.CertNotAfter = cc.CertificateDER, cc.Thumbprint, &notAfter
		return id, info, cc.PrivateKeyDER.Bytes(), cc.PrivateKeyDER.Zero, nil
	default:
		return id, info, nil, func() {}, nil
	}
}

// cleanAzureFacts makes a provider's access check storable and showable: GUIDs only if they are
// GUIDs, closed vocabularies for the model, the rows' names, results and roles, a stable reason
// shape, a bounded number of rows (ruling S4, S13: no Azure text is stored).
func cleanAzureFacts(f *providers.AzureFacts, now time.Time) *providers.AzureFacts {
	if f == nil {
		return nil
	}
	out := &providers.AzureFacts{ObjectID: guidOrEmpty(f.ObjectID), TenantID: guidOrEmpty(f.TenantID),
		PermissionModel: "unknown", CheckedAt: f.CheckedAt.UTC(), Checks: []providers.AzureCheck{}}
	if f.PermissionModel == "rbac" || f.PermissionModel == "access_policy" {
		out.PermissionModel = f.PermissionModel
	}
	if out.CheckedAt.IsZero() {
		out.CheckedAt = now
	}
	names := []string{providers.AzureCheckSignIn, providers.AzureCheckListCertificates, providers.AzureCheckListKeys,
		providers.AzureCheckListSecrets, providers.AzureCheckReadSecret, providers.AzureCheckImport}
	results := []string{providers.AzureResultOK, providers.AzureResultForbidden, providers.AzureResultFailed, providers.AzureResultNotChecked}
	roles := []string{providers.RoleKeyVaultReader, providers.RoleKeyVaultSecretsUser, providers.RoleKeyVaultCertificatesOfficer}
	for _, c := range f.Checks {
		if len(out.Checks) == maxAccessChecks || !slices.Contains(names, c.Name) {
			continue
		}
		row := providers.AzureCheck{Name: c.Name, Result: c.Result}
		if !slices.Contains(results, c.Result) {
			row.Result = providers.AzureResultFailed
		}
		if c.Reason != "" {
			row.Reason = c.Reason
			if !reasonRE.MatchString(c.Reason) {
				row.Reason = reasonInternal
			}
		}
		if slices.Contains(roles, c.Role) {
			row.Role = c.Role
		}
		out.Checks = append(out.Checks, row)
	}
	return out
}

// vaultCheckOutcome is the status a vault has after an access check and the reason of the first
// row that did not pass ("" when none): a forbidden or failed row makes the vault degraded, a row
// that was not checked does not.
func vaultCheckOutcome(f *providers.AzureFacts) (status, errorCode string) {
	if f == nil {
		return StatusOK, ""
	}
	for _, c := range f.Checks {
		switch c.Result {
		case providers.AzureResultForbidden:
			if errorCode == "" {
				errorCode = c.Reason
			}
			if errorCode == "" {
				errorCode = reasonForbidden
			}
		case providers.AzureResultFailed:
			if errorCode == "" {
				errorCode = c.Reason
			}
			if errorCode == "" {
				errorCode = reasonInternal
			}
		default:
			continue
		}
		if !reasonRE.MatchString(errorCode) {
			errorCode = reasonInternal
		}
		return StatusDegraded, errorCode
	}
	return StatusOK, ""
}

// refusalFromRows is the refusal a provider's rows imply when it reports the failure of the sign-in or
// of the first vault call (the listing of certificates) as rows instead of an error: only forbidden
// and firewall answers leave a vault addable (ruling S5). A report that lacks the sign-in row or the
// certificate listing row, or says the listing was not checked or failed without a reason, is
// incomplete and refuses too. nil when the rows allow the vault.
func refusalFromRows(f *providers.AzureFacts) *providers.Error {
	incomplete := providers.NewError(reasonInternal, false, nil, nil)
	if f == nil {
		return incomplete
	}
	var signedIn, listed bool
	for _, c := range f.Checks {
		switch c.Name {
		case providers.AzureCheckSignIn:
			if c.Result != providers.AzureResultOK {
				return providers.NewError(rowReason(c.Reason, "azure.auth_failed"), false, nil, nil)
			}
			signedIn = true
		case providers.AzureCheckListCertificates:
			switch {
			case c.Result == providers.AzureResultNotChecked:
				return incomplete
			case c.Result == providers.AzureResultFailed && c.Reason != reasonFirewall && c.Reason != reasonForbidden:
				return providers.NewError(rowReason(c.Reason, reasonInternal), false, nil, nil)
			}
			listed = true
		}
	}
	if !signedIn || !listed {
		return incomplete
	}
	return nil
}

func rowReason(reason, fallback string) string {
	if reasonRE.MatchString(reason) {
		return reason
	}
	return fallback
}

// degradedFacts is the access check of a vault whose first call was refused with forbidden or
// firewall by a provider that reported it as an error: signed in, the listing failed.
func degradedFacts(e *providers.Error, now time.Time) *providers.AzureFacts {
	row := providers.AzureCheck{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultFailed, Reason: e.Code}
	if e.Code == reasonForbidden {
		row.Result, row.Role = providers.AzureResultForbidden, providers.RoleKeyVaultReader
	}
	return &providers.AzureFacts{PermissionModel: "unknown", CheckedAt: now,
		Checks: []providers.AzureCheck{{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK}, row}}
}

// preflightVault signs in and makes the vault's first call with ident, through the azurekv provider
// and an in-memory credential source. id is the vault's own id (a new vault's, chosen before the
// call): the provider keeps nothing per target for a refused vault because the caller forgets the id.
// A non-nil error refuses the vault: the provider's *providers.Error unchanged, or a closed
// internal.unexpected error for anything else, a panic included (logged by type only, like a
// decoder panic of an upload); nothing foreign is reachable through it. nil means the vault may be
// stored, and the report's access check says whether it works in full.
func (s *Service) preflightVault(ctx context.Context, id uuid.UUID, name, vaultURL string, ident providers.AzureIdentity) (rep providers.ConnectionReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("a vault pre-flight panicked", "panic_type", fmt.Sprintf("%T", r))
			rep, err = providers.ConnectionReport{}, providers.NewError(reasonInternal, false, nil, nil)
		}
	}()
	rep, err = s.runPreflight(ctx, id, name, vaultURL, ident)
	if err != nil {
		var pe *providers.Error
		if !errors.As(err, &pe) {
			s.log.Error("a vault pre-flight failed", "error_type", fmt.Sprintf("%T", err))
			err = providers.NewError(reasonInternal, false, nil, nil)
		}
		return providers.ConnectionReport{}, err
	}
	return rep, nil
}

func (s *Service) runPreflight(ctx context.Context, id uuid.UUID, name, vaultURL string, ident providers.AzureIdentity) (providers.ConnectionReport, error) {
	p, ok := s.registry.Get(providers.KindAzureKV)
	if !ok {
		return providers.ConnectionReport{}, errors.New("inventory: the azurekv provider is not registered")
	}
	ctx, cancel := context.WithTimeout(ctx, vaultPreflightBudget)
	defer cancel()
	sess, err := p.Open(ctx, providers.TargetRef{ID: id, Name: name, Kind: providers.KindAzureKV,
		Config: providers.TargetConfig{"vault_url": vaultURL}}, memorySource{id: ident}, providers.Env{Clock: s.clock, Log: s.log})
	if err != nil {
		return providers.ConnectionReport{}, err
	}
	defer func() { _ = sess.Close() }()
	now := s.clock.Now().UTC()
	rep, err := sess.TestConnection(ctx)
	if err != nil {
		var pe *providers.Error
		if errors.As(err, &pe) && (pe.Code == reasonForbidden || pe.Code == reasonFirewall) {
			if rep.Azure == nil {
				rep.Azure = degradedFacts(pe, now)
			}
			rep.Azure = cleanAzureFacts(rep.Azure, now)
			return rep, nil
		}
		return providers.ConnectionReport{}, err
	}
	if rep.Azure == nil {
		return providers.ConnectionReport{}, providers.NewError(reasonInternal, false, nil, nil)
	}
	rep.Azure = cleanAzureFacts(rep.Azure, now)
	if pe := refusalFromRows(rep.Azure); pe != nil {
		return providers.ConnectionReport{}, pe
	}
	return rep, nil
}

// reasonOf is the stable reason of a refusal for the audit row.
func reasonOf(err error) string {
	var pe *providers.Error
	if errors.As(err, &pe) && reasonRE.MatchString(pe.Code) {
		return pe.Code
	}
	return reasonInternal
}

// auditVaultRefused records a vault that was not added (F-43) in its own transaction: nothing was
// stored. The record does not depend on the request.
func (s *Service) auditVaultRefused(ctx context.Context, a Actor, vaultURL, auth string, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "vault.add_refused", ObjectType: "target",
			Result: audit.Failure, Details: map[string]string{"vault_url": vaultURL, "auth": auth, "reason": reasonOf(cause)}})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refused vault", "error_type", fmt.Sprintf("%T", err))
	}
}

// checkVaultFree refuses a vault whose name or address is already taken, before the pre-flight (one
// sign-in less for a duplicate). The unique indexes stay the real guard: a race still ends in
// ErrDuplicateTarget at the insert.
func (s *Service) checkVaultFree(ctx context.Context, name, host string) error {
	var taken bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM targets WHERE deleted_at IS NULL
AND (name = $1::citext OR (type = 'azure_key_vault' AND lower(config->>'host') = $2)))`, name, host).Scan(&taken)
	if err != nil {
		return fmt.Errorf("inventory: look for a duplicate vault: %w", err)
	}
	if taken {
		return ErrDuplicateTarget
	}
	return nil
}

// auditVaultCredentialsRefused records a credential replacement that the pre-flight refused (SEC-070)
// in its own transaction, as auditVaultRefused does for an add; only the closed reason is recorded.
func (s *Service) auditVaultCredentialsRefused(ctx context.Context, a Actor, vault Target, auth string, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "vault.credentials_refused", ObjectType: "target",
			ObjectID: vault.ID.String(), Result: audit.Failure,
			Details: map[string]string{"vault_url": vault.Vault.URL, "auth": auth, "reason": reasonOf(cause)}})
		return err
	})
	if err != nil {
		s.log.Error("could not audit a refused credential replacement", "error_type", fmt.Sprintf("%T", err))
	}
}

// checkTargetLimit refuses early, before any call to Azure, when the license has no free slot (the
// insert transaction checks again and decides: L-74).
func (s *Service) checkTargetLimit(ctx context.Context) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error { return s.license.CheckCanAddTarget(ctx, tx) })
}

// CreateVault adds a Key Vault: validation, the license gate, a pre-flight with the credential that
// is about to be stored (S5, F-43), then in one transaction the sealed credential, the vault, the
// audit row and the first poll. It returns the vault, the pre-flight's report (the access check),
// and the poll job. A refusal of the pre-flight is the provider's *providers.Error, unchanged, after
// an audit row vault.add_refused; nothing is stored and no license slot is used.
func (s *Service) CreateVault(ctx context.Context, a Actor, in NewVault) (Target, providers.ConnectionReport, uuid.UUID, error) {
	defer in.clear()
	n, vault, errs := validateNewVault(in)
	if len(errs) > 0 {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, errs
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		s.auditLicenseDenial(ctx, a, n.Name, err)
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	if err := s.checkTargetLimit(ctx); err != nil {
		s.auditLicenseDenial(ctx, a, n.Name, err)
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	if err := s.checkVaultFree(ctx, n.Name, vault.Host); err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	p, ok := s.registry.Get(providers.KindAzureKV)
	if !ok {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, errors.New("inventory: the azurekv provider is not registered")
	}
	now := s.clock.Now().UTC()
	ident, info, payload, cleanup, err := s.vaultIdentity(n.credential(), now)
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	defer cleanup()
	id := uuid.Must(uuid.NewV7()) // the pre-flight opens the vault under the id it will get
	// Whatever fails from here on leaves no vault under this id, so the provider must not keep a
	// limiter claim for it; only a committed insert keeps it.
	committed := false
	defer func() {
		if !committed {
			s.forgetTarget(TypeAzureKeyVault, id)
		}
	}()
	rep, err := s.preflightVault(ctx, id, n.Name, vault.URL, ident)
	if err != nil {
		s.auditVaultRefused(ctx, a, vault.URL, n.Auth, err)
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	cred, err := s.sealVaultCredential(info, payload)
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	facts, err := json.Marshal(Facts{Azure: rep.Azure})
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	status, errorCode := vaultCheckOutcome(rep.Azure)
	var lastSuccess *time.Time // only a vault that answered the certificate listing has one
	if listingAnswered(rep.Azure) {
		lastSuccess = &now
	}
	caps := make([]string, 0, len(p.Capabilities()))
	for _, c := range p.Capabilities().Sorted() {
		caps = append(caps, string(c))
	}
	var jobID uuid.UUID
	var created Target
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.insertVaultCredential(ctx, tx, cred, id, now); err != nil {
			return err
		}
		if err := s.insertTarget(ctx, tx, targetRow{ID: id, Name: n.Name, Type: TypeAzureKeyVault,
			Config:       targetConfig{Host: vault.Host, Port: 443, VaultURL: vault.URL},
			CredentialID: cred.ID, Status: status, LastErrorCode: errorCode, LastSuccessAt: lastSuccess, Capabilities: caps,
			IntervalSeconds: n.PollIntervalMinutes * 60, Facts: facts, By: a.UserID}); err != nil {
			return err
		}
		var err error
		if created, err = getTarget(ctx, tx, id, false); err != nil {
			return err
		}
		if jobID, err = s.jobs.EnqueueTx(ctx, tx, s.pollRequest(a, id)); err != nil {
			return err
		}
		details := map[string]string{"name": n.Name, "type": TypeAzureKeyVault, "vault_url": vault.URL, "auth": n.Auth,
			"credential_id": cred.ID.String(), "status": status}
		if n.TenantID != "" {
			details["tenant_id"] = n.TenantID
		}
		if n.ClientID != "" {
			details["client_id"] = n.ClientID
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.created", ObjectType: "target",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		s.auditLicenseDenial(ctx, a, n.Name, err)
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	committed = true
	s.refreshLicense(ctx)
	return created, rep, jobID, nil
}

// pollRequest is the job that reads a vault's inventory; the dedupe key lets a manual request, the
// schedule and a new vault's first poll coalesce.
func (s *Service) pollRequest(a Actor, id uuid.UUID) JobRequest {
	return JobRequest{Type: JobKVPoll, TargetID: id, Payload: map[string]string{}, Kind: a.jobKind(),
		CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: "kv.poll:" + id.String()}
}

// getVault returns a live vault, ErrNotAVault for any other target.
func getVault(ctx context.Context, q db.Querier, id uuid.UUID, forUpdate bool) (Target, error) {
	t, err := getTarget(ctx, q, id, forUpdate)
	if err != nil {
		return Target{}, err
	}
	if t.Type != TypeAzureKeyVault || t.Vault == nil {
		return Target{}, ErrNotAVault
	}
	return t, nil
}

// ReplaceVaultCredentials replaces a vault's sign-in credential: the same validation and pre-flight
// as CreateVault (against the vault Alice already knows), then a new credential row, credential_id
// moved to it, the status and the failure count reset from the new access check, an audit row
// (vault.credentials_replaced) and a poll. The old row stays (credentials are append-only). A refused
// pre-flight or a stale ifVersion changes nothing. Only an Administrator with step-up may call it
// (ruling S6, enforced by the API); there is no weaker path.
func (s *Service) ReplaceVaultCredentials(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, in VaultCredentialInput) (Target, providers.ConnectionReport, uuid.UUID, error) {
	defer in.clear()
	c, errs := validateVaultCredential(in)
	if len(errs) > 0 {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, errs
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	cur, err := getVault(ctx, s.pool, id, false)
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	if cur.Version != ifVersion {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, ErrVersionMismatch
	}
	now := s.clock.Now().UTC()
	ident, info, payload, cleanup, err := s.vaultIdentity(c, now)
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	defer cleanup()
	rep, err := s.preflightVault(ctx, cur.ID, cur.Name, cur.Vault.URL, ident)
	if err != nil {
		// The stored credential did not change and the vault still exists: nothing is forgotten (that
		// would drop the claim on the vault's limiter while a poll may be running).
		s.auditVaultCredentialsRefused(ctx, a, cur, c.Auth, err)
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	cred, err := s.sealVaultCredential(info, payload)
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	var updated Target
	var jobID uuid.UUID
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		locked, err := getVault(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if locked.Version != ifVersion {
			return ErrVersionMismatch
		}
		var previous uuid.UUID
		if err := tx.QueryRow(ctx, "SELECT credential_id FROM targets WHERE id = $1", id).Scan(&previous); err != nil {
			return fmt.Errorf("inventory: read the vault credential: %w", err)
		}
		if err := s.insertVaultCredential(ctx, tx, cred, id, now); err != nil {
			return err
		}
		status, errorCode := vaultCheckOutcome(rep.Azure)
		if locked.Status == StatusDisabled {
			status, errorCode = StatusDisabled, locked.LastErrorCode
		}
		if err := s.moveVaultCredential(ctx, tx, id, cred.ID, status, errorCode, rep.Azure, now, ifVersion, listingAnswered(rep.Azure)); err != nil {
			return err
		}
		if updated, err = getTarget(ctx, tx, id, false); err != nil {
			return err
		}
		if locked.Status != StatusDisabled { // a disabled vault is not polled (as RequestDiscovery refuses it)
			if jobID, err = s.jobs.EnqueueTx(ctx, tx, s.pollRequest(a, id)); err != nil {
				return err
			}
		}
		details := map[string]string{"name": locked.Name, "vault_url": locked.Vault.URL, "auth": c.Auth,
			"credential_id": cred.ID.String(), "previous_credential_id": previous.String(), "status": status}
		if c.TenantID != "" {
			details["tenant_id"] = c.TenantID
		}
		if c.ClientID != "" {
			details["client_id"] = c.ClientID
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "vault.credentials_replaced", ObjectType: "target",
			ObjectID: id.String(), Result: audit.Success, Details: details})
		return err
	})
	if err != nil {
		return Target{}, providers.ConnectionReport{}, uuid.Nil, err
	}
	// Nothing is forgotten here either: a session reads the credential when it is opened, and the
	// provider keeps only a limiter claim per vault, which the vault still needs.
	return updated, rep, jobID, nil
}

// moveVaultCredential points the vault at its new credential row and stores the access check. The
// database refuses (SQLSTATE Z1006) a credential that is not the vault's own; the caller sees
// ErrCredentialNotTheTargets, never the SQLSTATE.
func (s *Service) moveVaultCredential(ctx context.Context, tx pgx.Tx, id, credential uuid.UUID, status, errorCode string,
	access *providers.AzureFacts, now time.Time, ifVersion int, answered bool) error {
	rawAccess, err := json.Marshal(access)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE targets SET credential_id = $2, status = $3, last_error_code = $4,
facts = jsonb_set(facts - 'kv_auth_failures' - 'kv_throttled_cycles', '{azure}', $5::jsonb), last_success_at = CASE WHEN $8 THEN $6 ELSE last_success_at END,
poll_failures = 0, version = version + 1, updated_at = $6 WHERE id = $1 AND version = $7 AND deleted_at IS NULL`,
		id, credential, status, errorCode, rawAccess, now, ifVersion, answered)
	if e, ok := closedTargetWriteError(err); ok {
		return e
	}
	if err != nil {
		return fmt.Errorf("inventory: replace the vault credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionMismatch
	}
	return nil
}

// forgetTarget tells the provider of a target type to drop what it holds for the target (pooled
// connections, a cached sign-in).
func (s *Service) forgetTarget(typ string, id uuid.UUID) {
	if p, ok := s.providerFor(typ); ok {
		if cc, ok := p.(providers.ConnectionCache); ok {
			cc.ForgetTarget(id)
		}
	}
}

// RecordKVConnection stores a successful access check of a vault: facts.azure, the status the
// checklist implies (ok, or degraded with the first failing row's reason) and the last success
// time. A status change is audited (target.status_changed, reason kv_check_ok or the failing
// reason). A disabled vault stays disabled. The failure counters belong to the poll's transitions.
func (s *Service) RecordKVConnection(ctx context.Context, id uuid.UUID, r providers.ConnectionReport) error {
	if r.Azure == nil {
		return errors.New("inventory: the report has no access check")
	}
	now := s.clock.Now().UTC()
	access := cleanAzureFacts(r.Azure, now)
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getVault(ctx, tx, id, true)
		if err != nil {
			return err
		}
		to, errorCode := vaultCheckOutcome(access)
		if t.Status == StatusDisabled {
			to, errorCode = StatusDisabled, t.LastErrorCode
		}
		f := t.Facts
		f.Azure = access
		raw, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET status = $2, last_error_code = $3, last_success_at = CASE WHEN $6 THEN $4 ELSE last_success_at END, updated_at = $4, facts = $5
WHERE id = $1`, id, to, errorCode, now, raw, listingAnswered(access)); err != nil {
			return fmt.Errorf("inventory: record a vault access check: %w", err)
		}
		reason := "kv_check_ok"
		if errorCode != "" {
			reason = errorCode
		}
		return s.auditStatus(ctx, tx, t, to, reason)
	})
}

// RequestAccessCheck queues an access check of a vault (kv.test_connection). With readSecretOf, a
// vault certificate id, the job also reads that certificate's current version's secret once, which
// proves the Key Vault Secrets User role: the certificate must belong to the vault, be exportable and
// have a current version Alice has read (ErrNotFound, ErrNotExportable, ErrVersionNotDeployable).
func (s *Service) RequestAccessCheck(ctx context.Context, a Actor, vaultID, readSecretOf uuid.UUID) (uuid.UUID, error) {
	var jobID uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		t, err := getVault(ctx, tx, vaultID, true)
		if err != nil {
			return err
		}
		if t.Status == StatusDisabled {
			return ErrTargetNotReady
		}
		req := JobRequest{Type: JobKVTest, TargetID: vaultID, Payload: map[string]string{}, Kind: a.jobKind(),
			CreatedBy: a.UserID, CreatedByRole: string(a.Role), DedupeKey: "kv.test_connection:" + vaultID.String()}
		if readSecretOf != uuid.Nil {
			var exportable *bool
			var version string
			err := tx.QueryRow(ctx, `SELECT exportable, current_version FROM kv_certificates
WHERE id = $1 AND target_id = $2 AND missing_since IS NULL`, readSecretOf, vaultID).Scan(&exportable, &version)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return ErrNotFound
			case err != nil:
				return fmt.Errorf("inventory: read the vault certificate: %w", err)
			case exportable == nil || !*exportable:
				return ErrNotExportable
			case version == "":
				return ErrVersionNotDeployable
			}
			req.Payload["read_secret_of"] = readSecretOf.String()
			req.DedupeKey += ":" + readSecretOf.String()
		}
		jobID, err = s.jobs.EnqueueTx(ctx, tx, req)
		return err
	})
	return jobID, err
}

// DeleteVault soft-deletes a vault: its license slot is free at once, its address can be added again
// and nothing is changed in Azure. A vault with connected websites is refused (ErrVaultHasBindings)
// unless removeBindings is set, which first soft-deletes each live binding and releases its
// locations (both audited). Credentials and the vault's inventory rows stay as history.
func (s *Service) DeleteVault(ctx context.Context, a Actor, id uuid.UUID, removeBindings bool) error {
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getVault(ctx, tx, id, true)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM bindings WHERE kv_target_id = $1 AND deleted_at IS NULL ORDER BY id FOR UPDATE`, id)
		if err != nil {
			return fmt.Errorf("inventory: find the vault's bindings: %w", err)
		}
		var bindings []uuid.UUID
		for rows.Next() {
			var b uuid.UUID
			if err := rows.Scan(&b); err != nil {
				rows.Close()
				return fmt.Errorf("inventory: read a binding: %w", err)
			}
			bindings = append(bindings, b)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(bindings) > 0 && !removeBindings {
			return ErrVaultHasBindings
		}
		if len(bindings) > 0 {
			// Every website of every binding is locked before the first audit row is appended: a request
			// takes website locks and then the audit chain's, so this order cannot deadlock with it.
			if _, err := tx.Exec(ctx, "SELECT 1 FROM certificate_locations WHERE binding_id = ANY($1) ORDER BY id FOR NO KEY UPDATE", bindings); err != nil {
				return fmt.Errorf("inventory: lock the connected websites: %w", err)
			}
		}
		now := s.clock.Now().UTC()
		for _, b := range bindings {
			if err := s.releaseBindingTx(ctx, tx, a, b, now, map[string]string{"vault_url": cur.Vault.URL, "reason": "vault_deleted"}); err != nil {
				return err
			}
		}
		if err := s.endVaultImports(ctx, tx, id, cur.Name, cur.Vault.URL, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE targets SET deleted_at = $2, version = version + 1, updated_at = $2 WHERE id = $1", id, now); err != nil {
			return fmt.Errorf("inventory: delete vault: %w", err)
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.deleted", ObjectType: "target",
			ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "type": TypeAzureKeyVault,
				"vault_url": cur.Vault.URL, "binding_count": strconv.Itoa(len(bindings))}})
		return err
	})
	if err != nil {
		return err
	}
	s.forgetTarget(TypeAzureKeyVault, id)
	s.refreshLicense(ctx)
	return nil
}

// listingAnswered reports whether the vault answered the certificate listing successfully: the
// meaning of last_success_at for a vault (a forbidden or firewalled vault never has one).
func listingAnswered(f *providers.AzureFacts) bool {
	if f == nil {
		return false
	}
	for _, c := range f.Checks {
		if c.Name == providers.AzureCheckListCertificates {
			return c.Result == providers.AzureResultOK
		}
	}
	return false
}

// RecordAccessCheckRead audits the access check's optional read of a certificate's secret (R40 rows 28 and
// 34: every secret read is audited): one kv.secret_read row with purpose access_check, the vault's address,
// the certificate name and version, the result (audit.Success or audit.Failure) and, for a failure, the
// closed reason. Nothing else is stored. ErrNotFound for an unknown or deleted vault, ErrNotAVault for a
// server, validate.Errors for a name or version of the wrong shape, ErrClaimLost when the job run lost its
// job. The caller is the access check job (Task 15), once per read, after the provider returned.
func (s *Service) RecordAccessCheckRead(ctx context.Context, vaultID uuid.UUID, certificateName, version string, result audit.Result, reason string) error {
	var errs validate.Errors
	if !azureid.ValidObjectName(certificateName) {
		errs.Add("certificate_name", validate.Pattern, nil)
	}
	if !azureid.ValidVersion(version) {
		errs.Add("version", validate.Pattern, nil)
	}
	if result != audit.Success && result != audit.Failure {
		errs.Add("result", validate.OneOf, map[string]string{"values": "success, failure"})
	}
	if result == audit.Failure && !errorCodeRE.MatchString(reason) {
		errs.Add("reason", validate.Pattern, nil)
	}
	if len(errs) > 0 {
		return errs
	}
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		t, err := readKVTarget(ctx, tx, vaultID, "")
		if err != nil {
			return err
		}
		if t.deleted {
			return ErrNotFound
		}
		details := map[string]string{"purpose": "access_check", "vault_url": t.url, "certificate_name": certificateName, "version": version}
		if result == audit.Failure {
			details["reason"] = reason
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: jobsActor, Action: "kv.secret_read", ObjectType: "target", ObjectID: vaultID.String(),
			Result: result, Details: details})
		return err
	})
}
