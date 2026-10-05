package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"alice/internal/inventory"
	"alice/internal/platform/azureid"
	"alice/internal/providers"
)

// Wire forms of the Phase 5 resources (Key Vault). Like every other DTO none has a credential, a private
// key, a vault secret or any text Azure sent: names, versions, thumbprints and dates come from the
// inventory's validated rows, errors are closed codes with allowlisted params (errorRef).

// vaultDTO is what a Key Vault target adds to targetDTO ("vault"): its address, how Alice signs in, the
// public facts of that credential and the last access check. It never carries a secret.
type vaultDTO struct {
	URL                 string     `json:"url"`
	Name                string     `json:"name"`
	Auth                string     `json:"auth"`
	TenantID            string     `json:"tenant_id"`
	ClientID            string     `json:"client_id"`
	PollIntervalMinutes int        `json:"poll_interval_minutes"`
	SecretExpiresOn     *time.Time `json:"secret_expires_on"`
	CertThumbprint      string     `json:"cert_thumbprint"`
	CertNotAfter        *time.Time `json:"cert_not_after"`
	Access              *accessDTO `json:"access"`
}

// accessDTO is the access check: who Alice is in Azure, the vault's permission model and one row per call.
type accessDTO struct {
	ObjectID        string           `json:"object_id"`
	TenantID        string           `json:"tenant_id"`
	PermissionModel string           `json:"permission_model"`
	Checks          []accessCheckDTO `json:"checks"`
	CheckedAt       time.Time        `json:"checked_at"`
}

// accessCheckDTO is one row of the access check. Role is the Azure role that would allow the call (a
// forbidden row); Error is the closed code of a row that did not work.
type accessCheckDTO struct {
	Name   string       `json:"name"`
	Result string       `json:"result"`
	Role   string       `json:"role"`
	Error  *errorRefDTO `json:"error"`
}

var (
	accessCheckNames = []string{providers.AzureCheckSignIn, providers.AzureCheckListCertificates, providers.AzureCheckListKeys,
		providers.AzureCheckListSecrets, providers.AzureCheckReadSecret, providers.AzureCheckImport}
	accessCheckResults = []string{providers.AzureResultOK, providers.AzureResultForbidden, providers.AzureResultFailed, providers.AzureResultNotChecked}
	permissionModels   = []string{"rbac", "access_policy", "unknown"}
)

func guidOrBlank(s string) string {
	g, ok := azureid.NormalizeGUID(s)
	if !ok {
		return ""
	}
	return g
}

var vaultAuths = []string{providers.AzureAuthCertificate, providers.AzureAuthClientSecret, providers.AzureAuthManagedIdentity}

// oneOfOr is v when it is one of allowed, else the safe meaning fallback.
func oneOfOr(v string, allowed []string, fallback string) string {
	if oneOfOrBlank(v, allowed) == "" {
		return fallback
	}
	return v
}

func oneOfOrBlank(v string, allowed []string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return ""
}

// roleOrBlank passes one of the three Azure roles Alice names, in Azure's spelling.
func roleOrBlank(v string) string {
	if paramRoleRE.MatchString(v) {
		return v
	}
	return ""
}

// accessJSON renders an access check; nil stays nil. Rows whose name or result are not in the closed sets are
// dropped (a stored row can only be one of them, this is the second line).
func accessJSON(f *providers.AzureFacts) *accessDTO {
	if f == nil {
		return nil
	}
	out := &accessDTO{
		ObjectID: guidOrBlank(f.ObjectID), TenantID: guidOrBlank(f.TenantID), PermissionModel: oneOfOrBlank(f.PermissionModel, permissionModels),
		Checks: []accessCheckDTO{}, CheckedAt: f.CheckedAt.UTC(),
	}
	for _, c := range f.Checks {
		name, result := oneOfOrBlank(c.Name, accessCheckNames), oneOfOrBlank(c.Result, accessCheckResults)
		if name == "" || result == "" {
			continue
		}
		role := roleOrBlank(c.Role)
		var params map[string]string
		if role != "" {
			params = map[string]string{"role": role}
		}
		out.Checks = append(out.Checks, accessCheckDTO{Name: name, Result: result, Role: role, Error: errorRef(c.Reason, params)})
	}
	return out
}

// vaultJSON renders the vault half of a target (nil for a server).
func vaultJSON(t inventory.Target) *vaultDTO {
	v := t.Vault
	if v == nil {
		return nil
	}
	name := ""
	if pv, err := azureid.ParseVault(v.URL); err == nil {
		name = pv.Name
	}
	return &vaultDTO{
		URL: v.URL, Name: name, Auth: oneOfOrBlank(v.Auth, vaultAuths), TenantID: guidOrBlank(v.TenantID), ClientID: guidOrBlank(v.ClientID),
		PollIntervalMinutes: int(v.PollInterval / time.Minute), SecretExpiresOn: utcPtr(v.SecretExpiresOn),
		CertThumbprint: thumbprintOrBlank(v.CertThumbprint), CertNotAfter: utcPtr(v.CertNotAfter), Access: accessJSON(v.Access),
	}
}

func thumbprintOrBlank(s string) string {
	if azureid.ValidThumbprint(s) {
		return s
	}
	return ""
}

// vaultLastError is a vault's last error. A vault's status stores the reason only, so the params a text needs
// come from the failure of the last poll that is that reason (facts.kv_poll: the firewall's client address, the
// permission model and the role) and from the access check (the role of the first row that was not allowed and
// the permission model). Each value passes its strict shape here again: an IP address literal without a zone,
// one of the three models, one of the three roles; anything else stored is dropped.
func vaultLastError(t inventory.Target) *errorRefDTO {
	if t.LastErrorCode == "" {
		return nil
	}
	params := map[string]string{}
	if t.Vault != nil && t.Vault.Access != nil && t.LastErrorCode == ErrAzureForbidden.Reason {
		for _, c := range t.Vault.Access.Checks {
			if c.Result == providers.AzureResultForbidden && roleOrBlank(c.Role) != "" {
				params["role"] = c.Role
				if m := oneOfOrBlank(t.Vault.Access.PermissionModel, permissionModels); m != "" {
					params["model"] = m
				}
				break
			}
		}
	}
	if f := pollFailureOf(t); f != nil {
		if a, err := netip.ParseAddr(f.ClientAddress); err == nil && a.Zone() == "" {
			params["client_address"] = a.String()
		}
		if m := oneOfOrBlank(f.Model, permissionModels); m != "" {
			params["model"] = m // the poll's refusal is the last error; the access check may be older
		}
		if _, ok := params["role"]; !ok && roleOrBlank(f.Role) != "" && t.LastErrorCode == ErrAzureForbidden.Reason {
			params["role"] = f.Role
		}
	}
	if len(params) == 0 {
		params = nil
	}
	return errorRef(t.LastErrorCode, params)
}

// pollFailureOf is the failure of the vault's last poll that is its last error: the whole poll's, else the first
// list's; nil when the last poll stored none.
func pollFailureOf(t inventory.Target) *inventory.KVPollFailure {
	if t.Facts.KVPoll == nil {
		return nil
	}
	var first *inventory.KVPollFailure
	for i := range t.Facts.KVPoll.Failures {
		f := &t.Facts.KVPoll.Failures[i]
		if f.Reason != t.LastErrorCode {
			continue
		}
		if f.Object == "vault" {
			return f
		}
		if first == nil {
			first = f
		}
	}
	return first
}

// kvCertificateDTO is one certificate of a vault.
type kvCertificateDTO struct {
	ID                string     `json:"id"`
	TargetID          string     `json:"target_id"`
	Name              string     `json:"name"`
	CurrentVersion    string     `json:"current_version"`
	CurrentThumbprint string     `json:"current_thumbprint"`
	Enabled           bool       `json:"enabled"`
	NotBefore         *time.Time `json:"not_before"`
	Expires           *time.Time `json:"expires"`
	KVCreatedAt       *time.Time `json:"kv_created_at"`
	KVUpdatedAt       *time.Time `json:"kv_updated_at"`
	Exportable        *bool      `json:"exportable"`
	KeyType           string     `json:"key_type"`
	KeySize           int        `json:"key_size"`
	ContentType       string     `json:"content_type"`
	IssuerName        string     `json:"issuer_name"`
	AutoRenew         bool       `json:"auto_renew"`
	DetailsPending    bool       `json:"details_pending"`
	FirstSeenAt       time.Time  `json:"first_seen_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	MissingSince      *time.Time `json:"missing_since"`
	Bound             bool       `json:"bound"`
	CurrentHeld       bool       `json:"current_held"`
	CurrentHeldReason string     `json:"current_held_reason"`
}

var heldReasons = []string{"", "license", "incomplete_chain"}

func kvCertificateJSON(c inventory.KVCertificate) kvCertificateDTO {
	return kvCertificateDTO{
		ID: c.ID.String(), TargetID: c.TargetID.String(), Name: c.Name, CurrentVersion: versionOrBlank(c.CurrentVersion),
		CurrentThumbprint: thumbprintOrBlank(c.CurrentThumbprint), Enabled: c.Enabled, NotBefore: utcPtr(c.NotBefore), Expires: utcPtr(c.Expires),
		KVCreatedAt: utcPtr(c.KVCreatedAt), KVUpdatedAt: utcPtr(c.KVUpdatedAt), Exportable: c.Exportable, KeyType: codeOrBlank(c.KeyType),
		KeySize: c.KeySize, ContentType: c.ContentType, IssuerName: c.IssuerName, AutoRenew: c.AutoRenew, DetailsPending: c.DetailsPending,
		FirstSeenAt: c.FirstSeenAt.UTC(), LastSeenAt: c.LastSeenAt.UTC(), MissingSince: utcPtr(c.MissingSince), Bound: c.Bound,
		CurrentHeld: c.CurrentHeld, CurrentHeldReason: oneOfOrBlank(c.CurrentHeldReason, heldReasons),
	}
}

func versionOrBlank(s string) string {
	if azureid.ValidVersion(s) {
		return s
	}
	return ""
}

// kvVersionDTO is one version of a certificate.
type kvVersionDTO struct {
	ID            string     `json:"id"`
	Version       string     `json:"version"`
	Thumbprint    string     `json:"thumbprint"`
	CertificateID *string    `json:"certificate_id"`
	Enabled       bool       `json:"enabled"`
	NotBefore     *time.Time `json:"not_before"`
	Expires       *time.Time `json:"expires"`
	KVCreatedAt   *time.Time `json:"kv_created_at"`
	Exportable    *bool      `json:"exportable"`
	KeyType       string     `json:"key_type"`
	ContentType   string     `json:"content_type"`
	DetectedAt    time.Time  `json:"detected_at"`
	Held          bool       `json:"held"`
	HeldReason    string     `json:"held_reason"`
}

func kvVersionJSON(v inventory.KVVersion) kvVersionDTO {
	return kvVersionDTO{
		ID: v.ID.String(), Version: versionOrBlank(v.Version), Thumbprint: thumbprintOrBlank(v.Thumbprint), CertificateID: idPtr(v.CertificateID),
		Enabled: v.Enabled, NotBefore: utcPtr(v.NotBefore), Expires: utcPtr(v.Expires), KVCreatedAt: utcPtr(v.KVCreatedAt), Exportable: v.Exportable,
		KeyType: codeOrBlank(v.KeyType), ContentType: v.ContentType, DetectedAt: v.DetectedAt.UTC(), Held: v.Held,
		HeldReason: oneOfOrBlank(v.HeldReason, heldReasons),
	}
}

// bindingSummaryDTO is the binding a certificate detail names.
type bindingSummaryDTO struct {
	ID             string     `json:"id"`
	AutoDeploy     bool       `json:"auto_deploy"`
	AutoSince      *time.Time `json:"auto_since"`
	StoppedVersion string     `json:"stopped_version"`
	LocationCount  int        `json:"location_count"`
	Version        int        `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
}

// kvCertificateDetailDTO is GET .../kv/certificates/{id}: the certificate, its versions (newest first), its
// binding and what is known of the access to deploy it.
type kvCertificateDetailDTO struct {
	kvCertificateDTO
	Versions     []kvVersionDTO     `json:"versions"`
	Binding      *bindingSummaryDTO `json:"binding"`
	DeployAccess string             `json:"deploy_access"`
}

func kvCertificateDetailJSON(d inventory.KVCertificateDetail) kvCertificateDetailDTO {
	out := kvCertificateDetailDTO{
		kvCertificateDTO: kvCertificateJSON(d.KVCertificate), Versions: make([]kvVersionDTO, 0, len(d.Versions)),
		DeployAccess: oneOfOr(d.DeployAccess, []string{inventory.DeployAccessOK, inventory.DeployAccessForbidden, inventory.DeployAccessNotChecked}, inventory.DeployAccessNotChecked),
	}
	for _, v := range d.Versions {
		out.Versions = append(out.Versions, kvVersionJSON(v))
	}
	if b := d.Binding; b != nil {
		out.Binding = &bindingSummaryDTO{ID: b.ID.String(), AutoDeploy: b.AutoDeploy, AutoSince: utcPtr(b.AutoSince), StoppedVersion: versionOrBlank(b.StoppedVersion),
			LocationCount: b.LocationCount, Version: b.Version, CreatedAt: b.CreatedAt.UTC()}
	}
	return out
}

// kvKeyDTO is the metadata of one key of a vault (never key material).
type kvKeyDTO struct {
	ID               string     `json:"id"`
	TargetID         string     `json:"target_id"`
	Name             string     `json:"name"`
	Version          string     `json:"version"`
	KeyType          string     `json:"key_type"`
	Curve            string     `json:"curve"`
	KeySize          int        `json:"key_size"`
	HSM              bool       `json:"hsm"`
	Managed          bool       `json:"managed"`
	Enabled          bool       `json:"enabled"`
	DetailsUpdatedAt *time.Time `json:"details_updated_at"`
	DetailsProblem   string     `json:"details_problem"`
	NotBefore        *time.Time `json:"not_before"`
	Expires          *time.Time `json:"expires"`
	KVCreatedAt      *time.Time `json:"kv_created_at"`
	KVUpdatedAt      *time.Time `json:"kv_updated_at"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	MissingSince     *time.Time `json:"missing_since"`
}

func kvKeyJSON(k inventory.KVKey) kvKeyDTO {
	return kvKeyDTO{
		ID: k.ID.String(), TargetID: k.TargetID.String(), Name: k.Name, Version: versionOrBlank(k.Version), KeyType: codeOrBlank(k.KeyType),
		Curve: k.Curve, KeySize: k.KeySize, HSM: k.HSM, Managed: k.Managed, Enabled: k.Enabled, DetailsUpdatedAt: utcPtr(k.DetailsUpdatedAt),
		DetailsProblem: oneOfOrBlank(k.DetailsProblem, []string{"", "forbidden", "failed"}), NotBefore: utcPtr(k.NotBefore), Expires: utcPtr(k.Expires),
		KVCreatedAt: utcPtr(k.KVCreatedAt), KVUpdatedAt: utcPtr(k.KVUpdatedAt), FirstSeenAt: k.FirstSeenAt.UTC(), LastSeenAt: k.LastSeenAt.UTC(),
		MissingSince: utcPtr(k.MissingSince),
	}
}

// kvSecretDTO is the metadata of one secret of a vault (never its value).
type kvSecretDTO struct {
	ID           string     `json:"id"`
	TargetID     string     `json:"target_id"`
	Name         string     `json:"name"`
	ContentType  string     `json:"content_type"`
	Managed      bool       `json:"managed"`
	Enabled      bool       `json:"enabled"`
	NotBefore    *time.Time `json:"not_before"`
	Expires      *time.Time `json:"expires"`
	KVCreatedAt  *time.Time `json:"kv_created_at"`
	KVUpdatedAt  *time.Time `json:"kv_updated_at"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	MissingSince *time.Time `json:"missing_since"`
}

func kvSecretJSON(s inventory.KVSecret) kvSecretDTO {
	return kvSecretDTO{
		ID: s.ID.String(), TargetID: s.TargetID.String(), Name: s.Name, ContentType: s.ContentType, Managed: s.Managed, Enabled: s.Enabled,
		NotBefore: utcPtr(s.NotBefore), Expires: utcPtr(s.Expires), KVCreatedAt: utcPtr(s.KVCreatedAt), KVUpdatedAt: utcPtr(s.KVUpdatedAt),
		FirstSeenAt: s.FirstSeenAt.UTC(), LastSeenAt: s.LastSeenAt.UTC(), MissingSince: utcPtr(s.MissingSince),
	}
}

// bindingLocationDTO is one connected website and what is known of its deployment.
type bindingLocationDTO struct {
	LocationID   string  `json:"location_id"`
	TargetID     string  `json:"target_id"`
	TargetName   string  `json:"target_name"`
	CertPath     string  `json:"cert_path"`
	State        string  `json:"state"`
	Version      string  `json:"version"`
	DeploymentID *string `json:"deployment_id"`
}

var bindingStates = []string{inventory.BindingLocationNotDeployed, inventory.BindingLocationPending, inventory.BindingLocationDeployed,
	inventory.BindingLocationFailed, inventory.BindingLocationStopped}

// bindingDTO is a vault certificate's connection to websites. Locations is set for one binding (GET, and the
// answers of the changes), not for lists.
type bindingDTO struct {
	ID              string               `json:"id"`
	KVCertificateID string               `json:"kv_certificate_id"`
	VaultID         string               `json:"vault_id"`
	CertificateName string               `json:"certificate_name"`
	VaultName       string               `json:"vault_name"`
	AutoDeploy      bool                 `json:"auto_deploy"`
	AutoSince       *time.Time           `json:"auto_since"`
	StoppedVersion  string               `json:"stopped_version"`
	LocationCount   int                  `json:"location_count"`
	Version         int                  `json:"version"`
	CreatedAt       time.Time            `json:"created_at"`
	CreatedBy       *string              `json:"created_by"`
	Locations       []bindingLocationDTO `json:"locations"`
}

func bindingJSON(b inventory.Binding) bindingDTO {
	out := bindingDTO{
		ID: b.ID.String(), KVCertificateID: b.KVCertificateID.String(), VaultID: b.VaultID.String(), CertificateName: b.CertificateName,
		VaultName: b.VaultName, AutoDeploy: b.AutoDeploy, AutoSince: utcPtr(b.AutoSince), StoppedVersion: versionOrBlank(b.StoppedVersion),
		LocationCount: b.LocationCount, Version: b.Version, CreatedAt: b.CreatedAt.UTC(), CreatedBy: idPtr(b.CreatedBy),
		Locations: make([]bindingLocationDTO, 0, len(b.Locations)),
	}
	for _, l := range b.Locations {
		out.Locations = append(out.Locations, bindingLocationDTO{
			LocationID: l.LocationID.String(), TargetID: l.TargetID.String(), TargetName: l.TargetName, CertPath: l.CertPath,
			State: oneOfOr(l.State, bindingStates, inventory.BindingLocationNotDeployed), Version: versionOrBlank(l.Version), DeploymentID: idPtr(l.DeploymentID),
		})
	}
	return out
}

// deployableLocationDTO is one website that can be connected to a vault certificate.
type deployableLocationDTO struct {
	ID          string   `json:"id"`
	TargetID    string   `json:"target_id"`
	TargetName  string   `json:"target_name"`
	CertPath    string   `json:"cert_path"`
	KeyPath     string   `json:"key_path"`
	KeyType     string   `json:"key_type"`
	ServerNames []string `json:"server_names"`
	BindingID   *string  `json:"binding_id"`
}

func deployableLocationJSON(l inventory.DeployableLocation) deployableLocationDTO {
	return deployableLocationDTO{
		ID: l.ID.String(), TargetID: l.TargetID.String(), TargetName: l.TargetName, CertPath: l.CertPath, KeyPath: l.KeyPath,
		KeyType: codeOrBlank(l.KeyType), ServerNames: nonNil(l.ServerNames), BindingID: idPtr(l.BindingID),
	}
}

var importStates = []string{inventory.ImportQueued, inventory.ImportRunning, inventory.ImportSucceeded, inventory.ImportFailed, inventory.ImportUncertain}

// importDTO is one import into a vault. Error is the closed code of a failed import; for the two reasons
// that name the certificate the name is added (the record has it), so the text never carries a placeholder.
type importDTO struct {
	ID            string       `json:"id"`
	CertificateID string       `json:"certificate_id"`
	TargetID      string       `json:"target_id"`
	Name          string       `json:"name"`
	NewVersion    bool         `json:"new_version"`
	State         string       `json:"state"`
	Version       string       `json:"version"`
	Thumbprint    string       `json:"thumbprint"`
	Error         *errorRefDTO `json:"error"`
	CanRetry      bool         `json:"can_retry"`
	JobID         *string      `json:"job_id"`
	RequestedBy   *string      `json:"requested_by"`
	CreatedAt     time.Time    `json:"created_at"`
	SentAt        *time.Time   `json:"sent_at"`
	FinishedAt    *time.Time   `json:"finished_at"`
}

func importJSON(im inventory.KVImport) importDTO {
	params := providerParams(im.ErrorParams)
	if (im.ErrorCode == ErrKVImportConfirmNeeded.Reason || im.ErrorCode == ErrKVImportNameExists.Reason) && azureid.ValidObjectName(im.Name) {
		if params == nil {
			params = map[string]string{}
		}
		params["certificate_name"] = im.Name
	}
	reason := im.ErrorCode
	if reason == "auth.forbidden" {
		// An import ends with this reason only when its job found that the requester is no longer an Administrator.
		reason = ErrKVImportAdminRequired.Reason
	}
	return importDTO{
		ID: im.ID.String(), CertificateID: im.CertificateID.String(), TargetID: im.VaultID.String(), Name: im.Name, NewVersion: im.NewVersion,
		State: oneOfOrBlank(im.State, importStates), Version: versionOrBlank(im.Version), Thumbprint: thumbprintOrBlank(im.Thumbprint),
		Error: errorRef(reason, params), CanRetry: im.CanRetry, JobID: idPtr(im.JobID), RequestedBy: idPtr(im.RequestedBy),
		CreatedAt: im.CreatedAt.UTC(), SentAt: utcPtr(im.SentAt), FinishedAt: utcPtr(im.FinishedAt),
	}
}

// secretText is a JSON string that is kept in a byte slice the handler owns and zeroes, instead of a Go
// string that cannot be: the client secret, the private key PEM, the PFX in base64 and the PFX password.
// UnmarshalJSON receives the raw value from the buffer decodeExact reads the body into (and clears), copies
// the unescaped text into its own slice once, and never builds a string from it.
type secretText []byte

var errSecretText = errors.New("api: a secret field must be a string")

// UnmarshalJSON implements json.Unmarshaler. encoding/json has validated the document, so escapes are
// well formed; null leaves the field empty.
func (s *secretText) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return errSecretText
	}
	*s = unescapeJSONString(b[1 : len(b)-1])
	if onSecretBytes != nil {
		onSecretBytes(*s)
	}
	return nil
}

// onSecretBytes sees every slice a secret field or a decoded PFX was copied into, so a test can check that the
// handler zeroed it on every path. nil in production.
var onSecretBytes func([]byte)

func (s secretText) zero() { clear(s) }

// unescapeJSONString turns the inside of a JSON string into bytes, in a slice of its own.
func unescapeJSONString(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' || i+1 >= len(in) {
			out = append(out, c)
			continue
		}
		i++
		switch in[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'u':
			r, n := readHex4(in[i+1:])
			if n == 0 {
				out = append(out, 'u')
				break
			}
			i += n
			if utf16.IsSurrogate(r) && i+6 < len(in)+0 && in[i+1] == '\\' && in[i+2] == 'u' {
				if r2, n2 := readHex4(in[i+3:]); n2 > 0 {
					if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
						r = dec
						i += 2 + n2
					}
				}
			}
			out = utf8.AppendRune(out, r)
		default: // \" \\ \/ and anything else maps to itself
			out = append(out, in[i])
		}
	}
	return out
}

// readHex4 reads four hexadecimal digits; n is 4, or 0 when they are not there.
func readHex4(b []byte) (rune, int) {
	if len(b) < 4 {
		return 0, 0
	}
	var r rune
	for _, c := range b[:4] {
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, 0
		}
		r = r*16 + d
	}
	return r, 4
}

// decodeBase64Secret decodes standard base64 (padding required, as the Phase 4 upload) into a new slice the
// caller zeroes; ok is false for text that is not base64.
func decodeBase64Secret(in secretText) ([]byte, bool) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, in)
	if err != nil {
		clear(out)
		return nil, false
	}
	if onSecretBytes != nil {
		onSecretBytes(out)
	}
	return out[:n], true
}
