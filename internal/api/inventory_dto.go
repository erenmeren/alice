package api

import (
	"maps"
	"time"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/providers"
)

// Wire forms of the Phase 3 resources (contract "API"). No DTO has a credential, private-key or
// secret field: Operators and Auditors see server metadata only (R3).

// errorRefDTO names a stored failure reason by its documented code.
type errorRefDTO struct {
	Code   string            `json:"code"`
	Reason string            `json:"reason"`
	Params map[string]string `json:"params,omitempty"`
}

// errorRef maps a stored reason; an unknown reason becomes the generic internal.unexpected so the
// UI always has a translated text.
func errorRef(reason string, params map[string]string) *errorRefDTO {
	if reason == "" {
		return nil
	}
	ec := codeForReason(reason)
	return &errorRefDTO{Code: ec.Code, Reason: ec.Reason, Params: completeParams(ec.Reason, params)}
}

// roleReader is the role a vault needs for everything Alice does except reading a private key and importing.
const roleReader = "Key Vault Reader"

// completeParams adds what a text of the reason always needs and a stored record may lack: azure.forbidden
// names the role it asks for, and an older record (or a vault's status, which stores no params) does not carry
// one. The role of the first row the access check marked forbidden is used where the caller has it
// (vaultLastError); this is the floor, so that no text is ever shown with a placeholder in it.
func completeParams(reason string, params map[string]string) map[string]string {
	if reason == ErrAzureForbidden.Reason && params["role"] == "" {
		out := maps.Clone(params)
		if out == nil {
			out = map[string]string{}
		}
		out["role"] = roleReader
		return out
	}
	return params
}

type acceptedDTO struct {
	JobID     string `json:"job_id"`
	StatusURL string `json:"status_url"`
}

func accepted(id uuid.UUID) acceptedDTO {
	return acceptedDTO{JobID: id.String(), StatusURL: "/api/v1/jobs/" + id.String()}
}

type osDTO struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
}

type sshdDTO struct {
	Read                   bool     `json:"read"`
	PubkeyAuthentication   string   `json:"pubkey_authentication"`
	PasswordAuthentication string   `json:"password_authentication"`
	PermitRootLogin        string   `json:"permit_root_login"`
	AuthorizedKeysFile     []string `json:"authorized_keys_file"`
	AuthorizedKeysCommand  string   `json:"authorized_keys_command"`
	KeysManagedElsewhere   bool     `json:"keys_managed_elsewhere"`
	CertificatesInUse      bool     `json:"certificates_in_use"`
}

type discoveredHostKeyDTO struct {
	KeyType     string `json:"key_type"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
	Weak        bool   `json:"weak"`
}

type warningDTO struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params"`
}

type unreadableDTO struct {
	OSUser   string `json:"os_user"`
	FilePath string `json:"file_path"`
	LineNo   int    `json:"line_no"`
}

type factsDTO struct {
	OS             osDTO                  `json:"os"`
	HelperVersion  string                 `json:"helper_version"`
	HelperProtocol int                    `json:"helper_protocol"`
	SSHD           *sshdDTO               `json:"sshd"`
	HostKeys       []discoveredHostKeyDTO `json:"host_keys"`
	Warnings       []warningDTO           `json:"warnings"`
	Unreadable     []unreadableDTO        `json:"unreadable"`
	Nginx          *nginxFactsDTO         `json:"nginx,omitempty"` // Nginx servers only
}

type targetDTO struct {
	ID                     string       `json:"id"`
	Name                   string       `json:"name"`
	Type                   string       `json:"type"`
	Host                   string       `json:"host"`
	Port                   int          `json:"port"`
	Username               string       `json:"username"`
	Status                 string       `json:"status"`
	LastError              *errorRefDTO `json:"last_error"`
	LastSuccessAt          *time.Time   `json:"last_success_at"`
	LastDiscoveryAt        *time.Time   `json:"last_discovery_at"`
	DiscoveryIntervalHours int          `json:"discovery_interval_hours"`
	KeysManagedElsewhere   bool         `json:"keys_managed_elsewhere"`
	Capabilities           []string     `json:"capabilities"`
	Facts                  factsDTO     `json:"facts"`
	Version                int          `json:"version"`
	CreatedAt              time.Time    `json:"created_at"`
	UpdatedAt              time.Time    `json:"updated_at"`
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func factsJSON(f inventory.Facts) factsDTO {
	d := factsDTO{
		OS:            osDTO{ID: f.OS.ID, VersionID: f.OS.VersionID, PrettyName: f.OS.PrettyName},
		HelperVersion: f.HelperVersion, HelperProtocol: f.HelperProtocol,
		HostKeys: []discoveredHostKeyDTO{}, Warnings: []warningDTO{}, Unreadable: []unreadableDTO{}, Nginx: nginxFactsJSON(f.Nginx),
	}
	if f.SSHD != nil {
		d.SSHD = &sshdDTO{
			Read: f.SSHD.Read, PubkeyAuthentication: f.SSHD.PubkeyAuthentication, PasswordAuthentication: f.SSHD.PasswordAuthentication,
			PermitRootLogin: f.SSHD.PermitRootLogin, AuthorizedKeysFile: nonNil(f.SSHD.AuthorizedKeysFile),
			AuthorizedKeysCommand: f.SSHD.AuthorizedKeysCommand, KeysManagedElsewhere: f.SSHD.KeysManagedElsewhere,
			CertificatesInUse: f.SSHD.CertificatesInUse,
		}
	}
	for _, k := range f.HostKeys {
		d.HostKeys = append(d.HostKeys, discoveredHostKeyDTO{KeyType: k.KeyType, Bits: k.Bits, Fingerprint: k.Fingerprint, Weak: k.Weak})
	}
	for _, w := range f.Warnings {
		params := w.Params
		if params == nil {
			params = map[string]string{}
		}
		d.Warnings = append(d.Warnings, warningDTO{Code: w.Code, Params: params})
	}
	for _, u := range f.Unreadable {
		d.Unreadable = append(d.Unreadable, unreadableDTO{OSUser: u.OSUser, FilePath: u.FilePath, LineNo: u.LineNo})
	}
	return d
}

func targetJSON(t inventory.Target) targetDTO {
	return targetDTO{
		ID: t.ID.String(), Name: t.Name, Type: t.Type, Host: t.Host, Port: t.Port, Username: t.Username,
		Status: t.Status, LastError: errorRef(t.LastErrorCode, nil),
		LastSuccessAt: utcPtr(t.LastSuccessAt), LastDiscoveryAt: utcPtr(t.LastDiscoveryAt),
		DiscoveryIntervalHours: int(t.DiscoveryInterval / time.Hour), KeysManagedElsewhere: t.KeysManagedElsewhere,
		Capabilities: nonNil(t.Capabilities), Facts: factsJSON(t.Facts), Version: t.Version,
		CreatedAt: t.CreatedAt.UTC(), UpdatedAt: t.UpdatedAt.UTC(),
	}
}

type hostKeyDTO struct {
	ID              string     `json:"id"`
	KeyType         string     `json:"key_type"`
	Fingerprint     string     `json:"fingerprint"`
	Status          string     `json:"status"`
	ObservedAt      time.Time  `json:"observed_at"`
	ConfirmedAt     *time.Time `json:"confirmed_at"`
	ConfirmedByName string     `json:"confirmed_by_name"`
	SupersededAt    *time.Time `json:"superseded_at"`
	VerifyCommand   string     `json:"verify_command"`
}

func hostKeyJSON(k inventory.HostKeyRecord) hostKeyDTO {
	return hostKeyDTO{
		ID: k.ID.String(), KeyType: k.KeyType, Fingerprint: k.Fingerprint, Status: k.Status, ObservedAt: k.ObservedAt.UTC(),
		ConfirmedAt: utcPtr(k.ConfirmedAt), ConfirmedByName: k.ConfirmedByName, SupersededAt: utcPtr(k.SupersededAt),
		VerifyCommand: inventory.VerifyCommand(k.KeyType), // what an administrator runs on the server (R33)
	}
}

type keyLocationDTO struct {
	ID                   string     `json:"id"`
	SSHKeyID             string     `json:"ssh_key_id"`
	Fingerprint          string     `json:"fingerprint"`
	KeyType              string     `json:"key_type"`
	TargetID             string     `json:"target_id"`
	TargetName           string     `json:"target_name"`
	OSUser               string     `json:"os_user"`
	FilePath             string     `json:"file_path"`
	LineNo               int        `json:"line_no"`
	Options              string     `json:"options"`
	Comment              string     `json:"comment"`
	Flags                []string   `json:"flags"`
	FirstSeenAt          time.Time  `json:"first_seen_at"`
	LastSeenAt           time.Time  `json:"last_seen_at"`
	MissingSince         *time.Time `json:"missing_since"`
	RemovedAt            *time.Time `json:"removed_at"`
	IsAliceConnectionKey bool       `json:"is_alice_connection_key"`
}

func keyLocationJSON(l inventory.KeyLocation) keyLocationDTO {
	return keyLocationDTO{
		ID: l.ID.String(), SSHKeyID: l.SSHKeyID.String(), Fingerprint: l.Fingerprint, KeyType: l.KeyType,
		TargetID: l.TargetID.String(), TargetName: l.TargetName, OSUser: l.OSUser, FilePath: l.FilePath, LineNo: l.LineNo,
		Options: l.Options, Comment: l.Comment, Flags: nonNil(l.Flags), FirstSeenAt: l.FirstSeenAt.UTC(),
		LastSeenAt: l.LastSeenAt.UTC(), MissingSince: utcPtr(l.MissingSince), RemovedAt: utcPtr(l.RemovedAt),
		IsAliceConnectionKey: l.IsAliceConnectionKey,
	}
}

type sshKeyDTO struct {
	ID            string           `json:"id"`
	Fingerprint   string           `json:"fingerprint"`
	KeyType       string           `json:"key_type"`
	Bits          int              `json:"bits"`
	PublicKey     string           `json:"public_key"`
	Managed       bool             `json:"managed"`
	IsPlatformKey bool             `json:"is_platform_key"`
	Weak          bool             `json:"weak"`
	Comment       string           `json:"comment"`
	LocationCount int              `json:"location_count"`
	TargetCount   int              `json:"target_count"`
	Missing       bool             `json:"missing"`
	FirstSeenAt   time.Time        `json:"first_seen_at"`
	Locations     []keyLocationDTO `json:"locations,omitempty"`
}

// sshKeyJSON renders a key; withLocations adds the locations array (always present, possibly empty).
func sshKeyJSON(k inventory.SSHKey, withLocations bool) sshKeyDTO {
	d := sshKeyDTO{
		ID: k.ID.String(), Fingerprint: k.Fingerprint, KeyType: k.KeyType, Bits: k.Bits, PublicKey: k.PublicKey,
		Managed: k.Managed, IsPlatformKey: k.IsPlatformKey, Weak: k.Weak, Comment: k.Comment,
		LocationCount: k.LocationCount, TargetCount: k.TargetCount, Missing: k.Missing, FirstSeenAt: k.FirstSeenAt.UTC(),
	}
	if withLocations {
		d.Locations = make([]keyLocationDTO, 0, len(k.Locations))
		for _, l := range k.Locations {
			d.Locations = append(d.Locations, keyLocationJSON(l))
		}
	}
	return d
}

type snippetDTO struct {
	Sudoers string `json:"sudoers"`
	Script  string `json:"script"`
}

type platformKeyDTO struct {
	PublicKey          string                `json:"public_key"`
	Fingerprint        string                `json:"fingerprint"`
	AuthorizedKeysLine string                `json:"authorized_keys_line"`
	HelperPath         string                `json:"helper_path"`
	HelperProtocol     int                   `json:"helper_protocol"`
	Profiles           map[string]snippetDTO `json:"profiles"`
}

func platformKeyJSON(g inventory.Guide) platformKeyDTO {
	d := platformKeyDTO{
		PublicKey: g.PublicKey, Fingerprint: g.Fingerprint, AuthorizedKeysLine: g.AuthorizedKeysLine,
		HelperPath: g.HelperPath, HelperProtocol: g.HelperProtocol, Profiles: map[string]snippetDTO{},
	}
	for name, p := range g.Profiles {
		d.Profiles[name] = snippetDTO{Sudoers: p.Sudoers, Script: p.Script}
	}
	return d
}

type jobDTO struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Kind        string         `json:"kind"`
	Status      string         `json:"status"`
	TargetID    *string        `json:"target_id"`
	Attempts    int            `json:"attempts"`
	MaxAttempts int            `json:"max_attempts"`
	Error       *errorRefDTO   `json:"error"`
	Result      map[string]any `json:"result"`
	CreatedAt   time.Time      `json:"created_at"`
	RunAt       time.Time      `json:"run_at"`
	StartedAt   *time.Time     `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at"`
}

// jobJSON maps a job. Its stored error params pass the provider param allowlist (they are shown
// as error.params only, never again under result.error_params), so a handler that ever stored
// remote text in them cannot leak it through the API.
func jobJSON(v jobs.View) jobDTO {
	d := jobDTO{
		ID: v.ID.String(), Type: v.Type, Kind: v.Kind, Status: string(v.Status), Attempts: v.Attempts, MaxAttempts: v.MaxAttempts,
		Error: errorRef(v.LastErrorCode, providerParams(v.ErrorParams)), Result: map[string]any{}, CreatedAt: v.CreatedAt.UTC(),
		RunAt: v.RunAt.UTC(), StartedAt: utcPtr(v.StartedAt), FinishedAt: utcPtr(v.FinishedAt),
	}
	for k, val := range v.Result {
		if k != "error_params" {
			d.Result[k] = val
		}
	}
	if v.TargetID != uuid.Nil {
		id := v.TargetID.String()
		d.TargetID = &id
	}
	return d
}

type fieldDTO struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Default  any      `json:"default"`
	LabelKey string   `json:"label_key"`
	HelpKey  string   `json:"help_key"`
	Pattern  string   `json:"pattern"`
	Min      int      `json:"min"`
	Max      int      `json:"max"`
	Values   []string `json:"values"`
}

type providerDTO struct {
	Kind           string   `json:"kind"`
	DisplayNameKey string   `json:"display_name_key"`
	Capabilities   []string `json:"capabilities"`
	ConfigSchema   struct {
		Fields []fieldDTO `json:"fields"`
	} `json:"config_schema"`
}

func providerJSON(d providers.Descriptor) providerDTO {
	out := providerDTO{Kind: string(d.Kind), DisplayNameKey: d.DisplayNameKey, Capabilities: []string{}}
	for _, c := range d.Capabilities {
		out.Capabilities = append(out.Capabilities, string(c))
	}
	out.ConfigSchema.Fields = []fieldDTO{}
	for _, f := range d.ConfigSchema.Fields {
		out.ConfigSchema.Fields = append(out.ConfigSchema.Fields, fieldDTO{
			Name: f.Name, Type: string(f.Type), Required: f.Required, Default: f.Default, LabelKey: f.LabelKey,
			HelpKey: f.HelpKey, Pattern: f.Pattern, Min: f.Min, Max: f.Max, Values: nonNil(f.Values),
		})
	}
	return out
}
