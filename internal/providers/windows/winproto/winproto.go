// Package winproto is the protocol between Alice and the Windows helper (design 2026-10-21 §5, §7,
// R60, R61): subcommand names, exit codes, error codes, the JSON inputs and answers and the argument
// vocabulary that both sides enforce. It uses only the standard library and helperproto, because the
// Windows helper imports it too.
package winproto

import (
	"encoding/base64"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

// Protocol and locations. Protocol 1 spans W1 and W2 (W1 Ruling 2: nothing was released between
// them): W2 adds iis-deploy, iis-restore, iis-status and iis-fence to it; iis-cleanup is W3. Version
// is the helper's version string: 0.1.0 was W1's read-only helper, 0.2.0 is W2's (W2 Ruling 2);
// 1.0.0 is kept for the first released helper (W4). WriteMinVersion is the oldest helper Alice sends
// a write subcommand to (W2 Ruling 3).
const (
	Protocol        = 1
	MinProtocol     = 1
	Version         = "0.2.0"
	WriteMinVersion = "0.2.0"

	HelperPath   = `C:\Program Files\Alice\alice-helper.exe`
	DataDir      = `C:\ProgramData\Alice\helper`
	HelperBudget = 50 * time.Second
)

// Subcommands. SubSSH is the forced-command entry (sshd runs the helper with SSH_ORIGINAL_COMMAND).
const (
	SubSSH      = "ssh"
	SubVersion  = "version"
	SubWinFacts = "win-facts"
	SubIISDump  = "iis-dump"
	SubTLSProbe = "tls-probe"

	// The write subcommands (W2). Their command line is the subcommand and ArgOp <operation id>
	// only (W2 Ruling 4); iis-deploy reads a DeployInput and iis-restore a RestoreInput from stdin.
	SubIISDeploy  = "iis-deploy"
	SubIISRestore = "iis-restore"
	SubIISStatus  = "iis-status"
	SubIISFence   = "iis-fence"

	ArgOp = "--op"
)

// Exit codes equal helperproto's.
const (
	ExitOK           = helperproto.ExitOK
	ExitRefused      = helperproto.ExitRefused
	ExitPrecondition = helperproto.ExitPrecondition
	ExitFailed       = helperproto.ExitFailed
)

// Error codes of ErrorResponse.
const (
	CodeUsage             = "USAGE"
	CodeUnknownSubcommand = "UNKNOWN_SUBCOMMAND"
	CodeInvalidArgument   = "INVALID_ARGUMENT"
	CodeNotElevated       = "NOT_ELEVATED"
	CodeIOError           = "IO_ERROR"
	CodeProbeFailed       = "PROBE_FAILED"
	CodeOutputTooLarge    = "OUTPUT_TOO_LARGE"
	CodeStoreError        = "STORE_ERROR"

	// The write subcommands' codes (design §7). Where a code means what the Linux helper's means it
	// carries helperproto's name (a test compares).
	CodeHashMismatch    = helperproto.CodeHashMismatch    // the record names another certificate than expected (exit 3, nothing changed)
	CodeFenced          = helperproto.CodeFenced          // iis-deploy of a fenced operation (exit 3, nothing changed)
	CodeSuperseded      = helperproto.CodeSuperseded      // iis-restore of an operation that is no longer the binding's latest
	CodeOutcomeUnknown  = helperproto.CodeOutcomeUnknown  // the budget ended after the first durable write (exit 4)
	CodeBusy            = helperproto.CodeBusy            // another process held helper.lock for LockWait
	CodeRecoveryPending = helperproto.CodeRecoveryPending // the binding's latest operation is interrupted; ErrorResponse.PendingOp names it
	CodeUnknownOp       = "UNKNOWN_OP"                    // no journal of that operation
	CodeOperationExists = "OPERATION_EXISTS"              // iis-deploy of an operation the helper knows: a re-send never runs twice
	CodeBadContent      = "BAD_CONTENT"                   // stdin is not a valid input
	CodeTooLarge        = "TOO_LARGE"                     // stdin is over MaxDeployInput or MaxRestoreInput
	CodeIISNotFound     = "IIS_NOT_FOUND"
	CodeBindingNotFound = "BINDING_NOT_FOUND" // http.sys holds no record for the locator
	CodeBackupMissing   = "BACKUP_MISSING"    // the previous certificate is not in its store with a usable key
	CodeKeyUnusable     = "KEY_UNUSABLE"      // the certificate is in the store without a usable key
	CodeJournalFailed   = "JOURNAL_FAILED"    // the journal directory cannot be trusted or written
)

// Binding types of SSLBinding.Type.
const (
	BindingIPPort       = "ipport"
	BindingHostnamePort = "hostnameport"
	BindingCCS          = "ccs"
)

// Warnings: server level (IISDumpResponse.Warnings) and location level (WarnCTL).
const (
	WarnListTruncated  = "list_truncated"
	WarnSharedConfig   = "win_shared_config"
	WarnAutoCertRebind = "win_autocertrebind"
	WarnCCSEnabled     = "win_ccs_enabled"
	WarnExpiredInStore = "win_expired_in_store"
	WarnCTL            = "win_ctl"
)

// AppIDIIS is the application id IIS registers its http.sys bindings under.
const AppIDIIS = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"

// AppIDIISExpress is the application id of IIS Express, whose records fill the http.sys table of the
// GitHub runner images.
const AppIDIISExpress = "{214124cd-d05b-4309-9af9-9caa44b2b74a}"

// KnownApps names the applications whose http.sys bindings Alice recognises (win_foreign_app).
// Confirmed in W0 (design §14 F8); the AD FS id is unknown, so Alice shows the raw id for it.
var KnownApps = map[string]string{
	AppIDIIS:                                 "iis",
	AppIDIISExpress:                          "iisexpress",
	"{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}": "winrm",
	"{ba195980-cd49-458b-9e23-c84ee0adcd75}": "sstp",
}

// Bounds (Ruling 20) and the command line limits (Ruling 5).
const (
	MaxBindings     = 1000
	MaxCertificates = 1000
	MaxSites        = 2000
	MaxSiteBindings = 10000
	MaxChainCerts   = helperproto.MaxProbeChainCerts
	MaxCertDER      = 64 << 10
	MaxAppcmdOutput = 32 << 20
	DumpOutput      = helperproto.ServerDumpOutput

	MaxTokens    = 16
	MaxLineBytes = 4096
	MaxText      = 256 // names, friendly names, versions
)

// Journal phases, with the values of providers.Phase* (a test compares them); declared now so the W2
// journal exists from protocol 1.
const (
	PhaseNone             = "none"
	PhasePrepared         = "prepared"
	PhaseWriting          = "writing"
	PhaseCommitted        = "committed"
	PhaseUnchanged        = "unchanged"
	PhaseRestoring        = "restoring"
	PhaseRestored         = "restored"
	PhaseRestoreFailed    = "restore_failed"
	PhaseFenced           = "fenced"
	PhaseRestoreForbidden = "restore_forbidden"
)

// Steps of a deployment or restore, with the values of providers.StepName* (a test compares them).
const (
	StepImportChain       = "import_chain"
	StepImportCertificate = "import_certificate"
	StepBind              = "bind"
	StepJournal           = "journal"
	StepRestore           = "restore"
)

// Step.Status values, the words helperproto.NginxStep uses.
const (
	StepOK     = "ok"
	StepFailed = "failed"
)

// Step error classes (Step.Error and the answers' Error). ErrForbidden and ErrFileChanged equal
// providers.DeployErrForbidden and providers.DeployErrFileChanged.
const (
	ErrKeyUnusable   = "key_unusable"
	ErrReadBack      = "read_back"
	ErrStore         = "store_error"
	ErrFileChanged   = "file_changed"
	ErrForbidden     = "forbidden"
	ErrBackupMissing = "backup_missing"
)

// Bounds of the write subcommands. MaxExtendedBytes bounds each extended parameter's raw bytes.
// WriteGrace is how long a write subcommand may still finish its step or self-restore after its
// context ended (W2 Ruling 7).
const (
	MaxDeployInput    = 256 << 10
	MaxRestoreInput   = 32 << 10
	MaxExtendedParams = 16
	MaxExtendedBytes  = 4096
	MaxForbidden      = helperproto.MaxForbidden
	LockWait          = 20 * time.Second
	WriteGrace        = 8 * time.Second
)

// ErrorResponse is the helper's refusal (stdout, JSON), as helperproto's.
type ErrorResponse struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// PendingOp is set with CodeRecoveryPending only: the interrupted operation (a ValidOpID).
	PendingOp string `json:"pending_op,omitempty"`
}

// VersionResponse answers "version"; its tags are helperproto's so linuxssh.DecodeHelper reads it.
type VersionResponse struct {
	OK       bool   `json:"ok"`
	Helper   string `json:"helper"`
	Protocol int    `json:"protocol"`
}

// IISFacts is what the helper found about IIS.
type IISFacts struct {
	Installed      bool   `json:"installed"`
	Version        string `json:"version"`
	SharedConfig   bool   `json:"shared_config"`
	CCSEnabled     bool   `json:"ccs_enabled"`
	CCSPath        string `json:"ccs_path"`
	AutoCertRebind bool   `json:"autocertrebind"`
}

// WinFactsResponse answers "win-facts".
type WinFactsResponse struct {
	OK               bool     `json:"ok"`
	OSBuild          string   `json:"os_build"`
	OSProduct        string   `json:"os_product"`
	InstallationType string   `json:"installation_type"`
	Elevated         bool     `json:"elevated"`
	IIS              IISFacts `json:"iis"`
	Stores           []string `json:"stores"`
	OpenSSHVersion   string   `json:"openssh_version"`
}

// ExtendedParam is one extended parameter of an http.sys record (an HTTP_SSL_SERVICE_CONFIG_EX_PARAM_TYPE
// queried through the Ex configuration ids, F9): Data is the standard base64 of the parameter struct as
// read, at most MaxExtendedBytes raw bytes, so the helper can write it back byte for byte.
type ExtendedParam struct {
	Type uint32 `json:"type"`
	Data string `json:"data"`
}

// ValidExtended reports whether a record's extended parameters are within the bounds: at most
// MaxExtendedParams, each Data standard base64 of 1 to MaxExtendedBytes bytes, no Type twice (a record
// holds one parameter of each type).
func ValidExtended(params []ExtendedParam) bool {
	if len(params) > MaxExtendedParams {
		return false
	}
	seen := make(map[uint32]bool, len(params))
	for _, p := range params {
		if seen[p.Type] || p.Data == "" || len(p.Data) > base64.StdEncoding.EncodedLen(MaxExtendedBytes) {
			return false
		}
		seen[p.Type] = true
		raw, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil || len(raw) > MaxExtendedBytes {
			return false
		}
	}
	return true
}

// SSLBinding is one http.sys certificate binding (HTTP_SERVICE_CONFIG_SSL_*). Extended holds the
// record's extended parameters (at most MaxExtendedParams, Windows Server 2022 and later), absent when
// none is set.
type SSLBinding struct {
	Type                    string          `json:"type"`
	IP                      string          `json:"ip,omitempty"`
	Host                    string          `json:"host,omitempty"`
	Port                    int             `json:"port"`
	AppID                   string          `json:"app_id"`
	CertSHA1                string          `json:"cert_sha1"`
	Store                   string          `json:"store"`
	Flags                   uint32          `json:"flags"`
	CertCheckMode           uint32          `json:"cert_check_mode"`
	RevocationFreshnessTime uint32          `json:"revocation_freshness_time"`
	URLRetrievalTimeout     uint32          `json:"url_retrieval_timeout"`
	CTLIdentifier           string          `json:"ctl_identifier,omitempty"`
	CTLStore                string          `json:"ctl_store,omitempty"`
	Extended                []ExtendedParam `json:"extended,omitempty"`
}

// StoreCertificate is a certificate of a machine store. DER and Chain are standard base64; Chain is
// what CertGetCertificateChain built after the leaf, root excluded. KeyProblem is "", "key_missing"
// or "key_inaccessible".
type StoreCertificate struct {
	Store             string   `json:"store"`
	SHA1              string   `json:"sha1"`
	SHA256            string   `json:"sha256"`
	DER               string   `json:"der"`
	Chain             []string `json:"chain"`
	FriendlyName      string   `json:"friendly_name"`
	NotAfter          string   `json:"not_after"`
	HasKey            bool     `json:"has_key"`
	KeyProvider       string   `json:"key_provider"`
	KeyExportable     bool     `json:"key_exportable"`
	KeyUsableBySystem *bool    `json:"key_usable_by_system"`
	KeyProblem        string   `json:"key_problem,omitempty"`
}

// SiteBinding is one binding of an IIS site.
type SiteBinding struct {
	Protocol    string `json:"protocol"`
	Information string `json:"binding_information"`
	SSLFlags    int    `json:"ssl_flags"`
}

// Site is an IIS site.
type Site struct {
	Name     string        `json:"name"`
	ID       int64         `json:"id"`
	State    string        `json:"state"`
	Bindings []SiteBinding `json:"bindings"`
}

// CertificateRef names a certificate of a machine store.
type CertificateRef struct {
	Store string `json:"store"`
	SHA1  string `json:"sha1"`
}

// IISDumpResponse answers "iis-dump".
// DroppedCertificates names the certificates a binding names that the store holds but the helper left out (over
// MaxCertDER or MaxChainCerts, or malformed; Truncated is then set too), so Alice tells them from certificates the
// store does not hold (final review M3; protocol 1 grows, Ruling 2).
type IISDumpResponse struct {
	OK                  bool               `json:"ok"`
	IIS                 IISFacts           `json:"iis"`
	Bindings            []SSLBinding       `json:"bindings"`
	Certificates        []StoreCertificate `json:"certificates"`
	DroppedCertificates []CertificateRef   `json:"dropped_certificates"`
	Sites               []Site             `json:"sites"`
	ExpiredInStore      map[string]int     `json:"expired_in_store"`
	Warnings            []string           `json:"warnings"`
	Truncated           bool               `json:"truncated"`
}

// TLSProbeResponse is the shared tls-probe answer (design §7).
type TLSProbeResponse = helperproto.TLSProbeResponse

var (
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,253}$`)
	sha1RE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	appIDRE = regexp.MustCompile(`^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)
	storeRE = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
)

// ValidToken reports whether s may be one token of a forced command line.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// SplitCommandLine splits the line sshd passes in SSH_ORIGINAL_COMMAND: tokens separated by exactly
// one ASCII space, at most MaxTokens tokens and MaxLineBytes bytes, each a ValidToken. No quoting.
func SplitCommandLine(line string) ([]string, bool) {
	if len(line) > MaxLineBytes {
		return nil, false
	}
	tokens := strings.Split(line, " ")
	if !validTokens(tokens) {
		return nil, false
	}
	return tokens, true
}

// JoinCommandLine builds the line SplitCommandLine reads; false when a token is not a ValidToken, when
// there are no tokens or more than MaxTokens.
func JoinCommandLine(tokens []string) (string, bool) {
	if !validTokens(tokens) {
		return "", false
	}
	// MaxTokens tokens of 253 bytes and their separators are 4063 bytes: within MaxLineBytes.
	return strings.Join(tokens, " "), true
}

func validTokens(tokens []string) bool {
	if len(tokens) == 0 || len(tokens) > MaxTokens {
		return false
	}
	for _, t := range tokens {
		if !ValidToken(t) {
			return false
		}
	}
	return true
}

// ValidSHA1 reports whether s is 40 lower-case hex digits.
func ValidSHA1(s string) bool { return sha1RE.MatchString(s) }

// ValidAppID reports whether s is a lower-case braced GUID.
func ValidAppID(s string) bool { return appIDRE.MatchString(s) }

// CanonicalAppID accepts a GUID in upper or lower case, with or without braces, and returns the
// lower-case braced form.
func CanonicalAppID(s string) (string, bool) {
	s = strings.ToLower(s) //nolint:forbidigo // a GUID is ASCII
	if !strings.HasPrefix(s, "{") {
		s = "{" + s + "}"
	}
	return s, ValidAppID(s)
}

// ValidStore reports whether s may name a certificate store.
func ValidStore(s string) bool { return storeRE.MatchString(s) }

// Locator names the http.sys record a write subcommand acts on: the providers.Locator of a
// win_sslbinding location (type, ip or host, port, app_id).
type Locator struct {
	Type  string `json:"type"`
	IP    string `json:"ip,omitempty"`
	Host  string `json:"host,omitempty"`
	Port  int    `json:"port"`
	AppID string `json:"app_id"`
}

// Canonical is the locator's canonical text, the text W1's discovery gives the same record
// ("http.sys/hostnameport/<host>:<port>", "http.sys/ipport/<addr:port>"). False for a locator Alice
// does not deploy to: a ccs record, a host that is not a ValidHost, an IP not in its canonical form,
// a port outside 1-65535, an application id that is not a lower-case braced GUID, or the other
// type's member set.
func (l Locator) Canonical() (string, bool) {
	if !ValidAppID(l.AppID) || l.Port < 1 || l.Port > 65535 {
		return "", false
	}
	switch l.Type {
	case BindingHostnamePort:
		if l.IP != "" || !ValidHost(l.Host) {
			return "", false
		}
		return "http.sys/hostnameport/" + l.Host + ":" + strconv.Itoa(l.Port), true
	case BindingIPPort:
		ip, err := netip.ParseAddr(l.IP)
		if err != nil || l.Host != "" || ip.Zone() != "" || ip.Unmap().String() != l.IP {
			return "", false
		}
		return "http.sys/ipport/" + netip.AddrPortFrom(ip, uint16(l.Port)).String(), true //nolint:gosec // G115: 1..65535
	}
	return "", false
}

var hostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// nilUUID is never an operation id.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// ValidHost reports whether s is a host name Alice deploys to (W2 Ruling 5): labels of 1 to 63 ASCII
// lower-case letters, digits and inner hyphens, at most 253 bytes, a leading "*." label allowed. An IDN
// is deployable by its A-label; a U-label and a name in upper case (not folded) are refused.
func ValidHost(s string) bool { return len(s) <= 253 && hostRE.MatchString(s) }

// ValidOpID reports whether s is a lower-case UUID in 8-4-4-4-12 form, not the nil UUID.
func ValidOpID(s string) bool { return s != nilUUID && helperproto.ValidOpID(s) }

// ValidForbidden reports a forbidden list as helperproto's: at most MaxForbidden entries, each 64
// lower-case hex digits, none twice.
func ValidForbidden(list []string) bool { return helperproto.ValidForbidden(list) }

// VersionAtLeast compares dotted-decimal versions (at most 4 parts of 1 to 5 digits, missing parts
// zero): true when v is min or later. A version or minimum outside that form is never at least.
func VersionAtLeast(v, min string) bool {
	a, ok := versionParts(v)
	b, okMin := versionParts(min)
	if !ok || !okMin {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

func versionParts(v string) ([4]int, bool) {
	var out [4]int
	parts := strings.Split(v, ".")
	if len(parts) > len(out) {
		return out, false
	}
	for i, p := range parts {
		if p == "" || len(p) > 5 || strings.Trim(p, "0123456789") != "" {
			return out, false
		}
		out[i], _ = strconv.Atoi(p) // at most five digits always parse
	}
	return out, true
}

// DeployInput is the JSON on iis-deploy's stdin (W2 Ruling 4), at most MaxDeployInput bytes. ExpectSHA256
// is the DER SHA-256 of the certificate the record must name now (the compare-and-swap token); ChainPEM is
// the leaf and its intermediates; ForbiddenSPKI and ForbiddenLeaf are the rollback guard (R48, at most
// MaxForbidden ValidForbidden hashes each). The target store is not sent: the helper keeps the record's.
//
// It carries a private key: its String, GoString and LogValue redact the values so %v, %+v, %#v, %s and
// slog never print them. The type must still never be put into a log or an error: %d and json.Marshal
// print the fields (the wire form requires marshaling).
type DeployInput struct {
	Locator       Locator  `json:"locator"`
	ExpectSHA256  string   `json:"expect_sha256"`
	ChainPEM      string   `json:"chain_pem"`
	KeyPEM        string   `json:"key_pem"`
	ForbiddenSPKI []string `json:"forbidden_spki_sha256"`
	ForbiddenLeaf []string `json:"forbidden_leaf_sha256"`
}

// String redacts the key material so %v and %+v never print it.
func (DeployInput) String() string { return "winproto.DeployInput{redacted}" }

// GoString redacts the key material so %#v never prints it.
func (DeployInput) GoString() string { return "winproto.DeployInput{redacted}" }

// LogValue redacts the key material for log/slog handlers.
func (DeployInput) LogValue() slog.Value { return slog.StringValue("redacted") }

// Step is one step of a deployment or restore: Name a Step*, Status "ok" or "failed", Error an Err*
// class or "" (never raw text).
type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// DeployResponse answers iis-deploy. Phase is PhaseCommitted, PhaseUnchanged, PhaseRestored,
// PhaseRestoreFailed or PhaseRestoreForbidden; FailedStep, CauseStep and Error as
// helperproto.NginxDeployResponse's. The SHA-1 and DER SHA-256 name the new and the previous
// certificate, Store the store the record names (the one it named before: a binding never moves
// between stores). AliceImported is false when the certificate was in the store already;
// BuiltChainLength is the chain the helper built after the imports, leaf included, root excluded.
type DeployResponse struct {
	OK               bool   `json:"ok"`
	Phase            string `json:"phase"`
	FailedStep       string `json:"failed_step"`
	CauseStep        string `json:"cause_step"`
	Error            string `json:"error"`
	Steps            []Step `json:"steps"`
	NewSHA1          string `json:"new_sha1"`
	NewSHA256        string `json:"new_sha256"`
	PreviousSHA1     string `json:"previous_sha1"`
	PreviousSHA256   string `json:"previous_sha256"`
	Store            string `json:"store"`
	AliceImported    bool   `json:"alice_imported"`
	BuiltChainLength int    `json:"built_chain_length"`
}

// RestoreInput is the JSON on iis-restore's stdin, at most MaxRestoreInput bytes: the rollback guard as
// it stands now, checked together with the journal's lists. Both members are required (possibly empty),
// each at most MaxForbidden ValidForbidden hashes.
type RestoreInput struct {
	ForbiddenSPKI []string `json:"forbidden_spki_sha256"`
	ForbiddenLeaf []string `json:"forbidden_leaf_sha256"`
}

// RestoreResponse answers iis-restore.
type RestoreResponse struct {
	OK         bool   `json:"ok"`
	Phase      string `json:"phase"`
	FailedStep string `json:"failed_step"`
	CauseStep  string `json:"cause_step"`
	Error      string `json:"error"`
	Steps      []Step `json:"steps"`
}

// StatusResponse answers iis-status and iis-fence (helperproto.NginxStatusResponse without
// backup_dir). Active is "another process holds helper.lock now".
type StatusResponse struct {
	OK                bool   `json:"ok"`
	Phase             string `json:"phase"`
	Active            bool   `json:"active"`
	FailedStep        string `json:"failed_step"`
	CauseStep         string `json:"cause_step"`
	Error             string `json:"error"`
	NewCertSHA256     string `json:"new_cert_sha256"`
	CurrentCertSHA256 string `json:"current_cert_sha256"`
}
