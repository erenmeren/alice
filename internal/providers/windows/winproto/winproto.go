// Package winproto is the protocol between Alice and the Windows helper (design 2026-10-21 §5, §7,
// R60): subcommand names, exit codes, error codes, the JSON answers and the argument vocabulary that
// both sides enforce. It uses only the standard library and helperproto, because the Windows helper
// imports it too.
package winproto

import (
	"regexp"
	"strings"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

// Protocol and locations. Protocol 1 spans W1 and W2 (Ruling 2): W2 adds iis-deploy, iis-restore,
// iis-status, iis-fence and iis-cleanup to it.
const (
	Protocol    = 1
	MinProtocol = 1
	Version     = "0.1.0" // helper version string; W2 sets "1.0.0"

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

// KnownApps names the applications whose http.sys bindings Alice recognises (win_foreign_app).
// Phase W0 (F8) has not confirmed these ids yet.
var KnownApps = map[string]string{
	AppIDIIS:                                 "iis",
	"{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}": "winrm",
	"{5d89a20c-beab-4389-9447-324788eb944a}": "adfs",
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

// ErrorResponse is the helper's refusal (stdout, JSON), as helperproto's.
type ErrorResponse struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code"`
	Message string `json:"message"`
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

// SSLBinding is one http.sys certificate binding (HTTP_SERVICE_CONFIG_SSL_*). Phase W0 (F2) has not
// confirmed the extended parameters of Windows Server 2022 and later; they are added when it does.
type SSLBinding struct {
	Type                    string `json:"type"`
	IP                      string `json:"ip,omitempty"`
	Host                    string `json:"host,omitempty"`
	Port                    int    `json:"port"`
	AppID                   string `json:"app_id"`
	CertSHA1                string `json:"cert_sha1"`
	Store                   string `json:"store"`
	Flags                   uint32 `json:"flags"`
	CertCheckMode           uint32 `json:"cert_check_mode"`
	RevocationFreshnessTime uint32 `json:"revocation_freshness_time"`
	URLRetrievalTimeout     uint32 `json:"url_retrieval_timeout"`
	CTLIdentifier           string `json:"ctl_identifier,omitempty"`
	CTLStore                string `json:"ctl_store,omitempty"`
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

// IISDumpResponse answers "iis-dump".
type IISDumpResponse struct {
	OK             bool               `json:"ok"`
	IIS            IISFacts           `json:"iis"`
	Bindings       []SSLBinding       `json:"bindings"`
	Certificates   []StoreCertificate `json:"certificates"`
	Sites          []Site             `json:"sites"`
	ExpiredInStore map[string]int     `json:"expired_in_store"`
	Warnings       []string           `json:"warnings"`
	Truncated      bool               `json:"truncated"`
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
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "{") {
		s = "{" + s + "}"
	}
	return s, ValidAppID(s)
}

// ValidStore reports whether s may name a certificate store.
func ValidStore(s string) bool { return storeRE.MatchString(s) }
