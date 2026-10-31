package providers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"alice/internal/secrets"
)

// The deployment targets groundwork (R59, phase G of docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md;
// rulings in docs/superpowers/rulings/deployment-targets-groundwork.md): what the Windows server, F5 BIG-IP and
// Kubernetes targets share. Nothing here changes a web server or a vault: their locations are certificate files
// (LocationServerFile, no locator), their backups stay on the server (BackupOnTarget) and they sign in as before.

// Target types and provider kinds of the three targets (targets.type, migration 00031). No provider of these kinds is
// registered by the groundwork: a target of these types cannot be added until its phase registers one.
const (
	TargetTypeWindows    = "windows"
	TargetTypeF5BigIP    = "f5_bigip"
	TargetTypeKubernetes = "kubernetes"

	KindWindows    Kind = "windows"
	KindF5BigIP    Kind = "f5bigip"
	KindKubernetes Kind = "kubernetes"
)

// LocationKind is certificate_locations.kind (G1).
type LocationKind string

// Location kinds. A certificate file of a web server has no locator; every other kind is identified by its Locator.
const (
	LocationServerFile    LocationKind = "server_file"    // a certificate and key file pair (Nginx, Apache, HAProxy)
	LocationWinSSLBinding LocationKind = "win_sslbinding" // an http.sys SSL binding of a Windows server
	LocationF5ClientSSL   LocationKind = "f5_clientssl"   // one certKeyChain entry of a BIG-IP client SSL profile
	LocationK8sTLSSecret  LocationKind = "k8s_tls_secret" //nolint:gosec // G101 false positive: a location kind (a Kubernetes Secret of type kubernetes.io/tls)
	LocationWinCCSFile    LocationKind = "win_ccs_file"   // a PFX file of a Windows server's Centralized Certificate Store (W5, migration 00036)
	LocationWinRDP        LocationKind = "win_rdp"        // the Remote Desktop listener RDP-Tcp of a Windows server (W6, migration 00037)
)

var locationKinds = []LocationKind{LocationServerFile, LocationWinSSLBinding, LocationF5ClientSSL, LocationK8sTLSSecret, LocationWinCCSFile,
	LocationWinRDP}

// Known reports a kind the schema takes.
func (k LocationKind) Known() bool {
	for _, x := range locationKinds {
		if x == k {
			return true
		}
	}
	return false
}

// IsFile reports a certificate file location; "" is a file (every web-server provider leaves the kind empty).
func (k LocationKind) IsFile() bool { return k == "" || k == LocationServerFile }

// OrFile is k, or LocationServerFile when k is empty.
func (k LocationKind) OrFile() LocationKind {
	if k == "" {
		return LocationServerFile
	}
	return k
}

// Bounds of a locator and of a location's details (the CHECKs of migration 00031).
const (
	MaxLocatorBytes    = 1024
	MaxLocatorKeys     = 16
	MaxLocatorText     = 256
	MaxDetailsBytes    = 16384
	MaxCanonicalLength = 1024 // cert_path of a location that is not a file: the locator's canonical text
)

var locatorKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Locator is the identity of a location that is not a file (certificate_locations.locator): a flat JSON object of at most
// MaxLocatorKeys keys (lower-case words), each a string of at most MaxLocatorText printable characters, an integer or a
// boolean. Its stored form is Canonical (keys sorted, no white space): two locators are the same location exactly when
// their canonical forms are equal. The provider of the kind validates what the keys mean; this checks the shape only.
type Locator map[string]any

// ErrLocator is the cause of a locator Canonical refuses.
var ErrLocator = errors.New("providers: the locator is not a flat object of short values")

// Canonical validates l's shape and returns its stored form. An empty or nil locator is refused.
func (l Locator) Canonical() ([]byte, error) {
	if len(l) == 0 || len(l) > MaxLocatorKeys {
		return nil, ErrLocator
	}
	norm := make(map[string]any, len(l))
	for k, v := range l {
		if !locatorKeyRE.MatchString(k) {
			return nil, ErrLocator
		}
		switch x := v.(type) {
		case string:
			if x == "" || utf8.RuneCountInString(x) > MaxLocatorText || !utf8.ValidString(x) || strings.ContainsFunc(x, notPrintable) {
				return nil, ErrLocator
			}
			norm[k] = x
		case bool:
			norm[k] = x
		case int:
			norm[k] = x
		case int64:
			norm[k] = x
		case float64: // what encoding/json gives for a number
			if x != math.Trunc(x) || math.Abs(x) > 1<<53 {
				return nil, ErrLocator
			}
			norm[k] = int64(x)
		case json.Number:
			n, err := x.Int64()
			if err != nil {
				return nil, ErrLocator
			}
			norm[k] = n
		default:
			return nil, ErrLocator
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(norm) // strings, integers and booleans cannot fail; map keys are sorted by encoding/json
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(out) > MaxLocatorBytes {
		return nil, ErrLocator
	}
	return out, nil
}

// ParseLocator reads a stored locator (nil for SQL NULL: a file location).
func ParseLocator(raw []byte) (Locator, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var l Locator
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLocator, err)
	}
	if _, err := l.Canonical(); err != nil {
		return nil, err
	}
	return l, nil
}

// Equal reports whether two locators name the same location (their canonical forms are equal; an invalid one equals
// nothing).
func (l Locator) Equal(o Locator) bool {
	a, err := l.Canonical()
	if err != nil {
		return false
	}
	b, err := o.Canonical()
	return err == nil && bytes.Equal(a, b)
}

func notPrintable(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) || r == utf8.RuneError
}

// ErrDetails is the cause of details that do not fit (MaxDetailsBytes) or are not an object of code-shaped keys.
var ErrDetails = errors.New("providers: the location details are not a bounded object")

var detailsKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// CanonicalDetails validates a location's details (facts the UI shows for a kind: a Secret's resourceVersion, a
// profile's object names, a store's key provider) and returns their stored form: a JSON object whose top-level keys are
// lower-case words, at most MaxDetailsBytes. nil or empty details are "{}".
func CanonicalDetails(d map[string]any) ([]byte, error) {
	if len(d) == 0 {
		return []byte("{}"), nil
	}
	for k := range d {
		if !detailsKeyRE.MatchString(k) {
			return nil, ErrDetails
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDetails, err)
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	// PostgreSQL's jsonb text adds a space after every ':' and ','; the CHECK measures that text.
	if len(out)+bytes.Count(out, []byte(":"))+bytes.Count(out, []byte(",")) > MaxDetailsBytes {
		return nil, ErrDetails
	}
	return out, nil
}

// Deployment step names of the new targets (G1), reported to the StepLogger like the helper's: a Windows server imports
// the intermediates and the certificate into its stores and re-points the http.sys binding (or, for a CCS file, writes
// the file: StepNameWriteFile, W5; for the Remote Desktop listener, lets NETWORK SERVICE read the key and sets the
// listener: StepNameGrantKeyRead, StepNameSetListener, W6); a BIG-IP uploads a PKCS #12,
// installs its objects, commits one transaction, synchronises its device group and saves its configuration; a Kubernetes
// cluster backs the Secret up into Alice (StepNameBackup) and writes it. Each target's steps end with the engine's own
// verify, restore and verify_old.
const (
	StepNameImportChain       = "import_chain"
	StepNameImportCertificate = "import_certificate"
	StepNameBind              = "bind"
	StepNameUpload            = "upload"
	StepNameInstall           = "install"
	StepNameCommit            = "commit"
	StepNameSync              = "sync"
	StepNameSave              = "save"
	StepNameWriteSecret       = "write_secret"
	StepNameWriteFile         = "write_file"
	StepNameGrantKeyRead      = "grant_key_read"
	StepNameSetListener       = "set_listener"
)

// BackupModel says where the previous content of a location stays while a rollback may need it (G5).
type BackupModel string

// Backup models.
const (
	// BackupOnTarget: the target keeps it (the helper's backup files, the previous certificate in a Windows store, the
	// previous BIG-IP objects); DeployOutcome.Backup (deployments.rollback_info) names what to point back to.
	BackupOnTarget BackupModel = "on_target"
	// BackupHeldByAlice: the target keeps nothing (a Kubernetes Secret is overwritten); the provider hands the previous
	// certificate and key to DeployRequest.Backups before the change and reads them from RollbackRequest.Backups.
	BackupHeldByAlice BackupModel = "held_by_alice"
)

// RollbackTraits is what a deploying provider declares about rollback (G5). SelfRestores says that the target may put
// the backup back by itself after a failed change (the Linux helper and the Windows helper do; a BIG-IP and a Kubernetes
// cluster never do: only Alice restores, after checking the guard). The R48 rule "a deployment that needs the guard must
// not run on a server that cannot check it itself" exists because of self-restore: RollbackGuard.SatisfiedBy applies it.
type RollbackTraits struct {
	Backup       BackupModel
	SelfRestores bool
}

// RollbackModel is implemented by a deploying provider that declares its traits; one that does not has
// DefaultRollbackTraits (the Linux helper's model).
type RollbackModel interface {
	RollbackTraits() RollbackTraits
}

// DefaultRollbackTraits are the traits of a provider that declares none: the backup on the target and a target that may
// restore by itself (the web-server providers: the helper's journal restores after a failed reload).
var DefaultRollbackTraits = RollbackTraits{Backup: BackupOnTarget, SelfRestores: true}

// TraitsOf returns p's declared rollback traits, or DefaultRollbackTraits.
func TraitsOf(p Provider) RollbackTraits {
	if m, ok := p.(RollbackModel); ok {
		return m.RollbackTraits()
	}
	return DefaultRollbackTraits
}

// ErrRollbackTraits is the cause of traits Validate refuses.
var ErrRollbackTraits = errors.New("providers: inconsistent rollback traits")

// Validate checks the traits: a known model, and a target that keeps no backup never restores by itself (it has nothing
// to restore from).
func (t RollbackTraits) Validate() error {
	switch {
	case t.Backup != BackupOnTarget && t.Backup != BackupHeldByAlice:
		return fmt.Errorf("%w: unknown backup model %q", ErrRollbackTraits, t.Backup)
	case t.Backup == BackupHeldByAlice && t.SelfRestores:
		return fmt.Errorf("%w: a target that keeps no backup cannot restore by itself", ErrRollbackTraits)
	}
	return nil
}

// SatisfiedBy reports whether a deployment with this guard may run on a target with traits t whose server checks the
// guard itself (serverChecks: the Linux helper from protocol 10, the Windows helper) or not. Only Required matters: a
// Required guard is satisfied when the target never restores by itself (Alice checks the guard before every restore it
// sends) or when the server checks it.
func (g RollbackGuard) SatisfiedBy(t RollbackTraits, serverChecks bool) bool {
	return !g.Required || !t.SelfRestores || serverChecks
}

// HeldBackup is the previous content of a location that a BackupHeldByAlice provider hands to Alice before it changes the
// location: the certificate chain as the target held it (leaf first) and its private key. It carries a key: Format and
// LogValue print nothing of it, it has no JSON form, and Zero clears the key in place.
type HeldBackup struct {
	CertificatePEM []byte            // public
	PrivateKeyPEM  secrets.Plaintext `json:"-"`
}

func (HeldBackup) redacted() string { return "providers.HeldBackup{key:[redacted]}" }

// Format prints nothing of the backup, for every verb and flag.
func (b HeldBackup) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, b.redacted()) }

// LogValue keeps the key out of slog output.
func (b HeldBackup) LogValue() slog.Value { return slog.StringValue(b.redacted()) }

// MarshalJSON keeps the backup out of every JSON rendering.
func (b HeldBackup) MarshalJSON() ([]byte, error) { return json.Marshal(b.redacted()) }

// Zero clears the key in place.
func (b HeldBackup) Zero() { b.PrivateKeyPEM.Zero() }

// HeldBackups is the engine's store of one deployment's held backup (BackupHeldByAlice). Hold stores the backup before
// the change (sealed like every key Alice holds); an error means it was not stored and the provider must not change the
// location. A backup is held once: a second Hold of the same deployment keeps the first (the content before any change
// of this deployment). Load returns it (the caller zeroes it), or ErrNoHeldBackup. A provider of another model ignores it.
type HeldBackups interface {
	Hold(ctx context.Context, b HeldBackup) error
	Load(ctx context.Context) (HeldBackup, error)
}

// ErrNoHeldBackup: the deployment holds no backup (none was taken, or it was deleted by the retention).
var ErrNoHeldBackup = errors.New("providers: no backup is held for this deployment")

// Sign-in secret kinds of an API target's credential (G3).
const (
	TargetSecretPassword          = "password"           // a user name and password (BIG-IP, used only to obtain a token)
	TargetSecretToken             = "token"              // a bearer token (a Kubernetes ServiceAccount token)
	TargetSecretClientCertificate = "client_certificate" // a client certificate and its key (Kubernetes)
)

// TargetSecret is the sign-in secret of an API target's credential. It carries secrets: Format and LogValue print the kind
// and user name only, the secret fields are Plaintext and have no JSON form, and Zero clears them in place.
type TargetSecret struct {
	Kind                 string            // TargetSecret*
	Username             string            // TargetSecretPassword
	Password             secrets.Plaintext `json:"-"` // TargetSecretPassword
	Token                secrets.Plaintext `json:"-"` // TargetSecretToken
	ClientCertificatePEM []byte            // TargetSecretClientCertificate (public)
	ClientKeyPEM         secrets.Plaintext `json:"-"` // TargetSecretClientCertificate
}

func (s TargetSecret) redacted() string {
	return fmt.Sprintf("providers.TargetSecret{kind:%s, username:%s, secret:[redacted]}", s.Kind, s.Username)
}

// Format prints the kind and the user name only, for every verb and flag (pointers too).
func (s TargetSecret) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, s.redacted()) }

// LogValue keeps the secrets out of slog output.
func (s TargetSecret) LogValue() slog.Value { return slog.StringValue(s.redacted()) }

// Zero clears the password, the token and the client key in place.
func (s TargetSecret) Zero() {
	s.Password.Zero()
	s.Token.Zero()
	s.ClientKeyPEM.Zero()
}

// TargetSecretSource is implemented by the credential source of an API target (a BIG-IP, a Kubernetes cluster), as
// AzureCredentialSource is by a vault's. release zeroes what was decrypted; the caller calls it as soon as the secret is
// used (a login, a request's header).
type TargetSecretSource interface {
	TargetSecret(ctx context.Context) (TargetSecret, func(), error)
}

// CCSPasswordSource is implemented by the platform credential source when it can answer the Centralized Certificate
// Store password of a Windows server (W5 Rulings 9 and 11): the password an Administrator set for target, or an error
// that matches ErrNoCCSPassword (and the inventory's ErrNotFound) when none was set. Any other error (the database, the
// master key, a credential of another target) says nothing about whether a password is set; ErrCCSPasswordUnusable
// marks the ones that will not pass. It answers only for a live Windows server and only with that server's own
// credential. release zeroes the password; the caller calls it as soon as the password was sent.
type CCSPasswordSource interface {
	CCSPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error)
}

// CCSPasswordSource's sentinel errors: ErrNoCCSPassword for a Windows server that has no CCS password set,
// ErrCCSPasswordUnusable for a stored password that cannot be used however often it is read again (a credential of
// another target or kind, or one this master key cannot decrypt). Any other error may pass (the database).
var (
	ErrNoCCSPassword       = errors.New("providers: no CCS password is set")
	ErrCCSPasswordUnusable = errors.New("providers: the CCS password cannot be used")
)

// WinRMPasswordSource is implemented by the platform credential source when it can answer the WinRM password of a
// Windows server whose transport is winrm (R71 Rulings 7 and 8): the password an Administrator set for target, or an
// error that matches ErrNoWinRMPassword (and the inventory's ErrNotFound) when none was set. Any other error (the
// database, the master key, a credential of another target) says nothing about whether a password is set;
// ErrWinRMPasswordUnusable marks the ones that will not pass. It answers only for a live Windows server and only with
// that server's own credential. release zeroes the password; the caller calls it as soon as the call that used it
// returned.
type WinRMPasswordSource interface {
	WinRMPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error)
}

// WinRMPasswordSource's sentinel errors: ErrNoWinRMPassword for a Windows server that has no WinRM password set,
// ErrWinRMPasswordUnusable for a stored password that cannot be used however often it is read again (a credential of
// another target or kind, or one this master key cannot decrypt). Any other error may pass (the database).
var (
	ErrNoWinRMPassword       = errors.New("providers: no WinRM password is set")
	ErrWinRMPasswordUnusable = errors.New("providers: the WinRM password cannot be used")
)

// HostKeyTypeTLSSPKI is host_keys.key_type of a TLS server identity (G2): the SubjectPublicKeyInfo of the certificate an
// API target presents, pinned and confirmed like an SSH host key.
const HostKeyTypeTLSSPKI = "tls-spki"

// TLSIdentity is the HostKey of a TLS server's SubjectPublicKeyInfo (DER): key type tls-spki, fingerprint
// "SHA256:" and the unpadded standard base64 of its SHA-256 (the form of an SSH fingerprint, 43 characters).
func TLSIdentity(spkiDER []byte) HostKey {
	sum := sha256.Sum256(spkiDER)
	return HostKey{Type: HostKeyTypeTLSSPKI, PublicKey: bytes.Clone(spkiDER), Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
}

// ValidTLSIdentity reports whether k is a TLS identity whose public key parses as a SubjectPublicKeyInfo and whose
// fingerprint is its own.
func ValidTLSIdentity(k HostKey) bool {
	if k.Type != HostKeyTypeTLSSPKI || len(k.PublicKey) == 0 {
		return false
	}
	if _, err := x509.ParsePKIXPublicKey(k.PublicKey); err != nil {
		return false
	}
	return TLSIdentity(k.PublicKey).Fingerprint == k.Fingerprint
}
