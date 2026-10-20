// Package issuer is the vendor side of licensing (spec §16.7, §19.2): the passphrase-protected
// signing key file, license issuing and the signed issuance ledger, and the release signing key
// (SEC-107, R43 rows 20 and 43), which is a separate key with its own purpose. Only
// cmd/licensectl, the release tools under tools/ and tests import it; the alice binary never
// links it (a test in cmd/alice checks this).
package issuer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"alice/internal/license"
)

// KDFParams are the Argon2id parameters of the key file.
type KDFParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// KeyKDF is used for new key files: stronger than backups, because the key is opened rarely
// and offline (256 MiB, 4 passes).
var KeyKDF = KDFParams{MemoryKiB: 256 * 1024, Time: 4, Threads: 4}

// File names and limits.
const (
	PrivateKeyFile      = "alice-license-private.pem"
	PublicKeyFile       = "alice-license-public.pem"
	LedgerFile          = "issued.csv"
	MinPassphraseWords  = 6
	MinPassphraseLength = 24

	privatePEMType        = "ALICE LICENSE SIGNING KEY"
	releasePrivatePEMType = "ALICE RELEASE SIGNING KEY"
	publicPEMType         = "PUBLIC KEY"
	keyAAD                = "alice/license-signing-key/v1"
	releaseKeyAAD         = "alice/release-signing-key/v1"
	maxKDFMemory          = 1024 * 1024 // KiB (1 GiB): a hostile key file cannot exhaust memory
	maxKDFTime            = 64
	saltSize              = 16
)

// Errors.
var (
	ErrWeakPassphrase  = errors.New("issuer: the passphrase needs at least 6 words and 24 characters")
	ErrWrongPassphrase = errors.New("issuer: wrong passphrase, or the key file is damaged")
	ErrKeyExists       = errors.New("issuer: a key file already exists here; keygen never overwrites a key")
	ErrBadKeyFile      = errors.New("issuer: this is not an Alice license signing key file")
	ErrBadKeyID        = errors.New("issuer: the key ID must look like vk-2026-01")
	ErrBadReleaseKeyID = errors.New("issuer: the release key ID must look like rk-2026-01")
	ErrWrongPurpose    = errors.New("issuer: this key is for another purpose: license and release signing keys are separate (spec §16.7)")
)

// Purpose says what a signing key signs. A key file without the PurposeHeader (every license key
// file written before release keys existed) is a license key.
type Purpose string

// The two purposes.
const (
	PurposeLicense Purpose = "license"
	PurposeRelease Purpose = "release"
)

// PurposeHeader is the PEM header naming a key file's purpose.
const PurposeHeader = "Alice-Key-Purpose"

// keyIDPattern is stricter than the license format's key ID rule: vendor keys are named by
// year and number, so the public test key ID (vk-test-01) can never be a vendor key.
var keyIDPattern = regexp.MustCompile(`^vk-\d{4}-\d{2}$`)

// Release key IDs: rk-YYYY-NN for vendor keys; rk-test-NN only for the throw-away keys of test
// packages (tools/releasesign), which are never passphrase key files (R43 row 43).
var (
	releaseKeyIDPattern     = regexp.MustCompile(`^rk-\d{4}-\d{2}$`)
	testReleaseKeyIDPattern = regexp.MustCompile(`^rk-test-\d{2}$`)
)

// IsReleaseKeyID reports whether id names a release key: rk-YYYY-NN, and with test also rk-test-NN.
func IsReleaseKeyID(id string, test bool) bool {
	return releaseKeyIDPattern.MatchString(id) || (test && testReleaseKeyIDPattern.MatchString(id))
}

// CheckPassphrase enforces R8/§16.7: at least six words (separated by spaces or dashes) and
// 24 characters, as a Diceware passphrase has.
func CheckPassphrase(p []byte) error {
	words := strings.FieldsFunc(string(p), func(r rune) bool { return unicode.IsSpace(r) || r == '-' })
	if len(words) < MinPassphraseWords || utf8.RuneCount(p) < MinPassphraseLength {
		return ErrWeakPassphrase
	}
	return nil
}

// SigningKey is an opened signing key. It never prints itself.
type SigningKey struct {
	id      string
	purpose Purpose
	priv    ed25519.PrivateKey
}

// KeyID returns the key ID (vk-YYYY-NN or rk-YYYY-NN).
func (k *SigningKey) KeyID() string { return k.id }

// Purpose returns what the key signs.
func (k *SigningKey) Purpose() Purpose { return k.purpose }

// Public returns the public key.
func (k *SigningKey) Public() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }

// Zero overwrites the private key in memory.
func (k *SigningKey) Zero() { clear(k.priv) }

func (k *SigningKey) redacted() string { return "issuer.SigningKey{" + k.id + " [redacted]}" }

// String never reveals the key.
func (k *SigningKey) String() string { return k.redacted() }

// GoString never reveals the key (%#v).
func (k *SigningKey) GoString() string { return k.redacted() }

// Format never reveals the key, whatever the verb (%x, %+v, ...).
func (k *SigningKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.redacted()) }

// LogValue never reveals the key in structured logs.
func (k *SigningKey) LogValue() slog.Value { return slog.StringValue(k.redacted()) }

// MarshalJSON never reveals the key.
func (k *SigningKey) MarshalJSON() ([]byte, error) { return json.Marshal(k.redacted()) }

// Issue signs p and returns the license file. Free-text fields are NFC-normalized before
// signing (04-security.md), so the same name typed on different systems signs the same bytes.
func (k *SigningKey) Issue(p license.Payload) ([]byte, error) {
	if k.purpose != PurposeLicense {
		return nil, ErrWrongPurpose
	}
	f, err := license.Sign(k.priv, k.id, normalize(p))
	if err != nil {
		return nil, err
	}
	return license.EncodeFile(f)
}

// SignRelease returns the raw 64-byte Ed25519 signature of data (a SHA256SUMS file or the outer
// .sha256 of a package, C5). Only a release key signs releases.
func (k *SigningKey) SignRelease(data []byte) ([]byte, error) {
	if k.purpose != PurposeRelease {
		return nil, ErrWrongPurpose
	}
	return ed25519.Sign(k.priv, data), nil
}

// NormalizePayload returns p as Issue signs it (free text in NFC). A signer that holds its key
// elsewhere (the vendor console's YubiKey signer) signs license.SignedBytes of this payload, so
// it signs exactly the bytes this package would.
func NormalizePayload(p license.Payload) license.Payload { return normalize(p) }

// normalize returns p with every free-text string in Unicode NFC.
func normalize(p license.Payload) license.Payload {
	p.LicenseID = norm.NFC.String(p.LicenseID)
	p.Customer = norm.NFC.String(p.Customer)
	p.Replaces = norm.NFC.String(p.Replaces)
	features := make([]string, 0, len(p.Features))
	for _, f := range p.Features {
		features = append(features, norm.NFC.String(f))
	}
	p.Features = features
	return p
}

// GenerateKey creates a license key pair: the private key encrypted under Argon2id(passphrase)
// with AES-256-GCM, and the public key as a PKIX PEM. Both carry the key ID.
func GenerateKey(keyID string, passphrase []byte, p KDFParams) (privPEM, pubPEM []byte, err error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, nil, ErrBadKeyID
	}
	privPEM, pub, err := generate(PurposeLicense, keyID, passphrase, p)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Headers: map[string]string{"Key-Id": keyID}, Bytes: der})
	return privPEM, pubPEM, nil
}

// GenerateReleaseKey creates a release key pair (key ID rk-YYYY-NN): the private key file is
// encrypted like a license key, has its own block type and the header "Alice-Key-Purpose: release"
// (both bound into the encryption), and the public key is written by EncodeReleasePublicKey.
func GenerateReleaseKey(keyID string, passphrase []byte, p KDFParams) (privPEM, pubPEM []byte, err error) {
	if !IsReleaseKeyID(keyID, false) {
		return nil, nil, ErrBadReleaseKeyID
	}
	privPEM, pub, err := generate(PurposeRelease, keyID, passphrase, p)
	if err != nil {
		return nil, nil, err
	}
	pubPEM, err = EncodeReleasePublicKey(keyID, pub)
	if err != nil {
		return nil, nil, err
	}
	return privPEM, pubPEM, nil
}

// generate creates the encrypted private key file of purpose and returns it with the public key.
func generate(purpose Purpose, keyID string, passphrase []byte, p KDFParams) ([]byte, ed25519.PublicKey, error) {
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	defer clear(priv)
	seed := priv.Seed()
	defer clear(seed)
	salt := make([]byte, saltSize)
	rand.Read(salt)
	headers := map[string]string{
		"Key-Id":     keyID,
		"Kdf":        "argon2id",
		"Kdf-Params": fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Time, p.Threads),
		"Salt":       base64.StdEncoding.EncodeToString(salt),
		"Public-Key": base64.StdEncoding.EncodeToString(pub),
	}
	blockType := privatePEMType
	if purpose == PurposeRelease {
		headers[PurposeHeader] = string(PurposeRelease)
		blockType = releasePrivatePEMType
	}
	gcm, err := keyCipher(passphrase, salt, p)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	headers["Nonce"] = base64.StdEncoding.EncodeToString(nonce)
	ct := gcm.Seal(nil, nonce, seed, keyAADFor(purpose, headers))
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Headers: headers, Bytes: ct}), pub, nil
}

func keyCipher(passphrase, salt []byte, p KDFParams) (cipher.AEAD, error) {
	kek := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, 32)
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keyAADFor binds the ciphertext to its purpose and headers: changing the purpose, the key ID, the
// KDF parameters, the salt or the public key makes the file fail to open. A license key keeps the
// AAD it always had, so existing key files open unchanged.
func keyAADFor(purpose Purpose, h map[string]string) []byte {
	prefix := keyAAD
	if purpose == PurposeRelease {
		prefix = releaseKeyAAD
	}
	return []byte(prefix + "\n" + h["Key-Id"] + "\n" + h["Kdf-Params"] + "\n" + h["Salt"] + "\n" + h["Public-Key"])
}

// OpenKey decrypts a license key file. A release key file is refused with ErrWrongPurpose
// before the passphrase is tried.
func OpenKey(pemBytes, passphrase []byte) (*SigningKey, error) {
	return openKey(PurposeLicense, pemBytes, passphrase)
}

// OpenReleaseKey decrypts a release key file. A license key file is refused with ErrWrongPurpose
// before the passphrase is tried.
func OpenReleaseKey(pemBytes, passphrase []byte) (*SigningKey, error) {
	return openKey(PurposeRelease, pemBytes, passphrase)
}

// filePurpose returns the purpose a private key block declares: its type and its purpose header
// must agree (a license block has no header, or "license").
func filePurpose(block *pem.Block) (Purpose, error) {
	header, has := block.Headers[PurposeHeader]
	switch {
	case block.Type == privatePEMType && (!has || header == string(PurposeLicense)):
		return PurposeLicense, nil
	case block.Type == releasePrivatePEMType && header == string(PurposeRelease):
		return PurposeRelease, nil
	}
	return "", ErrBadKeyFile
}

func openKey(want Purpose, pemBytes, passphrase []byte) (*SigningKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrBadKeyFile
	}
	purpose, err := filePurpose(block)
	if err != nil {
		return nil, err
	}
	if purpose != want {
		return nil, ErrWrongPurpose
	}
	h := block.Headers
	idOK := keyIDPattern.MatchString(h["Key-Id"])
	if purpose == PurposeRelease {
		idOK = IsReleaseKeyID(h["Key-Id"], false)
	}
	if !idOK || h["Kdf"] != "argon2id" {
		return nil, ErrBadKeyFile
	}
	var p KDFParams
	if _, err := fmt.Sscanf(h["Kdf-Params"], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil ||
		p.MemoryKiB == 0 || p.MemoryKiB > maxKDFMemory || p.Time == 0 || p.Time > maxKDFTime || p.Threads == 0 {
		return nil, ErrBadKeyFile
	}
	salt, err1 := base64.StdEncoding.Strict().DecodeString(h["Salt"])
	nonce, err2 := base64.StdEncoding.Strict().DecodeString(h["Nonce"])
	pub, err3 := base64.StdEncoding.Strict().DecodeString(h["Public-Key"])
	if err1 != nil || err2 != nil || err3 != nil || len(salt) != saltSize || len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadKeyFile
	}
	gcm, err := keyCipher(passphrase, salt, p)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrBadKeyFile
	}
	seed, err := gcm.Open(nil, nonce, block.Bytes, keyAADFor(purpose, h))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrBadKeyFile
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		clear(priv)
		return nil, ErrBadKeyFile
	}
	return &SigningKey{id: h["Key-Id"], purpose: purpose, priv: priv}, nil
}

// ReadPublicKey reads a public key file written by GenerateKey.
func ReadPublicKey(pemBytes []byte) (license.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != publicPEMType || !keyIDPattern.MatchString(block.Headers["Key-Id"]) {
		return license.PublicKey{}, ErrBadKeyFile
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return license.PublicKey{}, ErrBadKeyFile
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return license.PublicKey{}, ErrBadKeyFile
	}
	return license.PublicKey{ID: block.Headers["Key-Id"], Key: pub, Status: license.KeyActive}, nil
}

// EncodeReleasePublicKey returns a release public key file (C5): the line "key-id: <ID>" and the
// PKIX PEM block, which OpenSSL reads as it is (text before the block is skipped).
func EncodeReleasePublicKey(keyID string, pub ed25519.PublicKey) ([]byte, error) {
	if !IsReleaseKeyID(keyID, true) {
		return nil, ErrBadReleaseKeyID
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return append([]byte("key-id: "+keyID+"\n"), pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: der})...), nil
}

// ParseReleasePublicKey reads a file written by EncodeReleasePublicKey (production or test key
// ID; callers decide which they accept).
func ParseReleasePublicKey(raw []byte) (keyID string, pub ed25519.PublicKey, err error) {
	first, rest, ok := bytes.Cut(raw, []byte("\n"))
	id, isID := strings.CutPrefix(string(first), "key-id: ")
	if !ok || !isID || !IsReleaseKeyID(id, true) {
		return "", nil, ErrBadKeyFile
	}
	block, tail := pem.Decode(rest)
	if block == nil || block.Type != publicPEMType || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		return "", nil, ErrBadKeyFile
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", nil, ErrBadKeyFile
	}
	pub, isEd := k.(ed25519.PublicKey)
	if !isEd {
		return "", nil, ErrBadKeyFile
	}
	return id, pub, nil
}

// ReleaseFingerprint is the fingerprint install.sh prints and customers compare (C5, S-23): the
// hex SHA-256 of the DER public key, as "openssl pkey -pubin -outform DER | sha256sum" prints it.
func ReleaseFingerprint(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// WriteKeyPair writes a new license key pair into dir (created with mode 0700): the private key
// with mode 0600, the public key with 0644. It never overwrites an existing file.
func WriteKeyPair(dir, keyID string, passphrase []byte, p KDFParams) (privPath, pubPath string, err error) {
	return writePair(dir, filepath.Join(dir, PrivateKeyFile), filepath.Join(dir, PublicKeyFile), func() ([]byte, []byte, error) {
		return GenerateKey(keyID, passphrase, p)
	})
}

// WriteReleaseKeyPair writes a new release key pair into dir (created with mode 0700):
// <key ID>.key (encrypted, 0600) and <key ID>.pem (public, 0644, the file deploy/release/keys/
// holds). It never overwrites an existing file.
func WriteReleaseKeyPair(dir, keyID string, passphrase []byte, p KDFParams) (privPath, pubPath string, err error) {
	if !IsReleaseKeyID(keyID, false) {
		return "", "", ErrBadReleaseKeyID
	}
	return writePair(dir, filepath.Join(dir, keyID+".key"), filepath.Join(dir, keyID+".pem"), func() ([]byte, []byte, error) {
		return GenerateReleaseKey(keyID, passphrase, p)
	})
}

func writePair(dir, privPath, pubPath string, gen func() ([]byte, []byte, error)) (string, string, error) {
	for _, path := range []string{privPath, pubPath} {
		if _, err := os.Lstat(path); err == nil {
			return "", "", ErrKeyExists
		}
	}
	privPEM, pubPEM, err := gen()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	if err := WriteNew(privPath, privPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := WriteNew(pubPath, pubPEM, 0o644); err != nil {
		return "", "", err
	}
	return privPath, pubPath, nil
}

// WriteNew creates path with data and mode; it fails with ErrKeyExists if path exists
// (O_EXCL also refuses a symbolic link, dangling or not).
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: vendor CLI path from its own flags
	if errors.Is(err, os.ErrExist) {
		return ErrKeyExists
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Request is what the vendor types into licensectl issue.
type Request struct {
	Installation string   // as typed; the check character is verified
	Customer     string   // NFC-normalized
	Targets      int      // 1..100000
	From         string   // "" = today 00:00 UTC; "2026-10-01" or RFC 3339
	Months       int      // 0 = 12; at most 60
	Features     []string // empty entries are dropped
	Replaces     string   // license ID a correction replaces (R7)
	LicenseID    string   // "" = LIC-<year>-<6 random digits>
	// Days, when not 0, is a term of 1 to MaxEmergencyDays days instead of months, from the start
	// of the signing day (an emergency extension of the vendor console). It excludes Months, From
	// and Replaces. The payload is an ordinary license; only the vendor records what it is.
	Days int
}

// MaxEmergencyDays is the longest term in days (an emergency extension).
const MaxEmergencyDays = 30

// addMonths returns t plus n calendar months on the same day of the month, or on the last day of a shorter target
// month (2026-01-31 + 1 month = 2026-02-28). time.AddDate would carry the overflow into the next month (2026-03-03,
// review-fixes L-5). The time of day is kept.
func addMonths(t time.Time, n int) time.Time {
	first := time.Date(t.Year(), t.Month()+time.Month(n), 1, 0, 0, 0, 0, t.Location())
	last := first.AddDate(0, 1, -1).Day()
	return time.Date(first.Year(), first.Month(), min(t.Day(), last), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(),
		t.Location())
}

// BuildPayload turns a request into a valid payload. A license normally starts at most a day
// in the past (§16.3: issued_at <= valid_from + 24h); a correction license (Replaces) may start
// earlier and then carries issued_at = valid_from ("may have an earlier issued_at", R7).
func BuildPayload(req Request, now time.Time) (license.Payload, error) {
	now = now.UTC().Truncate(time.Second)
	id, err := license.ParseInstallationID(req.Installation)
	if err != nil {
		return license.Payload{}, fmt.Errorf("the installation ID %q is not valid; check each character (the last one is a check character): %w", strings.TrimSpace(req.Installation), err)
	}
	from := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if s := strings.TrimSpace(req.From); s != "" {
		if from, err = parseDate(s); err != nil {
			return license.Payload{}, err
		}
	}
	if req.Days != 0 {
		switch {
		case req.Days < 1 || req.Days > MaxEmergencyDays:
			return license.Payload{}, fmt.Errorf("an emergency extension lasts 1 to %d days", MaxEmergencyDays)
		case req.Months != 0 || strings.TrimSpace(req.From) != "" || strings.TrimSpace(req.Replaces) != "":
			return license.Payload{}, errors.New("an emergency extension starts on the signing day and is not a correction: it has no months, start date or replaced license")
		}
	}
	months := req.Months
	if months == 0 {
		months = 12
	}
	if months < 1 || months > 60 {
		return license.Payload{}, errors.New("--months must be between 1 and 60")
	}
	until := addMonths(from, months)
	if req.Days != 0 {
		until = from.AddDate(0, 0, req.Days)
	}
	issued := now
	if now.After(from.Add(24 * time.Hour)) {
		if strings.TrimSpace(req.Replaces) == "" {
			return license.Payload{}, errors.New("--from is more than a day in the past; only a correction license (--replaces) may start earlier")
		}
		issued = from
	}
	licenseID := strings.TrimSpace(req.LicenseID)
	if licenseID == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
		if err != nil {
			return license.Payload{}, err
		}
		licenseID = fmt.Sprintf("LIC-%d-%06d", now.Year(), n.Int64())
	}
	features := []string{}
	for _, f := range req.Features {
		if f = strings.TrimSpace(f); f != "" {
			features = append(features, f)
		}
	}
	p := normalize(license.Payload{
		LicenseID:      licenseID,
		Customer:       strings.TrimSpace(req.Customer),
		InstallationID: id,
		IssuedAt:       issued,
		ValidFrom:      from,
		ValidUntil:     until,
		MaxTargets:     req.Targets,
		Features:       features,
		Format:         license.FormatVersion,
		Replaces:       strings.TrimSpace(req.Replaces),
	})
	if err := p.Validate(); err != nil {
		return license.Payload{}, fmt.Errorf("the license would not be valid: %w", err)
	}
	return p, nil
}

func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Truncate(time.Second), nil
	}
	return time.Time{}, fmt.Errorf("--from %q must be a date like 2026-10-01 or an RFC 3339 time", s)
}
