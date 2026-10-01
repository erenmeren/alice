package linuxssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

var (
	// ErrAuthorizedKeysTooLarge means the file is larger than helperproto.MaxAuthorizedKeysSize.
	ErrAuthorizedKeysTooLarge = errors.New("linuxssh: authorized_keys file too large")
	// ErrInvalidKeyLine means a line to add is not exactly one valid key line.
	ErrInvalidKeyLine = errors.New("linuxssh: not a single valid authorized_keys line")
)

// LineKind classifies one line of an authorized_keys file.
type LineKind int

// Line kinds.
const (
	LineBlank LineKind = iota
	LineComment
	LineKey
	LineInvalid
)

// Line is one line of an authorized_keys file. Raw is kept verbatim so a rewrite changes only
// the lines Alice means to change (spec §13.3 step 3).
type Line struct {
	Raw         string // verbatim, without the line terminator
	CR          bool   // the line ended with "\r\n" (or is a last line ending in "\r")
	Kind        LineKind
	Options     []string
	OptionsText string // verbatim options prefix ("" when none)
	KeyType     string
	PublicKey   string // "type base64"
	Fingerprint string
	Bits        int
	Comment     string
}

// AuthorizedKeys is a parsed file.
type AuthorizedKeys struct {
	Lines           []Line
	TrailingNewline bool
}

// ParseAuthorizedKeys parses data line by line. It never fails on content: lines that are not a
// valid key are kept as LineInvalid. Only a file over the size limit is refused.
func ParseAuthorizedKeys(data []byte) (AuthorizedKeys, error) {
	if len(data) > helperproto.MaxAuthorizedKeysSize {
		return AuthorizedKeys{}, ErrAuthorizedKeysTooLarge
	}
	var a AuthorizedKeys
	if len(data) == 0 {
		return a, nil
	}
	text := string(data)
	if strings.HasSuffix(text, "\n") {
		a.TrailingNewline = true
		text = text[:len(text)-1]
	}
	for _, raw := range strings.Split(text, "\n") {
		a.Lines = append(a.Lines, parseLine(raw))
	}
	return a, nil
}

func parseLine(raw string) Line {
	l := Line{Raw: raw}
	if strings.HasSuffix(raw, "\r") {
		l.CR = true
		l.Raw = raw[:len(raw)-1]
	}
	t := strings.TrimSpace(l.Raw)
	switch {
	case t == "":
		l.Kind = LineBlank
	case t[0] == '#':
		l.Kind = LineComment
	default:
		parseKeyLine(&l)
	}
	return l
}

// parseKeyLine fills l from a line that should hold one key. x/crypto/ssh ignores everything after
// a '\r' inside a line, so such a line is refused instead of half-trusted.
func parseKeyLine(l *Line) {
	l.Kind = LineInvalid
	if strings.ContainsRune(l.Raw, '\r') {
		return
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(l.Raw))
	if err != nil || len(rest) != 0 {
		return
	}
	l.Kind = LineKey
	l.Options = options
	l.KeyType = key.Type()
	l.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	l.Fingerprint = ssh.FingerprintSHA256(key)
	l.Bits = keyBits(key)
	l.Comment = comment
	l.OptionsText = optionsText(l.Raw, key)
}

// optionsText returns the verbatim text before the key type field: the part of the line between
// its start and the type token that precedes the base64 blob.
func optionsText(raw string, key ssh.PublicKey) string {
	blob := base64.StdEncoding.EncodeToString(key.Marshal())
	idx := strings.Index(raw, blob)
	if idx <= 0 {
		return ""
	}
	prefix := strings.TrimRight(raw[:idx], " \t")
	i := strings.LastIndexAny(prefix, " \t")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(prefix[:i])
}

// keyBits is the RSA modulus size, the ECDSA curve size or 256 for Ed25519 (also for FIDO keys).
func keyBits(k ssh.PublicKey) int {
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch p := ck.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return p.N.BitLen()
	case *ecdsa.PublicKey:
		return p.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// Bytes serializes the file; for an unchanged parse it is byte-for-byte the input.
func (a AuthorizedKeys) Bytes() []byte {
	var b strings.Builder
	for i, l := range a.Lines {
		b.WriteString(l.Raw)
		if l.CR {
			b.WriteByte('\r')
		}
		if i < len(a.Lines)-1 || a.TrailingNewline {
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// CountKeys returns the number of key lines.
func (a AuthorizedKeys) CountKeys() int {
	n := 0
	for _, l := range a.Lines {
		if l.Kind == LineKey {
			n++
		}
	}
	return n
}

// Keys lists the key lines as discovered keys (line numbers start at 1) and the lines that are
// neither keys, comments nor blank.
func (a AuthorizedKeys) Keys(osUser, filePath string) ([]providers.DiscoveredSSHKey, []providers.UnreadableLine) {
	count := map[string]int{}
	for _, l := range a.Lines {
		if l.Kind == LineKey {
			count[l.Fingerprint]++
		}
	}
	var keys []providers.DiscoveredSSHKey
	var bad []providers.UnreadableLine
	for i, l := range a.Lines {
		switch l.Kind {
		case LineKey:
			keys = append(keys, providers.DiscoveredSSHKey{
				OSUser: osUser, FilePath: filePath, LineNo: i + 1, PublicKey: l.PublicKey, Fingerprint: l.Fingerprint,
				KeyType: l.KeyType, Bits: l.Bits, Comment: l.Comment, Options: l.OptionsText,
				Flags: flagsFor(l, osUser, count[l.Fingerprint] > 1),
			})
		case LineInvalid:
			bad = append(bad, providers.UnreadableLine{OSUser: osUser, FilePath: filePath, LineNo: i + 1})
		}
	}
	return keys, bad
}

// flagsFor returns the dangerous-finding flags of §13.3 step 5 in a fixed order.
func flagsFor(l Line, osUser string, duplicate bool) []string {
	var f []string
	if (l.KeyType == ssh.KeyAlgoRSA && l.Bits < 2048) || l.KeyType == algoDSA {
		f = append(f, providers.FlagWeak)
	}
	if hasOption(l.Options, "command") {
		f = append(f, providers.FlagCommand)
	}
	if osUser == "root" && !hasOption(l.Options, "from") {
		f = append(f, providers.FlagRootWithoutFrom)
	}
	if duplicate {
		f = append(f, providers.FlagDuplicate)
	}
	if hasOption(l.Options, "cert-authority") {
		f = append(f, providers.FlagCertAuthority)
	}
	if strings.HasPrefix(l.KeyType, "sk-") {
		f = append(f, providers.FlagSecurityKey)
	}
	return f
}

// hasOption reports whether an option name is present (OpenSSH option names are case-insensitive).
func hasOption(opts []string, name string) bool {
	for _, o := range opts {
		k := o
		if i := strings.IndexByte(o, '='); i >= 0 {
			k = o[:i]
		}
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return true
		}
	}
	return false
}

// AddLine returns a copy with line appended on a line of its own (F-37) and true, or the file
// unchanged and false when a line with the same fingerprint exists. line must be exactly one
// valid key line without control characters. A file whose lines all end in CRLF keeps CRLF.
func (a AuthorizedKeys) AddLine(line string) (AuthorizedKeys, bool, error) {
	for _, r := range line {
		if r < 0x20 || r == 0x7f {
			return a, false, ErrInvalidKeyLine
		}
	}
	nl := parseLine(line)
	if nl.Kind != LineKey {
		return a, false, ErrInvalidKeyLine
	}
	for _, l := range a.Lines {
		if l.Kind == LineKey && l.Fingerprint == nl.Fingerprint {
			return a, false, nil
		}
	}
	if len(a.Lines) > 0 {
		allCR := true
		for _, l := range a.Lines {
			allCR = allCR && l.CR
		}
		nl.CR = allCR
	}
	lines := make([]Line, 0, len(a.Lines)+1)
	lines = append(append(lines, a.Lines...), nl)
	return AuthorizedKeys{Lines: lines, TrailingNewline: true}, true, nil
}

// RemoveFingerprint returns a copy without every key line of that fingerprint and how many were
// removed. Comment, blank and invalid lines are never touched, and the line before a removed
// last line keeps its terminator.
func (a AuthorizedKeys) RemoveFingerprint(fp string) (AuthorizedKeys, int) {
	out := AuthorizedKeys{TrailingNewline: a.TrailingNewline}
	removed := 0
	lastRemoved := false
	for i, l := range a.Lines {
		if l.Kind == LineKey && l.Fingerprint == fp {
			removed++
			lastRemoved = i == len(a.Lines)-1
			continue
		}
		out.Lines = append(out.Lines, l)
	}
	if lastRemoved && !a.TrailingNewline && len(out.Lines) > 0 {
		out.TrailingNewline = true
	}
	if len(out.Lines) == 0 {
		out.TrailingNewline = false
	}
	return out, removed
}

// algoDSA is the "ssh-dss" key type; the x/crypto constant is deprecated, and Alice only needs the name.
const algoDSA = "ssh-dss"
