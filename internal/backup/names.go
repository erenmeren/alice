package backup

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Ext is the extension of every backup file; ChecksumExt follows it for the checksum file beside it.
const (
	Ext         = ".alicebak"
	ChecksumExt = ".sha256"
)

// maxNameLen is the longest file name most file systems allow.
const maxNameLen = 255

var (
	installationIDPattern = regexp.MustCompile(`^ALICE-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$`)
	kindPattern           = regexp.MustCompile(`^(auto|manual|pre-restore|pre-upgrade-[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)$`)
	// standardName is C7's pattern of the names Alice gives its backups.
	standardName = regexp.MustCompile(`^alice-backup-[0-9A-Z]{8}-[0-9]{8}T[0-9]{6}Z-(auto|manual|pre-restore|pre-upgrade-[0-9A-Za-z.-]+)\.alicebak$`)
)

// nameTimeLayout is the time in a standard name.
const nameTimeLayout = "20060102T150405Z"

// errName is wrapped by the name errors.
var errName = errors.New("backup: the backup name is not allowed")

// ValidKind reports whether k is a kind of C7 (auto, manual, pre-restore, pre-upgrade-<version>).
func ValidKind(k Kind) bool { return kindPattern.MatchString(string(k)) }

// FileName is the standard name of a backup (C7): alice-backup-<ID8>-<yyyymmddThhmmssZ>-<kind>.alicebak, ID8 being
// the first 8 symbols of the Installation ID.
func FileName(installationID string, at time.Time, kind Kind) (string, error) {
	if !installationIDPattern.MatchString(installationID) {
		return "", errors.New("backup: the installation ID is not in its canonical form")
	}
	if !ValidKind(kind) {
		return "", errName
	}
	id8 := strings.ReplaceAll(strings.TrimPrefix(installationID, "ALICE-"), "-", "")[:8]
	return "alice-backup-" + id8 + "-" + at.UTC().Format(nameTimeLayout) + "-" + string(kind) + Ext, nil
}

// ValidName reports whether name is a backup file name Alice reads or writes: a standard name (C7), or a name given
// with --out that ends in .alicebak, has no path separator, NUL, control character or leading dot, is UTF-8 and at
// most 255 bytes long. Nothing that fails it ever reaches the file system.
func ValidName(name string) bool {
	if standardName.MatchString(name) {
		return true
	}
	base, ok := strings.CutSuffix(name, Ext)
	if !ok || base == "" || len(name) > maxNameLen || strings.HasPrefix(name, ".") || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return r == '/' || r == '\\' || r == 0 || unicode.IsControl(r)
	})
}
