// Package pcsc connects the OpenPGP card protocol (package openpgp) to a YubiKey through the
// system's PC/SC service. The real transport is compiled only with the build tag yubikey, because
// it needs cgo and libpcsclite on Linux and macOS; without the tag Readers and Connect return
// ErrNoPCSC and the binary carries no PC/SC code.
//
// The signing connection holds the card exclusively (SCARD_SHARE_EXCLUSIVE, the constant
// shareMode of the tagged build). The OpenPGP applet's default PW1 policy unlocks one signature per
// VERIFY; on a shared connection another PC/SC client (scdaemon, a browser's smart card stack)
// could send its own PSO:CDS in the window between our VERIFY and our signature. The trade-off:
// while any other program has the card open, Connect fails with ErrSharingViolation, whose text
// tells the operator to run `gpgconf --kill scdaemon`; and while vendor-console holds the card,
// gpg cannot use it. Both are acceptable for a short-lived signing tool that closes the card as
// soon as the license is signed.
//
// No error of this package quotes APDU bytes: a command may hold the PIN.
package pcsc

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoPCSC is returned by every call of a build without the yubikey tag.
var ErrNoPCSC = errors.New("pcsc: this build has no YubiKey support (build with -tags yubikey)")

// Readable PC/SC failures. The tagged build maps the PC/SC status codes onto them; they exist in
// both builds so that callers can test for them without the tag.
var (
	ErrNoService         = errors.New("pcsc: the smart card service is not running (Linux: start pcscd)")
	ErrNoReaders         = errors.New("pcsc: no smart card reader is connected")
	ErrNoCard            = errors.New("pcsc: no card in the reader")
	ErrCardRemoved       = errors.New("pcsc: the card was removed or reset")
	ErrReaderUnavailable = errors.New("pcsc: the reader is not available (unplugged?)")
	ErrSharingViolation  = errors.New("pcsc: another program holds the card (often gpg's scdaemon: run gpgconf --kill scdaemon)")
	ErrTimeout           = errors.New("pcsc: the card did not answer in time")

	// ErrReaderNotFound: the named reader, or any YubiKey reader, is not connected.
	ErrReaderNotFound = errors.New("pcsc: reader not found")
	// ErrAmbiguousReader: no reader was named and more than one YubiKey is connected.
	ErrAmbiguousReader = errors.New("pcsc: more than one YubiKey is connected")
)

// pick chooses the reader to open: want itself when it names a connected reader exactly, or,
// when want is empty, the only reader whose name contains "yubi" in any letter case. Errors list
// reader names only (quoted, so a hostile name cannot drive the terminal).
func pick(names []string, want string) (string, error) {
	if want != "" {
		for _, n := range names {
			if n == want {
				return n, nil
			}
		}
		return "", fmt.Errorf("%w: %q is not connected; readers present: %s", ErrReaderNotFound, want, list(names))
	}
	var yubi []string
	for _, n := range names {
		if containsFold(n, "yubi") {
			yubi = append(yubi, n)
		}
	}
	switch len(yubi) {
	case 1:
		return yubi[0], nil
	case 0:
		return "", fmt.Errorf("%w: no YubiKey reader; readers present: %s", ErrReaderNotFound, list(names))
	default:
		return "", fmt.Errorf("%w: %s; name the reader to use", ErrAmbiguousReader, list(yubi))
	}
}

func list(names []string) string {
	if len(names) == 0 {
		return "(none)"
	}
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(q, ", ")
}

// containsFold reports whether sub occurs in s ignoring case. strings.ToLower is avoided on
// purpose (Turkish dotted i; the linter forbids it): EqualFold compares by Unicode simple folding.
func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}
