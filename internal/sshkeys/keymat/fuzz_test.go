package keymat

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzAuthorizedLine (spec §25.6, with FuzzParseAuthorizedKeys): Line never panics, and a line it
// accepts is exactly one plain key line with the requested comment, no line break and no
// certificate authority.
func FuzzAuthorizedLine(f *testing.F) {
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	f.Add("", pub, "c")
	f.Add(`from="10.0.0.0/8",restrict`, pub, "alice:web:2026-10-05")
	f.Add("cert-authority", pub, "c")
	f.Add(`command="a\"b"`, pub, "c")
	f.Fuzz(func(t *testing.T, options, publicKey, comment string) {
		line, err := Line(options, publicKey, comment)
		if err != nil {
			return
		}
		if strings.ContainsAny(line, "\r\n\x00") {
			t.Fatalf("line break in %q", line)
		}
		_, got, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(rest) != 0 || got != comment {
			t.Fatalf("accepted line does not parse back: %q", line)
		}
		for _, o := range opts {
			if strings.EqualFold(o, "cert-authority") {
				t.Fatalf("certificate authority accepted: %q", line)
			}
		}
	})
}
