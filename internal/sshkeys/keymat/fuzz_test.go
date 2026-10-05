package keymat

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// unquotedBytes returns options with every double-quoted value (backslash escapes honoured) reduced to "Q".
// It is deliberately written apart from validOptions: the fuzz target checks Line against it.
func unquotedBytes(options string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(options); i++ {
		switch c := options[i]; {
		case in && c == '\\':
			i++
		case in:
			in = c != '"'
		case c == '"':
			in = true
			b.WriteByte('Q') // a quoted value stands for one printable character
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// FuzzAuthorizedLine (spec §25.6, with FuzzParseAuthorizedKeys): Line never panics, and a line it
// accepts is exactly one plain key line with the requested comment. The checks do not rely on the
// parser Line uses itself: one line, no control byte anywhere, options as given with only printable
// ASCII outside quoted values and no empty item, the key and comment split on single spaces as sshd
// reads them, and no certificate authority.
func FuzzAuthorizedLine(f *testing.F) {
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	f.Add("", pub, "c")
	f.Add(`from="10.0.0.0/8",restrict`, pub, "alice:web:2026-10-05")
	f.Add("cert-authority", pub, "c")
	f.Add(`command="a\"b"`, pub, "c")
	f.Add("\vrestrict", pub, "c")
	f.Add("restrict,", pub, "c")
	f.Fuzz(func(t *testing.T, options, publicKey, comment string) {
		line, err := Line(options, publicKey, comment)
		if err != nil {
			return
		}
		for i := 0; i < len(line); i++ {
			if line[i] < ' ' || line[i] == 0x7f {
				t.Fatalf("control byte %#x in %q", line[i], line)
			}
		}
		prefix := ""
		if options != "" {
			prefix = options + " "
			if bad := unquotedBytes(options); strings.ContainsAny(bad, " \t") || strings.Contains(bad, ",,") ||
				strings.HasPrefix(bad, ",") || strings.HasSuffix(bad, ",") {
				t.Fatalf("options accepted with a bad separator: %q", options)
			}
			for _, r := range unquotedBytes(options) {
				if r < '!' || r > '~' {
					t.Fatalf("non-printable option byte %q in %q", r, options)
				}
			}
		}
		if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, " "+comment) {
			t.Fatalf("line is not options + key + comment: %q", line)
		}
		key := strings.TrimSuffix(strings.TrimPrefix(line, prefix), " "+comment)
		if len(strings.Split(key, " ")) != 2 || strings.Contains(comment, " ") {
			t.Fatalf("key is not two fields: %q", line)
		}
		want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
		if err != nil || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(want))) != key {
			t.Fatalf("the key in %q is not the key given", line)
		}
		for _, o := range strings.Split(unquotedBytes(options), ",") {
			if strings.EqualFold(strings.SplitN(o, "=", 2)[0], "cert-authority") {
				t.Fatalf("certificate authority accepted: %q", line)
			}
		}
	})
}
