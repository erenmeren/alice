package linuxssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// pubKeyLine returns "type base64" for pub and its SHA-256 fingerprint. Key material is generated
// at test time; no private key is ever committed (spec §22.6).
func pubKeyLine(t testing.TB, pub any) (string, string) {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), ssh.FingerprintSHA256(k)
}

func edKey(t testing.TB) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pubKeyLine(t, pub)
}

func rsaKey(t testing.TB, bits int) (string, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits) //nolint:gosec // G403: a weak test key on purpose (flag "weak")
	require.NoError(t, err)
	return pubKeyLine(t, &priv.PublicKey)
}

func ecdsaKey(t testing.TB) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return pubKeyLine(t, &priv.PublicKey)
}

// skKey builds an sk-ssh-ed25519@openssh.com (FIDO) public key from its wire form.
func skKey(t testing.TB) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	wire := ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, "ssh:"})
	k, err := ssh.ParsePublicKey(wire)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), ssh.FingerprintSHA256(k)
}

func mustParse(t *testing.T, s string) AuthorizedKeys {
	t.Helper()
	a, err := ParseAuthorizedKeys([]byte(s))
	require.NoError(t, err)
	return a
}

func TestParseClassifiesLines(t *testing.T) {
	k1, fp1 := edKey(t)
	k2, fp2 := ecdsaKey(t)
	text := "\n# deploy keys\n" +
		`from="10.0.0.0/8",command="echo a, b",no-pty ` + k1 + " deploy@laptop\n" +
		"   \t\n" +
		"not a key at all\n" +
		k2 + "\n"
	a := mustParse(t, text)
	require.Len(t, a.Lines, 6)
	kinds := []LineKind{LineBlank, LineComment, LineKey, LineBlank, LineInvalid, LineKey}
	for i, k := range kinds {
		assert.Equal(t, k, a.Lines[i].Kind, "line %d", i+1)
	}
	l := a.Lines[2]
	assert.Equal(t, `from="10.0.0.0/8",command="echo a, b",no-pty`, l.OptionsText)
	assert.Equal(t, []string{`from="10.0.0.0/8"`, `command="echo a, b"`, "no-pty"}, l.Options)
	assert.Equal(t, "ssh-ed25519", l.KeyType)
	assert.Equal(t, k1, l.PublicKey)
	assert.Equal(t, fp1, l.Fingerprint)
	assert.Equal(t, 256, l.Bits)
	assert.Equal(t, "deploy@laptop", l.Comment)
	assert.Equal(t, fp2, a.Lines[5].Fingerprint)
	assert.Equal(t, 256, a.Lines[5].Bits)
	assert.Empty(t, a.Lines[5].OptionsText)
	assert.Equal(t, 2, a.CountKeys())

	keys, bad := a.Keys("deploy", "/home/deploy/.ssh/authorized_keys")
	require.Len(t, keys, 2)
	assert.Equal(t, providers.DiscoveredSSHKey{OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", LineNo: 3,
		PublicKey: k1, Fingerprint: fp1, KeyType: "ssh-ed25519", Bits: 256, Comment: "deploy@laptop",
		Options: `from="10.0.0.0/8",command="echo a, b",no-pty`, Flags: []string{providers.FlagCommand}}, keys[0])
	assert.Equal(t, 6, keys[1].LineNo)
	assert.Equal(t, []providers.UnreadableLine{{OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", LineNo: 5}}, bad)
}

func TestBytesIsByteExact(t *testing.T) {
	k, _ := edKey(t)
	for _, in := range []string{
		"", "\n", "a", "a\n", "a\n\n", "\n\n\n", "a\r\nb\r\n", "a\r\nb", "k\r", "\x00\xff\xfe\n",
		k, k + "\n", k + "\r\n# c\r\n\r\n", "  " + k + "  trailing  \n", "\r", "\r\n",
	} {
		a := mustParse(t, in)
		assert.Equal(t, []byte(in), a.Bytes(), "%q", in)
	}
}

func TestMidLineCarriageReturnIsUnreadable(t *testing.T) {
	k, _ := edKey(t)
	// x/crypto/ssh would cut the line at '\r' and accept the key; Alice does not trust such a line.
	a := mustParse(t, k+" comment\rhidden\n")
	assert.Equal(t, LineInvalid, a.Lines[0].Kind)
}

// Review Focus 1: unreadable lines are reported and preserved byte for byte when Alice rewrites.
func TestParsePreservesUnreadableLinesVerbatim(t *testing.T) {
	keep, _ := edKey(t)
	drop, dropFP := edKey(t)
	garbage := "ssh-ed25519 AAAA-not-base64 broken\n" + "\x00\x01binary\xff\n" + "ssh-rsa\n"
	in := keep + "\n" + garbage + drop + " to-remove\n"
	a := mustParse(t, in)
	_, bad := a.Keys("root", "/root/.ssh/authorized_keys")
	require.Len(t, bad, 3)
	assert.Equal(t, []int{2, 3, 4}, []int{bad[0].LineNo, bad[1].LineNo, bad[2].LineNo})

	out, n := a.RemoveFingerprint(dropFP)
	assert.Equal(t, 1, n)
	assert.Equal(t, keep+"\n"+garbage, string(out.Bytes()))
}

// Review Focus 1: removal touches only lines with the fingerprint, also copies with other
// options or comments; comments, blank and invalid lines and CRLF endings stay as they are.
func TestRemoveTouchesOnlyMatchingLines(t *testing.T) {
	k1, _ := edKey(t)
	k2, fp2 := rsaKey(t, 2048)
	in := "# team keys\r\n" + k1 + " a@b\r\n" + `from="10.1.2.3" ` + k2 + " old-laptop\r\n" + "\r\n" +
		"garbage line\r\n" + k2 + " same-key-other-comment\r\n" + k1 + " c@d\r\n"
	a := mustParse(t, in)
	out, n := a.RemoveFingerprint(fp2)
	assert.Equal(t, 2, n)
	assert.Equal(t, "# team keys\r\n"+k1+" a@b\r\n"+"\r\n"+"garbage line\r\n"+k1+" c@d\r\n", string(out.Bytes()))
	assert.Equal(t, in, string(a.Bytes()), "RemoveFingerprint does not change its receiver")

	same, n := a.RemoveFingerprint("SHA256:not-present")
	assert.Zero(t, n)
	assert.Equal(t, in, string(same.Bytes()))
}

func TestRemoveKeepsTheTerminatorOfThePreviousLine(t *testing.T) {
	k1, _ := edKey(t)
	k2, fp2 := edKey(t)
	out, n := mustParse(t, k1+"\n"+k2).RemoveFingerprint(fp2)
	assert.Equal(t, 1, n)
	assert.Equal(t, k1+"\n", string(out.Bytes()))

	out, _ = mustParse(t, k2).RemoveFingerprint(fp2)
	assert.Empty(t, out.Bytes())
}

// F-37: adding to a file without a trailing newline starts a new line; existing lines stay intact.
func TestAddLineStartsOnANewLine(t *testing.T) {
	k1, _ := edKey(t)
	k2, fp2 := edKey(t)
	a := mustParse(t, k1+" existing")
	out, added, err := a.AddLine(`from="10.0.0.0/8" ` + k2 + " alice:deploy:2026-10-01")
	require.NoError(t, err)
	require.True(t, added)
	assert.Equal(t, k1+" existing\n"+`from="10.0.0.0/8" `+k2+" alice:deploy:2026-10-01\n", string(out.Bytes()))
	assert.Equal(t, fp2, out.Lines[1].Fingerprint)

	_, added, err = out.AddLine(k2 + " other comment")
	require.NoError(t, err)
	assert.False(t, added, "a key that is already present is not added twice")

	empty, added, err := mustParse(t, "").AddLine(k2)
	require.NoError(t, err)
	assert.True(t, added)
	assert.Equal(t, k2+"\n", string(empty.Bytes()))
}

func TestAddLineKeepsCRLFFiles(t *testing.T) {
	k1, _ := edKey(t)
	k2, _ := edKey(t)
	out, _, err := mustParse(t, k1+"\r\n").AddLine(k2)
	require.NoError(t, err)
	assert.Equal(t, k1+"\r\n"+k2+"\r\n", string(out.Bytes()))

	out, _, err = mustParse(t, "# mixed\n"+k1+"\r\n").AddLine(k2)
	require.NoError(t, err)
	assert.Equal(t, "# mixed\n"+k1+"\r\n"+k2+"\n", string(out.Bytes()), "mixed files get LF")
}

func TestAddLineRefusesAnythingButOneKey(t *testing.T) {
	k1, _ := edKey(t)
	k2, _ := edKey(t)
	a := mustParse(t, "")
	for _, bad := range []string{
		"", "# comment", "garbage", k1 + "\n" + k2, k1 + "\r", k1 + " comment\x1b[31m", k1 + "\tcomment",
		k1 + " \x00", "ssh-rsa " + strings.Split(k1, " ")[1],
	} {
		_, _, err := a.AddLine(bad)
		require.ErrorIs(t, err, ErrInvalidKeyLine, "%q", bad)
	}
}

func TestFlags(t *testing.T) {
	weak, _ := rsaKey(t, 1024)
	strong, _ := rsaKey(t, 2048)
	ed, _ := edKey(t)
	sk, _ := skKey(t)
	ca, _ := edKey(t)
	in := weak + " w\n" +
		strong + " s\n" +
		`From="10.0.0.0/8" ` + ed + " with-from\n" +
		`command="/usr/bin/backup" ` + ed + " dup-with-command\n" +
		sk + " yubikey\n" +
		`cert-authority,principals="ops" ` + ca + " ca\n"
	a := mustParse(t, in)

	keys, _ := a.Keys("root", "/root/.ssh/authorized_keys")
	require.Len(t, keys, 6)
	assert.Equal(t, []string{providers.FlagWeak, providers.FlagRootWithoutFrom}, keys[0].Flags)
	assert.Equal(t, 1024, keys[0].Bits)
	assert.Equal(t, []string{providers.FlagRootWithoutFrom}, keys[1].Flags)
	assert.Equal(t, 2048, keys[1].Bits)
	assert.Equal(t, []string{providers.FlagDuplicate}, keys[2].Flags, "from= (any case) satisfies the root rule")
	assert.Equal(t, []string{providers.FlagCommand, providers.FlagRootWithoutFrom, providers.FlagDuplicate}, keys[3].Flags)
	assert.Equal(t, []string{providers.FlagRootWithoutFrom, providers.FlagSecurityKey}, keys[4].Flags)
	assert.Equal(t, "sk-ssh-ed25519@openssh.com", keys[4].KeyType)
	assert.Equal(t, 256, keys[4].Bits)
	assert.Equal(t, []string{providers.FlagRootWithoutFrom, providers.FlagCertAuthority}, keys[5].Flags)

	other, _ := a.Keys("deploy", "/home/deploy/.ssh/authorized_keys")
	assert.Equal(t, []string{providers.FlagWeak}, other[0].Flags, "the from= rule applies to root only")
	assert.Empty(t, other[1].Flags)
}

// Review Focus 1: a file over 1 MiB is not parsed.
func TestParseRejectsOversizedFile(t *testing.T) {
	_, err := ParseAuthorizedKeys(bytes.Repeat([]byte("#"), helperproto.MaxAuthorizedKeysSize+1))
	require.ErrorIs(t, err, ErrAuthorizedKeysTooLarge)
	a, err := ParseAuthorizedKeys(bytes.Repeat([]byte("#"), helperproto.MaxAuthorizedKeysSize))
	require.NoError(t, err)
	assert.Len(t, a.Lines, 1)
}

// FuzzParseAuthorizedKeys (spec §25.6): never panics; parsing then serializing returns the input
// byte for byte; a valid line keeps its blob and options after re-parsing; removing a key keeps
// every invalid line verbatim.
func FuzzParseAuthorizedKeys(f *testing.F) {
	k, _ := edKey(f)
	sk, _ := skKey(f)
	for _, seed := range []string{
		k + " user@host\n",
		`command="echo \"quoted\" a,b",from="10.0.0.0/8",no-pty ` + k + " c\n",
		`environment="A=B" ` + k,
		k + "\r\n# comment\r\n\r\n",
		"cert-authority " + k + " ca\n",
		sk + " security key\n",
		strings.Repeat("A", 70000) + "\n",
		"ssh-ed25519 \x00\x00\x00 nul\n",
		"\xff\xfe binary\n" + k,
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := ParseAuthorizedKeys(data)
		if err != nil {
			if len(data) <= helperproto.MaxAuthorizedKeysSize {
				t.Fatalf("parse refused an input within the size limit: %v", err)
			}
			return
		}
		if !bytes.Equal(a.Bytes(), data) {
			t.Fatalf("round trip changed the file")
		}
		var invalid []string
		for _, l := range a.Lines {
			switch l.Kind {
			case LineKey:
				if (len(l.Options) > 0) != (l.OptionsText != "") || strings.Join(l.Options, ",") != l.OptionsText {
					t.Fatalf("options and OptionsText disagree: %q", l.Raw)
				}
				again, err := ParseAuthorizedKeys([]byte(l.Raw))
				if err != nil || len(again.Lines) != 1 || again.Lines[0].Fingerprint != l.Fingerprint ||
					again.Lines[0].OptionsText != l.OptionsText || again.Lines[0].PublicKey != l.PublicKey {
					t.Fatalf("a valid line did not survive re-parsing: %q", l.Raw)
				}
			case LineInvalid:
				invalid = append(invalid, l.Raw)
			}
		}
		if len(a.Lines) > 0 && a.Lines[0].Kind == LineKey {
			fp := a.Lines[0].Fingerprint
			out, n := a.RemoveFingerprint(fp)
			if out.CountKeys() != a.CountKeys()-n {
				t.Fatalf("removal count %d does not match key count %d -> %d", n, a.CountKeys(), out.CountKeys())
			}
			for _, l := range out.Lines {
				if l.Kind == LineKey && l.Fingerprint == fp {
					t.Fatalf("fingerprint still present after removal")
				}
			}
			var kept []string
			for _, l := range out.Lines {
				if l.Kind == LineInvalid {
					kept = append(kept, l.Raw)
				}
			}
			if strings.Join(kept, "\n") != strings.Join(invalid, "\n") {
				t.Fatalf("removing a key changed invalid lines")
			}
		}
	})
}

// Fix round 1: OptionsText is the verbatim options field even when the blob also occurs in an option.
func TestOptionsTextWhenBlobRepeatsInOption(t *testing.T) {
	k, _ := edKey(t)
	blob := strings.Split(k, " ")[1]
	line := `from="*",command="sh ` + blob + `" ` + k + " c"
	a := mustParse(t, line)
	require.Equal(t, LineKey, a.Lines[0].Kind)
	assert.Equal(t, `from="*",command="sh `+blob+`"`, a.Lines[0].OptionsText)
	assert.Equal(t, strings.Join(a.Lines[0].Options, ","), a.Lines[0].OptionsText)
	assert.Equal(t, "c", a.Lines[0].Comment)
}

func TestNonCanonicalBlobIsUnreadable(t *testing.T) {
	k, _ := ecdsaKey(t) // 104-byte blob: the base64 ends in one "=" with two spare bits
	parts := strings.Split(k, " ")
	b := parts[1]
	require.True(t, strings.HasSuffix(b, "="))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	idx := strings.IndexByte(alphabet, b[len(b)-2])
	require.Zero(t, idx&3)
	alt := b[:len(b)-2] + string(alphabet[idx|1]) + "="
	_, err := base64.StdEncoding.DecodeString(alt)
	require.NoError(t, err, "Go's decoder accepts the non-canonical form")
	a := mustParse(t, parts[0]+" "+alt+" c\n")
	assert.Equal(t, LineInvalid, a.Lines[0].Kind)
	a = mustParse(t, `no-pty `+parts[0]+" "+alt+"\n")
	assert.Equal(t, LineInvalid, a.Lines[0].Kind)
}

func TestUnknownOrControlOptionsAreUnreadable(t *testing.T) {
	k, _ := edKey(t)
	for _, in := range []string{
		"bogus-option " + k, `command="x",frobnicate ` + k,
		"NO-PTY,From=\"10.0.0.1\" " + k, // valid, case-insensitive: handled below
	} {
		a := mustParse(t, in)
		want := LineInvalid
		if strings.HasPrefix(in, "NO-PTY") {
			want = LineKey
		}
		assert.Equal(t, want, a.Lines[0].Kind, "%q", in)
	}
	a := mustParse(t, "command=\"a\x01b\" "+k)
	assert.Equal(t, LineInvalid, a.Lines[0].Kind)
}

func TestAddLineRefusesUnsafeText(t *testing.T) {
	k, _ := edKey(t)
	for _, bad := range []string{k + " c\u0085x", k + " c\u202ex", k + " c\u2066x", k + " c\xff"} {
		_, _, err := mustParse(t, "").AddLine(bad)
		require.ErrorIs(t, err, ErrInvalidKeyLine, "%q", bad)
	}
	_, added, err := mustParse(t, "").AddLine(k + " kullanıcı")
	require.NoError(t, err)
	assert.True(t, added)
}

// Fix round 2: lines OpenSSH accepts stay keys; lines it rejects become unreadable.
func TestOpenSSHAcceptedOptionForms(t *testing.T) {
	k, fp := edKey(t)
	for _, in := range []string{"no-pty, " + k + " c", "command=\"echo\ta\" " + k + " c"} {
		a := mustParse(t, in+"\n")
		require.Equal(t, LineKey, a.Lines[0].Kind, "%q", in)
		assert.Equal(t, strings.Join(a.Lines[0].Options, ","), a.Lines[0].OptionsText)
		assert.Equal(t, fp, a.Lines[0].Fingerprint)
		out, n := a.RemoveFingerprint(fp)
		assert.Equal(t, 1, n)
		assert.Zero(t, out.CountKeys())
	}
}

func TestOpenSSHRejectedOptionForms(t *testing.T) {
	k, _ := edKey(t)
	for _, in := range []string{`principal` + "ſ" + `="x" ` + k, "no-pty=x " + k, `command=x ` + k, `from ` + k,
		"no-pty,, " + k, "command=\"a\x01b\" " + k, "no-pty\t" + "," + k,
		", " + k, "  , " + k + " c"} { // A-10: a lone comma is not an empty options field for OpenSSH
		a := mustParse(t, in+"\n")
		assert.Equal(t, LineInvalid, a.Lines[0].Kind, "%q", in)
	}
}

func TestLineOfFindsTheFirstLineOfAKey(t *testing.T) {
	a, afp := edKey(t)
	b, bfp := edKey(t)
	ak, err := ParseAuthorizedKeys([]byte("# c\n" + a + "\nnot a key\n" + b + "\n" + a + "\n"))
	require.NoError(t, err)
	assert.Equal(t, 2, lineOf(ak, afp), "the first of two lines")
	assert.Equal(t, 4, lineOf(ak, bfp))
	assert.Equal(t, 0, lineOf(ak, "SHA256:none"))
	assert.Equal(t, 0, lineOf(ak, ""))
}
