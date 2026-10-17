package haproxyconf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readFileNotRead is readFile with a missing file answered as the root helper answers a file it
// cannot read: an error wrapping ErrNotRead.
func (f *fakeFS) readFileNotRead(path string) ([]byte, error) {
	data, err := f.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: missing", ErrNotRead)
	}
	return data, nil
}

// Review I1 of Task 6: with Writable, Parse calls neither callback; every crt and crt-list
// argument it can resolve is one config_file_writable pair with only the text as written.
func TestParseWritableReadsNothing(t *testing.T) {
	in := Input{Path: cfgPath, Version: "2.6.12", Writable: true,
		ReadFile: func(p string) ([]byte, error) { t.Errorf("ReadFile(%s)", p); return nil, errors.New("no") },
		ReadDir: func(p string) ([]string, bool, error) {
			t.Errorf("ReadDir(%s)", p)
			return nil, false, errors.New("no")
		},
		Data: []byte(fe(
			"  bind :9443 ssl crt /root/keys crt-list /root/notes crt $X/a.pem crt-list rel.lst",
			".if defined(NEVER_SET)",
			"  bind :9444 ssl crt-list /root/hidden crt /etc/shadow",
			".endif",
		)),
	}
	c, err := Parse(in)
	require.NoError(t, err)
	require.Len(t, c.Servers, 2)
	assert.Equal(t, []Pair{
		uns("/root/keys", ReasonConfigFileWritable),
		uns("/root/notes", ReasonConfigFileWritable),
		uns("$X/a.pem", ReasonVariable),
		uns("rel.lst", ReasonPathNotAllowed),
	}, c.Servers[0].Pairs)
	assert.Equal(t, []Pair{uns("/root/hidden", ReasonConfigFileWritable), uns("/etc/shadow", ReasonConfigFileWritable)}, c.Servers[1].Pairs)
	assert.Empty(t, c.CertPaths())
	assert.Empty(t, c.KeyPaths())
	ResolveKeys(&c, func(string) bool { t.Error("keyInCert"); return false })
	assert.Empty(t, c.CertPaths())
}

// Review I2 of Task 6: a crt-list or crt directory that cannot be read, named only in an
// uncertain region, is one conditional pair and a warning; an active naming still fails.
func TestParseNotReadInUncertainRegion(t *testing.T) {
	staging := ".if defined(STAGING)\nfrontend z\n  bind :9445 ssl crt-list /l/staging.lst\n.endif\n"
	active := fe("  bind :9443 ssl crt /c/a.pem")
	t.Run("reviewer's case: only in .if defined(STAGING)", func(t *testing.T) {
		fs := newFS()
		in := fs.input(active+staging, "2.6.12")
		in.ReadFile = fs.readFileNotRead
		c, err := Parse(in)
		require.NoError(t, err)
		require.Len(t, c.Servers, 2)
		assert.Equal(t, []Pair{plain("/c/a.pem")}, c.Servers[0].Pairs)
		assert.Equal(t, []Pair{uns("/l/staging.lst", ReasonConditional)}, c.Servers[1].Pairs)
		assert.Equal(t, []string{WarnConfigFileNotRead}, c.Warnings)
	})
	t.Run("named in the region, then actively", func(t *testing.T) {
		fs := newFS()
		in := fs.input(staging+fe("  bind :9443 ssl crt-list /l/staging.lst"), "2.6.12")
		in.ReadFile = fs.readFileNotRead
		_, err := Parse(in)
		require.ErrorIs(t, err, ErrNotRead)
		assert.Equal(t, 1, fs.fileCalls["/l/staging.lst"], "asked once")
	})
	t.Run("named actively, then in the region", func(t *testing.T) {
		fs := newFS()
		in := fs.input(fe("  bind :9443 ssl crt-list /l/staging.lst")+staging, "2.6.12")
		in.ReadFile = fs.readFileNotRead
		_, err := Parse(in)
		require.ErrorIs(t, err, ErrNotRead)
	})
	t.Run("twice in the region", func(t *testing.T) {
		fs := newFS()
		in := fs.input(staging+staging, "2.6.12")
		in.ReadFile = fs.readFileNotRead
		c, err := Parse(in)
		require.NoError(t, err)
		assert.Len(t, c.Servers, 2)
		assert.Equal(t, 1, fs.fileCalls["/l/staging.lst"])
	})
	t.Run("another error fails even in the region", func(t *testing.T) {
		fs := newFS()
		_, err := Parse(fs.input(staging, "2.6.12")) // a plain error, not ErrNotRead
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotRead)
	})
	t.Run("a crt directory that cannot be listed", func(t *testing.T) {
		fs := newFS()
		fs.dirErr = fmt.Errorf("%w: listing failed", ErrNotRead)
		c, err := Parse(fs.input(".if defined(X)\nfrontend z\n  bind :1 ssl crt /c/dir\n.endif\n", "2.6.12"))
		require.NoError(t, err)
		assert.Equal(t, []Pair{uns("/c/dir", ReasonConditional)}, c.Servers[0].Pairs)
		assert.Equal(t, []string{WarnConfigFileNotRead}, c.Warnings)
		_, err = Parse(fs.input(fe("  bind :1 ssl crt /c/dir"), "2.6.12"))
		assert.ErrorIs(t, err, ErrNotRead)
	})
	t.Run("a crt-list entry directory that cannot be listed", func(t *testing.T) {
		fs := newFS()
		fs.files["/l/s.lst"] = "/c/dir x.test\n"
		fs.dirErr = fmt.Errorf("%w: listing failed", ErrNotRead)
		c, err := Parse(fs.input(".if defined(X)\nfrontend z\n  bind :1 ssl crt-list /l/s.lst\n.endif\n"+
			".if defined(Y)\nfrontend y\n  bind :2 ssl crt-list /l/s.lst\n.endif\n", "2.6.12"))
		require.NoError(t, err)
		assert.Equal(t, []Pair{uns("/l/s.lst", ReasonConditional)}, c.Servers[0].Pairs)
		assert.Equal(t, 1, fs.dirCalls["/c/dir"], "a failed listing is asked for once")
	})
}

// Review M6 of Task 6: a writable configuration's conditional pairs are config_file_writable too.
func TestMarkWritableConditional(t *testing.T) {
	c := Config{Servers: []Server{{Pairs: []Pair{uns("/c/x.pem", ReasonConditional), uns("rel", ReasonPathNotAllowed), plain("/c/a.pem")}}}}
	MarkWritable(&c)
	assert.Equal(t, []Pair{uns("/c/x.pem", ReasonConfigFileWritable), uns("rel", ReasonPathNotAllowed),
		{Cert: "/c/a.pem", CertRaw: "/c/a.pem", Unsupported: ReasonConfigFileWritable}}, c.Servers[0].Pairs)
}
