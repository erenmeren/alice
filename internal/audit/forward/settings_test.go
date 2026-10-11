package forward

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/validate"
	"alice/internal/testutil/pki"
)

func TestCheckCAPEM(t *testing.T) {
	ca := pki.NewCA("t", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "x"}, time.Now())
	cases := map[string]struct {
		text, code string
	}{
		"none":             {"", ""},
		"one":              {string(ca.RootPEM), ""},
		"two":              {string(ca.RootPEM) + string(ca.IntermediatePEM), ""},
		"a key block":      {string(leaf.KeyPEM), validate.Pattern},
		"trailing text":    {string(ca.RootPEM) + "junk", validate.Pattern},
		"no block":         {"junk", validate.Pattern},
		"broken DER":       {"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", validate.Pattern},
		"too many":         {strings.Repeat(string(ca.RootPEM), maxCACerts+1), validate.TooLong},
		"longer than 64 K": {strings.Repeat(" ", maxCAPEM+1), validate.TooLong},
	}
	for name, c := range cases {
		assert.Equal(t, c.code, checkCAPEM(c.text), name)
	}
}

func TestNormalize(t *testing.T) {
	got, err := normalize(Settings{})
	require.NoError(t, err)
	assert.Equal(t, Settings{Port: DefaultPort, Transport: TransportTLS}, got)

	_, err = normalize(Settings{Enabled: true, Host: strings.Repeat("a", maxHost+1), Port: 514})
	var verrs validate.Errors
	require.True(t, errors.As(err, &verrs))
	assert.Equal(t, "host", verrs[0].Field)
	assert.Equal(t, validate.TooLong, verrs[0].Code)

	for _, host := range []string{"10.0.0.5", "::1", "syslog.example.com", "fd00::1"} {
		_, err := normalize(Settings{Enabled: true, Host: host, Port: 514})
		assert.NoError(t, err, host)
	}
	for _, host := range []string{"169.254.169.254", "fe80::1", "ff02::1"} {
		_, err := normalize(Settings{Enabled: true, Host: host, Port: 514})
		assert.ErrorIs(t, err, ErrAddressRefused, host)
	}
}

func TestNewDefaults(t *testing.T) {
	f := New(Config{Clock: clock.Real{}})
	assert.Equal(t, "alice", f.app)
	assert.NotNil(t, f.log)
	// The default dialer applies the address rule.
	_, err := f.dial(context.Background(), "tcp", net.JoinHostPort("169.254.169.254", "6514"))
	assert.ErrorIs(t, err, netaddr.ErrNotAllowed)
}

func TestRootPool(t *testing.T) {
	ca := pki.NewCA("t", pki.ECDSA256, time.Now())
	own := x509.NewCertPool()
	f := New(Config{RootCAs: own})
	pool, err := f.rootPool(string(ca.RootPEM))
	require.NoError(t, err)
	assert.Len(t, own.Subjects(), 0, "the configured pool is not changed") //nolint:staticcheck // SA1019: counting only
	assert.NotSame(t, own, pool)
	_, err = f.rootPool("not a certificate")
	require.Error(t, err)
	sys, err := New(Config{}).rootPool("")
	require.NoError(t, err)
	assert.NotNil(t, sys)
}

func TestUntrustedClassification(t *testing.T) {
	assert.True(t, untrusted(x509.UnknownAuthorityError{}))
	assert.True(t, untrusted(x509.HostnameError{}))
	assert.True(t, untrusted(x509.CertificateInvalidError{}))
	assert.False(t, untrusted(errors.New("connection reset")))
}

// failingConn accepts ok writes, then fails every write.
type failingConn struct {
	net.Conn
	ok     int
	writes [][]byte
}

func (c *failingConn) Write(b []byte) (int, error) {
	if len(c.writes) == c.ok {
		return 0, errors.New("connection reset")
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func TestSendAdvancesTheCursorOnlyAfterAWrite(t *testing.T) {
	f := New(Config{Hostname: "h"})
	rows := []audit.Entry{entry(), entry(), entry()}
	rows[0].Seq, rows[1].Seq, rows[2].Seq = 10, 11, 12
	cp := audit.Checkpoint{Seq: 12, Hash: "ab"}

	st := State{CursorSeq: 9, CheckpointSeq: 3}
	c := &failingConn{ok: 2}
	require.Error(t, f.send(c, TransportTCP, rows, cp, true, &st))
	assert.Equal(t, int64(11), st.CursorSeq, "the failed row is not counted")
	assert.Equal(t, int64(3), st.CheckpointSeq)
	n, msg, ok := strings.Cut(string(c.writes[0]), " ")
	require.True(t, ok)
	assert.Equal(t, strconv.Itoa(len(msg)), n, "octet-counted")

	st = State{CursorSeq: 9, CheckpointSeq: 3}
	c = &failingConn{ok: 3}
	require.Error(t, f.send(c, TransportUDP, rows, cp, true, &st))
	assert.Equal(t, int64(12), st.CursorSeq)
	assert.Equal(t, int64(3), st.CheckpointSeq, "the checkpoint failed")
	assert.True(t, strings.HasPrefix(string(c.writes[0]), "<37>1 "), "a datagram is not framed")

	st = State{CursorSeq: 9, CheckpointSeq: 3}
	require.NoError(t, f.send(&failingConn{ok: 4}, TransportTLS, rows, cp, true, &st))
	assert.Equal(t, State{CursorSeq: 12, CheckpointSeq: 12}, st)
}
