package certs

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

func TestParseChainPEMDescribesTheLeaf(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA384, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", "10.0.0.5", "example.test"}, KeyType: pki.ECDSA384}, now)
	p, err := ParseChainPEM(l.FullchainPEM)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%X", l.Cert.SerialNumber), p.Serial)
	assert.Regexp(t, `^[0-9A-F]+$`, p.Serial)
	assert.Equal(t, []string{"www.example.test", "example.test", "10.0.0.5"}, p.SANs, "DNS names, then IP addresses")
	assert.Equal(t, "ecdsa", p.Algorithm)
	assert.Equal(t, 384, p.Bits)
	assert.Equal(t, "www.example.test", p.SubjectCN)
	assert.Equal(t, pki.Fingerprint(l.Cert), p.Fingerprint)
	assert.Equal(t, l.Cert.NotAfter, p.NotAfter)
	assert.False(t, p.SelfSigned)
	require.Len(t, p.Chain, 1)
	assert.Equal(t, ca.Intermediate.Raw, p.Chain[0].Raw)
}

func TestParseChainPEMAcceptsBOMAndCRLF(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	in := append([]byte("\xef\xbb\xbf"), bytes.ReplaceAll(l.FullchainPEM, []byte("\n"), []byte("\r\n"))...)
	p, err := ParseChainPEM(in)
	require.NoError(t, err)
	assert.Equal(t, string(l.FullchainPEM), p.PEMChain, "re-encoded with LF line endings")
	_, err = ParseChainPEM(bytes.Repeat([]byte("a"), MaxInputSize+1))
	assert.ErrorIs(t, err, ErrTooLarge)
	_, err = ParseChainPEM([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	assert.ErrorIs(t, err, ErrInvalid)
}
