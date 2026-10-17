package nginx

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// AUD-13: a certificate block whose validity dates lie outside the years 1 to 9999 in UTC (a
// GeneralizedTime zone offset) is treated like a block that does not parse: as the first block the
// file is not a certificate; behind a good leaf it is dropped and the leaf is kept, so it can never
// hide a valid certificate (internal/certs would refuse the whole file).
func TestCertificateChainDropsBlocksOutsideYears1To9999(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	ca := pki.NewCA("Edge", pki.ECDSA256, now)
	good := ca.Issue(pki.Opts{CommonName: "good.example.test", SANs: []string{"good.example.test"}}, now)
	sum := strings.Repeat("ab", 32)
	for _, bad := range []pki.Leaf{
		ca.IssueRawValidity(pki.Opts{CommonName: "high.example.test"}, pki.GeneralizedTime("20260101000000Z"), pki.GeneralizedTime("99991231235959-2359"), now),
		ca.IssueRawValidity(pki.Opts{CommonName: "low.example.test"}, pki.GeneralizedTime("00000101000000+2359"), pki.GeneralizedTime("20300101000000Z"), now),
	} {
		chain, gotSum, dropped, problem := certificateChain(helperproto.DumpFile{SHA256: sum, PEM: string(good.CertPEM) + string(bad.CertPEM) + string(ca.IntermediatePEM)})
		require.Empty(t, problem)
		assert.True(t, dropped)
		assert.Equal(t, sum, gotSum)
		var cns []string
		for rest := chain; ; {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			require.NoError(t, err)
			cns = append(cns, c.Subject.CommonName)
		}
		assert.Equal(t, []string{"good.example.test", "Edge Intermediate"}, cns)
		p, err := certs.ParseServedChain(chain, now)
		require.NoError(t, err, "the leaf is stored")
		assert.Equal(t, "good.example.test", p.SubjectCN)

		_, _, _, problem = certificateChain(helperproto.DumpFile{SHA256: sum, PEM: string(bad.CertPEM) + string(good.CertPEM)})
		assert.Equal(t, providers.CertProblemNotACertificate, problem, "as the first block it would be the leaf")
	}
}
