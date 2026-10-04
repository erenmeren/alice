package validate

import "time"

// Bounds of a certificate's validity dates in UTC (AUD-13). A GeneralizedTime names years
// 0000-9999 in its own digits, and Go's parser accepts a zone offset of up to ±23:59 (RFC 5280 asks
// for "Z"), so a file can say a time a day outside that range in UTC; year 0000 is no year of the
// calendar Alice shows. Such a time cannot be written as an RFC 3339 timestamp, so a certificate
// with one is not a certificate Alice handles. "99991231235959Z", RFC 5280's "no well-defined
// expiration", is the latest time allowed.
var (
	EarliestCertificateTime = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	LatestCertificateTime   = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// CertificateTimes reports whether a certificate's NotBefore and NotAfter both lie within
// EarliestCertificateTime … LatestCertificateTime. internal/certs (every certificate Alice reads)
// and the Nginx provider (the blocks of a file found on a server) share this one rule.
func CertificateTimes(notBefore, notAfter time.Time) bool {
	for _, t := range []time.Time{notBefore, notAfter} {
		if t.Before(EarliestCertificateTime) || t.After(LatestCertificateTime) {
			return false
		}
	}
	return true
}
