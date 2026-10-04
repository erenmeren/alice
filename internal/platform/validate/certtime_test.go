package validate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCertificateTimes(t *testing.T) {
	ok := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		nb, na time.Time
		want   bool
	}{
		{ok, ok, true},
		{EarliestCertificateTime, LatestCertificateTime, true},
		{time.Date(1965, 1, 1, 0, 0, 0, 0, time.UTC), ok, true},
		{EarliestCertificateTime.Add(-time.Second), ok, false},
		{ok, LatestCertificateTime.Add(time.Nanosecond), false},
		{time.Date(-1, 12, 31, 0, 1, 0, 0, time.UTC), ok, false},
		{ok, time.Date(10000, 1, 1, 23, 58, 59, 0, time.UTC), false},
		{ok, time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("", -60)), false}, // 10000-01-01T00:00:59Z
	} {
		assert.Equal(t, c.want, CertificateTimes(c.nb, c.na), "%s %s", c.nb.UTC(), c.na.UTC())
	}
}
