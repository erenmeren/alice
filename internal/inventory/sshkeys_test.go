package inventory

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFoldSearchMatchesTurkishCaseVariants(t *testing.T) {
	for in, want := range map[string]string{
		"İZMİR":   "izmir",
		"izmir":   "izmir",
		"IZMIR":   "izmir",
		"Iğdır":   "iğdir",
		"ığdır":   "iğdir",
		"SHA256:": "sha256:",
	} {
		assert.Equal(t, want, foldSearch(in), in)
	}
	assert.Equal(t, `%100\%\_done\\%`, likePattern("100%_done\\"), "wildcards are matched literally")
}

func TestCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 1, 9, 0, 0, 123456000, time.UTC)
	id := uuid.Must(uuid.NewV7())
	c := encodeCursor(at, id)
	gotAt, gotID, err := decodeCursor(c)
	require.NoError(t, err)
	assert.True(t, at.Equal(gotAt))
	assert.Equal(t, id, gotID)
	for _, bad := range []string{"%%%", "bm90LWEtY3Vyc29y", encodeCursor(at, id) + "x"} {
		_, _, err := decodeCursor(bad)
		require.Error(t, err, bad)
	}
}

// AUD-13, D19: a cursor's time is bounded by what the lists can hold, years 0000 to 9999 (an X.509
// GeneralizedTime NotAfter, UTCTime from 1950: certificates before 1970 page too), which PostgreSQL
// timestamptz stores; outside that range, or with an id that is not a UUID, a cursor is refused
// instead of reaching the database. Every cursor the lists hand out decodes to the same values.
func TestCursorTimeRange(t *testing.T) {
	ids := []uuid.UUID{uuid.Nil, uuid.Max, uuid.Must(uuid.NewV7()), uuid.MustParse("018f0000-0000-7000-8000-000000000000")}
	times := []time.Time{
		time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1969, 12, 31, 23, 59, 59, 999999000, time.UTC),
		time.Unix(0, 0).UTC(),
		time.Date(2026, 10, 4, 12, 0, 0, 1000, time.UTC),
		time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC),
		time.Date(2026, 10, 4, 15, 0, 0, 0, time.FixedZone("TRT", 3*3600)),
	}
	for i := range 200 {
		times = append(times, time.UnixMicro(cursorMinMicros+int64(i)*((cursorMaxMicros-cursorMinMicros)/199)))
	}
	for _, at := range times {
		for _, id := range ids {
			gotAt, gotID, err := decodeCursor(encodeCursor(at, id))
			require.NoError(t, err, at)
			assert.True(t, at.Equal(gotAt), at)
			assert.Equal(t, id, gotID)
		}
	}
	raw := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	const id = "018f0000-0000-7000-8000-000000000000"
	for _, bad := range []string{
		raw("-9223372036854775808." + id), raw("9223372036854775807." + id),
		raw(strconv.FormatInt(cursorMinMicros-1, 10) + "." + id), raw(strconv.FormatInt(cursorMaxMicros+1, 10) + "." + id),
		raw("0.not-a-uuid"), raw("0.018F0000-0000-7000-8000-000000000000"), raw("0"), raw("." + id), raw("1e3." + id),
	} {
		_, _, err := decodeCursor(bad)
		assert.Error(t, err, bad)
	}
	for _, ok := range []string{raw(strconv.FormatInt(cursorMinMicros, 10) + "." + id), raw(strconv.FormatInt(cursorMaxMicros, 10) + "." + id), raw("-1." + id)} {
		_, _, err := decodeCursor(ok)
		assert.NoError(t, err, ok)
	}
}
