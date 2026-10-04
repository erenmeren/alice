package jobs

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AUD-13: a jobs cursor's time is bounded (years 0000 to 9999, which PostgreSQL timestamptz holds)
// and its id is a UUID; anything else is ErrBadCursor (400) instead of a database error. Every
// cursor List hands out decodes to the same values.
func TestCursorTimeRange(t *testing.T) {
	ids := []uuid.UUID{uuid.Nil, uuid.Max, uuid.Must(uuid.NewV7())}
	times := []time.Time{
		time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Unix(0, 0), time.Date(2026, 10, 4, 12, 0, 0, 1000, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC),
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
		raw("-9223372036854775808|" + id), raw("9223372036854775807|" + id),
		raw(strconv.FormatInt(cursorMinMicros-1, 10) + "|" + id), raw(strconv.FormatInt(cursorMaxMicros+1, 10) + "|" + id),
		raw("0|not-a-uuid"), raw("0"), "%%%",
	} {
		_, _, err := decodeCursor(bad)
		assert.ErrorIs(t, err, ErrBadCursor, bad)
	}
}
