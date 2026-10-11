package forward

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
)

func entry() audit.Entry {
	return audit.Entry{
		Seq: 42, At: time.Date(2026, 10, 10, 2, 30, 0, 0, time.UTC), ActorType: audit.ActorSystem, ActorName: "cli",
		Action: "backup.created", ObjectType: "backup", ObjectID: "alice-20261010T023000Z-auto.alicebackup",
		Result: audit.Success, Details: map[string]string{"size": "1024", "kind": "auto"},
		PrevHash: bytes.Repeat([]byte{0xcd}, 32), Hash: bytes.Repeat([]byte{0xab}, 32),
	}
}

func TestRFC5424Message(t *testing.T) {
	want := `<37>1 2026-10-10T02:30:00Z alice01 alice - backup.created [alice@32473 seq="42" hash="` +
		strings.Repeat("ab", 32) + `" prev_hash="` + strings.Repeat("cd", 32) + `" actor="cli" result="success"] ` +
		`{"object_type":"backup","object_id":"alice-20261010T023000Z-auto.alicebackup","details":{"kind":"auto","size":"1024"}}`
	assert.Equal(t, want, string(message(entry(), "alice01", "alice")))

	e := entry()
	e.At = time.Date(2026, 10, 10, 2, 30, 0, 123456000, time.UTC)
	e.ActorName = ""
	e.Details = nil
	got := string(message(e, "", ""))
	assert.True(t, strings.HasPrefix(got, `<37>1 2026-10-10T02:30:00.123456Z - - - backup.created [`), got)
	assert.Contains(t, got, ` actor="system" `, "an entry without an actor name names its type")
	assert.True(t, strings.HasSuffix(got, `"details":{}}`), got)
}

func TestHeaderFieldsArePrintableASCII(t *testing.T) {
	e := entry()
	e.Action = "a bç" + strings.Repeat("x", 40)
	got := string(message(e, "host name\x00ç", "ap p"))
	assert.True(t, strings.HasPrefix(got, "<37>1 2026-10-10T02:30:00Z host_name__ ap_p - a_b_"+strings.Repeat("x", 28)+" ["), got)
	assert.True(t, utf8.ValidString(got))
	long := string(message(entry(), strings.Repeat("h", 300), strings.Repeat("a", 60)))
	assert.Contains(t, long, " "+strings.Repeat("h", 255)+" "+strings.Repeat("a", 48)+" - ")
}

func TestSDParamEscaping(t *testing.T) {
	assert.Equal(t, `a\"b\\c\]d[e`, sdEscape(`a"b\c]d[e`))
	e := entry()
	e.ActorName = `ev"il\] [x`
	assert.Contains(t, string(message(e, "h", "alice")), ` actor="ev\"il\\\] [x" `)
}

func TestOctetCounting(t *testing.T) {
	assert.Equal(t, "9 <37>1 abc", string(octetFrame([]byte("<37>1 abc"))))
	assert.Equal(t, "8 <37>1 é", string(octetFrame([]byte("<37>1 é"))), "the length counts octets")
}

func TestMessageIsCutToEightKiB(t *testing.T) {
	e := entry()
	e.Details = map[string]string{"reason": strings.Repeat("ğ", 6000) + `"quoted"`, "name": "x"}
	got := message(e, "alice01", "alice")
	require.LessOrEqual(t, len(got), MaxMessage)
	assert.Greater(t, len(got), MaxMessage-8, "the cut fills the budget")
	assert.True(t, utf8.Valid(got))
	_, body, ok := bytes.Cut(got, []byte(`result="success"] `))
	require.True(t, ok)
	assert.True(t, bytes.HasSuffix(body, []byte(`,"truncated":true}`)), string(body[len(body)-40:]))
	var parsed struct {
		ObjectType  string `json:"object_type"`
		ObjectID    string `json:"object_id"`
		DetailsText string `json:"details_text"`
		Truncated   bool   `json:"truncated"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed), "the cut message is still JSON")
	full, err := json.Marshal(e.Details)
	require.NoError(t, err)
	assert.True(t, parsed.Truncated)
	assert.Equal(t, "backup", parsed.ObjectType)
	assert.NotEmpty(t, parsed.DetailsText)
	assert.True(t, strings.HasPrefix(string(full), parsed.DetailsText), "the cut text is a prefix of the details")

	small := message(entry(), "alice01", "alice")
	assert.NotContains(t, string(small), "truncated")
}

func TestLongObjectIDIsCut(t *testing.T) {
	e := entry()
	e.ObjectID = strings.Repeat("ş", 9000)
	got := message(e, "alice01", "alice")
	assert.LessOrEqual(t, len(got), MaxMessage)
	assert.True(t, utf8.Valid(got))
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		action string
		result audit.Result
		pri    string
	}{
		{"backup.created", audit.Success, "<37>"},
		{"backup.failed", audit.Failure, "<36>"},
		{"auth.login", audit.Denied, "<36>"},
		{"audit.verified", audit.Success, "<37>"},
		{"audit.verified", audit.Failure, "<34>"},
	}
	for _, c := range cases {
		e := entry()
		e.Action, e.Result = c.action, c.result
		assert.True(t, strings.HasPrefix(string(message(e, "h", "alice")), c.pri+"1 "), "%s %s", c.action, c.result)
	}
}

func TestCheckpointMessage(t *testing.T) {
	cp := audit.Checkpoint{Seq: 7, Hash: strings.Repeat("ef", 32), At: time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)}
	assert.Equal(t, `<37>1 2026-10-10T03:00:00Z alice01 alice - audit.checkpoint [alice@32473 seq="7" hash="`+
		strings.Repeat("ef", 32)+`"] {"object_type":"audit_log","object_id":"","details":{}}`,
		string(checkpointMessage(cp, "alice01", "alice")))
}
