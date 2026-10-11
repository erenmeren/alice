package forward

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"

	"alice/internal/audit"
)

// MaxMessage bounds one syslog message (without its octet-count frame): the details are cut to fit.
const MaxMessage = 8 << 10

const (
	facilityAuth   = 4
	sevCritical    = 2
	sevWarning     = 4
	sevNotice      = 5
	sdID           = "alice@32473" // RFC 5424 §7.2.2: a private SD-ID under the example enterprise number
	timeLayout     = "2006-01-02T15:04:05.999999Z07:00"
	maxHostname    = 255
	maxAppName     = 48
	maxMsgID       = 32
	maxActor       = 255
	maxObjectID    = 1024
	maxObjectType  = 255
	checkpointName = "audit.checkpoint"
)

// body is the MSG part: the object and the details of an entry.
type body struct {
	ObjectType string            `json:"object_type"`
	ObjectID   string            `json:"object_id"`
	Details    map[string]string `json:"details"`
}

// cutBody replaces body when the message would exceed MaxMessage: the details JSON cut at a UTF-8 boundary.
type cutBody struct {
	ObjectType  string `json:"object_type"`
	ObjectID    string `json:"object_id"`
	DetailsText string `json:"details_text"`
	Truncated   bool   `json:"truncated"`
}

// severity maps a result to a syslog severity: a failed chain verification is critical.
func severity(e audit.Entry) int {
	switch {
	case e.Action == "audit.verified" && e.Result == audit.Failure:
		return sevCritical
	case e.Result == audit.Failure || e.Result == audit.Denied:
		return sevWarning
	}
	return sevNotice
}

// message renders e as one RFC 5424 message of at most MaxMessage bytes.
func message(e audit.Entry, hostname, app string) []byte {
	actor := e.ActorName
	if actor == "" {
		actor = string(e.ActorType)
	}
	sd := "[" + sdID + ` seq="` + strconv.FormatInt(e.Seq, 10) + `" hash="` + hex.EncodeToString(e.Hash) +
		`" prev_hash="` + hex.EncodeToString(e.PrevHash) + `" actor="` + sdEscape(cutUTF8(actor, maxActor)) +
		`" result="` + sdEscape(string(e.Result)) + `"]`
	head := header(severity(e), e.At.UTC().Format(timeLayout), hostname, app, e.Action) + sd + " "
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	objectType, objectID := cutUTF8(e.ObjectType, maxObjectType), cutUTF8(e.ObjectID, maxObjectID)
	msg := append([]byte(head), marshal(body{ObjectType: objectType, ObjectID: objectID, Details: details})...)
	if len(msg) <= MaxMessage {
		return msg
	}
	budget := MaxMessage - len(head)
	b := fit(string(marshal(details)), budget, func(cut string) []byte {
		return marshal(cutBody{ObjectType: objectType, ObjectID: objectID, DetailsText: cut, Truncated: true})
	})
	if b == nil { // the object alone is over the budget: no details, and the object id cut to fit
		b = fit(objectID, budget, func(cut string) []byte {
			return marshal(cutBody{ObjectType: objectType, ObjectID: cut, Truncated: true})
		})
	}
	if b == nil { // unreachable with the caps above (head ≤ ~1.1 KiB, escaped object type ≤ 1.5 KiB); total anyway
		b = marshal(cutBody{Truncated: true})
	}
	return append([]byte(head), b...)
}

// fit returns build of the longest UTF-8 prefix of s it finds whose result is at most budget bytes, or nil when
// even the empty prefix is over the budget. JSON escapes can grow a byte up to six, so each step shrinks the
// prefix by at least half the excess and never below zero (review minor 1).
func fit(s string, budget int, build func(cut string) []byte) []byte {
	for n := len(s); ; {
		cut := cutUTF8(s, max(n, 0))
		b := build(cut)
		if len(b) <= budget {
			return b
		}
		if cut == "" {
			return nil
		}
		n = len(cut) - max(1, (len(b)-budget)/2)
	}
}

// checkpointMessage renders a stored checkpoint as its own message (F-92).
func checkpointMessage(cp audit.Checkpoint, hostname, app string) []byte {
	sd := "[" + sdID + ` seq="` + strconv.FormatInt(cp.Seq, 10) + `" hash="` + sdEscape(cp.Hash) + `"]`
	head := header(sevNotice, cp.At.UTC().Format(timeLayout), hostname, app, checkpointName) + sd + " "
	return append([]byte(head), marshal(body{ObjectType: "audit_log", Details: map[string]string{}})...)
}

// header is "<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ".
func header(sev int, ts, hostname, app, msgID string) string {
	return "<" + strconv.Itoa(facilityAuth*8+sev) + ">1 " + ts + " " + headerField(hostname, maxHostname) + " " +
		headerField(app, maxAppName) + " - " + headerField(msgID, maxMsgID) + " "
}

// headerField keeps a header field to PRINTUSASCII (RFC 5424 §6): every other rune becomes '_', "" becomes "-".
func headerField(s string, limit int) string {
	if s == "" {
		return "-"
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len() == limit {
			break
		}
		if r < 33 || r > 126 {
			r = '_'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sdEscape escapes '"', '\' and ']' in a PARAM-VALUE (RFC 5424 §6.3.3).
func sdEscape(s string) string {
	return strings.NewReplacer(`"`, `\"`, `\`, `\\`, `]`, `\]`).Replace(s)
}

// cutUTF8 returns the longest prefix of s of at most n bytes that ends on a rune boundary.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// marshal encodes v as compact JSON without HTML escaping. The values are strings and maps of strings, so it cannot fail.
func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// octetFrame is the octet-counting frame of RFC 6587 §3.4.1 (and RFC 5425): "<length> <message>".
func octetFrame(msg []byte) []byte {
	return append(strconv.AppendInt(nil, int64(len(msg)), 10), append([]byte(" "), msg...)...)
}
