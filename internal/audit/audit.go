// Package audit is Alice's append-only, hash-chained audit log (spec §7.5, SEC-070..075).
//
// Every row stores hash = SHA-256(prev_hash || canonical JSON of the row).
// Rows are appended by Append only, under a transaction-scoped advisory lock,
// with gapless sequence numbers, so any edit, deletion, insertion or reorder
// breaks the chain. Details hold keys and parameters, never secrets.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/clock"
)

// ActorType says who performed an action.
type ActorType string

// Actor types stored in audit_log.actor_type.
const (
	ActorUser   ActorType = "user"
	ActorToken  ActorType = "api_token"
	ActorSystem ActorType = "system"
	// ActorOIDC is an identity provider's user before (or without) a session: SSO
	// provisioning, role synchronization and refused SSO sign-ins.
	ActorOIDC ActorType = "oidc"
)

// Result is the outcome of an audited action.
type Result string

// Results stored in audit_log.result.
const (
	Success Result = "success"
	Failure Result = "failure"
	Denied  Result = "denied"
)

// Actor identifies who acted, from where, in which request.
type Actor struct {
	Type      ActorType
	ID        uuid.UUID // uuid.Nil = none
	Name      string
	IP        netip.Addr // zero = none
	RequestID string
}

// SystemActor is an actor for actions Alice or a host CLI performs itself.
func SystemActor(name string) Actor { return Actor{Type: ActorSystem, Name: name} }

// Event is one action to record.
type Event struct {
	Actor      Actor
	Action     string
	ObjectType string
	ObjectID   string
	Result     Result
	Details    map[string]string
}

// Entry is a stored audit row.
type Entry struct {
	Seq        int64
	At         time.Time
	ActorType  ActorType
	ActorID    uuid.UUID // uuid.Nil = none
	ActorName  string
	IP         string // canonical address, "" = none
	Action     string
	ObjectType string
	ObjectID   string
	Result     Result
	Details    map[string]string
	RequestID  string
	PrevHash   []byte
	Hash       []byte
}

// ErrForbiddenDetailKey is returned when a details key names something that may carry a secret.
var ErrForbiddenDetailKey = errors.New("audit: details key may carry a secret")

// lockKey is the pg_advisory_xact_lock key that serializes chain writes (an arbitrary constant).
const lockKey int64 = 7160927315633811300

const timeLayout = "2006-01-02T15:04:05.000000Z07:00"

// Log appends audit events using an injected clock.
type Log struct {
	clock clock.Clock
}

// New returns a Log.
func New(c clock.Clock) *Log { return &Log{clock: c} }

// lockChain takes the transaction advisory lock that serializes chain writes and
// checkpoint updates. Taking it again in the same transaction is harmless.
func lockChain(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("audit: lock chain: %w", err)
	}
	return nil
}

// Append writes e as the next chain link inside tx. The caller's business
// change and its audit row therefore commit or roll back together.
func (l *Log) Append(ctx context.Context, tx pgx.Tx, e Event) (Entry, error) {
	e = normalize(e)
	if err := checkDetails(e.Details); err != nil {
		return Entry{}, err
	}
	if e.Action == "" || e.Result == "" || e.Actor.Type == "" {
		return Entry{}, errors.New("audit: event needs an actor type, an action and a result")
	}
	if err := lockChain(ctx, tx); err != nil {
		return Entry{}, err
	}
	withService, serr := withServiceID(ctx, tx, e)
	if serr != nil {
		return Entry{}, serr
	}
	e.Details = withService
	var lastSeq int64
	prev := make([]byte, sha256.Size)
	err := tx.QueryRow(ctx, "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&lastSeq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, fmt.Errorf("audit: read chain head: %w", err)
	}

	en := Entry{
		Seq:        lastSeq + 1,
		At:         l.clock.Now().UTC().Truncate(time.Microsecond),
		ActorType:  e.Actor.Type,
		ActorID:    e.Actor.ID,
		ActorName:  e.Actor.Name,
		IP:         canonicalIP(e.Actor.IP),
		Action:     e.Action,
		ObjectType: e.ObjectType,
		ObjectID:   e.ObjectID,
		Result:     e.Result,
		Details:    e.Details,
		RequestID:  e.Actor.RequestID,
		PrevHash:   prev,
	}
	en.Hash = ComputeHash(prev, en)

	details, err := json.Marshal(en.Details)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: encode details: %w", err)
	}
	var actorID *uuid.UUID
	if en.ActorID != uuid.Nil {
		actorID = &en.ActorID
	}
	var ip *string
	if en.IP != "" {
		ip = &en.IP
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log
		(seq, at, actor_type, actor_id, actor_name, ip, action, object_type, object_id, result, details, request_id, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12, $13, $14)`,
		en.Seq, en.At, string(en.ActorType), actorID, en.ActorName, ip, en.Action, en.ObjectType, en.ObjectID,
		string(en.Result), details, en.RequestID, en.PrevHash, en.Hash)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: insert: %w", err)
	}
	return en, nil
}

type canonical struct {
	Seq        int64             `json:"seq"`
	At         string            `json:"at"`
	ActorType  string            `json:"actor_type"`
	ActorID    string            `json:"actor_id"`
	ActorName  string            `json:"actor_name"`
	IP         string            `json:"ip"`
	Action     string            `json:"action"`
	ObjectType string            `json:"object_type"`
	ObjectID   string            `json:"object_id"`
	Result     string            `json:"result"`
	Details    map[string]string `json:"details"`
	RequestID  string            `json:"request_id"`
}

// ComputeHash returns SHA-256(prev || canonical JSON of e). Field order is
// fixed by the struct, map keys are sorted by encoding/json, the time is
// microsecond-precision UTC, so the hash is identical after a database round trip.
func ComputeHash(prev []byte, e Entry) []byte {
	c := canonical{
		Seq:        e.Seq,
		At:         e.At.UTC().Truncate(time.Microsecond).Format(timeLayout),
		ActorType:  string(e.ActorType),
		ActorName:  e.ActorName,
		IP:         e.IP,
		Action:     e.Action,
		ObjectType: e.ObjectType,
		ObjectID:   e.ObjectID,
		Result:     string(e.Result),
		Details:    copyDetails(e.Details),
		RequestID:  e.RequestID,
	}
	if e.ActorID != uuid.Nil {
		c.ActorID = e.ActorID.String()
	}
	b, err := json.Marshal(c)
	if err != nil {
		panic("audit: canonical encoding failed: " + err.Error()) // only strings and ints: cannot fail
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return h.Sum(nil)
}

// sensitiveSegments are key segments that mark a details key as possibly carrying a secret.
var sensitiveSegments = map[string]bool{
	"password": true, "passphrase": true, "secret": true, "private": true, "token": true, "code": true,
	"totp": true, "otp": true, "key": true, "dek": true, "credential": true, "cookie": true, "session": true,
}

// checkDetails rejects details keys with a sensitive segment (case-insensitive; segments split on
// '_', '-', '.' and camelCase boundaries). Keys ending in id, prefix or count, and error_code and
// reason_code, are metadata about a secret rather than the secret and are allowed.
func checkDetails(d map[string]string) error {
	for k := range d {
		segs := keySegments(k)
		if len(segs) == 0 {
			continue
		}
		joined := strings.Join(segs, "_")
		if joined == "error_code" || joined == "reason_code" {
			continue
		}
		if len(segs) > 1 {
			switch segs[len(segs)-1] {
			case "id", "prefix", "count":
				continue
			}
		}
		for _, s := range segs {
			if sensitiveSegments[s] || sensitiveSegments[strings.TrimSuffix(s, "s")] {
				return fmt.Errorf("%w: %q", ErrForbiddenDetailKey, k)
			}
		}
	}
	return nil
}

// keySegments splits k into lower-case ASCII segments.
func keySegments(k string) []string {
	var segs []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, string(cur))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c == '_' || c == '-' || c == '.':
			flush()
		case c >= 'A' && c <= 'Z':
			prevLower := i > 0 && (k[i-1] >= 'a' && k[i-1] <= 'z' || k[i-1] >= '0' && k[i-1] <= '9')
			nextLower := i+1 < len(k) && k[i+1] >= 'a' && k[i+1] <= 'z'
			prevUpper := i > 0 && k[i-1] >= 'A' && k[i-1] <= 'Z'
			if prevLower || (prevUpper && nextLower) {
				flush()
			}
			cur = append(cur, c+'a'-'A')
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return segs
}

// sanitize makes s storable in PostgreSQL text and jsonb: invalid UTF-8 and NUL become U+FFFD.
func sanitize(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "\uFFFD")
}

// normalize sanitizes every string of e so that the hash covers exactly what is stored.
func normalize(e Event) Event {
	e.Actor.Name = sanitize(e.Actor.Name)
	e.Actor.RequestID = sanitize(e.Actor.RequestID)
	e.Action = sanitize(e.Action)
	e.ObjectType = sanitize(e.ObjectType)
	e.ObjectID = sanitize(e.ObjectID)
	d := make(map[string]string, len(e.Details))
	for k, v := range e.Details {
		d[sanitize(k)] = sanitize(v)
	}
	e.Details = d
	return e
}

func copyDetails(d map[string]string) map[string]string {
	out := make(map[string]string, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

func canonicalIP(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.Unmap().WithZone("").String()
}

// canonicalIPText canonicalizes an address read back with host(ip).
func canonicalIPText(s *string) string {
	if s == nil {
		return ""
	}
	a, err := netip.ParseAddr(*s)
	if err != nil {
		return *s
	}
	return a.Unmap().String()
}
