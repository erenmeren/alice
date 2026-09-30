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

var forbiddenKeys = map[string]bool{
	"password": true, "secret": true, "passphrase": true, "token": true, "code": true,
	"totp_secret": true, "private_key": true, "recovery_code": true,
}

// lockKey is the pg_advisory_xact_lock key that serializes chain writes ("caudit" as bytes).
const lockKey int64 = 7160927315633811300

const timeLayout = "2006-01-02T15:04:05.000000Z07:00"

// Log appends audit events using an injected clock.
type Log struct {
	clock clock.Clock
}

// New returns a Log.
func New(c clock.Clock) *Log { return &Log{clock: c} }

// Append writes e as the next chain link inside tx. The caller's business
// change and its audit row therefore commit or roll back together.
func (l *Log) Append(ctx context.Context, tx pgx.Tx, e Event) (Entry, error) {
	if err := checkDetails(e.Details); err != nil {
		return Entry{}, err
	}
	if e.Action == "" || e.Result == "" || e.Actor.Type == "" {
		return Entry{}, errors.New("audit: event needs an actor type, an action and a result")
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return Entry{}, fmt.Errorf("audit: lock chain: %w", err)
	}
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
		Details:    copyDetails(e.Details),
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

func checkDetails(d map[string]string) error {
	for k := range d {
		if forbiddenKeys[k] || strings.HasPrefix(k, "private") {
			return fmt.Errorf("%w: %q", ErrForbiddenDetailKey, k)
		}
	}
	return nil
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
	return a.Unmap().String()
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
