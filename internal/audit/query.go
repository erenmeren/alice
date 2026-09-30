package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// Filter selects entries for List.
type Filter struct {
	Action    string // prefix match, "" = any
	Actor     string // exact actor_name (case-insensitive), "" = any
	Result    Result // "" = any
	BeforeSeq int64  // 0 = newest
	Limit     int    // default 50, max 200
}

const (
	defaultLimit = 50
	maxLimit     = 200
)

const selectColumns = `SELECT seq, at, actor_type, actor_id, actor_name, host(ip), action, object_type, object_id,
	result, details, request_id, prev_hash, hash FROM audit_log`

// List returns entries newest first. next is the seq to pass as BeforeSeq for
// the following page, or 0 when there are no more entries.
func List(ctx context.Context, q db.Querier, f Filter) ([]Entry, int64, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxLimit)
	var action, actor, result *string
	if f.Action != "" {
		p := escapeLike(f.Action) + "%"
		action = &p
	}
	if f.Actor != "" {
		actor = &f.Actor
	}
	if f.Result != "" {
		r := string(f.Result)
		result = &r
	}
	var before *int64
	if f.BeforeSeq > 0 {
		before = &f.BeforeSeq
	}
	rows, err := q.Query(ctx, selectColumns+`
		WHERE ($1::text IS NULL OR action LIKE $1 ESCAPE '\')
		  AND ($2::text IS NULL OR lower(actor_name) = lower($2))
		  AND ($3::text IS NULL OR result = $3)
		  AND ($4::bigint IS NULL OR seq < $4)
		ORDER BY seq DESC LIMIT $5`, action, actor, result, before, limit+1)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: list: %w", err)
	}
	items, err := collect(rows)
	if err != nil {
		return nil, 0, err
	}
	var next int64
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].Seq
	}
	return items, next, nil
}

// Iterate calls fn for every entry in ascending seq order, streaming rows.
func Iterate(ctx context.Context, q db.Querier, fn func(Entry) error) error {
	rows, err := q.Query(ctx, selectColumns+" ORDER BY seq")
	if err != nil {
		return fmt.Errorf("audit: iterate: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

func collect(rows pgx.Rows) ([]Entry, error) {
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scan(rows pgx.Rows) (Entry, error) {
	var (
		e                 Entry
		actorType, result string
		actorID           *uuid.UUID
		ip                *string
		details           []byte
	)
	if err := rows.Scan(&e.Seq, &e.At, &actorType, &actorID, &e.ActorName, &ip, &e.Action, &e.ObjectType,
		&e.ObjectID, &result, &details, &e.RequestID, &e.PrevHash, &e.Hash); err != nil {
		return Entry{}, fmt.Errorf("audit: scan: %w", err)
	}
	e.At = e.At.UTC()
	e.ActorType, e.Result = ActorType(actorType), Result(result)
	if actorID != nil {
		e.ActorID = *actorID
	}
	e.IP = canonicalIPText(ip)
	e.Details = map[string]string{}
	if err := json.Unmarshal(details, &e.Details); err != nil {
		return Entry{}, fmt.Errorf("audit: decode details of entry %d: %w", e.Seq, err)
	}
	return e, nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
