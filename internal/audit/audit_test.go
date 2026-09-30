package audit_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"alice/internal/audit"
)

func sample() audit.Entry {
	return audit.Entry{
		Seq:       1,
		At:        time.Date(2026, 9, 30, 10, 0, 0, 123456789, time.UTC),
		ActorType: audit.ActorUser,
		ActorID:   uuid.MustParse("0192e0a0-0000-7000-8000-000000000001"),
		ActorName: "admin",
		IP:        "10.0.0.7",
		Action:    "user.created",
		Result:    audit.Success,
		Details:   map[string]string{"b": "2", "a": "İzmir"},
		RequestID: "req-1",
	}
}

func TestComputeHashIsDeterministicAndTruncatesToMicroseconds(t *testing.T) {
	zero := make([]byte, sha256.Size)
	e := sample()
	h := audit.ComputeHash(zero, e)
	assert.Len(t, h, 32)

	same := sample()
	same.At = same.At.Truncate(time.Microsecond).In(time.FixedZone("TRT", 3*3600))
	same.Details = map[string]string{"a": "İzmir", "b": "2"}
	assert.Equal(t, h, audit.ComputeHash(zero, same), "time zone, sub-microsecond digits and map order do not matter")

	nilDetails := sample()
	nilDetails.Details = nil
	empty := sample()
	empty.Details = map[string]string{}
	assert.Equal(t, audit.ComputeHash(zero, nilDetails), audit.ComputeHash(zero, empty))
}

func TestComputeHashCoversEveryField(t *testing.T) {
	zero := make([]byte, sha256.Size)
	base := audit.ComputeHash(zero, sample())
	mutations := map[string]func(*audit.Entry){
		"seq":         func(e *audit.Entry) { e.Seq = 2 },
		"at":          func(e *audit.Entry) { e.At = e.At.Add(time.Microsecond) },
		"actor_type":  func(e *audit.Entry) { e.ActorType = audit.ActorSystem },
		"actor_id":    func(e *audit.Entry) { e.ActorID = uuid.Nil },
		"actor_name":  func(e *audit.Entry) { e.ActorName = "root" },
		"ip":          func(e *audit.Entry) { e.IP = "" },
		"action":      func(e *audit.Entry) { e.Action = "user.updated" },
		"object_type": func(e *audit.Entry) { e.ObjectType = "user" },
		"object_id":   func(e *audit.Entry) { e.ObjectID = "x" },
		"result":      func(e *audit.Entry) { e.Result = audit.Failure },
		"details":     func(e *audit.Entry) { e.Details["a"] = "Izmir" },
		"request_id":  func(e *audit.Entry) { e.RequestID = "req-2" },
	}
	for name, mutate := range mutations {
		e := sample()
		mutate(&e)
		assert.NotEqual(t, base, audit.ComputeHash(zero, e), name)
	}
	prev := make([]byte, sha256.Size)
	prev[0] = 1
	assert.NotEqual(t, base, audit.ComputeHash(prev, sample()), "prev hash is chained")
}

func TestSystemActor(t *testing.T) {
	a := audit.SystemActor("cli")
	assert.Equal(t, audit.ActorSystem, a.Type)
	assert.Equal(t, "cli", a.Name)
	assert.Equal(t, uuid.Nil, a.ID)
}
