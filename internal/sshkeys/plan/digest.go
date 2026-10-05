package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
)

type digestAction struct {
	Location uuid.UUID `json:"l"`
	Target   uuid.UUID `json:"t"`
	User     string    `json:"u"`
	File     string    `json:"f"`
	Options  string    `json:"o"`
	Skip     string    `json:"s"`
	Verify   bool      `json:"v"`
	Note     string    `json:"n"`
}

// Digest is the SHA-256 of the plan's decisions: the key, the new key type, the overlap and every
// action's location, server, user, file, options, skip and verification rule, in the plan's order.
// Display text (server names, comments, the lines) is not part of it.
func (p Plan) Digest() string {
	d := struct {
		Key        uuid.UUID      `json:"k"`
		FP         string         `json:"fp"`
		NewKeyType string         `json:"nt"`
		Overlap    int            `json:"o"`
		Actions    []digestAction `json:"a"`
	}{Key: p.KeyID, FP: p.Fingerprint, NewKeyType: p.NewKeyType, Overlap: p.Overlap, Actions: make([]digestAction, 0, len(p.Actions))}
	for _, a := range p.Actions {
		d.Actions = append(d.Actions, digestAction{a.LocationID, a.TargetID, a.OSUser, a.FilePath, a.Options, a.Skip, a.Verify, a.VerifyNote})
	}
	raw, _ := json.Marshal(d) // cannot fail: fixed struct of strings, bools, ints and UUIDs
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
