package plan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strconv"
)

// digestVersion changes the encoding below; it is part of what is hashed.
const digestVersion = 1

type digestWriter struct{ h hash.Hash }

func (w digestWriter) str(s string) {
	w.u64(uint64(len(s)))
	_, _ = w.h.Write([]byte(s)) // hash.Hash.Write never returns an error
}

func (w digestWriter) u64(n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	_, _ = w.h.Write(b[:])
}

func (w digestWriter) bool(v bool) {
	if v {
		w.u64(1)
	} else {
		w.u64(0)
	}
}

// Digest is the SHA-256 of the plan's decisions: the key, its fingerprint, the new key type, the
// overlap and every action's location, server, user, file, options, skip and verification rule, in
// the plan's order. Display text (server names, comments, the lines) is not part of it. Every field
// is written length-prefixed as raw bytes, so the encoding is injective for any string, valid UTF-8
// or not.
func (p Plan) Digest() string {
	w := digestWriter{sha256.New()}
	w.u64(digestVersion)
	w.str(string(p.KeyID[:]))
	w.str(p.Fingerprint)
	w.str(p.NewKeyType)
	w.str(strconv.Itoa(p.Overlap))
	w.u64(uint64(len(p.Actions)))
	for _, a := range p.Actions {
		w.str(string(a.LocationID[:]))
		w.str(string(a.TargetID[:]))
		w.str(a.OSUser)
		w.str(a.FilePath)
		w.str(a.Options)
		w.str(a.Skip)
		w.bool(a.Verify)
		w.str(a.VerifyNote)
	}
	return hex.EncodeToString(w.h.Sum(nil))
}
