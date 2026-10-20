package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestHashCoversEveryContentField(t *testing.T) {
	base := Request{ID: 1, Customer: "Acme Ltd", NewRequest: NewRequest{CustomerID: 1, Installation: "ALICE-AAAAA-BBBBB",
		Targets: 5, From: "2026-11-01", Months: 12, Features: []string{"ssh", "tls"}, Replaces: ""}}
	h := RequestHash(base)
	assert.Len(t, h, 64)
	assert.Equal(t, h, RequestHash(base), "stable")

	for name, mutate := range map[string]func(*Request){
		"customer":     func(r *Request) { r.Customer = "Other Ltd" },
		"installation": func(r *Request) { r.Installation = "ALICE-AAAAA-BBBBC" },
		"targets":      func(r *Request) { r.Targets = 6 },
		"from":         func(r *Request) { r.From = "2026-11-02" },
		"months":       func(r *Request) { r.Months = 13 },
		"features":     func(r *Request) { r.Features = []string{"ssh"} },
		"replaces":     func(r *Request) { r.Replaces = "LIC-2026-000001" },
	} {
		changed := base
		changed.Features = append([]string(nil), base.Features...)
		mutate(&changed)
		assert.NotEqual(t, h, RequestHash(changed), name)
	}
}

func TestRequestHashSeparatesFields(t *testing.T) {
	a := Request{Customer: "ab", NewRequest: NewRequest{Installation: "c"}}
	b := Request{Customer: "a", NewRequest: NewRequest{Installation: "bc"}}
	assert.NotEqual(t, RequestHash(a), RequestHash(b))
}

func TestRequestHashIgnoresStatusAndTimes(t *testing.T) {
	a := Request{Status: "open", RequestedBy: "x"}
	b := Request{Status: "signed", RequestedBy: "y"}
	assert.Equal(t, RequestHash(a), RequestHash(b))
}

// An emergency extension's kind, days, reason and extended license are content the signer
// approves; a normal request hashes exactly as before the extension existed (a hash shown by an
// older build still matches).
func TestRequestHashCoversTheEmergencyFields(t *testing.T) {
	normal := Request{Customer: "Acme Ltd", NewRequest: NewRequest{Installation: "ALICE-AAAAA-BBBBB", Targets: 5,
		Months: 12, Features: []string{"ssh"}}}
	raw, _ := json.Marshal([]any{"Acme Ltd", "ALICE-AAAAA-BBBBB", 5, "", 12, []string{"ssh"}, ""})
	sum := sha256.Sum256(raw)
	assert.Equal(t, hex.EncodeToString(sum[:]), RequestHash(normal))
	normal.Kind = KindLicense
	assert.Equal(t, hex.EncodeToString(sum[:]), RequestHash(normal), "kind license is the old hash")

	ext := Request{Customer: "Acme Ltd", Kind: KindEmergency, Days: 14, Reason: "PO delayed", Extends: "LIC-1",
		NewRequest: NewRequest{Installation: "ALICE-AAAAA-BBBBB", Targets: 5, Features: []string{"ssh"}}}
	h := RequestHash(ext)
	for name, mutate := range map[string]func(*Request){
		"kind":    func(r *Request) { r.Kind = KindLicense },
		"days":    func(r *Request) { r.Days = 30 },
		"reason":  func(r *Request) { r.Reason = "other" },
		"extends": func(r *Request) { r.Extends = "LIC-2" },
	} {
		changed := ext
		mutate(&changed)
		assert.NotEqual(t, h, RequestHash(changed), name)
	}
}
