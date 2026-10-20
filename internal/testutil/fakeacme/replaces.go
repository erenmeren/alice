package fakeacme

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Replacement is one order that carried the replaces field (RFC 9773 section 5): the order and the RFC 9773 identifier
// of the certificate it replaces.
type Replacement struct {
	OrderID string `json:"order_id"`
	CertID  string `json:"cert_id"`
}

// ariWindow is a renewal window set for one certificate.
type ariWindow struct{ start, end time.Time }

// validARIID reports whether id has the form of an RFC 9773 certificate identifier: two non-empty base64url parts
// joined by one ".".
func validARIID(id string) bool {
	aki, serial, ok := strings.Cut(id, ".")
	if !ok || aki == "" || serial == "" || strings.Contains(serial, ".") || len(id) > 512 {
		return false
	}
	_, err1 := base64.RawURLEncoding.DecodeString(aki)
	_, err2 := base64.RawURLEncoding.DecodeString(serial)
	return err1 == nil && err2 == nil
}

// replacesLocked checks the replaces field of the new order o (RFC 9773 section 5) and marks the certificate replaced
// by it: a certificate this CA issued (malformed otherwise), to the order's account (unauthorized), sharing at least one
// name with the order (malformed), not replaced already by an order that is not invalid (alreadyReplaced, 409; an
// invalid order never counts). The caller holds mu.
func (s *Server) replacesLocked(id string, o *order) *problem {
	c := s.st.byARI[id]
	if c == nil {
		return malformed(http.StatusBadRequest, "replaces names no certificate this CA issued")
	}
	if c.account != o.account {
		return newProblem(http.StatusForbidden, "unauthorized", "the certificate to replace was issued to another account")
	}
	shared := false
	for _, n := range c.leaf.DNSNames {
		for _, ident := range o.idents {
			shared = shared || ident.Value == n
		}
	}
	if !shared {
		return malformed(http.StatusBadRequest, "the order shares no identifier with the certificate it replaces")
	}
	if prev := s.st.orders[c.replacedBy]; prev != nil {
		s.refreshLocked(prev)
		if prev.status != "invalid" {
			return newProblem(http.StatusConflict, "alreadyReplaced", "the certificate is already being replaced by another order")
		}
	}
	o.replaces, c.replacedBy = id, o.id
	s.st.replaced = append(s.st.replaced, Replacement{OrderID: o.id, CertID: id})
	return nil
}

// Replacements lists the orders that carried the replaces field, oldest first.
func (s *Server) Replacements() []Replacement {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Replacement{}, s.st.replaced...)
}

// SetARIWindowFor makes the renewalInfo answer of one certificate (by its RFC 9773 identifier) this absolute window,
// whatever SetARIWindow or SetARIRelative say for the others.
func (s *Server) SetARIWindowFor(certID string, start, end time.Time) error {
	if !end.After(start) {
		return fmt.Errorf("fakeacme: the window must end after it starts")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.byARI[certID] == nil {
		return fmt.Errorf("fakeacme: no certificate with that identifier")
	}
	s.st.ariWindows[certID] = ariWindow{start: start, end: end}
	return nil
}

// SetARIWindowForSerial is SetARIWindowFor for the certificate with the serial number serialHex (hexadecimal).
func (s *Server) SetARIWindowForSerial(serialHex string, start, end time.Time) error {
	want, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(serialHex, "0x"), "0X"), 16)
	if !ok {
		return fmt.Errorf("fakeacme: the serial number is not hexadecimal")
	}
	s.mu.Lock()
	id := ""
	for _, c := range s.st.certs {
		if c.leaf.SerialNumber.Cmp(want) == 0 {
			id = ariID(c.leaf)
		}
	}
	s.mu.Unlock()
	if id == "" {
		return fmt.Errorf("fakeacme: no certificate with that serial number")
	}
	return s.SetARIWindowFor(id, start, end)
}

// ClearARIWindows removes every window set for one certificate.
func (s *Server) ClearARIWindows() {
	s.mu.Lock()
	s.st.ariWindows = map[string]ariWindow{}
	s.mu.Unlock()
}
