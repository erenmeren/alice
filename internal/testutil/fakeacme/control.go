package fakeacme

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Credentials are the values a client of the fake needs; they survive Reset.
type Credentials struct {
	DirectoryURL string `json:"directory_url"`
	BaseURL      string `json:"base_url"`
	TermsURL     string `json:"terms_url"`
	EABKID       string `json:"eab_kid"`
	EABHMAC      string `json:"eab_hmac"` // base64url, as CAs hand it out
	HookURL      string `json:"hook_url"`
	HookSecret   string `json:"hook_secret"`
}

// Credentials returns the EAB credentials and the DNS hook's address and secret.
func (s *Server) Credentials() Credentials {
	base := s.BaseURL()
	return Credentials{DirectoryURL: base + "/directory", BaseURL: base, TermsURL: base + "/terms", EABKID: s.opts.EABKID,
		EABHMAC: base64.RawURLEncoding.EncodeToString(s.opts.EABKey), HookURL: base + "/hook", HookSecret: s.opts.HookSecret}
}

// Reset clears accounts, orders, certificates, the DNS table, HTTP targets, faults, counters, the
// request log and every toggle. CAs, TLS certificate, EAB credentials and hook secret stay.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetLocked()
}

// Counters are the requests served per endpoint ("requests" is all of them), plus "issued",
// "validations-http-01", "validations-dns-01", "hook-present" and "hook-cleanup". A test asserts the
// CA was not contacted with Counters()["requests"] == 0.
func (s *Server) Counters() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.st.counters))
	for k, v := range s.st.counters {
		out[k] = v
	}
	return out
}

// Requests is the request log: method, path, status, time. Never a body, header or query.
func (s *Server) Requests() []LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]LogEntry{}, s.st.log...)
}

// ClearRequests empties the request log and the counters.
func (s *Server) ClearRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.log = nil
	s.st.counters = map[string]int{}
}

// DNSSet adds a TXT value to a name of the fake's DNS table (what DNS-01 validation reads).
func (s *Server) DNSSet(fqdn, value string) {
	n := normFQDN(fqdn)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !contains(s.st.dns[n], value) {
		s.st.dns[n] = append(s.st.dns[n], value)
	}
}

// DNSClear removes one value of a name, or the whole name when value is empty; an empty name clears
// the table.
func (s *Server) DNSClear(fqdn, value string) {
	n := normFQDN(fqdn)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case n == "":
		s.st.dns = map[string][]string{}
	case value == "":
		delete(s.st.dns, n)
	default:
		var keep []string
		for _, v := range s.st.dns[n] {
			if v != value {
				keep = append(keep, v)
			}
		}
		if len(keep) == 0 {
			delete(s.st.dns, n)
		} else {
			s.st.dns[n] = keep
		}
	}
}

// DNSRecords is a copy of the DNS table.
func (s *Server) DNSRecords() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]string, len(s.st.dns))
	for k, v := range s.st.dns {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// SetHTTPTarget makes HTTP-01 validation of name connect to addr ("host:port", or a bare host for
// port 80); the Host header and URL keep name. An empty addr removes the mapping.
func (s *Server) SetHTTPTarget(name, addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if addr == "" {
		delete(s.st.targets, asciiLower(name))
		return
	}
	s.st.targets[asciiLower(name)] = addr
}

// SetExternalAccountRequired toggles meta.externalAccountRequired and its enforcement.
func (s *Server) SetExternalAccountRequired(on bool) {
	s.mu.Lock()
	s.cfg.requireEAB = on
	s.mu.Unlock()
}

// SetLeafLifetime sets the validity of leaves issued from now on.
func (s *Server) SetLeafLifetime(d time.Duration) error {
	if d < time.Minute || d > 400*24*time.Hour {
		return fmt.Errorf("fakeacme: a lifetime must be between one minute and 400 days")
	}
	s.mu.Lock()
	s.cfg.lifetime = d
	s.mu.Unlock()
	return nil
}

// SetARIWindow makes every renewalInfo answer this absolute window.
func (s *Server) SetARIWindow(start, end time.Time) error {
	if !end.After(start) {
		return fmt.Errorf("fakeacme: the window must end after it starts")
	}
	s.mu.Lock()
	s.cfg.ariStart, s.cfg.ariEnd = start, end
	s.mu.Unlock()
	return nil
}

// SetARIRelative makes the window start before-expiry ahead of each certificate's notAfter and last
// length. Zero values mean the defaults (a third of the life before expiry; a twelfth long).
func (s *Server) SetARIRelative(beforeExpiry, length time.Duration) {
	s.mu.Lock()
	s.cfg.ariStart, s.cfg.ariEnd = time.Time{}, time.Time{}
	s.cfg.ariBefore, s.cfg.ariLength = beforeExpiry, length
	s.mu.Unlock()
}

// SetStuckPending makes every challenge POST answer "processing" and never validate: the order
// stays pending for good.
func (s *Server) SetStuckPending(on bool) {
	s.mu.Lock()
	s.cfg.stuck = on
	s.mu.Unlock()
}

// FailValidation makes validation of a challenge type (http-01, dns-01) fail.
func (s *Server) FailValidation(typ string, on bool) error {
	if typ != HTTP01 && typ != DNS01 {
		return fmt.Errorf("fakeacme: unknown challenge type %q", typ)
	}
	s.mu.Lock()
	s.cfg.failValidation[typ] = on
	s.mu.Unlock()
	return nil
}

// RejectIdentifier makes newOrder refuse name and every name below it (rejectedIdentifier).
func (s *Server) RejectIdentifier(name string) {
	s.mu.Lock()
	s.cfg.rejected = append(s.cfg.rejected, asciiLower(strings.TrimPrefix(name, "*.")))
	s.mu.Unlock()
}

// ClearRejected removes every rejected identifier.
func (s *Server) ClearRejected() {
	s.mu.Lock()
	s.cfg.rejected = nil
	s.mu.Unlock()
}

// AdvertiseFields are the URLs Advertise can replace: the directory's (newNonce, newAccount,
// newOrder, keyChange, revokeCert, renewalInfo) and those inside answers (order is the order's
// Location, authz, finalize and certificate the URLs in an order).
var AdvertiseFields = []string{"newNonce", "newAccount", "newOrder", "keyChange", "revokeCert", "renewalInfo", "order", "authz", "finalize", "certificate",
	"termsOfService"}

// Advertise makes the fake hand out url for field (an http:// URL, 169.254.169.254, anything, to
// test that a client refuses it). An empty url restores the real one; "off" removes a directory
// field.
func (s *Server) Advertise(field, url string) error {
	if !contains(AdvertiseFields, field) {
		return fmt.Errorf("fakeacme: unknown field %q (known: %v)", field, AdvertiseFields)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch url {
	case "":
		delete(s.cfg.overrides, field)
	case "off":
		s.cfg.overrides[field] = ""
	default:
		s.cfg.overrides[field] = url
	}
	return nil
}

// SetChallenges sets the challenge types offered for non-wildcard names.
func (s *Server) SetChallenges(types ...string) error {
	if len(types) == 0 {
		return fmt.Errorf("fakeacme: at least one challenge type")
	}
	for _, t := range types {
		if t != HTTP01 && t != DNS01 {
			return fmt.Errorf("fakeacme: unknown challenge type %q", t)
		}
	}
	s.mu.Lock()
	s.cfg.challenges = append([]string(nil), types...)
	s.mu.Unlock()
	return nil
}

// SetProcessingPolls makes a finalized order answer "processing" to n polls before it is valid.
func (s *Server) SetProcessingPolls(n int) {
	s.mu.Lock()
	s.cfg.processingPolls = max(n, 0)
	s.mu.Unlock()
}

// SetClock runs the fake's clock from at (the zero time: the real one). It moves issued
// certificates, expiries and ARI windows, never the TLS certificate.
func (s *Server) SetClock(at time.Time) {
	if at.IsZero() {
		s.skew.Store(0)
		return
	}
	s.skew.Store(int64(at.Sub(s.opts.Now())))
}

// Now is the fake's time.
func (s *Server) Now() time.Time { return s.now() }
