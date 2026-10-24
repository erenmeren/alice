// Package fakerevocation is a test helper: an OCSP responder and a CRL server of a test CA (pki.CA), with the faults the
// revocation check must survive (R64, D5). It imports the test PKI and the clock and nothing else of Alice, so it cannot
// drift towards the checker it tests. Production code never imports it.
package fakerevocation

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

// Fault is what one path of the server does instead of a correct answer.
type Fault int

// The faults. Each applies to the path it is set on ("/ocsp" or "/crl").
const (
	FaultNone        Fault = iota
	FaultDown              // 500
	FaultGarbage           // a 200 answer that is not DER
	FaultWrongSigner       // signed by another CA's key (the issuer's name kept on a CRL)
	FaultStale             // an answer whose next update is an hour ago
	FaultHuge              // a 200 answer of 11 MiB
	FaultRedirect          // 302 to /target on the same server
	FaultUnknown           // OCSP: the responder does not know the certificate
	FaultOtherIssuer       // CRL: signed by the issuer's key under another issuer name
)

// HugeSize is the size of a FaultHuge answer: over both caps of the checker (64 KiB and 10 MiB).
const HugeSize = 11 << 20

type entry struct {
	reason int
	at     time.Time
}

// Server is the fake responder and CRL server of one CA.
type Server struct {
	ca    *pki.CA
	clk   clock.Clock
	other *pki.CA

	mu       sync.Mutex
	revoked  map[string]entry // by serial (decimal)
	serials  map[string]*big.Int
	faults   map[string]Fault
	requests map[string]int
	crlPEM   bool
}

// New is a server of ca at the time clk tells.
func New(ca *pki.CA, clk clock.Clock) *Server {
	return &Server{ca: ca, clk: clk, other: pki.NewCA("Fake Revocation Other", pki.ECDSA256, clk.Now()),
		revoked: map[string]entry{}, serials: map[string]*big.Int{}, faults: map[string]Fault{}, requests: map[string]int{}}
}

// Revoke lists serial as revoked with an RFC 5280 reason code at.
func (s *Server) Revoke(serial *big.Int, reason int, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[serial.String()] = entry{reason: reason, at: at}
	s.serials[serial.String()] = serial
}

// Hold suspends serial (certificateHold, reason 6).
func (s *Server) Hold(serial *big.Int, at time.Time) { s.Revoke(serial, 6, at) }

// Release lifts a suspension (or a revocation) of serial.
func (s *Server) Release(serial *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.revoked, serial.String())
	delete(s.serials, serial.String())
}

// SetFault sets what path does ("/ocsp" or "/crl"); FaultNone answers correctly again.
func (s *Server) SetFault(path string, f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[path] = f
}

// SetCRLPEM makes the CRL answer one PEM block labelled X509 CRL instead of DER.
func (s *Server) SetCRLPEM(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crlPEM = on
}

// Requests counts the requests path received ("/ocsp", "/crl" or "/target").
func (s *Server) Requests(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[path]
}

// Start serves on 127.0.0.1:0 until the test ends and returns host:port.
func (s *Server) Start(t testing.TB) string {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// ServeHTTP answers /ocsp (POST), /crl (GET) and /target (the redirect's target).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests[r.URL.Path]++
	fault := s.faults[r.URL.Path]
	s.mu.Unlock()
	switch fault {
	case FaultDown:
		http.Error(w, "down", http.StatusInternalServerError)
		return
	case FaultGarbage:
		_, _ = w.Write([]byte("garbage, not DER"))
		return
	case FaultHuge:
		_, _ = io.Copy(w, io.LimitReader(zeros{}, HugeSize))
		return
	case FaultRedirect:
		http.Redirect(w, r, "/target", http.StatusFound)
		return
	}
	switch r.URL.Path {
	case "/ocsp":
		s.serveOCSP(w, r, fault)
	case "/crl":
		s.serveCRL(w, fault)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveOCSP(w http.ResponseWriter, r *http.Request, fault Fault) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, "request", http.StatusBadRequest)
		return
	}
	now := s.clk.Now()
	tmpl := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	s.mu.Lock()
	if e, ok := s.revoked[req.SerialNumber.String()]; ok {
		tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, e.at, e.reason
	}
	s.mu.Unlock()
	signer, key := s.ca.Intermediate, s.ca.IntermediateKey
	switch fault {
	case FaultUnknown:
		tmpl.Status = ocsp.Unknown
	case FaultStale:
		tmpl.ThisUpdate, tmpl.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour)
	case FaultWrongSigner:
		signer, key = s.other.Intermediate, s.other.IntermediateKey
	}
	der, err := ocsp.CreateResponse(s.ca.Intermediate, signer, tmpl, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}

func (s *Server) serveCRL(w http.ResponseWriter, fault Fault) {
	now := s.clk.Now()
	list := &x509.RevocationList{Number: big.NewInt(now.Unix()), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	s.mu.Lock()
	for k, e := range s.revoked {
		list.RevokedCertificateEntries = append(list.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s.serials[k],
			RevocationTime: e.at, ReasonCode: e.reason})
	}
	asPEM := s.crlPEM
	s.mu.Unlock()
	issuer, key := s.ca.Intermediate, s.ca.IntermediateKey
	switch fault {
	case FaultStale:
		list.ThisUpdate, list.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour)
	case FaultWrongSigner:
		// The issuer's name, another key: the signature does not verify against the issuer.
		issuer = &x509.Certificate{Subject: s.ca.Intermediate.Subject, RawSubject: s.ca.Intermediate.RawSubject, KeyUsage: x509.KeyUsageCRLSign,
			SubjectKeyId: s.ca.Intermediate.SubjectKeyId}
		key = s.other.IntermediateKey
	case FaultOtherIssuer:
		// The issuer's key, another name: the signature verifies, the issuer does not match the certificate's.
		issuer = &x509.Certificate{Subject: pkix.Name{CommonName: "Another Issuer"}, KeyUsage: x509.KeyUsageCRLSign,
			SubjectKeyId: s.ca.Intermediate.SubjectKeyId}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, issuer, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if asPEM {
		der = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = io.Copy(w, bytes.NewReader(der))
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
