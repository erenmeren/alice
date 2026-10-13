package fakeacme

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	validationTimeout = 5 * time.Second
	maxProbeBody      = 4096
)

func (s *Server) newHTTPClient() *http.Client {
	d := &net.Dialer{Timeout: validationTimeout}
	return &http.Client{
		Timeout: validationTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				s.mu.Lock()
				target, ok := s.st.targets[host]
				s.mu.Unlock()
				if !ok {
					// Only names the admin mapped are ever dialled: an order for any other name (an address,
					// a metadata host, a container) must not make the fake connect anywhere.
					return nil, errors.New("fakeacme: the name is not mapped to a target")
				}
				if _, _, err := net.SplitHostPort(target); err != nil {
					target = net.JoinHostPort(target, port)
				}
				s.count("http-01-dials")
				return d.DialContext(ctx, network, target)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func authzDoc(base string, az *authz) map[string]any {
	chs := make([]map[string]any, len(az.challenges))
	for i, c := range az.challenges {
		d := map[string]any{"type": c.typ, "url": base + "/acme/chall/" + az.id + "/" + strconv.Itoa(i), "token": c.token, "status": c.status}
		if c.problem != nil {
			d["error"] = c.problem.doc()
		}
		if !c.validated.IsZero() {
			d["validated"] = c.validated.UTC().Format(time.RFC3339)
		}
		chs[i] = d
	}
	doc := map[string]any{"status": az.status, "expires": az.expires.UTC().Format(time.RFC3339), "identifier": az.ident, "challenges": chs}
	if az.wildcard {
		doc["wildcard"] = true
	}
	return doc
}

// copyAuthz deep-copies an authorization so a document can be rendered without the lock.
func copyAuthz(az *authz) *authz {
	c := *az
	c.challenges = make([]*challenge, len(az.challenges))
	for i, ch := range az.challenges {
		x := *ch
		c.challenges[i] = &x
	}
	return &c
}

func (s *Server) ownedAuthz(w http.ResponseWriter, r *http.Request, req *jwsReq) (*authz, bool) {
	s.mu.Lock()
	az := s.st.authzs[r.PathValue("id")]
	if az == nil || az.account != req.acct.id {
		s.mu.Unlock()
		s.writeProblem(w, malformed(http.StatusNotFound, "no such authorization"))
		return nil, false
	}
	c := copyAuthz(az)
	s.mu.Unlock()
	return c, true
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request, req *jwsReq) {
	if !s.requireEmpty(w, req) {
		return
	}
	az, ok := s.ownedAuthz(w, r, req)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, authzDoc(s.BaseURL(), az))
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, req *jwsReq) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(req.payload, &body); err != nil || len(body) != 0 {
		s.writeProblem(w, malformed(http.StatusBadRequest, "a challenge request body must be {}"))
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	s.mu.Lock()
	az := s.st.authzs[r.PathValue("id")]
	if err != nil || az == nil || az.account != req.acct.id || n < 0 || n >= len(az.challenges) {
		s.mu.Unlock()
		s.writeProblem(w, malformed(http.StatusNotFound, "no such challenge"))
		return
	}
	ch := az.challenges[n]
	validate := az.status == "pending" && ch.status == "pending"
	stuck, fail := s.cfg.stuck, s.cfg.failValidation[ch.typ]
	typ, token, ident := ch.typ, ch.token, az.ident.Value
	thumb := req.acct.thumb
	if validate {
		ch.status = "processing"
	}
	s.mu.Unlock()

	if validate && !stuck {
		var prob *problem
		if fail {
			prob = newProblem(http.StatusForbidden, "unauthorized", "validation of "+ident+" is configured to fail in the fake")
		} else {
			prob = s.probe(r.Context(), typ, ident, token, thumb)
		}
		s.mu.Lock()
		if prob != nil {
			ch.status, ch.problem, az.status = "invalid", prob, "invalid"
		} else {
			ch.status, ch.validated, az.status = "valid", s.now(), "valid"
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	doc := authzDoc(s.baseLocked(), copyAuthz(az))["challenges"].([]map[string]any)[n]
	s.mu.Unlock()
	w.Header().Add("Link", "<"+s.BaseURL()+"/acme/authz/"+az.id+">;rel=\"up\"")
	writeJSON(w, http.StatusOK, doc)
}

// baseLocked is BaseURL for a caller that holds mu.
func (s *Server) baseLocked() string { return s.base }

// probe performs the real validation of one challenge.
func (s *Server) probe(ctx context.Context, typ, ident, token, thumb string) *problem {
	keyAuth := token + "." + thumb
	s.count("validations-" + typ)
	switch typ {
	case HTTP01:
		u := "http://" + ident + "/.well-known/acme-challenge/" + token
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return newProblem(http.StatusForbidden, "unauthorized", "bad probe URL")
		}
		resp, err := s.httpClient.Do(req) //nolint:gosec // G704: the fake's whole job is to fetch the name an order asks for
		if err != nil {
			return newProblem(http.StatusForbidden, "connection", "could not fetch "+u)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != keyAuth {
			return newProblem(http.StatusForbidden, "unauthorized", "the http-01 response for "+ident+" is not the key authorization")
		}
		return nil
	case DNS01:
		sum := sha256.Sum256([]byte(keyAuth))
		want := b64(sum[:])
		s.mu.Lock()
		values := append([]string(nil), s.st.dns["_acme-challenge."+ident]...)
		s.mu.Unlock()
		if !contains(values, want) {
			return newProblem(http.StatusForbidden, "unauthorized", "no TXT record at _acme-challenge."+ident+" has the expected value")
		}
		return nil
	}
	return newProblem(http.StatusForbidden, "unauthorized", "unknown challenge type")
}
