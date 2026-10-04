package fakekv

import (
	"time"
)

// Role names of the Azure RBAC built-in roles Alice's guidance names (Key Vault data plane).
const (
	RoleReader              = "Key Vault Reader"
	RoleSecretsUser         = "Key Vault Secrets User"
	RoleCertificatesOfficer = "Key Vault Certificates Officer"
)

var allActions = []string{"certificates/list", "certificates/get", "certificates/import", "keys/list", "keys/get", "secrets/list", "secrets/get"}

// roleActions maps a built-in role to the fake actions its data actions cover. In Azure the list and the
// get of a type share ONE data action (certificates/read, keys/read), so a preset grants them together;
// per-action RevokeRole can build the impossible state "list without get" and should be used only
// where a test means to. GUESS (from memory of the built-in role definitions, not verified): Reader =
// read of certificates and keys plus secret metadata, no secret values; Secrets User = secret values and
// metadata only; Certificates Officer = every certificate action (list, get, import), no secrets or keys.
var roleActions = map[string][]string{
	RoleReader:              {"certificates/list", "certificates/get", "keys/list", "keys/get", "secrets/list"},
	RoleSecretsUser:         {"secrets/list", "secrets/get"},
	RoleCertificatesOfficer: {"certificates/list", "certificates/get", "certificates/import"},
}

// SetRoles makes the caller hold exactly the given built-in roles (RoleReader, RoleSecretsUser,
// RoleCertificatesOfficer): every action they do not cover is revoked. It panics on an unknown role.
// SetRoles() with no role revokes everything; GrantAllRoles undoes it.
func (s *Server) SetRoles(roles ...string) {
	granted := map[string]bool{}
	for _, r := range roles {
		acts, ok := roleActions[r]
		if !ok {
			panic("fakekv: unknown role " + r)
		}
		for _, a := range acts {
			granted[a] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = map[string]bool{}
	for _, a := range allActions {
		if !granted[a] {
			s.revoked[a] = true
		}
	}
}

// GrantAllRoles restores every action.
func (s *Server) GrantAllRoles() { s.mu.Lock(); s.revoked = map[string]bool{}; s.mu.Unlock() }

// SetPageFill caps the items of every listing page at n (1..25; 0 = full pages). Azure promises "up to"
// 25 items per page (GUESS: whether it answers short pages while more remain).
func (s *Server) SetPageFill(n int) { s.mu.Lock(); s.pageFill = n; s.mu.Unlock() }

// SetEmptyPages makes every listing answer an EMPTY page that still carries a nextLink before each real
// page (GUESS: a client must follow nextLink, not stop at an empty page).
func (s *Server) SetEmptyPages(on bool) { s.mu.Lock(); s.emptyPages = on; s.mu.Unlock() }

// Reset returns the fake to a clean state and returns the NEW client secret (cmd/alice-fakeazure's
// "ctl reset"). It keeps the CA, the listeners, and the tenant, client and vault IDs; it clears the vault
// state (certificates, keys, secrets), issued tokens, faults, holds (released), latency, roles, firewall,
// challenge override, expired-secret flag, paging knobs, token claims and the request log, and issues a new
// client secret (the old one and every old token are refused). Registered certificates stay.
func (s *Server) Reset() (clientSecret string) {
	secret := NewClientSecret()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.holds {
		h.releaseLocked()
	}
	s.holds, s.faults = nil, nil
	s.certs, s.keys, s.secrets = map[string]*certEntry{}, map[string]*keyEntry{}, map[string]*secretEntry{}
	s.tokens, s.lastToken, s.testToken = map[string]issuedToken{}, "", ""
	s.oid, s.tid = s.origOID, s.o.TenantID
	s.tokenLife = s.o.TokenLifetime
	s.expiredSec, s.revoked, s.firewall, s.challenge = false, map[string]bool{}, "", ""
	s.latency, s.pageFill, s.emptyPages = 0*time.Second, 0, false
	s.log = nil
	s.secret = secret
	return secret
}
