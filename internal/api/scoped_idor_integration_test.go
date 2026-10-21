//go:build integration

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/authz/services"
	"alice/internal/rbac"
	"alice/internal/testutil/seed"
)

// Scoped access, Phase 2 (R49, design §12 Phase 2, SR-11..SR-16): the IDOR suite generated from the route table. Every
// resource kind exists in service A; people hold roles on service B only. Every by-id route answers a resource of A
// exactly as an absent one (the route's 404 when the route's permission is held somewhere), every list leaves A's rows
// out, every create into A is refused (ALC-SVC-0006) and every platform route 403.

// scopedWorld is the fixture: one resource of every kind the resolvers know, in service A, and a few in B.
type scopedWorld struct {
	a, b, c uuid.UUID // services: A (the resources), B (the people's), C (the other side of A's trust)
	// byKind is the resource of each resolver kind in A (a uuid.UUID, or the fingerprint of a discovered certificate).
	byKind map[string]any
	// aIDs are every id and fingerprint of A's resources: a list that names one leaks A.
	aIDs []string
	// Resources in B.
	bServer, bCert, bLocation uuid.UUID
}

// sysActor makes the fixture's services, moves and trusts.
var sysActor = services.Actor{Audit: audit.SystemActor("test")}

// mustExec runs a statement as the owner.
func (s *stack) mustExec(sql string, args ...any) {
	s.t.Helper()
	_, err := s.db.Owner.Exec(context.Background(), sql, args...)
	require.NoError(s.t, err, sql)
}

func (s *stack) mustID(sql string, args ...any) uuid.UUID {
	s.t.Helper()
	var id uuid.UUID
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), sql, args...).Scan(&id), sql)
	return id
}

// seedScopedWorld builds the fixture: services A, B and C, every kind in A (moved there by the services store, as an
// Administrator's assignment does), and a server with a certificate in B.
func seedScopedWorld(t *testing.T, s *stack) scopedWorld {
	t.Helper()
	ctx := context.Background()
	svc := func(name string) uuid.UUID {
		sv, err := s.serviceStore.CreateService(ctx, sysActor, services.ServiceInput{Name: name})
		require.NoError(t, err)
		return sv.ID
	}
	w := scopedWorld{a: svc("Alpha"), b: svc("Bravo"), c: svc("Charlie"), byKind: map[string]any{}}
	now := s.clock.Now()

	server, err := seed.Target(ctx, s.db.Owner, "alpha-web", "nginx", "ok", nil)
	require.NoError(t, err)
	vault, err := seed.Target(ctx, s.db.Owner, "alpha-kv", "azure_key_vault", "ok", nil)
	require.NoError(t, err)
	cert, err := seed.Certificate(ctx, s.db.Owner, "alpha.example.test", now.Add(30*24*time.Hour), []uuid.UUID{server}, "alpha.example.test")
	require.NoError(t, err)
	loc := s.mustID("SELECT id FROM certificate_locations WHERE certificate_id = $1", cert)
	cert2, err := seed.Certificate(ctx, s.db.Owner, "alpha-acme.example.test", now.Add(30*24*time.Hour), []uuid.UUID{server})
	require.NoError(t, err)
	acmeLoc := s.mustID("SELECT id FROM certificate_locations WHERE certificate_id = $1", cert2)
	kvCert, _, err := seed.KeyVault(ctx, s.db.Owner, vault, "alpha", now.Add(30*24*time.Hour), &cert, "alpha-key", now.Add(30*24*time.Hour))
	require.NoError(t, err)
	binding := uuid.New()
	s.mustExec(`INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_at) VALUES ($1, $2, $3, now())`, binding, kvCert, vault)
	s.mustExec(`UPDATE certificate_locations SET binding_id = $2 WHERE id = $1`, loc, binding)
	dep, err := seed.Deployment(ctx, s.db.Owner, cert, server, "failed", "deployment.failed", now)
	require.NoError(t, err)

	pk, csr := uuid.New(), uuid.New()
	s.mustExec(`INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version,
    created_at) VALUES ($1, 'csr', 'ecdsa', 256, repeat('a', 64), '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, pk)
	s.mustExec(`INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, created_at)
VALUES ($1, $2, 'alpha-csr.example.test', 'pem', 'pending', now())`, csr, pk)

	keyPK, sshKey, sshLoc := uuid.New(), uuid.New(), uuid.New()
	s.mustExec(`INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce, wrapped_dek, key_version,
    created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('b', 64), '\x02', decode(repeat('01', 12), 'hex'), '\x02', 1, now())`, keyPK)
	s.mustExec(`INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, private_key_id, first_seen_at, created_at)
VALUES ($1, 'SHA256:' || repeat('Q', 43), 'ssh-ed25519', 'ssh-ed25519 QUxQSEE=', true, $2, now(), now())`, sshKey, keyPK)
	s.mustExec(`INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, 'root', '/root/.ssh/authorized_keys', 1, now(), now())`, sshLoc, sshKey, server)
	policy, run := uuid.New(), uuid.New()
	s.mustExec(`INSERT INTO rotation_policies (id, ssh_key_id, name, enabled, interval_days, created_at, updated_at)
VALUES ($1, $2, 'alpha-policy', false, 30, now(), now())`, policy, sshKey)
	s.mustExec(`INSERT INTO rotations (id, policy_id, old_ssh_key_id, trigger, status, plan, plan_digest, new_key_type, overlap_minutes, planned_for,
    notified_at, created_at, updated_at) VALUES ($1, $2, $3, 'manual', 'dry_run_notified', '{}', repeat('d', 64), 'ed25519', 0, now(), now(), now(), now())`,
		run, policy, sshKey)

	provider, account, acme := uuid.New(), uuid.New(), uuid.New()
	s.mustExec(`INSERT INTO acme_providers (id, name, directory_url, preset, created_at, updated_at)
VALUES ($1, 'Shared CA', 'https://ca.example.test/directory', 'custom', now(), now())`, provider)
	s.mustExec(`INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, key_ct, key_nonce, key_wrapped_dek, key_version, state,
    created_at, updated_at) VALUES ($1, $2, 'ops@example.test', 'https://ca.example.test/acct/1', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1,
    'active', now(), now())`, account, provider)
	s.mustExec(`INSERT INTO acme_certificates (id, provider_id, account_id, names, key_type, challenge, http_target_id, state, created_at, updated_at)
VALUES ($1, $2, $3, '{alpha-acme.example.test}', 'ecdsa_p256', 'http01', $4, 'active', now(), now())`, acme, provider, account, server)
	s.mustExec(`INSERT INTO acme_bindings (acme_certificate_id, location_id, auto_deploy, created_at) VALUES ($1, $2, false, now())`, acme, acmeLoc)

	scope, err := seed.DiscoveryScope(ctx, s.db.Owner, "Alpha LAN", false)
	require.NoError(t, err)
	scan := uuid.New()
	s.mustExec(`INSERT INTO discovery_scans (id, scope_id, trigger, state, queued_at, started_at, finished_at, endpoints_total, endpoints_answered)
VALUES ($1, $2, 'manual', 'done', now(), now(), now(), 1, 1)`, scan, scope)
	fp := strings.Repeat("ab", 32)
	require.NoError(t, seed.DiscoveredCertificate(ctx, s.db.Owner, fp, "alpha-found.example.test", now.Add(20*24*time.Hour)))
	_, err = seed.DiscoveredEndpoint(ctx, s.db.Owner, scope, "10.0.0.7", 443, "", fp, "present")
	require.NoError(t, err)

	incident := uuid.New()
	s.mustExec(`INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at, updated_at)
SELECT $1, id, public_key_sha256, 'awaiting_replacement', 'not_possible', now(), now() FROM certificates WHERE id = $2`, incident, cert)
	job := uuid.New()
	s.mustExec(`INSERT INTO jobs (id, type, class, kind, payload, payload_mac, status, run_at, max_attempts, created_at, target_id)
VALUES ($1, 'test.job', 'always', 'system', '{}', decode(repeat('07', 32), 'hex'), 'queued', now(), 3, now(), $2)`, job, server)

	_, err = s.serviceStore.Assign(ctx, sysActor, w.a, []services.Resource{
		{Type: services.KindTarget, ID: server}, {Type: services.KindTarget, ID: vault}, {Type: services.KindCertificate, ID: cert},
		{Type: services.KindCertificate, ID: cert2}, {Type: services.KindCSR, ID: csr}, {Type: services.KindSSHKey, ID: sshKey},
		{Type: services.KindACMECertificate, ID: acme}, {Type: services.KindDiscoveryScope, ID: scope},
	}, false)
	require.NoError(t, err)
	s.mustExec(`UPDATE jobs SET service_id = $2 WHERE id = $1`, job, w.a)
	s.mustExec(`UPDATE certificate_incidents SET service_ids = ARRAY[$2::uuid] WHERE id = $1`, incident, w.a)
	trust, err := s.serviceStore.CreateTrust(ctx, sysActor, w.a, w.c)
	require.NoError(t, err)

	w.byKind = map[string]any{
		services.KindTarget: server, services.KindCertificate: cert, services.KindCSR: csr, services.KindSSHKey: sshKey,
		services.KindACMECertificate: acme, services.KindDiscoveryScope: scope, services.KindLocation: loc,
		services.KindACMEBindingPlace: acmeLoc, services.KindSSHKeyLocation: sshLoc, services.KindDiscoveryScan: scan,
		services.KindDiscoveredCert: fp, services.KindDeployment: dep, services.KindKVBinding: binding, services.KindIncident: incident,
		services.KindJob: job, services.KindRotationPolicy: policy, services.KindRotationRun: run, services.KindService: w.a,
		services.KindServiceTrust: trust.ID, services.KindIncidentReach: cert, services.KindRotationReach: policy,
		services.KindKVCertificate: kvCert,
	}
	for _, v := range []any{server, vault, cert, cert2, loc, acmeLoc, kvCert, binding, dep, csr, sshKey, sshLoc, policy, run, acme, scope, scan,
		incident, job, trust.ID, w.a, fp} {
		w.aIDs = append(w.aIDs, fmt.Sprint(v))
	}
	w.aIDs = append(w.aIDs, "alpha-web", "alpha-kv", "alpha.example.test", "alpha-acme.example.test", "alpha-csr.example.test", "Alpha")

	w.bServer, err = seed.Target(ctx, s.db.Owner, "bravo-web", "nginx", "ok", nil)
	require.NoError(t, err)
	w.bCert, err = seed.Certificate(ctx, s.db.Owner, "bravo.example.test", now.Add(30*24*time.Hour), []uuid.UUID{w.bServer})
	require.NoError(t, err)
	w.bLocation = s.mustID("SELECT id FROM certificate_locations WHERE certificate_id = $1", w.bCert)
	_, err = s.serviceStore.Assign(ctx, sysActor, w.b, []services.Resource{{Type: services.KindTarget, ID: w.bServer},
		{Type: services.KindCertificate, ID: w.bCert}}, false)
	require.NoError(t, err)
	return w
}

// scopedIdentity is a person (or a token) whose only right is a role binding on service B.
type scopedIdentity struct {
	name    string
	c       *client
	acct    *account
	subject rbac.Subject // what the guard sees (the step-up window open for the people)
}

// createScopedPerson adds a person without a global role, binds role on service, and signs them in.
func (s *stack) createScopedPerson(admin *client, adminAcct *account, username, role string, service uuid.UUID) *account {
	t := s.t
	t.Helper()
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/users", map[string]any{"username": username, "display_name": "User " + username, "email": "",
		"role": nil, "password": "correct horse battery staple " + username})
	requireStatus(t, rec, http.StatusCreated)
	u := decodeBody[map[string]any](t, rec)
	assert.Nil(t, u["role"], "a person without a global role")
	a := &account{id: u["id"].(string), username: username, password: "correct horse battery staple " + username}
	rec = admin.do(http.MethodPost, "/api/v1/role-bindings", map[string]any{"user_id": a.id, "role": role, "service_id": service})
	requireStatus(t, rec, http.StatusCreated)
	return a
}

// fillPath puts the resources of the fixture into a route's pattern: the resolver's parameter, then the others (an
// ACME binding's website, random ids for children the handler checks itself). absent fills random ids everywhere.
func fillPath(rt route, w scopedWorld, absent bool) string {
	param := regexp.MustCompile(`\{([a-z_]+)\}`)
	return param.ReplaceAllStringFunc(rt.pattern, func(m string) string {
		name := m[1 : len(m)-1]
		if absent {
			if rt.resolve != nil && rt.resolve.kind == services.KindDiscoveredCert {
				b := make([]byte, 32)
				_, _ = rand.Read(b)
				return hex.EncodeToString(b)
			}
			return uuid.NewString()
		}
		switch {
		case rt.resolve != nil && name == rt.resolve.param:
			return fmt.Sprint(w.byKind[rt.resolve.kind])
		case rt.resolve != nil && rt.resolve.either != nil && name == rt.resolve.either.param:
			return fmt.Sprint(w.byKind[rt.resolve.either.kind])
		default:
			return uuid.NewString()
		}
	})
}

type answer struct {
	status int
	code   string
}

func answerOf(rec *httptest.ResponseRecorder) answer {
	var e apiError
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	return answer{rec.Code, e.Error.Code}
}

// createBodies are minimal create bodies naming service A, one per create route: the service is checked first.
func createBodies(w scopedWorld) map[string]map[string]any {
	return map[string]map[string]any{
		"POST /api/v1/targets":             {"name": "x", "type": "nginx", "host": "10.0.0.9", "port": 22, "username": "alice-svc", "service_id": w.a},
		"POST /api/v1/key-vaults":          {"service_id": w.a},
		"POST /api/v1/certificates/upload": {"service_id": w.a},
		"POST /api/v1/certificates/csr":    {"common_name": "x.example.test", "key_type": "ecdsa-p256", "service_id": w.a},
		"POST /api/v1/ssh-keys/generate":   {"label": "x", "key_type": "ed25519", "service_id": w.a},
		"POST /api/v1/acme/certificates":   {"service_id": w.a},
		"POST /api/v1/rotation/policies":   {"ssh_key_id": w.byKind[services.KindSSHKey], "name": "x", "interval_days": 30},
	}
}

func TestScopedIDOR(t *testing.T) {
	s := newStack(t)
	adminAcct := &account{username: "ada", password: "correct horse battery staple"}
	admin := s.setupAdmin(adminAcct, "a long enough recovery passphrase", nil)
	w := seedScopedWorld(t, s)

	var ids []scopedIdentity
	for _, p := range []struct{ name, role string }{{"opb", "operator"}, {"audb", "auditor"}, {"admb", "admin"}} {
		acct := s.createScopedPerson(admin, adminAcct, p.name, p.role, w.b)
		c := s.freshClient()
		s.firstSignIn(c, acct)
		role, _ := rbac.ParseRole(p.role)
		ids = append(ids, scopedIdentity{name: p.role + "@B", c: c, acct: acct,
			subject: rbac.Subject{Kind: rbac.UserSession, StepUp: true, Grants: []rbac.ScopedGrant{{Role: role, Services: []uuid.UUID{w.b}}}}})
	}
	// An operate token of operator@B.
	s.stepUp(ids[0].c, ids[0].acct)
	rec := ids[0].c.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "ci", "scope": "operate", "expires_in_days": 30})
	requireStatus(t, rec, http.StatusCreated)
	tok := s.freshClient()
	tok.bearer = decodeBody[map[string]any](t, rec)["token"].(string)
	ids = append(ids, scopedIdentity{name: "operate token of operator@B", c: tok,
		subject: rbac.Subject{Kind: rbac.APIToken, Scope: rbac.ScopeOperate, Grants: ids[0].subject.Grants}})

	routes := s.api.s.apiRoutes()
	kinds := map[string]bool{}
	for _, k := range services.ResolveKinds() {
		kinds[k] = true
	}
	for _, rt := range routes {
		if rt.resolve != nil {
			require.True(t, kinds[rt.resolve.kind], "%s %s resolves an unknown kind %q", rt.method, rt.pattern, rt.resolve.kind)
			_, planted := w.byKind[rt.resolve.kind]
			require.True(t, planted, "%s %s: the suite plants no resource of kind %q", rt.method, rt.pattern, rt.resolve.kind)
		}
		if rt.scope == scopeResource {
			require.NotNil(t, rt.resolve, "%s %s is a resource route without a resolver", rt.method, rt.pattern)
		}
	}
	creates := createBodies(w)

	for _, id := range ids {
		if id.acct != nil {
			s.stepUp(id.c, id.acct)
		}
		// Every answer to a person of B, refusals and errors included, names nothing of A (the leak-style check of design
		// §12 Phase 2: no foreign object's id or name in any error text).
		do := func(method, path string, body any) *httptest.ResponseRecorder {
			rec := id.c.do(method, path, body)
			for _, a := range w.aIDs {
				if strings.Contains(path, a) {
					continue // the caller named it: an echo is not a leak (no answer echoes a path today)
				}
				assert.NotContains(t, rec.Body.String(), a, "%s %s as %s names a resource of A", method, path, id.name)
			}
			return rec
		}
		for _, rt := range routes {
			key := rt.method + " " + rt.pattern
			if rt.scope == scopeNone || rt.scope == scopeSelf || rt.pattern == "/livez" || rt.pattern == "/healthz" {
				continue
			}
			s.api.ResetLimits() // per-person limits (the download's 5 a minute, the general 300) never answer for the guard
			name := fmt.Sprintf("%s as %s", key, id.name)
			allowed := rbac.DecideAnywhere(rt.perm, id.subject) == rbac.Allow
			switch rt.scope {
			case scopePlatform:
				got := answerOf(do(rt.method, fillPath(rt, w, true), map[string]any{}))
				assert.Equal(t, answer{http.StatusForbidden, ErrForbidden.Code}, got, name)
			case scopeResource, scopeCross:
				if rt.resolve == nil {
					continue // a cross route without a path resource (POST /bindings, POST /service-trusts): checked below
				}
				inA := answerOf(do(rt.method, fillPath(rt, w, false), map[string]any{}))
				absent := answerOf(do(rt.method, fillPath(rt, w, true), map[string]any{}))
				assert.Equal(t, absent, inA, "%s: a resource of A answers as an absent one (no existence oracle)", name)
				if allowed {
					assert.Equal(t, answer{http.StatusNotFound, notFoundOf(rt.resolve.kind).Code}, inA, name)
				} else {
					assert.Equal(t, http.StatusForbidden, inA.status, name)
				}
			case scopeList, scopeAny:
				if rt.method != http.MethodGet || strings.Contains(rt.pattern, "{") {
					continue // a platform object by id (an ACME provider or hook): readable by every holder, no service
				}
				rec := do(rt.method, rt.pattern, nil)
				if !allowed {
					assert.Equal(t, http.StatusForbidden, rec.Code, name)
					continue
				}
				if !assert.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, rec.Code, "%s: %s", name, rec.Body.String()) {
					continue
				}
				body := rec.Body.String()
				for _, a := range w.aIDs {
					assert.NotContains(t, body, a, "%s leaks a row of A", name)
				}
			case scopeCreate:
				body, ok := creates[key]
				require.True(t, ok, "%s: the suite has no body for this create route", key)
				got := answerOf(do(rt.method, rt.pattern, body))
				switch {
				case !allowed:
					assert.Equal(t, http.StatusForbidden, got.status, name)
				case key == "POST /api/v1/rotation/policies":
					assert.Equal(t, answer{http.StatusNotFound, ErrNotFound.Code}, got, "%s: a key of A is unknown to B", name)
				default:
					assert.Equal(t, answer{http.StatusForbidden, ErrSVCNotAllowed.Code}, got, name)
				}
			}
		}
		// The cross routes without a path resource name A's resources in the body.
		if rbac.DecideAnywhere(rbac.CertificatesOperate, id.subject) == rbac.Allow {
			got := answerOf(do(http.MethodPost, "/api/v1/bindings", map[string]any{
				"kv_certificate_id": w.byKind[services.KindKVCertificate], "location_ids": []string{w.bLocation.String()}}))
			assert.Equal(t, answer{http.StatusNotFound, ErrNotFound.Code}, got, "POST /bindings from a vault of A as %s", id.name)
			got = answerOf(do(http.MethodPost, fmt.Sprintf("/api/v1/certificates/%s/deploy", w.bCert), map[string]any{
				"location_ids": []string{fmt.Sprint(w.byKind[services.KindLocation])}}))
			assert.Equal(t, answer{http.StatusForbidden, ErrSVCSpansServices.Code}, got, "deploying B's certificate to A's website as %s", id.name)
		}
		if rbac.DecideAnywhere(rbac.ServicesTrust, id.subject) == rbac.Allow {
			got := answerOf(do(http.MethodPost, "/api/v1/service-trusts", map[string]any{"source_service_id": w.a, "target_service_id": w.b}))
			assert.Equal(t, answer{http.StatusForbidden, ErrSVCSpansServices.Code}, got, "a trust with A as %s", id.name)
		}
	}
}

// The same people on their own service: what their role allows works (design §12 Phase 2, second acceptance line).
func TestScopedPeopleWorkInTheirService(t *testing.T) {
	s := newStack(t)
	adminAcct := &account{username: "ada", password: "correct horse battery staple"}
	admin := s.setupAdmin(adminAcct, "a long enough recovery passphrase", nil)
	w := seedScopedWorld(t, s)
	acct := s.createScopedPerson(admin, adminAcct, "opb", "operator", w.b)
	c := s.freshClient()
	s.firstSignIn(c, acct)

	rec := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireStatus(t, rec, http.StatusOK)
	sess := decodeBody[map[string]any](t, rec)
	access := sess["access"].(map[string]any)
	assert.Nil(t, access["global_role"])
	svcs := access["services"].([]any)
	require.Len(t, svcs, 1)
	assert.Equal(t, "Bravo", svcs[0].(map[string]any)["name"])
	assert.Contains(t, access["permissions_anywhere"], "certificates.operate")
	assert.NotContains(t, access["platform_permissions"], "users.read")

	rec = c.do(http.MethodGet, "/api/v1/targets", nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec)
	require.Len(t, list.Items, 1, "B's server only")
	assert.Equal(t, w.bServer.String(), list.Items[0]["id"])
	assert.Contains(t, list.Items[0]["allowed_actions"], "certificates.operate")
	assert.NotContains(t, list.Items[0]["allowed_actions"], "targets.manage", "an Operator manages no servers")

	requireStatus(t, c.do(http.MethodGet, "/api/v1/targets/"+w.bServer.String(), nil), http.StatusOK)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/certificates/"+w.bCert.String(), nil), http.StatusOK)
	requireError(t, c.do(http.MethodPatch, "/api/v1/targets/"+w.bServer.String(), map[string]any{"name": "x"}, func(r *http.Request) {
		r.Header.Set("If-Match", `"1"`)
	}), http.StatusForbidden, ErrForbidden.Code)

	// A create without a service lands in the only service the Operator may create in.
	rec = c.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "bravo-csr.example.test", "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	assert.Equal(t, w.b.String(), decodeBody[map[string]any](t, rec)["service"].(map[string]any)["id"])

	// The dashboard counts B only: one server.
	rec = c.do(http.MethodGet, "/api/v1/dashboard/summary", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.EqualValues(t, 1, decodeBody[map[string]any](t, rec)["targets"].(map[string]any)["total"])

	// The global Administrator still sees everything.
	rec = admin.do(http.MethodGet, "/api/v1/targets", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Len(t, decodeBody[struct {
		Items []map[string]any `json:"items"`
	}](t, rec).Items, 3)
}
