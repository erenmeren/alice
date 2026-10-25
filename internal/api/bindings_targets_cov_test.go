package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/authz/services"
	"alice/internal/inventory"
	"alice/internal/rbac"
)

var (
	errCovB         = errors.New("covb: the services module failed")
	covBOtherTarget = uuid.MustParse("0192d000-0000-7000-8000-0000000000c1") // a server of svcDefault
	covBLocationC   = uuid.MustParse("0192d000-0000-7000-8000-0000000000c2") // a website on covBOtherTarget
)

// covBServices is fakeServices whose TargetServices fails when targetsErr is set.
type covBServices struct {
	*fakeServices
	targetsErr error
}

func (f *covBServices) TargetServices(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	if f.targetsErr != nil {
		return nil, f.targetsErr
	}
	return f.fakeServices.TargetServices(ctx, ids)
}

// covBScoped is the binding handlers with a person ("covb-scoped") who has no global role and role on svcPay only,
// with a fresh step-up. targetID is a server of svcPay, covBOtherTarget one of svcDefault.
func covBScoped(t *testing.T, role rbac.Role) (http.Handler, *fakeInventory, *covBServices) {
	t.Helper()
	d, inv := inventoryDeps(t)
	svc := &covBServices{fakeServices: &fakeServices{targetServices: map[uuid.UUID]uuid.UUID{targetID: svcPay, covBOtherTarget: svcDefault}}}
	d.Services = svc
	fa := d.Auth.(*fakeAuth)
	prev := fa.AuthenticateFn
	fa.AuthenticateFn = func(ctx context.Context, tok string) (auth.Principal, error) {
		if tok == "covb-scoped" {
			return auth.Principal{Kind: rbac.UserSession, UserID: operatorID, Username: "scoped", DisplayName: "scoped", Role: auth.NoGlobalRole,
				Locale: "en", SessionHash: []byte("covb-scoped"), StepUpUntil: testNow.Add(5 * time.Minute),
				Grants: []rbac.ScopedGrant{{Role: role, Services: []uuid.UUID{svcPay}}}}, nil
		}
		return prev(ctx, tok)
	}
	return NewHandler(d), inv, svc
}

// covBResolve answers the binding as a resource of svcPay, the vault certificate as owned by kvOwner (visible from
// kvVisible), locationA/B as websites of svcPay and covBLocationC as one of svcDefault.
func covBResolve(kvOwner uuid.UUID, kvVisible []uuid.UUID, kvErr error) func(kind string, id any) (services.Resolution, error) {
	return func(kind string, id any) (services.Resolution, error) {
		switch kind {
		case services.KindKVBinding:
			return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil
		case services.KindKVCertificate:
			if kvErr != nil {
				return services.Resolution{}, kvErr
			}
			return services.Resolution{Owning: kvOwner, Visible: kvVisible}, nil
		case services.KindLocation:
			if id == covBLocationC {
				return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
			}
			return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil
		}
		return services.Resolution{}, services.ErrResourceNotFound
	}
}

// covBBinding is sampleBinding with a second website, on a server of another service the caller does not see.
func covBBinding(auto bool) inventory.Binding {
	b := sampleBinding(auto)
	b.Locations = append(b.Locations, inventory.BindingLocation{LocationID: covBLocationC, TargetID: covBOtherTarget, TargetName: "hidden-01",
		CertPath: "/etc/ssl/c.pem", State: inventory.BindingLocationDeployed})
	return b
}

// Design §5.6 (a): a person with a role on some services binds a vault certificate only with certificates.operate on
// the vault's service; a certificate it cannot see is 404, one it sees but may not bind 403, an unknown one is left to
// the inventory, and a failed look-up is an error. Websites outside its services are refused before the inventory.
func TestCovBCreateBindingChecksTheVaultsService(t *testing.T) {
	h, inv, svc := covBScoped(t, rbac.Operator)
	var calls int
	inv.CreateBindingFn = func(context.Context, inventory.Actor, inventory.BindingInput) (inventory.Binding, error) {
		calls++
		return sampleBinding(false), nil
	}
	body := func(locs ...uuid.UUID) string {
		ids := make([]string, len(locs))
		for i, l := range locs {
			ids[i] = `"` + l.String() + `"`
		}
		return `{"kv_certificate_id":"` + kvCertID.String() + `","location_ids":[` + strings.Join(ids, ",") + `]}`
	}
	for _, tc := range []struct {
		name    string
		owner   uuid.UUID
		visible []uuid.UUID
		err     error
		body    string
		code    int
		errCode string
	}{
		{"the vault's service is the caller's", svcPay, []uuid.UUID{svcPay}, nil, body(locationA), http.StatusCreated, ""},
		{"an unknown certificate is the inventory's to answer", uuid.Nil, nil, services.ErrResourceNotFound, body(locationA), http.StatusCreated, ""},
		{"a certificate out of sight is unknown", svcDefault, []uuid.UUID{svcDefault}, nil, body(locationA), http.StatusNotFound, ErrNotFound.Code},
		{"a certificate seen but not the caller's to bind", svcDefault, []uuid.UUID{svcDefault, svcPay}, nil, body(locationA), http.StatusForbidden,
			ErrForbidden.Code},
		{"a failed look-up", uuid.Nil, nil, errCovB, body(locationA), http.StatusInternalServerError, ErrUnexpected.Code},
		{"a website of another service", svcPay, []uuid.UUID{svcPay}, nil, body(locationA, covBLocationC), ErrSVCSpansServices.Status,
			ErrSVCSpansServices.Code},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls = 0
			svc.ResolveFn = covBResolve(tc.owner, tc.visible, tc.err)
			rec := call(h, http.MethodPost, "/api/v1/bindings", "covb-scoped", tc.body)
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			if tc.errCode != "" {
				assert.Equal(t, tc.errCode, decodeErr(t, rec).Error.Code)
				assert.Zero(t, calls, "nothing reached the inventory")
				return
			}
			assert.Equal(t, 1, calls)
		})
	}
}

// A binding answers only the websites on servers the caller sees and counts the others (hidden_count); when the
// servers' services cannot be read the answer is an error, never the whole list.
func TestCovBBindingAnswerHidesWebsitesOfOtherServices(t *testing.T) {
	h, inv, svc := covBScoped(t, rbac.Operator)
	svc.ResolveFn = covBResolve(svcPay, []uuid.UUID{svcPay}, nil)
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return covBBinding(false), nil }
	path := "/api/v1/bindings/" + bindingA.String()

	rec := call(h, http.MethodGet, path, "covb-scoped", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	b := jsonObj(t, rec)
	assert.InDelta(t, 1, b["hidden_count"], 0)
	locs := b["locations"].([]any)
	require.Len(t, locs, 1)
	assert.Equal(t, locationA.String(), locs[0].(map[string]any)["location_id"])

	svc.targetsErr = errCovB
	rec = call(h, http.MethodGet, path, "covb-scoped", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, ErrUnexpected.Code, decodeErr(t, rec).Error.Code)
	assert.NotContains(t, rec.Body.String(), "hidden-01")
}

// Design §5.6 for a change of a binding's websites by a person with certificates.operate on the vault's service: the
// websites it does not see stay as they are whatever the list names, an added website needs the permission on its own
// service, and a failed read of the servers' services is an error.
func TestCovBPatchBindingKeepsUnseenWebsites(t *testing.T) {
	h, inv, svc := covBScoped(t, rbac.Operator)
	svc.ResolveFn = covBResolve(svcPay, []uuid.UUID{svcPay}, nil)
	path := "/api/v1/bindings/" + bindingA.String()
	hdr := map[string]string{"If-Match": `"4"`}
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return covBBinding(false), nil }
	var got [][]uuid.UUID
	inv.UpdateBindingLocationsStrictFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, l []uuid.UUID, _ bool) (inventory.Binding, error) {
		assert.Equal(t, 4, v)
		got = append(got, l)
		return covBBinding(false), nil
	}

	// Releasing locationA only: the hidden website covBLocationC is kept.
	rec := callWith(h, http.MethodPatch, path, "covb-scoped", `{"location_ids":["`+locationB.String()+`"]}`, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, got, 1)
	assert.Equal(t, []uuid.UUID{locationB, covBLocationC}, got[0], "the website of another service stays, locationB is added")

	// The list names the hidden website itself: it is not added twice.
	rec = callWith(h, http.MethodPatch, path, "covb-scoped", `{"location_ids":["`+locationA.String()+`","`+covBLocationC.String()+`"]}`, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []uuid.UUID{locationA, covBLocationC}, got[1])

	// Adding a website of svcDefault, where the caller holds nothing, is refused before the inventory.
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return sampleBinding(false), nil }
	rec = callWith(h, http.MethodPatch, path, "covb-scoped", `{"location_ids":["`+locationA.String()+`","`+covBLocationC.String()+`"]}`, hdr)
	assert.Equal(t, ErrSVCSpansServices.Code, decodeErr(t, rec).Error.Code)
	assert.Len(t, got, 2, "nothing reached the inventory")

	svc.targetsErr = errCovB
	rec = callWith(h, http.MethodPatch, path, "covb-scoped", `{"location_ids":["`+locationA.String()+`"]}`, hdr)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Len(t, got, 2)
}

// Design §11: switching automatic deployment on, for a person with a role on some services, also needs
// certificates.operate on the service of every website it will deploy to; switching it off does not look.
func TestCovBSetAutoDeployOnChecksEveryWebsite(t *testing.T) {
	h, inv, svc := covBScoped(t, rbac.Admin)
	svc.ResolveFn = covBResolve(svcPay, []uuid.UUID{svcPay}, nil)
	path := "/api/v1/bindings/" + bindingA.String() + "/auto-deploy"
	hdr := map[string]string{"If-Match": `"4"`}
	var set []bool
	inv.SetAutoDeployFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, _ int, enabled bool) (inventory.Binding, error) {
		set = append(set, enabled)
		return sampleBinding(enabled), nil
	}
	reads := 0
	current := sampleBinding(false)
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) {
		reads++
		return current, nil
	}

	rec := callWith(h, http.MethodPut, path, "covb-scoped", `{"enabled":true}`, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []bool{true}, set)
	assert.Equal(t, 1, reads, "the binding's websites were read")

	current = covBBinding(false) // a website on a server of svcDefault
	rec = callWith(h, http.MethodPut, path, "covb-scoped", `{"enabled":true}`, hdr)
	assert.Equal(t, ErrSVCSpansServices.Code, decodeErr(t, rec).Error.Code)
	assert.Equal(t, []bool{true}, set, "nothing was switched")

	rec = callWith(h, http.MethodPut, path, "covb-scoped", `{"enabled":false}`, hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 2, reads, "switching off reads no website")

	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) {
		return inventory.Binding{}, inventory.ErrNotFound
	}
	rec = callWith(h, http.MethodPut, path, "covb-scoped", `{"enabled":true}`, hdr)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, []bool{true, false}, set)
}

func TestCovBListDeployableLocationsRefusesALongCursor(t *testing.T) {
	h, inv, _ := vaultDeps(t)
	calls := 0
	inv.ListDeployableLocationsFn = func(context.Context, inventory.LocationFilter) (inventory.DeployableLocationPage, error) {
		calls++
		return inventory.DeployableLocationPage{}, nil
	}
	rec := call(h, http.MethodGet, "/api/v1/certificate-locations?cursor="+strings.Repeat("c", maxCursorBytes+1), "auditor", "")
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Equal(t, "cursor", errorDetails(t, rec)[0].Field)
	assert.Zero(t, calls)
}

// The server routes answer a malformed id as an unknown one, pass the inventory's errors on, and check their bodies
// before anything reaches the inventory.
func TestCovBTargetRoutesRefusals(t *testing.T) {
	d, inv := inventoryDeps(t)
	h := NewHandler(d)
	inv.ListTargetsFn = func(context.Context) ([]inventory.Target, error) { return nil, errCovB }
	inv.GetTargetFn = func(context.Context, uuid.UUID) (inventory.Target, error) {
		return inventory.Target{}, inventory.ErrNotFound
	}
	inv.ListHostKeysFn = func(context.Context, uuid.UUID) ([]inventory.HostKeyRecord, error) { return nil, inventory.ErrNotFound }
	inv.ListTargetKeysFn = func(context.Context, uuid.UUID, bool) ([]inventory.KeyLocation, error) {
		return nil, inventory.ErrNotFound
	}
	repins := 0
	inv.RepinHostKeyFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID, string, string) (uuid.UUID, error) {
		repins++
		return uuid.Nil, nil
	}
	confirms := 0
	inv.ConfirmHostKeyFn = func(context.Context, inventory.Actor, uuid.UUID, uuid.UUID, string) (uuid.UUID, error) {
		confirms++
		return uuid.Nil, nil
	}

	rec := call(h, http.MethodGet, "/api/v1/targets", "auditor", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, ErrUnexpected.Code, decodeErr(t, rec).Error.Code)

	base := "/api/v1/targets/" + targetID.String()
	key := uuid.MustParse("0192b000-0000-7000-8000-0000000000f1")
	for _, path := range []string{base, base + "/host-keys", base + "/ssh-keys"} {
		rec = call(h, http.MethodGet, path, "auditor", "")
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
		assert.Equal(t, ErrNotFound.Code, decodeErr(t, rec).Error.Code, path)
	}

	for _, tc := range []struct{ method, path, id, body string }{
		{http.MethodPatch, "/api/v1/targets/nope", "admin", `{"name":"x"}`},
		{http.MethodPost, "/api/v1/targets/nope/actions/test", "admin", ""},
		{http.MethodPost, "/api/v1/targets/nope/actions/discover", "admin", ""},
		{http.MethodGet, "/api/v1/targets/nope/host-keys", "auditor", ""},
		{http.MethodGet, "/api/v1/targets/nope/ssh-keys", "auditor", ""},
		{http.MethodPost, base + "/host-keys/nope/actions/confirm", "admin-stepup", `{"fingerprint":"SHA256:x"}`},
		{http.MethodPost, base + "/host-keys/nope/actions/repin", "admin-stepup", `{"fingerprint":"SHA256:x","reason":"the server was rebuilt"}`},
	} {
		rec = callWith(h, tc.method, tc.path, tc.id, tc.body, map[string]string{"If-Match": `"1"`})
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s %s", tc.method, tc.path, rec.Body.String())
	}

	keyPath := base + "/host-keys/" + key.String() + "/actions/"
	rec = call(h, http.MethodPost, keyPath+"confirm", "admin-stepup", `{"fingerprint":`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = call(h, http.MethodPost, keyPath+"repin", "admin-stepup", `{"fingerprint":`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	rec = call(h, http.MethodPost, keyPath+"repin", "admin-stepup", `{"reason":"the server was rebuilt today"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	assert.Equal(t, "fingerprint", errorDetails(t, rec)[0].Field)
	assert.Zero(t, repins+confirms, "nothing reached the inventory")
}

// Design §5.6 "either side" (HB-02, R64 ruling 9): a person of a website's service may release its own websites from a
// Key Vault binding of another service it can see, and nothing else: adding a website, or releasing a website of a
// service it only reads, is 403 before the inventory. The person holds Operator on svcPay (the websites) and Auditor on
// svcDefault (the vault, and website C), so it sees website C but holds no right on it. A binding not visible from
// svcPay stays unknown (404) to a person of svcPay only.
func TestPatchBindingFromTheWebsiteSide(t *testing.T) {
	d, inv := inventoryDeps(t)
	svc := &covBServices{fakeServices: &fakeServices{targetServices: map[uuid.UUID]uuid.UUID{targetID: svcPay, covBOtherTarget: svcDefault}}}
	d.Services = svc
	fa := d.Auth.(*fakeAuth)
	prev := fa.AuthenticateFn
	fa.AuthenticateFn = func(ctx context.Context, tok string) (auth.Principal, error) {
		if tok == "website-side" {
			return auth.Principal{Kind: rbac.UserSession, UserID: operatorID, Username: "web", DisplayName: "web", Role: auth.NoGlobalRole,
				Locale: "en", SessionHash: []byte("website-side"), StepUpUntil: testNow.Add(5 * time.Minute),
				Grants: []rbac.ScopedGrant{{Role: rbac.Operator, Services: []uuid.UUID{svcPay}}, {Role: rbac.Auditor, Services: []uuid.UUID{svcDefault}}}}, nil
		}
		return prev(ctx, tok)
	}
	h := NewHandler(d)
	visible := []uuid.UUID{svcDefault, svcPay}
	svc.ResolveFn = func(kind string, id any) (services.Resolution, error) {
		switch kind {
		case services.KindKVBinding:
			return services.Resolution{Owning: svcDefault, Visible: visible}, nil // the vault's service owns the binding
		case services.KindLocation:
			if id == covBLocationC {
				return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
			}
			return services.Resolution{Owning: svcPay, Visible: []uuid.UUID{svcPay}}, nil
		}
		return services.Resolution{}, services.ErrResourceNotFound
	}
	binding := sampleBinding(false)
	binding.Locations = append(binding.Locations,
		inventory.BindingLocation{LocationID: locationB, TargetID: targetID, TargetName: "web-01", CertPath: "/etc/ssl/b.pem",
			State: inventory.BindingLocationDeployed},
		inventory.BindingLocation{LocationID: covBLocationC, TargetID: covBOtherTarget, TargetName: "db-01", CertPath: "/etc/ssl/c.pem",
			State: inventory.BindingLocationDeployed})
	inv.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { return binding, nil }
	var got [][]uuid.UUID
	inv.UpdateBindingLocationsStrictFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, _ int, l []uuid.UUID, _ bool) (inventory.Binding, error) {
		got = append(got, l)
		return binding, nil
	}
	path := "/api/v1/bindings/" + bindingA.String()
	hdr := map[string]string{"If-Match": `"4"`}
	body := func(locs ...uuid.UUID) string {
		ids := make([]string, len(locs))
		for i, l := range locs {
			ids[i] = `"` + l.String() + `"`
		}
		return `{"location_ids":[` + strings.Join(ids, ",") + `]}`
	}

	// (a) Releasing its own website B.
	rec := callWith(h, http.MethodPatch, path, "website-side", body(locationA, covBLocationC), hdr)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, got, 1)
	assert.Equal(t, []uuid.UUID{locationA, covBLocationC}, got[0])

	// (b) Adding a website, even one of its own service, is the vault side's.
	locationD := uuid.MustParse("0192d000-0000-7000-8000-0000000000d4")
	rec = callWith(h, http.MethodPatch, path, "website-side", body(locationA, locationB, covBLocationC, locationD), hdr)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, ErrForbidden.Code, decodeErr(t, rec).Error.Code)
	assert.Len(t, got, 1, "nothing reached the inventory")

	// (c) Releasing website C, which it sees but holds no right on.
	rec = callWith(h, http.MethodPatch, path, "website-side", body(locationA, locationB), hdr)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, ErrForbidden.Code, decodeErr(t, rec).Error.Code)
	assert.Len(t, got, 1, "nothing reached the inventory")

	// (d) A binding visible from svcDefault only is unknown to a person of svcPay only (the guard, unchanged).
	hs, invS, svcS := covBScoped(t, rbac.Operator)
	svcS.ResolveFn = func(kind string, _ any) (services.Resolution, error) {
		if kind == services.KindKVBinding {
			return services.Resolution{Owning: svcDefault, Visible: []uuid.UUID{svcDefault}}, nil
		}
		return services.Resolution{}, services.ErrResourceNotFound
	}
	var calls int
	invS.BindingFn = func(context.Context, uuid.UUID) (inventory.Binding, error) { calls++; return binding, nil }
	rec = callWith(hs, http.MethodPatch, path, "covb-scoped", body(locationA), hdr)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Zero(t, calls)
}
