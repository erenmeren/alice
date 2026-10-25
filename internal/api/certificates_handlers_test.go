package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
)

var (
	certID     = uuid.MustParse("0192c000-0000-7000-8000-0000000000d1")
	locationID = uuid.MustParse("0192c000-0000-7000-8000-0000000000d2")
	csrID      = uuid.MustParse("0192c000-0000-7000-8000-0000000000d3")
	deployID   = uuid.MustParse("0192c000-0000-7000-8000-0000000000d4")
)

func sampleLocation() inventory.CertificateLocation {
	at := time.Date(2026, 10, 2, 8, 0, 0, 0, time.FixedZone("x", 3*3600))
	port := 8443
	return inventory.CertificateLocation{
		ID: locationID, TargetID: targetID, TargetName: "web-01", CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key",
		ResolvedCertPath: "/etc/letsencrypt/archive/www/fullchain3.pem", KeyType: "ecdsa",
		Certificate: &inventory.CertificateRef{ID: certID, SubjectCN: "www.example.com", Label: "Web", Fingerprint: strings.Repeat("a", 64), NotAfter: at},
		Servers: []providers.CertServer{{Names: []string{"www.example.com"}, Listens: []providers.CertListen{{Addr: "*", Port: 443, DefaultServer: true}},
			File: "/etc/nginx/conf.d/www.conf", Line: 3}},
		Supported: false, UnsupportedReason: "file_problem", Problem: "", KeyProblem: "not_root_controlled", Inherited: true,
		CustomLocation: true, Symlinked: true, CertFileSHA256: strings.Repeat("f", 64), KeyExists: true, KeyMode: "0640", KeyOwner: "root",
		KeyGroup: "ssl-cert", Warnings: []string{"symlinked", "list_truncated"}, DeployedFingerprint: strings.Repeat("b", 64),
		ChangedOutsideAt: &at, VerifyPort: &port, VerifySNI: "www.example.com", SkipVerify: true, FirstSeenAt: at, LastSeenAt: at,
		MissingSince: &at, Version: 4, ActiveDeploymentID: &deployID, TargetType: inventory.TypeNginx, Deployable: true,
	}
}

func sampleCertificate() inventory.Certificate {
	at := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	return inventory.Certificate{
		ID: certID, Fingerprint: strings.Repeat("a", 64), SubjectCN: "www.example.com", Subject: "CN=www.example.com", Issuer: "CN=Test CA",
		Serial: "01", SANs: []string{"www.example.com"}, NotBefore: at, NotAfter: at.AddDate(0, 3, 0), KeyAlgorithm: "ecdsa", KeyBits: 256,
		PEMChain: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", ChainComplete: true, Source: "uploaded", Label: "Web",
		HasPrivateKey: true, LocationCount: 1, FirstSeenAt: at, LastSeenAt: at, Locations: []inventory.CertificateLocation{sampleLocation()},
		LocationsTruncated: true,
	}
}

func sampleCSR() inventory.CSR {
	at := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	return inventory.CSR{ID: csrID, CommonName: "www.example.com", SANs: []string{"www.example.com", "example.com"}, KeyAlgorithm: "ecdsa",
		KeyBits: 256, CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", Status: inventory.CSRPending,
		CreatedAt: at}
}

func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sorted(keys ...string) []string {
	sort.Strings(keys)
	return keys
}

// The certificate, location and signing request DTOs carry exactly the contract's fields (plus the
// documented additions), and none names a key or a secret.
func TestCertificateDTOsHaveExactlyTheDocumentedFields(t *testing.T) {
	certFields := []string{"id", "fingerprint", "subject_cn", "subject", "issuer", "serial", "sans", "not_before", "not_after", "key_algorithm",
		"key_bits", "source", "label", "has_private_key", "chain_complete", "self_signed", "location_count", "first_seen_at", "last_seen_at",
		"public_key_sha256", "revoked_at", "revocation_reason", "revoked_by_name", "compromised_at", "acme_certificate_id", "capabilities",
		"revoked_by_authority"}
	assert.Equal(t, sorted(certFields...), jsonKeys(t, certificateJSON(sampleCertificate(), serviceRefs{})))
	assert.Equal(t, sorted(append(certFields, "pem_chain", "locations", "locations_truncated", "hidden_count", "revocation_check")...),
		jsonKeys(t, certificateDetailJSON(sampleCertificate(), serviceRefs{})))
	assert.Equal(t, sorted("id", "target_id", "target_name", "cert_path", "key_path", "resolved_cert_path", "key_type", "certificate", "servers",
		"supported", "unsupported_reason", "problem", "key_problem", "inherited", "custom_location", "symlinked", "key_exists", "key_mode",
		"key_owner", "key_group", "warnings", "deployed_fingerprint", "changed_outside_at", "verify_port", "verify_sni", "skip_verify",
		"first_seen_at", "last_seen_at", "missing_since", "version", "active_deployment_id", "target_type", "deployable", "observation",
		"kind", "locator", "details", "verify_address"), // R59: the kind, its identity and facts, the probe address
		jsonKeys(t, locationJSON(sampleLocation())))
	assert.Equal(t, sorted("id", "common_name", "sans", "key_algorithm", "key_bits", "csr_pem", "status", "certificate_id", "created_at",
		"finished_at"), jsonKeys(t, csrJSON(sampleCSR(), serviceRefs{})))

	raw, err := json.Marshal(locationJSON(sampleLocation()))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"changed_outside_at":"2026-10-02T05:00:00Z"`, "times are UTC")
	assert.Contains(t, string(raw), `"servers":[{"names":["www.example.com"],"listens":[{"addr":"*","port":443,"default_server":true}],"file":"/etc/nginx/conf.d/www.conf","line":3}]`)
	assert.Contains(t, string(raw), `"active_deployment_id":"`+deployID.String()+`"`)
	assert.NotContains(t, string(raw), strings.Repeat("f", 64), "the file hash (compare-and-swap value) stays internal")
	for _, v := range []any{certificateDetailJSON(sampleCertificate(), serviceRefs{}), csrJSON(sampleCSR(), serviceRefs{}), locationJSON(sampleLocation())} {
		for _, k := range jsonKeys(t, v) {
			for _, bad := range []string{"private_key_id", "password", "secret", "envelope", "ciphertext", "pfx"} {
				assert.NotContains(t, k, bad)
			}
		}
	}

	// Slices are never null; an empty location has a null certificate.
	raw, err = json.Marshal(locationJSON(inventory.CertificateLocation{}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"servers":[]`)
	assert.Contains(t, string(raw), `"warnings":[]`)
	assert.Contains(t, string(raw), `"certificate":null`)
	raw, err = json.Marshal(certificateDetailJSON(inventory.Certificate{}, serviceRefs{}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"sans":[]`)
	assert.Contains(t, string(raw), `"locations":[]`)
	raw, err = json.Marshal(csrJSON(inventory.CSR{}, serviceRefs{}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"sans":[]`)
	assert.Contains(t, string(raw), `"certificate_id":null`)
}

func TestUploadCertificate(t *testing.T) {
	d, inv := inventoryDeps(t)
	var got inventory.UploadInput
	var actor inventory.Actor
	inv.UploadCertificateFn = func(_ context.Context, a inventory.Actor, in inventory.UploadInput) (inventory.Certificate, []string, error) {
		got, actor = in, a
		return sampleCertificate(), []string{"chain_incomplete"}, nil
	}
	h := NewHandler(d)
	key := "-----BEGIN " + "PRIVATE KEY-----\\nk\\n-----END " + "PRIVATE KEY-----\\n"
	rec := call(h, http.MethodPost, "/api/v1/certificates/upload", "operator",
		`{"label":"Web","certificate_pem":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n","private_key_pem":"`+key+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var body struct {
		Certificate map[string]any `json:"certificate"`
		Warnings    []string       `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, []string{"chain_incomplete"}, body.Warnings)
	assert.Equal(t, true, body.Certificate["has_private_key"])
	assert.Equal(t, certID.String(), body.Certificate["id"])
	assert.Contains(t, body.Certificate, "pem_chain")
	assert.Equal(t, "/api/v1/certificates/"+certID.String(), rec.Header().Get("Location"))
	assert.Equal(t, "Web", got.Label)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n", got.CertificatePEM)
	assert.Contains(t, got.PrivateKeyPEM, "PRIVATE KEY")
	assert.Equal(t, operatorID, actor.UserID)
	assert.NotContains(t, rec.Body.String(), "PRIVATE KEY", "the key never comes back")

	// PFX fields are passed on as sent; the service decides (and refuses both kinds at once).
	rec = call(h, http.MethodPost, "/api/v1/certificates/upload", "admin", `{"pfx_base64":"AAAA","pfx_password":"pw"}`)
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, inventory.UploadInput{PFXBase64: "AAAA", PFXPassword: "pw"}, got)

	// Strict decoding: unknown fields, trailing data, malformed JSON.
	for _, bad := range []string{`{"certificate_pem":"x","unknown":1}`, `{"certificate_pem":"x"} {}`, `{"certificate_pem":`} {
		rec = call(h, http.MethodPost, "/api/v1/certificates/upload", "operator", bad)
		assert.Equal(t, http.StatusBadRequest, rec.Code, bad)
	}
	// Warnings are never null.
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		return sampleCertificate(), nil, nil
	}
	rec = call(h, http.MethodPost, "/api/v1/certificates/upload", "operator", `{"pfx_base64":"AAAA"}`)
	assert.Contains(t, rec.Body.String(), `"warnings":[]`)

	// AUD-17: an upload that only completed the chain of a held certificate answers 200 with the
	// detail form and no Location (nothing was created).
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		return sampleCertificate(), []string{inventory.WarnChainCompleted}, nil
	}
	rec = call(h, http.MethodPost, "/api/v1/certificates/upload", "operator", `{"pfx_base64":"AAAA"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Contains(t, rec.Body.String(), `"warnings":["chain_completed"]`)
	assert.Contains(t, rec.Body.String(), `"pem_chain"`)
}

// The body caps: an upload or a completion larger than its cap is refused unread with 413, and
// the service is never called; a body at the certs limits plus JSON overhead still goes through.
func TestCertificateBodiesAreCapped(t *testing.T) {
	d, inv := inventoryDeps(t)
	calls := 0
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		calls++
		return sampleCertificate(), nil, nil
	}
	inv.CompleteCSRFn = func(context.Context, inventory.Actor, uuid.UUID, string, string) (inventory.Certificate, []string, error) {
		calls++
		return sampleCertificate(), nil, nil
	}
	h := NewHandler(d)
	// 256 KiB of PEM text in each field, with a JSON-escaped line break every 64 characters.
	pemField := func() string {
		line := strings.Repeat("A", 64) + `\n`
		return strings.Repeat(line, (256<<10)/65)
	}
	rec := call(h, http.MethodPost, "/api/v1/certificates/upload", "admin", `{"certificate_pem":"`+pemField()+`","private_key_pem":"`+pemField()+`"}`)
	assert.Equal(t, http.StatusCreated, rec.Code, "the certs limits fit")
	rec = call(h, http.MethodPost, "/api/v1/certificates/csr/"+csrID.String()+"/actions/complete", "admin", `{"certificate_pem":"`+pemField()+`"}`)
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, 2, calls)

	// Absolute bounds (not the constants): 768 KiB for an upload, 384 KiB for a completion.
	for _, tc := range []struct {
		path, field string
		size        int
	}{
		{"/api/v1/certificates/upload", "pfx_base64", 768 << 10},
		{"/api/v1/certificates/csr/" + csrID.String() + "/actions/complete", "certificate_pem", 384 << 10},
	} {
		rec := call(h, http.MethodPost, tc.path, "admin", `{"`+tc.field+`":"`+strings.Repeat("A", tc.size)+`"}`)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, tc.path)
		assert.Equal(t, "ALC-SYS-0007", decodeErr(t, rec).Error.Code)
	}
	assert.Equal(t, 2, calls, "an oversized body never reaches the service")
}

// TestCertificateErrorsMapToCodes: every refusal the inventory returns to these routes has its
// documented code, status and params.
func TestCertificateErrorsMapToCodes(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
		params map[string]string
	}{
		{inventory.ErrNotFound, "ALC-SYS-0001", 404, nil},
		{inventory.ErrCertificateInvalid, "ALC-CRT-0001", 422, nil},
		{inventory.ErrKeyMismatch, "ALC-CRT-0002", 422, nil},
		{inventory.ErrCertificateExpired, "ALC-CRT-0003", 422, nil},
		{inventory.ErrKeyEncrypted, "ALC-CRT-0004", 422, nil},
		{inventory.ErrPFXPassword, "ALC-CRT-0005", 422, nil},
		{inventory.ErrWeakCertificate, "ALC-CRT-0006", 422, nil},
		{inventory.ErrUnsupportedKey, "ALC-CRT-0007", 422, nil},
		{inventory.ErrCertificateDuplicate, "ALC-CRT-0008", 409, nil},
		{inventory.ErrNoPrivateKey, "ALC-CRT-0009", 409, nil},
		{&inventory.KeyTypeMismatchError{Expected: "ecdsa", Actual: "rsa"}, "ALC-CRT-0010", 409, map[string]string{"expected": "ecdsa", "actual": "rsa"}},
		{inventory.ErrKeyTypeMismatch, "ALC-CRT-0010", 409, nil},
		{inventory.ErrChainUnconfirmed, "ALC-CRT-0011", 409, nil},
		{inventory.ErrCSRNotPending, "ALC-CRT-0012", 409, nil},
		{inventory.ErrCSRMismatch, "ALC-CRT-0013", 422, nil},
		{inventory.ErrCertificateNotYetValid, "ALC-CRT-0014", 409, nil},
		{inventory.ErrPFXBusy, "ALC-CRT-0015", 503, nil},
		{inventory.ErrDeploymentInProgress, "ALC-DEP-0001", 409, nil},
		{inventory.ErrRecoveryPending, "ALC-DEP-0002", 409, nil},
		{inventory.ErrTargetNotReady, "ALC-DEP-0011", 409, nil},
		{inventory.ErrLocationNeedsDiscovery, "ALC-DEP-0021", 409, nil},
		{inventory.ErrLocationUnsupported, "ALC-NGX-0007", 409, nil},
		{inventory.ErrNginxConfigInvalid, "ALC-NGX-0002", 409, nil},
		{inventory.ErrCertificateTooLarge, "ALC-SYS-0007", 413, nil},
		{inventory.ErrVersionMismatch, "ALC-SYS-0008", 412, nil},
		{license.ErrLocked, "ALC-LIC-0001", 403, nil},
		// A refusal decided for one location names it.
		{&inventory.LocationRefusalError{LocationID: locationID, Err: inventory.ErrDeploymentInProgress}, "ALC-DEP-0001", 409,
			map[string]string{"location_id": locationID.String()}},
		{&inventory.LocationRefusalError{LocationID: locationID, Err: &inventory.KeyTypeMismatchError{Expected: "rsa", Actual: "ecdsa"}},
			"ALC-CRT-0010", 409, map[string]string{"expected": "rsa", "actual": "ecdsa", "location_id": locationID.String()}},
		{&inventory.LocationRefusalError{LocationID: locationID, Err: inventory.ErrNotFound}, "ALC-SYS-0001", 404,
			map[string]string{"location_id": locationID.String()}},
	} {
		d, inv := inventoryDeps(t)
		inv.RequestDeploymentFn = func(context.Context, inventory.Actor, inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
			return nil, tc.err
		}
		rec := call(NewHandler(d), http.MethodPost, "/api/v1/certificates/"+uuid.NewString()+"/deploy", "admin",
			`{"location_ids":["`+uuid.NewString()+`"]}`)
		name := fmt.Sprintf("%v", tc.err)
		assert.Equal(t, tc.status, rec.Code, name)
		var body struct {
			Error struct {
				Code      string            `json:"code"`
				Retryable bool              `json:"retryable"`
				Params    map[string]string `json:"params"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), name)
		assert.Equal(t, tc.code, body.Error.Code, name)
		assert.Equal(t, tc.params, body.Error.Params, name)
		if errors.Is(tc.err, inventory.ErrPFXBusy) {
			assert.True(t, body.Error.Retryable)
			assert.Equal(t, "1", rec.Header().Get("Retry-After"))
		}
		assert.NotContains(t, rec.Body.String(), "inventory:", "no Go error text reaches the client")
	}
}

func TestDeployAnswersAcceptedWithJobs(t *testing.T) {
	d, inv := inventoryDeps(t)
	loc2 := uuid.New()
	job1, job2, dep2 := uuid.New(), uuid.New(), uuid.New()
	var got inventory.DeployRequestInput
	var actor inventory.Actor
	inv.RequestDeploymentFn = func(_ context.Context, a inventory.Actor, in inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
		got, actor = in, a
		return []inventory.RequestedDeployment{
			{ID: deployID, JobID: job1, LocationID: locationID, Warnings: []string{"san_mismatch"}},
			{ID: dep2, JobID: job2, LocationID: loc2},
		}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodPost, "/api/v1/certificates/"+certID.String()+"/deploy", "operator",
		`{"location_ids":["`+locationID.String()+`","`+loc2.String()+`"],"confirm_incomplete_chain":true}`)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"deployments":[
		{"id":"`+deployID.String()+`","job_id":"`+job1.String()+`","location_id":"`+locationID.String()+`","status_url":"/api/v1/jobs/`+job1.String()+`",
		 "deployment_url":"/api/v1/deployments/`+deployID.String()+`","warnings":["san_mismatch"]},
		{"id":"`+dep2.String()+`","job_id":"`+job2.String()+`","location_id":"`+loc2.String()+`","status_url":"/api/v1/jobs/`+job2.String()+`",
		 "deployment_url":"/api/v1/deployments/`+dep2.String()+`","warnings":[]}]}`, rec.Body.String())
	assert.Equal(t, inventory.DeployRequestInput{CertificateID: certID, LocationIDs: []uuid.UUID{locationID, loc2}, ConfirmIncompleteChain: true}, got,
		"an Operator's confirm_incomplete_chain is passed on as sent (the inventory decides)")
	assert.Equal(t, operatorID, actor.UserID)

	calls := 0
	inv.RequestDeploymentFn = func(context.Context, inventory.Actor, inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
		calls++
		return nil, nil
	}
	ids := make([]string, 21)
	for i := range ids {
		ids[i] = `"` + uuid.NewString() + `"`
	}
	for body, field := range map[string]string{
		`{"location_ids":[` + strings.Join(ids, ",") + `]}`: validate.OutOfRange,
		`{"location_ids":[]}`:                               validate.OutOfRange,
		`{}`:                                                validate.OutOfRange,
		`{"location_ids":["x"]}`:                            validate.Pattern,
		`{"location_ids":["` + uuid.Nil.String() + `"]}`:                                 validate.Pattern,
		`{"location_ids":["` + locationID.String() + `","` + locationID.String() + `"]}`: validate.Duplicate,
	} {
		rec := call(h, http.MethodPost, "/api/v1/certificates/"+certID.String()+"/deploy", "admin", body)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, body)
		assert.Equal(t, []validate.FieldError{{Field: "location_ids", Code: field, Params: errorDetails(t, rec)[0].Params}}, errorDetails(t, rec), body)
	}
	rec = call(h, http.MethodPost, "/api/v1/certificates/not-a-uuid/deploy", "admin", `{"location_ids":["`+locationID.String()+`"]}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = call(h, http.MethodPost, "/api/v1/certificates/"+certID.String()+"/deploy", "admin", `{"location_ids":["`+locationID.String()+`"],"retry":true}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "unknown fields")
	assert.Zero(t, calls, "nothing invalid reaches the service")

	// A repeated request while one is in progress answers the specific code, never a 500.
	inv.RequestDeploymentFn = func(context.Context, inventory.Actor, inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
		return nil, &inventory.LocationRefusalError{LocationID: locationID, Err: inventory.ErrDeploymentInProgress}
	}
	rec = call(h, http.MethodPost, "/api/v1/certificates/"+certID.String()+"/deploy", "admin", `{"location_ids":["`+locationID.String()+`"]}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	e := decodeErr(t, rec)
	assert.Equal(t, "ALC-DEP-0001", e.Error.Code)
	assert.True(t, e.Error.Retryable)
}

// C m1: the deploy request, the signing request creation and the location settings refuse a
// repeated or case-variant top-level key (encoding/json alone would let the last or a differently
// cased one win) before the service is called.
func TestChangeBodiesRefuseRepeatedAndCaseVariantKeys(t *testing.T) {
	d, inv := inventoryDeps(t)
	calls := 0
	inv.RequestDeploymentFn = func(context.Context, inventory.Actor, inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
		calls++
		return nil, nil
	}
	inv.CreateCSRFn = func(context.Context, inventory.Actor, inventory.CSRInput) (inventory.CSR, error) {
		calls++
		return sampleCSR(), nil
	}
	inv.UpdateLocationFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.LocationPatch) (inventory.CertificateLocation, error) {
		calls++
		return sampleLocation(), nil
	}
	h := NewHandler(d)
	loc, other := `"`+locationID.String()+`"`, `"`+uuid.NewString()+`"`
	ifMatch := map[string]string{"If-Match": `"3"`}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/certificates/" + certID.String() + "/deploy", `{"location_ids":[` + loc + `],"location_ids":[` + other + `]}`},
		{http.MethodPost, "/api/v1/certificates/" + certID.String() + "/deploy", `{"location_ids":[` + loc + `],"Location_IDs":[` + other + `]}`},
		{http.MethodPost, "/api/v1/certificates/" + certID.String() + "/deploy",
			`{"location_ids":[` + loc + `],"confirm_incomplete_chain":false,"confirm_incomplete_chain":true}`},
		{http.MethodPost, "/api/v1/certificates/" + certID.String() + "/deploy", `{"location_ids":[` + loc + `],"CONFIRM_INCOMPLETE_CHAIN":true}`},
		{http.MethodPost, "/api/v1/certificates/csr", `{"common_name":"a.example.test","common_name":"b.example.test","key_type":"ecdsa-p256"}`},
		{http.MethodPost, "/api/v1/certificates/csr", `{"common_name":"a.example.test","Key_Type":"rsa-4096","key_type":"ecdsa-p256"}`},
		{http.MethodPatch, "/api/v1/locations/" + locationID.String(), `{"skip_verify":false,"skip_verify":true}`},
		{http.MethodPatch, "/api/v1/locations/" + locationID.String(), `{"Skip_Verify":true}`},
	} {
		rec := callWith(h, tc.method, tc.path, "admin", tc.body, ifMatch)
		assert.Equal(t, http.StatusBadRequest, rec.Code, tc.body)
		assert.Equal(t, "ALC-SYS-0004", decodeErr(t, rec).Error.Code, tc.body)
	}
	assert.Zero(t, calls, "nothing ambiguous reaches the service")
	// The exact keys still work.
	rec := callWith(h, http.MethodPost, "/api/v1/certificates/"+certID.String()+"/deploy", "admin", `{"location_ids":[`+loc+`],"confirm_incomplete_chain":true}`, nil)
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	rec = callWith(h, http.MethodPost, "/api/v1/certificates/csr", "admin", `{"common_name":"a.example.test","sans":[],"key_type":"ecdsa-p256"}`, nil)
	assert.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	rec = callWith(h, http.MethodPatch, "/api/v1/locations/"+locationID.String(), "admin", `{"verify_port":null,"skip_verify":true}`, ifMatch)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 3, calls)
}

func TestCertificateListQueryValidation(t *testing.T) {
	d, inv := inventoryDeps(t)
	var got inventory.CertificateFilter
	calls := 0
	inv.ListCertificatesFn = func(_ context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error) {
		got = f
		calls++
		c := sampleCertificate()
		c.PEMChain, c.Locations = "", nil
		return inventory.CertificatePage{Items: []inventory.Certificate{c}, NextCursor: "next"}, nil
	}
	h := NewHandler(d)
	for q, field := range map[string]string{
		"expiry=45": "expiry", "source=kv": "source", "limit=0": "limit", "limit=201": "limit", "limit=x": "limit",
		"target_id=x": "target_id", "q=" + strings.Repeat("ş", 201): "q", "cursor=" + strings.Repeat("c", 513): "cursor",
	} {
		rec := call(h, http.MethodGet, "/api/v1/certificates?"+q, "auditor", "")
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
		assert.Equal(t, field, errorDetails(t, rec)[0].Field, q)
	}
	assert.Zero(t, calls)
	rec := call(h, http.MethodGet, "/api/v1/certificates?target_id="+targetID.String()+"&source=csr&q=www&expiry=30&cursor=abc&limit=10", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.CertificateFilter{TargetID: targetID, Source: "csr", Query: "www", Expiry: "30", Cursor: "abc", Limit: 10}, got)
	var body struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	assert.NotContains(t, body.Items[0], "pem_chain", "the list has no chain")
	assert.NotContains(t, body.Items[0], "locations")
	require.NotNil(t, body.NextCursor)
	assert.Equal(t, "next", *body.NextCursor)
	rec = call(h, http.MethodGet, "/api/v1/certificates", "alice_read_auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, inventory.CertificateFilter{Limit: 50}, got, "defaults")

	// A cursor the inventory cannot decode is its field error (422), as for SSH keys.
	inv.ListCertificatesFn = func(context.Context, inventory.CertificateFilter) (inventory.CertificatePage, error) {
		return inventory.CertificatePage{}, validate.Errors{{Field: "cursor", Code: validate.Pattern}}
	}
	rec = call(h, http.MethodGet, "/api/v1/certificates?cursor=zz", "auditor", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	inv.ListCertificatesFn = func(context.Context, inventory.CertificateFilter) (inventory.CertificatePage, error) {
		return inventory.CertificatePage{Items: []inventory.Certificate{}}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/certificates", "auditor", "")
	assert.JSONEq(t, `{"items":[],"next_cursor":null}`, rec.Body.String())
}

func TestGetCertificate(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.GetCertificateFn = func(_ context.Context, id uuid.UUID) (inventory.Certificate, error) {
		if id != certID {
			return inventory.Certificate{}, inventory.ErrNotFound
		}
		return sampleCertificate(), nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/certificates/"+certID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, sampleCertificate().PEMChain, body["pem_chain"])
	assert.Len(t, body["locations"], 1)
	assert.Equal(t, true, body["locations_truncated"])
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/certificates/"+uuid.NewString(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/certificates/upload", "auditor", "").Code, "not a UUID")
}

// Each place of a certificate carries its server's type and whether that server deploys
// certificates: an Nginx place is deployable, a supported place on a discovery-only Apache server is not.
func TestGetCertificateSaysWhichPlacesAreDeployable(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.GetCertificateFn = func(context.Context, uuid.UUID) (inventory.Certificate, error) {
		c := sampleCertificate()
		ap := sampleLocation()
		ap.ID, ap.TargetName, ap.TargetType, ap.Deployable, ap.Supported, ap.UnsupportedReason = uuid.New(), "apache-01", inventory.TypeApache, false, true, ""
		c.Locations = []inventory.CertificateLocation{sampleLocation(), ap}
		return c, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/certificates/"+certID.String(), "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Locations []struct {
			TargetType string `json:"target_type"`
			Deployable bool   `json:"deployable"`
			Supported  bool   `json:"supported"`
		} `json:"locations"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Locations, 2)
	assert.Equal(t, "nginx", body.Locations[0].TargetType)
	assert.True(t, body.Locations[0].Deployable)
	assert.Equal(t, "apache", body.Locations[1].TargetType)
	assert.False(t, body.Locations[1].Deployable)
	assert.True(t, body.Locations[1].Supported)
}

func TestCSRRoutes(t *testing.T) {
	d, inv := inventoryDeps(t)
	var created inventory.CSRInput
	var completedID uuid.UUID
	var completedPEM, completedLabel string
	inv.CreateCSRFn = func(_ context.Context, _ inventory.Actor, in inventory.CSRInput) (inventory.CSR, error) {
		created = in
		return sampleCSR(), nil
	}
	inv.ListCSRsFn = func(context.Context) ([]inventory.CSR, error) { return []inventory.CSR{sampleCSR()}, nil }
	inv.GetCSRFn = func(_ context.Context, id uuid.UUID) (inventory.CSR, error) {
		if id != csrID {
			return inventory.CSR{}, inventory.ErrNotFound
		}
		return sampleCSR(), nil
	}
	inv.CompleteCSRFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID, pemText, label string) (inventory.Certificate, []string, error) {
		completedID, completedPEM, completedLabel = id, pemText, label
		return sampleCertificate(), []string{"csr_name_mismatch"}, nil
	}
	inv.CancelCSRFn = func(_ context.Context, _ inventory.Actor, id uuid.UUID) (inventory.CSR, error) {
		c := sampleCSR()
		c.Status = inventory.CSRCancelled
		return c, nil
	}
	h := NewHandler(d)
	base := "/api/v1/certificates/csr"
	rec := call(h, http.MethodPost, base, "operator", `{"common_name":"www.example.com","sans":["example.com"],"key_type":"ecdsa-p256"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, inventory.CSRInput{CommonName: "www.example.com", SANs: []string{"example.com"}, KeyType: "ecdsa-p256"}, created)
	assert.Contains(t, rec.Body.String(), `"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----`)
	assert.Equal(t, base+"/"+csrID.String(), rec.Header().Get("Location"))

	rec = call(h, http.MethodGet, base, "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, "pending", list.Items[0]["status"])

	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, base+"/"+csrID.String(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, base+"/"+uuid.NewString(), "auditor", "").Code)
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, base+"/x", "auditor", "").Code)

	rec = call(h, http.MethodPost, base+"/"+csrID.String()+"/actions/complete", "operator", `{"certificate_pem":"PEM","label":"Shop"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Equal(t, csrID, completedID)
	assert.Equal(t, "PEM", completedPEM)
	assert.Equal(t, "Shop", completedLabel)
	assert.Contains(t, rec.Body.String(), `"warnings":["csr_name_mismatch"]`)
	assert.Contains(t, rec.Body.String(), `"certificate":{`)

	rec = call(h, http.MethodPost, base+"/"+csrID.String()+"/actions/cancel", "operator", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"status":"cancelled"`)
	assert.Equal(t, http.StatusOK, call(h, http.MethodPost, base+"/"+csrID.String()+"/actions/cancel", "operator", `{}`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, base+"/"+csrID.String()+"/actions/cancel", "operator", `{"x":1}`).Code)

	// An Auditor reads, but every change is forbidden; so is a read-scoped token.
	for _, id := range []string{"auditor", "alice_read_admin"} {
		for _, p := range []string{base, base + "/" + csrID.String() + "/actions/complete", base + "/" + csrID.String() + "/actions/cancel"} {
			assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, p, id, `{}`).Code, id+" "+p)
		}
	}
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, base, "alice_read_auditor", "").Code)

	inv.CompleteCSRFn = func(context.Context, inventory.Actor, uuid.UUID, string, string) (inventory.Certificate, []string, error) {
		return inventory.Certificate{}, nil, inventory.ErrCSRNotPending
	}
	rec = call(h, http.MethodPost, base+"/"+csrID.String()+"/actions/complete", "operator", `{"certificate_pem":"PEM"}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-CRT-0012", decodeErr(t, rec).Error.Code)
}

func TestTargetCertificateLocations(t *testing.T) {
	d, inv := inventoryDeps(t)
	var gotTarget uuid.UUID
	var gotMissing bool
	inv.ListLocationsFn = func(_ context.Context, id uuid.UUID, missing bool) (inventory.LocationList, error) {
		gotTarget, gotMissing = id, missing
		return inventory.LocationList{Items: []inventory.CertificateLocation{sampleLocation()}, Truncated: true}, nil
	}
	h := NewHandler(d)
	rec := call(h, http.MethodGet, "/api/v1/targets/"+targetID.String()+"/certificate-locations?missing=true", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, targetID, gotTarget)
	assert.True(t, gotMissing)
	var body struct {
		Items     []map[string]any `json:"items"`
		Truncated bool             `json:"truncated"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.True(t, body.Truncated)
	require.Len(t, body.Items, 1)
	assert.Equal(t, "not_root_controlled", body.Items[0]["key_problem"])
	rec = call(h, http.MethodGet, "/api/v1/targets/"+targetID.String()+"/certificate-locations?missing=yes", "auditor", "")
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	inv.ListLocationsFn = func(context.Context, uuid.UUID, bool) (inventory.LocationList, error) {
		return inventory.LocationList{}, inventory.ErrNotFound
	}
	assert.Equal(t, http.StatusNotFound, call(h, http.MethodGet, "/api/v1/targets/"+uuid.NewString()+"/certificate-locations", "auditor", "").Code)
	inv.ListLocationsFn = func(context.Context, uuid.UUID, bool) (inventory.LocationList, error) {
		return inventory.LocationList{}, nil
	}
	rec = call(h, http.MethodGet, "/api/v1/targets/"+targetID.String()+"/certificate-locations", "auditor", "")
	assert.JSONEq(t, `{"items":[],"truncated":false}`, rec.Body.String())
}

// An HAProxy location's servers carry the frontend (or listen) name as "section"; Nginx and Apache
// servers have none and the field is omitted.
func TestTargetCertificateLocationsCarryTheServerSection(t *testing.T) {
	d, inv := inventoryDeps(t)
	inv.ListLocationsFn = func(context.Context, uuid.UUID, bool) (inventory.LocationList, error) {
		loc := sampleLocation()
		loc.Servers = []providers.CertServer{
			{Names: []string{}, Listens: []providers.CertListen{}, File: "/etc/haproxy/haproxy.cfg", Line: 10, Section: "fe_https"},
			{Names: []string{"sni.example.test"}, Listens: []providers.CertListen{}, File: "/etc/haproxy/haproxy.cfg", Line: 20},
		}
		return inventory.LocationList{Items: []inventory.CertificateLocation{loc}}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/targets/"+targetID.String()+"/certificate-locations", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Items []struct {
			Servers []map[string]any `json:"servers"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	require.Len(t, body.Items[0].Servers, 2)
	assert.Equal(t, "fe_https", body.Items[0].Servers[0]["section"])
	assert.NotContains(t, body.Items[0].Servers[1], "section")
}

func TestUpdateLocationNeedsIfMatch(t *testing.T) {
	d, inv := inventoryDeps(t)
	var gotVersion int
	var gotPatch inventory.LocationPatch
	calls := 0
	inv.UpdateLocationFn = func(_ context.Context, _ inventory.Actor, _ uuid.UUID, v int, p inventory.LocationPatch) (inventory.CertificateLocation, error) {
		calls++
		gotVersion, gotPatch = v, p
		l := sampleLocation()
		l.Version = v + 1
		return l, nil
	}
	h := NewHandler(d)
	path := "/api/v1/locations/" + locationID.String()
	for _, hdr := range []map[string]string{nil, {"If-Match": `W/"3"`}, {"If-Match": "*"}, {"If-Match": `"3", "4"`}, {"If-Match": "3"}} {
		rec := callWith(h, http.MethodPatch, path, "admin", `{"skip_verify":true}`, hdr)
		assert.Equal(t, http.StatusPreconditionFailed, rec.Code, hdr)
		assert.Equal(t, "ALC-SYS-0008", decodeErr(t, rec).Error.Code)
	}
	assert.Zero(t, calls)
	rec := callWith(h, http.MethodPatch, path, "admin", `{"verify_port":0,"verify_sni":"","skip_verify":false}`, map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 3, gotVersion)
	require.NotNil(t, gotPatch.VerifyPort)
	assert.Equal(t, 0, *gotPatch.VerifyPort)
	require.NotNil(t, gotPatch.VerifySNI)
	assert.Empty(t, *gotPatch.VerifySNI)
	require.NotNil(t, gotPatch.SkipVerify)
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))
	rec = callWith(h, http.MethodPatch, path, "alice_operate_admin", `{"skip_verify":true}`, map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, gotPatch.VerifyPort, "absent fields stay unchanged")
	assert.Nil(t, gotPatch.VerifySNI)

	// The value rules are the inventory's, passed through as field errors.
	inv.UpdateLocationFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.LocationPatch) (inventory.CertificateLocation, error) {
		return inventory.CertificateLocation{}, validate.Errors{{Field: "verify_port", Code: validate.OutOfRange, Params: map[string]string{"min": "0", "max": "65535"}}}
	}
	rec = callWith(h, http.MethodPatch, path, "admin", `{"verify_port":70000}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "verify_port", errorDetails(t, rec)[0].Field)
	inv.UpdateLocationFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.LocationPatch) (inventory.CertificateLocation, error) {
		return inventory.CertificateLocation{}, inventory.ErrVersionMismatch
	}
	rec = callWith(h, http.MethodPatch, path, "admin", `{"skip_verify":true}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "a stale version")
	assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPatch, path, "admin", `{"verify_port":"x"}`, map[string]string{"If-Match": `"3"`}).Code)
	assert.Equal(t, http.StatusNotFound, callWith(h, http.MethodPatch, "/api/v1/locations/x", "admin", `{}`, map[string]string{"If-Match": `"3"`}).Code)
	// An Operator may not change verification settings (an Administrator's decision).
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPatch, path, "operator", `{"skip_verify":true}`, map[string]string{"If-Match": `"3"`}).Code)
	assert.Equal(t, http.StatusForbidden, callWith(h, http.MethodPatch, path, "alice_operate_operator", `{"skip_verify":true}`, map[string]string{"If-Match": `"3"`}).Code)
}

// changeRequests are the Phase 4 state-changing routes with a body each would accept.
func changeRequests() []struct{ method, path, body string } {
	return []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/certificates/upload", `{"pfx_base64":"AAAA"}`},
		{http.MethodPost, "/api/v1/certificates/" + certID.String() + "/deploy", `{"location_ids":["` + locationID.String() + `"]}`},
		{http.MethodPost, "/api/v1/certificates/csr", `{"common_name":"a.example","key_type":"ecdsa-p256"}`},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID.String() + "/actions/complete", `{"certificate_pem":"x"}`},
		{http.MethodPost, "/api/v1/certificates/csr/" + csrID.String() + "/actions/cancel", ``},
		{http.MethodPatch, "/api/v1/locations/" + locationID.String(), `{"skip_verify":true}`},
	}
}

// In lock every Phase 4 change is refused by the guard before the body is read: an oversized or
// malformed body still answers license.locked, and the service is never called (R38 item 9).
func TestCertificateChangesAreRefusedInLockBeforeTheBody(t *testing.T) {
	d, inv := inventoryDeps(t)
	d.License.(*fakeLicense).set(license.ErrLocked)
	calls := 0
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		calls++
		return inventory.Certificate{}, nil, nil
	}
	h := NewHandler(d)
	routes := changeRequests()
	require.Len(t, routes, 6)
	for _, rt := range routes {
		for _, body := range []string{rt.body, `{"x":`, strings.Repeat("A", maxUploadBody+1)} {
			rec := callWith(h, rt.method, rt.path, "admin", body, map[string]string{"If-Match": `"1"`})
			assert.Equal(t, http.StatusForbidden, rec.Code, rt.path)
			assert.Equal(t, "license.locked", decodeErr(t, rec).Error.Reason, rt.path)
		}
	}
	assert.Zero(t, calls)
	assert.Positive(t, d.Audit.(*fakeAudit).Count("request.denied_license"))
	// Reads stay available.
	inv.ListCertificatesFn = func(context.Context, inventory.CertificateFilter) (inventory.CertificatePage, error) {
		return inventory.CertificatePage{}, nil
	}
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/certificates", "auditor", "").Code)
}

// Role × route for the Phase 4 changes, with real handlers: who reaches the service.
func TestCertificateChangesByRole(t *testing.T) {
	reached := map[string]bool{}
	d, inv := inventoryDeps(t)
	inv.UploadCertificateFn = func(context.Context, inventory.Actor, inventory.UploadInput) (inventory.Certificate, []string, error) {
		reached["upload"] = true
		return sampleCertificate(), nil, nil
	}
	inv.RequestDeploymentFn = func(context.Context, inventory.Actor, inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error) {
		reached["deploy"] = true
		return nil, nil
	}
	inv.CreateCSRFn = func(context.Context, inventory.Actor, inventory.CSRInput) (inventory.CSR, error) {
		reached["csr"] = true
		return sampleCSR(), nil
	}
	inv.CompleteCSRFn = func(context.Context, inventory.Actor, uuid.UUID, string, string) (inventory.Certificate, []string, error) {
		reached["complete"] = true
		return sampleCertificate(), nil, nil
	}
	inv.CancelCSRFn = func(context.Context, inventory.Actor, uuid.UUID) (inventory.CSR, error) {
		reached["cancel"] = true
		return sampleCSR(), nil
	}
	inv.UpdateLocationFn = func(context.Context, inventory.Actor, uuid.UUID, int, inventory.LocationPatch) (inventory.CertificateLocation, error) {
		reached["location"] = true
		return sampleLocation(), nil
	}
	h := NewHandler(d)
	keys := []string{"upload", "deploy", "csr", "complete", "cancel", "location"}
	for id, want := range map[string][]string{
		"admin":                  keys,
		"operator":               keys[:5],
		"auditor":                nil,
		"alice_operate_admin":    keys,
		"alice_operate_operator": keys[:5],
		"alice_read_admin":       nil,
		"":                       nil,
	} {
		clear(reached)
		for _, rt := range changeRequests() {
			callWith(h, rt.method, rt.path, id, rt.body, map[string]string{"If-Match": `"1"`})
		}
		var got []string
		for _, k := range keys {
			if reached[k] {
				got = append(got, k)
			}
		}
		assert.Equal(t, want, got, "identity %q", id)
	}
}

// The revocation check on the certificate page (R64, D5, HB-17): whether the authority revoked it, and the last check
// with its error as an errorRef (null before the first check).
func TestCertificateDTORevocationCheck(t *testing.T) {
	c := sampleCertificate()
	raw, err := json.Marshal(certificateDetailJSON(c, serviceRefs{}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"revocation_check":null`)
	assert.Contains(t, string(raw), `"revoked_by_authority":false`)

	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.FixedZone("x", 3600))
	c.RevokedByAuthority = true
	c.RevocationCheck = &inventory.RevocationCheck{Status: "unavailable", ErrorCode: "certificate.revocation_unreachable", CheckedAt: at,
		NextCheckAt: at.Add(time.Hour)}
	d := certificateDetailJSON(c, serviceRefs{})
	require.NotNil(t, d.RevocationCheck)
	require.NotNil(t, d.RevocationCheck.Error)
	assert.Equal(t, "ALC-CRT-0020", d.RevocationCheck.Error.Code)
	raw, err = json.Marshal(d)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"revoked_by_authority":true`)
	assert.Contains(t, string(raw), `"revocation_check":{"status":"unavailable","method":"","reason":"","revoked_at":null,"checked_at":"2026-10-24T11:00:00Z","next_check_at":"2026-10-24T12:00:00Z","error":{"code":"ALC-CRT-0020","reason":"certificate.revocation_unreachable"}}`)

	c.RevocationCheck = &inventory.RevocationCheck{Status: "revoked", Method: "ocsp", Reason: "keyCompromise", RevokedAt: &at, CheckedAt: at, NextCheckAt: at}
	raw, err = json.Marshal(certificateDetailJSON(c, serviceRefs{}))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"revoked_at":"2026-10-24T11:00:00Z"`)
	assert.Contains(t, string(raw), `"error":null`)
}
