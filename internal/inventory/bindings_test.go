package inventory

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/rbac"
)

func TestMapBindingError(t *testing.T) {
	assert.ErrorIs(t, mapBindingError(&pgconn.PgError{Code: "23505", ConstraintName: "bindings_one_live"}), ErrBindingExists)
	assert.ErrorIs(t, mapBindingError(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23503", ConstraintName: "bindings_vault"})), ErrKVCertificateMissing,
		"the composite key refuses a certificate and vault that do not belong together: a closed error, never a SQLSTATE")
	other := &pgconn.PgError{Code: "23505", ConstraintName: "something_else"}
	assert.Same(t, other, mapBindingError(other), "other database errors pass through")
	assert.NoError(t, mapBindingError(nil))
	plain := errors.New("x")
	assert.Equal(t, plain, mapBindingError(plain))
}

func TestVersionRefusalTable(t *testing.T) {
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	cert, row := uuid.New(), uuid.New()
	good := deployVersion{id: uuid.New(), certificate: cert, certificateRow: &row, version: "v", enabled: true, exportable: ptrTo(true)}
	c := kvCertInfo{id: cert}
	leaf := deployCertificate{algorithm: "ecdsa", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	admin, operator := Actor{Role: rbac.Admin}, Actor{Role: rbac.Operator}
	for name, tc := range map[string]struct {
		mutate func(*deployVersion, *kvCertInfo, *deployCertificate)
		actor  Actor
		reason string
		err    error
	}{
		"deployable":             {func(*deployVersion, *kvCertInfo, *deployCertificate) {}, operator, "", nil},
		"another certificate":    {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.certificate = uuid.New() }, admin, "version_not_deployable", ErrVersionNotDeployable},
		"certificate removed":    {func(_ *deployVersion, c *kvCertInfo, _ *deployCertificate) { c.missing = true }, admin, "certificate_missing", ErrKVCertificateMissing},
		"no details":             {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.certificateRow = nil }, admin, "version_not_deployable", ErrVersionNotDeployable},
		"not exportable":         {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.exportable = ptrTo(false) }, admin, "not_exportable", ErrNotExportable},
		"exportability unknown":  {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.exportable = nil }, operator, "", nil},
		"disabled":               {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.enabled = false }, admin, "version_disabled", ErrVersionDisabled},
		"expired":                {func(_ *deployVersion, _ *kvCertInfo, l *deployCertificate) { l.notAfter = now }, admin, "expired", ErrCertificateExpired},
		"not yet valid":          {func(_ *deployVersion, _ *kvCertInfo, l *deployCertificate) { l.notBefore = now.Add(time.Second) }, admin, "not_yet_valid", ErrCertificateNotYetValid},
		"unsupported key":        {func(_ *deployVersion, _ *kvCertInfo, l *deployCertificate) { l.algorithm = "ed25519" }, admin, "unsupported_key", ErrUnsupportedKey},
		"held, an Operator":      {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.held, v.heldReason = true, "license" }, operator, "held_needs_admin", ErrHeldNeedsAdmin},
		"held, an Administrator": {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.held, v.heldReason = true, "license" }, admin, "", nil},
		"held and disabled":      {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) { v.held, v.enabled = true, false }, admin, "version_disabled", ErrVersionDisabled},
		"held for the chain": {func(v *deployVersion, _ *kvCertInfo, _ *deployCertificate) {
			v.held, v.heldReason = true, "incomplete_chain"
		}, operator, "held_needs_admin", ErrHeldNeedsAdmin},
	} {
		v, cc, l := good, c, leaf
		tc.mutate(&v, &cc, &l)
		reason, err := versionRefusal(v, cc, l, tc.actor, now)
		assert.Equal(t, tc.reason, reason, name)
		if tc.err == nil {
			assert.NoError(t, err, name)
		} else {
			assert.ErrorIs(t, err, tc.err, name)
		}
	}
}

func ptrTo[T any](v T) *T { return &v }

func TestCertificateRefusal(t *testing.T) {
	for name, tc := range map[string]struct {
		c      kvCertInfo
		reason string
		err    error
	}{
		"fine":            {kvCertInfo{keyType: "ecdsa"}, "", nil},
		"unknown details": {kvCertInfo{}, "", nil},
		"missing":         {kvCertInfo{missing: true}, "certificate_missing", ErrKVCertificateMissing},
		"not exportable":  {kvCertInfo{exportable: ptrTo(false)}, "not_exportable", ErrNotExportable},
		"other key type":  {kvCertInfo{keyType: "other"}, "unsupported_key", ErrUnsupportedKey},
	} {
		reason, err := certificateRefusal(tc.c)
		assert.Equal(t, tc.reason, reason, name)
		if tc.err == nil {
			assert.NoError(t, err, name)
		} else {
			assert.ErrorIs(t, err, tc.err, name)
		}
	}
}

func TestLocationCursorRoundTripAndRefusals(t *testing.T) {
	id := uuid.New()
	got, ok := decodeLocationCursor(encodeLocationCursor("web-01", "/etc/nginx/a.crt", id))
	require.True(t, ok)
	assert.Equal(t, locationCursor{name: "web-01", path: "/etc/nginx/a.crt", id: id}, got)
	for name, c := range map[string]string{
		"not base64": "!!",
		"two parts":  encodeRaw("a\x00b"),
		"four parts": encodeRaw("a\x00b\x00" + id.String() + "\x00c"),
		"bad id":     encodeRaw("a\x00b\x00nope"),
		"upper id":   encodeRaw("a\x00b\x00" + "ABCDEFAB-0000-0000-0000-000000000000"),
		"not utf8":   encodeRaw("\xff\x00b\x00" + id.String()),
	} {
		_, ok := decodeLocationCursor(c)
		assert.False(t, ok, name)
	}
}

func TestValidateLocationIDs(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	assert.Empty(t, validateLocationIDs([]uuid.UUID{a, b}, 2))
	assert.NotEmpty(t, validateLocationIDs(nil, 2))
	assert.NotEmpty(t, validateLocationIDs([]uuid.UUID{a, b, uuid.New()}, 2))
	assert.NotEmpty(t, validateLocationIDs([]uuid.UUID{a, a}, 2))
	assert.NotEmpty(t, validateLocationIDs([]uuid.UUID{uuid.Nil}, 2))
}

func TestServerNames(t *testing.T) {
	assert.Equal(t, []string{}, serverNames(nil))
	assert.Equal(t, []string{"a", "b", "c"}, serverNames([]providers.CertServer{{Names: []string{"a", "b"}}, {Names: []string{"b", "c"}}}))
}

func TestDenialDetailsNamesTheWebsiteOnlyWhenThereIsOne(t *testing.T) {
	loc := uuid.New()
	assert.Equal(t, map[string]string{"binding_id": "x", "reason": "r"}, denialDetails(bindingDenial{reason: "r"}, map[string]string{"binding_id": "x"}))
	assert.Equal(t, map[string]string{"reason": "r", "location_id": loc.String()}, denialDetails(bindingDenial{reason: "r", location: loc}, map[string]string{}))
}

func encodeRaw(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
