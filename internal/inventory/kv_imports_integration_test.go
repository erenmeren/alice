//go:build integration

package inventory_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// importFixture is the bind fixture (a vault "prod" with web-cert, second-cert, ...; an uploaded ECDSA
// certificate f.cert with its key, an RSA one, one without a key) for imports.
type importFixture struct {
	*bindFixture
}

func newImportFixture(t *testing.T) *importFixture { return &importFixture{newBindFixture(t)} }

func (f *importFixture) request(name string, confirm bool) (inventory.KVImport, error) {
	return f.h.svc.RequestImport(f.h.ctx, f.admin, inventory.ImportInput{VaultID: f.vault, CertificateID: f.cert.ID, Name: name, ConfirmExisting: confirm})
}

func (f *importFixture) mustRequest(name string, confirm bool) inventory.KVImport {
	f.h.t.Helper()
	im, err := f.request(name, confirm)
	require.NoError(f.h.t, err)
	return im
}

func (f *importFixture) thumb() string { return azureid.ThumbprintOf(f.nw.Cert.Raw) }

func (f *importFixture) created(version int) providers.ImportResult {
	return providers.ImportResult{Outcome: providers.ImportCreated, Version: ver(version), Thumbprint: f.thumb(), CER: f.nw.Cert.Raw}
}

func (f *importFixture) get(id uuid.UUID) inventory.KVImport {
	f.h.t.Helper()
	// Read as a job run reads (a claim): the vault may be deleted by the test, and the API's check is pinned elsewhere.
	var job uuid.UUID
	require.NoError(f.h.t, f.h.db.Owner.QueryRow(f.h.ctx, "SELECT coalesce(job_id, gen_random_uuid()) FROM kv_imports WHERE id = $1", id).Scan(&job))
	im, err := f.h.svc.Import(inventory.WithClaim(f.h.ctx, inventory.Claim{JobID: job, Attempt: 1}), f.vault, id)
	require.NoError(f.h.t, err)
	return im
}

// toState brings a fresh import of name to the state.
func (f *importFixture) toState(name, state string) inventory.KVImport {
	f.h.t.Helper()
	im := f.mustRequest(name, false)
	ctx := f.h.ctx
	if state == inventory.ImportQueued {
		return im
	}
	require.NoError(f.h.t, f.h.svc.MarkImportSent(ctx, im.ID))
	var err error
	switch state {
	case inventory.ImportRunning:
	case inventory.ImportSucceeded:
		_, err = f.h.svc.FinishImport(ctx, im.ID, f.created(7), nil)
	case inventory.ImportFailed:
		_, err = f.h.svc.FinishImport(ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused}, providers.NewError("azure.forbidden", false, nil, nil))
	case inventory.ImportUncertain:
		_, err = f.h.svc.FinishImport(ctx, im.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("connection reset"))
	}
	require.NoError(f.h.t, err)
	got := f.get(im.ID)
	require.Equal(f.h.t, state, got.State)
	return got
}

func (f *importFixture) imports() int { return f.h.count("SELECT count(*) FROM kv_imports") }

// poll lets a poll see name with the leaf as version n, created at the time.
func (f *importFixture) poll(name string, leaf pki.Leaf, n int, created time.Time) {
	f.h.t.Helper()
	f.h.reconcile(f.vault, kvResult(f.h.kvc(name, leaf, ver(n), created, true)))
}

func TestImportStateMachine(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx

	// A new name: queued, thumbprint = the leaf's x5t, a job for the vault, an audit row.
	im := f.mustRequest("fresh-name", false)
	assert.Equal(t, inventory.ImportQueued, im.State)
	assert.False(t, im.NewVersion)
	assert.Equal(t, f.thumb(), im.Thumbprint)
	assert.Equal(t, f.vault, im.VaultID)
	assert.Equal(t, f.cert.ID, im.CertificateID)
	assert.Nil(t, im.SentAt)
	require.NotNil(t, im.JobID)
	var job *inventory.JobRequest
	for _, r := range h.jobs.requests() {
		if r.Type == inventory.JobKVImport {
			job = &r
		}
	}
	require.NotNil(t, job)
	assert.Equal(t, f.vault, job.TargetID)
	assert.Equal(t, map[string]string{"import_id": im.ID.String()}, job.Payload)
	assert.Equal(t, "kv.import:"+im.ID.String(), job.DedupeKey)
	assert.Equal(t, "user", job.Kind)
	ev := h.auditDetails("kv.import.requested")
	require.Len(t, ev, 1)
	assert.Equal(t, im.ID.String(), ev[0]["import_id"])
	assert.Equal(t, "fresh-name", ev[0]["certificate_name"])
	assert.Equal(t, f.thumb(), ev[0]["thumbprint"])
	assert.Equal(t, "false", ev[0]["new_version"])

	// Refusals: each audited kv.import.denied, nothing stored.
	n := f.imports()
	denied := func(what string, want error, reason string, a inventory.Actor, in inventory.ImportInput) {
		t.Helper()
		before := h.audits("kv.import.denied")
		_, err := h.svc.RequestImport(ctx, a, in)
		assert.ErrorIs(t, err, want, what)
		assert.Equal(t, before+1, h.audits("kv.import.denied"), what)
		d := h.auditDetails("kv.import.denied")
		assert.Equal(t, reason, d[len(d)-1]["reason"], what)
		assert.Equal(t, n, f.imports(), "%s: nothing stored", what)
	}
	in := func(mutate func(*inventory.ImportInput)) inventory.ImportInput {
		i := inventory.ImportInput{VaultID: f.vault, CertificateID: f.cert.ID, Name: "other-name"}
		mutate(&i)
		return i
	}
	denied("no private key", inventory.ErrNoPrivateKey, "no_private_key", f.admin, in(func(i *inventory.ImportInput) { i.CertificateID = f.discovered.ID }))
	denied("unknown certificate", inventory.ErrNotFound, "certificate_not_found", f.admin, in(func(i *inventory.ImportInput) { i.CertificateID = uuid.New() }))
	denied("an Operator", inventory.ErrAdminRequired, "admin_required", f.operator, in(func(*inventory.ImportInput) {}))
	denied("a server", inventory.ErrNotAVault, "not_a_vault", f.admin, in(func(i *inventory.ImportInput) { i.VaultID = f.target1 }))
	denied("an unknown vault", inventory.ErrNotFound, "vault_not_found", f.admin, in(func(i *inventory.ImportInput) { i.VaultID = uuid.New() }))
	for _, name := range []string{"", "has space", "dot.dot", strings.Repeat("a", 128), "ü"} {
		_, err := h.svc.RequestImport(ctx, f.admin, in(func(i *inventory.ImportInput) { i.Name = name }))
		var errs validate.Errors
		require.ErrorAs(t, err, &errs, "name %q", name)
		assert.Equal(t, "name", errs[0].Field)
	}
	assert.Equal(t, n, f.imports())
	// An existing name needs the confirmation (the comparison folds ASCII case).
	_, err := f.request("WEB-cert", false)
	var ce *inventory.ImportConfirmError
	require.ErrorAs(t, err, &ce)
	assert.ErrorIs(t, err, inventory.ErrImportConfirmNeeded)
	assert.Equal(t, "web-cert", ce.CertificateName, "the name as the vault has it")
	assert.Equal(t, "confirm_needed", h.auditDetails("kv.import.denied")[len(h.auditDetails("kv.import.denied"))-1]["reason"])
	assert.Equal(t, n, f.imports())
	again, err := f.request("WEB-cert", true)
	require.NoError(t, err)
	assert.True(t, again.NewVersion)
	assert.Equal(t, "true", h.auditDetails("kv.import.requested")[1]["new_version"])
	n = f.imports()
	// One active import per vault and folded name.
	denied("the same name while queued", inventory.ErrImportInProgress, "in_progress", f.admin, in(func(i *inventory.ImportInput) { i.Name = "FRESH-name" }))
	denied("the same name, confirmed, while queued", inventory.ErrImportInProgress, "in_progress", f.admin,
		in(func(i *inventory.ImportInput) { i.Name, i.ConfirmExisting = "Web-Cert", true }))
	// A disabled vault.
	f.exec("UPDATE targets SET status = 'disabled' WHERE id = $1", f.vault)
	denied("a disabled vault", inventory.ErrVaultUnavailable, "vault_unavailable", f.admin, in(func(*inventory.ImportInput) {}))
	f.exec("UPDATE targets SET status = 'ok' WHERE id = $1", f.vault)
	// An expired certificate.
	f.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", f.cert.ID, h.clock.Now().Add(-time.Second))
	denied("expired", inventory.ErrCertificateExpired, "expired", f.admin, in(func(*inventory.ImportInput) {}))
	f.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", f.cert.ID, h.clock.Now().Add(24*time.Hour))
	// In lock: nothing reaches the vault (L-26).
	h.clock.Advance(40 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(ctx))
	f.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", f.cert.ID, h.clock.Now().Add(24*time.Hour))
	denied("the license is locked", license.ErrLocked, "locked", f.admin, in(func(*inventory.ImportInput) {}))
	h.installLicense("LIC-IMP", 5, 365)
	require.NoError(t, h.lic.Allow(license.ClassChange))
}

// The state table: every operation in every state, as the schema's trigger allows it.
func TestImportStateTable(t *testing.T) {
	type op struct {
		name string
		do   func(f *importFixture, im inventory.KVImport) error
	}
	ops := []op{
		{"mark sent", func(f *importFixture, im inventory.KVImport) error { return f.h.svc.MarkImportSent(f.h.ctx, im.ID) }},
		{"finish created", func(f *importFixture, im inventory.KVImport) error {
			_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, f.created(8), nil)
			return err
		}},
		{"finish refused", func(f *importFixture, im inventory.KVImport) error {
			_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused}, providers.NewError("azure.forbidden", false, nil, nil))
			return err
		}},
		{"finish uncertain", func(f *importFixture, im inventory.KVImport) error {
			_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("reset"))
			return err
		}},
		{"fail queued", func(f *importFixture, im inventory.KVImport) error {
			_, err := f.h.svc.FailQueuedImport(f.h.ctx, im.ID, "target.disabled")
			return err
		}},
		{"material", func(f *importFixture, im inventory.KVImport) error {
			m, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
			m.Request.PFX.Zero()
			return err
		}},
		{"a poll that sees the version", func(f *importFixture, im inventory.KVImport) error {
			f.poll(im.Name, f.nw, 8, f.h.clock.Now().Add(time.Minute))
			return nil
		}},
	}
	// state -> op -> state afterwards ("" = the operation is refused with ErrImportState and nothing changes)
	table := map[string]map[string]string{
		inventory.ImportQueued: {"mark sent": inventory.ImportRunning, "finish created": "", "finish refused": inventory.ImportFailed, "finish uncertain": "",
			"fail queued": inventory.ImportFailed, "material": inventory.ImportQueued, "a poll that sees the version": inventory.ImportQueued},
		inventory.ImportRunning: {"mark sent": "", "finish created": inventory.ImportSucceeded, "finish refused": inventory.ImportFailed,
			"finish uncertain": inventory.ImportUncertain, "fail queued": "", "material": "", "a poll that sees the version": inventory.ImportRunning},
		inventory.ImportUncertain: {"mark sent": "", "finish created": "", "finish refused": "", "finish uncertain": "", "fail queued": "", "material": "",
			"a poll that sees the version": inventory.ImportSucceeded},
		inventory.ImportSucceeded: {"mark sent": "", "finish created": "", "finish refused": "", "finish uncertain": "", "fail queued": "", "material": "",
			"a poll that sees the version": inventory.ImportSucceeded},
		inventory.ImportFailed: {"mark sent": "", "finish created": "", "finish refused": "", "finish uncertain": "", "fail queued": "", "material": "",
			"a poll that sees the version": inventory.ImportFailed},
	}
	for state, row := range table {
		for _, o := range ops {
			t.Run(state+"/"+o.name, func(t *testing.T) {
				f := newImportFixture(t)
				im := f.toState("walk-"+state, state)
				before := f.get(im.ID)
				err := o.do(f, im)
				want := row[o.name]
				after := f.get(im.ID)
				if want == "" {
					assert.ErrorIs(t, err, inventory.ErrImportState)
					assert.Equal(t, before, after, "a refused step changes nothing")
					return
				}
				if o.name != "a poll that sees the version" {
					require.NoError(t, err)
				}
				assert.Equal(t, want, after.State)
				if state == inventory.ImportQueued && o.name == "mark sent" {
					require.NotNil(t, after.SentAt)
				}
				if state != inventory.ImportQueued {
					assert.Equal(t, before.SentAt, after.SentAt, "sent_at is set once")
				}
				if want == inventory.ImportSucceeded || want == inventory.ImportFailed {
					assert.NotNil(t, after.FinishedAt)
				} else {
					assert.Nil(t, after.FinishedAt)
				}
				if before.State == inventory.ImportSucceeded || before.State == inventory.ImportFailed {
					assert.Equal(t, before, after, "a finished import is never changed again")
				}
			})
		}
	}
}

func TestImportMaterialBuildsThePFXFromTheValidatedLeaf(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx
	im := f.mustRequest("pfx-name", false)
	m, err := h.svc.ImportMaterial(ctx, im.ID)
	require.NoError(t, err)
	defer m.Request.PFX.Zero()
	assert.Equal(t, f.vault, m.VaultID)
	r := m.Request
	assert.Equal(t, im.ID, r.OperationID)
	assert.Equal(t, "pfx-name", r.Name)
	assert.Equal(t, f.thumb(), r.LeafThumbprint)
	assert.Equal(t, "ecdsa", r.KeyType)
	assert.Equal(t, 256, r.KeySize)
	assert.False(t, r.ReplaceExisting)
	require.NoError(t, r.Validate())
	key, leaf, chain, err := pkcs12.DecodeChain(r.PFX.Bytes(), "")
	require.NoError(t, err)
	assert.True(t, f.nw.Cert.Equal(leaf), "the leaf of the stored certificate")
	require.NotEmpty(t, chain, "the intermediate travels with it")
	block, _ := pem.Decode(f.nw.KeyPEM)
	require.NotNil(t, block)
	wantKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, wantKey.(interface{ Equal(crypto.PrivateKey) bool }).Equal(key), "the stored key")

	// The confirmation travels as ReplaceExisting; an RSA certificate says rsa and its size.
	conf := f.mustRequest("web-cert", true)
	m2, err := h.svc.ImportMaterial(ctx, conf.ID)
	require.NoError(t, err)
	assert.True(t, m2.Request.ReplaceExisting)
	m2.Request.PFX.Zero()
	rsaIm, err := h.svc.RequestImport(ctx, f.admin, inventory.ImportInput{VaultID: f.vault, CertificateID: f.deployFixture.rsaCert.ID, Name: "rsa-name"})
	require.NoError(t, err)
	m3, err := h.svc.ImportMaterial(ctx, rsaIm.ID)
	require.NoError(t, err)
	assert.Equal(t, "rsa", m3.Request.KeyType)
	assert.Equal(t, 2048, m3.Request.KeySize)
	assert.Equal(t, azureid.ThumbprintOf(f.rsaLeaf.Cert.Raw), m3.Request.LeafThumbprint)
	m3.Request.PFX.Zero()

	// Only a queued import; fenced by the claim; refused when the certificate changed or expired.
	claimed := inventory.WithClaim(ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	_, err = h.svc.ImportMaterial(claimed, im.ID)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	f.exec("UPDATE kv_imports SET thumbprint = $2 WHERE id = $1", im.ID, strings.Repeat("ab", 20))
	_, err = h.svc.ImportMaterial(ctx, im.ID)
	assert.ErrorIs(t, err, inventory.ErrImportChanged)
	f.exec("UPDATE kv_imports SET thumbprint = $2 WHERE id = $1", im.ID, f.thumb())
	f.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", f.cert.ID, h.clock.Now().Add(-time.Second))
	_, err = h.svc.ImportMaterial(ctx, im.ID)
	assert.ErrorIs(t, err, inventory.ErrCertificateExpired, "an expired leaf is refused before the PFX is built")
	f.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", f.cert.ID, h.clock.Now().Add(24*time.Hour))
	f.exec("UPDATE targets SET status = 'disabled' WHERE id = $1", f.vault)
	_, err = h.svc.ImportMaterial(ctx, im.ID)
	assert.ErrorIs(t, err, inventory.ErrVaultUnavailable)
	f.exec("UPDATE targets SET deleted_at = now() WHERE id = $1", f.vault)
	_, err = h.svc.ImportMaterial(ctx, im.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.ImportMaterial(ctx, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

// The key, the PFX and every buffer between are wiped on every path; nothing of them is stored.
func TestImportMaterialZeroesTheKeyAndThePFX(t *testing.T) {
	type seen struct{ der, pfx []byte }
	run := func(t *testing.T, panicAt string) (seen, any, inventory.ImportMaterial, error) {
		f := newImportFixture(t)
		im := f.mustRequest("zero-name", false)
		var s seen
		restore := inventory.SetImportMaterialHook(func(stage string, b []byte) {
			switch stage {
			case "der":
				s.der = b
			case "pfx":
				s.pfx = b
			}
			if len(b) > 0 && allZero(b) {
				t.Errorf("the %s buffer is zero before it is used", stage)
			}
			if stage == panicAt {
				panic("injected")
			}
		})
		defer restore()
		var (
			m   inventory.ImportMaterial
			err error
			rec any
		)
		func() {
			defer func() { rec = recover() }()
			m, err = f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		}()
		return s, rec, m, err
	}
	t.Run("success: the key is wiped, the PFX is the caller's", func(t *testing.T) {
		s, _, m, err := run(t, "")
		require.NoError(t, err)
		require.NotEmpty(t, s.der)
		assert.True(t, allZero(s.der), "the stored key, decrypted for the PFX")
		assert.False(t, allZero(m.Request.PFX.Bytes()))
		m.Request.PFX.Zero()
		assert.True(t, allZero(s.pfx), "the hook saw the very buffer the caller zeroes")
	})
	t.Run("a panic once the key is decrypted", func(t *testing.T) {
		s, rec, m, _ := run(t, "der")
		assert.Equal(t, "injected", rec)
		require.NotEmpty(t, s.der)
		assert.True(t, allZero(s.der))
		assert.Zero(t, len(m.Request.PFX.Bytes()))
	})
	t.Run("a panic once the PFX is built", func(t *testing.T) {
		s, rec, _, _ := run(t, "pfx")
		assert.Equal(t, "injected", rec)
		require.NotEmpty(t, s.der)
		require.NotEmpty(t, s.pfx)
		assert.True(t, allZero(s.der))
		assert.True(t, allZero(s.pfx), "the PFX is wiped when the step panics")
	})
}

func TestFinishImportOutcomes(t *testing.T) {
	t.Run("created: succeeded, the vault rows stored at once, audited", func(t *testing.T) {
		f := newImportFixture(t)
		h := f.h
		im := f.toState("new-cert", inventory.ImportRunning)
		got, err := h.svc.FinishImport(h.ctx, im.ID, f.created(9), nil)
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportSucceeded, got.State)
		assert.Equal(t, ver(9), got.Version)
		require.NotNil(t, got.FinishedAt)
		row := h.certRow(f.vault, "new-cert")
		assert.Equal(t, ver(9), row.Version)
		assert.Equal(t, f.thumb(), row.Thumb)
		assert.Equal(t, "ecdsa", row.KeyType)
		assert.False(t, row.Pending)
		require.NotNil(t, row.Exportable)
		assert.True(t, *row.Exportable)
		vr := h.versionRows(row.ID)
		require.Len(t, vr, 1)
		v := vr[ver(9)]
		assert.Equal(t, f.thumb(), v.Thumb)
		assert.False(t, v.Held)
		require.NotNil(t, v.CertID)
		var source string
		require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT source FROM certificates WHERE id = $1", *v.CertID).Scan(&source))
		assert.Equal(t, "uploaded", source, "the version points at the certificate Alice holds, key included")
		ev := h.auditDetails("kv.import.succeeded")
		require.Len(t, ev, 1)
		assert.Equal(t, ver(9), ev[0]["version"])
		assert.Equal(t, im.ID.String(), ev[0]["import_id"])
		assert.Zero(t, h.emails("kv.import_failed"))
	})

	t.Run("refused: failed with the closed code and the allowlisted params, one mail", func(t *testing.T) {
		f := newImportFixture(t)
		h := f.h
		im := f.toState("denied-cert", inventory.ImportRunning)
		cause := providers.NewError("azure.forbidden", false, errors.New("canary-raw-azure-text"), map[string]string{
			"role": "Key Vault Certificates Officer", "model": "rbac", "azure_request_id": "req-1", "secret_junk": "must-not-be-stored"})
		got, err := h.svc.FinishImport(h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused}, cause)
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportFailed, got.State)
		assert.Equal(t, "azure.forbidden", got.ErrorCode)
		assert.Equal(t, map[string]string{"role": "Key Vault Certificates Officer", "model": "rbac", "azure_request_id": "req-1"}, got.ErrorParams)
		assert.False(t, got.CanRetry)
		assert.Equal(t, 1, h.audits("kv.import.failed"))
		assert.Equal(t, 1, h.emails("kv.import_failed"))
		assert.NotContains(t, dumpEverything(h), "canary-raw-azure-text")
		assert.NotContains(t, dumpEverything(h), "must-not-be-stored")
		assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates WHERE lower(name) = 'denied-cert'"), "nothing was created")
	})

	t.Run("refused with the name existing: the confirmation is what is missing", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("stale-name", inventory.ImportRunning)
		got, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError(providers.CodeKVImportNameExists, false, nil, nil))
		require.NoError(t, err)
		assert.Equal(t, inventory.ReasonImportConfirmNeeded, got.ErrorCode)
	})

	t.Run("refused before anything was sent: failed, and a new request is accepted", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("retry-name", inventory.ImportRunning)
		got, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused}, providers.NewError("azure.unreachable", true, nil, nil))
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportFailed, got.State)
		assert.True(t, got.CanRetry, "nothing reached the vault: the state machine shows it as a failed import that may be requested again")
		again, err := f.request("retry-name", false)
		require.NoError(t, err)
		assert.NotEqual(t, im.ID, again.ID)
		assert.Equal(t, inventory.ImportQueued, again.State)
	})

	t.Run("uncertain: no mail, never sent again, the name stays blocked", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("lost-answer", inventory.ImportRunning)
		got, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("read: connection reset"))
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportUncertain, got.State)
		assert.Nil(t, got.FinishedAt)
		assert.Equal(t, 1, f.h.audits("kv.import.uncertain"))
		assert.Zero(t, f.h.emails("kv.import_failed"))
		_, err = f.request("lost-answer", false)
		assert.ErrorIs(t, err, inventory.ErrImportInProgress)
		_, err = f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		assert.ErrorIs(t, err, inventory.ErrImportState, "an uncertain import is never built again, so never sent again")
	})

	t.Run("a provider that breaks its contract is uncertain", func(t *testing.T) {
		for name, tc := range map[string]struct {
			res   func(f *importFixture) providers.ImportResult
			cause error
		}{
			"created with an error": {func(f *importFixture) providers.ImportResult { return f.created(5) }, errors.New("boom")},
			"created for another leaf": {func(f *importFixture) providers.ImportResult {
				r := f.created(5)
				r.Thumbprint = strings.Repeat("ab", 20)
				return r
			}, nil},
			"refused by a transport": {func(*importFixture) providers.ImportResult {
				return providers.ImportResult{Outcome: providers.ImportRefused}
			}, context.DeadlineExceeded},
			"a blank outcome": {func(*importFixture) providers.ImportResult { return providers.ImportResult{} }, nil},
			"refused with a plain error": {func(*importFixture) providers.ImportResult {
				return providers.ImportResult{Outcome: providers.ImportRefused}
			}, errors.New("plain")},
			"created, another thumbprint than the request": {func(f *importFixture) providers.ImportResult {
				other := f.issue("other.example.test", pki.ECDSA256)
				return providers.ImportResult{Outcome: providers.ImportCreated, Version: ver(5), Thumbprint: azureid.ThumbprintOf(other.Cert.Raw), CER: other.Cert.Raw}
			}, nil},
		} {
			t.Run(name, func(t *testing.T) {
				f := newImportFixture(t)
				im := f.toState("breach-name", inventory.ImportRunning)
				got, err := f.h.svc.FinishImport(f.h.ctx, im.ID, tc.res(f), tc.cause)
				require.NoError(t, err)
				assert.Equal(t, inventory.ImportUncertain, got.State)
				assert.Zero(t, f.h.count("SELECT count(*) FROM kv_certificates WHERE lower(name) = 'breach-name'"), "no vault row from an answer that cannot be trusted")
			})
		}
	})

	t.Run("a queued import whose vault vanished fails cleanly", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.mustRequest("cancelled-name", false)
		got, err := f.h.svc.FailQueuedImport(f.h.ctx, im.ID, "target.disabled")
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportFailed, got.State)
		assert.Equal(t, "target.disabled", got.ErrorCode)
		assert.Nil(t, got.SentAt)
		assert.Equal(t, 1, f.h.emails("kv.import_failed"))
		_, err = f.h.svc.FailQueuedImport(f.h.ctx, im.ID, "not a code!")
		assert.Error(t, err)
	})

	t.Run("a stale claim writes nothing", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.mustRequest("claim-name", false)
		claimed := inventory.WithClaim(f.h.ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
		assert.ErrorIs(t, f.h.svc.MarkImportSent(claimed, im.ID), inventory.ErrClaimLost)
		require.NoError(t, f.h.svc.MarkImportSent(f.h.ctx, im.ID))
		_, err := f.h.svc.FinishImport(claimed, im.ID, f.created(3), nil)
		assert.ErrorIs(t, err, inventory.ErrClaimLost)
		assert.Equal(t, inventory.ImportRunning, f.get(im.ID).State)
		_, err = f.h.svc.FailQueuedImport(claimed, im.ID, "target.disabled")
		assert.ErrorIs(t, err, inventory.ErrClaimLost)
	})
}

// S14 and the 24 hours: an uncertain import is settled only by a later poll.
func TestImportSettlingFromPolls(t *testing.T) {
	uncertain := func(t *testing.T) (*importFixture, inventory.KVImport) {
		f := newImportFixture(t)
		f.h.clock.Advance(time.Minute)
		return f, f.toState("settle-name", inventory.ImportUncertain)
	}
	t.Run("a version of that name with the thumbprint, created after the request", func(t *testing.T) {
		f, im := uncertain(t)
		f.h.clock.Advance(time.Minute)
		f.poll("settle-name", f.nw, 4, f.h.clock.Now())
		got := f.get(im.ID)
		assert.Equal(t, inventory.ImportSucceeded, got.State)
		assert.Equal(t, ver(4), got.Version)
		require.NotNil(t, got.FinishedAt)
		ev := f.h.auditDetails("kv.import.settled")
		require.Len(t, ev, 1)
		assert.Equal(t, im.ID.String(), ev[0]["import_id"])
		assert.Equal(t, ver(4), ev[0]["version"])
		assert.Zero(t, f.h.emails("kv.import_failed"))
		// A later poll never changes it again, and another version does not either.
		before := f.get(im.ID)
		f.h.clock.Advance(48 * time.Hour)
		f.poll("settle-name", f.issue("x.example.test", pki.ECDSA256), 5, f.h.clock.Now())
		assert.Equal(t, before, f.get(im.ID))
	})
	t.Run("a certificate with that thumbprint that existed before the request does not settle it", func(t *testing.T) {
		f, im := uncertain(t)
		f.poll("settle-name", f.nw, 4, f.h.clock.Now().Add(-time.Hour))
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State)
		f.h.clock.Advance(25 * time.Hour)
		f.poll("settle-name", f.nw, 4, f.h.clock.Now().Add(-26*time.Hour))
		got := f.get(im.ID)
		assert.Equal(t, inventory.ImportFailed, got.State, "it ends as not confirmed")
		assert.Equal(t, inventory.ReasonImportOutcomeUnknown, got.ErrorCode)
	})
	t.Run("a version Alice stored before the request does not settle it, even when Azure's clock is ahead", func(t *testing.T) {
		f := newImportFixture(t)
		f.h.clock.Advance(time.Minute)
		// The same certificate is already in the vault; Azure's stamp is ahead of Alice's clock.
		f.poll("settle-name", f.nw, 3, f.h.clock.Now().Add(time.Hour))
		f.h.clock.Advance(time.Minute)
		im, err := f.request("settle-name", true)
		require.NoError(t, err)
		require.NoError(t, f.h.svc.MarkImportSent(f.h.ctx, im.ID))
		_, err = f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("connection reset"))
		require.NoError(t, err)
		f.h.clock.Advance(time.Minute)
		f.poll("settle-name", f.nw, 3, f.h.clock.Now().Add(time.Hour-2*time.Minute))
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State, "version 3 was known before the import was requested")
		f.h.clock.Advance(time.Minute)
		f.poll("settle-name", f.nw, 4, f.h.clock.Now().Add(time.Hour))
		got := f.get(im.ID)
		assert.Equal(t, inventory.ImportSucceeded, got.State)
		assert.Equal(t, ver(4), got.Version, "the version the import created")
	})
	t.Run("another name with that thumbprint does not settle it", func(t *testing.T) {
		f, im := uncertain(t)
		f.h.clock.Advance(time.Minute)
		f.poll("other-name", f.nw, 4, f.h.clock.Now())
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State)
	})
	t.Run("the vault's whole seconds against the request time", func(t *testing.T) {
		f := newImportFixture(t)
		f.h.clock.Advance(500 * time.Millisecond) // the request is half a second into the second
		im := f.toState("second-name", inventory.ImportUncertain)
		req := f.h.clock.Now()
		f.poll("second-name", f.nw, 4, req.Truncate(time.Second))
		assert.Equal(t, inventory.ImportSucceeded, f.get(im.ID).State, "created in the request's second counts")
		f2 := newImportFixture(t)
		f2.h.clock.Advance(500 * time.Millisecond)
		im2 := f2.toState("second-name", inventory.ImportUncertain)
		f2.poll("second-name", f2.nw, 4, f2.h.clock.Now().Truncate(time.Second).Add(-time.Second))
		assert.Equal(t, inventory.ImportUncertain, f2.get(im2.ID).State, "a second earlier does not")
	})
	t.Run("an unknown creation time cannot settle", func(t *testing.T) {
		f, im := uncertain(t)
		f.h.clock.Advance(time.Minute)
		c := f.h.kvc("settle-name", f.nw, ver(4), f.h.clock.Now(), true)
		c.Created = nil
		c.Versions[0].Created = nil
		f.h.reconcile(f.vault, kvResult(c))
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State)
		assert.Equal(t, 1, f.h.count("SELECT count(*) FROM kv_certificate_versions WHERE kv_created_at IS NULL AND thumbprint = $1", f.thumb()))
	})
	t.Run("24 hours without it: failed, outcome unknown, one mail; not before; not on a cut listing", func(t *testing.T) {
		f, im := uncertain(t)
		f.h.clock.Advance(23 * time.Hour)
		f.h.reconcile(f.vault, kvResult())
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State, "23 hours")
		f.h.clock.Advance(2 * time.Hour)
		cut := kvResult()
		cut.KV.Failures = []providers.KVListFailure{{Object: "certificates", Err: providers.NewError("azure.forbidden", false, nil, nil)}}
		f.h.reconcile(f.vault, cut)
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State, "the listing did not answer: the absence means nothing")
		f.h.reconcile(f.vault, kvResult())
		got := f.get(im.ID)
		assert.Equal(t, inventory.ImportFailed, got.State)
		assert.Equal(t, inventory.ReasonImportOutcomeUnknown, got.ErrorCode)
		assert.Equal(t, 1, f.h.emails("kv.import_outcome_unknown"))
		assert.Zero(t, f.h.emails("kv.import_failed"))
		assert.Equal(t, 1, f.h.audits("kv.import.failed"))
		f.h.reconcile(f.vault, kvResult())
		assert.Equal(t, 1, f.h.emails("kv.import_outcome_unknown"), "once")
		_, err := f.request("settle-name", false)
		assert.NoError(t, err, "the name is free again")
	})
}

// The import's own version row and the next poll agree: one row, the pointer on it, details read, nothing
// announced twice.
func TestImportCreatedThenPoll(t *testing.T) {
	f := newImportFixture(t)
	h := f.h
	im := f.toState("polled-name", inventory.ImportRunning)
	_, err := h.svc.FinishImport(h.ctx, im.ID, f.created(9), nil)
	require.NoError(t, err)
	announced := h.audits("kv.certificate.new_version")
	h.clock.Advance(time.Minute)
	f.poll("polled-name", f.nw, 9, h.clock.Now())
	row := h.certRow(f.vault, "polled-name")
	assert.Equal(t, ver(9), row.Version)
	assert.Equal(t, f.thumb(), row.Thumb)
	assert.False(t, row.Pending, "the details were read")
	assert.Len(t, h.versionRows(row.ID), 1, "one version row")
	assert.Equal(t, announced, h.audits("kv.certificate.new_version"), "the poll announces nothing the import already stored")
	assert.Equal(t, inventory.ImportSucceeded, f.get(im.ID).State)
}

// An import into an existing, bound name adds a version that follows the normal planner path.
func TestImportedVersionFollowsThePlanner(t *testing.T) {
	f := newAutoFixture(t, true)
	h := f.h
	leaf := f.issue("web.example.test", pki.ECDSA256)
	up, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(leaf))
	require.NoError(t, err)
	h.clock.Advance(time.Minute)
	im, err := h.svc.RequestImport(h.ctx, f.admin, inventory.ImportInput{VaultID: f.vault, CertificateID: up.ID, Name: "web-cert", ConfirmExisting: true})
	require.NoError(t, err)
	require.NoError(t, h.svc.MarkImportSent(h.ctx, im.ID))
	res := providers.ImportResult{Outcome: providers.ImportCreated, Version: ver(2), Thumbprint: azureid.ThumbprintOf(leaf.Cert.Raw), CER: leaf.Cert.Raw}
	h.clock.Advance(time.Second)
	_, err = h.svc.FinishImport(h.ctx, im.ID, res, nil)
	require.NoError(t, err)
	row := h.certRow(f.vault, "web-cert")
	assert.Equal(t, ver(2), row.Version, "the pointer moved to the imported version")
	assert.Equal(t, 3, f.plan(), "auto-deploy follows: one deployment per website")
	assert.Len(t, f.deps(ver(2)), 3)
	// The next poll agrees and plans nothing more.
	h.reconcile(f.vault, kvResult(h.kvc("web-cert", leaf, ver(2), h.clock.Now(), true)))
	assert.Zero(t, f.plan())
}

// Concurrent finishers and pollers of one import: it ends once.
func TestImportFinishRacesAPoll(t *testing.T) {
	f := newImportFixture(t)
	h := f.h
	im := f.toState("race-name", inventory.ImportUncertain)
	h.clock.Advance(time.Minute)
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				_, errs[i] = h.svc.ReconcileKV(h.ctx, f.vault, kvResult(h.kvc("race-name", f.nw, ver(4), h.clock.Now(), true)))
			} else {
				_, errs[i] = h.svc.ReconcileKV(h.ctx, f.vault, kvResult())
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 1, h.audits("kv.import.settled")+h.audits("kv.import.failed"), "settled once")
	assert.Equal(t, inventory.ImportSucceeded, f.get(im.ID).State)
}

// What an import leaves behind: no key, no PFX, in any form, whatever the outcome.
func TestImportLeavesNoKeyMaterialBehind(t *testing.T) {
	run := func(t *testing.T, name string, flow func(f *importFixture, im inventory.KVImport) []byte) {
		t.Run(name, func(t *testing.T) {
			f := newImportFixture(t)
			h := f.h
			im := f.mustRequest("quiet-name", false)
			pfx := flow(f, im)
			dump := dumpEverything(h)
			block, _ := pem.Decode(f.nw.KeyPEM)
			assert.Empty(t, keyLeaks(dump, block.Bytes, pfx), "the key and the PFX are nowhere (database rows, logs), in no encoding")
			assert.NotContains(t, dump, "PRIVATE KEY-----\n")
		})
	}
	build := func(f *importFixture, im inventory.KVImport) []byte {
		m, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		require.NoError(f.h.t, err)
		pfx := append([]byte(nil), m.Request.PFX.Bytes()...)
		m.Request.PFX.Zero()
		return pfx
	}
	run(t, "created", func(f *importFixture, im inventory.KVImport) []byte {
		pfx := build(f, im)
		require.NoError(t, f.h.svc.MarkImportSent(f.h.ctx, im.ID))
		_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, f.created(2), nil)
		require.NoError(t, err)
		return pfx
	})
	run(t, "refused", func(f *importFixture, im inventory.KVImport) []byte {
		pfx := build(f, im)
		require.NoError(t, f.h.svc.MarkImportSent(f.h.ctx, im.ID))
		_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused},
			providers.NewError("azure.forbidden", false, errors.New(base64.StdEncoding.EncodeToString(pfx[20:60])), map[string]string{"role": "Key Vault Certificates Officer"}))
		require.NoError(t, err)
		return pfx
	})
	run(t, "uncertain", func(f *importFixture, im inventory.KVImport) []byte {
		pfx := build(f, im)
		require.NoError(t, f.h.svc.MarkImportSent(f.h.ctx, im.ID))
		_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New(hex.EncodeToString(pfx[20:60])))
		require.NoError(t, err)
		return pfx
	})
	run(t, "a panic while the PFX is built", func(f *importFixture, im inventory.KVImport) []byte {
		defer inventory.SetImportMaterialHook(func(stage string, _ []byte) {
			if stage == "pfx" {
				panic("injected")
			}
		})()
		func() {
			defer func() { _ = recover() }()
			_, _ = f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		}()
		return nil
	})
	run(t, "expired", func(f *importFixture, im inventory.KVImport) []byte {
		f.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", f.cert.ID, f.h.clock.Now().Add(-time.Second))
		_, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		assert.ErrorIs(t, err, inventory.ErrCertificateExpired)
		return nil
	})
	run(t, "not yet valid", func(f *importFixture, im inventory.KVImport) []byte {
		f.exec("UPDATE certificates SET not_before = $2 WHERE id = $1", f.cert.ID, f.h.clock.Now().Add(time.Hour))
		_, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		assert.ErrorIs(t, err, inventory.ErrCertificateNotYetValid)
		return nil
	})
	run(t, "admin required", func(f *importFixture, im inventory.KVImport) []byte {
		f.exec("UPDATE users SET role = 'operator' WHERE id = $1", f.admin.UserID)
		_, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
		assert.ErrorIs(t, err, inventory.ErrAdminRequired)
		return nil
	})
}

// dumpEverything is every row of every table of the public schema as text, with the logs.
func dumpEverything(h *harness) string {
	h.t.Helper()
	rows, err := h.db.Owner.Query(h.ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")
	require.NoError(h.t, err)
	var tables []string
	for rows.Next() {
		var s string
		require.NoError(h.t, rows.Scan(&s))
		tables = append(tables, s)
	}
	rows.Close()
	var sb strings.Builder
	for _, table := range tables {
		rows, err := h.db.Owner.Query(h.ctx, `SELECT x::text FROM "`+table+`" x`)
		require.NoError(h.t, err)
		for rows.Next() {
			var s string
			require.NoError(h.t, rows.Scan(&s))
			sb.WriteString(table + ":" + s + "\n")
		}
		rows.Close()
	}
	sb.WriteString(h.logs.String())
	return sb.String()
}

// The edges: lists, unknown ids, a vault or certificate that is not usable, a queue that fails.
func TestImportEdges(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx
	a := f.mustRequest("edge-one", false)
	h.clock.Advance(time.Second)
	b := f.mustRequest("edge-two", false)
	list, err := h.svc.ListImports(ctx, f.vault, 10)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []uuid.UUID{b.ID, a.ID}, []uuid.UUID{list[0].ID, list[1].ID}, "newest first")
	for _, limit := range []int{0, 201} {
		_, err = h.svc.ListImports(ctx, f.vault, limit)
		var errs validate.Errors
		assert.ErrorAs(t, err, &errs)
	}
	other := h.vault("other-vault")
	_, err = h.svc.Import(ctx, other, a.ID)
	assert.ErrorIs(t, err, inventory.ErrNotFound, "another vault's import")
	_, err = h.svc.Import(ctx, f.vault, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.ErrorIs(t, h.svc.MarkImportSent(ctx, uuid.New()), inventory.ErrNotFound)
	_, err = h.svc.FinishImport(ctx, uuid.New(), f.created(1), nil)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.FailQueuedImport(ctx, uuid.New(), "target.disabled")
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	// Requests that cannot be made.
	_, err = h.svc.RequestImport(ctx, f.admin, inventory.ImportInput{Name: "x"})
	var errs validate.Errors
	require.ErrorAs(t, err, &errs)
	assert.Len(t, errs, 2, "both ids are missing")
	f.exec("UPDATE certificates SET key_algorithm = 'ed25519' WHERE id = $1", f.cert.ID)
	_, err = f.request("edge-ed", false)
	assert.ErrorIs(t, err, inventory.ErrUnsupportedKey)
	f.exec("UPDATE certificates SET key_algorithm = 'ecdsa' WHERE id = $1", f.cert.ID)
	f.exec("UPDATE certificates SET fingerprint_sha256 = $2 WHERE id = $1", f.cert.ID, strings.Repeat("ef", 32))
	_, err = f.request("edge-fp", false)
	assert.ErrorIs(t, err, inventory.ErrCertificateInvalid, "the stored leaf is not the row's certificate")
	f.exec("UPDATE certificates SET fingerprint_sha256 = $2 WHERE id = $1", f.cert.ID, pki.Fingerprint(f.nw.Cert))
	h.jobs.fail = errors.New("the queue is down")
	n := f.imports()
	_, err = f.request("edge-queue", false)
	assert.Error(t, err)
	assert.Equal(t, n, f.imports(), "the import and its job are one transaction")
	require.NoError(t, h.svc.MarkImportSent(ctx, a.ID))
	f.exec("UPDATE targets SET deleted_at = now() WHERE id = $1", f.vault)
	_, err = f.request("edge-deleted", false)
	assert.ErrorIs(t, err, inventory.ErrNotFound, "a deleted vault")
	// An answer that arrives for a vault that was deleted meanwhile is recorded; no vault rows are written.
	got, err := h.svc.FinishImport(ctx, a.ID, f.created(5), nil)
	require.NoError(t, err)
	assert.Equal(t, inventory.ImportSucceeded, got.State)
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificates WHERE lower(name) = 'edge-one'"))
}

// A version id the vault already holds with another thumbprint is never overwritten by an import's answer.
func TestFinishImportKeepsAVersionStoredWithAnotherThumbprint(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx
	other := f.issue("other.example.test", pki.ECDSA256)
	f.poll("clash-name", other, 9, h.clock.Now())
	im := f.mustRequest("clash-name", true)
	require.NoError(t, h.svc.MarkImportSent(ctx, im.ID))
	got, err := h.svc.FinishImport(ctx, im.ID, f.created(9), nil)
	require.NoError(t, err)
	assert.Equal(t, inventory.ImportSucceeded, got.State)
	row := h.certRow(f.vault, "clash-name")
	assert.Equal(t, azureid.ThumbprintOf(other.Cert.Raw), h.versionRows(row.ID)[ver(9)].Thumb, "the stored row is kept")
	assert.Equal(t, 1, h.audits("kv.certificate.version_conflict"))
	// An uncertain answer keeps the provider's closed code.
	im2 := f.mustRequest("clash-two", false)
	require.NoError(t, h.svc.MarkImportSent(ctx, im2.ID))
	u, err := h.svc.FinishImport(ctx, im2.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, providers.NewError("azure.unexpected_response", false, nil, nil))
	require.NoError(t, err)
	assert.Equal(t, "azure.unexpected_response", u.ErrorCode)
}

// Two bindings in one run share the run's batch.
func TestAutoDeployBatchIsSharedByBindings(t *testing.T) {
	defer inventory.SetAutoDeployBatch(2)()
	f := newAutoFixture(t, true)
	extra := f.moreLocations(2)
	other, err := f.h.svc.CreateBinding(f.h.ctx, f.admin, inventory.BindingInput{KVCertificateID: f.second, LocationIDs: extra})
	require.NoError(t, err)
	_, err = f.h.svc.SetAutoDeploy(f.h.ctx, f.admin, other.ID, other.Version, true)
	require.NoError(t, err)
	f.h.clock.Advance(time.Minute)
	f.h.reconcile(f.vault, kvResult(
		f.h.kvc("web-cert", f.issue("web.example.test", pki.ECDSA256), ver(2), f.h.clock.Now(), true),
		f.h.kvc("second-cert", f.issue("second.example.test", pki.ECDSA256), ver(3), f.h.clock.Now(), true)))
	assert.Equal(t, 2, f.plan(), "the run stops at its batch, whichever binding came first")
	assert.Equal(t, 2, f.plan(), "the next run does the next two")
	assert.Equal(t, 4, f.h.count("SELECT count(*) FROM deployments"))
}

// I3: a certificate row of that name needs the confirmation even when it is marked missing, and the error
// says whether a live binding with automatic deployment would deploy the imported version by itself.
func TestImportIntoABoundMissingNameNeedsConfirmation(t *testing.T) {
	f := newImportFixture(t)
	h := f.h
	bind := f.create(f.admin, f.web, f.loc1)
	on, err := h.svc.SetAutoDeploy(h.ctx, f.admin, bind.ID, bind.Version, true)
	require.NoError(t, err)
	_ = on
	f.exec("UPDATE kv_certificates SET missing_since = $2 WHERE id = $1", f.web, h.clock.Now())
	_, err = f.request("web-cert", false)
	var ce *inventory.ImportConfirmError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "web-cert", ce.CertificateName)
	assert.True(t, ce.Bound)
	assert.True(t, ce.AutoDeploy, "the websites would get it by themselves")
	assert.Zero(t, f.imports())
	// A missing certificate nobody bound asks too, and says nothing of deployment.
	f.exec("UPDATE kv_certificates SET missing_since = $2 WHERE id = $1", f.second, h.clock.Now())
	_, err = f.request("second-cert", false)
	require.ErrorAs(t, err, &ce)
	assert.False(t, ce.Bound)
	assert.False(t, ce.AutoDeploy)
}

// I4: the user's confirmation travels to the provider even when the inventory does not know the name (a
// refusal "the name exists" must not loop).
func TestImportConfirmationIsKeptForANameTheInventoryDoesNotKnow(t *testing.T) {
	f := newImportFixture(t)
	h := f.h
	im := f.mustRequest("unknown-to-alice", true)
	assert.True(t, im.NewVersion, "the confirmation is recorded")
	m, err := h.svc.ImportMaterial(h.ctx, im.ID)
	require.NoError(t, err)
	defer m.Request.PFX.Zero()
	assert.True(t, m.Request.ReplaceExisting)
	plain := f.mustRequest("really-new", false)
	m2, err := h.svc.ImportMaterial(h.ctx, plain.ID)
	require.NoError(t, err)
	defer m2.Request.PFX.Zero()
	assert.False(t, m2.Request.ReplaceExisting, "never true without the user's confirmation")
}

// I5: the requester must still be an enabled Administrator when the job runs.
func TestImportMaterialRechecksTheRequester(t *testing.T) {
	for name, sql := range map[string]string{
		"disabled": "UPDATE users SET disabled_at = now() WHERE id = $1",
		"demoted":  "UPDATE users SET role = 'operator' WHERE id = $1",
	} {
		t.Run(name, func(t *testing.T) {
			f := newImportFixture(t)
			im := f.mustRequest("recheck-name", false)
			f.exec(sql, f.admin.UserID)
			read := false
			defer inventory.SetImportMaterialHook(func(string, []byte) { read = true })()
			_, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
			assert.ErrorIs(t, err, inventory.ErrAdminRequired)
			assert.False(t, read, "the key is not read")
			got, err := f.h.svc.FailQueuedImport(f.h.ctx, im.ID, "kv.admin_required")
			require.NoError(t, err)
			assert.Equal(t, inventory.ImportFailed, got.State)
		})
	}
}

// I6: a leaf that is not valid yet is refused at the request and again when the job runs.
func TestImportRefusesALeafThatIsNotValidYet(t *testing.T) {
	f := newImportFixture(t)
	h := f.h
	im := f.mustRequest("early-name", false)
	f.exec("UPDATE certificates SET not_before = $2 WHERE id = $1", f.cert.ID, h.clock.Now().Add(time.Hour))
	read := false
	defer inventory.SetImportMaterialHook(func(string, []byte) { read = true })()
	_, err := h.svc.ImportMaterial(h.ctx, im.ID)
	assert.ErrorIs(t, err, inventory.ErrCertificateNotYetValid)
	assert.False(t, read, "before the key is read")
	n := f.imports()
	_, err = f.request("early-two", false)
	assert.ErrorIs(t, err, inventory.ErrCertificateNotYetValid)
	d := h.auditDetails("kv.import.denied")
	assert.Equal(t, "not_yet_valid", d[len(d)-1]["reason"])
	assert.Equal(t, n, f.imports())
}

// m4: an uncertain import cannot stay uncertain for ever.
func TestUncertainImportsEnd(t *testing.T) {
	t.Run("72 hours after the send, whatever the listings looked like", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("old-lost", inventory.ImportUncertain)
		f.h.clock.Advance(71 * time.Hour)
		n, err := f.h.svc.SweepImports(f.h.ctx)
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State)
		f.h.clock.Advance(2 * time.Hour)
		n, err = f.h.svc.SweepImports(f.h.ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		got := f.get(im.ID)
		assert.Equal(t, inventory.ImportFailed, got.State)
		assert.Equal(t, inventory.ReasonImportOutcomeUnknown, got.ErrorCode)
		assert.Equal(t, 1, f.h.emails("kv.import_outcome_unknown"))
		assert.Equal(t, 1, f.h.audits("kv.import.failed"))
		n, _ = f.h.svc.SweepImports(f.h.ctx)
		assert.Zero(t, n, "once")
	})
	t.Run("a poll with a cut listing and details pending ends it at 72 hours too", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("old-lost-two", inventory.ImportUncertain)
		f.h.clock.Advance(73 * time.Hour)
		cut := kvResult()
		cut.KV.Failures = []providers.KVListFailure{{Object: "certificates", Err: providers.NewError("azure.forbidden", false, nil, nil)}}
		f.h.reconcile(f.vault, cut)
		assert.Equal(t, inventory.ImportFailed, f.get(im.ID).State)
	})
	t.Run("a disabled vault follows the 72 hours", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("disabled-lost", inventory.ImportUncertain)
		f.exec("UPDATE targets SET status = 'disabled' WHERE id = $1", f.vault)
		f.h.clock.Advance(73 * time.Hour)
		_, err := f.h.svc.SweepImports(f.h.ctx)
		require.NoError(t, err)
		assert.Equal(t, inventory.ImportFailed, f.get(im.ID).State)
	})
	t.Run("deleting the vault ends its active imports", func(t *testing.T) {
		f := newImportFixture(t)
		queued := f.mustRequest("q-name", false)
		unc := f.toState("u-name", inventory.ImportUncertain)
		run := f.toState("r-name", inventory.ImportRunning)
		require.NoError(t, f.h.svc.DeleteVault(f.h.ctx, f.admin, f.vault, true))
		q, u, r := f.get(queued.ID), f.get(unc.ID), f.get(run.ID)
		assert.Equal(t, inventory.ImportFailed, q.State)
		assert.Equal(t, inventory.ReasonImportVaultDeleted, q.ErrorCode)
		assert.Equal(t, inventory.ImportFailed, u.State)
		assert.Equal(t, inventory.ReasonImportOutcomeUnknown, u.ErrorCode)
		assert.Equal(t, inventory.ImportFailed, r.State)
		assert.Equal(t, inventory.ReasonImportOutcomeUnknown, r.ErrorCode)
		assert.Zero(t, f.h.count("SELECT count(*) FROM kv_imports WHERE state IN ('queued', 'running', 'uncertain')"))
	})
	// A1: an import whose job ends without the handler finishing it does not block its name for ever.
	queuedEnds := func(name string, end func(f *importFixture, im inventory.KVImport)) {
		t.Run("queued import, job "+name+": failed, cancelled, and the name is free", func(t *testing.T) {
			f := newImportFixture(t)
			im := f.mustRequest("a1-name", false)
			healthy := f.mustRequest("a1-live", false)
			end(f, im)
			n, err := f.h.svc.SweepImports(f.h.ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, n)
			got := f.get(im.ID)
			assert.Equal(t, inventory.ImportFailed, got.State)
			assert.Equal(t, inventory.ReasonImportCancelled, got.ErrorCode)
			assert.True(t, got.CanRetry, "nothing was sent")
			assert.Equal(t, 1, f.h.audits("kv.import.failed"))
			assert.Equal(t, inventory.ImportQueued, f.get(healthy.ID).State, "a live job is left alone")
			// A late handler of the swept import sends nothing.
			assert.ErrorIs(t, f.h.svc.MarkImportSent(f.h.ctx, im.ID), inventory.ErrImportState)
			_, err = f.h.svc.ImportMaterial(f.h.ctx, im.ID)
			assert.ErrorIs(t, err, inventory.ErrImportState)
			n, err = f.h.svc.SweepImports(f.h.ctx)
			require.NoError(t, err)
			assert.Zero(t, n, "idempotent")
			_, err = f.request("a1-name", false)
			assert.NoError(t, err, "the name is accepted again")
		})
	}
	queuedEnds("cancelled", func(f *importFixture, im inventory.KVImport) {
		f.exec("UPDATE jobs SET status = 'cancelled' WHERE id = $1", *im.JobID)
	})
	queuedEnds("dead", func(f *importFixture, im inventory.KVImport) {
		f.exec("UPDATE jobs SET status = 'dead' WHERE id = $1", *im.JobID)
	})
	queuedEnds("failed", func(f *importFixture, im inventory.KVImport) {
		f.exec("UPDATE jobs SET status = 'failed' WHERE id = $1", *im.JobID)
	})
	queuedEnds("gone", func(f *importFixture, im inventory.KVImport) {
		f.exec("DELETE FROM jobs WHERE id = $1", *im.JobID)
	})
	for _, how := range []string{"dead after the mark", "failed after a created answer that could not be recorded", "cancelled", "gone"} {
		t.Run("running import, job "+how+": uncertain, then a poll settles it", func(t *testing.T) {
			f := newImportFixture(t)
			f.h.clock.Advance(time.Minute)
			im := f.toState("a1-run", inventory.ImportRunning)
			live := f.toState("a1-live-run", inventory.ImportRunning)
			switch how {
			case "gone":
				f.exec("DELETE FROM jobs WHERE id = $1", *im.JobID)
			case "cancelled":
				f.exec("UPDATE jobs SET status = 'cancelled' WHERE id = $1", *im.JobID)
			case "dead after the mark":
				f.exec("UPDATE jobs SET status = 'dead' WHERE id = $1", *im.JobID)
			default:
				f.exec("UPDATE jobs SET status = 'failed' WHERE id = $1", *im.JobID)
			}
			n, err := f.h.svc.SweepImports(f.h.ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, n)
			assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State)
			assert.Equal(t, inventory.ImportRunning, f.get(live.ID).State, "a live job is left alone")
			assert.Equal(t, 1, f.h.audits("kv.import.uncertain"), "its own audit row")
			// A late handler cannot record a send or an answer over it.
			_, err = f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("x"))
			assert.ErrorIs(t, err, inventory.ErrImportState)
			f.h.clock.Advance(time.Minute)
			f.poll("a1-run", f.nw, 4, f.h.clock.Now())
			assert.Equal(t, inventory.ImportSucceeded, f.get(im.ID).State, "the poll settles it")
		})
	}
	t.Run("a job that is blocked by the licence or still running is not an ended job", func(t *testing.T) {
		f := newImportFixture(t)
		a := f.mustRequest("blk-name", false)
		b := f.mustRequest("run-name", false)
		f.exec("UPDATE jobs SET status = 'blocked_license' WHERE id = $1", *a.JobID)
		f.exec("UPDATE jobs SET status = 'running' WHERE id = $1", *b.JobID)
		n, err := f.h.svc.SweepImports(f.h.ctx)
		require.NoError(t, err)
		assert.Zero(t, n)
	})
	t.Run("a sweep and a handler racing: nothing is sent twice", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.mustRequest("race-sweep", false)
		f.exec("UPDATE jobs SET status = 'dead' WHERE id = $1", *im.JobID)
		var wg sync.WaitGroup
		var sent, swept atomic.Int32
		for range 4 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if f.h.svc.MarkImportSent(f.h.ctx, im.ID) == nil {
					sent.Add(1)
				}
			}()
			go func() {
				defer wg.Done()
				n, _ := f.h.svc.SweepImports(f.h.ctx)
				swept.Add(int32(n))
			}()
		}
		wg.Wait()
		got := f.get(im.ID)
		if sent.Load() > 0 { // the handler won: marked once, then the sweep made it uncertain
			assert.Equal(t, int32(1), sent.Load(), "marked at most once")
			assert.Equal(t, inventory.ImportUncertain, got.State)
		} else {
			assert.Equal(t, inventory.ImportFailed, got.State)
		}
		assert.Equal(t, int32(1), swept.Load(), "ended once")
	})
}

// m7: the 24 hour end waits for certificates whose details are pending; a version stored while the gate is
// closed is held.
func TestImportSurvivors(t *testing.T) {
	t.Run("details pending: the 24 hour end waits", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("pending-name", inventory.ImportUncertain)
		f.h.clock.Advance(25 * time.Hour)
		c := f.h.kvc("pending-name", f.issue("p.example.test", pki.ECDSA256), ver(3), f.h.clock.Now().Add(-48*time.Hour), false)
		f.h.reconcile(f.vault, kvResult(c))
		require.True(t, f.h.certRow(f.vault, "pending-name").Pending)
		assert.Equal(t, inventory.ImportUncertain, f.get(im.ID).State, "its details may be the import's version")
	})
	t.Run("held when the gate is closed at FinishImport", func(t *testing.T) {
		f := newImportFixture(t)
		im := f.toState("held-name", inventory.ImportRunning)
		f.h.clock.Advance(40 * 24 * time.Hour)
		require.NoError(t, f.h.lic.Tick(f.h.ctx))
		_, err := f.h.svc.FinishImport(f.h.ctx, im.ID, f.created(6), nil)
		require.NoError(t, err)
		v := f.h.versionRows(f.h.certRow(f.vault, "held-name").ID)[ver(6)]
		assert.True(t, v.Held)
		assert.Equal(t, "license", v.HeldReason)
	})
}

// A2: the access check's optional secret read is audited like every secret read.
func TestRecordAccessCheckRead(t *testing.T) {
	f := newImportFixture(t)
	h, ctx := f.h, f.h.ctx
	require.NoError(t, h.svc.RecordAccessCheckRead(ctx, f.vault, "web-cert", ver(1), audit.Success, ""))
	require.NoError(t, h.svc.RecordAccessCheckRead(ctx, f.vault, "web-cert", ver(1), audit.Failure, "azure.forbidden"))
	d := h.auditDetails("kv.secret_read")
	require.Len(t, d, 2)
	assert.Equal(t, map[string]string{"vault_url": "https://prod.vault.azure.net", "certificate_name": "web-cert", "version": ver(1), "purpose": "access_check"}, d[0])
	assert.Equal(t, "azure.forbidden", d[1]["reason"])
	assert.Equal(t, 1, h.secretReads("success"))
	assert.Equal(t, 1, h.secretReads("failure"))
	require.ErrorIs(t, h.svc.RecordAccessCheckRead(ctx, uuid.New(), "web-cert", ver(1), audit.Success, ""), inventory.ErrNotFound)
	require.ErrorIs(t, h.svc.RecordAccessCheckRead(ctx, f.target1, "web-cert", ver(1), audit.Success, ""), inventory.ErrNotAVault)
	var errs validate.Errors
	require.ErrorAs(t, h.svc.RecordAccessCheckRead(ctx, f.vault, "not a name!", ver(1), audit.Success, ""), &errs)
	require.NoError(t, h.svc.DeleteVault(ctx, f.admin, f.vault, true))
	assert.ErrorIs(t, h.svc.RecordAccessCheckRead(ctx, f.vault, "web-cert", ver(1), audit.Success, ""), inventory.ErrNotFound, "a deleted vault")
	assert.Equal(t, 2, h.audits("kv.secret_read"))
	claimed := inventory.WithClaim(ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	other := h.vault("again")
	assert.ErrorIs(t, h.svc.RecordAccessCheckRead(claimed, other, "web-cert", ver(1), audit.Success, ""), inventory.ErrClaimLost)

	// Run by the access check job: the row names who asked for the check (final review B M-7).
	job, err := h.svc.RequestAccessCheck(ctx, f.operator, other, uuid.Nil)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(ctx, "UPDATE jobs SET status = 'running', attempts = 1 WHERE id = $1", job)
	require.NoError(t, err)
	require.NoError(t, h.svc.RecordAccessCheckRead(inventory.WithClaim(ctx, inventory.Claim{JobID: job, Attempt: 1}), other, "web-cert", ver(1),
		audit.Success, ""))
	d = h.auditDetails("kv.secret_read")
	require.Len(t, d, 3)
	assert.Equal(t, f.operator.UserID.String(), d[2]["requested_by"])
	assert.Equal(t, "operator", d[2]["requested_by_role"])
}

// Without a notifier nothing is mailed and nothing breaks: the marks, audit rows and states are the same.
func TestImportsAndPlannerWorkWithoutAnEmailSender(t *testing.T) {
	f := newImportFixture(t)
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.Root)
	f.h.svc = inventory.New(inventory.Config{Pool: f.h.db.App, Keyring: f.h.keyring, Audit: f.h.audit, Clock: f.h.clock, License: f.h.lic,
		Registry: f.h.reg, Jobs: f.h.jobs, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Roots: roots})
	im := f.toState("quiet-mail", inventory.ImportRunning)
	got, err := f.h.svc.FinishImport(f.h.ctx, im.ID, providers.ImportResult{Outcome: providers.ImportRefused}, providers.NewError("azure.forbidden", false, nil, nil))
	require.NoError(t, err)
	assert.Equal(t, inventory.ImportFailed, got.State)
	assert.Zero(t, f.h.emails("kv.import_failed"))
	n, err := f.h.svc.PlanKVAutoDeploy(f.h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	// Sweeping with a lost claim writes nothing and says so.
	claimed := inventory.WithClaim(f.h.ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	other := f.mustRequest("quiet-two", false)
	f.exec("UPDATE jobs SET status = 'dead' WHERE id = $1", *other.JobID)
	_, err = f.h.svc.SweepImports(claimed)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	assert.Equal(t, inventory.ImportQueued, f.get(other.ID).State)
}

// keyLeaks lists the forms of the key and the PFX found in text: raw, hex, and slices of the base64 and
// base64url ENCODING OF THE WHOLE buffer at several offsets (so a whole-buffer encoding in a log line is
// found whatever its alignment).
func keyLeaks(text string, key, pfx []byte) []string {
	var found []string
	check := func(label string, raw []byte) {
		if len(raw) < 80 {
			return
		}
		needles := map[string]string{"raw": string(raw[20:60]), "hex": hex.EncodeToString(raw[20:60])}
		for _, enc := range []struct {
			name string
			text string
		}{{"base64", base64.StdEncoding.EncodeToString(raw)}, {"base64url", base64.RawURLEncoding.EncodeToString(raw)}} {
			for i, off := range []int{8, 21, 34, 47, 60, 77} {
				if off+40 <= len(enc.text) {
					needles[enc.name+" slice "+string(rune('a'+i))] = enc.text[off : off+40]
				}
			}
		}
		for k, n := range needles {
			if strings.Contains(text, n) {
				found = append(found, label+" "+k)
			}
		}
	}
	check("key", key)
	check("pfx", pfx)
	return found
}

// The scan is not blind: a PFX logged as base64 (at DEBUG, say) is found, in either alphabet, and so is a key.
func TestKeyLeakScanFindsALoggedPFX(t *testing.T) {
	f := newImportFixture(t)
	im := f.mustRequest("scan-name", false)
	m, err := f.h.svc.ImportMaterial(f.h.ctx, im.ID)
	require.NoError(t, err)
	pfx := append([]byte(nil), m.Request.PFX.Bytes()...)
	m.Request.PFX.Zero()
	block, _ := pem.Decode(f.nw.KeyPEM)
	assert.Empty(t, keyLeaks(dumpEverything(f.h), block.Bytes, pfx))
	f.h.logs.WriteString("level=DEBUG msg=sent body=" + base64.StdEncoding.EncodeToString(pfx) + "\n")
	assert.NotEmpty(t, keyLeaks(dumpEverything(f.h), block.Bytes, pfx))
	f.h.logs.Reset()
	f.h.logs.WriteString("x " + base64.RawURLEncoding.EncodeToString(pfx) + "\n")
	assert.NotEmpty(t, keyLeaks(dumpEverything(f.h), block.Bytes, pfx))
	f.h.logs.Reset()
	f.h.logs.WriteString("x " + base64.StdEncoding.EncodeToString(block.Bytes) + "\n")
	assert.NotEmpty(t, keyLeaks(dumpEverything(f.h), block.Bytes, pfx))
}

// n5: a job that ended `succeeded` while its import is still queued or running is ended too; n4: the sweep
// is bounded per call and the next call continues; the material path audits an unreadable deployment.
func TestSweepEdges(t *testing.T) {
	t.Run("succeeded job", func(t *testing.T) {
		f := newImportFixture(t)
		q := f.mustRequest("sw-q", false)
		r := f.toState("sw-r", inventory.ImportRunning)
		f.exec("UPDATE jobs SET status = 'succeeded' WHERE id IN ($1, $2)", *q.JobID, *r.JobID)
		n, err := f.h.svc.SweepImports(f.h.ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, n)
		assert.Equal(t, inventory.ImportFailed, f.get(q.ID).State)
		assert.Equal(t, inventory.ReasonImportCancelled, f.get(q.ID).ErrorCode)
		assert.Equal(t, inventory.ImportUncertain, f.get(r.ID).State)
	})
	t.Run("bounded per call", func(t *testing.T) {
		defer inventory.SetSweepBatch(2)()
		f := newImportFixture(t)
		var ids []uuid.UUID
		for _, name := range []string{"b-one", "b-two", "b-three", "b-four", "b-five"} {
			im := f.mustRequest(name, false)
			f.exec("UPDATE jobs SET status = 'cancelled' WHERE id = $1", *im.JobID)
			ids = append(ids, im.ID)
		}
		for _, want := range []int{2, 2, 1, 0} {
			n, err := f.h.svc.SweepImports(f.h.ctx)
			require.NoError(t, err)
			assert.Equal(t, want, n)
		}
		for _, id := range ids {
			assert.Equal(t, inventory.ImportFailed, f.get(id).State)
		}
	})
}
