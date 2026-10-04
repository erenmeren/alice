//go:build integration

package inventory_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// secretReads counts the kv.secret_read audit rows with the result.
func (h *harness) secretReads(result string) int {
	return h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read' AND result = $1", result)
}

// beginKV requests a deployment of a version and begins it; auto turns it into an automatic one.
func (b *bindFixture) beginKV(a inventory.Actor, bind, version uuid.UUID, auto bool, locs ...uuid.UUID) []uuid.UUID {
	b.h.t.Helper()
	reqs, err := b.h.svc.RequestKVDeployment(b.h.ctx, a, inventory.KVDeployInput{BindingID: bind, VersionID: version, LocationIDs: locs})
	require.NoError(b.h.t, err)
	var out []uuid.UUID
	for _, r := range reqs {
		if auto {
			b.exec("UPDATE deployments SET trigger = 'kv_renewal' WHERE id = $1", r.ID)
		}
		_, err := b.h.svc.BeginDeployment(b.h.ctx, r.ID)
		require.NoError(b.h.t, err)
		out = append(out, r.ID)
	}
	return out
}

func (b *bindFixture) fullSecret() ([]byte, providers.CertificateSecret) {
	return pemSecret(string(b.webLeaf.KeyPEM) + string(b.webLeaf.FullchainPEM))
}

// C1: a queued deployment gets no key once its binding is gone, its website left the binding, or (for
// an automatic deployment) automatic deployment was switched off. Nothing is read, written or audited.
func TestKVDeployMaterialRefusesAfterUnbinding(t *testing.T) {
	run := func(name string, want error, prepare func(b *bindFixture, bind inventory.Binding, v1 uuid.UUID) uuid.UUID) {
		t.Run(name, func(t *testing.T) {
			b := newBindFixture(t)
			h, ctx := b.h, b.h.ctx
			bind := b.create(b.admin, b.web, b.loc1, b.loc2)
			id := prepare(b, bind, b.versionID(b.web, ver(1)))
			before, _ := b.certPEM(pki.Fingerprint(b.webLeaf.Cert))
			raw, secret := b.fullSecret()
			m, err := h.svc.KVDeployMaterial(ctx, id, secret)
			assert.ErrorIs(t, err, want)
			assert.Zero(t, len(m.PrivateKeyPEM.Bytes()), "no key is handed out")
			assert.True(t, allZero(raw), "the secret is zeroed")
			assert.Zero(t, h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read'"), "a pre-read refusal is not a read")
			after, _ := b.certPEM(pki.Fingerprint(b.webLeaf.Cert))
			assert.Equal(t, before, after, "nothing is written")
			assert.ErrorIs(t, h.svc.KVDeployPrecheck(ctx, id), want, "the engine can ask before it reads the vault")
			require.NoError(t, h.svc.FinishDeployment(ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed, ErrorCode: "deployment.binding_gone"}),
				"the deployment ends failed cleanly")
		})
	}
	run("binding deleted", inventory.ErrBindingGone, func(b *bindFixture, bind inventory.Binding, v1 uuid.UUID) uuid.UUID {
		ids := b.beginKV(b.operator, bind.ID, v1, false, b.loc1)
		require.NoError(b.h.t, b.h.svc.DeleteBinding(b.h.ctx, b.admin, bind.ID))
		return ids[0]
	})
	run("website released from the binding", inventory.ErrBindingGone, func(b *bindFixture, bind inventory.Binding, v1 uuid.UUID) uuid.UUID {
		ids := b.beginKV(b.operator, bind.ID, v1, false, b.loc1)
		_, err := b.h.svc.UpdateBindingLocations(b.h.ctx, b.admin, bind.ID, bind.Version, []uuid.UUID{b.loc2})
		require.NoError(b.h.t, err)
		return ids[0]
	})
	run("automatic deployment switched off", inventory.ErrAutoDeployOff, func(b *bindFixture, bind inventory.Binding, v1 uuid.UUID) uuid.UUID {
		on, err := b.h.svc.SetAutoDeploy(b.h.ctx, b.admin, bind.ID, bind.Version, true)
		require.NoError(b.h.t, err)
		ids := b.beginKV(b.admin, bind.ID, v1, true, b.loc1)
		_, err = b.h.svc.SetAutoDeploy(b.h.ctx, b.admin, bind.ID, on.Version, false)
		require.NoError(b.h.t, err)
		return ids[0]
	})
	t.Run("a manual deployment does not need automatic deployment", func(t *testing.T) {
		b := newBindFixture(t)
		bind := b.create(b.admin, b.web, b.loc1)
		ids := b.beginKV(b.operator, bind.ID, b.versionID(b.web, ver(1)), false, b.loc1)
		_, secret := b.fullSecret()
		m, err := b.h.svc.KVDeployMaterial(b.h.ctx, ids[0], secret)
		require.NoError(t, err)
		m.PrivateKeyPEM.Zero()
	})
}

// I1 and m4: nothing from the request is trusted at material time. Every row asserts that no key is
// handed out, the secret is zeroed and no read is audited (except the rows that proceed).
func TestKVDeployMaterialRefusesWhatChangedSinceTheRequest(t *testing.T) {
	type row struct {
		name      string
		auto      bool
		requester string // "admin" | "operator"
		mutate    func(b *bindFixture, v1 uuid.UUID)
		want      error
	}
	held := func(reason string) func(b *bindFixture, v1 uuid.UUID) {
		return func(b *bindFixture, v1 uuid.UUID) {
			b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = $2 WHERE id = $1", v1, reason)
		}
	}
	for _, tc := range []row{
		{"vault disabled", false, "operator", func(b *bindFixture, _ uuid.UUID) {
			b.exec("UPDATE targets SET status = 'disabled' WHERE id = $1", b.vault)
		}, inventory.ErrVaultUnavailable},
		{"vault deleted", false, "operator", func(b *bindFixture, _ uuid.UUID) {
			b.exec("UPDATE targets SET deleted_at = now() WHERE id = $1", b.vault)
		}, inventory.ErrVaultUnavailable},
		{"certificate missing", false, "operator", func(b *bindFixture, _ uuid.UUID) {
			b.exec("UPDATE kv_certificates SET missing_since = now() WHERE id = $1", b.web)
		}, inventory.ErrKVCertificateMissing},
		{"version disabled", false, "operator", func(b *bindFixture, v1 uuid.UUID) {
			b.exec("UPDATE kv_certificate_versions SET enabled = false WHERE id = $1", v1)
		}, inventory.ErrVersionDisabled},
		{"version expired by its row", false, "operator", func(b *bindFixture, v1 uuid.UUID) {
			b.exec("UPDATE kv_certificate_versions SET expires = $2 WHERE id = $1", v1, b.h.clock.Now().Add(-time.Second))
		}, inventory.ErrCertificateExpired},
		{"version not yet valid by its row", false, "operator", func(b *bindFixture, v1 uuid.UUID) {
			b.exec("UPDATE kv_certificate_versions SET not_before = $2 WHERE id = $1", v1, b.h.clock.Now().Add(time.Hour))
		}, inventory.ErrCertificateNotYetValid},
		{"automatic, held for the license", true, "admin", held("license"), inventory.ErrVersionHeld},
		{"automatic, held for the chain", true, "admin", held("incomplete_chain"), inventory.ErrVersionHeld},
		{"manual by an Operator, held afterwards", false, "operator", held("license"), inventory.ErrVersionHeld},
		{"manual by an Administrator, held afterwards: the request recorded who asked", false, "admin", held("license"), nil},
		{"manual by an Administrator who is an Operator now", false, "admin", func(b *bindFixture, v1 uuid.UUID) {
			held("license")(b, v1)
			b.exec("UPDATE users SET role = 'operator' WHERE id = $1", b.admin.UserID)
		}, inventory.ErrVersionHeld},
		{"manual by an Administrator who is disabled now", false, "admin", func(b *bindFixture, v1 uuid.UUID) {
			held("license")(b, v1)
			b.exec("UPDATE users SET disabled_at = now() WHERE id = $1", b.admin.UserID)
		}, inventory.ErrVersionHeld},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBindFixture(t)
			h, ctx := b.h, b.h.ctx
			bind := b.create(b.admin, b.web, b.loc1)
			v1 := b.versionID(b.web, ver(1))
			a := b.operator
			if tc.requester == "admin" {
				a = b.admin
			}
			id := b.beginKV(a, bind.ID, v1, tc.auto, b.loc1)[0]
			if tc.auto {
				_, err := h.svc.SetAutoDeploy(ctx, b.admin, bind.ID, bind.Version, true)
				require.NoError(t, err)
			}
			tc.mutate(b, v1)
			raw, secret := b.fullSecret()
			m, err := h.svc.KVDeployMaterial(ctx, id, secret)
			assert.True(t, allZero(raw))
			if tc.want == nil {
				require.NoError(t, err)
				assert.NotZero(t, len(m.PrivateKeyPEM.Bytes()))
				m.PrivateKeyPEM.Zero()
				assert.Equal(t, 1, h.secretReads("success"))
				return
			}
			assert.ErrorIs(t, err, tc.want)
			assert.Zero(t, len(m.PrivateKeyPEM.Bytes()))
			assert.Zero(t, h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read'"), "no read happened")
			assert.ErrorIs(t, h.svc.KVDeployPrecheck(ctx, id), tc.want)
		})
	}

	t.Run("a sibling of a wave whose version was just held is refused before it reads", func(t *testing.T) {
		b := newBindFixture(t)
		h, ctx := b.h, b.h.ctx
		bind := b.create(b.admin, b.web, b.loc1, b.loc2)
		v1 := b.versionID(b.web, ver(1))
		on, err := h.svc.SetAutoDeploy(ctx, b.admin, bind.ID, bind.Version, true)
		require.NoError(t, err)
		_ = on
		ids := b.beginKV(b.admin, bind.ID, v1, true, b.loc1, b.loc2)
		_, s := pemSecret(string(b.webLeaf.KeyPEM) + string(b.webLeaf.CertPEM)) // the chain is incomplete
		_, err = h.svc.KVDeployMaterial(ctx, ids[0], s)
		require.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
		reads := h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read'")
		raw, secret := b.fullSecret()
		_, err = h.svc.KVDeployMaterial(ctx, ids[1], secret)
		assert.ErrorIs(t, err, inventory.ErrVersionHeld)
		assert.True(t, allZero(raw))
		assert.Equal(t, reads, h.count("SELECT count(*) FROM audit_log WHERE action = 'kv.secret_read'"), "the sibling never read")
		assert.ErrorIs(t, h.svc.KVDeployPrecheck(ctx, ids[1]), inventory.ErrVersionHeld)
	})
}

// I3: the decoded key and the PEM are wiped on every path; on success the PEM is the caller's.
func TestKVDeployMaterialZeroesDERAndPEM(t *testing.T) {
	type seen struct{ der, pem []byte }
	run := func(t *testing.T, ctxOf func(b *bindFixture) (claimed bool), secretOf func(b *bindFixture) providers.CertificateSecret, panicAt string) (seen, any, error) {
		b := newBindFixture(t)
		bind := b.create(b.admin, b.web, b.loc1)
		id := b.beginKV(b.operator, bind.ID, b.versionID(b.web, ver(1)), false, b.loc1)[0]
		var s seen
		restore := inventory.SetKVMaterialHook(func(stage string, buf []byte) {
			switch stage {
			case "der":
				s.der = buf
			case "pem":
				s.pem = buf
			}
			if stage == panicAt {
				panic("injected")
			}
			if len(buf) > 0 && allZero(buf) {
				t.Errorf("the %s buffer is zero before it was used", stage)
			}
		})
		defer restore()
		ctx := b.h.ctx
		if ctxOf(b) {
			ctx = inventory.WithClaim(ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
		}
		var err error
		var rec any
		var m inventory.Material
		func() {
			defer func() { rec = recover() }()
			m, err = b.h.svc.KVDeployMaterial(ctx, id, secretOf(b))
		}()
		if err == nil && rec == nil {
			assert.False(t, allZero(m.PrivateKeyPEM.Bytes()), "success hands the key PEM to the caller")
			assert.False(t, allZero(s.pem))
			m.PrivateKeyPEM.Zero()
			assert.True(t, allZero(s.pem), "and it is the caller's to zero")
		}
		return s, rec, err
	}
	good := func(b *bindFixture) providers.CertificateSecret { _, s := b.fullSecret(); return s }
	t.Run("success", func(t *testing.T) {
		s, _, err := run(t, func(*bindFixture) bool { return false }, good, "")
		require.NoError(t, err)
		require.NotEmpty(t, s.der)
		assert.True(t, allZero(s.der), "the decoded key is wiped")
	})
	t.Run("lost claim at the record", func(t *testing.T) {
		s, _, err := run(t, func(*bindFixture) bool { return true }, good, "")
		assert.ErrorIs(t, err, inventory.ErrClaimLost)
		require.NotEmpty(t, s.der)
		require.NotEmpty(t, s.pem)
		assert.True(t, allZero(s.der))
		assert.True(t, allZero(s.pem), "the PEM is wiped when the record fails")
	})
	t.Run("a mismatch", func(t *testing.T) {
		s, _, err := run(t, func(*bindFixture) bool { return false }, func(b *bindFixture) providers.CertificateSecret {
			other := b.issue("web.example.test", pki.ECDSA256)
			_, sec := pemSecret(string(other.KeyPEM) + string(other.FullchainPEM))
			return sec
		}, "")
		assert.ErrorIs(t, err, inventory.ErrSecretMismatch)
		require.NotEmpty(t, s.der)
		assert.True(t, allZero(s.der))
	})
	t.Run("a panic after the PEM was made", func(t *testing.T) {
		s, rec, _ := run(t, func(*bindFixture) bool { return false }, good, "pem")
		assert.Equal(t, "injected", rec)
		require.NotEmpty(t, s.der)
		require.NotEmpty(t, s.pem)
		assert.True(t, allZero(s.der))
		assert.True(t, allZero(s.pem), "the PEM is wiped when something panics")
	})
}

// I4: DeleteVault takes the websites' row locks before its first audit row (the order of every
// request: websites, then the audit chain), so a request in flight cannot deadlock with it.
func TestDeleteVaultLocksWebsitesBeforeItsAuditRows(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	b1 := b.create(b.admin, b.web, b.loc1)
	b2 := b.create(b.admin, b.second, b.loc2)
	second := b2
	if strings.Compare(b2.ID.String(), b1.ID.String()) < 0 {
		second = b1
	}
	loc := second.Locations[0].LocationID
	tx, err := h.db.Owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SELECT 1 FROM certificate_locations WHERE id = $1 FOR NO KEY UPDATE", loc) // as lockDeployTargets
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- h.svc.DeleteVault(ctx, b.admin, b.vault, true) }()
	time.Sleep(1500 * time.Millisecond)
	_, lockErr := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(7160927315633811300)) // audit.Append in insertDeployment
	if lockErr != nil {
		_ = tx.Rollback(ctx)
	} else {
		require.NoError(t, tx.Commit(ctx))
	}
	var delErr error
	select {
	case delErr = <-done:
	case <-time.After(20 * time.Second):
		delErr = fmt.Errorf("DeleteVault still blocked after 20s")
	}
	assert.NoError(t, lockErr, "the request side is never chosen as the deadlock victim")
	assert.NoError(t, delErr)
}

// m1: the thumbprint and the fingerprint are each compared.
func TestKVDeployMaterialComparesThumbprintAndFingerprintSeparately(t *testing.T) {
	for name, mutate := range map[string]func(b *bindFixture, v1, id uuid.UUID){
		"the version's thumbprint is another one": func(b *bindFixture, v1, _ uuid.UUID) {
			b.exec("UPDATE kv_certificate_versions SET thumbprint = $2 WHERE id = $1", v1, strings.Repeat("ab", 20))
		},
		"the leaf row has another fingerprint": func(b *bindFixture, _, _ uuid.UUID) {
			b.exec("UPDATE certificates SET fingerprint_sha256 = $2 WHERE fingerprint_sha256 = $1", pki.Fingerprint(b.webLeaf.Cert), strings.Repeat("cd", 32))
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBindFixture(t)
			bind := b.create(b.admin, b.web, b.loc1)
			v1 := b.versionID(b.web, ver(1))
			id := b.beginKV(b.operator, bind.ID, v1, false, b.loc1)[0]
			mutate(b, v1, id)
			raw, secret := b.fullSecret()
			_, err := b.h.svc.KVDeployMaterial(b.h.ctx, id, secret)
			assert.ErrorIs(t, err, inventory.ErrSecretMismatch)
			assert.True(t, allZero(raw))
		})
	}
}

// m2: an Administrator's confirmation is recorded only for a chain that is incomplete as far as Alice knows.
func TestConfirmIncompleteChainIsRecordedOnlyWhenNeeded(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	request := func() inventory.RequestedDeployment {
		reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{BindingID: bind.ID, VersionID: v1, ConfirmIncompleteChain: true})
		require.NoError(t, err)
		return reqs[0]
	}
	first := request()
	assert.True(t, b.get(first.ID).ConfirmIncompleteChain, "the leaf row holds the leaf only: the chain is unknown, the confirmation is kept")
	b.finishQueued(first)
	b.exec("UPDATE certificates SET chain_complete = true WHERE fingerprint_sha256 = $1", pki.Fingerprint(b.webLeaf.Cert))
	second := request()
	assert.False(t, b.get(second.ID).ConfirmIncompleteChain, "a chain known to be complete needs no confirmation")
	ev := h.auditDetails("deployment.requested")
	require.Len(t, ev, 2)
	assert.Equal(t, "true", ev[0]["confirm_incomplete_chain"])
	assert.Equal(t, "false", ev[1]["confirm_incomplete_chain"])
}

// m3: a disabled vault is refused at the request; the other states are left to the read.
func TestRequestKVDeploymentRefusesADisabledVault(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	b.exec("UPDATE targets SET status = 'disabled' WHERE id = $1", b.vault)
	_, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{BindingID: bind.ID, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrVaultUnavailable)
	d := h.auditDetails("deployment.denied")
	require.Len(t, d, 1)
	assert.Equal(t, "vault_disabled", d[0]["reason"])
	assert.Zero(t, h.count("SELECT count(*) FROM deployments"))
	for _, st := range []string{"degraded", "auth_failed", "unreachable"} {
		b.exec("UPDATE targets SET status = $2 WHERE id = $1", b.vault, st)
		reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{BindingID: bind.ID, VersionID: v1})
		require.NoError(t, err, st)
		b.finishQueued(reqs...)
	}
}

// m6: both release audit rows name the version as their object and the certificate in details.
func TestReleaseAuditsNameTheVersionAsObject(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	v1 := b.versionID(b.web, ver(1))
	b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v1)
	_, err := h.svc.ReleaseVersion(ctx, b.operator, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	require.ErrorIs(t, err, inventory.ErrHeldNeedsAdmin)
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	require.NoError(t, err)
	for _, action := range []string{"kv.version.release_denied", "kv.version.released"} {
		var typ, obj string
		require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT object_type, object_id FROM audit_log WHERE action = $1", action).Scan(&typ, &obj))
		assert.Equal(t, "kv_certificate_version", typ, action)
		assert.Equal(t, v1.String(), obj, action)
	}
	assert.Equal(t, b.web.String(), h.auditDetails("kv.version.released")[0]["kv_certificate_id"])
	assert.Equal(t, b.web.String(), h.auditDetails("kv.version.release_denied")[0]["kv_certificate_id"])
}

// m9: the version must belong to the named certificate of the named vault.
func TestReleaseVersionChecksItsCertificateAndVault(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	v1 := b.versionID(b.web, ver(1))
	b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v1)
	other := h.vault("other")
	_, err := h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.second, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrNotFound, "another certificate")
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: other, KVCertificateID: b.web, VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrNotFound, "another vault")
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VersionID: v1})
	var errs validate.Errors
	require.ErrorAs(t, err, &errs)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificate_versions WHERE id = $1 AND held", v1), "nothing was released")
	_, err = h.svc.ReleaseVersion(ctx, b.admin, inventory.ReleaseInput{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1})
	require.NoError(t, err)
}

// m8: a website whose server was deleted is named in the refusal; the key type filter and the binding
// agree that a website of an unknown key type fits every certificate.
func TestWebsiteOfADeletedServerIsNamedAndUnknownKeyTypesAgree(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	require.NoError(t, h.svc.DeleteTarget(ctx, b.admin, b.target1))
	_, err := h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: b.web, LocationIDs: []uuid.UUID{b.loc1}})
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.Equal(t, b.loc1, lr.LocationID)
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	b.exec("UPDATE certificate_locations SET key_type = '' WHERE id = $1", b.loc2)
	for _, kt := range []string{"rsa", "ecdsa"} {
		page, err := h.svc.ListDeployableLocations(ctx, inventory.LocationFilter{KeyType: kt, Limit: 200})
		require.NoError(t, err)
		ids := []uuid.UUID{}
		for _, l := range page.Items {
			ids = append(ids, l.ID)
		}
		assert.Contains(t, ids, b.loc2, "a website of an unknown key type is listed for %s", kt)
	}
	_, err = h.svc.CreateBinding(ctx, b.admin, inventory.BindingInput{KVCertificateID: b.web, LocationIDs: []uuid.UUID{b.loc2}})
	assert.NoError(t, err, "and it can be bound")
}

// KVDeployPrecheck knows what it is asked about.
func TestKVDeployPrecheckKnowsItsDeployments(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	assert.ErrorIs(t, h.svc.KVDeployPrecheck(ctx, uuid.New()), inventory.ErrNotFound)
	ordinary := b.request(b.admin, b.cert.ID, b.loc5)
	assert.ErrorIs(t, h.svc.KVDeployPrecheck(ctx, ordinary), inventory.ErrDeploymentState, "not a Key Vault deployment")
	bind := b.create(b.admin, b.web, b.loc1)
	id := b.beginKV(b.operator, bind.ID, b.versionID(b.web, ver(1)), false, b.loc1)[0]
	assert.NoError(t, h.svc.KVDeployPrecheck(ctx, id))
	b.exec("UPDATE kv_certificates SET missing_since = now() WHERE id = $1", b.web)
	assert.ErrorIs(t, h.svc.KVDeployPrecheck(ctx, id), inventory.ErrKVCertificateMissing)
}
