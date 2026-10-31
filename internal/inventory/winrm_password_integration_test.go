//go:build integration

package inventory_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/providers/windows"
	"alice/internal/rbac"
	"alice/internal/secrets"
)

// The WinRM password of a Windows server whose transport is winrm (R71 Rulings 5, 7 and 8): W5's CCS password pattern,
// one sealed credentials row per setting, the newest is the password, read only through the platform credential source.

// winrmPassword is a password of the rule, built at run time (never a literal).
func winrmPassword() []byte { return []byte("WinRM-" + strings.ReplaceAll(uuid.NewString(), "-", "")) }

func winrmSource(t *testing.T, h *harness) providers.WinRMPasswordSource {
	t.Helper()
	src, ok := h.svc.Credentials().(providers.WinRMPasswordSource)
	require.True(t, ok, "the platform credential source answers the WinRM password")
	return src
}

// winrmTarget creates a Windows server with the WinRM transport.
func winrmTarget(t *testing.T, h *harness, a inventory.Actor, name string) inventory.Target {
	t.Helper()
	tg, _, err := h.svc.CreateTarget(h.ctx, a, inventory.NewTarget{Name: name, Type: "windows", Host: name + ".corp.example",
		Transport: inventory.TransportWinRM})
	require.NoError(t, err)
	return tg
}

// setWinRM sets pw (a copy: the inventory zeroes what it is given) on target and returns the updated target.
func setWinRM(t *testing.T, h *harness, a inventory.Actor, target inventory.Target, pw []byte) (inventory.Target, error) {
	t.Helper()
	return h.svc.SetWinRMPassword(h.ctx, a, target.ID, target.Version, secrets.NewPlaintext(bytes.Clone(pw)))
}

func TestWinRMTargetWithoutPassword(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winrmTarget(t, h, admin, "iis-01")
	assert.Equal(t, inventory.TransportWinRM, win.Transport)
	assert.Equal(t, 5986, win.Port, "the WinRM HTTPS port when none is named")
	assert.Equal(t, "alice", win.Username)
	assert.Nil(t, win.WinRMPasswordSetAt, "a WinRM target exists before its password")
	assert.Zero(t, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", win.ID))
	var cfg string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT config::text FROM targets WHERE id = $1", win.ID).Scan(&cfg))
	assert.Contains(t, cfg, `"transport": "winrm"`)

	ssh := winTarget(t, h, admin, "iis-02")
	assert.Equal(t, inventory.TransportSSH, ssh.Transport, "a Windows server without a transport uses OpenSSH")
	assert.Equal(t, 22, ssh.Port)
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT config::text FROM targets WHERE id = $1", ssh.ID).Scan(&cfg))
	assert.NotContains(t, cfg, "transport", "an SSH target's config is W6's")
	linux := okTarget(t, h, admin, "web-01")
	assert.Empty(t, linux.Transport, "only a Windows server has a transport")

	local, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "iis-03", Type: "windows", Host: "iis-03.corp.example",
		Port: 45986, Username: `.\alice`, Transport: inventory.TransportWinRM})
	require.NoError(t, err)
	assert.Equal(t, 45986, local.Port)
	assert.Equal(t, `.\alice`, local.Username, "kept as typed")

	for name, in := range map[string]inventory.NewTarget{
		"username": {Name: "x1", Type: "windows", Host: "x1.corp.example", Username: `.\alice`},
		"username ": {Name: "x2", Type: "windows", Host: "x2.corp.example", Username: "alice@corp.example",
			Transport: inventory.TransportWinRM},
		"transport":  {Name: "x3", Type: "windows", Host: "x3.corp.example", Transport: "psrp"},
		"transport ": {Name: "x4", Type: "linux", Host: "x4.corp.example", Transport: inventory.TransportWinRM},
	} {
		_, _, err := h.svc.CreateTarget(h.ctx, admin, in)
		var errs validate.Errors
		require.ErrorAs(t, err, &errs, name)
		require.Len(t, errs, 1, name)
		assert.Equal(t, strings.TrimSpace(name), errs[0].Field, name)
	}
}

func TestSetWinRMPassword(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winrmTarget(t, h, admin, "iis-01")
	_, _, err := winrmSource(t, h).WinRMPassword(h.ctx, win.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound)
	require.ErrorIs(t, err, providers.ErrNoWinRMPassword)

	first := winrmPassword()
	given := bytes.Clone(first)
	updated, err := h.svc.SetWinRMPassword(h.ctx, admin, win.ID, win.Version, secrets.NewPlaintext(given))
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(first)), given, "the inventory zeroes the password it was given")
	require.NotNil(t, updated.WinRMPasswordSetAt)
	assert.Equal(t, h.clock.Now().UTC(), *updated.WinRMPasswordSetAt)
	assert.Nil(t, updated.CCSPasswordSetAt, "the CCS password is another credential")
	assert.Equal(t, win.Version+1, updated.Version, "the target's version moves (its ETag names the new state)")

	var purpose, kind string
	var owner uuid.UUID
	var ciphertext []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, `SELECT purpose, kind, target_id, ciphertext FROM credentials WHERE target_id = $1`, win.ID).
		Scan(&purpose, &kind, &owner, &ciphertext))
	assert.Equal(t, "win_winrm", purpose)
	assert.Equal(t, "winrm_password", kind)
	assert.Equal(t, win.ID, owner)
	assert.False(t, bytes.Contains(ciphertext, first), "sealed")

	var details string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, `SELECT details::text FROM audit_log WHERE action = 'target.winrm_password_set' AND object_id = $1`,
		win.ID.String()).Scan(&details))
	assert.NotContains(t, details, string(first), "the audit row holds no secret")
	assert.Contains(t, details, "iis-01")

	pt, release, err := winrmSource(t, h).WinRMPassword(h.ctx, win.ID)
	require.NoError(t, err)
	assert.Equal(t, first, pt.Bytes(), "the source answers the bytes that were set")
	release()

	h.clock.Advance(time.Hour)
	second := winrmPassword()
	updated, err = setWinRM(t, h, admin, updated, second)
	require.NoError(t, err)
	assert.Equal(t, h.clock.Now().UTC(), *updated.WinRMPasswordSetAt, "winrm_password_set_at follows the newest row")
	assert.Equal(t, 2, h.count("SELECT count(*) FROM credentials WHERE target_id = $1", win.ID), "rows are append-only")

	pt, release, err = winrmSource(t, h).WinRMPassword(h.ctx, win.ID)
	require.NoError(t, err)
	assert.Equal(t, second, pt.Bytes(), "the newest row is the password")
	release()
	assert.Equal(t, make([]byte, len(second)), pt.Bytes(), "release zeroes it")
	got, err := h.svc.GetTarget(h.ctx, win.ID)
	require.NoError(t, err)
	assert.Equal(t, updated.WinRMPasswordSetAt, got.WinRMPasswordSetAt)
}

func TestSetWinRMPasswordRefuses(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winrmTarget(t, h, admin, "iis-01")
	ssh := winTarget(t, h, admin, "iis-02")
	linux := okTarget(t, h, admin, "web-01")
	// refuse sets pw (a copy) on tg and checks that the inventory zeroed the copy on the refusal too.
	refuse := func(tg inventory.Target, pw []byte) error {
		t.Helper()
		given := bytes.Clone(pw)
		_, err := h.svc.SetWinRMPassword(h.ctx, admin, tg.ID, tg.Version, secrets.NewPlaintext(given))
		assert.True(t, bytes.Equal(make([]byte, len(pw)), given), "the password is zeroed on a refusal")
		return err
	}

	for _, tg := range []inventory.Target{ssh, linux} {
		err := refuse(tg, []byte("short"))
		require.ErrorIs(t, err, inventory.ErrNotWindowsTarget, tg.Name)
		assert.NotErrorIs(t, err, inventory.ErrWinRMPasswordInvalid, "the target before the rule")
	}
	pw := winrmPassword()
	for name, bad := range map[string][]byte{
		"11 characters": pw[:11],
		"a space":       append(bytes.Clone(pw[:12]), ' '),
		"empty":         nil,
	} {
		err := refuse(win, bad)
		assert.ErrorIs(t, err, inventory.ErrWinRMPasswordInvalid, name)
		if err != nil && len(bad) > 0 {
			assert.NotContains(t, err.Error(), string(bad), name)
		}
	}
	err := refuse(inventory.Target{ID: win.ID, Version: win.Version + 1}, pw)
	require.ErrorIs(t, err, inventory.ErrVersionMismatch)
	err = refuse(inventory.Target{ID: uuid.New(), Version: 1}, winrmPassword())
	require.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Zero(t, h.count("SELECT count(*) FROM credentials WHERE purpose = 'win_winrm'"), "nothing stored")
	assert.Zero(t, h.count("SELECT count(*) FROM audit_log WHERE action = 'target.winrm_password_set'"))
}

func TestWinRMPasswordForeign(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	a, b := winrmTarget(t, h, admin, "iis-01"), winrmTarget(t, h, admin, "iis-02")
	web := nginxTarget(t, h, admin, "web-01")
	_, err := setWinRM(t, h, admin, b, winrmPassword())
	require.NoError(t, err)
	src := winrmSource(t, h)

	pt, release, err := src.WinRMPassword(h.ctx, a.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound, "another server's password is never this one's")
	require.ErrorIs(t, err, providers.ErrNoWinRMPassword)
	assert.Nil(t, release)
	assert.Empty(t, pt.Bytes())

	// A row that names a server of another type (as a bug or the owner role could write) is refused, never opened.
	copyRow := `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
SELECT $2, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, $3 FROM credentials WHERE target_id = $1`
	_, err = h.db.Owner.Exec(h.ctx, copyRow, b.ID, uuid.New(), web.ID)
	require.NoError(t, err)
	pt, release, err = src.WinRMPassword(h.ctx, web.ID)
	require.ErrorIs(t, err, inventory.ErrForeignCredential)
	require.ErrorIs(t, err, providers.ErrWinRMPasswordUnusable)
	assert.Nil(t, release)
	assert.Empty(t, pt.Bytes())

	// A row of another kind under the purpose cannot be written (the CHECK); a row of the purpose that holds another
	// target's ciphertext does not open (the AAD names the row), so it is unusable, never another server's password.
	_, err = h.db.Owner.Exec(h.ctx, copyRow, b.ID, uuid.New(), a.ID)
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE credentials SET created_at = created_at + interval '1 day' WHERE target_id = $1", a.ID)
	require.NoError(t, err)
	_, _, err = src.WinRMPassword(h.ctx, a.ID)
	require.ErrorIs(t, err, providers.ErrWinRMPasswordUnusable)
	assert.NotErrorIs(t, err, providers.ErrNoWinRMPassword)

	// A CCS password is not a WinRM password.
	_, err = h.svc.SetCCSPassword(h.ctx, admin, a.ID, mustTarget(t, h, a.ID).Version, secrets.NewPlaintext(ccsPassword()))
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "DELETE FROM credentials WHERE target_id = $1 AND purpose = 'win_winrm'", a.ID)
	require.NoError(t, err)
	_, _, err = src.WinRMPassword(h.ctx, a.ID)
	require.ErrorIs(t, err, providers.ErrNoWinRMPassword)

	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET deleted_at = now() WHERE id = $1", b.ID)
	require.NoError(t, err)
	_, _, err = src.WinRMPassword(h.ctx, b.ID)
	require.ErrorIs(t, err, inventory.ErrNotFound, "a deleted server has no password")
	_, _, err = src.WinRMPassword(h.ctx, uuid.New())
	require.ErrorIs(t, err, inventory.ErrNotFound)
}

func mustTarget(t *testing.T, h *harness, id uuid.UUID) inventory.Target {
	t.Helper()
	tg, err := h.svc.GetTarget(h.ctx, id)
	require.NoError(t, err)
	return tg
}

// Ruling 3: the transport is fixed when the target is created.
func TestTransportImmutable(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	win := winrmTarget(t, h, admin, "iis-01")
	ssh := winTarget(t, h, admin, "iis-02")
	name := "renamed"
	tr := func(s string) *string { return &s }

	for _, c := range []struct {
		target inventory.Target
		to     string
	}{{win, inventory.TransportSSH}, {ssh, inventory.TransportWinRM}} {
		_, err := h.svc.UpdateTarget(h.ctx, admin, c.target.ID, c.target.Version, inventory.TargetPatch{Name: &name, Transport: tr(c.to)})
		require.ErrorIs(t, err, inventory.ErrTransportImmutable, c.target.Name)
		assert.Equal(t, c.target.Version, mustTarget(t, h, c.target.ID).Version, "nothing changed")
	}
	got, err := h.svc.UpdateTarget(h.ctx, admin, win.ID, win.Version, inventory.TargetPatch{Name: &name, Transport: tr(inventory.TransportWinRM)})
	require.NoError(t, err, "the same transport passes")
	assert.Equal(t, inventory.TransportWinRM, got.Transport)
	name2 := "renamed-2"
	got, err = h.svc.UpdateTarget(h.ctx, admin, win.ID, got.Version, inventory.TargetPatch{Name: &name2})
	require.NoError(t, err, "no transport member passes")
	assert.Equal(t, inventory.TransportWinRM, got.Transport)
	name3 := "renamed-3"
	_, err = h.svc.UpdateTarget(h.ctx, admin, ssh.ID, ssh.Version, inventory.TargetPatch{Name: &name3, Transport: tr(inventory.TransportSSH)})
	require.NoError(t, err, "an SSH target names its own transport")

	// A patch of the transport alone: another value is the conflict; the same value changes nothing and stays an empty
	// patch (refused as one, the version unchanged).
	cur := mustTarget(t, h, win.ID)
	_, err = h.svc.UpdateTarget(h.ctx, admin, win.ID, cur.Version, inventory.TargetPatch{Transport: tr(inventory.TransportSSH)})
	require.ErrorIs(t, err, inventory.ErrTransportImmutable, "a transport-only change")
	_, err = h.svc.UpdateTarget(h.ctx, admin, win.ID, cur.Version, inventory.TargetPatch{Transport: tr(inventory.TransportWinRM)})
	var empty validate.Errors
	require.ErrorAs(t, err, &empty, "the same transport alone is an empty patch")
	assert.Equal(t, "name", empty[0].Field)
	assert.NotErrorIs(t, err, inventory.ErrTransportImmutable)
	// A transport that is no transport is the field's error, never the conflict.
	for _, bad := range []string{"", "psrp", "WinRM"} {
		_, err = h.svc.UpdateTarget(h.ctx, admin, win.ID, cur.Version, inventory.TargetPatch{Name: &name, Transport: tr(bad)})
		var fe validate.Errors
		require.ErrorAs(t, err, &fe, "%q", bad)
		require.Len(t, fe, 1, "%q", bad)
		assert.Equal(t, "transport", fe[0].Field, "%q", bad)
		assert.Equal(t, validate.OneOf, fe[0].Code, "%q", bad)
	}
	assert.Equal(t, cur.Version, mustTarget(t, h, win.ID).Version, "nothing changed")

	linux := okTarget(t, h, admin, "web-01")
	_, err = h.svc.UpdateTarget(h.ctx, admin, linux.ID, linux.Version, inventory.TargetPatch{Name: &name, Transport: tr(inventory.TransportSSH)})
	var errs validate.Errors
	require.ErrorAs(t, err, &errs, "only a Windows server has a transport")
	assert.Equal(t, "transport", errs[0].Field)
}

// Ruling 19: the WinRM setup script is for a live Windows server whose transport is winrm.
func TestWinRMSetupOnlyForWinRMTargets(t *testing.T) {
	h := newHarness(t, withWindowsProvider())
	admin := h.user("ada", rbac.Admin, "")
	local, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "iis-01", Type: "windows", Host: "iis-01.corp.example",
		Username: `.\alice-w7`, Transport: inventory.TransportWinRM})
	require.NoError(t, err)
	got, err := h.svc.WinRMSetup(h.ctx, local.ID, "")
	require.NoError(t, err)
	assert.Equal(t, `.\alice-w7`, got.User, "the account as typed")
	want, err := windows.SetupScriptWinRM(`.\alice-w7`, "", false)
	if err != nil { // a test build has no helper checksums: the provider answers "" as SetupSnippets does
		want = ""
	}
	assert.Equal(t, want, got.Script, "the Windows provider's script")

	// from (fix round 1): validated as the setup guide's, canonical in the script.
	got, err = h.svc.WinRMSetup(h.ctx, local.ID, "2001:DB8::5")
	require.NoError(t, err)
	if want != "" {
		assert.Contains(t, got.Script, "$AliceAddress = '2001:db8::5'\n")
	}
	for _, bad := range []string{"web-01", "fe80::1%eth0", "::ffff:192.0.2.1"} {
		_, err = h.svc.WinRMSetup(h.ctx, local.ID, bad)
		var errs validate.Errors
		require.ErrorAs(t, err, &errs, bad)
		assert.Equal(t, "from", errs[0].Field, bad)
	}

	for _, tg := range []inventory.Target{winTarget(t, h, admin, "iis-02"), okTarget(t, h, admin, "web-01")} {
		_, err := h.svc.WinRMSetup(h.ctx, tg.ID, "")
		require.ErrorIs(t, err, inventory.ErrNotWindowsTarget, tg.Name)
	}
	_, err = h.svc.WinRMSetup(h.ctx, uuid.New(), "")
	require.ErrorIs(t, err, inventory.ErrNotFound)
}
