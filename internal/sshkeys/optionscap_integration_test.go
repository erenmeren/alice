//go:build integration

package sshkeys_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh"
	"alice/internal/sshkeys"
	"alice/internal/sshkeys/plan"
)

// cutOptions is the options text the inventory parser stores for a line of the key whose option list
// is longer than the cap: cut, ending in "…". With the 4095-byte cap it is 4096 characters, the most
// rotation_locations.options holds (CHECK (char_length(options) <= 4096)).
func cutOptions(t *testing.T, k sshkeys.ManagedKey) string {
	t.Helper()
	list := `environment="K=` + strings.Repeat("v", 10000) + `"`
	a, err := linuxssh.ParseAuthorizedKeys([]byte(list + " " + strings.TrimSpace(k.PublicKey) + " ci\n"))
	require.NoError(t, err)
	require.Len(t, a.Lines, 1)
	s := a.Lines[0].OptionsText
	require.True(t, strings.HasSuffix(s, "…"))
	require.True(t, strings.HasPrefix(list, strings.TrimSuffix(s, "…")))
	t.Logf("stored options text: %d characters", utf8.RuneCountInString(s))
	return s
}

// keyWithCutOptions is a key at deploy@web-01 (rotatable) and deploy@web-02, whose stored options
// were cut.
func (e *env) keyWithCutOptions(t *testing.T) (sshkeys.ManagedKey, uuid.UUID, string) {
	t.Helper()
	k := e.deployed("ci", e.server("web-01"), "deploy")
	cut := e.addLocation(k.ID, e.server("web-02"), "deploy")
	opts := cutOptions(t, k)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE ssh_key_locations SET options = $2 WHERE id = $1", cut, opts)
	require.NoError(t, err)
	return k, cut, opts
}

func assertCutLocationSkipped(t *testing.T, r sshkeys.Rotation, cut uuid.UUID, opts string) {
	t.Helper()
	require.Len(t, r.Locations, 2)
	for _, l := range r.Locations {
		if l.OldLocationID == cut {
			assert.Equal(t, sshkeys.LocSkipped, l.State)
			assert.Equal(t, plan.SkipOptionsTruncated, l.SkipReason)
			assert.Equal(t, opts, l.Options)
		} else {
			assert.NotEqual(t, sshkeys.LocSkipped, l.State)
		}
	}
}

// F1 (re-review of REM-2): a run stores every place, skipped ones included, in rotation_locations;
// a place whose options were cut must fit there, so the run starts and that place is skipped
// (options_truncated) instead of the whole run failing on the column's CHECK.
func TestRunStartsWithACutOptionsLocationSkipped(t *testing.T) {
	t.Run("run now", func(t *testing.T) {
		e := newEnv(t)
		k, cut, opts := e.keyWithCutOptions(t)
		p := e.policy(k.ID, 90, 7, 24)
		pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
		require.NoError(t, err)
		assert.Equal(t, 1, pv.Plan.Changes)
		r := e.runNow(p)
		assert.Equal(t, sshkeys.StatusAddingNew, e.run(r.ID).Status)
		assertCutLocationSkipped(t, e.run(r.ID), cut, opts)
	})
	t.Run("scheduled", func(t *testing.T) {
		e := newEnv(t)
		k, cut, opts := e.keyWithCutOptions(t)
		_, id := e.dueScheduledRun(k)
		assertCutLocationSkipped(t, e.run(id), cut, opts)
		require.NoError(t, e.svc.Advance(e.ctx, id))
		assert.Equal(t, sshkeys.StatusAddingNew, e.run(id).Status)
	})
}
