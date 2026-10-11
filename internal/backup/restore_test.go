package backup_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/backup"
)

// R43 row 48: the restore's DDL is built in one function from names quoted by pgx.
func TestDDLQuotesNames(t *testing.T) {
	assert.Equal(t, `CREATE DATABASE "alice_restore"`, backup.DDL("create", "alice_restore", ""))
	assert.Equal(t, `ALTER DATABASE "alice" RENAME TO "alice_previous_20261010T023000Z"`,
		backup.DDL("rename", "alice", "alice_previous_20261010T023000Z"))
	assert.Equal(t, `DROP DATABASE IF EXISTS "alice_restore"`, backup.DDL("drop", "alice_restore", ""))
	assert.Equal(t, `CREATE DATABASE "a""; DROP DATABASE x; --"`, backup.DDL("create", `a"; DROP DATABASE x; --`, ""))
	assert.Equal(t, `ALTER DATABASE "a""b" RENAME TO "c""d"`, backup.DDL("rename", `a"b`, `c"d`))
}

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		v, running string
		newer      bool
	}{
		{"9.0.0", "1.0.0", true},
		{"1.0.1", "1.0.0", true},
		{"1.1.0", "1.0.9", true},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.1", false},
		{"1.0.0", "1.0.0-rc.1", true},
		{"1.0.0-rc.1", "1.0.0", false},
		{"1.0.0-rc.2", "1.0.0-rc.1", true},
		{"1.0.0-rc.10", "1.0.0-rc.9", true},
		{"1.0.0-rc.1", "1.0.0-rc.1", false},
		{"1.0.0-rc.1.1", "1.0.0-rc.1", true},
		{"1.0.0-beta", "1.0.0-alpha", true},
		{"1.0.0-alpha", "1.0.0-1", true},
		{"10.0.0", "9.99.99", true},
		{"dev", "1.0.0", false},
		{"1.0.0", "dev", false},
		{"garbage", "1.0.0", true},
		{"1.0.0", "garbage", false},
	} {
		assert.Equal(t, c.newer, backup.NewerVersion(c.v, c.running), "%s vs %s", c.v, c.running)
	}
}

func TestRestoreErrorMessages(t *testing.T) {
	assert.Equal(t, "backup: the backup was created by a newer Alice version (9.0.0)", (&backup.ErrNewer{Version: "9.0.0"}).Error())
	assert.Equal(t, "backup: the backup could not be verified (seal)", (&backup.ErrNotVerified{Reason: "seal"}).Error())
	assert.Equal(t, "backup: the audit log in the backup is damaged at entry 7", (&backup.ErrAuditBroken{Seq: 7}).Error())
	assert.Equal(t, "backup: not enough free disk space for a restore: 1 bytes free, 2 needed", (&backup.ErrNoSpace{Free: 1, Need: 2}).Error())
}
