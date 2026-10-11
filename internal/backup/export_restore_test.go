package backup

import (
	"context"
	"crypto/ecdh"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/backup/dump"
	"alice/internal/backup/format"
	"alice/internal/secrets"
)

// SetRestoreHook runs f at each of Restore's crash points; an error fails the restore there, a panic stops it as a
// crash would.
func SetRestoreHook(in *RestoreInput, f func(point string) error) { in.hook = f }

// SetLoad replaces dump.Load in Restore.
func SetLoad(in *RestoreInput, f func(ctx context.Context, conn *pgx.Conn, dec *dump.Decoder, first dump.Frame) (dump.Stats, error)) {
	in.load = f
}

// WriteBackupWith writes a manual backup of the service's database to path with these keys instead of the stored
// ones (a database of an older schema cannot hold the sender key). It skips the lock, the state and the audit row.
func WriteBackupWith(ctx context.Context, s *Service, path string, w format.WrappedKey, sender *ecdh.PrivateKey) error {
	now := s.c.Clock.Now().UTC().Truncate(time.Second)
	id, err := s.installationID(ctx, s.c.Pool)
	if err != nil {
		return err
	}
	files, err := s.readFiles()
	if err != nil {
		return err
	}
	in := CreateInput{Kind: KindManual, Actor: audit.SystemActor("test")}
	_, err = s.writePartial(ctx, path, w, sender, format.Meta{AliceVersion: s.c.Version, CreatedAt: now, Kind: string(in.Kind)},
		func(enc *dump.Encoder) error { return s.payload(ctx, enc, in, now, id, files) })
	return err
}

// RestorePoints lists Restore's crash points in order.
func RestorePoints() []string { return slices.Clone(restorePoints) }

// InstallationSeal is the seal the restore verifies.
func InstallationSeal(k *secrets.Keyring, id string, at time.Time) []byte {
	return installationSeal(k, id, at)
}

// DDL is the restore's one DDL builder: op is "create", "rename" or "drop".
func DDL(op, name, to string) string {
	return ddl(map[string]ddlOp{"create": ddlCreate, "rename": ddlRename, "drop": ddlDrop}[op], name, to)
}

// NewerVersion reports whether version v is newer than the running one.
func NewerVersion(v, running string) bool { return newerVersion(v, running) }
