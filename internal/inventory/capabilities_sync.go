package inventory

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// SyncCapabilities rewrites targets.capabilities of every live target from the provider registered for its type (spec
// §8.1), so the UI's can() and the server's checks always agree and a capability change needs no data migration. It runs
// at startup, in one transaction, and returns how many targets changed. A type without a registered provider is skipped.
// version and updated_at stay: the capability set is not part of the editable resource. One audit row records a change;
// a run that changes nothing writes none.
func (s *Service) SyncCapabilities(ctx context.Context) (int, error) {
	changed := 0
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		changed = 0
		for _, typ := range append([]string{TypeLinux, TypeWindows, TypeAzureKeyVault}, webServerTypes...) {
			p, ok := s.providerFor(typ)
			if !ok {
				continue
			}
			caps := make([]string, 0, len(p.Capabilities()))
			for _, c := range p.Capabilities().Sorted() {
				caps = append(caps, string(c))
			}
			tag, err := tx.Exec(ctx, `UPDATE targets SET capabilities = $2
WHERE type = $1 AND deleted_at IS NULL AND capabilities IS DISTINCT FROM $2`, typ, caps)
			if err != nil {
				return fmt.Errorf("inventory: sync the capabilities of %s targets: %w", typ, err)
			}
			changed += int(tag.RowsAffected())
		}
		if changed == 0 {
			return nil
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.SystemActor("startup"), Action: "target.capabilities_synced",
			ObjectType: "target", Result: audit.Success, Details: map[string]string{"targets": strconv.Itoa(changed)}})
		return err
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}
