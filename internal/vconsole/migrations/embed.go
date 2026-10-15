// Package migrations embeds the goose SQL migrations of the vendor console database. It is
// separate from alice/migrations: this schema lives in the vendor's own database.
package migrations

import "embed"

// FS holds the migration files at its root.
//
//go:embed *.sql
var FS embed.FS
