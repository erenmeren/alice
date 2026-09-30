package db_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

	"alice/internal/platform/db"
)

func TestIsUniqueViolation(t *testing.T) {
	dup := &pgconn.PgError{Code: "23505"}
	assert.True(t, db.IsUniqueViolation(dup))
	assert.True(t, db.IsUniqueViolation(fmt.Errorf("insert user: %w", dup)))
	assert.False(t, db.IsUniqueViolation(&pgconn.PgError{Code: "23503"}))
	assert.False(t, db.IsUniqueViolation(errors.New("23505")))
	assert.False(t, db.IsUniqueViolation(nil))
}
