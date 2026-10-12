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

// Review L-14: a caller that means one unique constraint names it, so a violation of another one is not misreported.
func TestIsUniqueViolationOn(t *testing.T) {
	dup := &pgconn.PgError{Code: "23505", ConstraintName: "users_username_key"}
	assert.True(t, db.IsUniqueViolationOn(dup, "users_username_key"))
	assert.True(t, db.IsUniqueViolationOn(fmt.Errorf("insert user: %w", dup), "users_username_key"))
	assert.False(t, db.IsUniqueViolationOn(dup, "users_pkey"), "another constraint")
	assert.False(t, db.IsUniqueViolationOn(&pgconn.PgError{Code: "23503", ConstraintName: "users_username_key"}, "users_username_key"))
	assert.False(t, db.IsUniqueViolationOn(errors.New("23505"), "users_username_key"))
	assert.False(t, db.IsUniqueViolationOn(nil, "users_username_key"))
}
