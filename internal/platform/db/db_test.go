package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
)

func TestOpenGivesUpWhenDatabaseUnreachableWithoutLeakingPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	pool, err := db.Open(ctx, "postgres://alice:s3cret-pw@127.0.0.1:1/alice?sslmode=disable")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.True(t, errors.Is(err, db.ErrUnreachable))
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "127.0.0.1:1")
	assert.Less(t, time.Since(start), 4*time.Second)
}

func TestOpenRejectsInvalidURLWithoutEchoingIt(t *testing.T) {
	_, err := db.Open(context.Background(), "postgres://alice:s3cret-pw@host:notaport/alice")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "ALICE_DATABASE_URL")
}
