package version_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/version"
)

func TestGetReturnsBuildInfoWithSnakeCaseJSON(t *testing.T) {
	version.Version, version.Commit, version.BuildTime = "1.2.3", "abc123", "2026-09-29T10:00:00Z"
	t.Cleanup(func() { version.Version, version.Commit, version.BuildTime = "dev", "unknown", "unknown" })

	b, err := json.Marshal(version.Get())
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":"1.2.3","commit":"abc123","build_time":"2026-09-29T10:00:00Z"}`, string(b))
}
