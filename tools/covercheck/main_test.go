package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const profile = `mode: atomic
alice/internal/license/file.go:10.2,12.3 3 1
alice/internal/license/file.go:14.2,15.3 1 0
alice/internal/license/state.go:5.1,9.2 4 2
alice/internal/license/state.go:5.1,9.2 4 0
alice/internal/rbac/rbac.go:1.1,2.2 2 0
`

func TestPackageCoverage(t *testing.T) {
	cov, err := packageCoverage(strings.NewReader(profile))
	require.NoError(t, err)
	assert.InDelta(t, 87.5, cov["alice/internal/license"], 0.01, "7 of 8 statements; a repeated block counts once")
	assert.InDelta(t, 0, cov["alice/internal/rbac"], 0.01)
}

func TestRunEnforcesFloors(t *testing.T) {
	dir := t.TempDir()
	prof := filepath.Join(dir, "coverage.out")
	require.NoError(t, os.WriteFile(prof, []byte(profile), 0o600))
	floors := filepath.Join(dir, "floors.json")

	require.NoError(t, os.WriteFile(floors, []byte(`{"alice/internal/license": 85}`), 0o600))
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"-profile", prof, "-floors", floors}, &out, &errOut))
	assert.Contains(t, out.String(), "alice/internal/license")

	require.NoError(t, os.WriteFile(floors, []byte(`{"alice/internal/license": 95, "alice/internal/missing": 10}`), 0o600))
	out.Reset()
	assert.Equal(t, 1, run([]string{"-profile", prof, "-floors", floors}, &out, &errOut))
	assert.Contains(t, out.String(), "BELOW FLOOR")
	assert.Contains(t, errOut.String(), "alice/internal/missing: no coverage data")
}
