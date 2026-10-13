package transport

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNoInsecureSkipVerify fails when the identifier appears in any non-test source under internal/acme.
func TestNoInsecureSkipVerify(t *testing.T) {
	root := filepath.Join("..")
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		n++
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		require.NotContains(t, string(b), "Insecure"+"SkipVerify", p)
		return nil
	})
	require.NoError(t, err)
	require.Positive(t, n)
}
