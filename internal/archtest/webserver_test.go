package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only the one web-server type list names Nginx: every other check asks inventory.IsWebServer
// or a provider capability, so a discovery-only web server is never offered a deployment.
func TestOnlyTheTypeListNamesNginx(t *testing.T) {
	root := moduleRoot(t)
	allowed := filepath.Join(root, "internal", "inventory", "types.go")
	var violations []string
	scanned := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == allowed {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			scanned++
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == "TypeNginx" {
					violations = append(violations, fset.Position(id.Pos()).String())
				}
				return true
			})
			return nil
		})
		require.NoError(t, err)
	}
	assert.Greater(t, scanned, 100, "the scan found the sources")
	assert.Empty(t, violations, "TypeNginx is named by internal/inventory/types.go only")
}
