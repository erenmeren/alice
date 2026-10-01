package linuxssh

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only dial.go opens SSH sessions, so Conn.Run (with its timeout, output cap and the
// constructor-built command line) is the only way a command reaches a server (SEC-063).
func TestOnlyDialCreatesSessions(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "NewSession", "Shell", "RequestPty":
				if name != "dial.go" || sel.Sel.Name != "NewSession" {
					t.Errorf("%s: %s outside dial.go's Conn.Run", fset.Position(call.Pos()), sel.Sel.Name)
				}
				found++
			}
			return true
		})
	}
	assert.Equal(t, 1, found, "exactly one NewSession call, in Conn.Run")
}

// Nothing in the repository may accept every host key (SEC-080). The needles are built at run
// time so this file does not match itself.
func TestNoCodeAcceptsAnyHostKey(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err, "repository root not found")
	insecure := "ssh." + "InsecureIgnoreHostKey"
	strict := "StrictHostKeyChecking" + "=no"
	skip := map[string]bool{".git": true, "node_modules": true, "docs": true, "bin": true, "dist": true,
		"playwright-report": true, "test-results": true}
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		switch {
		case ext == ".go", ext == ".sh", ext == ".yml", ext == ".yaml", ext == ".ts", ext == ".tsx", ext == ".js",
			strings.HasPrefix(d.Name(), "Dockerfile"), ext == ".conf":
		default:
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: walking the repository in a test
		if err != nil {
			return err
		}
		scanned++
		if strings.Contains(string(b), insecure) {
			t.Errorf("%s uses %s", path, insecure)
		}
		if strings.Contains(string(b), strict) {
			t.Errorf("%s disables host key checking", path)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, scanned, 100, "the walk found too few files; is it scanning the repository?")
}
