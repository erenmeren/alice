package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const linuxsshImport = "alice/internal/providers/linuxssh"

// forcedCommandUses lists where a file names linuxssh.ForcedCommand through its import of linuxssh (under any name).
func forcedCommandUses(fset *token.FileSet, f *ast.File) []string {
	names := map[string]bool{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != linuxsshImport {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = true
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "ForcedCommand" {
			if id, ok := sel.X.(*ast.Ident); ok && names[id.Name] {
				out = append(out, fset.Position(sel.Pos()).String())
			}
		}
		return true
	})
	return out
}

// linuxssh.ForcedCommand builds a helper line without a shell's quoting (R60 Ruling 5): only the Windows provider,
// whose forced command splits the line itself, may use it. Every other caller stays on the quoted HelperCommand
// constructors (SEC-063). Test files are not scanned; linuxssh's own files do not import linuxssh.
func TestOnlyTheWindowsProviderUsesForcedCommand(t *testing.T) {
	root := moduleRoot(t)
	allowed := filepath.Join(root, "internal", "providers", "windows")
	var violations []string
	scanned, uses := 0, 0
	for _, dir := range []string{"internal", "cmd", "tools"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly|parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			scanned++
			imports := false
			for _, imp := range f.Imports {
				imports = imports || imp.Path.Value == strconv.Quote(linuxsshImport)
			}
			if !imports {
				return nil
			}
			if f, err = parser.ParseFile(fset, p, nil, parser.SkipObjectResolution); err != nil {
				return err
			}
			found := forcedCommandUses(fset, f)
			if filepath.Dir(p) == allowed {
				uses += len(found)
				return nil
			}
			violations = append(violations, found...)
			return nil
		})
		require.NoError(t, err)
	}
	assert.Greater(t, scanned, 100, "the scan found the sources")
	assert.Positive(t, uses, "the Windows provider's use is found (the guard sees what it guards)")
	assert.Empty(t, violations, "only internal/providers/windows calls linuxssh.ForcedCommand")
}

// The guard finds the call under the package name and under an alias, and ignores another package's ForcedCommand.
func TestForcedCommandUsesFindsAliases(t *testing.T) {
	src := `package x
import (
	ls "alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh"
	other "example.com/other"
)
var _, _ = ls.ForcedCommand(nil, nil, 0, 0)
var _, _ = linuxssh.ForcedCommand(nil, nil, 0, 0)
var _ = other.ForcedCommand
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	require.NoError(t, err)
	assert.Len(t, forcedCommandUses(fset, f), 2)
}
