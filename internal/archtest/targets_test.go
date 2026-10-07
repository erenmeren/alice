package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var insertIntoTargets = regexp.MustCompile(`(?i)\binsert\s+into\s+targets\b`)

// targetInsertViolations lists the functions of f that insert into the targets table
// without calling CheckCanAddTarget (spec L-79: no code path may bypass the license limit).
func targetInsertViolations(fset *token.FileSet, f *ast.File) []string {
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		inserts, checks := false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind == token.STRING && insertIntoTargets.MatchString(x.Value) {
					inserts = true
				}
			case *ast.SelectorExpr:
				if x.Sel.Name == "CheckCanAddTarget" {
					checks = true
				}
			}
			return true
		})
		if inserts && !checks {
			out = append(out, fset.Position(fn.Pos()).String()+" "+fn.Name.Name)
		}
	}
	return out
}

func TestEveryTargetInsertChecksTheLicense(t *testing.T) {
	root := moduleRoot(t)
	scanned := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// Test-data helpers (internal/testutil/seed) write rows as the owner role and are never linked into a
			// release binary; they have no license service to ask.
			if strings.Contains(filepath.ToSlash(path), "/internal/testutil/") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			scanned++
			for _, v := range targetInsertViolations(fset, f) {
				t.Errorf("%s inserts into targets without license.Service.CheckCanAddTarget (spec L-79)", v)
			}
			return nil
		})
		require.NoError(t, err)
	}
	require.Positive(t, scanned)
}

func TestTargetInsertCheckCatchesAMissingCall(t *testing.T) {
	src := `package x
func bad(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "INSERT INTO targets (id) VALUES ($1)", 1)
	return err
}
func good(ctx context.Context, tx pgx.Tx, l *license.Service) error {
	if err := l.CheckCanAddTarget(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "insert into targets (id) values ($1)", 1)
	return err
}
func other(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "INSERT INTO target_locks (id) VALUES ($1)", 1)
	return err
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	require.NoError(t, err)
	v := targetInsertViolations(fset, f)
	require.Len(t, v, 1)
	assert.Contains(t, v[0], "bad")
}
