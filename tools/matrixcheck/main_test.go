package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureSpec = `# Quality

## 22. Something else

| ID | Case |
| --- | --- |
| L-99 | outside the matrices |

## 23. License

| ID | Setup | Action | Result |
| --- | --- | --- | --- |
| L-01 | Fresh install | Complete wizard | EVAL |
| L-02 | Nearly over | Wait | still EVAL |

## 24. Failures

| ID | Failure | Expected |
| --- | --- | --- |
| F-01 | nginx -t fails | rolled back |
| F-80 | wrong passphrase | nothing changes |

## 25. Security

### 25.2 Leaks

| ID | Check | Expected |
| --- | --- | --- |
| S-01 | secrets in logs | none |

## 26. Plan

| X-01 | not a matrix row |
`

func writeFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

// fixture builds a tree with a spec, a test package and a map, and returns the paths.
func fixture(t *testing.T, mapJSON string) (root, spec, mp string) {
	t.Helper()
	root = t.TempDir()
	spec = writeFile(t, root, "spec.md", fixtureSpec)
	mp = writeFile(t, root, "map.json", mapJSON)
	writeFile(t, root, "internal/lic/lic_test.go", "package lic\n\nfunc TestL01Fresh(t *testing.T) {}\nfunc TestL02Nearly(t *testing.T) {}\nfunc FuzzParse(f *testing.F) {}\n")
	writeFile(t, root, "web/src/a.test.ts", "it('shows the banner S-01', () => {})\n")
	return root, spec, mp
}

const fullMap = `[
 {"id":"L-01","status":"test","tests":["internal/lic:TestL01Fresh"]},
 {"id":"L-02","status":"test","tests":["internal/lic:TestL02Nearly","web/src/a.test.ts:shows the banner"]},
 {"id":"F-01","status":"owner","owner":"docs/security/reviews/phase-8.md#owner-verification"},
 {"id":"F-80","status":"deferred","ruling":"R43 row 35"},
 {"id":"S-01","status":"gap","note":"no test yet"}
]`

func TestExtractsEveryMatrixID(t *testing.T) {
	ids, titles, err := SpecIDs(strings.NewReader(fixtureSpec))
	require.NoError(t, err)
	assert.Equal(t, []string{"L-01", "L-02", "F-01", "F-80", "S-01"}, ids, "rows of sections 23 to 25 only")
	assert.Equal(t, "Fresh install / Complete wizard", titles["L-01"], "a license row names setup and action")
	assert.Equal(t, "nginx -t fails", titles["F-01"])

	_, _, err = SpecIDs(strings.NewReader("## 23. A\n| L-01 | a |\n| L-01 | b |\n"))
	assert.Error(t, err, "a duplicate ID in the specification")
}

func TestRefusesMissingUnknownAndBrokenEntries(t *testing.T) {
	for name, tc := range map[string]struct{ mapJSON, want string }{
		"missing":          {`[{"id":"L-01","status":"owner","owner":"x"}]`, "L-02: no entry"},
		"unknown":          {fullMap[:len(fullMap)-1] + `,{"id":"L-77","status":"owner","owner":"x"}]`, "L-77: the specification has no such ID"},
		"duplicate":        {fullMap[:len(fullMap)-1] + `,{"id":"L-01","status":"owner","owner":"x"}]`, "L-01: listed twice"},
		"deferred":         {strings.Replace(fullMap, `"ruling":"R43 row 35"`, `"note":"n"`, 1), "F-80: status deferred without ruling"},
		"owner":            {strings.Replace(fullMap, `"owner":"docs/security/reviews/phase-8.md#owner-verification"`, `"note":"n"`, 1), "F-01: status owner without owner"},
		"test no tests":    {strings.Replace(fullMap, `"tests":["internal/lic:TestL01Fresh"]`, `"tests":[]`, 1), "L-01: status test without tests"},
		"bad test name":    {strings.Replace(fullMap, `internal/lic:TestL01Fresh`, `internal/lic:helper`, 1), "not a Test or Fuzz function"},
		"no colon":         {strings.Replace(fullMap, `internal/lic:TestL01Fresh`, `TestL01Fresh`, 1), "is not <directory>:<name>"},
		"gap no note":      {strings.Replace(fullMap, `"note":"no test yet"`, `"ruling":"r"`, 1), "S-01: status gap without note"},
		"unknown status":   {strings.Replace(fullMap, `"status":"gap"`, `"status":"done"`, 1), `S-01: unknown status "done"`},
		"partial no note":  {strings.Replace(fullMap, `"status":"test","tests":["internal/lic:TestL01Fresh"]`, `"status":"partial","tests":["internal/lic:TestL01Fresh"],"ruling":"r"`, 1), "L-01: status partial without note"},
		"partial no tests": {strings.Replace(fullMap, `"status":"test","tests":["internal/lic:TestL01Fresh"]`, `"status":"partial","note":"n","ruling":"r"`, 1), "L-01: status partial without tests"},
	} {
		t.Run(name, func(t *testing.T) {
			root, spec, mp := fixture(t, tc.mapJSON)
			for _, strict := range []bool{false, true} {
				res, err := Run(root, spec, mp, strict)
				require.NoError(t, err)
				assert.Contains(t, strings.Join(res.Errors, "\n"), tc.want, "strict=%v", strict)
			}
		})
	}

	root, spec, mp := fixture(t, `[{"id":"L-01","status":"owner","owner":"x","surprise":1}]`)
	_, err := Run(root, spec, mp, false)
	assert.Error(t, err, "an unknown JSON field")
	_, err = Run(root, spec, filepath.Join(root, "nope.json"), false)
	assert.Error(t, err)
}

func TestPendingTestsFailOnlyWhenStrict(t *testing.T) {
	m := strings.Replace(fullMap, `internal/lic:TestL01Fresh`, `internal/lic:TestL01NotWrittenYet`, 1)
	m = strings.Replace(m, `"web/src/a.test.ts:shows the banner"`, `"web/src/a.test.ts:no such title"`, 1)
	root, spec, mp := fixture(t, m)

	res, err := Run(root, spec, mp, false)
	require.NoError(t, err)
	assert.Empty(t, res.Errors)
	assert.Equal(t, 2, res.Pending)
	assert.Equal(t, 0, res.ByTests)
	assert.Equal(t, "matrix-check: 5 IDs, 0 by tests, 0 partial, 2 pending, 1 owner, 1 deferred, 1 gaps", res.Summary())

	res, err = Run(root, spec, mp, true)
	require.NoError(t, err)
	joined := strings.Join(res.Errors, "\n")
	assert.Contains(t, joined, "L-01: test internal/lic:TestL01NotWrittenYet does not exist")
	assert.Contains(t, joined, "L-02: test web/src/a.test.ts:no such title does not exist")
}

func TestStrictRefusesGaps(t *testing.T) {
	root, spec, mp := fixture(t, fullMap)
	res, err := Run(root, spec, mp, false)
	require.NoError(t, err)
	assert.Empty(t, res.Errors)
	assert.Equal(t, "matrix-check: 5 IDs, 2 by tests, 0 partial, 0 pending, 1 owner, 1 deferred, 1 gaps", res.Summary())

	res, err = Run(root, spec, mp, true)
	require.NoError(t, err)
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "S-01: gap: no test yet")
}

// Task 14 review I-1: a row whose tests prove only part of it is "partial"; -strict refuses it
// unless a ruling (or an owner step) accounts for the rest.
func TestPartialNeedsARulingWhenStrict(t *testing.T) {
	m := strings.Replace(fullMap, `"status":"test","tests":["internal/lic:TestL01Fresh"]`,
		`"status":"partial","tests":["internal/lic:TestL01Fresh"],"note":"the warning is unproven"`, 1)
	root, spec, mp := fixture(t, m)
	res, err := Run(root, spec, mp, false)
	require.NoError(t, err)
	assert.Empty(t, res.Errors)
	assert.Equal(t, "matrix-check: 5 IDs, 1 by tests, 1 partial, 0 pending, 1 owner, 1 deferred, 1 gaps", res.Summary())
	assert.Contains(t, res.Doc, "| L-01 | Fresh install / Complete wizard | partial | `internal/lic:TestL01Fresh`<br>the warning is unproven |")
	assert.Contains(t, res.Doc, "5 IDs: 1 test, 1 partial, 1 owner, 1 deferred, 1 gap.")

	res, err = Run(root, spec, mp, true)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(res.Errors, "\n"), "L-01: partial without a ruling or owner step: the warning is unproven")

	for _, extra := range []string{`,"ruling":"rulings/phase-8.md G-1"`, `,"owner":"release checklist 1.2"`} {
		root, spec, mp = fixture(t, strings.Replace(m, `"note":"the warning is unproven"`, `"note":"the warning is unproven"`+extra, 1))
		res, err = Run(root, spec, mp, true)
		require.NoError(t, err)
		require.Len(t, res.Errors, 1, extra)
		assert.Contains(t, res.Errors[0], "S-01: gap")
	}

	// A partial row's named tests must exist like a test row's.
	root, spec, mp = fixture(t, strings.Replace(m, "TestL01Fresh", "TestL01Missing", 1))
	res, err = Run(root, spec, mp, false)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Pending)
	assert.Equal(t, 0, res.Partial)
}

func TestDocIsCurrent(t *testing.T) {
	root, spec, mp := fixture(t, fullMap)
	res, err := Run(root, spec, mp, false)
	require.NoError(t, err)
	assert.Contains(t, res.Doc, "| L-01 | Fresh install / Complete wizard | test | `internal/lic:TestL01Fresh` |")
	assert.Contains(t, res.Doc, "| F-80 | wrong passphrase | deferred | ruling: R43 row 35 |")
	assert.Contains(t, res.Doc, "5 IDs: 2 test, 0 partial, 1 owner, 1 deferred, 1 gap.")

	// The repository's own document equals the generated text.
	repo := filepath.Join("..", "..")
	real, err := Run(repo, filepath.Join(repo, "docs/superpowers/specs/alice-v1/06-quality.md"), filepath.Join(repo, "test/matrix/traceability.json"), false)
	require.NoError(t, err)
	assert.Empty(t, real.Errors)
	cur, err := os.ReadFile(filepath.Join(repo, "docs/security/traceability.md"))
	require.NoError(t, err)
	assert.Equal(t, string(cur), real.Doc, "run: go run ./tools/matrixcheck -update")
}
