package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// today is the date every test checks expiries against.
var today = time.Date(2026, 10, 11, 15, 4, 5, 0, time.UTC)

func TestAcceptsTheFixturePolicy(t *testing.T) {
	p, err := LoadPolicy("testdata/rules.tsv", today)
	require.NoError(t, err)
	assert.Equal(t, Rule{ID: "10096", Action: "IGNORE", Reason: "Timestamps in the build information are not a disclosure", Expires: "2027-01-31"}, p["10096"])
	assert.Equal(t, "FAIL", p["10020"].Action)
	assert.Len(t, p, 3)
}

func TestAcceptsTheRepositoryPolicy(t *testing.T) {
	_, err := LoadPolicy("../../.zap/rules.tsv", today)
	require.NoError(t, err)
}

func TestRefusesABrokenPolicy(t *testing.T) {
	for name, tc := range map[string]struct{ line, want string }{
		"missing reason":       {"10096\tIGNORE\t \t2027-01-31", "rules.tsv:2: rule 10096 has no reason"},
		"three fields":         {"10096\tIGNORE\treason", "rules.tsv:2: want 4 tab-separated fields"},
		"five fields":          {"10096\tIGNORE\treason\t2027-01-31\tmore", "rules.tsv:2: want 4 tab-separated fields"},
		"expired":              {"10096\tIGNORE\treason\t2026-10-10", "rules.tsv:2: rule 10096 expired on 2026-10-10"},
		"too far ahead":        {"10096\tIGNORE\treason\t2027-04-10", "rules.tsv:2: rule 10096 expires 2027-04-10, more than 180 days ahead"},
		"no expiry":            {"10096\tIGNORE\treason\t", "rules.tsv:2: rule 10096 has no expiry date YYYY-MM-DD"},
		"bad date":             {"10096\tIGNORE\treason\t2027-13-01", "rules.tsv:2: rule 10096 has no expiry date YYYY-MM-DD"},
		"unknown action":       {"10096\tINFO\treason\t2027-01-31", "rules.tsv:2: rule 10096: the action must be IGNORE, WARN or FAIL"},
		"rule id is not ZAP's": {"*\tIGNORE\treason\t2027-01-31", "rules.tsv:2: \"*\" is not a ZAP rule id"},
		"duplicate":            {"10020\tWARN\treason\t2027-01-31", "rules.tsv:2: rule 10020 is listed twice"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "rules.tsv")
			require.NoError(t, os.WriteFile(p, []byte("10020\tFAIL\tframing\t2027-01-31\n"+tc.line+"\n"), 0o600))
			_, err := LoadPolicy(p, today)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestExpiryOnTheLastAllowedDayAndToday(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.tsv")
	// 180 days after 2026-10-11 is 2027-04-09; an expiry of today is still valid today.
	require.NoError(t, os.WriteFile(p, []byte("1\tIGNORE\tr\t2027-04-09\n2\tIGNORE\tr\t2026-10-11\n"), 0o600))
	_, err := LoadPolicy(p, today)
	require.NoError(t, err)
}

func TestEvaluateFailsOnMediumAndHighUnlessIgnored(t *testing.T) {
	pol, err := LoadPolicy("testdata/rules.tsv", today)
	require.NoError(t, err)
	var out bytes.Buffer
	failed, err := Evaluate(&out, pol, []string{"testdata/reports/admin.json", "testdata/reports/unauthenticated.json"})
	require.NoError(t, err)
	assert.Equal(t, 3, failed)
	got := out.String()
	// Counts per report (role), the ignored alert included, false positives left out.
	assert.Contains(t, got, "admin: High 1, Medium 2, Low 2, Informational 1 (ignored 1)")
	assert.Contains(t, got, "unauthenticated: High 0, Medium 0, Low 1, Informational 0 (ignored 0)")
	// The High and the Medium fail; the ignored Medium does not; the Low of a FAIL rule does.
	assert.Contains(t, got, "FAIL admin: 40012 High Cross Site Scripting (Reflected) (1 instance(s), first GET https://127.0.0.1:9445/api/v1/x)")
	assert.Contains(t, got, "FAIL admin: 10038 Medium Content Security Policy (CSP) Header Not Set")
	assert.Contains(t, got, "FAIL unauthenticated: 10020 Low Missing Anti-clickjacking Header")
	assert.Contains(t, got, "ignored admin: 10096 Medium Timestamp Disclosure - Unix (until 2027-01-31: Timestamps in the build information are not a disclosure)")
	assert.NotContains(t, got, "10055", "a false positive (confidence 0) is not counted")
}

func TestEvaluatePassesACleanReport(t *testing.T) {
	var out bytes.Buffer
	failed, err := Evaluate(&out, Policy{}, []string{"testdata/reports/clean.json"})
	require.NoError(t, err)
	assert.Zero(t, failed)
	assert.Contains(t, out.String(), "clean: High 0, Medium 0, Low 0, Informational 0 (ignored 0)")
}

func TestEvaluateRefusesAnUnreadableReport(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	require.NoError(t, os.WriteFile(p, []byte("not json"), 0o600))
	_, err := Evaluate(&bytes.Buffer{}, Policy{}, []string{p})
	require.Error(t, err)
	_, err = Evaluate(&bytes.Buffer{}, Policy{}, []string{filepath.Join(t.TempDir(), "missing.json")})
	require.Error(t, err)
}

func TestRun(t *testing.T) {
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"testdata/rules.tsv"}, today, &out, &errOut), errOut.String())
	assert.Contains(t, out.String(), "zaprules: testdata/rules.tsv: 3 rule(s)")

	out.Reset()
	assert.Equal(t, 1, run([]string{"-reports", "testdata/reports", "testdata/rules.tsv"}, today, &out, &errOut))
	assert.Contains(t, out.String(), "3 alert(s) at Medium or above")

	assert.Equal(t, 2, run(nil, today, &out, &errOut))
	errOut.Reset()
	assert.Equal(t, 1, run([]string{"testdata/missing.tsv"}, today, &out, &errOut))
	assert.True(t, strings.Contains(errOut.String(), "missing.tsv"), errOut.String())
	errOut.Reset()
	assert.Equal(t, 1, run([]string{"-reports", "testdata/none", "testdata/rules.tsv"}, today, &out, &errOut))
	assert.Contains(t, errOut.String(), "no ZAP report")
}
