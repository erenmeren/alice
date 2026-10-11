// Command zaprules checks the ZAP rule policy .zap/rules.tsv and, with -reports, applies it to the
// JSON reports of a ZAP run (spec §25.7).
//
//	go run ./tools/zaprules .zap/rules.tsv                      check the policy
//	go run ./tools/zaprules -reports bin/zap .zap/rules.tsv     check it, then judge every *.json report in bin/zap
//	go run ./tools/zaprules -reports bin/zap -expect admin,auditor .zap/rules.tsv
//	                                                            the same, and admin.json and auditor.json must exist
//
// A policy line is "<rule id>\t<IGNORE|WARN|FAIL>\t<reason>\t<expires YYYY-MM-DD>"; lines starting
// with # and empty lines are comments. ZAP reads the same file (-c): it takes the third field as
// the rule's name and the fourth as its message. Every line needs a reason and an expiry at most
// 180 days ahead; an expired line, a missing reason or a duplicate rule fails the check.
//
// A report fails on any alert of level Medium or High whose rule is not IGNORE, and on any alert
// of a FAIL rule; WARN changes nothing (Medium and High always fail). Alerts ZAP marks as false
// positives (confidence 0) are not counted. The summary names each report by its file name (the
// role of the scan) with its alert counts per level.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxAhead is how far ahead an expiry may lie: every rule is reviewed at least twice a year.
const maxAhead = 180 * 24 * time.Hour

func main() {
	os.Exit(run(os.Args[1:], time.Now(), os.Stdout, os.Stderr)) //nolint:forbidigo // a developer tool, not product code
}

func run(args []string, now time.Time, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("zaprules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reports := fs.String("reports", "", "judge every *.json ZAP report in this directory")
	expect := fs.String("expect", "", "comma-separated report names (without .json) that must be in -reports, one per role scanned")
	usage := func() int {
		_, _ = fmt.Fprintln(stderr, "usage: zaprules [-reports DIR [-expect NAME,...]] RULES.tsv")
		return 2
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return usage()
	}
	var expected []string
	if *expect != "" {
		if *reports == "" {
			return usage()
		}
		expected = strings.Split(*expect, ",")
		for _, e := range expected {
			if e == "" || strings.ContainsAny(e, "/\\") {
				return usage()
			}
		}
	}
	pol, err := LoadPolicy(fs.Arg(0), now)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "zaprules:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "zaprules: %s: %d rule(s), none expired\n", fs.Arg(0), len(pol))
	if *reports == "" {
		return 0
	}
	// A role whose scan wrote no report would otherwise pass unnoticed (Task 15 review M-1).
	for _, e := range expected {
		if _, err := os.Stat(filepath.Join(*reports, e+".json")); err != nil {
			_, _ = fmt.Fprintf(stderr, "zaprules: the report %s.json is missing from %s\n", e, *reports)
			return 1
		}
	}
	files, _ := filepath.Glob(filepath.Join(*reports, "*.json"))
	if len(files) == 0 {
		_, _ = fmt.Fprintf(stderr, "zaprules: no ZAP report (*.json) in %s\n", *reports)
		return 1
	}
	sort.Strings(files)
	failed, err := Evaluate(stdout, pol, files)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "zaprules:", err)
		return 1
	}
	if failed > 0 {
		_, _ = fmt.Fprintf(stdout, "zaprules: %d alert(s) at Medium or above (or of a FAIL rule) not ignored by %s\n", failed, fs.Arg(0))
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "zaprules: no alert at Medium or above")
	return 0
}

// Rule is one policy line.
type Rule struct {
	ID, Action, Reason, Expires string
}

// Policy maps a ZAP rule (plugin) id to its line.
type Policy map[string]Rule

var (
	ruleIDRe = regexp.MustCompile(`^[0-9]{1,6}$`)
	dateRe   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// LoadPolicy reads and checks a policy file against the date of now.
func LoadPolicy(path string, now time.Time) (Policy, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the policy file named on the command line
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	name := filepath.Base(path)
	pol := Policy{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("%s:%d: want 4 tab-separated fields (rule id, IGNORE|WARN|FAIL, reason, expires YYYY-MM-DD), got %d", name, n, len(f))
		}
		r := Rule{ID: strings.TrimSpace(f[0]), Action: strings.TrimSpace(f[1]), Reason: strings.TrimSpace(f[2]), Expires: strings.TrimSpace(f[3])}
		if !ruleIDRe.MatchString(r.ID) {
			return nil, fmt.Errorf("%s:%d: %q is not a ZAP rule id", name, n, r.ID)
		}
		switch r.Action {
		case "IGNORE", "WARN", "FAIL":
		default:
			return nil, fmt.Errorf("%s:%d: rule %s: the action must be IGNORE, WARN or FAIL", name, n, r.ID)
		}
		if r.Reason == "" {
			return nil, fmt.Errorf("%s:%d: rule %s has no reason", name, n, r.ID)
		}
		exp, err := time.Parse(time.DateOnly, r.Expires)
		if err != nil || !dateRe.MatchString(r.Expires) {
			return nil, fmt.Errorf("%s:%d: rule %s has no expiry date YYYY-MM-DD", name, n, r.ID)
		}
		if exp.Before(today) {
			return nil, fmt.Errorf("%s:%d: rule %s expired on %s; review it and set a new expiry or remove the line", name, n, r.ID, r.Expires)
		}
		if exp.Sub(today) > maxAhead {
			return nil, fmt.Errorf("%s:%d: rule %s expires %s, more than 180 days ahead", name, n, r.ID, r.Expires)
		}
		if _, dup := pol[r.ID]; dup {
			return nil, fmt.Errorf("%s:%d: rule %s is listed twice", name, n, r.ID)
		}
		pol[r.ID] = r
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pol, nil
}

// report is the part of ZAP's traditional JSON report (-J) the check reads.
type report struct {
	Site []struct {
		Alerts []struct {
			PluginID   string `json:"pluginid"`
			Name       string `json:"name"`
			RiskCode   string `json:"riskcode"`
			Confidence string `json:"confidence"`
			Count      string `json:"count"`
			Instances  []struct {
				URI    string `json:"uri"`
				Method string `json:"method"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

var levels = []string{"Informational", "Low", "Medium", "High"}

// Evaluate judges the reports against pol, writes a summary per report to w and returns the number
// of failing alerts.
func Evaluate(w io.Writer, pol Policy, files []string) (int, error) {
	failed := 0
	for _, file := range files {
		raw, err := os.ReadFile(file) //nolint:gosec // G304: a report of this ZAP run
		if err != nil {
			return 0, err
		}
		var rep report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return 0, fmt.Errorf("%s: not a ZAP JSON report: %w", file, err)
		}
		role := strings.TrimSuffix(filepath.Base(file), ".json")
		counts := make([]int, len(levels))
		ignored := 0
		var lines []string
		for _, site := range rep.Site {
			for _, a := range site.Alerts {
				risk, err := strconv.Atoi(a.RiskCode)
				if err != nil || risk < 0 || risk >= len(levels) {
					return 0, fmt.Errorf("%s: alert %s has the risk code %q", file, a.PluginID, a.RiskCode)
				}
				if a.Confidence == "0" {
					continue // ZAP's "False Positive" confidence
				}
				counts[risk]++
				r, listed := pol[a.PluginID]
				switch {
				case listed && r.Action == "IGNORE":
					ignored++
					if risk >= 2 {
						lines = append(lines, fmt.Sprintf("  ignored %s: %s %s %s (until %s: %s)", role, a.PluginID, levels[risk], a.Name, r.Expires, r.Reason))
					}
				case risk >= 2 || (listed && r.Action == "FAIL"):
					failed++
					first := ""
					if len(a.Instances) > 0 {
						first = ", first " + a.Instances[0].Method + " " + a.Instances[0].URI
					}
					lines = append(lines, fmt.Sprintf("  FAIL %s: %s %s %s (%s instance(s)%s)", role, a.PluginID, levels[risk], a.Name, a.Count, first))
				}
			}
		}
		if _, err := fmt.Fprintf(w, "%s: High %d, Medium %d, Low %d, Informational %d (ignored %d)\n", role, counts[3], counts[2], counts[1], counts[0], ignored); err != nil {
			return 0, err
		}
		for _, l := range lines {
			if _, err := fmt.Fprintln(w, l); err != nil {
				return 0, err
			}
		}
	}
	return failed, nil
}
