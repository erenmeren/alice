// Command covercheck enforces per-package statement coverage floors (spec §22.7, R36).
//
//	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("covercheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profilePath := fs.String("profile", "coverage.out", "Go cover profile")
	floorsPath := fs.String("floors", "coverage-floors.json", "JSON object: package import path -> minimum percent")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	raw, err := os.ReadFile(*floorsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	floors := map[string]float64{}
	if err := json.Unmarshal(raw, &floors); err != nil {
		fmt.Fprintln(stderr, "floors:", err)
		return 2
	}
	f, err := os.Open(*profilePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer func() { _ = f.Close() }()
	cov, err := packageCoverage(f)
	if err != nil {
		fmt.Fprintln(stderr, "profile:", err)
		return 2
	}
	pkgs := make([]string, 0, len(floors))
	for p := range floors {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	failed := false
	for _, p := range pkgs {
		got, ok := cov[p]
		if !ok {
			fmt.Fprintf(stderr, "%s: no coverage data\n", p)
			failed = true
			continue
		}
		status := "ok"
		if got < floors[p] {
			status, failed = "BELOW FLOOR", true
		}
		fmt.Fprintf(stdout, "%-40s %6.1f%%  (floor %.0f%%)  %s\n", p, got, floors[p], status)
	}
	if failed {
		return 1
	}
	return 0
}

// packageCoverage returns statement coverage per package from a cover profile. A block that
// appears more than once (merged profiles) counts once, covered if any copy was executed.
func packageCoverage(r io.Reader) (map[string]float64, error) {
	type block struct {
		stmts   int
		covered bool
	}
	blocks := map[string]*block{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("bad profile line %q", line)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad profile line %q", line)
		}
		b, ok := blocks[fields[0]]
		if !ok {
			b = &block{stmts: stmts}
			blocks[fields[0]] = b
		}
		b.covered = b.covered || count > 0
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	total, covered := map[string]int{}, map[string]int{}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ":")]
		pkg := path.Dir(file)
		total[pkg] += b.stmts
		if b.covered {
			covered[pkg] += b.stmts
		}
	}
	out := map[string]float64{}
	for p, n := range total {
		if n > 0 {
			out[p] = 100 * float64(covered[p]) / float64(n)
		}
	}
	return out, nil
}
