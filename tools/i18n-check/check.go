package main

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"

	"alice/internal/i18n"
)

// Problem is one catalog inconsistency.
type Problem struct {
	File, Key, Msg string
}

var placeholderRE = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.]+)\s*\}\}`)

// CheckDir compares every <code>.json in fsys against <base>.json.
func CheckDir(fsys fs.FS, base string) ([]Problem, error) {
	baseFile := base + ".json"
	baseMsgs, err := load(fsys, baseFile)
	if err != nil {
		return nil, err
	}
	var problems []Problem
	for k, v := range baseMsgs {
		if strings.TrimSpace(v) == "" {
			problems = append(problems, Problem{baseFile, k, "value is empty"})
		}
	}
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f == baseFile {
			continue
		}
		code := strings.TrimSuffix(f, ".json")
		msgs, err := load(fsys, f)
		if err != nil {
			return nil, err
		}
		for k, bv := range baseMsgs {
			v, ok := msgs[k]
			switch {
			case !ok:
				problems = append(problems, Problem{f, k, "missing key"})
			case strings.TrimSpace(v) == "":
				problems = append(problems, Problem{f, k, "value is empty"})
			case !slices.Equal(placeholders(bv), placeholders(v)):
				problems = append(problems, Problem{f, k, fmt.Sprintf("placeholders differ: %s has %v, %s has %v", base, placeholders(bv), code, placeholders(v))})
			}
		}
		for k := range msgs {
			if _, ok := baseMsgs[k]; !ok {
				problems = append(problems, Problem{f, k, "key not present in " + baseFile})
			}
		}
	}
	sort.Slice(problems, func(i, j int) bool {
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		return problems[i].Key < problems[j].Key
	})
	return problems, nil
}

func load(fsys fs.FS, name string) (map[string]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	m, err := i18n.Flatten(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return m, nil
}

func placeholders(s string) []string {
	var out []string
	for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}
