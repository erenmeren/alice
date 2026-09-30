package main

import (
	"encoding/json"
	"errors"
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

// allowListFile optionally lists keys whose translation may equal the base value
// (brand names, technical terms). Files starting with "." are never catalogs.
const allowListFile = ".i18n-identical.json"

var (
	// placeholderRE matches the only placeholder form the backend substitutes: {{name}}.
	placeholderRE = regexp.MustCompile(`\{\{([A-Za-z0-9_.]+)\}\}`)
	// spacedRE matches placeholders with inner whitespace, which i18n.T would not substitute.
	spacedRE = regexp.MustCompile(`\{\{\s*[A-Za-z0-9_.]+\s*\}\}`)
)

// CheckDir compares every <code>.json in fsys against <base>.json.
func CheckDir(fsys fs.FS, base string) ([]Problem, error) {
	baseFile := base + ".json"
	baseMsgs, err := load(fsys, baseFile)
	if err != nil {
		return nil, err
	}
	allowed, err := loadAllowList(fsys)
	if err != nil {
		return nil, err
	}
	var problems []Problem
	for k, v := range baseMsgs {
		problems = append(problems, valueProblems(baseFile, k, v)...)
	}
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f == baseFile || strings.HasPrefix(f, ".") {
			continue
		}
		code := strings.TrimSuffix(f, ".json")
		msgs, err := load(fsys, f)
		if err != nil {
			return nil, err
		}
		for k, bv := range baseMsgs {
			v, ok := msgs[k]
			if !ok {
				problems = append(problems, Problem{f, k, "missing key"})
				continue
			}
			if vp := valueProblems(f, k, v); len(vp) > 0 {
				problems = append(problems, vp...)
				continue
			}
			switch {
			case !slices.Equal(placeholders(bv), placeholders(v)):
				problems = append(problems, Problem{f, k, fmt.Sprintf("placeholders differ: %s has %v, %s has %v", base, placeholders(bv), code, placeholders(v))})
			case v == bv && !allowed[k]:
				problems = append(problems, Problem{f, k, "value is identical to " + base + "; translate it or allow-list the key in " + allowListFile})
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
		if problems[i].Key != problems[j].Key {
			return problems[i].Key < problems[j].Key
		}
		return problems[i].Msg < problems[j].Msg
	})
	return problems, nil
}

// valueProblems reports problems that depend on one value only.
func valueProblems(file, key, v string) []Problem {
	if strings.TrimSpace(v) == "" {
		return []Problem{{file, key, "value is empty"}}
	}
	var out []Problem
	for _, m := range spacedRE.FindAllString(v, -1) {
		if !placeholderRE.MatchString(m) {
			out = append(out, Problem{file, key, "placeholder must not contain spaces: " + m})
		}
	}
	return out
}

func loadAllowList(fsys fs.FS) (map[string]bool, error) {
	data, err := fs.ReadFile(fsys, allowListFile)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", allowListFile, err)
	}
	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("%s must be a JSON array of keys: %w", allowListFile, err)
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out, nil
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
