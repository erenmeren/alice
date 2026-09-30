// Package i18n loads translation catalogs and renders messages by key.
// The backend returns stable keys; this package only produces fallback text
// (API error messages and, in later phases, emails).
package i18n

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"golang.org/x/text/language"
)

// Locale describes one supported language.
type Locale struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Direction string `json:"direction"`
}

type manifest struct {
	Default string   `json:"default"`
	Locales []Locale `json:"locales"`
}

// Catalog holds flattened messages for every supported locale.
type Catalog struct {
	def     string
	locales []Locale
	msgs    map[string]map[string]string
	codes   []string // matcher order: default first
	matcher language.Matcher
}

// Load reads manifest.json and common/<code>.json from fsys.
func Load(fsys fs.FS) (*Catalog, error) {
	raw, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read locale manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse locale manifest: %w", err)
	}
	if len(m.Locales) == 0 {
		return nil, errors.New("locale manifest lists no locales")
	}
	c := &Catalog{def: m.Default, locales: m.Locales, msgs: map[string]map[string]string{}}
	var tags []language.Tag
	for _, l := range m.Locales {
		tag, err := language.Parse(l.Code)
		if err != nil {
			return nil, fmt.Errorf("locale code %q: %w", l.Code, err)
		}
		path := "common/" + l.Code + ".json"
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		flat, err := Flatten(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		c.msgs[l.Code] = flat
		if l.Code == m.Default {
			tags = append([]language.Tag{tag}, tags...)
			c.codes = append([]string{l.Code}, c.codes...)
		} else {
			tags = append(tags, tag)
			c.codes = append(c.codes, l.Code)
		}
	}
	if _, ok := c.msgs[m.Default]; !ok {
		return nil, fmt.Errorf("default locale %q is not listed in the manifest", m.Default)
	}
	c.matcher = language.NewMatcher(tags)
	return c, nil
}

// Locales returns the supported locales in manifest order.
func (c *Catalog) Locales() []Locale { return append([]Locale(nil), c.locales...) }

// Default returns the default locale code.
func (c *Catalog) Default() string { return c.def }

// Negotiate picks the best supported locale for an Accept-Language header.
func (c *Catalog) Negotiate(acceptLanguage string) string {
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return c.def
	}
	_, idx, conf := c.matcher.Match(tags...)
	if conf == language.No {
		return c.def
	}
	return c.codes[idx]
}

// T renders key in lang, falling back to the default locale and then to the key itself.
// Placeholders use the i18next syntax {{name}}.
func (c *Catalog) T(lang, key string, params map[string]string) string {
	s, ok := c.msgs[lang][key]
	if !ok {
		s, ok = c.msgs[c.def][key]
	}
	if !ok {
		return key
	}
	for k, v := range params {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// Flatten converts nested JSON objects into dot-separated keys.
func Flatten(data []byte) (map[string]string, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	out := map[string]string{}
	if err := flattenInto(out, "", root); err != nil {
		return nil, err
	}
	return out, nil
}

func flattenInto(out map[string]string, prefix string, node map[string]any) error {
	for k, v := range node {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case string:
			out[key] = t
		case map[string]any:
			if err := flattenInto(out, key, t); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: value must be a string or an object", key)
		}
	}
	return nil
}
