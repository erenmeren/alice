package providers

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// FieldType is the type of a config field; the server validator and the SPA form generator use it.
type FieldType string

// Field types.
const (
	FieldString FieldType = "string"
	FieldInt    FieldType = "int"
	FieldBool   FieldType = "bool"
	FieldEnum   FieldType = "enum"
	FieldPath   FieldType = "path"
	FieldHost   FieldType = "host"
)

// Field describes one config or credential field. Labels are i18n keys, never text.
type Field struct {
	Name     string
	Type     FieldType
	Required bool
	Default  any
	LabelKey string // i18n key, e.g. "provider.linuxssh.fields.host.label"
	HelpKey  string
	Pattern  string // Go regexp starting with ^ and ending with $; matched as ^(?:Pattern)$ (MatchPattern)
	Min, Max int    // ints: value range; strings: length range (0 = unbounded)
	Values   []string
}

// anchored wraps a pattern so that it must match the whole value: "^a|b$" alone matches every
// value that starts with a or ends with b; ^(?:^a|b$)$ only "a" and "b" (the HTML pattern attribute
// is matched the same way).
func anchored(pattern string) (*regexp.Regexp, error) { return regexp.Compile("^(?:" + pattern + ")$") }

// MatchPattern reports whether v matches the field's Pattern as a whole (true without a pattern,
// false for a pattern that does not compile).
func (f Field) MatchPattern(v string) bool {
	if f.Pattern == "" {
		return true
	}
	re, err := anchored(f.Pattern)
	return err == nil && re.MatchString(v)
}

// ConfigSchema describes the non-secret target config.
type ConfigSchema struct{ Fields []Field }

// CredentialSchema describes secret fields (never echoed back).
type CredentialSchema struct{ Fields []Field }

var fieldNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var fieldTypes = map[FieldType]bool{FieldString: true, FieldInt: true, FieldBool: true, FieldEnum: true, FieldPath: true, FieldHost: true}

// checkFields validates a schema at registration: snake_case unique names, known types,
// translatable labels, compiling patterns, enums with values, sane ranges.
func checkFields(fields []Field) error {
	seen := map[string]bool{}
	for _, f := range fields {
		switch {
		case !fieldNameRE.MatchString(f.Name):
			return fmt.Errorf("field name %q is not snake_case", f.Name)
		case seen[f.Name]:
			return fmt.Errorf("field %q is declared twice", f.Name)
		case !fieldTypes[f.Type]:
			return fmt.Errorf("field %q has unknown type %q", f.Name, f.Type)
		case f.LabelKey == "":
			return fmt.Errorf("field %q has no label key", f.Name)
		case f.Type == FieldEnum && len(f.Values) == 0:
			return fmt.Errorf("enum field %q has no values", f.Name)
		case f.Min < 0:
			return fmt.Errorf("field %q has a negative min", f.Name)
		case f.Max < 0:
			return fmt.Errorf("field %q has a negative max", f.Name)
		// Max == 0 means unbounded (see Field), so a positive Min with Max == 0 is valid.
		case f.Max > 0 && f.Min > f.Max:
			return fmt.Errorf("field %q has min %d above max %d", f.Name, f.Min, f.Max)
		}
		if f.Pattern != "" {
			if !strings.HasPrefix(f.Pattern, "^") || !strings.HasSuffix(f.Pattern, "$") {
				return fmt.Errorf("field %q has a pattern that is not anchored with ^ and $", f.Name)
			}
			if _, err := anchored(f.Pattern); err != nil {
				return fmt.Errorf("field %q has a pattern that does not compile", f.Name)
			}
		}
		if err := checkDefault(f); err != nil {
			return err
		}
		seen[f.Name] = true
	}
	return nil
}

// checkDefault verifies that a field's default has the Go type its Type implies and, for ints
// and enums, lies inside the declared range or value set.
func checkDefault(f Field) error {
	if f.Default == nil {
		return nil
	}
	switch f.Type {
	case FieldString, FieldPath, FieldHost, FieldEnum:
		v, ok := f.Default.(string)
		if !ok {
			return fmt.Errorf("field %q has a default that is not a string", f.Name)
		}
		if f.Type == FieldEnum && !slices.Contains(f.Values, v) {
			return fmt.Errorf("field %q has a default outside its values", f.Name)
		}
	case FieldInt:
		v, ok := f.Default.(int)
		if !ok {
			return fmt.Errorf("field %q has a default that is not an int", f.Name)
		}
		if v < f.Min || (f.Max > 0 && v > f.Max) {
			return fmt.Errorf("field %q has a default outside its range", f.Name)
		}
	case FieldBool:
		if _, ok := f.Default.(bool); !ok {
			return fmt.Errorf("field %q has a default that is not a bool", f.Name)
		}
	}
	return nil
}
