package providers

import (
	"fmt"
	"regexp"
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
	Pattern  string // Go regexp, anchored
	Min, Max int    // ints: value range; strings: length range (0 = unbounded)
	Values   []string
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
		case f.Max > 0 && f.Min > f.Max:
			return fmt.Errorf("field %q has min %d above max %d", f.Name, f.Min, f.Max)
		}
		if f.Pattern != "" {
			if _, err := regexp.Compile(f.Pattern); err != nil {
				return fmt.Errorf("field %q has a pattern that does not compile", f.Name)
			}
		}
		seen[f.Name] = true
	}
	return nil
}
