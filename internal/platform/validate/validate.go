// Package validate carries field-level validation failures from services to the
// API, which returns them as error details with translatable codes.
package validate

import "strings"

// Codes are also the message keys in the shared locale catalog.
const (
	Required   = "validation.required"
	TooShort   = "validation.too_short"    // params: min
	TooLong    = "validation.too_long"     // params: max
	Pattern    = "validation.pattern"      // the value has characters or a form that is not allowed
	OneOf      = "validation.one_of"       // params: values ("a, b")
	OutOfRange = "validation.out_of_range" // params: min, max
	Email      = "validation.email"
	Duplicate  = "validation.duplicate" // a list names the same value more than once
)

// FieldError is one invalid field.
type FieldError struct {
	Field  string            `json:"field"`
	Code   string            `json:"code"`
	Params map[string]string `json:"params,omitempty"`
}

// Errors is a list of field errors. It implements error; callers detect it with
// errors.As(err, &validate.Errors{}).
type Errors []FieldError

// Error summarises the failures without values (values may be secrets).
func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, f := range e {
		parts[i] = f.Field + " " + f.Code
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

// Add appends a field error.
func (e *Errors) Add(field, code string, params map[string]string) {
	*e = append(*e, FieldError{Field: field, Code: code, Params: params})
}

// Err returns nil when there are no failures, else the list itself.
func (e Errors) Err() error {
	if len(e) == 0 {
		return nil
	}
	return e
}
