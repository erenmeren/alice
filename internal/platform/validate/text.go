package validate

import (
	"strings"
	"unicode/utf8"
)

// StorableText reports whether s can be stored in a PostgreSQL text column: valid UTF-8 without
// a NUL character (AUD-13). PostgreSQL refuses both (SQLSTATE 22021), so text that fails this
// must be refused before it reaches a query.
func StorableText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
