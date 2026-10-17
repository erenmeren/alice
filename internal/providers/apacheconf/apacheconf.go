// Package apacheconf reads an Apache httpd configuration the way the root helper's apache-dump
// sees it: the output of the control program ("-V", "-D DUMP_INCLUDES -t", "-D DUMP_MODULES -t",
// "-D DUMP_RUN_CFG -t") and the text of every configuration file the include tree names. It is
// pure (standard library and helperproto for ValidPath and the warning codes): the root helper
// uses it to decide which files it reads and reports, and it is fuzzed (§25.6). Its input is
// hostile: a compromised server writes the configuration files, and the program that prints the
// tool output is that server's binary.
//
// The tool-output parsers are strict: a line that is not in the format Apache prints is an
// ErrOutput, never a guess. The configuration lexer follows Apache's own reader (ap_cfg_getline
// and ap_getword_conf): a trailing backslash continues a line, "#" starts a comment only as the
// first character of a line, and quotes group words. Every input is bounded (MaxInput, MaxLine,
// MaxTokens, MaxDepth, MaxFiles).
package apacheconf

import (
	"errors"

	"alice/internal/providers/linuxssh/helperproto"
)

// Limits (§25.6: deep nesting, huge lines and amplification are refused cleanly).
const (
	MaxInput  = 20 << 20 // bytes of one tool output, or of one configuration file
	MaxFiles  = 4096     // entries of the include tree
	MaxDepth  = 100      // nesting of sections, and of includes
	MaxLine   = 1 << 20  // bytes of one logical configuration line (continuations joined)
	MaxTokens = 1 << 20  // words (directive names and arguments) of one configuration file
)

// Errors.
var (
	ErrTooLarge    = errors.New("apacheconf: the input is larger than 20 MiB")
	ErrLineTooLong = errors.New("apacheconf: a configuration line is longer than 1 MiB")
	ErrTooComplex  = errors.New("apacheconf: the configuration has too many words or files")
	ErrTooDeep     = errors.New("apacheconf: sections or includes are nested deeper than 100 levels")
	ErrSyntax      = errors.New("apacheconf: an unterminated quote, an unbalanced section or a malformed section line")
	ErrNUL         = errors.New("apacheconf: the configuration contains a NUL byte")
	ErrOutput      = errors.New("apacheconf: the output of the Apache control program is not in the expected format")
	// ErrIncludeMismatch: the include tree names a file at an Include line the configuration text
	// does not have there (the configuration changed between the runs, or the output is forged).
	ErrIncludeMismatch = errors.New("apacheconf: the include tree does not match the Include directives of the configuration")
)

// Reasons a pair is not supported (spec §8).
const (
	ReasonVariable       = "variable"         // an undefined ${VAR} in a path, name or address
	ReasonConditional    = "conditional"      // the directive lies in a region Alice cannot evaluate
	ReasonPathNotAllowed = "path_not_allowed" // the path is not one the helper may use
	// ReasonConfigFileWritable is set by the root helper: a loaded configuration file can be
	// changed by a user other than root.
	ReasonConfigFileWritable = helperproto.WarnConfigFileWritable
)
