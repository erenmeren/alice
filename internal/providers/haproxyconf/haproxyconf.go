// Package haproxyconf reads an HAProxy configuration the way the root helper's haproxy-dump
// sees it: the first line of "haproxy -v", the text of /etc/haproxy/haproxy.cfg, and the text of
// every crt-list file a bind names. It is pure (standard library and helperproto for ValidPath
// and the warning codes): the root helper uses it to decide which files it reads and reports,
// and it is fuzzed (§25.6). Its input is hostile: a compromised server writes the configuration
// files, and the program that prints the version is that server's binary.
//
// The configuration lexer follows HAProxy's own reader (parse_line): blanks separate words, "#"
// outside quotes starts a comment anywhere, double and single quotes group words and join
// adjacent text, a backslash escapes a fixed set of characters, and there is no line
// continuation. crt-list lines have their own, simpler syntax (no quotes, no escapes). Every
// parser walks its input without recursion and without splitting it, stops at the first error
// (fail closed: nothing is guessed), and copies only what it returns. Every input is bounded
// (MaxInput, MaxLine, MaxTokens and the counts below).
package haproxyconf

import (
	"errors"
	"fmt"

	"alice/internal/providers/linuxssh/helperproto"
)

// Limits (Ruling 14; §25.6: deep nesting, huge lines and amplification are refused cleanly).
// They sit on top of the helper's read budget (MaxServerConfig, MaxServerFiles). Each crt-list
// and each directory is fetched once however many binds name it, so the work is bounded by
// MaxPairs, not by binds × lines.
const (
	MaxInput      = 20 << 20 // bytes of one file (the configuration or one crt-list)
	MaxLine       = 1 << 20  // bytes of one line, without its line end
	MaxTokens     = 1 << 20  // words of all files
	MaxDepth      = 100      // nesting of .if blocks
	MaxCrtLists   = 256      // distinct crt-list files
	MaxDirs       = 256      // distinct crt directories
	MaxDirEntries = 4096     // entries of one crt directory
	MaxPairs      = 1 << 16  // certificate pairs across all servers
	MaxServers    = 1 << 16  // servers (a bind's crt pairs, or one crt-list line)
	MaxNames      = 1 << 17  // SNI filters across all servers
	// MaxListens bounds the listens of all binds together (controller ruling for Task 5): one
	// 1 MiB address argument names about 200,000. A bind's listens are shared by all its
	// servers and counted once; past the bound they are cut and Config.Warnings says
	// WarnListTruncated, as Alice's other list bounds do.
	MaxListens = 1 << 16
)

// WarnListTruncated is Config.Warnings' code for a list cut at its bound (providers.WarnListTruncated).
const WarnListTruncated = "list_truncated"

// WarnConfigFileNotRead is Config.Warnings' code for a crt-list or crt directory that could not
// be read (ErrNotRead) where every naming of it lies in an uncertain region: its pairs are
// conditional, or there are none (review I2 of Task 6).
const WarnConfigFileNotRead = "config_file_not_read"

// Errors.
var (
	ErrTooLarge    = errors.New("haproxyconf: the input is larger than 20 MiB")
	ErrLineTooLong = errors.New("haproxyconf: a configuration line is longer than 1 MiB")
	ErrTooComplex  = errors.New("haproxyconf: the configuration has too many words, files, directory entries, servers, pairs or names")
	ErrTooDeep     = errors.New("haproxyconf: .if blocks are nested deeper than 100 levels")
	ErrSyntax      = errors.New("haproxyconf: an unterminated quote, an unknown escape, a malformed crt-list line or an unbalanced .if block")
	ErrNUL         = errors.New("haproxyconf: the configuration contains a NUL byte")
	// ErrNotRead is for the callbacks: an error wrapping it says the path could not be read
	// (absent, not a regular file, not root-controlled, a listing error), as opposed to a bound.
	// Parse then makes a naming in an uncertain region one conditional pair (and warns
	// WarnConfigFileNotRead) and fails only for a naming in an active region: "-c" may have
	// skipped an uncertain one (review I2 of Task 6).
	ErrNotRead = errors.New("haproxyconf: a file the configuration names could not be read")
)

// Reasons a pair is not supported (spec §8).
const (
	ReasonVariable       = "variable"         // a "$" in a path, whatever its quoting (Ruling 5, D4)
	ReasonConditional    = "conditional"      // the line lies in a region Alice cannot evaluate
	ReasonPathNotAllowed = "path_not_allowed" // the path is not one the helper may use
	// ReasonUnknownKeyword: a bind carries a keyword bindArity does not know, so its arguments
	// cannot be read (a newer HAProxy's keyword, since "-c" passed).
	ReasonUnknownKeyword = "unknown_keyword"
	// ReasonConfigFileWritable is set by the root helper: a read configuration or crt-list file
	// can be changed by a user other than root.
	ReasonConfigFileWritable = helperproto.WarnConfigFileWritable
)

// bindArity is the number of arguments each bind keyword takes (Ruling 8): the union of the
// "haproxy -dKall" bind lists of 2.6.12 and 2.8.14, plus 2.4's "process", the QUIC keywords and
// "ssl" (which -dKall does not print). A keyword that is not here stops the reading of its bind.
var bindArity = map[string]int{
	// no argument
	"accept-proxy": 0, "defer-accept": 0, "tfo": 0, "transparent": 0, "v4v6": 0, "v6only": 0, "ssl": 0,
	"allow-0rtt": 0, "force-sslv3": 0, "force-tlsv10": 0, "force-tlsv11": 0, "force-tlsv12": 0, "force-tlsv13": 0,
	"generate-certificates": 0, "no-alpn": 0, "no-ca-names": 0, "no-sslv3": 0, "no-tls-tickets": 0, "no-tlsv10": 0,
	"no-tlsv11": 0, "no-tlsv12": 0, "no-tlsv13": 0, "prefer-client-ciphers": 0, "strict-sni": 0, "quic-force-retry": 0,
	// one argument
	"accept-netscaler-cip": 1, "backlog": 1, "expose-fd": 1, "gid": 1, "group": 1, "id": 1, "interface": 1, "level": 1,
	"maxconn": 1, "mode": 1, "mss": 1, "name": 1, "namespace": 1, "nice": 1, "process": 1, "proto": 1,
	"severity-output": 1, "shards": 1, "tcp-ut": 1, "thread": 1, "uid": 1, "user": 1, "alpn": 1, "ca-file": 1,
	"ca-ignore-err": 1, "ca-sign-file": 1, "ca-sign-pass": 1, "ca-verify-file": 1, "ciphers": 1, "ciphersuites": 1,
	"client-sigalgs": 1, "crl-file": 1, "crt": 1, "crt-ignore-err": 1, "crt-list": 1, "curves": 1, "ecdhe": 1, "npn": 1,
	"sigalgs": 1, "ssl-max-ver": 1, "ssl-min-ver": 1, "tls-ticket-keys": 1, "verify": 1, "quic-cc-algo": 1,
	"quic-socket": 1,
}

func lineErr(err error, n int) error {
	return fmt.Errorf("%w (line %d)", err, n)
}
