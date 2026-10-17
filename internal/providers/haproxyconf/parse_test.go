package haproxyconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

const cfgPath = "/etc/haproxy/haproxy.cfg"

// fakeFS is an in-memory host: files for ReadFile, directories (their regular entries) for
// ReadDir. It counts the calls per path.
type fakeFS struct {
	files     map[string]string
	dirs      map[string][]string
	fileErr   error
	dirErr    error
	mu        sync.Mutex
	fileCalls map[string]int
	dirCalls  map[string]int
}

func newFS() *fakeFS {
	return &fakeFS{files: map[string]string{}, dirs: map[string][]string{}, fileCalls: map[string]int{}, dirCalls: map[string]int{}}
}

func (f *fakeFS) readFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fileCalls[path]++
	if f.fileErr != nil {
		return nil, f.fileErr
	}
	data, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("%s: no such file", path)
	}
	return []byte(data), nil
}

func (f *fakeFS) readDir(path string) ([]string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirCalls[path]++
	if f.dirErr != nil {
		return nil, false, f.dirErr
	}
	names, ok := f.dirs[path]
	return names, ok, nil
}

func (f *fakeFS) input(cfg, version string) Input {
	return Input{Path: cfgPath, Data: []byte(cfg), Version: version, ReadFile: f.readFile, ReadDir: f.readDir}
}

// sup is a supported pair before ResolveKeys: the key is the certificate, beside its companion.
func sup(cert, raw, beside string) Pair {
	return Pair{Cert: cert, Key: cert, CertRaw: raw, KeyBeside: beside}
}

// plain is sup for an absolute path written as is, with the default companion.
func plain(cert string) Pair { return sup(cert, cert, cert+".key") }

func uns(raw, reason string) Pair { return Pair{CertRaw: raw, Unsupported: reason} }

func srv(line int, section string, listens []Listen, pairs ...Pair) Server {
	return Server{File: cfgPath, Line: line, Section: section, Listens: listens, Pairs: pairs}
}

func named(s Server, names ...string) Server {
	s.Names = names
	return s
}

var any9443 = []Listen{{"", 9443}}

// fe wraps bind lines in a frontend "f" (the bind is then on line 2).
func fe(lines ...string) string { return "frontend f\n" + strings.Join(lines, "\n") + "\n" }

const listSample = "# comment\n" +
	"/probe/certs/a.pem\n" +
	"h.pem [alpn h2 ssl-min-ver TLSv1.2] h.example.test *.h.example.test !nope.h.example.test\n" +
	"/b.pem b.example.test other.example.test # trailing comment\n" +
	"   \n" +
	"  /a.pem indented.example.test\n" +
	"   # indented\n" +
	"\"/a.pem\" x\n" +
	"/c/dir y.example.test\n" +
	"$X/a.pem z.example.test\n"

var dirEntries = []string{".old.pem", "a.pem", "a.pem.key", "b.crt", "x.ocsp", "y.issuer", "z.sctl", "w.pem.rsa"}

func TestParse(t *testing.T) {
	listServers := func(line int, section string, listens []Listen) []Server {
		return []Server{
			srv(line, section, listens, plain("/probe/certs/a.pem")),
			named(srv(line, section, listens, sup("/c/h.pem", "h.pem", "/c/h.pem.key")), "h.example.test", "*.h.example.test"),
			named(srv(line, section, listens, plain("/b.pem")), "b.example.test", "other.example.test", "#", "trailing", "comment"),
			named(srv(line, section, listens, plain("/a.pem")), "indented.example.test"),
			named(srv(line, section, listens, uns("#", ReasonPathNotAllowed)), "indented"),
			named(srv(line, section, listens, uns(`"/a.pem"`, ReasonPathNotAllowed)), "x"),
			named(srv(line, section, listens, uns("/c/dir", ReasonPathNotAllowed)), "y.example.test"),
			named(srv(line, section, listens, uns("$X/a.pem", ReasonVariable)), "z.example.test"),
		}
	}
	bindA := "  bind :9443 ssl crt /c/a.pem"
	feA := func(pairs ...Pair) []Server { return []Server{srv(2, "f", any9443, pairs...)} }
	cond := []Server{srv(2, "f", any9443, uns("/c/a.pem", ReasonConditional))}
	in3 := func(pairs ...Pair) []Server { return []Server{srv(3, "f", any9443, pairs...)} }
	cond3 := in3(uns("/c/a.pem", ReasonConditional))
	for name, tc := range map[string]struct {
		cfg     string
		version string
		want    []Server
	}{
		// Two frontends and a listen (Rulings 6 and 13).
		"frontend, listen and backend": {
			cfg: "frontend fe_https\n  bind *:9443 ssl crt /c/a.pem crt /c/b.pem\n" +
				"listen li\n  bind 10.0.0.1:9444,ipv6@[::1]:9445 ssl crt /c/l.pem\n" +
				"backend be\n  bind :9445 ssl crt /c/x.pem\n",
			want: []Server{
				srv(2, "fe_https", any9443, plain("/c/a.pem"), plain("/c/b.pem")),
				srv(4, "li", []Listen{{"10.0.0.1", 9444}, {"::1", 9445}}, plain("/c/l.pem")),
			},
		},
		"other sections are skipped": {
			cfg:  "peers p\n  bind :9443 ssl crt /c/p.pem\nlog-forward lf\n  bind :9443 ssl crt /c/q.pem\n" + fe(bindA),
			want: []Server{srv(6, "f", any9443, plain("/c/a.pem"))},
		},
		"lines before any section": {cfg: "bind :9443 ssl crt /c/a.pem\n"},
		"keywords are case-sensitive": {
			cfg:  fe("  BIND :9443 ssl crt /c/a.pem") + "FRONTEND g\n  bind :9443 ssl crt /c/b.pem\n",
			want: []Server{srv(4, "f", any9443, plain("/c/b.pem"))},
		},
		"bind without ssl": {cfg: fe("  bind :443 crt /c/a.pem")},
		"ssl after crt":    {cfg: fe("  bind :9443 crt /c/a.pem ssl"), want: feA(plain("/c/a.pem"))},
		"ssl without crt":  {cfg: fe("  bind :9443 ssl")},
		"bind alone":       {cfg: fe("  bind")},
		"arity":            {cfg: fe("  bind :9443 ssl name crt crt /c/a.pem"), want: feA(plain("/c/a.pem"))},
		"unknown keyword": {
			cfg:  fe("  bind :9443 ssl crt /c/a.pem default-crt /c/b.pem"),
			want: feA(uns("/c/a.pem", ReasonUnknownKeyword)),
		},
		"unknown keyword before ssl": {
			cfg:  fe("  bind :9443 crt /c/a.pem quic-xyz ssl"),
			want: feA(uns("/c/a.pem", ReasonUnknownKeyword)),
		},
		"unknown keyword without ssl": {cfg: fe("  bind :9443 crt /c/a.pem quic-xyz")},
		"missing argument":            {cfg: fe("  bind :9443 ssl crt /c/a.pem crt"), want: feA(plain("/c/a.pem"))},
		"no listen":                   {cfg: fe("  bind unix@/run/h.sock ssl crt /c/a.pem"), want: []Server{srv(2, "f", nil, plain("/c/a.pem"))}},
		// crt-base (Ruling 9).
		// HAProxy refuses a second crt-base (review M2), so a later global can only set the first.
		"crt-base": {
			cfg: "frontend e\n  bind :9442 ssl crt a.pem\n" + "global\n  crt-base /c\n" + "frontend f\n  bind :9443 ssl crt a.pem\n",
			want: []Server{srv(2, "e", []Listen{{"", 9442}}, uns("a.pem", ReasonPathNotAllowed)),
				srv(6, "f", any9443, sup("/c/a.pem", "a.pem", "/c/a.pem.key"))},
		},
		"crt-base with a slash": {
			cfg:  "global\n  crt-base /c/\nfrontend f\n  bind :9443 ssl crt a.pem crt /d/b.pem\n",
			want: []Server{srv(4, "f", any9443, sup("/c/a.pem", "a.pem", "/c/a.pem.key"), plain("/d/b.pem"))},
		},
		"no crt-base":       {cfg: fe("  bind :9443 ssl crt a.pem"), want: feA(uns("a.pem", ReasonPathNotAllowed))},
		"relative crt-base": {cfg: "global\n  crt-base c\n" + fe("  bind :9443 ssl crt a.pem"), want: []Server{srv(4, "f", any9443, uns("a.pem", ReasonPathNotAllowed))}},
		"crt-base with dots": {
			cfg:  "global\n  crt-base /c/../d\n" + fe("  bind :9443 ssl crt a.pem"),
			want: []Server{srv(4, "f", any9443, uns("a.pem", ReasonPathNotAllowed))},
		},
		"crt-base variable": {
			cfg:  "global\n  crt-base \"${B}\"\n" + fe("  bind :9443 ssl crt a.pem crt /c/b.pem"),
			want: []Server{srv(4, "f", any9443, uns("a.pem", ReasonVariable), plain("/c/b.pem"))},
		},
		"crt-base without argument": {cfg: "global\n  crt-base\n" + fe("  bind :9443 ssl crt a.pem"), want: []Server{srv(4, "f", any9443, uns("a.pem", ReasonPathNotAllowed))}},
		"dot dot":                   {cfg: fe("  bind :9443 ssl crt /c/../a.pem"), want: feA(uns("/c/../a.pem", ReasonPathNotAllowed))},
		"dot":                       {cfg: fe("  bind :9443 ssl crt /c/./a.pem"), want: feA(uns("/c/./a.pem", ReasonPathNotAllowed))},
		"root":                      {cfg: fe("  bind :9443 ssl crt /"), want: feA(uns("/", ReasonPathNotAllowed))},
		"trailing slash":            {cfg: fe("  bind :9443 ssl crt /c/"), want: feA(uns("/c/", ReasonPathNotAllowed))},
		"not a helper path":         {cfg: fe("  bind :9443 ssl crt '/c/a b.pem'"), want: feA(uns("/c/a b.pem", ReasonPathNotAllowed))},
		"companion too long": {
			cfg:  fe("  bind :9443 ssl crt /" + strings.Repeat("a", 4093)),
			want: feA(uns("/"+strings.Repeat("a", maxRaw-1), ReasonPathNotAllowed)),
		},
		// Review I2: an uncertain naming never decides a certificate's companion key (probe k4,
		// HAProxy 2.4, 2.6 and 2.8: f2 loads a.pem with "all", key a.pem.key). The change of the
		// setting after it is uncertain, so f2's pair is conditional, never a wrong key.
		"uncertain naming does not decide the key": {
			cfg: "global\n  ssl-load-extra-files none\nfrontend f1\n.if defined(X)\n  bind :9443 ssl crt /c/a.pem\n.endif\n" +
				"global\n  ssl-load-extra-files all\nfrontend f2\n  bind :9444 ssl crt /c/a.pem crt /c/b.pem\n",
			want: []Server{srv(5, "f1", any9443, uns("/c/a.pem", ReasonConditional)),
				srv(10, "f2", []Listen{{"", 9444}}, uns("/c/a.pem", ReasonConditional), uns("/c/b.pem", ReasonConditional))},
		},
		"a certain naming decides before an uncertain one": {
			cfg: "global\n  ssl-load-extra-files none\n" + fe(bindA, ".if X", "  bind :9444 ssl crt /c/a.pem", ".endif") +
				"frontend g\n  bind :9445 ssl crt /c/a.pem\n",
			want: []Server{srv(4, "f", any9443, sup("/c/a.pem", "/c/a.pem", "")), srv(6, "f", []Listen{{"", 9444}}, uns("/c/a.pem", ReasonConditional)),
				srv(9, "g", []Listen{{"", 9445}}, sup("/c/a.pem", "/c/a.pem", ""))},
		},
		"a server's crt is a load Alice does not follow": {
			cfg: "global\n  ssl-load-extra-files none\nbackend be\n  server s 10.0.0.1:443 ssl crt /c/a.pem\n" +
				"global\n  ssl-load-extra-files all\n" + fe(bindA),
			want: []Server{srv(8, "f", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		"a bind without ssl loads its crt": {
			cfg: "global\n  ssl-load-extra-del-ext\n" + "frontend e\n  bind :80 crt /c/x.crt\n" +
				"global\n  ssl-load-extra-files none\n" + "frontend f\n  bind :9443 ssl crt /c/x.crt\n",
			want: []Server{srv(8, "f", any9443, uns("/c/x.crt", ReasonConditional))},
		},
		"a certain setting ends an uncertain one": {
			cfg:  "global\n.if X\n  ssl-load-extra-files none\n.endif\n  ssl-load-extra-files all\n" + fe(bindA),
			want: []Server{srv(7, "f", any9443, plain("/c/a.pem"))},
		},
		"no unfollowed load before the change": {
			cfg:  "global\n  ssl-load-extra-files none\n  ssl-load-extra-files all\n  ssl-load-extra-del-ext\n" + fe("  bind :9443 ssl crt /c/x.crt"),
			want: []Server{srv(6, "f", any9443, sup("/c/x.crt", "/c/x.crt", "/c/x.key"))},
		},
		"uncertain crt-list naming first": {
			cfg:  fe(".if X", "  bind :9443 ssl crt-list /l/short.txt", ".endif", "  bind :9444 ssl crt-list /l/short.txt"),
			want: []Server{named(srv(3, "f", any9443, uns("/c/s.pem", ReasonConditional)), "s.example.test"), named(srv(5, "f", []Listen{{"", 9444}}, plain("/c/s.pem")), "s.example.test")},
		},
		// Review M1: an unknown keyword before every crt still lists the words after crt and
		// crt-list, unread.
		"unknown keyword first": {
			cfg:  fe("  bind :9443 ssl default-crt /c/b.pem crt /c/a.pem crt-list /l/list.txt crt"),
			want: feA(uns("/c/a.pem", ReasonUnknownKeyword), uns("/l/list.txt", ReasonUnknownKeyword)),
		},
		"cleaned section and names": {
			cfg:  "frontend \"f\\x01e\"\n  bind :9443 ssl crt-list /l/ctl.txt\n",
			want: []Server{named(srv(2, "fe", any9443, plain("/c/s.pem")), "a.test", "b.test")},
		},
		// crt-list (Rulings 9 and 11).
		"crt-list": {
			cfg:  "global\n  crt-base /c\n" + fe("  bind :9443 ssl crt-list /l/list.txt"),
			want: listServers(4, "f", any9443),
		},
		"crt-list after crt": {
			cfg:  "global\n  crt-base /c\n" + fe("  bind :9443 ssl crt-list /l/list.txt crt /c/a.pem"),
			want: append([]Server{srv(4, "f", any9443, plain("/c/a.pem"))}, listServers(4, "f", any9443)...),
		},
		"relative crt-list": {cfg: "global\n  crt-base /l\n" + fe("  bind :9443 ssl crt-list list.txt"), want: []Server{srv(4, "f", any9443, uns("list.txt", ReasonPathNotAllowed))}},
		"crt-list variable": {cfg: fe("  bind :9443 ssl crt-list $L/list.txt"), want: feA(uns("$L/list.txt", ReasonVariable))},
		"crt-list unknown keyword": {
			cfg:  fe("  bind :9443 ssl crt-list /l/short.txt ca-sign-pass x default-crt /c/b.pem"),
			want: []Server{named(srv(2, "f", any9443, uns("/c/s.pem", ReasonUnknownKeyword)), "s.example.test")},
		},
		"empty crt-list": {cfg: fe("  bind :9443 ssl crt-list /l/empty.txt")},
		"shared crt-list": {
			cfg:  "global\n  crt-base /c\n" + fe("  bind :9443 ssl crt-list /l/list.txt") + "frontend g\n  bind :9444 ssl crt-list /l/list.txt\n",
			want: append(listServers(4, "f", any9443), listServers(6, "g", []Listen{{"", 9444}})...),
		},
		// crt directories (Ruling 10).
		"crt directory": {
			cfg: fe("  bind :9443 ssl crt /c/dir crt /c/a.pem crt /c/dir"),
			want: feA(plain("/c/dir/a.pem"), plain("/c/dir/b.crt"), plain("/c/dir/w.pem.rsa"), plain("/c/a.pem"),
				plain("/c/dir/a.pem"), plain("/c/dir/b.crt"), plain("/c/dir/w.pem.rsa")),
		},
		"crt directory 2.4": {
			cfg: fe("  bind :9443 ssl crt /c/dir"), version: "2.4.30",
			want: feA(plain("/c/dir/.old.pem"), plain("/c/dir/a.pem"), plain("/c/dir/b.crt"), plain("/c/dir/w.pem.rsa")),
		},
		"crt directory 2.5": {
			cfg: fe("  bind :9443 ssl crt /c/dir"), version: "2.5.14",
			want: feA(plain("/c/dir/.old.pem"), plain("/c/dir/a.pem"), plain("/c/dir/b.crt"), plain("/c/dir/w.pem.rsa")),
		},
		"crt directory unknown version": {
			cfg: fe("  bind :9443 ssl crt /c/dir"), version: "weird",
			want: feA(uns("/c/dir/.old.pem", ReasonConditional), plain("/c/dir/a.pem"), plain("/c/dir/b.crt"), plain("/c/dir/w.pem.rsa")),
		},
		"relative crt directory": {
			cfg:  "global\n  crt-base /c\n" + fe("  bind :9443 ssl crt dir"),
			want: []Server{srv(4, "f", any9443, sup("/c/dir/a.pem", "dir/a.pem", "/c/dir/a.pem.key"), sup("/c/dir/b.crt", "dir/b.crt", "/c/dir/b.crt.key"), sup("/c/dir/w.pem.rsa", "dir/w.pem.rsa", "/c/dir/w.pem.rsa.key"))},
		},
		"odd directory entries": {
			cfg:  fe("  bind :9443 ssl crt /c/odd"),
			want: feA(plain("/c/odd/ok.pem"), uns("/c/odd/sp ace.pem", ReasonPathNotAllowed)),
		},
		"empty directory": {cfg: fe("  bind :9443 ssl crt /c/empty")},
		// ssl-load-extra-files and ssl-load-extra-del-ext (Ruling 12).
		"extra files none": {
			cfg: "global\n  ssl-load-extra-files none\n" + fe(bindA), want: []Server{srv(4, "f", any9443, sup("/c/a.pem", "/c/a.pem", ""))},
		},
		"extra files ocsp": {
			cfg: "global\n  ssl-load-extra-files ocsp\n" + fe(bindA), want: []Server{srv(4, "f", any9443, sup("/c/a.pem", "/c/a.pem", ""))},
		},
		"extra files ocsp bundle": {
			cfg: "global\n  ssl-load-extra-files ocsp bundle\n" + fe(bindA), want: []Server{srv(4, "f", any9443, sup("/c/a.pem", "/c/a.pem", ""))},
		},
		"extra files ocsp key": {
			cfg: "global\n  ssl-load-extra-files ocsp key\n" + fe(bindA), want: []Server{srv(4, "f", any9443, plain("/c/a.pem"))},
		},
		"extra files all": {
			cfg: "global\n  ssl-load-extra-files none\n  ssl-load-extra-files all\n" + fe(bindA), want: []Server{srv(5, "f", any9443, plain("/c/a.pem"))},
		},
		"del-ext": {
			cfg:  "global\n  ssl-load-extra-del-ext\n" + fe("  bind :9443 ssl crt /c/x.crt crt /c/x.pem"),
			want: []Server{srv(4, "f", any9443, sup("/c/x.crt", "/c/x.crt", "/c/x.key"), plain("/c/x.pem"))},
		},
		"first load wins": {
			cfg: "global\n  ssl-load-extra-files none\n" + fe(bindA) + "global\n  ssl-load-extra-files all\n" +
				"frontend g\n  bind :9444 ssl crt /c/a.pem crt /c/b.pem\n",
			want: []Server{srv(4, "f", any9443, sup("/c/a.pem", "/c/a.pem", "")),
				srv(8, "g", []Listen{{"", 9444}}, sup("/c/a.pem", "/c/a.pem", ""), plain("/c/b.pem"))},
		},
		// Variables (Ruling 5, D4).
		"variables": {
			cfg:  fe(`  bind :9443 ssl crt "${D}/a.pem" crt "$D/a.pem" crt '${D}/a.pem' crt ${D}/a.pem crt /c/a.pem`),
			want: feA(uns("${D}/a.pem", ReasonVariable), uns("$D/a.pem", ReasonVariable), uns("${D}/a.pem", ReasonVariable), uns("${D}/a.pem", ReasonVariable), plain("/c/a.pem")),
		},
		// .if blocks (Ruling 7).
		".if 0":         {cfg: fe(".if 0", bindA, ".endif")},
		".if 1":         {cfg: fe(".if 1", bindA, ".endif"), want: in3(plain("/c/a.pem"))},
		".if -1":        {cfg: fe(".if -1", bindA, ".endif"), want: in3(plain("/c/a.pem"))},
		`.if "1"`:       {cfg: fe(`.if "1"`, bindA, ".endif"), want: in3(plain("/c/a.pem"))},
		".if 00":        {cfg: fe(".if 00", bindA, ".endif")},
		".if alone":     {cfg: fe(".if", bindA, ".endif")},
		".if defined":   {cfg: fe(".if defined(X)", bindA, ".endif"), want: cond3},
		".if !0":        {cfg: fe(".if !0", bindA, ".endif"), want: cond3},
		".if version":   {cfg: fe(".if version_atleast(2.4)", bindA, ".endif"), want: cond3},
		".if variable":  {cfg: fe(`.if "$X"`, bindA, ".endif"), want: cond3},
		".if two words": {cfg: fe(".if 1 1", bindA, ".endif"), want: cond3},
		".if empty":     {cfg: fe(`.if ""`, bindA, ".endif"), want: cond3},
		".elif":         {cfg: fe(".if 0", "  bind :9443 ssl crt /c/x.pem", ".elif 1", bindA, ".else", "  bind :9443 ssl crt /c/y.pem", ".endif"), want: []Server{srv(5, "f", any9443, plain("/c/a.pem"))}},
		".elif false":   {cfg: fe(".if 0", ".elif 0", bindA, ".else", "  bind :9443 ssl crt /c/b.pem", ".endif"), want: []Server{srv(6, "f", any9443, plain("/c/b.pem"))}},
		".elif uncertain": {
			cfg:  fe(".if 0", ".elif defined(X)", bindA, ".else", "  bind :9443 ssl crt /c/b.pem", ".endif"),
			want: []Server{srv(4, "f", any9443, uns("/c/a.pem", ReasonConditional)), srv(6, "f", any9443, uns("/c/b.pem", ReasonConditional))},
		},
		".elif after uncertain": {
			cfg:  fe(".if X", ".elif 1", bindA, ".else", "  bind :9443 ssl crt /c/b.pem", ".endif"),
			want: []Server{srv(4, "f", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		".else after taken": {cfg: fe(".if 1", bindA, ".else", "  bind :9443 ssl crt /c/b.pem", ".endif"), want: in3(plain("/c/a.pem"))},
		".else uncertain": {
			cfg:  fe(".if X", ".else", bindA, ".endif"),
			want: []Server{srv(4, "f", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		".else after false": {cfg: fe(".if 0", ".else", bindA, ".endif"), want: []Server{srv(4, "f", any9443, plain("/c/a.pem"))}},
		"nested":            {cfg: fe(".if 0", ".if 1", bindA, ".endif", ".elif 0", ".else", ".endif")},
		"nested in uncertain": {
			cfg:  fe(".if X", ".if 0", "  bind :9443 ssl crt /c/b.pem", ".else", bindA, ".endif", ".endif"),
			want: []Server{srv(6, "f", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		"messages are ignored": {cfg: fe(".diag x", ".notice x", ".warning x", ".alert x", ".unknown x", bindA), want: []Server{srv(7, "f", any9443, plain("/c/a.pem"))}},
		"inactive header": {
			cfg:  fe(bindA, ".if 0", "frontend fe2", ".endif", "  bind :9444 ssl crt /c/b.pem"),
			want: []Server{srv(2, "f", any9443, plain("/c/a.pem")), srv(6, "f", []Listen{{"", 9444}}, plain("/c/b.pem"))},
		},
		"uncertain header": {
			cfg: fe(bindA, ".if X", "frontend fe2", ".endif", "  bind :9444 ssl crt /c/b.pem") + "frontend fe3\n  bind :9445 ssl crt /c/c.pem\n",
			want: []Server{srv(2, "f", any9443, plain("/c/a.pem")), srv(6, "", []Listen{{"", 9444}}, uns("/c/b.pem", ReasonConditional)),
				srv(8, "fe3", []Listen{{"", 9445}}, plain("/c/c.pem"))},
		},
		"uncertain backend header": {
			cfg:  fe(".if X", "backend b", ".endif", bindA),
			want: []Server{srv(5, "", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		"uncertain frontend after backend": {
			cfg:  "backend b\n.if X\nfrontend g\n.endif\n  bind :9443 ssl crt /c/a.pem\n",
			want: []Server{srv(5, "", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		"uncertain global header": {
			cfg:  fe(".if X", "global", ".endif", "  crt-base /c", "  bind :9443 ssl crt a.pem") + "frontend g\n  bind :9444 ssl crt b.pem\n",
			want: []Server{srv(6, "", any9443, uns("a.pem", ReasonConditional)), srv(8, "g", []Listen{{"", 9444}}, uns("b.pem", ReasonConditional))},
		},
		"crt-base in uncertain region": {
			cfg:  "global\n.if X\n  crt-base /c\n.endif\n" + fe("  bind :9443 ssl crt a.pem crt /d/b.pem"),
			want: []Server{srv(6, "f", any9443, uns("a.pem", ReasonConditional), plain("/d/b.pem"))},
		},
		"crt-base uncertain and unset": {
			cfg:  ".if X\nglobal\n  crt-base c\n.endif\n" + fe("  bind :9443 ssl crt a.pem"),
			want: []Server{srv(6, "f", any9443, uns("a.pem", ReasonConditional))},
		},
		"extra files in uncertain region": {
			cfg:  "global\n.if X\n  ssl-load-extra-files none\n.endif\n" + fe(bindA),
			want: []Server{srv(6, "f", any9443, uns("/c/a.pem", ReasonConditional))},
		},
		"del-ext in uncertain region": {
			cfg:  "global\n.if X\n  ssl-load-extra-del-ext\n.endif\n" + fe("  bind :9443 ssl crt /c/x.crt crt /c/x.pem"),
			want: []Server{srv(6, "f", any9443, uns("/c/x.crt", ReasonConditional), plain("/c/x.pem"))},
		},
		"crt-list in uncertain region": {
			cfg:  fe(".if X", "  bind :9443 ssl crt-list /l/short.txt", ".endif"),
			want: []Server{named(srv(3, "f", any9443, uns("/c/s.pem", ReasonConditional)), "s.example.test")},
		},
		// disabled and enabled (Ruling 6).
		"disabled":                     {cfg: fe(bindA, "  disabled") + "frontend g\n  bind :9444 ssl crt /c/b.pem\n", want: []Server{srv(5, "g", []Listen{{"", 9444}}, plain("/c/b.pem"))}},
		"disabled then enabled":        {cfg: fe("  disabled", bindA, "  enabled"), want: []Server{srv(3, "f", any9443, plain("/c/a.pem"))}},
		"disabled in uncertain region": {cfg: fe(bindA, ".if X", "  disabled", ".endif"), want: cond},
		"disabled in defaults": {
			cfg: "frontend e\n  bind :9442 ssl crt /c/e.pem\n" + "defaults\n  disabled\n" + fe(bindA) + "frontend g\n  enabled\n  bind :9444 ssl crt /c/b.pem\n",
			want: []Server{srv(2, "e", []Listen{{"", 9442}}, plain("/c/e.pem")), srv(6, "f", any9443, uns("/c/a.pem", ReasonConditional)),
				srv(9, "g", []Listen{{"", 9444}}, plain("/c/b.pem"))},
		},
		"enabled in defaults": {cfg: "defaults\n  enabled\n" + fe(bindA), want: []Server{srv(4, "f", any9443, uns("/c/a.pem", ReasonConditional))}},
		"disabled in uncertain section": {
			cfg:  fe(bindA, ".if X", "defaults", ".endif", "  disabled") + "frontend g\n  bind :9444 ssl crt /c/b.pem\n",
			want: []Server{cond[0], srv(8, "g", []Listen{{"", 9444}}, uns("/c/b.pem", ReasonConditional))},
		},
		"conditional keeps the stronger reason": {
			cfg:  fe(".if X", "  bind :9443 ssl crt $D/a.pem crt /c/../b.pem", ".endif"),
			want: []Server{srv(3, "f", any9443, uns("$D/a.pem", ReasonVariable), uns("/c/../b.pem", ReasonPathNotAllowed))},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newFS()
			fs.files["/l/list.txt"] = listSample
			fs.files["/l/short.txt"] = "/c/s.pem s.example.test\n"
			fs.files["/l/empty.txt"] = "# nothing\n"
			fs.files["/l/ctl.txt"] = "/c/s.pem a\x01.test b\xff.test\n"
			fs.dirs["/c/dir"] = dirEntries
			fs.dirs["/c/odd"] = []string{"ok.pem", "sp ace.pem", "", ".", "..", "a/b"}
			fs.dirs["/c/empty"] = nil
			version := tc.version
			if version == "" {
				version = "2.6.12"
			}
			got, err := Parse(fs.input(tc.cfg, version))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Servers)
			assert.Empty(t, got.Warnings)
			for path, n := range fs.fileCalls {
				assert.Equal(t, 1, n, "ReadFile(%s) is called once", path)
			}
			for path, n := range fs.dirCalls {
				assert.Equal(t, 1, n, "ReadDir(%s) is called once", path)
			}
		})
	}
}

func TestParseReadsFilesOnce(t *testing.T) {
	fs := newFS()
	fs.files["/l/list.txt"] = listSample
	fs.dirs["/c/dir"] = dirEntries
	cfg := fe("  bind :9443 ssl crt-list /l/list.txt crt /c/dir", "  bind :9444 ssl crt-list /l/list.txt crt /c/dir crt-list l.txt") +
		"frontend g\n  bind :9445 ssl crt-list /l/list.txt\n"
	got, err := Parse(fs.input(cfg, "2.6.12"))
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"/l/list.txt": 1}, fs.fileCalls, "a relative crt-list is never read")
	assert.Equal(t, 1, fs.dirCalls["/c/dir"])
	assert.Len(t, got.Servers, 3*8+2)
	// The servers of one bind share its listens.
	assert.Same(t, &got.Servers[0].Listens[0], &got.Servers[1].Listens[0])
}

func TestParseErrors(t *testing.T) {
	deep := strings.Repeat(".if 1\n", MaxDepth+1) + strings.Repeat(".endif\n", MaxDepth+1)
	for name, tc := range map[string]struct {
		cfg  string
		want error
	}{
		"unclosed .if":       {fe(".if 1", "  bind :9443 ssl crt /c/a.pem"), ErrSyntax},
		"stray .endif":       {fe(".endif"), ErrSyntax},
		"stray .else":        {fe(".else"), ErrSyntax},
		"stray .elif":        {fe(".elif 1"), ErrSyntax},
		".elif after .else":  {fe(".if 0", ".else", ".elif 1", ".endif"), ErrSyntax},
		".else after .else":  {fe(".if 0", ".else", ".else", ".endif"), ErrSyntax},
		"too deep":           {deep, ErrTooDeep},
		"lexer error":        {fe(`  bind :9443 ssl crt "/c/a.pem`), ErrSyntax},
		"crt-list error":     {fe("  bind :9443 ssl crt-list /l/bad.txt"), ErrSyntax},
		"crt-list too large": {fe("  bind :9443 ssl crt-list /l/huge.txt"), ErrTooLarge},
		"NUL":                {"frontend f\x00\n", ErrNUL},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newFS()
			fs.files["/l/bad.txt"] = "[x\n"
			fs.files["/l/huge.txt"] = strings.Repeat("#", MaxInput+1)
			got, err := Parse(fs.input(tc.cfg, "2.6.12"))
			assert.ErrorIs(t, err, tc.want)
			assert.Empty(t, got.Servers)
		})
	}
	t.Run("100 levels", func(t *testing.T) {
		_, err := Parse(newFS().input(strings.Repeat(".if 1\n", MaxDepth)+strings.Repeat(".endif\n", MaxDepth), ""))
		assert.NoError(t, err)
	})
}

var errFake = errors.New("fake")

func TestParseCallbackErrors(t *testing.T) {
	fs := newFS()
	fs.fileErr = errFake
	_, err := Parse(fs.input(fe("  bind :9443 ssl crt-list /l/list.txt"), ""))
	assert.ErrorIs(t, err, errFake)

	fs = newFS()
	fs.dirErr = errFake
	_, err = Parse(fs.input(fe("  bind :9443 ssl crt /c/a.pem"), ""))
	assert.ErrorIs(t, err, errFake)

	fs = newFS()
	fs.files["/l/list.txt"] = "/c/a.pem\n"
	fs.dirErr = errFake
	_, err = Parse(fs.input(fe("  bind :9443 ssl crt-list /l/list.txt"), ""))
	assert.ErrorIs(t, err, errFake, "a crt-list entry is checked for a directory")

	_, err = Parse(Input{Path: cfgPath, Data: []byte(fe("  bind :9443 ssl crt-list /l/list.txt crt /c/a.pem"))})
	assert.Error(t, err, "no callbacks")
	_, err = Parse(Input{Path: cfgPath, Data: []byte(fe("  bind :9443 ssl crt /c/a.pem"))})
	assert.Error(t, err, "no callbacks")
}

func TestParseBounds(t *testing.T) {
	big := func(n int, f func(i int) string) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(f(i))
		}
		return b.String()
	}
	t.Run("crt-lists", func(t *testing.T) {
		fs := newFS()
		for i := range MaxCrtLists + 1 {
			fs.files[fmt.Sprintf("/l/%d.txt", i)] = ""
		}
		cfg := fe(big(MaxCrtLists, func(i int) string { return fmt.Sprintf("  bind :9443 ssl crt-list /l/%d.txt\n", i) }))
		_, err := Parse(fs.input(cfg, ""))
		require.NoError(t, err, "256 crt-lists")
		cfg = fe(big(MaxCrtLists+1, func(i int) string { return fmt.Sprintf("  bind :9443 ssl crt-list /l/%d.txt\n", i) }))
		_, err = Parse(fs.input(cfg, ""))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("directories", func(t *testing.T) {
		fs := newFS()
		for i := range MaxDirs + 1 {
			fs.dirs[fmt.Sprintf("/d/%d", i)] = []string{"a.pem"}
		}
		_, err := Parse(fs.input(fe(big(MaxDirs, func(i int) string { return fmt.Sprintf("  bind :9443 ssl crt /d/%d\n", i) })), ""))
		require.NoError(t, err, "256 directories")
		_, err = Parse(fs.input(fe(big(MaxDirs+1, func(i int) string { return fmt.Sprintf("  bind :9443 ssl crt /d/%d\n", i) })), ""))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("directory entries", func(t *testing.T) {
		fs := newFS()
		fs.dirs["/d/ok"] = make([]string, MaxDirEntries)
		fs.dirs["/d/big"] = make([]string, MaxDirEntries+1)
		for i := range MaxDirEntries + 1 {
			if i < MaxDirEntries {
				fs.dirs["/d/ok"][i] = fmt.Sprintf("%d.pem", i)
			}
			fs.dirs["/d/big"][i] = fmt.Sprintf("%d.pem", i)
		}
		got, err := Parse(fs.input(fe("  bind :9443 ssl crt /d/ok"), ""))
		require.NoError(t, err)
		assert.Len(t, got.Servers[0].Pairs, MaxDirEntries)
		_, err = Parse(fs.input(fe("  bind :9443 ssl crt /d/big"), ""))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("pairs", func(t *testing.T) {
		fs := newFS()
		entries := make([]string, MaxDirEntries)
		for i := range entries {
			entries[i] = fmt.Sprintf("%d.pem", i)
		}
		fs.dirs["/d/x"] = entries
		ok := fe(strings.Repeat("  bind :9443 ssl crt /d/x\n", MaxPairs/MaxDirEntries))
		got, err := Parse(fs.input(ok, ""))
		require.NoError(t, err)
		assert.Len(t, got.Servers, MaxPairs/MaxDirEntries)
		_, err = Parse(fs.input(ok+"  bind :9443 ssl crt /c/a.pem\n", ""))
		assert.ErrorIs(t, err, ErrTooComplex)
		// One bind naming the directory again and again stops at the bound too.
		_, err = Parse(fs.input(fe("  bind :9443 ssl"+strings.Repeat(" crt /d/x", MaxPairs/MaxDirEntries+1)), ""))
		assert.ErrorIs(t, err, ErrTooComplex)
	})
	t.Run("crt-list lines", func(t *testing.T) {
		fs := newFS()
		fs.files["/l/ok.txt"] = strings.Repeat("/c/a.pem\n", MaxServers)
		fs.files["/l/big.txt"] = strings.Repeat("/c/a.pem\n", MaxServers+1)
		got, err := Parse(fs.input(fe("  bind :9443 ssl crt-list /l/ok.txt"), ""))
		require.NoError(t, err)
		assert.Len(t, got.Servers, MaxServers)
		assert.Equal(t, 1, fs.dirCalls["/c/a.pem"], "each entry path is looked at once")
		_, err = Parse(fs.input(fe("  bind :9443 ssl crt-list /l/big.txt"), ""))
		assert.ErrorIs(t, err, ErrTooComplex)
		assert.Equal(t, 1, fs.dirCalls["/c/a.pem"], "a list over the bound is refused before its entries are looked at")
		_, err = Parse(fs.input(fe("  bind :9443 ssl crt-list /l/ok.txt", "  bind :9444 ssl crt /c/b.pem"), ""))
		assert.ErrorIs(t, err, ErrTooComplex, "servers")
	})
	t.Run("names", func(t *testing.T) {
		fs := newFS()
		fs.files["/l/ok.txt"] = "/c/a.pem" + strings.Repeat(" n", MaxNames) + "\n"
		fs.files["/l/big.txt"] = "/c/a.pem" + strings.Repeat(" n", MaxNames/2) + "\n/c/b.pem" + strings.Repeat(" n", MaxNames/2+1) + "\n"
		got, err := Parse(fs.input(fe("  bind :9443 ssl crt-list /l/ok.txt"), ""))
		require.NoError(t, err)
		assert.Len(t, got.Servers[0].Names, MaxNames)
		_, err = Parse(fs.input(fe("  bind :9443 ssl crt-list /l/big.txt"), ""))
		assert.ErrorIs(t, err, ErrTooComplex)
		_, err = Parse(fs.input(fe("  bind :9443 ssl crt-list /l/ok.txt", "  bind :9444 ssl crt-list /l/ok.txt"), ""))
		assert.ErrorIs(t, err, ErrTooComplex, "a shared crt-list counts per server")
	})
	t.Run("tokens across files", func(t *testing.T) {
		// Each file is under MaxTokens; together they are over it.
		fs := newFS()
		cfg := fe("  bind :9443 ssl crt-list /l/list.txt") + strings.Repeat("x\n", MaxTokens/2)
		rest := MaxTokens - (2 + 5 + MaxTokens/2) // the words the configuration leaves to the list
		fs.files["/l/list.txt"] = strings.Repeat("/c/a.pem\n", MaxTokens/2)
		_, err := Parse(fs.input(cfg, ""))
		assert.ErrorIs(t, err, ErrTooComplex)
		// Options count as words, and no other bound applies to them.
		fs.files["/l/list.txt"] = "/c/a.pem [" + strings.Repeat(" o", rest) + " ]\n"
		_, err = Parse(fs.input(cfg, ""))
		assert.ErrorIs(t, err, ErrTooComplex, "one word over")
		fs.files["/l/list.txt"] = "/c/a.pem [" + strings.Repeat(" o", rest-1) + " ]\n"
		_, err = Parse(fs.input(cfg, ""))
		assert.NoError(t, err, "exactly MaxTokens words")
	})
}

// TestParseListensBound: listens count once per server that carries them (review C1), so a
// bind's listens shared by the servers of a crt-list are cut at MaxListens across them all.
func TestParseListensBound(t *testing.T) {
	entries := func(n int) string { return strings.TrimSuffix(strings.Repeat(":1,", n), ",") }
	fs := newFS()
	fs.files["/l/list.txt"] = "/c/a.pem\n/c/b.pem\n"
	cfg := fe("  bind "+entries(MaxListens/2-5)+" ssl crt-list /l/list.txt", "  bind "+entries(10)+" ssl crt /c/c.pem")
	got, err := Parse(fs.input(cfg, ""))
	require.NoError(t, err)
	assert.Empty(t, got.Warnings, "exactly MaxListens listens on the wire")
	assert.Len(t, got.Servers[0].Listens, MaxListens/2-5)
	assert.Len(t, got.Servers[1].Listens, MaxListens/2-5)
	assert.Len(t, got.Servers[2].Listens, 10)

	cfg = fe("  bind "+entries(MaxListens/2-5)+" ssl crt-list /l/list.txt", "  bind "+entries(11)+" ssl crt /c/c.pem", "  bind :2 ssl crt /c/d.pem")
	got, err = Parse(fs.input(cfg, ""))
	require.NoError(t, err)
	assert.Equal(t, []string{WarnListTruncated}, got.Warnings)
	assert.Equal(t, providers.WarnListTruncated, WarnListTruncated)
	require.Len(t, got.Servers, 4)
	assert.Len(t, got.Servers[2].Listens, 10, "cut to what is left")
	assert.Empty(t, got.Servers[3].Listens)
	assert.Len(t, got.Servers[3].Pairs, 1, "the server is still listed")

	// The reviewer's input: MaxListens listens on a bind naming a crt-list of MaxServers-1
	// lines gave 4,294,901,760 listens on the wire.
	fs.files["/l/big.txt"] = strings.Repeat("/c/a.pem\n", MaxServers-1)
	cfg = fe("  bind " + strings.Repeat(":1,", (MaxLine-100)/3) + " ssl crt-list /l/big.txt")
	start := time.Now()
	got, err = Parse(fs.input(cfg, ""))
	require.NoError(t, err)
	assert.Equal(t, []string{WarnListTruncated}, got.Warnings)
	assert.Len(t, got.Servers[0].Listens, MaxListens)
	assert.Equal(t, MaxListens, totalListens(got))
	assert.Less(t, time.Since(start), 2*time.Second*raceSlowdown)
}

func totalListens(c Config) int {
	n := 0
	for _, s := range c.Servers {
		n += len(s.Listens)
	}
	return n
}

// wireSize is what the servers take in the helper's JSON answer.
func wireSize(t *testing.T, c Config) int {
	n := 0
	for _, s := range c.Servers {
		b, err := json.Marshal(ToWire(s))
		require.NoError(t, err)
		n += len(b) + 1
	}
	return n
}

// TestParseWireEstimate: the size Parse counts against MaxWire is never below the real JSON,
// also after ResolveKeys and MarkWritable, and not far above it.
func TestParseWireEstimate(t *testing.T) {
	fs := newFS()
	fs.files["/l/list.txt"] = listSample + "/c/ctl.pem <a>&\"b\".test \xe2\x80\xa8.test\n"
	fs.dirs["/c/dir"] = dirEntries
	cfg := "global\n  crt-base /c\nfrontend \"<f>&\"\n  bind 10.0.0.1:9443,[::1]:443,*:1 ssl crt-list /l/list.txt crt dir crt a.pem crt $X\n" +
		".if X\n  bind :1 ssl crt '\"<x>\"'\n.endif\n" + "listen " + strings.Repeat("\u00e9", 300) + "\n  bind :2 ssl crt " + strings.Repeat("r", 3000) + "\n"
	got, err := Parse(fs.input(cfg, "2.4.30"))
	require.NoError(t, err)
	real := wireSize(t, got)
	assert.GreaterOrEqual(t, got.wire, real)
	ResolveKeys(&got, func(string) bool { return false })
	assert.GreaterOrEqual(t, got.wire, wireSize(t, got), "after ResolveKeys")
	MarkWritable(&got)
	assert.GreaterOrEqual(t, got.wire, wireSize(t, got), "after MarkWritable")
	assert.Less(t, got.wire, 2*real)
}

// TestParseWireBound: MaxWire refuses a configuration whose servers would not fit, before the
// strings of a long directory path are built for every entry.
func TestParseWireBound(t *testing.T) {
	fs := newFS()
	fs.files["/l/list.txt"] = strings.Repeat("/c/a.pem\n", MaxServers/2)
	long := strings.Repeat("<", maxText) // each "<" is six bytes of JSON
	_, err := Parse(fs.input("frontend f\n  bind :1 ssl crt-list /l/list.txt\n", ""))
	require.NoError(t, err)
	_, err = Parse(fs.input("frontend "+long+"\n  bind :1 ssl crt-list /l/list.txt\n", ""))
	assert.ErrorIs(t, err, ErrTooComplex)

	dir := "/" + strings.Repeat("d", 4000)
	names := make([]string, MaxDirEntries)
	for i := range names {
		names[i] = fmt.Sprintf("%04d.pem", i)
	}
	fs.dirs[dir] = names
	cfg := fe(strings.Repeat("  bind :1 ssl crt "+dir+"\n", MaxPairs/MaxDirEntries))
	peak, _, _, err := measureHeap(func() (any, error) { return Parse(fs.input(cfg, "")) })
	assert.ErrorIs(t, err, ErrTooComplex)
	assert.Less(t, peak, uint64(MaxWire+(16<<20)), "refused near MaxWire, not at 2 x 4 KiB x 65,536 pairs")
}

// TestToWireSharedTextIsCheap: text shared by many servers (a 1 MiB frontend name, a crt-list
// line of 1 MiB) is cleaned once in Parse, so ToWire of every server stays quick (review I1:
// it took about 3 minutes).
func TestToWireSharedTextIsCheap(t *testing.T) {
	fs := newFS()
	fs.files["/l/big.txt"] = "/" + strings.Repeat("a", MaxLine/2-10) + " " + strings.Repeat("n", MaxLine/2-10) + "\n"
	binds := MaxServers / 2
	for name, cfg := range map[string]string{
		"crt-list line": fe(strings.Repeat("  bind :1 ssl crt-list /l/big.txt\n", binds)),
		"section name":  "frontend " + strings.Repeat("s", MaxLine-100) + "\n" + strings.Repeat("  bind :1 ssl crt /c/a.pem\n", binds),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			got, err := Parse(fs.input(cfg, ""))
			require.NoError(t, err)
			require.Len(t, got.Servers, binds)
			for _, s := range got.Servers {
				_ = ToWire(s)
			}
			assert.Less(t, time.Since(start), 2*time.Second*raceSlowdown)
		})
	}
}

// TestParseHostileMemory measures the heap of Parse on hostile maximum-size inputs (controller
// ruling for Task 5: the lexer holds about 28-30 times its input, so the whole-configuration
// bounds must keep the worst case reasonable). It logs the peak (sampled), the heap still held
// by the result and the bytes allocated in all; run with -v to see them.
func TestParseHostileMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates hundreds of MiB")
	}
	dir := make([]string, MaxDirEntries)
	for i := range dir {
		dir[i] = fmt.Sprintf("%04d.pem", i)
	}
	listLines := strings.Repeat("/c/a.pem n\n", MaxServers-1)
	for name, tc := range map[string]struct {
		cfg   string
		files map[string]string
		dirs  map[string][]string
	}{
		// MaxTokens one-letter lines: the lexer's worst case per input byte.
		"max tokens": {cfg: strings.Repeat("a\n", MaxTokens)},
		// A 20 MiB file of long words: the lexer's worst case per word.
		"max input": {cfg: strings.Repeat(strings.Repeat("a", 1000)+"\n", MaxInput/1001)},
		// The configuration and the crt-lists share the token budget: half in each.
		"tokens across files": {
			cfg:   fe("  bind :1 ssl crt-list /l/list.txt\n") + strings.Repeat("a\n", MaxTokens/2),
			files: map[string]string{"/l/list.txt": "/c/a.pem [" + strings.Repeat(" o", MaxTokens/2-10) + " ]\n"},
		},
		// The output bounds: MaxServers servers sharing MaxListens listens and holding MaxNames
		// names, and MaxPairs pairs from crt directories.
		"max servers and names": {
			cfg:   fe("  bind " + strings.Repeat(":1,", MaxListens) + " ssl crt-list /l/list.txt"),
			files: map[string]string{"/l/list.txt": listLines + "/c/a.pem" + strings.Repeat(" n", MaxNames-MaxServers+1) + "\n"},
		},
		// Both at once: the configuration takes the words the crt-list leaves.
		"max tokens and output": {
			cfg: fe("  bind "+strings.Repeat(":1,", MaxListens)+" ssl crt-list /l/list.txt") +
				strings.Repeat("a\n", MaxTokens-7-(2*(MaxServers-1)+1+MaxNames-MaxServers+1)),
			files: map[string]string{"/l/list.txt": listLines + "/c/a.pem" + strings.Repeat(" n", MaxNames-MaxServers+1) + "\n"},
		},
		// Review C1: MaxListens listens on a bind naming a crt-list of MaxServers-1 lines.
		"listens of a crt-list": {
			cfg:   fe("  bind " + strings.Repeat(":1,", MaxListens) + " ssl crt-list /l/list.txt"),
			files: map[string]string{"/l/list.txt": strings.Repeat("/c/a.pem\n", MaxServers-1)},
		},
		"max pairs": {
			cfg:  fe("  bind :2 ssl" + strings.Repeat(" crt /c/dir", MaxPairs/MaxDirEntries)),
			dirs: map[string][]string{"/c/dir": dir},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newFS()
			if tc.files != nil {
				fs.files = tc.files
			}
			if tc.dirs != nil {
				fs.dirs = tc.dirs
			}
			in := fs.input(tc.cfg, "2.6.12")
			// Parse, then everything the helper builds from it: the wire servers and their JSON.
			peak, held, total, err := measureHeap(func() (any, error) {
				c, err := Parse(in)
				if err != nil {
					return nil, err
				}
				wire := make([]helperproto.DumpServer, len(c.Servers))
				for i, s := range c.Servers {
					wire[i] = ToWire(s)
				}
				return json.Marshal(wire)
			})
			require.NoError(t, err)
			t.Logf("%s: input %d MiB: peak heap %d MiB (sampled), held by the result %d MiB, allocated %d MiB",
				name, len(in.Data)>>20, peak>>20, held>>20, total>>20)
			// With the wire servers and their JSON, the worst case measured about 84 MiB
			// (streaming lexer, listens per server, MaxWire).
			assert.Less(t, peak, uint64(128<<20))
		})
	}
}

// measureHeap runs f once and returns the peak heap in use above the starting heap (sampled
// every 200 µs), the heap the result still holds after a collection, and the bytes allocated.
func measureHeap(f func() (any, error)) (peak, held, total uint64, err error) {
	defer debug.SetGCPercent(debug.SetGCPercent(100))
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var top atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > before.HeapAlloc && ms.HeapAlloc-before.HeapAlloc > top.Load() {
				top.Store(ms.HeapAlloc - before.HeapAlloc)
			}
			select {
			case <-done:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	res, err := f()
	close(done)
	wg.Wait()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc {
		held = after.HeapAlloc - before.HeapAlloc
	}
	runtime.KeepAlive(res)
	return max(top.Load(), held), held, after.TotalAlloc - before.TotalAlloc, err
}
