package linuxsshtest

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// This file is the emulated HAProxy host: the state and the exported API. The files (certificates,
// keys, configuration files, crt-lists) live in the same table as the Nginx host's
// (nginxHost.content and meta): one host, one file system. haproxy_dump.go answers haproxy-dump
// from this state by running the real parser (internal/providers/haproxyconf) over text the
// emulator renders as the output of "haproxy -v" and as haproxy.cfg and its crt-list.

const (
	haproxyConfPath      = "/etc/haproxy/haproxy.cfg"
	haproxyConfDir       = "/etc/haproxy/conf.d"
	defaultHAProxyVer    = "2.6.12"
	haproxyVersionBanner = "HAProxy version %s 2025/10/03 - https://haproxy.org/\n"
)

// HAProxySite is one frontend bind that serves TLS with one certificate. KeyBeside means the key
// is written to CertPath+".key" and not into the PEM. A site with SNI names is served through the
// generated crt-list of its frontend and port, /etc/haproxy/emu-<frontend>-<port>.crtlist (so each site keeps its
// port and each frontend lists only its own certificates); one without has its own "bind ... crt" line.
type HAProxySite struct {
	Frontend  string
	Port      int
	CertPath  string
	KeyBeside bool
	SNI       []string
}

// haproxyHost is the HAProxy part of the emulated server.
type haproxyHost struct {
	installed  bool
	profileOff bool
	version    string
	sites      []HAProxySite
	confs      map[string]bool // files whose text a test set (it overrides the generated text)
	confDir    []string        // the files SetHAProxyConfDir created
	invalid    bool
	killed     bool
}

func (e *Emulator) haproxy() *haproxyHost {
	if e.hx == nil {
		e.hx = &haproxyHost{confs: map[string]bool{}}
	}
	return e.hx
}

// EnableHAProxy installs HAProxy of the given version (/usr/sbin/haproxy; "" is 2.6.12). The
// sudoers profile of haproxy-dump is installed by default and independent of this
// (SetHAProxyProfile).
func (e *Emulator) EnableHAProxy(version string) {
	if version == "" {
		version = defaultHAProxyVer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	x := e.haproxy()
	x.installed, x.version = true, version
}

// SetHAProxyProfile installs (true, the default) or removes the sudoers profile of haproxy-dump:
// without it sudo refuses the subcommand (exit 1).
func (e *Emulator) SetHAProxyProfile(installed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.haproxy().profileOff = !installed
}

// AddHAProxySite adds a bind with one certificate: the configuration and the files. With KeyBeside
// the certificate file holds the certificate and the key is in CertPath+".key"; otherwise the
// certificate file holds the certificate and then the key (mode 0600).
func (e *Emulator) AddHAProxySite(s HAProxySite, certPEM, keyPEM []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	x, h := e.haproxy(), e.nginx()
	x.sites = append(x.sites, s)
	if s.KeyBeside {
		h.setContent(s.CertPath, certPEM)
		h.setContent(s.CertPath+".key", keyPEM)
		return
	}
	h.setContent(s.CertPath, append(append([]byte(nil), certPEM...), keyPEM...))
	h.metaOf(s.CertPath).mode = 0o600
}

// SetHAProxyConfig sets the text of haproxy.cfg, replacing the generated one.
func (e *Emulator) SetHAProxyConfig(text string) {
	e.SetHAProxyFile(haproxyConfPath, []byte(text))
}

// SetHAProxyFile creates or replaces a file of the host: a certificate, a key, a crt-list, a file
// of a crt directory, or haproxy.cfg and the generated crt-list (whose text it then replaces).
func (e *Emulator) SetHAProxyFile(p string, content []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p == haproxyConfPath || isCrtListPath(p) {
		e.haproxy().confs[p] = true
	}
	e.nginx().setContent(p, content)
}

// SetHAProxyConfigInvalid makes "haproxy -c" reject the configuration (a syntax error).
func (e *Emulator) SetHAProxyConfigInvalid(invalid bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.haproxy().invalid = invalid
}

// SetHAProxyKilled makes every run of haproxy time out or be killed.
func (e *Emulator) SetHAProxyKilled(killed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.haproxy().killed = killed
}

// SetHAProxyConfDir makes /etc/haproxy/conf.d hold files of these names (replacing the ones an
// earlier call made); none removes the directory. haproxy-dump never reads them: it warns when
// one is named *.cfg.
func (e *Emulator) SetHAProxyConfDir(names ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	x, h := e.haproxy(), e.nginx()
	for _, n := range x.confDir {
		delete(h.content, path.Join(haproxyConfDir, n))
	}
	x.confDir = slices.Clone(names)
	for _, n := range names {
		h.setContent(path.Join(haproxyConfDir, n), []byte("frontend x\n"))
	}
}

func isHAProxySub(sub string) bool { return sub == helperproto.SubHAProxyDump }

// handleHAProxy answers haproxy-dump: sudo (the profile, the sudoers pattern) first, then the
// helper (root only, no arguments).
func (e *Emulator) handleHAProxy(sudo bool, sub string, args []string) Response {
	e.mu.Lock()
	off := e.haproxy().profileOff
	e.mu.Unlock()
	if sudo && (off || !sudoersAllows(sub, args)) {
		return sudoRefusal()
	}
	if !sudo {
		return refuse(helperproto.ExitRefused, helperproto.CodeNotRoot)
	}
	e.mu.Lock()
	old := e.protocol < helperproto.HAProxyMinProtocol
	e.mu.Unlock()
	if old { // a helper of protocol 8 or below does not know the subcommand
		return refuse(helperproto.ExitRefused, helperproto.CodeUnknownSubcommand)
	}
	return e.haproxyDump(args)
}

// ---- the configuration text ---------------------------------------------------------------

// crtListPath is the generated crt-list of the SNI sites of one frontend on one port.
func crtListPath(frontend string, port int) string {
	return "/etc/haproxy/emu-" + frontend + "-" + strconv.Itoa(port) + ".crtlist"
}

func isCrtListPath(p string) bool {
	return strings.HasPrefix(p, "/etc/haproxy/emu-") && strings.HasSuffix(p, ".crtlist")
}

// mainText is the generated haproxy.cfg: one frontend per distinct Frontend, with a bind per site
// without SNI and, for the sites with SNI names, one bind per distinct port on the crt-list of
// that frontend and port.
func (x *haproxyHost) mainText() string {
	var b strings.Builder
	b.WriteString("global\n    log /dev/log local0\ndefaults\n    mode http\n")
	var order []string
	for _, s := range x.sites {
		if !slices.Contains(order, s.Frontend) {
			order = append(order, s.Frontend)
		}
	}
	for _, fe := range order {
		b.WriteString("frontend " + fe + "\n")
		var listed []int
		for _, s := range x.sites {
			switch {
			case s.Frontend != fe:
			case len(s.SNI) == 0:
				b.WriteString("    bind :" + strconv.Itoa(s.Port) + " ssl crt " + s.CertPath + "\n")
			case !slices.Contains(listed, s.Port):
				listed = append(listed, s.Port)
				b.WriteString("    bind :" + strconv.Itoa(s.Port) + " ssl crt-list " + crtListPath(fe, s.Port) + "\n")
			}
		}
	}
	return b.String()
}

// listText is the generated crt-list at p: one line per site with SNI names of its frontend and port.
func (x *haproxyHost) listText(p string) (string, bool) {
	var b strings.Builder
	found := false
	for _, s := range x.sites {
		if len(s.SNI) > 0 && crtListPath(s.Frontend, s.Port) == p {
			found = true
			b.WriteString(s.CertPath + " " + strings.Join(s.SNI, " ") + "\n")
		}
	}
	return b.String(), found
}

// confText is the text of a configuration file of the host (a test's, else the generated one).
func (x *haproxyHost) confText(h *nginxHost, p string) ([]byte, bool) {
	if x.confs[p] {
		b, ok := h.content[p]
		return b.bytes(), ok
	}
	if p == haproxyConfPath {
		return []byte(x.mainText()), true
	}
	if t, ok := x.listText(p); ok {
		return []byte(t), true
	}
	b, ok := h.content[p]
	return b.bytes(), ok
}

// vOutput is what "haproxy -v" prints.
func (x *haproxyHost) vOutput() string {
	return strings.Replace(haproxyVersionBanner, "%s", x.version, 1) +
		"Status: long-term supported branch - will stop receiving fixes around Q2 2027.\n"
}
