package linuxsshtest

import (
	"strconv"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// This file is the emulated Apache host: the state and the exported API. The files (certificates,
// keys, configuration files) live in the same table as the Nginx host's (nginxHost.content and
// meta): one host, one file system. apache_dump.go answers apache-dump from this state by running
// the real parser (internal/providers/apacheconf) over text the emulator renders as the output of
// the Apache control program and as configuration files.

const (
	apacheConfPath  = "/etc/apache2/apache2.conf"
	apacheSiteFile  = "/etc/apache2/sites-enabled/emu.conf"
	apacheServerDir = "/etc/apache2"
	// apacheIncludeLine is the line of the generated apache2.conf that includes sites-enabled.
	apacheIncludeLine = 3
)

// ApacheSite is one <VirtualHost> that serves TLS with one certificate and key pair. KeyPath ""
// means the key is in the certificate file (no SSLCertificateKeyFile).
type ApacheSite struct {
	Names    []string
	Port     int
	CertPath string
	KeyPath  string
}

// apacheHost is the Apache part of the emulated server.
type apacheHost struct {
	installed  bool
	profileOff bool
	version    string
	sites      []ApacheSite
	confs      map[string]bool // configuration files whose text a test set (it overrides the generated text)
	invalid    bool
	killed     bool
}

func (e *Emulator) apache() *apacheHost {
	if e.ax == nil {
		e.ax = &apacheHost{confs: map[string]bool{}}
	}
	return e.ax
}

// EnableApache installs Apache of the given version (apache2ctl). The sudoers profile of
// apache-dump is installed by default and independent of this (SetApacheProfile).
func (e *Emulator) EnableApache(version string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.apache()
	a.installed, a.version = true, version
}

// SetApacheProfile installs (true, the default) or removes the sudoers profile of apache-dump:
// without it sudo refuses the subcommand (exit 1).
func (e *Emulator) SetApacheProfile(installed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apache().profileOff = !installed
}

// AddApacheSite adds a virtual host with one certificate and key pair: the configuration and the
// files. With KeyPath "" the certificate file holds the certificate and then the key.
func (e *Emulator) AddApacheSite(s ApacheSite, certPEM, keyPEM []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	a, h := e.apache(), e.nginx()
	a.sites = append(a.sites, s)
	if s.KeyPath == "" {
		h.setContent(s.CertPath, append(append([]byte(nil), certPEM...), keyPEM...))
		return
	}
	h.setContent(s.CertPath, certPEM)
	h.setContent(s.KeyPath, keyPEM)
}

// SetApacheConfig sets the text of a configuration file, replacing the generated one. Only
// apache2.conf and sites-enabled/emu.conf are in the include tree the emulator reports.
func (e *Emulator) SetApacheConfig(p, text string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apache().confs[p] = true
	e.nginx().setContent(p, []byte(text))
}

// SetApacheConfigInvalid makes the control program reject the configuration (a syntax error).
func (e *Emulator) SetApacheConfigInvalid(invalid bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apache().invalid = invalid
}

// SetApacheKilled makes every run of the control program time out or be killed.
func (e *Emulator) SetApacheKilled(killed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apache().killed = killed
}

func isApacheSub(sub string) bool { return sub == helperproto.SubApacheDump }

// handleApache answers apache-dump: sudo (the profile, the sudoers pattern) first, then the
// helper (root only, no arguments).
func (e *Emulator) handleApache(sudo bool, sub string, args []string) Response {
	e.mu.Lock()
	off := e.apache().profileOff
	e.mu.Unlock()
	if sudo && (off || !sudoersAllows(sub, args)) {
		return sudoRefusal()
	}
	if !sudo {
		return refuse(helperproto.ExitRefused, helperproto.CodeNotRoot)
	}
	return e.apacheDump(args)
}

// ---- the configuration text ---------------------------------------------------------------

func (a *apacheHost) mainText() string {
	var b strings.Builder
	b.WriteString("ServerRoot \"" + apacheServerDir + "\"\n# Alice emulated host\n")
	if len(a.sites) > 0 {
		b.WriteString("IncludeOptional sites-enabled/*.conf\n") // line apacheIncludeLine
	} else {
		b.WriteString("#\n")
	}
	seen := map[int]bool{}
	for _, s := range a.sites {
		if !seen[s.Port] {
			seen[s.Port] = true
			b.WriteString("Listen " + strconv.Itoa(s.Port) + "\n")
		}
	}
	return b.String()
}

func (a *apacheHost) siteText() string {
	var b strings.Builder
	for _, s := range a.sites {
		b.WriteString("<VirtualHost *:" + strconv.Itoa(s.Port) + ">\n")
		if len(s.Names) > 0 {
			b.WriteString("    ServerName " + s.Names[0] + "\n")
		}
		if len(s.Names) > 1 {
			b.WriteString("    ServerAlias " + strings.Join(s.Names[1:], " ") + "\n")
		}
		b.WriteString("    SSLEngine on\n    SSLCertificateFile " + s.CertPath + "\n")
		if s.KeyPath != "" {
			b.WriteString("    SSLCertificateKeyFile " + s.KeyPath + "\n")
		}
		b.WriteString("</VirtualHost>\n")
	}
	return b.String()
}

// confText is the text of a configuration file of the host (a test's, else the generated one).
func (a *apacheHost) confText(h *nginxHost, p string) ([]byte, bool) {
	if a.confs[p] {
		b, ok := h.content[p]
		return b.bytes(), ok
	}
	switch p {
	case apacheConfPath:
		return []byte(a.mainText()), true
	case apacheSiteFile:
		if len(a.sites) > 0 {
			return []byte(a.siteText()), true
		}
	}
	return nil, false
}

// ---- what the control program prints -----------------------------------------------------------

func (a *apacheHost) vOutput() string {
	return "Server version: Apache/" + a.version + " (Debian)\nServer MPM:     event\nServer compiled with....\n" +
		" -D HTTPD_ROOT=\"" + apacheServerDir + "\"\n -D SERVER_CONFIG_FILE=\"apache2.conf\"\n"
}

func (a *apacheHost) includesOutput() string {
	s := "Included configuration files:\n  (*) " + apacheConfPath + "\n"
	if len(a.sites) > 0 {
		s += "    (" + strconv.Itoa(apacheIncludeLine) + ") " + apacheSiteFile + "\n"
	}
	return s
}

const (
	apacheModulesOutput = "Loaded Modules:\n core_module (static)\n so_module (static)\n ssl_module (shared)\n"
	apacheRunCfgOutput  = "ServerRoot: \"" + apacheServerDir + "\"\nMain DocumentRoot: \"/var/www/html\"\nDefine: DUMP_RUN_CFG\n"
)
