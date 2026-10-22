//go:build windows

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

// cmdElevation is what sshd's ForceCommand runs (§4.3): the token facts the helper checks before any change.
func cmdElevation() map[string]any {
	out := map[string]any{
		"ssh_original_command":     os.Getenv("SSH_ORIGINAL_COMMAND"),
		"ssh_original_command_set": os.Getenv("SSH_ORIGINAL_COMMAND") != "" || envSet("SSH_ORIGINAL_COMMAND"),
		"args":                     os.Args,
		"command_line":             windows.UTF16PtrToString(windows.GetCommandLine()),
		"ssh_connection":           os.Getenv("SSH_CONNECTION"),
		"username_env":             os.Getenv("USERNAME"),
	}
	tok := windows.GetCurrentProcessToken()
	if u, err := tok.GetTokenUser(); err == nil {
		out["user_sid"] = u.User.Sid.String()
		if acct, dom, _, err := u.User.Sid.LookupAccount(""); err == nil {
			out["user"] = dom + `\` + acct
		}
	}
	out["token_elevated"] = tok.IsElevated()
	var et uint32
	var n uint32
	if err := windows.GetTokenInformation(tok, windows.TokenElevationType, (*byte)(unsafe.Pointer(&et)), 4, &n); err == nil {
		out["token_elevation_type"] = map[uint32]string{1: "default", 2: "full", 3: "limited"}[et]
	} else {
		out["token_elevation_type_error"] = errString(err)
	}
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if groups, err := tok.GetTokenGroups(); err == nil {
		for _, g := range groups.AllGroups() {
			if g.Sid.Equals(admins) {
				out["administrators_in_token"] = true
				out["administrators_enabled"] = g.Attributes&windows.SE_GROUP_ENABLED != 0
				out["administrators_deny_only"] = g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0
			}
			if strings.HasPrefix(g.Sid.String(), "S-1-16-") {
				out["integrity_sid"] = g.Sid.String() // S-1-16-12288 high, S-1-16-8192 medium
			}
			if s := g.Sid.String(); s == "S-1-5-2" || s == "S-1-5-4" || s == "S-1-5-14" || s == "S-1-5-114" ||
				s == "S-1-5-113" || s == "S-1-5-3" || s == "S-1-5-6" {
				out["logon_group_"+s] = true // NETWORK, INTERACTIVE, REMOTE INTERACTIVE, local admin, local account
			}
		}
	}
	if member, err := tok.IsMember(admins); err == nil {
		out["check_token_membership_admins"] = member
	}
	if h, err := openStore("My", false); err != nil {
		out["machine_my_open_write"] = errString(err)
	} else {
		out["machine_my_open_write"] = "ok"
		closeStore(h)
	}
	if err := httpInit(); err != nil {
		out["http_initialize"] = errString(err)
		return out
	}
	defer httpTerm()
	list, err := enumerate(configSSLCertInfo)
	out["http_query_ipport_count"] = len(list)
	out["http_query_error"] = errString(err)
	// A real write: set and delete a throwaway record with the hash of any certificate in LocalMachine\My.
	if thumb := anyMachineCert(); thumb != "" {
		b := Binding{Type: "ipport", IP: "127.0.0.2", Port: 65001, Hash: thumb, Store: "MY", AppID: iisAppID}
		err := setBinding(b)
		out["http_set_error"] = errString(err)
		out["http_set_ok"] = err == nil
		if err == nil {
			out["http_delete_error"] = errString(deleteBinding(b))
		}
	}
	return out
}

func envSet(k string) bool { _, ok := os.LookupEnv(k); return ok }

func anyMachineCert() string {
	h, err := openStore("My", true)
	if err != nil {
		return ""
	}
	defer closeStore(h)
	ctx, err := windows.CertEnumCertificatesInStore(h, nil)
	if err != nil {
		return ""
	}
	defer freeCtx(ctx)
	return thumbOf(certDER(ctx))
}

// cmdSSHKey writes a fresh Ed25519 key pair: id_ed25519 (OpenSSH format) and authorized_line ("restrict " + key).
func cmdSSHKey(dir string) map[string]any {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	sp, _ := ssh.NewPublicKey(pub)
	line := "restrict " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " alice-w0-spike"
	_ = os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), pem.EncodeToMemory(blk), 0o600); err != nil {
		return map[string]any{"error": err.Error()}
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_line"), []byte(line+"\n"), 0o600); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"authorized_line": line, "fingerprint": ssh.FingerprintSHA256(sp)}
}

// cmdSSHRun dials sshd with x/crypto/ssh (the client Alice uses), the host key pinned from the server's own
// public key file, and runs each command; ForceCommand receives it as SSH_ORIGINAL_COMMAND.
func cmdSSHRun(addr, user, keyFile, hostKeyFile, passwordEnv string, cmds []string) map[string]any {
	out := map[string]any{"addr": addr, "user": user}
	hk, err := os.ReadFile(hostKeyFile) //nolint:gosec // spike
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey(hk)
	if err != nil {
		out["error"] = "host key: " + err.Error()
		return out
	}
	out["pinned_host_key"] = ssh.FingerprintSHA256(pinned)
	if passwordEnv != "" {
		cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(os.Getenv(passwordEnv))},
			HostKeyCallback: ssh.FixedHostKey(pinned), HostKeyAlgorithms: []string{pinned.Type()}, Timeout: 10 * time.Second}
		c, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			out["password_login"] = "ACCEPTED (unexpected)"
			c.Close()
		} else {
			out["password_login"] = "refused: " + err.Error()
		}
	}
	kb, err := os.ReadFile(keyFile) //nolint:gosec // spike
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	signer, err := ssh.ParsePrivateKey(kb)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(pinned), HostKeyAlgorithms: []string{pinned.Type()}, Timeout: 10 * time.Second}
	start := time.Now()
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		out["error"] = "dial: " + err.Error()
		return out
	}
	defer c.Close()
	out["dial_seconds"] = time.Since(start).Seconds()
	out["server_version"] = string(c.ServerVersion())
	var results []map[string]any
	for _, cmd := range cmds {
		r := map[string]any{"sent": cmd}
		s, err := c.NewSession()
		if err != nil {
			r["error"] = err.Error()
			results = append(results, r)
			continue
		}
		var so, se bytes.Buffer
		s.Stdout, s.Stderr = &so, &se
		t := time.Now()
		err = s.Run(cmd)
		r["seconds"] = time.Since(t).Seconds()
		var ee *ssh.ExitError
		switch {
		case errors.As(err, &ee):
			r["exit_status"] = ee.ExitStatus()
		case err != nil:
			r["error"] = err.Error()
		default:
			r["exit_status"] = 0
		}
		var parsed map[string]any
		if json.Unmarshal(so.Bytes(), &parsed) == nil {
			r["remote"] = parsed
			got, _ := parsed["ssh_original_command"].(string)
			r["original_command_intact"] = got == cmd
		} else {
			r["stdout"] = head(so.String(), 2000)
		}
		r["stderr"] = head(se.String(), 2000)
		s.Close()
		results = append(results, r)
	}
	out["results"] = results
	return out
}
