//go:build windows

// Command winspike is the throwaway Phase W0 spike of the Windows/IIS design
// (docs/superpowers/specs/2026-10-21-windows-iis-target-design.md §14). Each subcommand checks one fact, or does one
// step the workflow (.github/workflows/windows-spike.yml) needs, and prints one JSON object. It is not product code
// and is never merged; W1/W2 use it as the reference for the httpapi layouts, the import flags and the ACLs that
// worked on the GitHub windows-2022 and windows-2025 images.
//
//	winspike osinfo | sslenum | probe ADDR SNI | repoint KEY HASH | f1 A B | f2 A B | f4 PFX PASSWORD RESTORE |
//	         f5 RESTORE | f6 | elevation | sshkey DIR | sshrun ...
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func errString(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("%v (errno %d)", err, uint32(errno))
	}
	return err.Error()
}

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fail(format string, a ...any) {
	emit(map[string]any{"error": fmt.Sprintf(format, a...)})
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: winspike <subcommand> ...")
	}
	cmd, args := os.Args[1], os.Args[2:]
	need := func(n int) {
		if len(args) < n {
			fail("%s needs %d arguments", cmd, n)
		}
	}
	switch cmd {
	case "elevation", "sshkey", "sshrun", "probe":
	default:
		if err := httpInit(); err != nil {
			fail("HttpInitialize: %s", errString(err))
		}
		defer httpTerm()
	}
	var res any
	switch cmd {
	case "osinfo":
		res = cmdOSInfo()
	case "sslenum":
		res = enumerateAll()
	case "probe":
		need(2)
		res = probe(args[0], args[1])
	case "repoint":
		need(2)
		key, err := parseKey(args[0])
		if err != nil {
			fail("%v", err)
		}
		before, after, err := repoint(key, args[1], "")
		res = map[string]any{"before": before, "after": after, "error": errString(err)}
	case "f1":
		need(2)
		res = cmdF1(strings.ToLower(args[0]), strings.ToLower(args[1]))
	case "f2":
		need(2)
		res = cmdF2(strings.ToLower(args[0]), strings.ToLower(args[1]))
	case "f4":
		need(3)
		res = cmdF4(args[0], args[1], strings.ToLower(args[2]))
	case "f5":
		need(1)
		res = cmdF5(strings.ToLower(args[0]))
	case "f6":
		res = cmdF6()
	case "elevation":
		res = cmdElevation()
	case "sshkey":
		need(1)
		res = cmdSSHKey(args[0])
	case "sshrun":
		fs := flag.NewFlagSet("sshrun", flag.ExitOnError)
		user := fs.String("user", "", "")
		key := fs.String("key", "", "private key file")
		hostKey := fs.String("hostkey", `C:\ProgramData\ssh\ssh_host_ed25519_key.pub`, "pinned host key")
		addr := fs.String("addr", "127.0.0.1:22", "")
		password := fs.String("password-env", "", "env var holding a password to try (must be refused)")
		_ = fs.Parse(args)
		res = cmdSSHRun(*addr, *user, *key, *hostKey, *password, fs.Args())
	default:
		fail("unknown subcommand %q", cmd)
	}
	emit(res)
}

func cmdOSInfo() map[string]any {
	v := windows.RtlGetVersion()
	out := map[string]any{
		"rtl_version":  fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber),
		"struct_sizes": structSizes(),
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE); err == nil {
		for _, n := range []string{"CurrentBuild", "ProductName", "DisplayVersion", "EditionID", "InstallationType"} {
			if s, _, err := k.GetStringValue(n); err == nil {
				out[n] = s
			}
		}
		if u, _, err := k.GetIntegerValue("UBR"); err == nil {
			out["UBR"] = u
		}
		k.Close()
	}
	exports := map[string]string{}
	for _, p := range httpapiProcs {
		if err := p.Find(); err != nil {
			exports[p.Name] = "missing: " + err.Error()
		} else {
			exports[p.Name] = "exported"
		}
	}
	out["httpapi_exports"] = exports
	return out
}

func run(name string, args ...string) map[string]any {
	start := time.Now()
	c := exec.Command(name, args...)
	b, err := c.CombinedOutput()
	out := map[string]any{"cmd": name + " " + strings.Join(args, " "), "seconds": time.Since(start).Seconds()}
	if c.ProcessState != nil {
		out["exit_code"] = c.ProcessState.ExitCode()
	}
	if err != nil {
		out["error"] = err.Error()
	}
	s := string(b)
	if len(s) > 4000 {
		s = s[:4000] + "...(cut)"
	}
	out["output"] = s
	return out
}

func execOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func netshText() string {
	b, _ := exec.Command("netsh", "http", "show", "sslcert").CombinedOutput()
	return string(b)
}
