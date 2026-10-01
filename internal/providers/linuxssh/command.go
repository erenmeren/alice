package linuxssh

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"alice/internal/providers/linuxssh/helperproto"
)

// HelperCommand is one remote command line. Its fields are unexported, so a command can only be
// built by the constructors below: every argument passed helperproto's vocabulary check and
// quoteArg (spec §6.6, SEC-063). There is no way to send a free-form shell string.
type HelperCommand struct {
	sub       string
	tokens    []string // rendered arguments: constant flag names or quoteArg output
	stdin     []byte
	sudo      bool
	fixed     string // the one fixed non-helper command (cat /etc/os-release); set only in dial.go
	timeout   time.Duration
	maxOutput int64
}

const (
	smallOutput    = 64 << 10
	hostKeysOutput = 1 << 20
	readOutput     = 2 << 20 // base64 of a 1 MiB file plus the JSON around it
)

// OSReleaseCommand is the only command Alice runs that is not alice-helper (spec §6.6).
const OSReleaseCommand = "cat /etc/os-release"

// ErrInvalidArgument means a value is outside the helper's argument vocabulary; no command is built.
var ErrInvalidArgument = errors.New("linuxssh: argument outside the allowed vocabulary")

// quoteArg is the single audited quoting function for remote command lines (SEC-063). The value
// must be in helperproto's vocabulary ([A-Za-z0-9._/@:+-], no ".." component, no leading '-'),
// which contains no quote, no space and no shell metacharacter, so single quotes make it one
// literal word for the remote shell.
func quoteArg(s string) (string, error) {
	if !helperproto.ValidArg(s) || strings.ContainsRune(s, '\'') {
		return "", ErrInvalidArgument
	}
	return "'" + s + "'", nil
}

func privileged(sub string, timeout time.Duration, maxOutput int64, tokens ...string) HelperCommand {
	return HelperCommand{sub: sub, tokens: tokens, sudo: true, timeout: timeout, maxOutput: maxOutput}
}

// CmdVersion asks the helper for its version; it runs without sudo (sudoers does not list it).
func CmdVersion() HelperCommand {
	return HelperCommand{sub: helperproto.SubVersion, timeout: DefaultCommandTimeout, maxOutput: smallOutput}
}

// CmdSSHDDump returns the effective sshd configuration (sshd -T).
func CmdSSHDDump() HelperCommand {
	return privileged(helperproto.SubSSHDDump, LongCommandTimeout, DefaultMaxOutput)
}

// CmdHostKeys lists the server's host keys with their fingerprints.
func CmdHostKeys() HelperCommand {
	return privileged(helperproto.SubHostKeys, DefaultCommandTimeout, hostKeysOutput)
}

// CmdAuthKeysList lists the users and the authorized_keys files sshd would read for them.
func CmdAuthKeysList() HelperCommand {
	return privileged(helperproto.SubAuthKeysList, LongCommandTimeout, DefaultMaxOutput)
}

// CmdAuthKeysRead reads one authorized_keys file (the helper accepts only paths it computed itself).
func CmdAuthKeysRead(path string) (HelperCommand, error) {
	if !helperproto.ValidPath(path) {
		return HelperCommand{}, ErrInvalidArgument
	}
	q, err := quoteArg(path)
	if err != nil {
		return HelperCommand{}, err
	}
	return privileged(helperproto.SubAuthKeysRead, DefaultCommandTimeout, readOutput, q), nil
}

// CmdAuthKeysWrite replaces one authorized_keys file with content when its current SHA-256 is
// expectSHA256 (helperproto.AbsentSHA256 for a file that does not exist yet). op names the backup.
func CmdAuthKeysWrite(path, expectSHA256 string, op uuid.UUID, content []byte) (HelperCommand, error) {
	if !helperproto.ValidPath(path) || !helperproto.ValidSHA256(expectSHA256) || op == uuid.Nil || !helperproto.ValidOpID(op.String()) {
		return HelperCommand{}, ErrInvalidArgument
	}
	if len(content) > helperproto.MaxAuthorizedKeysSize {
		return HelperCommand{}, fmt.Errorf("%w: content is larger than %d bytes", ErrInvalidArgument, helperproto.MaxAuthorizedKeysSize)
	}
	qp, err := quoteArg(path)
	if err != nil {
		return HelperCommand{}, err
	}
	qh, err := quoteArg(expectSHA256)
	if err != nil {
		return HelperCommand{}, err
	}
	qo, err := quoteArg(op.String())
	if err != nil {
		return HelperCommand{}, err
	}
	c := privileged(helperproto.SubAuthKeysWrite, DefaultCommandTimeout, smallOutput, qp, "--expect-sha256", qh, "--op", qo)
	c.stdin = append([]byte(nil), content...)
	return c, nil
}

// CmdCleanup removes the helper's backup directory of one operation.
func CmdCleanup(op uuid.UUID) (HelperCommand, error) {
	if op == uuid.Nil || !helperproto.ValidOpID(op.String()) {
		return HelperCommand{}, ErrInvalidArgument
	}
	qo, err := quoteArg(op.String())
	if err != nil {
		return HelperCommand{}, err
	}
	return privileged(helperproto.SubCleanup, DefaultCommandTimeout, smallOutput, "--op", qo), nil
}

// Line is the exact command line sent over the SSH exec channel ("" for the zero value).
func (c HelperCommand) Line() string {
	if c.fixed != "" {
		return c.fixed
	}
	if c.sub == "" {
		return ""
	}
	var b strings.Builder
	if c.sudo {
		b.WriteString("sudo -n ")
	}
	b.WriteString(helperproto.HelperPath)
	b.WriteByte(' ')
	b.WriteString(c.sub)
	for _, t := range c.tokens {
		b.WriteByte(' ')
		b.WriteString(t)
	}
	return b.String()
}

// Subcommand names the helper subcommand ("os-release" for the fixed command).
func (c HelperCommand) Subcommand() string {
	if c.fixed != "" {
		return "os-release"
	}
	return c.sub
}
