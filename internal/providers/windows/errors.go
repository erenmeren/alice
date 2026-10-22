package windows

import (
	"errors"
	"maps"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/windows/winproto"
)

// The three reasons of the Windows provider (ALC-WIN-0001..0003). Every other helper refusal stays
// ssh.helper_refused with its helper_code parameter, as on Linux (Ruling 13).
const (
	ReasonHelperMissing  = "windows.helper_missing"
	ReasonHelperOutdated = "windows.helper_outdated"
	ReasonNotElevated    = "windows.not_elevated"
)

// mapHelper names the Windows conditions in an error of the shared SSH layer: an exit that is no
// helper exit (cmd.exe's "not recognized", or sshd without the forced command) is helper_missing, a
// helper that does not know the subcommand is helper_outdated, a refusal for want of an elevated token
// is not_elevated. The shared error stays the cause; anything else is returned unchanged.
func mapHelper(err error) error {
	var pe *providers.Error
	if !errors.As(err, &pe) {
		return err
	}
	switch {
	case pe.Code == "ssh.helper_missing":
		return providers.NewError(ReasonHelperMissing, false, err, maps.Clone(pe.Params))
	case pe.Code == "ssh.helper_refused" && pe.Params["helper_code"] == winproto.CodeUnknownSubcommand:
		return providers.NewError(ReasonHelperOutdated, false, err, maps.Clone(pe.Params))
	case pe.Code == "ssh.helper_refused" && pe.Params["helper_code"] == winproto.CodeNotElevated:
		return providers.NewError(ReasonNotElevated, false, err, maps.Clone(pe.Params))
	}
	return err
}

// budget is a command's time budget and output bound.
type budget struct {
	timeout   time.Duration
	maxOutput int64
}

// budgets of the W1 subcommands. iis-dump's helper gives up after winproto.HelperBudget (50 s), before
// Alice's 60 s cut the connection.
var budgets = map[string]budget{
	winproto.SubVersion:  {linuxssh.DefaultCommandTimeout, 64 << 10},
	winproto.SubWinFacts: {linuxssh.DefaultCommandTimeout, 64 << 10},
	winproto.SubIISDump:  {linuxssh.LongCommandTimeout, winproto.DumpOutput},
	winproto.SubTLSProbe: {linuxssh.DefaultCommandTimeout, 128 << 10},
}

// cmd builds the forced command line of a W1 subcommand: the protocol's own line check
// (winproto.JoinCommandLine), then linuxssh's one audited constructor. A subcommand without a budget
// or a token outside the vocabulary is linuxssh.ErrInvalidArgument.
func cmd(sub string, args ...string) (linuxssh.HelperCommand, error) {
	b, ok := budgets[sub]
	tokens := append([]string{sub}, args...)
	if _, valid := winproto.JoinCommandLine(tokens); !ok || !valid {
		return linuxssh.HelperCommand{}, linuxssh.ErrInvalidArgument
	}
	return linuxssh.ForcedCommand(tokens, nil, b.timeout, b.maxOutput)
}
