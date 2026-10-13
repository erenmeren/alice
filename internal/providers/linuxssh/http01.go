package linuxssh

import (
	"context"
	"errors"
	"strconv"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// ReasonHTTP01HelperOutdated is the reason of the error PublishHTTP01Token and RemoveHTTP01Token
// return when the server cannot run the HTTP-01 commands yet: its helper is older than
// helperproto.HTTP01MinProtocol, or its sudoers file predates them (sudo refused the line although
// the helper is new enough). The server keeps working for every other operation; the administrator
// runs the setup commands again (new helper and sudoers file) to use the HTTP-01 proof method.
// Params: helper_protocol, required_protocol. Registered as ALC-SSH-0013.
const ReasonHTTP01HelperOutdated = "ssh.helper_outdated_http01"

// http01OutdatedError is the cause of that error. Its HTTP01HelperOutdated method lets a caller that
// must not import this package (the ACME HTTP-01 solver) recognize it with errors.As on an interface.
type http01OutdatedError struct{}

func (http01OutdatedError) Error() string {
	return "linuxssh: reinstall the helper on this server to use this proof method"
}

// HTTP01HelperOutdated marks the error (see http01OutdatedError).
func (http01OutdatedError) HTTP01HelperOutdated() bool { return true }

// ErrHTTP01HelperOutdated is the cause of a ReasonHTTP01HelperOutdated error (errors.Is).
var ErrHTTP01HelperOutdated error = http01OutdatedError{}

// PublishHTTP01Token writes the HTTP-01 key authorization of token into the server's fixed challenge
// directory (helperproto.ACMEChallengePath) through the helper (protocol 7). Alice never edits the
// Nginx configuration: the administrator published helperproto.ACMEWebroot on port 80 and created the
// directory; the helper refuses anything else (links, a directory others can write, a missing
// directory: ssh.helper_refused with the helper's code). Whether the file is reachable from the
// Internet is for the caller to check by fetching the URL itself.
func (c *Conn) PublishHTTP01Token(ctx context.Context, token string, keyAuthorization []byte) error {
	cmd, err := CmdACMEChallengePut(token, keyAuthorization)
	if err != nil {
		return err
	}
	p, err := c.requireHTTP01(ctx)
	if err != nil {
		return err
	}
	_, err = runHelper[helperproto.ACMEChallengePutResponse](ctx, c, cmd)
	return sudoRefusedAsOutdated(err, p)
}

// RemoveHTTP01Token removes the token file again; removed is false when there was none (success).
func (c *Conn) RemoveHTTP01Token(ctx context.Context, token string) (removed bool, err error) {
	cmd, err := CmdACMEChallengeRm(token)
	if err != nil {
		return false, err
	}
	p, err := c.requireHTTP01(ctx)
	if err != nil {
		return false, err
	}
	r, err := runHelper[helperproto.ACMEChallengeRmResponse](ctx, c, cmd)
	if err != nil {
		return false, sudoRefusedAsOutdated(err, p)
	}
	return r.Removed, nil
}

// requireHTTP01 refuses a helper older than HTTP01MinProtocol and returns the helper's protocol. The
// protocol is the one the helper reported when the session was opened; a connection that did not go
// through Open asks it first.
func (c *Conn) requireHTTP01(ctx context.Context) (int, error) {
	p := int(c.helperProtocol.Load())
	if p == 0 {
		v, err := runHelper[helperproto.VersionResponse](ctx, c, CmdVersion())
		if err != nil {
			return 0, err
		}
		p = v.Protocol
		c.helperProtocol.Store(int64(p))
	}
	if p < helperproto.HTTP01MinProtocol {
		return p, http01Outdated(p)
	}
	return p, nil
}

func http01Outdated(p int) error {
	return providers.NewError(ReasonHTTP01HelperOutdated, false, ErrHTTP01HelperOutdated, map[string]string{
		"helper_protocol": strconv.Itoa(p), "required_protocol": strconv.Itoa(helperproto.HTTP01MinProtocol)})
}

// sudoRefusedAsOutdated turns ssh.helper_missing (sudo refused the line: exit 1) into the outdated
// error: the helper answered its version just before, so what is missing is the sudoers line of an
// older setup (or a linux-profile server), which the setup commands of this release install.
func sudoRefusedAsOutdated(err error, protocol int) error {
	var pe *providers.Error
	if errors.As(err, &pe) && pe.Code == "ssh.helper_missing" {
		return http01Outdated(protocol)
	}
	return err
}
