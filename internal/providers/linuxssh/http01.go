package linuxssh

import (
	"context"
	"errors"
	"strconv"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// ReasonHTTP01HelperOutdated is the reason of the error PublishHTTP01Token and RemoveHTTP01Token
// return for a helper older than helperproto.HTTP01MinProtocol: the server keeps working for every
// other operation, and the administrator reinstalls the helper on it (running the setup commands
// again) to use the HTTP-01 proof method. Params: helper_protocol, required_protocol.
const ReasonHTTP01HelperOutdated = "ssh.helper_outdated_http01"

// ErrHTTP01HelperOutdated is the cause of that error (errors.Is).
var ErrHTTP01HelperOutdated = errors.New("linuxssh: reinstall the helper on this server to use this proof method")

// PublishHTTP01Token writes the HTTP-01 key authorization of token into the server's fixed challenge
// directory (helperproto.ACMEChallengePath) through the helper (protocol 7). Alice never edits the
// Nginx configuration: the administrator published helperproto.ACMEWebroot on port 80 and created the
// directory; the helper refuses anything else (links, a directory others can write, a missing
// directory: ssh.helper_refused with the helper's code). Whether the file is reachable from the
// Internet is for the caller to check by fetching the URL itself.
func (c *Conn) PublishHTTP01Token(ctx context.Context, token string, keyAuthorization []byte) (helperproto.ACMEChallengePutResponse, error) {
	cmd, err := CmdACMEChallengePut(token, keyAuthorization)
	if err != nil {
		return helperproto.ACMEChallengePutResponse{}, err
	}
	if err := c.requireHTTP01(ctx); err != nil {
		return helperproto.ACMEChallengePutResponse{}, err
	}
	return runHelper[helperproto.ACMEChallengePutResponse](ctx, c, cmd)
}

// RemoveHTTP01Token removes the token file again; removed is false when there was none (success).
func (c *Conn) RemoveHTTP01Token(ctx context.Context, token string) (removed bool, err error) {
	cmd, err := CmdACMEChallengeRm(token)
	if err != nil {
		return false, err
	}
	if err := c.requireHTTP01(ctx); err != nil {
		return false, err
	}
	r, err := runHelper[helperproto.ACMEChallengeRmResponse](ctx, c, cmd)
	if err != nil {
		return false, err
	}
	return r.Removed, nil
}

// requireHTTP01 refuses a helper older than HTTP01MinProtocol. The protocol is the one the helper
// reported when the session was opened; a connection that did not go through Open asks it first.
func (c *Conn) requireHTTP01(ctx context.Context) error {
	p := int(c.helperProtocol.Load())
	if p == 0 {
		v, err := runHelper[helperproto.VersionResponse](ctx, c, CmdVersion())
		if err != nil {
			return err
		}
		p = v.Protocol
		c.helperProtocol.Store(int64(p))
	}
	if p < helperproto.HTTP01MinProtocol {
		return providers.NewError(ReasonHTTP01HelperOutdated, false, ErrHTTP01HelperOutdated, map[string]string{
			"helper_protocol": strconv.Itoa(p), "required_protocol": strconv.Itoa(helperproto.HTTP01MinProtocol)})
	}
	return nil
}
