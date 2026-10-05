package linuxssh

import (
	"context"
	"errors"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// KeyLoginBudget bounds one test login, dial to authentication (spec §13.4: 10 s).
const KeyLoginBudget = 10 * time.Second

// VerifyKeyLogin is the test login of spec §13.4 (R41 row 9): a fresh connection outside the pool,
// the target's pinned host key required, authenticating as OSUser with only req.Key. No channel is
// opened and nothing runs; the connection is closed at once. The dial releases the key as soon as
// the handshake ended. A refused or unprovable login is an outcome; a connection failure is the
// dial's error (a changed host key is still observed by the store, as for every dial; the address
// rule applies as for every dial).
func (s *session) VerifyKeyLogin(ctx context.Context, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	if err := s.begin(ctx); err != nil {
		return providers.KeyLoginResult{}, err
	}
	if req.Key == nil || !helperproto.ValidAccount(req.OSUser) {
		return providers.KeyLoginResult{}, refusedRequest("os_user")
	}
	ctx, cancel := context.WithTimeout(ctx, KeyLoginBudget)
	defer cancel()
	cfg := s.cfg
	cfg.Username = req.OSUser
	conn, err := s.dialer.Dial(ctx, s.target, cfg, req.Key)
	if err == nil {
		_ = conn.Close()
		return providers.KeyLoginResult{Outcome: providers.KeyLoginAccepted}, nil
	}
	var pe *providers.Error
	if errors.As(err, &pe) && pe.Code == "ssh.auth_failed" {
		if pe.Params["reason"] == "publickey_not_offered" {
			return providers.KeyLoginResult{Outcome: providers.KeyLoginUnprovable}, nil
		}
		return providers.KeyLoginResult{Outcome: providers.KeyLoginRefused}, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return providers.KeyLoginResult{}, providers.NewError("ssh.timeout", true, ctxErr, nil)
	}
	return providers.KeyLoginResult{}, err
}
