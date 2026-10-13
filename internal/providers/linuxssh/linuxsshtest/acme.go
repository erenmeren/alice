package linuxsshtest

import (
	"bytes"

	"alice/internal/providers/linuxssh/helperproto"
)

// acmeState is the emulated HTTP-01 webroot (protocol 7): the token files of
// helperproto.ACMEChallengeDir, whether the administrator prepared that directory, and an injected
// refusal.
type acmeState struct {
	tokens    map[string][]byte
	dirAbsent bool
	failExit  int
	failCode  string
}

func (e *Emulator) acme() *acmeState {
	if e.acmeWeb == nil {
		e.acmeWeb = &acmeState{tokens: map[string][]byte{}}
	}
	return e.acmeWeb
}

// ACMEToken returns the content of a published token file.
func (e *Emulator) ACMEToken(token string) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.acme().tokens[token]
	return bytes.Clone(b), ok
}

// SetACMEChallengeDir prepares (true, the default) or removes the challenge directory: without it
// acme-challenge-put answers NOT_FOUND (exit 3) and acme-challenge-rm succeeds with removed false.
func (e *Emulator) SetACMEChallengeDir(present bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.acme().dirAbsent = !present
}

// FailACME makes both acme-challenge subcommands refuse with exit and code (a link on the path, a
// directory others can write, ...); exit 0 clears it.
func (e *Emulator) FailACME(exit int, code string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.acme().failExit, e.acme().failCode = exit, code
}

func isACMESub(sub string) bool {
	return sub == helperproto.SubACMEChallengePut || sub == helperproto.SubACMEChallengeRm
}

// handleACME answers acme-challenge-put and -rm like sudo and the helper: the nginx profile's
// sudoers lines exist only from protocol 7 on (an older setup has none, so sudo refuses), then the
// helper refuses a call without root and checks its arguments and stdin.
func (e *Emulator) handleACME(sudo bool, sub string, args []string, stdin []byte) Response {
	e.mu.Lock()
	defer e.mu.Unlock()
	if sudo && (e.nginx().profileOff || e.protocol < helperproto.HTTP01MinProtocol ||
		len(args) != 2 || args[0] != "--token" || len(args[1]) < helperproto.MinACMEToken) {
		return sudoRefusal()
	}
	if !sudo {
		return refuse(helperproto.ExitRefused, helperproto.CodeNotRoot)
	}
	token := args[1]
	if !helperproto.ValidACMEToken(token) {
		return refuse(helperproto.ExitRefused, helperproto.CodeInvalidArgument)
	}
	st := e.acme()
	path := helperproto.ACMEChallengePath(token)
	if sub == helperproto.SubACMEChallengePut {
		switch {
		case len(stdin) > helperproto.MaxACMEBody:
			return refuse(helperproto.ExitRefused, helperproto.CodeTooLarge)
		case !helperproto.ValidKeyAuthorization(token, stdin):
			return refuse(helperproto.ExitRefused, helperproto.CodeBadContent)
		case st.failExit != 0:
			return refuse(st.failExit, st.failCode)
		case st.dirAbsent:
			return refuse(helperproto.ExitPrecondition, helperproto.CodeNotFound)
		}
		_, replaced := st.tokens[token]
		st.tokens[token] = bytes.Clone(stdin)
		return answer(helperproto.ACMEChallengePutResponse{OK: true, Path: path, Replaced: replaced})
	}
	if st.failExit != 0 {
		return refuse(st.failExit, st.failCode)
	}
	_, removed := st.tokens[token]
	delete(st.tokens, token)
	return answer(helperproto.ACMEChallengeRmResponse{OK: true, Path: path, Removed: removed})
}
