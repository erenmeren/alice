package winhelper

// The Centralized Certificate Store subcommands (W5, R68): ccs-dump reads the CCS folder the registry
// names with the PFX password from standard input.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"alice/internal/providers/windows/winproto"
)

// ccsDumpBudget is how long ccs-dump reads files before it answers Truncated with what it has: part of
// the call budget, so the answer is sent before the budget ends (tests lower it).
var ccsDumpBudget = winproto.HelperBudget * 4 / 5

// parseCCSPassword decodes a CCSDumpInput strictly: one object with exactly the member "password" (a
// JSON string), nothing after it but white space. The password is copied only into the returned
// buffer, which the caller clears. Syntax is BAD_CONTENT; a password outside ValidCCSPassword is
// INVALID_ARGUMENT.
func parseCCSPassword(raw []byte) ([]byte, error) {
	bad := refused(winproto.CodeBadContent, "the input is not a CCS password")
	p := jsonScan{b: raw}
	if !p.lit('{') {
		return nil, bad
	}
	if name, ok := p.str(make([]byte, 0, 16), 16); !ok || string(name) != "password" || !p.lit(':') {
		return nil, bad
	}
	pw, ok := p.str(make([]byte, 0, len(raw)), len(raw))
	if !ok || !p.lit('}') {
		clear(pw[:cap(pw)])
		return nil, bad
	}
	p.ws()
	if p.i != len(p.b) {
		clear(pw[:cap(pw)])
		return nil, bad
	}
	if !winproto.ValidCCSPassword(pw) {
		clear(pw[:cap(pw)])
		return nil, refused(winproto.CodeInvalidArgument, "the CCS password is not allowed")
	}
	return pw, nil
}

// cmdCCSDump answers "ccs-dump" (elevated, no lock): the registry's CCS folder and, for a local one,
// each .pfx whose name gives a host, read with the password from stdin. A file that cannot be read or
// opened, or a list cut at MaxCCSFiles or at the budget, sets Truncated (Alice then marks nothing
// missing, W2 Ruling 18). The password buffer is cleared before the answer.
func cmdCCSDump(ctx context.Context, c *call) (any, error) {
	if len(c.args) != 0 {
		return nil, refused(winproto.CodeUsage, "ccs-dump takes no arguments")
	}
	pw, err := parseCCSPassword(c.input)
	if err != nil {
		return nil, err
	}
	defer clear(pw[:cap(pw)])
	h := c.host
	enabled, path, err := h.CCSConfig(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the CCS configuration could not be read")
	}
	d := winproto.CCSDumpResponse{OK: true, Enabled: enabled, Files: []winproto.CCSFile{}}
	if !enabled {
		return d, nil
	}
	d.Path = cleanValue(path, winproto.MaxText)
	if !winproto.ValidCCSPath(path) {
		return d, nil
	}
	entries, err := h.ListCCS(ctx, path)
	if errors.Is(err, ErrCCSFolderUnsupported) {
		return d, nil
	}
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the CCS folder could not be read")
	}
	d.Local = true
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	end := h.Now().Add(ccsDumpBudget)
	for _, e := range entries {
		host, ok := winproto.CCSHost(e.Name)
		if !ok {
			d.Ignored++
			continue
		}
		if len(d.Files) == winproto.MaxCCSFiles || ctx.Err() != nil || !h.Now().Before(end) {
			d.Truncated = true
			break
		}
		f, ok := readCCSFile(ctx, h, path, e, host, pw)
		if !ok {
			d.Truncated = true
			continue
		}
		if f.Name != "" {
			d.Files = append(d.Files, f)
		}
	}
	return d, nil
}

// readCCSFile reads and opens one file. ok is false when it cannot be read or opened, or its
// certificates are past the bounds; a file that vanished since the list is the zero CCSFile.
func readCCSFile(ctx context.Context, h WriteHost, folder string, e CCSEntry, host string, pw []byte) (winproto.CCSFile, bool) {
	data, found, err := h.ReadCCS(ctx, folder, e.Name, winproto.MaxCCSFile)
	if err != nil {
		return winproto.CCSFile{}, false
	}
	if !found {
		return winproto.CCSFile{}, true
	}
	f := winproto.CCSFile{Name: e.Name, Host: host, Size: e.Size, ModifiedAt: e.ModTime.UTC().Format(time.RFC3339), Chain: []string{}}
	if len(data) > winproto.MaxCCSFile {
		f.Problem = winproto.CCSProblemTooLarge
		return f, true
	}
	sum := sha256.Sum256(data)
	f.FileSHA256 = hex.EncodeToString(sum[:])
	leaf, chain, problem, err := h.OpenPFX(data, pw)
	if err != nil {
		return winproto.CCSFile{}, false
	}
	if problem != "" {
		f.Problem = problem
		return f, true
	}
	if len(leaf) == 0 || len(leaf) > winproto.MaxCertDER || len(chain) > winproto.MaxChainCerts {
		return winproto.CCSFile{}, false
	}
	f.LeafDER = base64.StdEncoding.EncodeToString(leaf)
	for _, der := range chain {
		if len(der) == 0 || len(der) > winproto.MaxCertDER {
			return winproto.CCSFile{}, false
		}
		f.Chain = append(f.Chain, base64.StdEncoding.EncodeToString(der))
	}
	return f, true
}
