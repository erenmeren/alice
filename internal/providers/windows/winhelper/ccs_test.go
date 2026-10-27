package winhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"alice/internal/providers/windows/winproto"
	"alice/internal/testutil/pki"
)

const ccsFolder = `C:\CCS`

func ccsInput(pw []byte) []byte { return []byte(`{"password":"` + string(pw) + `"}`) }

func ccsDump(t *testing.T, h *fakeWriteHost, in []byte, args ...string) (Outcome, winproto.CCSDumpResponse, []byte) {
	t.Helper()
	o, out := execute(t, context.Background(), h, bytes.NewReader(in), append([]string{winproto.SubCCSDump}, args...)...)
	var r winproto.CCSDumpResponse
	if o.Exit == 0 {
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatal(err)
		}
	}
	return o, r, out
}

func lowerCCSBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := ccsDumpBudget
	ccsDumpBudget = d
	t.Cleanup(func() { ccsDumpBudget = old })
}

// tick advances the fake's clock by d.
func (f *fakeWriteHost) tick(d time.Duration) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.now.IsZero() {
		f.now = testNow
	}
	f.now = f.now.Add(d)
}

func TestCCSDump(t *testing.T) {
	ca := pki.NewCA("CCS Dump", pki.ECDSA256, testNow)
	l := ca.Issue(pki.Opts{CommonName: "a.example.test", SANs: []string{"a.example.test"}}, testNow)
	pw, otherPW := NewPFXPassword(), NewPFXPassword()
	alice, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), pw, ca.Intermediate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), otherPW)
	if err != nil {
		t.Fatal(err)
	}
	junk := []byte("not a pfx")
	many := map[string][]byte{}
	for i := range winproto.MaxCCSFiles + 1 {
		many["h"+strconv.Itoa(i)+".example.test.pfx"] = junk
	}
	stamp := testNow.Format(time.RFC3339)

	for _, c := range []struct {
		name  string
		setup func(t *testing.T, h *fakeWriteHost)
		check func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse)
	}{
		{"disabled", func(*testing.T, *fakeWriteHost) {}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if r.Enabled || r.Local || r.Files == nil || len(r.Files) != 0 || h.ccsLists != 0 {
				t.Fatalf("%+v lists=%d", r, h.ccsLists)
			}
		}},
		{"UNC path", func(_ *testing.T, h *fakeWriteHost) { h.setCCS(`\\fs\certs`, nil) }, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if !r.Enabled || r.Local || r.Path != `\\fs\certs` || len(r.Files) != 0 || h.ccsLists != 0 {
				t.Fatalf("%+v lists=%d", r, h.ccsLists)
			}
		}},
		{"folder is a reparse point", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, nil)
			h.ccsListErr = ErrCCSFolderUnsupported
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if !r.Enabled || r.Local || r.Path != ccsFolder || len(r.Files) != 0 {
				t.Fatalf("%+v", r)
			}
		}},
		{"three files", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": alice, "B.Example.Test.pfx": foreign, "x.pfx.bak": alice})
		}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if !r.Enabled || !r.Local || r.Path != ccsFolder || len(r.Files) != 2 || r.Ignored != 0 || r.Truncated {
				t.Fatalf("%+v", r)
			}
			a, b := r.Files[1], r.Files[0] // sorted by name: "B.Example..." < "a.example..."
			if a.Name != "a.example.test.pfx" || a.Host != "a.example.test" || a.Problem != "" || a.LeafDER != b64(l.Cert.Raw) ||
				len(a.Chain) != 1 || a.Chain[0] != b64(ca.Intermediate.Raw) || a.FileSHA256 != hexSHA256(alice) ||
				a.Size != int64(len(alice)) || a.ModifiedAt != stamp {
				t.Fatalf("alice's file: %+v", a)
			}
			if b.Host != "b.example.test" || b.Problem != winproto.CCSProblemPasswordMismatch || b.LeafDER != "" ||
				b.Chain == nil || len(b.Chain) != 0 || b.FileSHA256 != hexSHA256(foreign) {
				t.Fatalf("the other password's file: %+v", b)
			}
			if strings.Join(h.ccsReads, ",") != "B.Example.Test.pfx,a.example.test.pfx" {
				t.Fatalf("reads %v", h.ccsReads)
			}
		}},
		{"a name without a valid host", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"not a host.pfx": junk, "_.example.test.pfx": junk})
		}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if r.Ignored != 1 || len(r.Files) != 1 || r.Files[0].Host != "*.example.test" || r.Files[0].Problem != winproto.CCSProblemNotPFX ||
				r.Truncated || len(h.ccsReads) != 1 {
				t.Fatalf("%+v reads=%v", r, h.ccsReads)
			}
		}},
		{"501 files", func(_ *testing.T, h *fakeWriteHost) { h.setCCS(ccsFolder, many) }, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != winproto.MaxCCSFiles || !r.Truncated {
				t.Fatalf("%d %v", len(r.Files), r.Truncated)
			}
		}},
		{"a 257 KiB file", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"big.example.test.pfx": make([]byte, 257<<10)})
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 1 || r.Files[0].Problem != winproto.CCSProblemTooLarge || r.Files[0].Size != 257<<10 ||
				r.Files[0].FileSHA256 != "" || r.Files[0].LeafDER != "" || r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"the budget ends after 2 files", func(t *testing.T, h *fakeWriteHost) {
			lowerCCSBudget(t, 2*time.Second)
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk, "b.example.test.pfx": junk, "c.example.test.pfx": junk})
			h.ccsReadFn = func(string) error { h.tick(time.Second); return nil }
		}, func(t *testing.T, h *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 2 || !r.Truncated || len(h.ccsReads) != 2 {
				t.Fatalf("%d %v %v", len(r.Files), r.Truncated, h.ccsReads)
			}
		}},
		{"an unreadable file is dropped", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk, "b.example.test.pfx": junk})
			h.ccsReadFn = func(name string) error {
				if name == "a.example.test.pfx" {
					return errors.New("access denied")
				}
				return nil
			}
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 1 || r.Files[0].Name != "b.example.test.pfx" || !r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"a file that vanished is skipped", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk})
			h.ccsReadFn = func(name string) error {
				h.wmu.Lock()
				defer h.wmu.Unlock()
				delete(h.ccsFiles, name)
				return nil
			}
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 0 || r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"a chain past the bounds is dropped", func(t *testing.T, h *fakeWriteHost) {
			long, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), pw, slices.Repeat([][]byte{ca.Intermediate.Raw}, winproto.MaxChainCerts+1)...)
			if err != nil {
				t.Fatal(err)
			}
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": long})
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 0 || !r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
		{"a file the host cannot open is dropped", func(_ *testing.T, h *fakeWriteHost) {
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": junk})
			h.ccsOpenErr = func([]byte) error { return errors.New("crypt32") }
		}, func(t *testing.T, _ *fakeWriteHost, r winproto.CCSDumpResponse) {
			if len(r.Files) != 0 || !r.Truncated {
				t.Fatalf("%+v", r)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newWriteHost()
			c.setup(t, h)
			o, r, out := ccsDump(t, h, ccsInput(pw))
			if o.Exit != 0 || !r.OK {
				t.Fatalf("%+v %s", o, out)
			}
			if bytes.Contains(out, pw) {
				t.Fatal("the password is in the answer")
			}
			c.check(t, h, r)
		})
	}
}

func TestCCSDumpRefusals(t *testing.T) {
	pw := NewPFXPassword()
	for _, c := range []struct {
		name  string
		in    []byte
		args  []string
		setup func(h *fakeWriteHost)
		exit  int
		code  string
	}{
		{"not elevated", ccsInput(pw), nil, func(h *fakeWriteHost) { h.elevated = false }, winproto.ExitRefused, winproto.CodeNotElevated},
		{"an argument", ccsInput(pw), []string{"x"}, nil, winproto.ExitRefused, winproto.CodeUsage},
		{"11 characters", ccsInput(pw[:11]), nil, nil, winproto.ExitRefused, winproto.CodeInvalidArgument},
		{"a space", ccsInput(append([]byte("with space "), pw...)), nil, nil, winproto.ExitRefused, winproto.CodeInvalidArgument},
		{"an unknown member", []byte(`{"password":"` + string(pw) + `","path":"C:\\x"}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"a duplicate member", []byte(`{"password":"` + string(pw) + `","password":"` + string(pw) + `"}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"no member", []byte(`{}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"not an object", []byte(`["x"]`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"not a string", []byte(`{"password":12}`), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"trailing data", append(ccsInput(pw), []byte(" {}")...), nil, nil, winproto.ExitRefused, winproto.CodeBadContent},
		{"4 KiB + 1", append(ccsInput(pw), bytes.Repeat([]byte(" "), winproto.MaxCCSDumpInput+1-len(ccsInput(pw)))...), nil, nil,
			winproto.ExitRefused, winproto.CodeTooLarge},
		{"an unreadable registry", ccsInput(pw), nil, func(h *fakeWriteHost) { h.ccsConfigErr = errors.New("registry") }, winproto.ExitFailed, winproto.CodeIOError},
		{"an unreadable folder", ccsInput(pw), nil, func(h *fakeWriteHost) {
			h.setCCS(ccsFolder, nil)
			h.ccsListErr = errors.New("access denied")
		}, winproto.ExitFailed, winproto.CodeIOError},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newWriteHost()
			h.setCCS(ccsFolder, map[string][]byte{"a.example.test.pfx": []byte("x")})
			if c.setup != nil {
				c.setup(h)
			}
			o, _, out := ccsDump(t, h, c.in, c.args...)
			wantError(t, o.Exit, out, c.exit, c.code)
			if len(h.ccsReads) != 0 || bytes.Contains(out, pw[:11]) {
				t.Fatalf("reads %v, answer %s", h.ccsReads, out)
			}
		})
	}
	// The JSON escapes of a valid password decode (the strict parser is a JSON parser).
	h := newWriteHost()
	if o, r, out := ccsDump(t, h, []byte(` { "password" : "\u0041`+string(pw[1:])+`" } `)); o.Exit != 0 || r.Enabled {
		t.Fatalf("%+v %s", o, out)
	}
}

func TestCCSDumpClearsThePassword(t *testing.T) {
	ca := pki.NewCA("CCS Clear", pki.ECDSA256, testNow)
	l := ca.Issue(leafOpts, testNow)
	pw := NewPFXPassword()
	pfx, err := BuildPFX(l.Cert.Raw, pkcs8Of(t, l), pw)
	if err != nil {
		t.Fatal(err)
	}
	h := newWriteHost()
	h.setCCS(ccsFolder, map[string][]byte{"www.example.test.pfx": pfx, "b.example.test.pfx": pfx})
	o, r, out := ccsDump(t, h, ccsInput(pw))
	if o.Exit != 0 || len(r.Files) != 2 || r.Files[0].Problem != "" || r.Files[1].Problem != "" {
		t.Fatalf("%+v %s", o, out)
	}
	if len(h.ccsPasswords) != 2 {
		t.Fatalf("%d", len(h.ccsPasswords))
	}
	for _, p := range h.ccsPasswords {
		if len(p) != len(pw) || !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatalf("the password buffer was not cleared: %d bytes", len(p))
		}
	}
}
