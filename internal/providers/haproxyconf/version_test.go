package haproxyconf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseV(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"ubuntu 22.04": {"HAProxy version 2.4.30-0ubuntu0.22.04.2 2026/06/19 - https://haproxy.org/\nStatus: long-term supported branch - will stop receiving fixes around Q2 2026.\n",
			"2.4.30-0ubuntu0.22.04.2"},
		"rocky 9":           {"HAProxy version 2.8.14-c23fe91 2025/01/29 - https://haproxy.org/\nStatus: long-term supported branch\n", "2.8.14-c23fe91"},
		"old spelling":      {"HA-Proxy version 1.8.30 2021/04/02\n", "1.8.30"},
		"plus":              {"HAProxy version 2.6.12-1+deb12u3 2025/01/01 - x\n", "2.6.12-1+deb12u3"},
		"40 characters":     {"HAProxy version " + strings.Repeat("1", 40) + " x\n", strings.Repeat("1", 40)},
		"not the first":     {"Something\nHAProxy version 2.4.30 2026/06/19\n", ""},
		"no such line":      {"nginx version: nginx/1.22.1\n", ""},
		"empty":             {"", ""},
		"41 characters":     {"HAProxy version " + strings.Repeat("1", 41) + " x\n", ""},
		"slash":             {"HAProxy version 2.4/30 2026/06/19\n", ""},
		"underscore":        {"HAProxy version 2.4_30 2026/06/19\n", ""},
		"cr in the line":    {"HAProxy version 2.4.30 2026/06/19\r\n", ""},
		"cr later":          {"HAProxy version 2.4.30 2026/06/19\nStatus\r\n", ""},
		"no space after":    {"HAProxy version 2.4.30\n", ""},
		"no space at eof":   {"HAProxy version 2.4.30", ""},
		"empty version":     {"HAProxy version  2026/06/19\n", ""},
		"case":              {"haproxy version 2.4.30 x\n", ""},
		"leading blank":     {" HAProxy version 2.4.30 x\n", ""},
		"tab after version": {"HAProxy version 2.4.30\tx\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseV([]byte(tc.in)))
		})
	}
	t.Run("too large", func(t *testing.T) {
		in := append([]byte("HAProxy version 2.4.30 x\n"), make([]byte, MaxInput)...)
		assert.Equal(t, "", ParseV(in))
	})
}

func TestMinorAtLeast(t *testing.T) {
	for name, tc := range map[string]struct {
		v            string
		major, minor int
		yes, known   bool
	}{
		"2.4 below 2.6":   {"2.4.30-0ubuntu0.22.04.2", 2, 6, false, true},
		"2.6 at 2.6":      {"2.6.12-1+deb12u3", 2, 6, true, true},
		"2.8 above 2.6":   {"2.8.14", 2, 6, true, true},
		"10.0 above 2.6":  {"10.0", 2, 6, true, true},
		"1.9 below 2.6":   {"1.9.0", 2, 6, false, true},
		"2.10 above 2.6":  {"2.10.0", 2, 6, true, true},
		"2.5-dev below":   {"2.5-dev1", 2, 6, false, true},
		"x":               {"x", 2, 6, false, false},
		"empty":           {"", 2, 6, false, false},
		"major only":      {"2", 2, 6, false, false},
		"no minor":        {"2.", 2, 6, false, false},
		"no major":        {".6", 2, 6, false, false},
		"letter minor":    {"2.x", 2, 6, false, false},
		"huge major":      {"12345678901.0", 2, 6, false, false},
		"huge minor":      {"2.12345678901", 2, 6, false, false},
		"minor then text": {"2.6x", 2, 6, true, true},
	} {
		t.Run(name, func(t *testing.T) {
			yes, known := minorAtLeast(tc.v, tc.major, tc.minor)
			assert.Equal(t, tc.yes, yes, "yes")
			assert.Equal(t, tc.known, known, "known")
		})
	}
}
