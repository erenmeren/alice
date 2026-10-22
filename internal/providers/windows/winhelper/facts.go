package winhelper

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/providers/windows/winproto"
)

// maxStores bounds the store names win-facts lists.
const maxStores = 64

// cleanValue makes remote text safe to store and show: invalid UTF-8 and control and format
// characters (terminal escapes, bidi marks) dropped, length limited in runes (the rule of linuxssh's
// cleanValue, SC-4).
func cleanValue(v string, limit int) string {
	v = strings.TrimSpace(strings.ToValidUTF8(v, ""))
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, v)
	if utf8.RuneCountInString(v) > limit {
		v = string([]rune(v)[:limit])
	}
	return v
}

func cmdWinFacts(ctx context.Context, h Host, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(winproto.CodeUsage, "win-facts takes no arguments")
	}
	el, err := h.Elevated()
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the token could not be read")
	}
	osf, err := h.OSFacts(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the operating system could not be read")
	}
	iis, err := h.IISFacts(ctx)
	switch {
	case err == nil:
		iis = winproto.IISFacts{Installed: iis.Installed, Version: cleanValue(iis.Version, winproto.MaxText),
			SharedConfig: iis.SharedConfig, CCSEnabled: iis.CCSEnabled, CCSPath: cleanValue(iis.CCSPath, winproto.MaxText),
			AutoCertRebind: iis.AutoCertRebind}
	case errors.Is(err, ErrIISNotInstalled):
		iis = winproto.IISFacts{}
	default:
		return nil, failed(winproto.CodeIOError, "IIS could not be read")
	}
	stores, err := h.Stores(ctx)
	if err != nil {
		return nil, failed(winproto.CodeIOError, "the certificate stores could not be listed")
	}
	names := make([]string, 0, len(stores))
	for _, s := range stores {
		if len(names) == maxStores {
			break
		}
		if s = cleanValue(s, winproto.MaxText); s != "" {
			names = append(names, s)
		}
	}
	return winproto.WinFactsResponse{OK: true,
		OSBuild: cleanValue(osf.Build, winproto.MaxText), OSProduct: cleanValue(osf.Product, winproto.MaxText),
		InstallationType: cleanValue(osf.InstallationType, winproto.MaxText), Elevated: el, IIS: iis, Stores: names,
		OpenSSHVersion: cleanValue(osf.OpenSSHVersion, winproto.MaxText)}, nil
}
