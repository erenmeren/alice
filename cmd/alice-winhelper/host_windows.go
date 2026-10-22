//go:build windows

package main

import (
	"context"
	"errors"
	"net"

	"alice/internal/providers/windows/winhelper"
	"alice/internal/providers/windows/winproto"
)

var errNotImplemented = errors.New("alice-winhelper: the Windows host is not implemented yet")

// placeholderHost is the stand-in Host until the real Windows readings (tokens, http.sys, the
// certificate stores, appcmd) replace it.
type placeholderHost struct{}

func newHost() winhelper.Host { return placeholderHost{} }

func (placeholderHost) Elevated() (bool, error) { return false, nil }

func (placeholderHost) OSFacts(context.Context) (winhelper.OSFacts, error) {
	return winhelper.OSFacts{}, errNotImplemented
}

func (placeholderHost) IISFacts(context.Context) (winproto.IISFacts, error) {
	return winproto.IISFacts{}, errNotImplemented
}

func (placeholderHost) Stores(context.Context) ([]string, error) { return nil, errNotImplemented }

func (placeholderHost) SSLBindings(context.Context) ([]winproto.SSLBinding, error) {
	return nil, errNotImplemented
}

func (placeholderHost) Certificate(context.Context, string, string) (winproto.StoreCertificate, bool, error) {
	return winproto.StoreCertificate{}, false, errNotImplemented
}

func (placeholderHost) ExpiredInStore(context.Context, string) (int, error) {
	return 0, errNotImplemented
}

func (placeholderHost) AppcmdSites(context.Context) ([]byte, error) { return nil, errNotImplemented }

func (placeholderHost) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errNotImplemented
}
