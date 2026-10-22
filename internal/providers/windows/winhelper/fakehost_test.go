package winhelper

import (
	"context"
	"net"
	"sync/atomic"

	"alice/internal/providers/windows/winproto"
)

// fakeHost is a Host with settable readings and error injection; calls counts every reading.
type fakeHost struct {
	elevated    bool
	elevatedErr error
	os          OSFacts
	osErr       error
	iis         winproto.IISFacts
	iisErr      error
	stores      []string
	storesErr   error
	bindings    []winproto.SSLBinding
	block       bool // OSFacts blocks until ctx ends and then returns ctx.Err()
	dialErr     error
	calls       atomic.Int32
}

func (f *fakeHost) Elevated() (bool, error) { f.calls.Add(1); return f.elevated, f.elevatedErr }

func (f *fakeHost) OSFacts(ctx context.Context) (OSFacts, error) {
	f.calls.Add(1)
	if f.block {
		<-ctx.Done()
		return OSFacts{}, ctx.Err()
	}
	return f.os, f.osErr
}

func (f *fakeHost) IISFacts(context.Context) (winproto.IISFacts, error) {
	f.calls.Add(1)
	return f.iis, f.iisErr
}

func (f *fakeHost) Stores(context.Context) ([]string, error) {
	f.calls.Add(1)
	return f.stores, f.storesErr
}

func (f *fakeHost) SSLBindings(context.Context) ([]winproto.SSLBinding, error) {
	f.calls.Add(1)
	return f.bindings, nil
}

func (f *fakeHost) Certificate(context.Context, string, string) (winproto.StoreCertificate, bool, error) {
	f.calls.Add(1)
	return winproto.StoreCertificate{}, false, nil
}

func (f *fakeHost) ExpiredInStore(context.Context, string) (int, error) {
	f.calls.Add(1)
	return 0, nil
}

func (f *fakeHost) AppcmdSites(context.Context) ([]byte, error) { f.calls.Add(1); return nil, nil }

func (f *fakeHost) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.calls.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
