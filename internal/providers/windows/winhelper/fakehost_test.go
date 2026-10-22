package winhelper

import (
	"context"
	"net"
	"sync"
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

	// iis-dump readings
	certs        map[[2]string]winproto.StoreCertificate // by (store, sha1); absent means not found
	certErr      error
	certReads    map[[2]string]int
	expired      map[string]int
	appcmd       []byte
	appcmdErr    error
	appcmdCalls  atomic.Int32
	bindingsErr  error
	bindingBlock bool // SSLBindings blocks until ctx ends
	mu           sync.Mutex
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

func (f *fakeHost) SSLBindings(ctx context.Context) ([]winproto.SSLBinding, error) {
	f.calls.Add(1)
	if f.bindingBlock {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.bindings, f.bindingsErr
}

func (f *fakeHost) Certificate(_ context.Context, store, sha1 string) (winproto.StoreCertificate, bool, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.certReads == nil {
		f.certReads = map[[2]string]int{}
	}
	f.certReads[[2]string{store, sha1}]++
	if f.certErr != nil {
		return winproto.StoreCertificate{}, false, f.certErr
	}
	c, ok := f.certs[[2]string{store, sha1}]
	return c, ok, nil
}

func (f *fakeHost) ExpiredInStore(_ context.Context, store string) (int, error) {
	f.calls.Add(1)
	return f.expired[store], nil
}

func (f *fakeHost) AppcmdSites(context.Context) ([]byte, error) {
	f.calls.Add(1)
	f.appcmdCalls.Add(1)
	return f.appcmd, f.appcmdErr
}

func (f *fakeHost) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.calls.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
