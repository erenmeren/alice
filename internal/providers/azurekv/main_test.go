package azurekv

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
)

// bypassed counts the requests that reached http.DefaultTransport. Everything this provider sends
// goes through its own guarded transports, so any request here is a bypass of the guard (an SDK
// that builds a bare http.Client, a proxy-honouring default): the whole test binary fails.
var bypassed atomic.Int32

type failingDefault struct{}

func (failingDefault) RoundTrip(r *http.Request) (*http.Response, error) {
	bypassed.Add(1)
	fmt.Fprintf(os.Stderr, "azurekv test: a request bypassed the guarded transports: %s %s\n", r.Method, r.URL.Host)
	return nil, errors.New("request bypassed the guarded transports")
}

func TestMain(m *testing.M) {
	orig := http.DefaultTransport
	http.DefaultTransport = failingDefault{}
	code := m.Run()
	http.DefaultTransport = orig
	if bypassed.Load() > 0 && code == 0 {
		code = 1
	}
	os.Exit(code)
}
