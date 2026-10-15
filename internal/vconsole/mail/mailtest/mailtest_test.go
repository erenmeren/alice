package mailtest

import (
	"context"
	"net"
	"testing"
	"time"
)

// Close returns even with a silent session open and with connections racing the close.
func TestCloseDoesNotHang(t *testing.T) {
	s := Start(t, Options{Silent: true})
	var d net.Dialer
	stopDial := make(chan struct{})
	dialed := make(chan struct{})
	go func() {
		defer close(dialed)
		for {
			select {
			case <-stopDial:
				return
			default:
			}
			c, err := d.DialContext(context.Background(), "tcp", s.Addr())
			if err != nil {
				return // listener closed
			}
			defer func() { _ = c.Close() }()
		}
	}()
	time.Sleep(20 * time.Millisecond)
	done := make(chan struct{})
	go func() { s.Close(); s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	close(stopDial)
	<-dialed
}
