//go:build integration

package revocation

import (
	"context"
	"net"

	"alice/internal/platform/clock"
)

// NewWithDial is a checker whose connections dial (integration tests only: the inventory's tests reach the fake
// responder on 127.0.0.1, which the production guard refuses). It is not compiled into Alice.
func NewWithDial(clk clock.Clock, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Checker {
	return newChecker(clk, dial)
}
