//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

// probeTimeout bounds the connection and the handshake of tls-probe (tests lower it).
var probeTimeout = 15 * time.Second

// cmdTLSProbe connects to a TLS endpoint on the server itself and reports the served leaf
// (spec §12.8 item 6, R38 item 6). It runs without sudo; it sends no application data and reads
// nothing but the handshake. The vector is fixed: exactly these four flags in this order.
func cmdTLSProbe(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 8 || args[0] != "--addr" || args[2] != "--port" || args[4] != "--sni" || args[6] != "--key-type" {
		return nil, refused(helperproto.CodeUsage, "usage: tls-probe --addr <ip> --port <port> --sni <name|_> --key-type <any|rsa|ecdsa>")
	}
	addr, port, sni, kt := args[1], args[3], args[5], args[7]
	if !helperproto.ValidIP(addr) || !helperproto.ValidPort(port) || (sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) ||
		(kt != helperproto.ProbeAny && kt != helperproto.ProbeRSA && kt != helperproto.ProbeECDSA) {
		return nil, refused(helperproto.CodeInvalidArgument, "an argument is not allowed")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := s.dial(ctx, "tcp", net.JoinHostPort(addr, port))
	if err != nil {
		return nil, failed(helperproto.CodeProbeFailed, "the endpoint cannot be reached")
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tc := tls.Client(conn, helperproto.ProbeTLSConfig(sni, kt))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, failed(helperproto.CodeProbeFailed, "the TLS handshake failed")
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, failed(helperproto.CodeProbeFailed, "the server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	return helperproto.TLSProbeResponse{OK: true, LeafSHA256: hexSHA(leaf.Raw), ChainLength: len(cs.PeerCertificates),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339)}, nil
}
