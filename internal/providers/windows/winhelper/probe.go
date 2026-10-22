package winhelper

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/windows/winproto"
)

// probeTimeout bounds the connection and the handshake of tls-probe (tests lower it).
var probeTimeout = 15 * time.Second

// cmdTLSProbe connects to a TLS endpoint on the server itself and reports the served leaf and the chain
// presented (Alice checks its trust; the helper judges nothing). It sends no application data. The vector
// is fixed, as on Linux: exactly these four flags in this order.
func cmdTLSProbe(ctx context.Context, h Host, args []string) (any, error) {
	if len(args) != 8 || args[0] != "--addr" || args[2] != "--port" || args[4] != "--sni" || args[6] != "--key-type" {
		return nil, refused(winproto.CodeUsage, "usage: tls-probe --addr <ip> --port <port> --sni <name|_> --key-type <any|rsa|ecdsa>")
	}
	addr, port, sni, kt := args[1], args[3], args[5], args[7]
	if !helperproto.ValidIP(addr) || !helperproto.ValidPort(port) || (sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) ||
		(kt != helperproto.ProbeAny && kt != helperproto.ProbeRSA && kt != helperproto.ProbeECDSA) {
		return nil, refused(winproto.CodeInvalidArgument, "an argument is not allowed")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := h.Dial(ctx, "tcp", net.JoinHostPort(addr, port))
	if err != nil {
		return nil, failed(winproto.CodeProbeFailed, "the endpoint cannot be reached")
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tc := tls.Client(conn, helperproto.ProbeTLSConfig(sni, kt))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, failed(winproto.CodeProbeFailed, "the TLS handshake failed")
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, failed(winproto.CodeProbeFailed, "the server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	ders := make([][]byte, 0, len(cs.PeerCertificates))
	for _, c := range cs.PeerCertificates {
		ders = append(ders, c.Raw)
	}
	sum := sha256.Sum256(leaf.Raw)
	return winproto.TLSProbeResponse{OK: true, LeafSHA256: hex.EncodeToString(sum[:]), ChainLength: len(cs.PeerCertificates),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339), Chain: helperproto.ProbeChain(ders)}, nil
}
