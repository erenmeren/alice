//go:build windows

package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// PeerCert is one certificate the server sent.
type PeerCert struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Thumbprint string `json:"thumbprint"`
	IsCA       bool   `json:"is_ca"`
	SelfSigned bool   `json:"self_signed"`
}

// Probe is one fresh TLS handshake (no session cache, no tickets), as §6.4 wants.
type Probe struct {
	Addr       string     `json:"addr"`
	SNI        string     `json:"sni"`
	OK         bool       `json:"ok"`
	Error      string     `json:"error,omitempty"`
	Attempts   int        `json:"attempts"`
	Version    string     `json:"version,omitempty"`
	Leaf       string     `json:"leaf_thumbprint,omitempty"`
	ChainLen   int        `json:"chain_len"`
	Chain      []PeerCert `json:"chain,omitempty"`
	HTTPStatus string     `json:"http_status,omitempty"`
}

func probeOnce(addr, sni string) Probe {
	p := Probe{Addr: addr, SNI: sni}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", addr, &tls.Config{
		InsecureSkipVerify:     true, //nolint:gosec // the spike records what is served, it does not trust it
		ServerName:             sni,
		SessionTicketsDisabled: true,
	})
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer conn.Close()
	st := conn.ConnectionState()
	p.OK = true
	p.Version = tls.VersionName(st.Version)
	p.ChainLen = len(st.PeerCertificates)
	for _, c := range st.PeerCertificates {
		p.Chain = append(p.Chain, PeerCert{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName,
			Thumbprint: thumbOf(c.Raw), IsCA: c.IsCA, SelfSigned: c.Subject.String() == c.Issuer.String()})
	}
	if len(st.PeerCertificates) > 0 {
		p.Leaf = thumbOf(st.PeerCertificates[0].Raw)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		p.HTTPStatus = strings.TrimSpace(line)
	}
	return p
}

// probe retries a failed handshake a few times (the "short retry" of §6.4).
func probe(addr, sni string) Probe {
	var p Probe
	for i := 1; i <= 3; i++ {
		p = probeOnce(addr, sni)
		p.Attempts = i
		if p.OK {
			return p
		}
		time.Sleep(500 * time.Millisecond)
	}
	return p
}

func parseCert(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }

// issued is a certificate and its key, generated in memory.
type issued struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

func (i issued) pkcs8() []byte {
	b, err := x509.MarshalPKCS8PrivateKey(i.key)
	if err != nil {
		panic(err)
	}
	return b
}

// issue makes a certificate: self-signed when parent is nil; a CA when ca is set; RSA 2048 unless ec.
func issue(cn string, dns []string, ca, ec bool, parent *issued) issued {
	var key crypto.Signer
	var err error
	if ec {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		panic(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Alice W0 spike"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              dns,
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return issued{cert: c, der: der, key: key}
}
