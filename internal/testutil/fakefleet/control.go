package fakefleet

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"
)

// ControlHandler is the fleet's control API (cmd/alice-fakefleet serves it on loopback only):
//
//	GET  /ping        {"ok":true}
//	GET  /fleet       Info: every server's kind, address, name and default chain fingerprints
//	GET  /ca          the root certificate (PEM)
//	GET  /log         the access log ([]Access); ?settle=1 waits for WaitIdle first (at most 10 s)
//	POST /log/clear   ClearLog
//	GET  /counters    Counters
//	GET  /valid-pair  {"certificate_pem","private_key_pem"}: the valid server's chain (leaf first) and the leaf's key,
//	                  so a journey can store exactly the certificate the fleet presents (404 without that server)
func (f *Fleet) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]bool{"ok": true}) })
	mux.HandleFunc("GET /fleet", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, f.Info()) })
	mux.HandleFunc("GET /ca", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(f.RootPEM())
	})
	mux.HandleFunc("GET /log", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("settle") == "1" {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			err := f.WaitIdle(ctx)
			cancel()
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				writeJSON(w, map[string]string{"error": "the fleet did not settle: " + err.Error()})
				return
			}
		}
		writeJSON(w, f.Log())
	})
	mux.HandleFunc("POST /log/clear", func(w http.ResponseWriter, _ *http.Request) {
		f.ClearLog()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /counters", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, f.Counters()) })
	mux.HandleFunc("GET /valid-pair", func(w http.ResponseWriter, _ *http.Request) {
		certPEM, keyPEM, err := f.validPair()
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]string{"certificate_pem": string(certPEM), "private_key_pem": string(keyPEM)})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// errNoValidServer: the fleet does not serve the valid kind.
var errNoValidServer = errors.New("fakefleet: this fleet does not serve the valid kind")

// validPair is the valid server's default chain (PEM, leaf first) and the leaf's private key (PKCS#8 PEM). The fleet's
// keys are generated when it starts and die with it; they protect nothing.
func (f *Fleet) validPair() (certPEM, keyPEM []byte, err error) {
	s := f.byKind[KindValid]
	if s == nil || s.material.cert == nil {
		return nil, nil, errNoValidServer
	}
	der, err := x509.MarshalPKCS8PrivateKey(s.material.cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range s.material.chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
