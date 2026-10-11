package api

import (
	"net"
	"net/http"

	"alice/internal/license"
	"alice/internal/platform/tlscert"
	"alice/internal/rbac"
)

// httpsRoutes are Alice's own HTTPS certificate (C12, Phase 8): what the listener serves, and an upload that is
// applied without a restart. settings.manage; the upload is rate limited like a download (it parses PFX files).
func (s *server) httpsRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/settings/https", perm: rbac.SettingsManage, handler: s.getHTTPS},
		{method: http.MethodPut, pattern: "/api/v1/settings/https", perm: rbac.SettingsManage, limit: limitHTTPSUpload, lic: license.ClassAlways,
			handler: s.putHTTPS},
	}
}

// maxHTTPSBody caps the upload: a 1 MiB PFX file in base64, or a PEM chain and key of 1 MiB each, JSON-escaped.
const maxHTTPSBody = 2 << 20

func (s *server) getHTTPS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, httpsInfoJSON(s.deps.TLSStore.Info()))
}

// httpsBody is the upload: the certificate (chain) and its key as PEM, or a PFX file in base64 with its password. The
// key, the PFX and its password are secretText the handler clears; none of them reaches an answer, a log or an
// audit row.
type httpsBody struct {
	CertPEM     string     `json:"cert_pem"`
	KeyPEM      secretText `json:"key_pem"`
	PFXBase64   secretText `json:"pfx_base64"`
	PFXPassword secretText `json:"pfx_password"`
}

func (b *httpsBody) zero() {
	b.KeyPEM.zero()
	b.PFXBase64.zero()
	b.PFXPassword.zero()
}

// putHTTPS installs an uploaded certificate (tlscert.Store.Install through Deps.TLSStore, which then records the
// wizard's choice and https.certificate_replaced). The next TLS handshake presents it. The request host is passed
// as a name the certificate should cover (warning name_mismatch otherwise).
func (s *server) putHTTPS(w http.ResponseWriter, r *http.Request) {
	var req httpsBody
	defer req.zero()
	if !s.decodeExact(w, r, &req, maxHTTPSBody, "cert_pem", "key_pem", "pfx_base64", "pfx_password") {
		return
	}
	u := tlscert.Upload{CertPEM: []byte(req.CertPEM), KeyPEM: req.KeyPEM, PFXPassword: req.PFXPassword, Hosts: requestHost(r)}
	if len(req.PFXBase64) > 0 {
		pfx, ok := decodeBase64Secret(req.PFXBase64)
		if !ok {
			s.writeError(w, r, ErrTLSUnreadable)
			return
		}
		defer clear(pfx)
		u.PFX = pfx
	}
	info, err := s.deps.TLSStore.Install(r.Context(), principalFrom(r.Context()), s.meta(r), u)
	req.zero()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, httpsInfoJSON(info))
}

// requestHost is the host name the browser used (without a port), as a name the certificate should cover.
func requestHost(r *http.Request) []string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return nil
	}
	return []string{host}
}
