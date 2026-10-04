package fakekv

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// The structs below are the single source of the answer shapes. Field names, nesting and types follow
// the Key Vault REST reference for api-version 2025-07-01:
//   - CertificateListResult / CertificateItem:
//     https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates?view=rest-keyvault-certificates-2025-07-01
//   - CertificateBundle and CertificatePolicy:
//     https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate?view=rest-keyvault-certificates-2025-07-01
//   - import: https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/import-certificate/import-certificate?view=rest-keyvault-certificates-2025-07-01
//   - SecretBundle: https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01
//   - KeyListResult / KeyItem: https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-2025-07-01
//   - KeyBundle (public JWK): https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key?view=rest-keyvault-keys-2025-07-01
//   - KeyVaultError: https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes
//
// shapes_test.go compares every answer's key structure with test/testdata/kv-recordings.

type attributes struct {
	Enabled         bool   `json:"enabled"`
	Nbf             *int64 `json:"nbf,omitempty"`
	Exp             *int64 `json:"exp,omitempty"`
	Created         int64  `json:"created"`
	Updated         int64  `json:"updated"`
	RecoverableDays int    `json:"recoverableDays"`
	RecoveryLevel   string `json:"recoveryLevel"`
}

type policyAttributes struct {
	Enabled bool  `json:"enabled"`
	Created int64 `json:"created"`
	Updated int64 `json:"updated"`
}

type certItem struct {
	ID         string         `json:"id"`
	X5t        string         `json:"x5t"`
	Attributes attributes     `json:"attributes"`
	Tags       map[string]any `json:"tags"`
}

type listResult[T any] struct {
	Value    []T     `json:"value"`
	NextLink *string `json:"nextLink"`
}

type keyProps struct {
	Exportable bool   `json:"exportable"`
	Kty        string `json:"kty"`
	KeySize    int    `json:"key_size"`
	Crv        string `json:"crv,omitempty"`
	ReuseKey   bool   `json:"reuse_key"`
}

type secretProps struct {
	ContentType string `json:"contentType"`
}

type sans struct {
	DNSNames []string `json:"dns_names,omitempty"`
}

type x509Props struct {
	Subject        string   `json:"subject"`
	Ekus           []string `json:"ekus"`
	KeyUsage       []string `json:"key_usage"`
	ValidityMonths int      `json:"validity_months"`
	Sans           *sans    `json:"sans,omitempty"`
}

type lifetimeAction struct {
	Trigger struct {
		LifetimePercentage int `json:"lifetime_percentage"`
	} `json:"trigger"`
	Action struct {
		ActionType string `json:"action_type"`
	} `json:"action"`
}

type issuerParams struct {
	Name string `json:"name"`
}

type certPolicy struct {
	ID              string           `json:"id"`
	KeyProps        keyProps         `json:"key_props"`
	SecretProps     secretProps      `json:"secret_props"`
	X509Props       x509Props        `json:"x509_props"`
	LifetimeActions []lifetimeAction `json:"lifetime_actions"`
	Issuer          issuerParams     `json:"issuer"`
	Attributes      policyAttributes `json:"attributes"`
}

type certBundle struct {
	ID         string         `json:"id"`
	Kid        string         `json:"kid"`
	Sid        string         `json:"sid"`
	X5t        string         `json:"x5t"`
	Cer        string         `json:"cer"`
	Attributes attributes     `json:"attributes"`
	Policy     certPolicy     `json:"policy"`
	Tags       map[string]any `json:"tags"`
}

type secretItem struct {
	ID          string         `json:"id"`
	ContentType string         `json:"contentType,omitempty"`
	Attributes  attributes     `json:"attributes"`
	Tags        map[string]any `json:"tags"`
	Managed     bool           `json:"managed"`
}

type secretBundle struct {
	Value       string         `json:"value"`
	ContentType string         `json:"contentType,omitempty"`
	ID          string         `json:"id"`
	Kid         string         `json:"kid,omitempty"`
	Managed     bool           `json:"managed"`
	Attributes  attributes     `json:"attributes"`
	Tags        map[string]any `json:"tags"`
}

type keyItem struct {
	Kid        string         `json:"kid"`
	Attributes attributes     `json:"attributes"`
	Tags       map[string]any `json:"tags"`
	Managed    bool           `json:"managed"`
}

type jwk struct {
	Kid    string   `json:"kid"`
	Kty    string   `json:"kty"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
}

type keyBundle struct {
	Key        jwk            `json:"key"`
	Attributes attributes     `json:"attributes"`
	Tags       map[string]any `json:"tags"`
	Managed    bool           `json:"managed,omitempty"`
}

type kvErrorBody struct {
	Error kvError `json:"error"`
}

type kvError struct {
	Code       string   `json:"code"`
	Message    string   `json:"message"`
	InnerError *kvInner `json:"innererror,omitempty"`
}

type kvInner struct {
	Code string `json:"code"`
}

func unix(t time.Time) int64 { return t.Unix() }

func unixPtr(t time.Time) *int64 { v := t.Unix(); return &v }

// writeJSON writes v with the headers every Key Vault answer carries. The body is marshalled first
// so Content-Length is exact (fault injection relies on it).
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "fakekv: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeBytes(w, status, b)
}

func writeBytes(w http.ResponseWriter, status int, b []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("x-ms-request-id", uuid.NewString())
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// kvFail writes a KeyVaultError. inner may be "".
func kvFail(w http.ResponseWriter, status int, code, inner, message string) {
	e := kvError{Code: code, Message: message}
	if inner != "" {
		e.InnerError = &kvInner{Code: inner}
	}
	writeJSON(w, status, kvErrorBody{Error: e})
}
