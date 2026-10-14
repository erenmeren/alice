package seed

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DiscoveryScope inserts a live discovery scope named name (one address entry, port 443) whose findings raise expiry
// alerts when alert is true.
func DiscoveryScope(ctx context.Context, pool *pgxpool.Pool, name string, alert bool) (uuid.UUID, error) {
	id := uuid.New()
	_, err := pool.Exec(ctx, `INSERT INTO discovery_scopes (id, name, entries, ports, alert_on_expiry, created_at, updated_at)
VALUES ($1, $2, '["10.0.0.0/24"]', '{443}', $3, now(), now())`, id, name, alert)
	return id, err
}

// DiscoveredCertificate inserts a discovered leaf certificate with fingerprint fp, CN cn and SANs, expiring at notAfter.
func DiscoveredCertificate(ctx context.Context, pool *pgxpool.Pool, fp, cn string, notAfter time.Time, sans ...string) error {
	if sans == nil {
		sans = []string{}
	}
	_, err := pool.Exec(ctx, `INSERT INTO discovery_certificates (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before,
    not_after, key_algorithm, self_signed, pem, first_seen, last_seen)
VALUES ($1, true, $2, $3, 'Seed CA', $4::timestamptz - interval '90 days', $4, 'ecdsa', false,
    '-----BEGIN CERTIFICATE-----' || chr(10) || 'AA==' || chr(10) || '-----END CERTIFICATE-----', now(), now())`, fp, cn, sans, notAfter)
	return err
}

// DiscoveredEndpoint inserts an endpoint of scope at address:port that presents fp. host is the scope's host name the
// address came from ("" for an address entry, also sent as SNI); state is "present", "gone" or "excluded".
func DiscoveredEndpoint(ctx context.Context, pool *pgxpool.Pool, scope uuid.UUID, address string, port int, host, fp, state string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := pool.Exec(ctx, `INSERT INTO discovery_endpoints (id, scope_id, address, port, sni, host, fingerprint_sha256, state,
    first_seen, last_seen, last_scanned_at, gone_since, last_error_code, tls_version, cipher)
VALUES ($1, $2, $3, $4, $5, $5, $6, $7, now(), now(), now(), CASE WHEN $7 = 'gone' THEN now() END,
    CASE WHEN $7 = 'excluded' THEN 'policy' ELSE '' END, 'TLS 1.3',
    'TLS_AES_128_GCM_SHA256')`,
		id, scope, address, port, host, fp, state)
	return id, err
}
