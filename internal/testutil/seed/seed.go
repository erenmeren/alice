// Package seed inserts inventory rows for tests, the performance test and the e2e build's seed endpoint (Phase 7). It
// writes plain rows as the owner role; it is never linked into a release binary (only _test files, the perf test and
// the e2e-tagged seed endpoint import it). Every server shares the one platform key (credentials_one_platform_key).
package seed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Hex is a stable 64-hex value derived from s.
func Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Target inserts a live target of type typ ("linux", "nginx" or "azure_key_vault") with status. Servers share the one
// platform credential, created on first use; a vault gets a credential of its own, which carries secret_expires_on
// when secretExpires is set.
func Target(ctx context.Context, pool *pgxpool.Pool, name, typ, status string, secretExpires *time.Time) (uuid.UUID, error) {
	id := uuid.New()
	config := map[string]any{"host": name + ".example.test", "port": 22, "username": "alice-svc"}
	info := map[string]any{}
	if typ == "azure_key_vault" {
		info = map[string]any{"auth": "client_secret", "tenant_id": uuid.NewString(), "client_id": uuid.NewString()}
		if secretExpires != nil {
			info["secret_expires_on"] = secretExpires.UTC().Format(time.RFC3339)
		}
		config = map[string]any{"vault_url": "https://" + name + ".vault.azure.net", "host": name + ".vault.azure.net", "port": 443}
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return uuid.Nil, err
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	cred := uuid.New()
	if typ == "azure_key_vault" {
		if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version,
created_at, target_id) VALUES ($1, 'azure_vault', 'azure_sp_secret', $2, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), $3)`,
			cred, infoJSON, id); err != nil {
			return uuid.Nil, err
		}
	} else if err := tx.QueryRow(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', '{}', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())
ON CONFLICT (purpose) WHERE purpose = 'platform_ssh' DO UPDATE SET purpose = EXCLUDED.purpose RETURNING id`, cred).Scan(&cred); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, now(), now())`, id, name, typ, configJSON, cred, status); err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

// Certificate inserts an uploaded certificate with CN cn expiring at notAfter and, on each target, one live location
// whose server block names websites. A certificate on no target is in inventory but not monitored.
func Certificate(ctx context.Context, pool *pgxpool.Pool, cn string, notAfter time.Time, targets []uuid.UUID, websites ...string) (uuid.UUID, error) {
	id := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, $3, $4::timestamptz - interval '90 days', $4::timestamptz, 'ecdsa', $5, '', 'uploaded', now(), now(), now())`,
		id, Hex(id.String()), cn, notAfter, Hex("pk"+id.String())); err != nil {
		return uuid.Nil, err
	}
	if websites == nil {
		websites = []string{}
	}
	servers, err := json.Marshal([]map[string]any{{"names": websites, "listens": []any{}, "file": "/etc/nginx/conf.d/site.conf", "line": 1}})
	if err != nil {
		return uuid.Nil, err
	}
	for _, tg := range targets {
		if _, err := pool.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported,
servers, first_seen_at, last_seen_at) VALUES ($1, $2, 'nginx_file', $3, $4, $5, true, $6, now(), now())`,
			uuid.New(), tg, "/etc/nginx/ssl/"+id.String()+".crt", "/etc/nginx/ssl/"+id.String()+".key", id, servers); err != nil {
			return uuid.Nil, err
		}
	}
	return id, nil
}

// MoveLocations points every location of from at to (a renewal was deployed).
func MoveLocations(ctx context.Context, pool *pgxpool.Pool, from, to uuid.UUID) error {
	_, err := pool.Exec(ctx, `UPDATE certificate_locations SET certificate_id = $2 WHERE certificate_id = $1`, from, to)
	return err
}

// KeyVault inserts a Key Vault certificate (its current version linked to linkCert, which may be nil) and a key.
func KeyVault(ctx context.Context, pool *pgxpool.Pool, vault uuid.UUID, certName string, certExpires time.Time, linkCert *uuid.UUID,
	keyName string, keyExpires time.Time) (kvCert, kvKey uuid.UUID, err error) {
	kvCert, kvKey = uuid.New(), uuid.New()
	version := Hex(kvCert.String())[:32]
	if _, err = pool.Exec(ctx, `INSERT INTO kv_certificates (id, target_id, name, current_version, current_thumbprint,
listed_thumbprint, enabled, key_type, content_type, expires, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, repeat('b', 40), repeat('b', 40), true, 'rsa', 'pkcs12', $5, now(), now())`,
		kvCert, vault, certName, version, certExpires); err != nil {
		return
	}
	if _, err = pool.Exec(ctx, `INSERT INTO kv_certificate_versions (id, kv_certificate_id, version, thumbprint, enabled, key_type,
content_type, detected_at, certificate_id) VALUES ($1, $2, $3, repeat('b', 40), true, 'rsa', 'pkcs12', now(), $4)`,
		uuid.New(), kvCert, version, linkCert); err != nil {
		return
	}
	_, err = pool.Exec(ctx, `INSERT INTO kv_keys (id, target_id, name, enabled, expires, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, true, $4, now(), now())`, kvKey, vault, keyName, keyExpires)
	return
}
