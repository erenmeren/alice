package alerts

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const maxListed = 10

// itemsSQL is the one definition of "monitored" (R42 row 4): a certificate is monitored while a live location of a live
// target holds it; a Key Vault certificate whose current version is such a certificate is covered by that
// certificate's notice; keys and the vault's client secret are monitored while their vault is.
const itemsSQL = `
WITH live AS (
    SELECT l.certificate_id, l.servers, t.id AS target_id, t.name::text AS target_name
    FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
    WHERE l.missing_since IS NULL AND l.certificate_id IS NOT NULL
)
SELECT 'certificate_expiry'::text AS kind, c.id AS object_id,
       coalesce(nullif(c.subject_cn, ''), nullif(c.label, ''), left(c.fingerprint_sha256, 16)) AS name, c.not_after AS expires,
       c.fingerprint_sha256 AS fingerprint,
       array(SELECT DISTINCT n FROM live x, jsonb_array_elements(x.servers) s, jsonb_array_elements_text(s->'names') n
             WHERE x.certificate_id = c.id ORDER BY n LIMIT 11)::text[] AS websites,
       array(SELECT DISTINCT x.target_name FROM live x WHERE x.certificate_id = c.id ORDER BY 1 LIMIT 11)::text[] AS servers,
       array(SELECT DISTINCT x.target_id FROM live x WHERE x.certificate_id = c.id)::text[] AS target_ids,
       ''::text AS vault, NULL::uuid AS vault_id
FROM certificates c
WHERE 'certificate_expiry' = ANY ($1::text[]) AND c.not_after < $2::timestamptz
  AND EXISTS (SELECT 1 FROM live x WHERE x.certificate_id = c.id)
UNION ALL
SELECT 'kv_certificate_expiry', kc.id, kc.name, kc.expires, '', '{}'::text[], '{}'::text[], '{}'::text[], t.name::text, t.id
FROM kv_certificates kc JOIN targets t ON t.id = kc.target_id AND t.deleted_at IS NULL
WHERE 'kv_certificate_expiry' = ANY ($1::text[]) AND kc.missing_since IS NULL AND kc.enabled AND kc.expires IS NOT NULL
  AND kc.expires < $2::timestamptz
  AND NOT EXISTS (SELECT 1 FROM kv_certificate_versions v JOIN live x ON x.certificate_id = v.certificate_id
                  WHERE v.kv_certificate_id = kc.id AND v.version = kc.current_version)
UNION ALL
SELECT 'kv_key_expiry', k.id, k.name, k.expires, '', '{}'::text[], '{}'::text[], '{}'::text[], t.name::text, t.id
FROM kv_keys k JOIN targets t ON t.id = k.target_id AND t.deleted_at IS NULL
WHERE 'kv_key_expiry' = ANY ($1::text[]) AND k.missing_since IS NULL AND k.enabled AND k.expires IS NOT NULL
  AND k.expires < $2::timestamptz
UNION ALL
SELECT 'kv_credential_expiry', t.id, t.name::text, (cr.public_info->>'secret_expires_on')::timestamptz, '', '{}'::text[],
       '{}'::text[], '{}'::text[], t.name::text, t.id
FROM targets t JOIN credentials cr ON cr.id = t.credential_id
WHERE 'kv_credential_expiry' = ANY ($1::text[]) AND t.type = 'azure_key_vault' AND t.deleted_at IS NULL
  AND cr.public_info ? 'secret_expires_on' AND (cr.public_info->>'secret_expires_on')::timestamptz < $2::timestamptz
ORDER BY 4, 2
LIMIT NULLIF($3::int, 0)`

// Items lists the monitored items of kinds that expire before until, soonest first, expired ones included. limit 0
// is no limit.
func (s *Service) Items(ctx context.Context, kinds []Kind, until time.Time, limit int) ([]Item, error) {
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	rows, err := s.pool.Query(ctx, itemsSQL, names, until.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("alerts: read the monitored items: %w", err)
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var (
			it       Item
			kind     string
			targets  []string
			vaultID  *uuid.UUID
			websites []string
			servers  []string
		)
		if err := rows.Scan(&kind, &it.ObjectID, &it.Name, &it.ExpiresAt, &it.Fingerprint, &websites, &servers, &targets,
			&it.Vault, &vaultID); err != nil {
			return nil, fmt.Errorf("alerts: read the monitored items: %w", err)
		}
		it.Kind, it.ExpiresAt = Kind(kind), it.ExpiresAt.UTC()
		it.Websites, it.moreWebsites = capList(websites)
		it.Servers, it.moreServers = capList(servers)
		for _, t := range targets {
			id, err := uuid.Parse(t)
			if err != nil {
				return nil, fmt.Errorf("alerts: read the monitored items: %w", err)
			}
			it.TargetIDs = append(it.TargetIDs, id)
		}
		if vaultID != nil {
			it.VaultID = *vaultID
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alerts: read the monitored items: %w", err)
	}
	return out, nil
}

func capList(in []string) ([]string, bool) {
	if len(in) > maxListed {
		return in[:maxListed], true
	}
	return in, false
}

const countsSQL = `
WITH live AS (
    SELECT l.certificate_id FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
    WHERE l.missing_since IS NULL AND l.certificate_id IS NOT NULL
),
mon AS (SELECT c.not_after FROM certificates c WHERE EXISTS (SELECT 1 FROM live x WHERE x.certificate_id = c.id)),
kv AS (
    SELECT kc.expires FROM kv_certificates kc JOIN targets t ON t.id = kc.target_id AND t.deleted_at IS NULL
    WHERE kc.missing_since IS NULL AND kc.enabled AND kc.expires IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM kv_certificate_versions v JOIN live x ON x.certificate_id = v.certificate_id
                      WHERE v.kv_certificate_id = kc.id AND v.version = kc.current_version)
    UNION ALL
    SELECT k.expires FROM kv_keys k JOIN targets t ON t.id = k.target_id AND t.deleted_at IS NULL
    WHERE k.missing_since IS NULL AND k.enabled AND k.expires IS NOT NULL
    UNION ALL
    SELECT (cr.public_info->>'secret_expires_on')::timestamptz FROM targets t JOIN credentials cr ON cr.id = t.credential_id
    WHERE t.type = 'azure_key_vault' AND t.deleted_at IS NULL AND cr.public_info ? 'secret_expires_on'
)
SELECT (SELECT count(*) FROM mon),
       (SELECT count(*) FROM mon WHERE not_after <= $1::timestamptz),
       (SELECT count(*) FROM mon WHERE not_after > $1::timestamptz AND not_after <= $1::timestamptz + interval '7 days'),
       (SELECT count(*) FROM mon WHERE not_after > $1::timestamptz + interval '7 days' AND not_after <= $1::timestamptz + interval '30 days'),
       (SELECT count(*) FROM mon WHERE not_after > $1::timestamptz + interval '30 days' AND not_after <= $1::timestamptz + interval '60 days'),
       (SELECT count(*) FROM kv WHERE expires <= $1::timestamptz),
       (SELECT count(*) FROM kv WHERE expires > $1::timestamptz AND expires <= $1::timestamptz + interval '30 days')`

// Counts are the dashboard's numbers, computed from the same definition of "monitored".
func (s *Service) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	err := s.pool.QueryRow(ctx, countsSQL, s.clock.Now().UTC()).Scan(&c.Monitored, &c.Expired, &c.Within7, &c.Within30, &c.Within60,
		&c.KVExpired, &c.KVWithin30)
	if err != nil {
		return Counts{}, fmt.Errorf("alerts: count the monitored items: %w", err)
	}
	return c, nil
}
