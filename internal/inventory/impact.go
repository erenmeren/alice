package inventory

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The impact of a certificate (owner decision 2026-10-20, docs/superpowers/rulings/certificate-revocation.md): every
// place where the certificate itself (by its fingerprint) or another certificate made with the same private key (by
// the public key hash, the SHA-256 of the SubjectPublicKeyInfo) is deployed or was found: certificate files on managed
// servers (with the ACME certificate a file is bound to), Azure Key Vault versions, and endpoints network discovery
// found presenting it. It is what a person reads when a key leaked ("which servers are affected?") and what an incident
// replaces. Read-only; any source.

// Impact matches: the place holds the certificate itself, or another certificate with the same key.
const (
	ImpactMatchCertificate = "certificate"
	ImpactMatchKey         = "key"
)

// MaxImpactRows bounds each list of an impact (Truncated says when a list was cut).
const MaxImpactRows = 1000

// ImpactCertificate is a certificate with the same key (the certificate itself included, first).
type ImpactCertificate struct {
	ID            uuid.UUID
	Fingerprint   string
	SubjectCN     string
	Label         string
	Source        string
	NotAfter      time.Time
	RevokedAt     *time.Time
	CompromisedAt *time.Time
	Match         string
}

// ImpactLocation is a certificate file on a managed server that holds the certificate or one with the same key (in the
// file now, or deployed by Alice last: certificate_locations.deployed_fingerprint).
type ImpactLocation struct {
	LocationID    uuid.UUID
	TargetID      uuid.UUID
	TargetName    string
	TargetType    string
	CertPath      string
	CertificateID *uuid.UUID // the certificate in the file now (nil: none readable)
	Fingerprint   string     // its fingerprint ("" when none)
	Match         string
	// Deployable: Alice can deploy to the file (supported, a server whose software deploys certificates, a path the
	// helper takes); otherwise it is listed for a person to replace by hand.
	Deployable bool
	// ACMECertificateID is the ACME certificate the file follows (a binding), nil for none.
	ACMECertificateID *uuid.UUID
	// KVBound: the file follows an Azure Key Vault certificate.
	KVBound bool
}

// ImpactVaultVersion is an Azure Key Vault version whose certificate is the certificate or one with the same key.
type ImpactVaultVersion struct {
	VaultID         uuid.UUID
	VaultName       string
	KVCertificateID uuid.UUID
	Name            string
	Version         string
	CertificateID   uuid.UUID
	Current         bool // the vault's current version of that certificate
	Match           string
}

// ImpactEndpoint is an endpoint network discovery found presenting the certificate or one with the same key.
type ImpactEndpoint struct {
	EndpointID  uuid.UUID
	ScopeID     uuid.UUID
	ScopeName   string
	Address     netip.Addr
	Port        int
	SNI         string
	Host        string
	Fingerprint string
	State       string // present, or unreachable since it last presented it
	LastSeen    *time.Time
	Match       string
}

// CertificateImpact is the impact of one certificate.
type CertificateImpact struct {
	Certificate  Certificate
	Certificates []ImpactCertificate
	Locations    []ImpactLocation
	Vaults       []ImpactVaultVersion
	Endpoints    []ImpactEndpoint
	// Truncated: a list was cut at MaxImpactRows.
	Truncated bool
	// OpenIncidentID is the open key-compromise incident of the certificate, nil without one.
	OpenIncidentID *uuid.UUID
}

// CertificateImpact reads the impact of a certificate (ErrNotFound).
func (s *Service) CertificateImpact(ctx context.Context, id uuid.UUID) (CertificateImpact, error) {
	c, err := s.GetCertificate(ctx, id)
	if err != nil {
		return CertificateImpact{}, err
	}
	out := CertificateImpact{Certificate: c}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return CertificateImpact{}, fmt.Errorf("inventory: begin the impact read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := readImpact(ctx, tx, &out); err != nil {
		return CertificateImpact{}, err
	}
	for i := range out.Locations {
		out.Locations[i].Deployable = out.Locations[i].Deployable && s.canDeploy(out.Locations[i].TargetType)
	}
	return out, nil
}

func match(same bool) string {
	if same {
		return ImpactMatchCertificate
	}
	return ImpactMatchKey
}

// readImpact fills the lists of out (whose Certificate is read) in tx, a snapshot.
func readImpact(ctx context.Context, tx pgx.Tx, out *CertificateImpact) error {
	c := out.Certificate
	rows, err := tx.Query(ctx, `SELECT x.id, x.fingerprint_sha256, x.subject_cn, x.label, x.source, x.not_after, x.revoked_at, x.compromised_at
FROM certificates x WHERE x.public_key_sha256 = $1 ORDER BY x.id = $2 DESC, x.not_after DESC, x.id LIMIT $3`, c.PublicKeySHA256, c.ID, MaxImpactRows+1)
	if err != nil {
		return fmt.Errorf("inventory: read the certificates with the same key: %w", err)
	}
	out.Certificates, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ImpactCertificate, error) {
		var x ImpactCertificate
		err := r.Scan(&x.ID, &x.Fingerprint, &x.SubjectCN, &x.Label, &x.Source, &x.NotAfter, &x.RevokedAt, &x.CompromisedAt)
		x.NotAfter, x.RevokedAt, x.CompromisedAt, x.Match = x.NotAfter.UTC(), utcPtr(x.RevokedAt), utcPtr(x.CompromisedAt), match(x.ID == c.ID)
		return x, err
	})
	if err != nil {
		return fmt.Errorf("inventory: read the certificates with the same key: %w", err)
	}
	if len(out.Certificates) > MaxImpactRows {
		out.Certificates, out.Truncated = out.Certificates[:MaxImpactRows], true
	}

	// Files on live servers that hold (or were last given by Alice) a certificate with this key.
	rows, err = tx.Query(ctx, `SELECT l.id, l.target_id, t.name::text, t.type, l.cert_path, l.certificate_id, coalesce(x.fingerprint_sha256, ''),
    coalesce(x.fingerprint_sha256 = $2 OR l.deployed_fingerprint = $2, false),
    l.supported AND l.missing_since IS NULL AND l.cert_path ~ '^/[A-Za-z0-9._/@:+-]+$' AND l.key_path ~ '^/[A-Za-z0-9._/@:+-]+$',
    b.acme_certificate_id, l.binding_id IS NOT NULL
FROM certificate_locations l
JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
LEFT JOIN certificates x ON x.id = l.certificate_id
LEFT JOIN acme_bindings b ON b.location_id = l.id
WHERE l.missing_since IS NULL
  AND (x.public_key_sha256 = $1
       OR l.deployed_fingerprint IN (SELECT y.fingerprint_sha256 FROM certificates y WHERE y.public_key_sha256 = $1))
ORDER BY t.name, l.cert_path, l.id LIMIT $3`, c.PublicKeySHA256, c.Fingerprint, MaxImpactRows+1)
	if err != nil {
		return fmt.Errorf("inventory: read the affected locations: %w", err)
	}
	out.Locations, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ImpactLocation, error) {
		var l ImpactLocation
		var same bool
		err := r.Scan(&l.LocationID, &l.TargetID, &l.TargetName, &l.TargetType, &l.CertPath, &l.CertificateID, &l.Fingerprint, &same,
			&l.Deployable, &l.ACMECertificateID, &l.KVBound)
		l.Match = match(same)
		return l, err
	})
	if err != nil {
		return fmt.Errorf("inventory: read the affected locations: %w", err)
	}
	if len(out.Locations) > MaxImpactRows {
		out.Locations, out.Truncated = out.Locations[:MaxImpactRows], true
	}

	rows, err = tx.Query(ctx, `SELECT vt.id, vt.name::text, kc.id, kc.name, v.version, v.certificate_id, kc.current_version = v.version, v.certificate_id = $2
FROM kv_certificate_versions v
JOIN kv_certificates kc ON kc.id = v.kv_certificate_id AND kc.missing_since IS NULL
JOIN targets vt ON vt.id = kc.target_id AND vt.deleted_at IS NULL
JOIN certificates x ON x.id = v.certificate_id
WHERE x.public_key_sha256 = $1
ORDER BY vt.name, kc.name, v.detected_at DESC LIMIT $3`, c.PublicKeySHA256, c.ID, MaxImpactRows+1)
	if err != nil {
		return fmt.Errorf("inventory: read the affected vault versions: %w", err)
	}
	out.Vaults, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ImpactVaultVersion, error) {
		var v ImpactVaultVersion
		var same bool
		err := r.Scan(&v.VaultID, &v.VaultName, &v.KVCertificateID, &v.Name, &v.Version, &v.CertificateID, &v.Current, &same)
		v.Match = match(same)
		return v, err
	})
	if err != nil {
		return fmt.Errorf("inventory: read the affected vault versions: %w", err)
	}
	if len(out.Vaults) > MaxImpactRows {
		out.Vaults, out.Truncated = out.Vaults[:MaxImpactRows], true
	}

	// Endpoints of live scopes presenting (or, unreachable since, last presenting) a certificate with this key: by the
	// fingerprint of a managed certificate with the key, or by the discovered certificate's own key hash.
	rows, err = tx.Query(ctx, `SELECT e.id, e.scope_id, sc.name::text, e.address, e.port, e.sni, e.host, e.fingerprint_sha256, e.state, e.last_seen,
    e.fingerprint_sha256 = $2
FROM discovery_endpoints e
JOIN discovery_scopes sc ON sc.id = e.scope_id AND sc.deleted_at IS NULL
WHERE e.state IN ('present', 'unreachable') AND e.fingerprint_sha256 IS NOT NULL
  AND (e.fingerprint_sha256 IN (SELECT y.fingerprint_sha256 FROM certificates y WHERE y.public_key_sha256 = $1)
       OR e.fingerprint_sha256 IN (SELECT d.fingerprint_sha256 FROM discovery_certificates d WHERE d.public_key_sha256 = $1))
ORDER BY e.address, e.port, e.sni, e.id LIMIT $3`, c.PublicKeySHA256, c.Fingerprint, MaxImpactRows+1)
	if err != nil {
		return fmt.Errorf("inventory: read the affected endpoints: %w", err)
	}
	out.Endpoints, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ImpactEndpoint, error) {
		var e ImpactEndpoint
		var same bool
		err := r.Scan(&e.EndpointID, &e.ScopeID, &e.ScopeName, &e.Address, &e.Port, &e.SNI, &e.Host, &e.Fingerprint, &e.State, &e.LastSeen, &same)
		e.LastSeen, e.Match = utcPtr(e.LastSeen), match(same)
		return e, err
	})
	if err != nil {
		return fmt.Errorf("inventory: read the affected endpoints: %w", err)
	}
	if len(out.Endpoints) > MaxImpactRows {
		out.Endpoints, out.Truncated = out.Endpoints[:MaxImpactRows], true
	}

	var open uuid.UUID
	err = tx.QueryRow(ctx, "SELECT id FROM certificate_incidents WHERE certificate_id = $1 AND finished_at IS NULL", c.ID).Scan(&open)
	switch {
	case err == nil:
		out.OpenIncidentID = &open
	case err != pgx.ErrNoRows: //nolint:errorlint // pgx returns the sentinel itself
		return fmt.Errorf("inventory: read the open incident: %w", err)
	}
	return nil
}
