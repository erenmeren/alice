package discovery

// Ingestion (design decision 3, amendment A4): one transaction per batch of results; certificates are upserted by
// SHA-256 fingerprint (leaves, and the intermediates once each with is_leaf false), endpoints by (scope, address,
// port, SNI); batches are de-duplicated in memory first and written with at most ingestChunk rows per statement.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alice/internal/discovery/tlsprobe"
)

// Endpoint states (discovery_endpoints.state).
const (
	EndpointPresent     = "present"
	EndpointUnreachable = "unreachable"
	EndpointNoTLS       = "no_tls"
	EndpointMalformed   = "malformed"
	EndpointGone        = "gone"
)

// Caps on new certificates (A4): beyond them a new fingerprint is not stored, only counted in cert_churn.
const (
	MaxNewCertificatesPerScan = 1000
	MaxNewCertificatesPerDay  = 5000 // per scope, over the scans queued in the last 24 hours
)

// ingestChunk is the most rows one statement writes.
const ingestChunk = 500

// Result is the outcome of one endpoint. Code is "" when the endpoint presented a chain: Chain is its parse (the only
// copy of the DER a batch holds), ChainFingerprints the fingerprints of every certificate presented after the leaf
// (dropped ones included: limitation L2b) and ChainSHA256 the digest of the whole presented chain; otherwise Code says
// why not (tlsprobe's closed set; policy: the scan policy refused it, never dialed). PresentedResult builds one.
type Result struct {
	Endpoint          Endpoint
	Code              tlsprobe.Code
	Chain             tlsprobe.Chain
	ChainFingerprints []string
	ChainSHA256       string
	TLSVersion        string
	CipherSuite       string
}

// PresentedResult is the result of an endpoint that presented der (leaf first), parsed as chain. The fingerprints and
// the digest are computed here, so der itself need not be kept.
func PresentedResult(e Endpoint, der [][]byte, chain tlsprobe.Chain, version, suite string) Result {
	r := Result{Endpoint: e, Chain: chain, ChainFingerprints: make([]string, 0, max(0, len(der)-1)), ChainSHA256: chainDigest(der),
		TLSVersion: version, CipherSuite: suite}
	for _, d := range der[min(1, len(der)):] {
		r.ChainFingerprints = append(r.ChainFingerprints, fingerprint(d))
	}
	return r
}

// Batch is one transaction's worth of results of a scan.
type Batch struct {
	ScanID, ScopeID uuid.UUID
	Now             time.Time
	Results         []Result
}

// StateFor maps a result code to the endpoint state and last_error_code the migration's CHECKs accept:
//
//	""                         present      ''
//	refused, timeout, reset    unreachable  the code
//	chain_too_large            unreachable  chain_too_large
//	no_tls                     no_tls       no_tls
//	malformed                  malformed    malformed
//	policy                     excluded     policy (never dialed)
//
// A code outside the set (none exists) is treated as a refusal to connect: unreachable, refused.
func StateFor(c tlsprobe.Code) (state, code string) {
	switch c {
	case "":
		return EndpointPresent, ""
	case tlsprobe.CodeRefused, tlsprobe.CodeTimeout, tlsprobe.CodeReset, tlsprobe.CodeChainTooLarge:
		return EndpointUnreachable, string(c)
	case tlsprobe.CodeNoTLS, tlsprobe.CodeMalformed:
		return string(c), string(c)
	case tlsprobe.CodePolicy:
		return StateExcluded, ErrorCodePolicy
	}
	return EndpointUnreachable, string(tlsprobe.CodeRefused)
}

// answered reports whether the endpoint spoke TLS and showed a chain (stored, too large, or one Go cannot parse);
// failed results are the others an attempt produced (refused, timeout, reset, no TLS).
func answered(c tlsprobe.Code) bool {
	return c == "" || c == tlsprobe.CodeChainTooLarge || c == tlsprobe.CodeMalformed
}

// tlsVersions are the values discovery_endpoints.tls_version accepts.
var tlsVersions = []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}

// fingerprint is the lower-case hex SHA-256 of a certificate's DER (certificates.fingerprint_sha256).
func fingerprint(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// chainDigest is the SHA-256 of the whole presented chain: each certificate's DER preceded by its length (4 bytes, big
// endian), in the order presented.
func chainDigest(chain [][]byte) string {
	h := sha256.New()
	for _, der := range chain {
		_, _ = h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(der)))) //nolint:gosec // G115: tlsprobe caps a certificate at 16 KiB
		_, _ = h.Write(der)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// certRow is one discovery_certificates row to upsert.
type certRow struct {
	fp   string
	leaf bool
	c    tlsprobe.Certificate
}

// endpointRow is one discovery_endpoints row to upsert.
type endpointRow struct {
	e           Endpoint
	fp          string // leaf fingerprint, "" unless present
	chain       []string
	chainSHA    string
	tls, cipher string
	state, code string
}

// Ingest implements Store. In one transaction: the scan's counters are read (row locked); the certificates the batch
// presented are de-duplicated, the new ones admitted while the per-scan and per-day caps allow (leaves first) and the
// others only counted as churn; certificates and endpoints are upserted; an endpoint that answered with a leaf beyond the
// caps keeps its stored state and only records that it answered; the scan's counters grow. A scan whose cancel flag is
// set (read under the row lock) drops the batch.
// A batch that deadlocks or fails to serialize with another scan's (two scans storing the same new certificates) is
// retried once; certificates are written in fingerprint order, so two batches lock them in the same order.
func (s *PGStore) Ingest(ctx context.Context, b Batch) error {
	err := s.ingest(ctx, b)
	if retryable(err) {
		err = s.ingest(ctx, b)
	}
	return err
}

// retryable reports a deadlock (40P01) or a serialization failure (40001).
func retryable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == "40P01" || pe.Code == "40001")
}

func (s *PGStore) ingest(ctx context.Context, b Batch) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var scanNew, dayNew int
		var cancelled bool
		err := tx.QueryRow(ctx, `SELECT certificates_new, cancel_requested, (SELECT coalesce(sum(o.certificates_new), 0) FROM discovery_scans o
    WHERE o.scope_id = s.scope_id AND o.queued_at > $2)
FROM discovery_scans s WHERE s.id = $1 AND s.state = 'running' FOR UPDATE`, b.ScanID, b.Now.Add(-KeepScansFor)).Scan(&scanNew, &cancelled, &dayNew)
		if err != nil {
			return fmt.Errorf("%w (%w)", ErrScanNotRunning, err)
		}
		if cancelled {
			// A scan asked to stop stores nothing more: a scope edit or switch-off that asked (it marked endpoints gone
			// in the same transaction that set the flag) must not be undone by the batch still in flight.
			return nil
		}
		results := dedupeResults(b.Results)
		certs := presentedCertificates(results)
		existing, err := existingFingerprints(ctx, tx, certs)
		if err != nil {
			return err
		}
		budget := max(0, min(MaxNewCertificatesPerScan-scanNew, MaxNewCertificatesPerDay-dayNew))
		admitted, refused := admit(certs, existing, budget)
		var rows []endpointRow
		var unstored []Endpoint
		var nAnswered, nFailed, nExcluded int
		for _, r := range results {
			switch {
			case r.Code == tlsprobe.CodePolicy:
				nExcluded++
			case answered(r.Code):
				nAnswered++
			default:
				nFailed++
			}
			row := endpointRowOf(r)
			if row.fp != "" && refused[row.fp] {
				unstored = append(unstored, r.Endpoint)
				continue
			}
			rows = append(rows, row)
		}
		slices.SortFunc(admitted, func(a, b certRow) int { return strings.Compare(a.fp, b.fp) })
		if err := upsertCertificates(ctx, tx, admitted, b.Now); err != nil {
			return err
		}
		if err := upsertEndpoints(ctx, tx, b, rows); err != nil {
			return err
		}
		if err := touchEndpoints(ctx, tx, b, unstored); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE discovery_scans SET endpoints_answered = endpoints_answered + $2, endpoints_failed = endpoints_failed + $3,
    endpoints_excluded = endpoints_excluded + $4, certificates_new = certificates_new + $5, cert_churn = cert_churn + $6 WHERE id = $1`,
			b.ScanID, nAnswered, nFailed, nExcluded, len(admitted)-len(existing), len(refused))
		return wrap("count the batch", err)
	})
}

// dedupeResults keeps the last result per endpoint key, in first-seen order.
func dedupeResults(in []Result) []Result {
	type key struct {
		a    netip.Addr
		port uint16
		sni  string
	}
	at := make(map[key]int, len(in))
	out := make([]Result, 0, len(in))
	for _, r := range in {
		k := key{r.Endpoint.Address, r.Endpoint.Port, r.Endpoint.SNI}
		if i, ok := at[k]; ok {
			out[i] = r
			continue
		}
		at[k] = len(out)
		out = append(out, r)
	}
	return out
}

// presentedCertificates lists the batch's certificates once per fingerprint: every leaf first (in result order), then
// the intermediates. A certificate seen as a leaf anywhere is a leaf.
func presentedCertificates(results []Result) []certRow {
	at := map[string]int{}
	var out []certRow
	add := func(c tlsprobe.Certificate, leaf bool) {
		if i, ok := at[c.FingerprintSHA256]; ok {
			out[i].leaf = out[i].leaf || leaf
			return
		}
		at[c.FingerprintSHA256] = len(out)
		out = append(out, certRow{fp: c.FingerprintSHA256, leaf: leaf, c: c})
	}
	for pass := range 2 {
		for _, r := range results {
			if r.Code != "" || len(r.Chain.Certificates) == 0 {
				continue
			}
			if pass == 0 {
				add(r.Chain.Certificates[0], true)
				continue
			}
			for _, c := range r.Chain.Certificates[1:] {
				add(c, false)
			}
		}
	}
	return out
}

// existingFingerprints returns the certificates of the list that are stored already.
func existingFingerprints(ctx context.Context, tx pgx.Tx, certs []certRow) (map[string]bool, error) {
	fps := make([]string, len(certs))
	for i, c := range certs {
		fps[i] = c.fp
	}
	rows, err := tx.Query(ctx, `SELECT fingerprint_sha256 FROM discovery_certificates WHERE fingerprint_sha256 = ANY ($1::text[])`, fps)
	if err != nil {
		return nil, wrap("read the stored certificates", err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := make(map[string]bool, len(got))
	for _, fp := range got {
		out[fp] = true
	}
	return out, wrap("read the stored certificates", err)
}

// admit returns the certificates to upsert (the stored ones and the new ones within budget, in order) and the new ones
// refused by the caps.
func admit(certs []certRow, existing map[string]bool, budget int) (admitted []certRow, refused map[string]bool) {
	refused = map[string]bool{}
	for _, c := range certs {
		switch {
		case existing[c.fp]:
		case budget > 0:
			budget--
		default:
			refused[c.fp] = true
			continue
		}
		admitted = append(admitted, c)
	}
	return admitted, refused
}

// endpointRowOf is the row of one result (its chain as PresentedResult computed it).
func endpointRowOf(r Result) endpointRow {
	row := endpointRow{e: r.Endpoint, chain: []string{}}
	row.state, row.code = StateFor(r.Code)
	if row.state != EndpointPresent {
		return row
	}
	row.fp = r.Chain.Certificates[0].FingerprintSHA256
	row.chain = append(row.chain, r.ChainFingerprints...)
	row.chainSHA = r.ChainSHA256
	if slices.Contains(tlsVersions, r.TLSVersion) {
		row.tls = r.TLSVersion
	}
	if cipherOK(r.CipherSuite) {
		row.cipher = r.CipherSuite
	}
	return row
}

// cipherOK is the discovery_endpoints.cipher CHECK: at most 64 letters, digits and underscores.
func cipherOK(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// chunks calls fn for each run of at most ingestChunk elements.
func chunks[T any](list []T, fn func([]T) error) error {
	for len(list) > 0 {
		n := min(len(list), ingestChunk)
		if err := fn(list[:n]); err != nil {
			return err
		}
		list = list[n:]
	}
	return nil
}

// upsertCertificates writes the certificates; a stored one only gets its last sighting and, once seen as a leaf, is a
// leaf (its body never changes: the fingerprint is its hash); one stored before migration 00021 gets its public key hash.
func upsertCertificates(ctx context.Context, tx pgx.Tx, certs []certRow, now time.Time) error {
	return chunks(certs, func(part []certRow) error {
		n := len(part)
		fps, cns, issuers, algs, pems, sans := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		keys := make([]string, n)
		leaves, selfSigned := make([]bool, n), make([]bool, n)
		notBefore, notAfter := make([]time.Time, n), make([]time.Time, n)
		for i, r := range part {
			c := r.c
			list, _ := json.Marshal(append(append([]string{}, c.DNSNames...), c.IPAddresses...)) //nolint:errchkjson // strings always marshal
			fps[i], leaves[i], cns[i], issuers[i], algs[i], selfSigned[i] = r.fp, r.leaf, c.SubjectCN, c.IssuerCN, c.KeyAlgorithm, c.SelfSigned
			notBefore[i], notAfter[i], sans[i] = c.NotBefore, c.NotAfter, string(list)
			pems[i] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
			keys[i] = c.PublicKeySHA256
		}
		_, err := tx.Exec(ctx, `INSERT INTO discovery_certificates AS d (fingerprint_sha256, is_leaf, subject_cn, sans, issuer_cn, not_before, not_after,
    key_algorithm, self_signed, pem, first_seen, last_seen, public_key_sha256)
SELECT u.fp, u.leaf, u.cn, ARRAY(SELECT jsonb_array_elements_text(u.sans::jsonb)), u.issuer, u.nb, u.na, u.alg, u.ss, u.pem, $1, $1, u.pk
FROM unnest($2::text[], $3::bool[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::timestamptz[], $9::text[], $10::bool[], $11::text[],
    $12::text[]) AS u(fp, leaf, cn, sans, issuer, nb, na, alg, ss, pem, pk)
ON CONFLICT (fingerprint_sha256) DO UPDATE SET last_seen = greatest(d.last_seen, EXCLUDED.last_seen), is_leaf = d.is_leaf OR EXCLUDED.is_leaf,
    public_key_sha256 = CASE WHEN d.public_key_sha256 = '' THEN EXCLUDED.public_key_sha256 ELSE d.public_key_sha256 END`,
			now, fps, leaves, cns, sans, issuers, notBefore, notAfter, algs, selfSigned, pems, keys)
		return wrap("store the certificates", err)
	})
}

// upsertEndpoints writes the endpoint rows. On a stored endpoint: a presented chain replaces the leaf (the leaf it
// replaces goes to the front of previous_fingerprints, which keeps 5), the chain, version and suite and clears the
// misses; an answer without a stored certificate (malformed, chain too large) clears the misses too; a gone endpoint
// that still does not answer stays gone (its gone_since is kept, so retention removes it); every other result sets the
// state and the error code and keeps the last leaf seen. The misses themselves are counted when the scan ends.
func upsertEndpoints(ctx context.Context, tx pgx.Tx, b Batch, rows []endpointRow) error {
	return chunks(rows, func(part []endpointRow) error {
		n := len(part)
		ids, addrs, ports := make([]uuid.UUID, n), make([]netip.Addr, n), make([]int32, n)
		snis, hosts, fps, chains, shas, tlss, ciphers, states, codes := make([]string, n), make([]string, n), make([]string, n),
			make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		for i, r := range part {
			list, _ := json.Marshal(r.chain) //nolint:errchkjson // strings always marshal
			ids[i], addrs[i], ports[i], snis[i], hosts[i] = uuid.New(), r.e.Address, int32(r.e.Port), r.e.SNI, r.e.Host
			fps[i], chains[i], shas[i], tlss[i], ciphers[i], states[i], codes[i] = r.fp, string(list), r.chainSHA, r.tls, r.cipher, r.state, r.code
		}
		_, err := tx.Exec(ctx, `INSERT INTO discovery_endpoints AS e (id, scope_id, address, port, sni, host, fingerprint_sha256, chain_fingerprints,
    chain_sha256, tls_version, cipher, state, last_error_code, first_seen, last_seen, last_scanned_at, last_scan_id)
SELECT u.id, $1, u.address, u.port, u.sni, u.host, nullif(u.fp, ''), ARRAY(SELECT jsonb_array_elements_text(u.chain::jsonb)), u.sha, u.tls,
    u.cipher, u.state, u.code, $2, CASE WHEN u.state = 'present' THEN $2::timestamptz END, $2, $3
FROM unnest($4::uuid[], $5::inet[], $6::int[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[],
    $14::text[], $15::text[]) AS u(id, address, port, sni, host, fp, chain, sha, tls, cipher, state, code)
ON CONFLICT (scope_id, address, port, sni) DO UPDATE SET
    previous_fingerprints = CASE WHEN EXCLUDED.state = 'present' AND e.fingerprint_sha256 IS DISTINCT FROM EXCLUDED.fingerprint_sha256
        AND e.fingerprint_sha256 IS NOT NULL THEN (ARRAY[e.fingerprint_sha256] || e.previous_fingerprints)[1:5] ELSE e.previous_fingerprints END,
    fingerprint_sha256 = CASE WHEN EXCLUDED.state = 'present' THEN EXCLUDED.fingerprint_sha256 ELSE e.fingerprint_sha256 END,
    chain_fingerprints = CASE WHEN EXCLUDED.state = 'present' THEN EXCLUDED.chain_fingerprints ELSE e.chain_fingerprints END,
    chain_sha256 = CASE WHEN EXCLUDED.state = 'present' THEN EXCLUDED.chain_sha256 ELSE e.chain_sha256 END,
    tls_version = CASE WHEN EXCLUDED.state = 'present' THEN EXCLUDED.tls_version ELSE e.tls_version END,
    cipher = CASE WHEN EXCLUDED.state = 'present' THEN EXCLUDED.cipher ELSE e.cipher END,
    state = CASE WHEN e.state = 'gone' AND EXCLUDED.last_error_code IN ('refused', 'timeout', 'reset', 'no_tls') THEN 'gone' ELSE EXCLUDED.state END,
    gone_since = CASE WHEN e.state = 'gone' AND EXCLUDED.last_error_code IN ('refused', 'timeout', 'reset', 'no_tls') THEN e.gone_since END,
    last_error_code = EXCLUDED.last_error_code,
    missed_scans = CASE WHEN EXCLUDED.state IN ('present', 'malformed') OR EXCLUDED.last_error_code = 'chain_too_large' THEN 0 ELSE e.missed_scans END,
    last_seen = coalesce(EXCLUDED.last_seen, e.last_seen),
    last_scanned_at = EXCLUDED.last_scanned_at, last_scan_id = EXCLUDED.last_scan_id`,
			b.ScopeID, b.Now, b.ScanID, ids, addrs, ports, snis, hosts, fps, chains, shas, tlss, ciphers, states, codes)
		return wrap("store the endpoints", err)
	})
}

// touchEndpoints records that stored endpoints answered with a leaf the caps kept out: they were scanned and answered,
// so their misses are cleared, and one that was unreachable, without TLS or gone and has a leaf on record is present
// again (with that leaf: the new one is not stored). last_scan_id is left alone, so the scan's end counts no miss for
// them. An endpoint not stored yet is not created (it has no certificate to point at).
func touchEndpoints(ctx context.Context, tx pgx.Tx, b Batch, eps []Endpoint) error {
	return chunks(eps, func(part []Endpoint) error {
		addrs, ports, snis := make([]netip.Addr, len(part)), make([]int32, len(part)), make([]string, len(part))
		for i, e := range part {
			addrs[i], ports[i], snis[i] = e.Address, int32(e.Port), e.SNI
		}
		_, err := tx.Exec(ctx, `UPDATE discovery_endpoints e SET last_scanned_at = $2, missed_scans = 0,
    state = CASE WHEN e.fingerprint_sha256 IS NOT NULL AND e.state IN ('unreachable', 'no_tls', 'gone') THEN 'present' ELSE e.state END,
    last_error_code = CASE WHEN e.fingerprint_sha256 IS NOT NULL AND e.state IN ('unreachable', 'no_tls', 'gone') THEN '' ELSE e.last_error_code END,
    gone_since = CASE WHEN e.fingerprint_sha256 IS NOT NULL AND e.state = 'gone' THEN NULL ELSE e.gone_since END
FROM unnest($3::inet[], $4::int[], $5::text[]) AS k(a, p, s) WHERE e.scope_id = $1 AND e.address = k.a AND e.port = k.p AND e.sni = k.s`,
			b.ScopeID, b.Now, addrs, ports, snis)
		return wrap("record the endpoints over the caps", err)
	})
}
