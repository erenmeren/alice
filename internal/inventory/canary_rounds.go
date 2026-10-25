package inventory

// The rounds of a canary hold (R65, design §9.2-§9.5): a canary.check job reads what to observe (CanaryRoundTarget: the
// deployment's own verification request, the TLS baseline, and the optional HTTP check dialed at the location's own
// address), observes, and records the round (RecordCanaryRound). The job is fenced to its claim; a deployment that no
// longer holds records nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/authz"
	"alice/internal/platform/db"
	"alice/internal/providers"
)

// The results of a round and of its TLS baseline (canary_checks.last_result, last_tls).
const (
	RoundPass    = "pass"
	RoundFail    = "fail"
	RoundUnknown = "unknown"
	RoundSkipped = "skipped" // the baseline of a location that skips verification
)

// TemplateDeploymentRolloutStopped is the e-mail of a person's rollout whose wave 2 the licence stopped (design §14):
// params certificate_name, websites (the wave-2 websites, one line), rollout_id.
const TemplateDeploymentRolloutStopped = "deployment.rollout_stopped"

// CanaryTemplates lists the canary's e-mail templates (render tests; it names no server, so it is not in Templates).
func CanaryTemplates() []string { return []string{TemplateDeploymentRolloutStopped} }

// CanaryCheckSpec is the HTTP application check of one round (design §9.3), resolved for the location: the address
// dialed (the location's verification address, else its server's host; never the policy's host name), the port, the
// TLS server name and Host header ("" for none), the request target, the statuses that pass, the timeout and the leaf
// the website must serve. canaryjobs hands it to httpcheck.
type CanaryCheckSpec struct {
	Address          string
	Port             int
	ServerName       string
	Path             string
	ExpectStatus     []int
	Timeout          time.Duration
	ExpectLeafSHA256 string
}

// CanaryTarget is what one round of one holding deployment observes.
type CanaryTarget struct {
	Deployment uuid.UUID
	RolloutID  uuid.UUID
	TargetID   uuid.UUID
	Verify     providers.VerifyRequest // the deployment's own verification (Material.VerifyRequest)
	Check      *CanaryCheckSpec        // nil: the TLS baseline only
}

// CanaryRound is one round's outcome (Result RoundPass, RoundFail or RoundUnknown; TLS adds RoundSkipped).
type CanaryRound struct {
	Result, Reason, TLS   string
	HTTPStatus, LatencyMS int
}

// CanaryRoundTarget reads what a round of deployment id observes; ErrDeploymentState unless it holds.
func (s *Service) CanaryRoundTarget(ctx context.Context, id uuid.UUID) (CanaryTarget, error) {
	m, err := s.DeploymentMaterial(ctx, id, false)
	if err != nil {
		return CanaryTarget{}, err
	}
	d := m.Deployment
	if d.State != DeployStateHolding || d.RolloutID == nil {
		return CanaryTarget{}, ErrDeploymentState
	}
	t := CanaryTarget{Deployment: id, RolloutID: *d.RolloutID, TargetID: d.TargetID, Verify: m.VerifyRequest()}
	var (
		raw           []byte
		host, address string
	)
	err = s.pool.QueryRow(ctx, `SELECT r.settings, coalesce(t.config->>'host', ''), coalesce(l.verify_address, '') FROM deployment_rollouts r
JOIN deployments d ON d.rollout_id = r.id JOIN targets t ON t.id = d.target_id JOIN certificate_locations l ON l.id = d.location_id
WHERE d.id = $1`, id).Scan(&raw, &host, &address)
	if errors.Is(err, pgx.ErrNoRows) {
		return CanaryTarget{}, ErrDeploymentState
	}
	if err != nil {
		return CanaryTarget{}, fmt.Errorf("inventory: read the round's settings: %w", err)
	}
	var settings authz.CanarySettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return CanaryTarget{}, fmt.Errorf("inventory: decode the rollout's settings: %w", err)
	}
	if settings.Check != nil {
		t.Check = canaryCheckSpec(settings, m, host, address)
	}
	return t, nil
}

// canaryCheckSpec resolves the HTTP check for a location (design §9.3's table): address = the verification address,
// else the server's host; port = check.port, else the verification port, else the first SSL listen, else 443; server
// name = check.host, else the verification SNI, else the name the post-deploy probe sends (the location's names, then
// the certificate's).
func canaryCheckSpec(st authz.CanarySettings, m Material, host, address string) *CanaryCheckSpec {
	c := st.Check
	spec := &CanaryCheckSpec{Address: host, Path: c.Path, ExpectStatus: c.ExpectStatus, Timeout: st.Timeout, ExpectLeafSHA256: m.Fingerprint}
	if address != "" {
		spec.Address = address
	}
	switch {
	case c.Port > 0:
		spec.Port = c.Port
	case m.Verify.Port > 0:
		spec.Port = m.Verify.Port
	default:
		spec.Port = firstListenPort(m.Location.Servers)
	}
	switch {
	case c.Host != "":
		spec.ServerName = c.Host
	case m.Verify.SNI != "":
		spec.ServerName = m.Verify.SNI
	default:
		var names []string
		for _, sv := range m.Location.Servers {
			names = append(names, sv.Names...)
		}
		spec.ServerName = sniFor(names, m.SANs)
	}
	return spec
}

func firstListenPort(servers []providers.CertServer) int {
	for _, sv := range servers {
		for _, l := range sv.Listens {
			if l.Port >= 1 && l.Port <= 65535 {
				return l.Port
			}
		}
	}
	return 443
}

// sniFor is tlsverify.SNIFor (the inventory imports no provider package; a test keeps the two in step): the first
// usable name of the location, else of the certificate; a wildcard becomes alice-check.<suffix>.
func sniFor(names, sans []string) string {
	for _, list := range [][]string{names, sans} {
		for _, n := range list {
			if sni := sniCandidate(n); sni != "" {
				return sni
			}
		}
	}
	return ""
}

func sniCandidate(n string) string {
	n = foldName(n)
	switch {
	case n == "" || n == "_" || strings.HasPrefix(n, "~"):
		return ""
	case strings.HasPrefix(n, "*."):
		n = "alice-check." + n[2:]
	case strings.HasPrefix(n, "."):
		n = n[1:]
	}
	if strings.Contains(n, "*") || !sniShape(n) {
		return ""
	}
	return n
}

func foldName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// sniShape is a host name an SNI may carry: LDH labels of 1..63, at most 253, not an IP literal.
func sniShape(n string) bool {
	if len(n) == 0 || len(n) > 253 || strings.Trim(n, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// RecordCanaryRound records one round of deployment id (fenced to the job's claim): the counters, the latest result
// and the next round at now + interval. A pass resets the consecutive failures, a failure counts one, an unknown
// changes neither. A deployment that no longer holds records nothing (nil).
func (s *Service) RecordCanaryRound(ctx context.Context, id uuid.UUID, r CanaryRound) error {
	switch r.Result {
	case RoundPass, RoundFail, RoundUnknown:
	default:
		return errors.New("inventory: not a round result")
	}
	tls := oneOf(r.TLS, []string{"", RoundPass, RoundFail, RoundSkipped, RoundUnknown})
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		d, err := lockDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.state != DeployStateHolding || d.rollout == nil {
			return nil
		}
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT settings FROM deployment_rollouts WHERE id = $1", *d.rollout).Scan(&raw); err != nil {
			return fmt.Errorf("inventory: read the rollout's settings: %w", err)
		}
		var st authz.CanarySettings
		if err := json.Unmarshal(raw, &st); err != nil {
			return fmt.Errorf("inventory: decode the rollout's settings: %w", err)
		}
		interval := st.Interval
		if interval <= 0 {
			interval = authz.DefaultCanaryInterval
		}
		now := s.clock.Now().UTC()
		var status, latency *int
		if r.HTTPStatus >= 100 && r.HTTPStatus <= 599 {
			status = &r.HTTPStatus
		}
		if r.LatencyMS >= 0 && (r.HTTPStatus > 0 || r.LatencyMS > 0) {
			latency = &r.LatencyMS
		}
		var first []byte
		if r.Result == RoundFail {
			first, err = json.Marshal(map[string]string{"at": now.Format(time.RFC3339), "reason": sanitizeCode(r.Reason, ""),
				"http_status": strconv.Itoa(r.HTTPStatus)})
			if err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE canary_checks SET rounds = rounds + 1,
    passes = passes + CASE WHEN $2 = 'pass' THEN 1 ELSE 0 END,
    consecutive_failures = CASE $2 WHEN 'pass' THEN 0 WHEN 'fail' THEN consecutive_failures + 1 ELSE consecutive_failures END,
    next_check_at = $3, last_at = $4, last_result = $2, last_reason = $5, last_tls = $6, last_http_status = $7, last_latency_ms = $8,
    last_pass_at = CASE WHEN $2 = 'pass' THEN $4 ELSE last_pass_at END,
    first_failure = CASE WHEN first_failure IS NULL AND $9::jsonb IS NOT NULL THEN $9::jsonb ELSE first_failure END
WHERE deployment_id = $1`, id, r.Result, now.Add(interval), now, sanitizeCode(r.Reason, ""), tls, status, latency, first)
		if err != nil {
			return fmt.Errorf("inventory: record the round: %w", err)
		}
		if r.Result == RoundFail {
			s.log.Warn("a canary round failed", "deployment_id", id.String(), "rollout_id", d.rollout.String(), "error_type", sanitizeCode(r.Reason, ""))
		}
		return nil
	})
}

// notifyRolloutStopped queues the deployment.rollout_stopped e-mail for the services of the rollout's first wave-1
// deployment (its server's and its certificate's, as a deployment e-mail is routed).
func (s *Service) notifyRolloutStopped(ctx context.Context, tx pgx.Tx, r Rollout) error {
	if s.notifier == nil {
		return nil
	}
	var first uuid.UUID
	err := tx.QueryRow(ctx, "SELECT id FROM deployments WHERE rollout_id = $1 AND wave = 1 ORDER BY created_at, id LIMIT 1", r.ID).Scan(&first)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inventory: read the rollout's first deployment: %w", err)
	}
	svcs, err := deploymentServices(ctx, tx, first)
	if err != nil {
		return err
	}
	var name string
	if err := tx.QueryRow(ctx, `SELECT coalesce(nullif(label, ''), nullif(subject_cn, ''), left(fingerprint_sha256, 16)) FROM certificates WHERE id = $1`,
		r.CertificateID).Scan(&name); err != nil {
		return fmt.Errorf("inventory: read the certificate's name: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT t.name::text || ' ' || l.cert_path FROM certificate_locations l JOIN targets t ON t.id = l.target_id
WHERE l.id = ANY($1) ORDER BY t.name, l.cert_path`, r.Wave2)
	if err != nil {
		return fmt.Errorf("inventory: read the wave-2 websites: %w", err)
	}
	sites, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("inventory: read the wave-2 websites: %w", err)
	}
	params := map[string]string{"certificate_name": oneLine(truncRunes(strings.TrimSpace(name), 200)),
		"websites": oneLine(truncRunes(strings.Join(sites, ", "), 1000)), "rollout_id": r.ID.String()}
	if err := s.notifier.NotifyServices(ctx, tx, svcs, TemplateDeploymentRolloutStopped, params); err != nil {
		return fmt.Errorf("inventory: queue the %s email: %w", TemplateDeploymentRolloutStopped, err)
	}
	return nil
}

// oneLine replaces line breaks (a name from a server's configuration stays on one line of an e-mail).
func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
