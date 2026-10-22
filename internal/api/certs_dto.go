package api

import (
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// Wire forms of the Phase 4 resources (contract "API", Task 17). Certificates and signing requests
// are public data: no DTO has a private-key, key-id, sealed-envelope or password field; a held key
// is only indicated (has_private_key). Paths, server names, file names and accounts come from the
// servers: they are plain JSON strings, never interpolated into a message.

type certificateRefDTO struct {
	ID          string    `json:"id"`
	SubjectCN   string    `json:"subject_cn"`
	Label       string    `json:"label"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
}

type certificateDTO struct {
	ID            string    `json:"id"`
	Fingerprint   string    `json:"fingerprint"`
	SubjectCN     string    `json:"subject_cn"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	Serial        string    `json:"serial"`
	SANs          []string  `json:"sans"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	KeyAlgorithm  string    `json:"key_algorithm"`
	KeyBits       int       `json:"key_bits"`
	Source        string    `json:"source"`
	Label         string    `json:"label"`
	HasPrivateKey bool      `json:"has_private_key"`
	ChainComplete bool      `json:"chain_complete"`
	SelfSigned    bool      `json:"self_signed"`
	LocationCount int       `json:"location_count"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	// Revocation, key compromise and the per-source capability matrix (2026-10-20).
	PublicKeySHA256   string     `json:"public_key_sha256"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevocationReason  string     `json:"revocation_reason"`
	RevokedByName     string     `json:"revoked_by_name"`
	CompromisedAt     *time.Time `json:"compromised_at"`
	ACMECertificateID *string    `json:"acme_certificate_id"`
	Capabilities      []string   `json:"capabilities"`
	// Service is the owning service (R49, design §8.2).
	Service *serviceRefDTO `json:"service,omitempty"`
	// AllowedActions are the permissions the caller holds on the row's owning service (R49 Phase 2, design §8.2).
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

// capabilityNames is the wire form of a capability list.
func capabilityNames(in []inventory.SourceCapability) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, string(c))
	}
	return out
}

// certificateDetailDTO is GET /certificates/{id} and the certificate of an upload or a signing
// request's completion: the list form plus the chain (public PEM) and the locations using it.
type certificateDetailDTO struct {
	certificateDTO
	PEMChain           string        `json:"pem_chain"`
	Locations          []locationDTO `json:"locations"`
	LocationsTruncated bool          `json:"locations_truncated"`
	// HiddenCount is how many locations are on servers outside the caller's services (R49 Phase 2, design §5.8).
	HiddenCount int `json:"hidden_count"`
}

func certificateJSON(c inventory.Certificate, refs serviceRefs) certificateDTO {
	return certificateDTO{
		ID: c.ID.String(), Fingerprint: c.Fingerprint, SubjectCN: c.SubjectCN, Subject: c.Subject, Issuer: c.Issuer, Serial: c.Serial,
		SANs: nonNil(c.SANs), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), KeyAlgorithm: c.KeyAlgorithm, KeyBits: c.KeyBits,
		Source: c.Source, Label: c.Label, HasPrivateKey: c.HasPrivateKey, ChainComplete: c.ChainComplete, SelfSigned: c.SelfSigned,
		LocationCount: c.LocationCount, FirstSeenAt: c.FirstSeenAt.UTC(), LastSeenAt: c.LastSeenAt.UTC(),
		PublicKeySHA256: c.PublicKeySHA256, RevokedAt: utcPtr(c.RevokedAt), RevocationReason: c.RevocationReason, RevokedByName: c.RevokedByName,
		CompromisedAt: utcPtr(c.CompromisedAt), ACMECertificateID: idPtr(c.ACMECertificateID),
		Capabilities: capabilityNames(inventory.CertificateCapabilities(c)), Service: refs.of(c.ServiceID), AllowedActions: refs.actions(c.ServiceID),
	}
}

func certificateDetailJSON(c inventory.Certificate, refs serviceRefs) certificateDetailDTO {
	d := certificateDetailDTO{certificateDTO: certificateJSON(c, refs), PEMChain: c.PEMChain, Locations: make([]locationDTO, 0, len(c.Locations)),
		LocationsTruncated: c.LocationsTruncated}
	for _, l := range c.Locations {
		d.Locations = append(d.Locations, locationJSON(l))
	}
	return d
}

type listenDTO struct {
	Addr          string `json:"addr"`
	Port          int    `json:"port"`
	DefaultServer bool   `json:"default_server"`
}

type serverBlockDTO struct {
	Names   []string    `json:"names"`
	Listens []listenDTO `json:"listens"`
	File    string      `json:"file"`
	Line    int         `json:"line"`
	Section string      `json:"section,omitempty"`
}

type locationDTO struct {
	ID                  string             `json:"id"`
	TargetID            string             `json:"target_id"`
	TargetName          string             `json:"target_name"`
	CertPath            string             `json:"cert_path"`
	KeyPath             string             `json:"key_path"`
	ResolvedCertPath    string             `json:"resolved_cert_path"`
	KeyType             string             `json:"key_type"`
	Certificate         *certificateRefDTO `json:"certificate"`
	Servers             []serverBlockDTO   `json:"servers"`
	Supported           bool               `json:"supported"`
	UnsupportedReason   string             `json:"unsupported_reason"`
	Problem             string             `json:"problem"`
	KeyProblem          string             `json:"key_problem"`
	Inherited           bool               `json:"inherited"`
	CustomLocation      bool               `json:"custom_location"`
	Symlinked           bool               `json:"symlinked"`
	KeyExists           bool               `json:"key_exists"`
	KeyMode             string             `json:"key_mode"`
	KeyOwner            string             `json:"key_owner"`
	KeyGroup            string             `json:"key_group"`
	Warnings            []string           `json:"warnings"`
	DeployedFingerprint string             `json:"deployed_fingerprint"`
	ChangedOutsideAt    *time.Time         `json:"changed_outside_at"`
	VerifyPort          *int               `json:"verify_port"`
	VerifySNI           string             `json:"verify_sni"`
	SkipVerify          bool               `json:"skip_verify"`
	FirstSeenAt         time.Time          `json:"first_seen_at"`
	LastSeenAt          time.Time          `json:"last_seen_at"`
	MissingSince        *time.Time         `json:"missing_since"`
	Version             int                `json:"version"`
	ActiveDeploymentID  *string            `json:"active_deployment_id"`
	TargetType          string             `json:"target_type"`
	Deployable          bool               `json:"deployable"`
	// Observation (R52): what the location should have, what Alice last deployed and what is observed today; null for
	// a location that follows no binding.
	Observation *locationObservationDTO `json:"observation"`
	// R59 G1, G4: the kind, the locator (null for a file), the kind's details ({} for a file) and the probe address.
	Kind          string         `json:"kind"`
	Locator       map[string]any `json:"locator"`
	Details       map[string]any `json:"details"`
	VerifyAddress string         `json:"verify_address"`
}

func idPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func serversJSON(in []providers.CertServer) []serverBlockDTO {
	out := make([]serverBlockDTO, 0, len(in))
	for _, sv := range in {
		b := serverBlockDTO{Names: nonNil(sv.Names), Listens: make([]listenDTO, 0, len(sv.Listens)), File: sv.File, Line: sv.Line, Section: sv.Section}
		for _, l := range sv.Listens {
			b.Listens = append(b.Listens, listenDTO{Addr: l.Addr, Port: l.Port, DefaultServer: l.DefaultServer})
		}
		out = append(out, b)
	}
	return out
}

// locationJSON renders a certificate location. The file hash (the deployment's compare-and-swap
// value) stays internal.
func locationJSON(l inventory.CertificateLocation) locationDTO {
	d := locationDTO{
		ID: l.ID.String(), TargetID: l.TargetID.String(), TargetName: l.TargetName, CertPath: l.CertPath, KeyPath: l.KeyPath,
		ResolvedCertPath: l.ResolvedCertPath, KeyType: l.KeyType, Servers: serversJSON(l.Servers), Supported: l.Supported,
		UnsupportedReason: l.UnsupportedReason, Problem: l.Problem, KeyProblem: l.KeyProblem, Inherited: l.Inherited,
		CustomLocation: l.CustomLocation, Symlinked: l.Symlinked, KeyExists: l.KeyExists, KeyMode: l.KeyMode, KeyOwner: l.KeyOwner,
		KeyGroup: l.KeyGroup, Warnings: nonNil(l.Warnings), DeployedFingerprint: l.DeployedFingerprint,
		ChangedOutsideAt: utcPtr(l.ChangedOutsideAt), VerifyPort: l.VerifyPort, VerifySNI: l.VerifySNI, SkipVerify: l.SkipVerify,
		FirstSeenAt: l.FirstSeenAt.UTC(), LastSeenAt: l.LastSeenAt.UTC(), MissingSince: utcPtr(l.MissingSince), Version: l.Version,
		ActiveDeploymentID: idPtr(l.ActiveDeploymentID), TargetType: l.TargetType, Deployable: l.Deployable,
		Observation: observationJSON(l.Observation), Kind: string(l.Kind.OrFile()), Locator: l.Locator, Details: l.Details,
		VerifyAddress: l.VerifyAddress,
	}
	if d.Details == nil {
		d.Details = map[string]any{}
	}
	if c := l.Certificate; c != nil {
		d.Certificate = &certificateRefDTO{ID: c.ID.String(), SubjectCN: c.SubjectCN, Label: c.Label, Fingerprint: c.Fingerprint,
			NotAfter: c.NotAfter.UTC()}
	}
	return d
}

type csrDTO struct {
	ID            string     `json:"id"`
	CommonName    string     `json:"common_name"`
	SANs          []string   `json:"sans"`
	KeyAlgorithm  string     `json:"key_algorithm"`
	KeyBits       int        `json:"key_bits"`
	CSRPEM        string     `json:"csr_pem"`
	Status        string     `json:"status"`
	CertificateID *string    `json:"certificate_id"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	// Service is the owning service (R49, design §8.2).
	Service *serviceRefDTO `json:"service,omitempty"`
	// AllowedActions are the permissions the caller holds on the row's owning service (R49 Phase 2, design §8.2).
	AllowedActions []string `json:"allowed_actions,omitempty"`
}

func csrJSON(c inventory.CSR, refs serviceRefs) csrDTO {
	return csrDTO{
		ID: c.ID.String(), CommonName: c.CommonName, SANs: nonNil(c.SANs), KeyAlgorithm: c.KeyAlgorithm, KeyBits: c.KeyBits,
		CSRPEM: c.CSRPEM, Status: c.Status, CertificateID: idPtr(c.CertificateID), CreatedAt: c.CreatedAt.UTC(),
		FinishedAt: utcPtr(c.FinishedAt), Service: refs.of(c.ServiceID), AllowedActions: refs.actions(c.ServiceID),
	}
}

// requestedDeploymentDTO is one accepted item of a deployment request: the deployment, its job and
// where to follow each.
type requestedDeploymentDTO struct {
	ID            string   `json:"id"`
	JobID         string   `json:"job_id"`
	LocationID    string   `json:"location_id"`
	StatusURL     string   `json:"status_url"`
	DeploymentURL string   `json:"deployment_url"`
	Warnings      []string `json:"warnings"`
}

func requestedDeploymentJSON(r inventory.RequestedDeployment) requestedDeploymentDTO {
	return requestedDeploymentDTO{
		ID: r.ID.String(), JobID: r.JobID.String(), LocationID: r.LocationID.String(), StatusURL: "/api/v1/jobs/" + r.JobID.String(),
		DeploymentURL: "/api/v1/deployments/" + r.ID.String(), Warnings: nonNil(r.Warnings),
	}
}

type deploymentStepDTO struct {
	N      int               `json:"n"`
	Name   string            `json:"name"`
	Status string            `json:"status"`
	At     time.Time         `json:"at"`
	Params map[string]string `json:"params"`
}

type deploymentDTO struct {
	ID                     string       `json:"id"`
	CertificateID          string       `json:"certificate_id"`
	CertificateName        string       `json:"certificate_name"`
	LocationID             string       `json:"location_id"`
	TargetID               string       `json:"target_id"`
	TargetName             string       `json:"target_name"`
	CertPath               string       `json:"cert_path"`
	KeyPath                string       `json:"key_path"`
	JobID                  *string      `json:"job_id"`
	JobStatus              string       `json:"job_status"`
	Trigger                string       `json:"trigger"`
	State                  string       `json:"state"`
	Status                 string       `json:"status"`
	Result                 string       `json:"result"`
	Phase                  string       `json:"phase"`
	NewFingerprint         string       `json:"new_fingerprint"`
	PreviousFingerprint    string       `json:"previous_fingerprint"`
	ConfirmIncompleteChain bool         `json:"confirm_incomplete_chain"`
	Verified               string       `json:"verified"`
	VerifyFailed           *errorRefDTO `json:"verify_failed"`
	Error                  *errorRefDTO `json:"error"`
	FailedStep             string       `json:"failed_step"`
	CauseStep              string       `json:"cause_step"`
	HelperError            string       `json:"helper_error"`
	BackupDir              string       `json:"backup_dir"`
	// A Windows deployment (R61 Ruling 17): the store and SHA-1 of the previous certificate, which stays in its store
	// (backup_dir is ""); left out for every other deployment, whose JSON is unchanged.
	BackupStore      string     `json:"backup_store,omitempty"`
	BackupSHA1       string     `json:"backup_sha1,omitempty"`
	RequestedBy      *string    `json:"requested_by"`
	RequestedByName  string     `json:"requested_by_name"`
	RecoveryAttempts int        `json:"recovery_attempts"`
	RecoverAfter     *time.Time `json:"recover_after"`
	CreatedAt        time.Time  `json:"created_at"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	// Key Vault deployments (Phase 5): where the certificate came from and, for a vault's, the connection and
	// the vault version.
	Source    string  `json:"source"`
	BindingID *string `json:"binding_id"`
	KVVersion string  `json:"kv_version"`
	VaultName string  `json:"vault_name"`
	// Verification (R51): what the verification of the new certificate proved and found.
	Verification deploymentVerificationDTO `json:"verification"`
}

// deploymentVerificationDTO is a deployment's verification evidence (R51): the level a finished deployment proved
// (0 none, 1 installed, 2 served, 3 trusted; 4 is reserved for a service health check), what the verification found
// about the served chains (null when not measured: skipped, or a deployment from before R51), and the kind of a
// failed verification (network, certificate or trust; "" otherwise).
type deploymentVerificationDTO struct {
	Level   int                 `json:"level"`
	Trust   *deploymentTrustDTO `json:"trust"`
	Failure string              `json:"failure"`
}

// deploymentTrustDTO is what the verification found about the served chains: trusted, untrusted (error says why and
// port where) or unchecked (an older helper answered without the chain); the trust store it checked against (system,
// acme_bundle or uploaded_root); enforced: the anchor was known, so an untrusted chain failed the deployment (a name
// mismatch never does).
type deploymentTrustDTO struct {
	Status   string `json:"status"`
	Error    string `json:"error"`
	Port     *int   `json:"port"`
	Store    string `json:"store"`
	Enforced bool   `json:"enforced"`
}

// verifyFailures are the kinds of the verification reasons (R51).
var verifyFailures = map[string]string{
	ErrDeployVerifyUnreachable.Reason: providers.VerifyFailureNetwork, ErrDeployVerifyFailed.Reason: providers.VerifyFailureCertificate,
	ErrDeployVerifyOther.Reason: providers.VerifyFailureCertificate, ErrDeployVerifyChain.Reason: providers.VerifyFailureCertificate,
	ErrDeployVerifyUntrusted.Reason: providers.VerifyFailureTrust,
}

// verificationJSON is d's verification evidence; values outside their closed lists read as not measured.
func verificationJSON(d inventory.Deployment) deploymentVerificationDTO {
	out := deploymentVerificationDTO{Level: d.Level, Failure: verifyFailures[d.ErrorCode]}
	if out.Failure == "" {
		out.Failure = verifyFailures[d.VerifyFailedReason]
	}
	if out.Level < providers.LevelNone || out.Level > providers.LevelTrusted {
		out.Level = providers.LevelNone
	}
	t := d.Trust
	if !slices.Contains([]string{providers.TrustTrusted, providers.TrustUntrusted, providers.TrustUnchecked}, t.Status) {
		return out
	}
	tr := deploymentTrustDTO{Status: t.Status, Store: codeOrBlank(t.Store), Enforced: t.Enforced}
	if slices.Contains(providers.TrustErrors, t.Error) {
		tr.Error = t.Error
	}
	if t.Port >= 1 && t.Port <= 65535 && tr.Error != "" {
		tr.Port = &t.Port
	}
	out.Trust = &tr
	return out
}

// deploymentDetailDTO is GET /deployments/{id}: the record and its steps in order.
type deploymentDetailDTO struct {
	deploymentDTO
	Steps []deploymentStepDTO `json:"steps"`
}

// codeValueRE is the shape of the fixed codes a deployment record and its steps carry (a step,
// phase, result, error class, verification mode). Anything else is shown as "".
var codeValueRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

func codeOrBlank(v string) string {
	if codeValueRE.MatchString(v) {
		return v
	}
	return ""
}

var (
	reasonValueRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}\.[a-z][a-z0-9_]{0,59}$`)
	hex64ValueRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// verifiedValues are deployments.verified's values.
	verifiedValues = []string{"", "remote", "local", "skipped"}
)

// stepParamRules are the step params the API shows (inventory keeps error, port, mode, served,
// reason, operation_id, trust and trust_error) with their value rule: an error class, a port, a
// verification mode, a served leaf's fingerprint, a verification reason code, the unfinished earlier
// change a recover_pending step put back, and the served chain's trust and its reason (R51). Any
// other key or value is dropped.
var stepParamRules = map[string]*regexp.Regexp{
	"error": codeValueRE, "port": paramPortRE, "mode": codeValueRE, "served": hex64ValueRE, "reason": reasonValueRE,
	"operation_id": paramOperationRE, "trust": paramTrustRE, "trust_error": paramTrustErrorRE,
	// R61 Ruling 16: a Windows verify step whose served chain is not the one Alice deployed (chain_differs "true") and
	// the two lengths: what Alice deployed and what Windows built.
	"chain_differs": paramTrueRE, "deployed_chain": chainLengthRE, "built_chain": chainLengthRE,
}

var (
	paramTrueRE   = regexp.MustCompile(`^true$`)
	chainLengthRE = regexp.MustCompile(`^[1-9][0-9]?$`)
)

func stepParams(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		rule, ok := stepParamRules[k]
		if !ok || !rule.MatchString(v) {
			continue
		}
		if k == "reason" && codeForReason(v) == ErrUnexpected {
			continue // an unregistered reason never reaches the UI as a raw key
		}
		out[k] = v
	}
	return out
}

// verifyReasons are the reasons whose text names the port probed ({{port}}).
var verifyReasons = []string{ErrDeployVerifyUnreachable.Reason, ErrDeployVerifyChain.Reason, ErrDeployVerifyUntrusted.Reason}

// refineReason splits a stored deployment.rollback_failed by what the record says happened: the
// files are back but the previous certificate was not confirmed (phase restored), or the restore
// was refused because another program had changed the files (error class file_changed). Every
// other reason is returned as it is.
func refineReason(reason, phase, helperError string) string {
	if reason != ErrDeployRollbackFailed.Reason {
		return reason
	}
	switch {
	case phase == providers.PhaseRestored:
		return ErrDeployRestoredUnverified.Reason
	case helperError == providers.DeployErrFileChanged:
		return ErrDeployRollbackFileChanged.Reason
	}
	return reason
}

// deploymentError renders a deployment's error: the stored reason (refined), its documented code
// and the allowlisted params. A verification reason gets the recorded port when its params lack
// it (a recovery records the rollback's params, not the verification's).
func deploymentError(d inventory.Deployment) *errorRefDTO {
	if d.ErrorCode == "" {
		return nil
	}
	reason := refineReason(d.ErrorCode, d.Phase, d.HelperError)
	params := providerParams(d.ErrorParams)
	if _, ok := params["port"]; !ok && d.VerifyFailedPort != nil && slices.Contains(verifyReasons, reason) {
		if params == nil {
			params = map[string]string{}
		}
		params["port"] = strconv.Itoa(*d.VerifyFailedPort)
	}
	return errorRef(reason, providerParams(params))
}

// verifyFailedJSON is the verification failure recorded before an outcome (its reason and port).
func verifyFailedJSON(d inventory.Deployment) *errorRefDTO {
	if d.VerifyFailedReason == "" {
		return nil
	}
	var params map[string]string
	if d.VerifyFailedPort != nil {
		params = map[string]string{"port": strconv.Itoa(*d.VerifyFailedPort)}
	}
	return errorRef(d.VerifyFailedReason, providerParams(params))
}

func backupDir(b *providers.BackupRef) string {
	if b == nil || !paramPathRE.MatchString(b.Dir) {
		return ""
	}
	return b.Dir
}

// backupCert is where a Windows deployment's previous certificate is (R61 Ruling 17): its store and SHA-1, each
// "" when unset or outside its rule.
func backupCert(b *providers.BackupRef) (store, sha1 string) {
	if b == nil {
		return "", ""
	}
	if paramStoreRE.MatchString(b.Store) {
		store = b.Store
	}
	if paramSHA1RE.MatchString(b.PreviousSHA1) {
		sha1 = b.PreviousSHA1
	}
	return store, sha1
}

func deploymentJSON(d inventory.Deployment) deploymentDTO {
	verified := d.Verified
	if !slices.Contains(verifiedValues, verified) {
		verified = ""
	}
	backupStore, backupSHA1 := backupCert(d.Backup)
	return deploymentDTO{
		ID: d.ID.String(), CertificateID: d.CertificateID.String(), CertificateName: d.CertificateName, LocationID: d.LocationID.String(),
		TargetID: d.TargetID.String(), TargetName: d.TargetName, CertPath: d.CertPath, KeyPath: d.KeyPath, JobID: idPtr(d.JobID),
		JobStatus: codeOrBlank(d.JobStatus), Trigger: codeOrBlank(d.Trigger), State: codeOrBlank(d.State), Status: codeOrBlank(d.Status),
		Result: codeOrBlank(d.Result), Phase: codeOrBlank(d.Phase), NewFingerprint: d.NewFingerprint,
		PreviousFingerprint: d.PreviousFingerprint, ConfirmIncompleteChain: d.ConfirmIncompleteChain, Verified: verified,
		VerifyFailed: verifyFailedJSON(d), Error: deploymentError(d), FailedStep: codeOrBlank(d.FailedStep),
		CauseStep: codeOrBlank(d.CauseStep), HelperError: codeOrBlank(d.HelperError), BackupDir: backupDir(d.Backup),
		BackupStore: backupStore, BackupSHA1: backupSHA1, RequestedBy: idPtr(d.RequestedBy), RequestedByName: d.RequestedByName, RecoveryAttempts: d.RecoveryAttempts,
		RecoverAfter: utcPtr(d.RecoverAfter), CreatedAt: d.CreatedAt.UTC(), StartedAt: utcPtr(d.StartedAt), FinishedAt: utcPtr(d.FinishedAt),
		Source: deploymentSource(d), BindingID: idPtr(d.BindingID), KVVersion: versionOrBlank(d.KVVersion), VaultName: d.VaultName,
		Verification: verificationJSON(d),
	}
}

// deploymentSource is "key_vault" for a deployment of a vault version, "acme" for one of a certificate ordered from a
// certificate authority and "upload" for any other.
func deploymentSource(d inventory.Deployment) string {
	switch d.Source {
	case "key_vault", "acme":
		return d.Source
	}
	return "upload"
}

func deploymentDetailJSON(d inventory.Deployment) deploymentDetailDTO {
	out := deploymentDetailDTO{deploymentDTO: deploymentJSON(d), Steps: make([]deploymentStepDTO, 0, len(d.Steps))}
	for _, st := range d.Steps {
		out.Steps = append(out.Steps, deploymentStepDTO{N: st.N, Name: codeOrBlank(st.Name), Status: codeOrBlank(st.Status), At: st.At.UTC(),
			Params: stepParams(st.Params)})
	}
	return out
}

type webServerFactsDTO struct {
	Software          string `json:"software"`
	Version           string `json:"version"`
	ConfPath          string `json:"conf_path"`
	ConfigValid       bool   `json:"config_valid"`
	ConfigError       string `json:"config_error"`
	ConfigErrorReason string `json:"config_error_reason"`
	ConfigErrorFile   string `json:"config_error_file"`
	Found             bool   `json:"found"`
}

func webServerFactsJSON(n *providers.WebServerFacts) *webServerFactsDTO {
	if n == nil {
		return nil
	}
	return &webServerFactsDTO{Software: n.Software, Version: n.Version, ConfPath: n.ConfPath, ConfigValid: n.ConfigValid, ConfigError: codeOrBlank(n.ConfigError),
		ConfigErrorReason: codeOrBlank(n.ConfigErrorReason), ConfigErrorFile: n.ConfigErrorFile, Found: n.Found}
}
