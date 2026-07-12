package domain

import (
	"encoding/json"
	"time"
)

const ProviderCloudflare = "cloudflare"

type CredentialKind string

const (
	CredentialUserToken    CredentialKind = "user_token"
	CredentialAccountToken CredentialKind = "account_token"
)

type CredentialStatus string

const (
	CredentialUnknown CredentialStatus = "unknown"
	CredentialValid   CredentialStatus = "valid"
	CredentialInvalid CredentialStatus = "invalid"
)

type Credential struct {
	ID             string           `json:"id"`
	Provider       string           `json:"provider"`
	Label          string           `json:"label"`
	Kind           CredentialKind   `json:"kind"`
	AccountHint    string           `json:"account_hint,omitempty"`
	SecretRef      string           `json:"-"`
	Status         CredentialStatus `json:"status"`
	Capabilities   []string         `json:"capabilities,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	LastVerifiedAt *time.Time       `json:"last_verified_at,omitempty"`
	LastError      string           `json:"last_error,omitempty"`
}

type RemoteAccount struct {
	ID           string     `json:"id"`
	Provider     string     `json:"provider"`
	ProviderID   string     `json:"provider_id"`
	Name         string     `json:"name"`
	CreatedAt    time.Time  `json:"created_at"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
}

type AccountCredential struct {
	AccountID    string `json:"account_id"`
	CredentialID string `json:"credential_id"`
	Preferred    bool   `json:"preferred"`
}

type ZoneStatus string

const (
	ZoneActive       ZoneStatus = "active"
	ZonePending      ZoneStatus = "pending"
	ZoneInitializing ZoneStatus = "initializing"
	ZoneMoved        ZoneStatus = "moved"
	ZoneDeactivated  ZoneStatus = "deactivated"
	ZoneUnknown      ZoneStatus = "unknown"
)

type Zone struct {
	ID                    string     `json:"id"`
	Provider              string     `json:"provider"`
	ProviderID            string     `json:"provider_id"`
	AccountID             string     `json:"account_id"`
	PreferredCredentialID string     `json:"preferred_credential_id"`
	Name                  string     `json:"name"`
	UnicodeName           string     `json:"unicode_name,omitempty"`
	Status                ZoneStatus `json:"status"`
	Paused                bool       `json:"paused"`
	Plan                  string     `json:"plan,omitempty"`
	NameServers           []string   `json:"name_servers,omitempty"`
	ModifiedAt            *time.Time `json:"modified_at,omitempty"`
	LastSyncedAt          *time.Time `json:"last_synced_at,omitempty"`
}

type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
	RecordTXT   RecordType = "TXT"
	RecordMX    RecordType = "MX"
	RecordCAA   RecordType = "CAA"
	RecordNS    RecordType = "NS"
	RecordSRV   RecordType = "SRV"
)

func (t RecordType) Editable() bool {
	switch t {
	case RecordA, RecordAAAA, RecordCNAME, RecordTXT, RecordMX, RecordCAA, RecordNS, RecordSRV:
		return true
	default:
		return false
	}
}

type DNSRecord struct {
	ID           string          `json:"id"`
	ProviderID   string          `json:"provider_id"`
	ZoneID       string          `json:"zone_id"`
	Type         RecordType      `json:"type"`
	Name         string          `json:"name"`
	UnicodeName  string          `json:"unicode_name,omitempty"`
	Content      string          `json:"content,omitempty"`
	Priority     *uint16         `json:"priority,omitempty"`
	TTL          int             `json:"ttl"`
	Proxied      bool            `json:"proxied"`
	Proxiable    bool            `json:"proxiable"`
	Comment      string          `json:"comment,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Managed      bool            `json:"managed"`
	Data         json.RawMessage `json:"data,omitempty"`
	Raw          json.RawMessage `json:"raw,omitempty"`
	ModifiedAt   *time.Time      `json:"modified_at,omitempty"`
	LastSyncedAt *time.Time      `json:"last_synced_at,omitempty"`
}

type DNSMutationKind string

const (
	MutationCreate  DNSMutationKind = "create"
	MutationPatch   DNSMutationKind = "patch"
	MutationReplace DNSMutationKind = "replace"
	MutationDelete  DNSMutationKind = "delete"
)

type DNSMutation struct {
	Kind     DNSMutationKind `json:"kind"`
	RecordID string          `json:"record_id,omitempty"`
	Before   *DNSRecord      `json:"before,omitempty"`
	After    *DNSRecord      `json:"after,omitempty"`
}

type EdgeTLSSettings struct {
	ZoneID         string     `json:"zone_id"`
	Mode           string     `json:"mode"`
	AlwaysUseHTTPS bool       `json:"always_use_https"`
	MinimumTLS     string     `json:"minimum_tls"`
	TLS13          bool       `json:"tls_1_3"`
	HasProxiedDNS  bool       `json:"has_proxied_dns"`
	LastSyncedAt   *time.Time `json:"last_synced_at,omitempty"`
}

type EdgeCertificate struct {
	ID        string     `json:"id"`
	ZoneID    string     `json:"zone_id"`
	Type      string     `json:"type"`
	Status    string     `json:"status"`
	Hosts     []string   `json:"hosts"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type CertificateSource string

const (
	CertificateManaged  CertificateSource = "managed"
	CertificateImported CertificateSource = "imported_metadata"
)

type KeyAlgorithm string

const (
	KeyECDSAP256 KeyAlgorithm = "EC256"
	KeyRSA2048   KeyAlgorithm = "RSA2048"
)

type CertificateLineage struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ZoneID           string            `json:"zone_id,omitempty"`
	Source           CertificateSource `json:"source"`
	Identifiers      []string          `json:"identifiers"`
	KeyAlgorithm     KeyAlgorithm      `json:"key_algorithm"`
	Profile          string            `json:"profile"`
	ACMEAccountID    string            `json:"acme_account_id,omitempty"`
	CurrentVersionID string            `json:"current_version_id,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

type CertificateVersion struct {
	ID                  string     `json:"id"`
	LineageID           string     `json:"lineage_id"`
	SerialNumber        string     `json:"serial_number"`
	FingerprintSHA256   string     `json:"fingerprint_sha256"`
	Issuer              string     `json:"issuer"`
	Identifiers         []string   `json:"identifiers"`
	NotBefore           time.Time  `json:"not_before"`
	NotAfter            time.Time  `json:"not_after"`
	CertificatePath     string     `json:"certificate_path"`
	ChainPath           string     `json:"chain_path,omitempty"`
	PrivateKeyRef       string     `json:"-"`
	RenewalWindowStart  *time.Time `json:"renewal_window_start,omitempty"`
	RenewalWindowEnd    *time.Time `json:"renewal_window_end,omitempty"`
	RevocationPendingAt *time.Time `json:"revocation_pending_at,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevocationReason    *uint      `json:"revocation_reason,omitempty"`
	ExportedAt          *time.Time `json:"exported_at,omitempty"`
	ExportPath          string     `json:"export_path,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

type CertificateCommitIntent struct {
	VersionID    string    `json:"version_id"`
	LineageID    string    `json:"lineage_id"`
	SecretRef    string    `json:"-"`
	ArtifactPath string    `json:"artifact_path"`
	CreatedAt    time.Time `json:"created_at"`
}

type ACMEAccount struct {
	ID           string    `json:"id"`
	Environment  string    `json:"environment"`
	DirectoryURL string    `json:"directory_url"`
	Email        string    `json:"email"`
	Registration string    `json:"registration"`
	SecretRef    string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type ACMEAccountCommitIntent struct {
	AccountID string    `json:"account_id"`
	SecretRef string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type ObservedEndpoint struct {
	ID                string     `json:"id"`
	ZoneID            string     `json:"zone_id"`
	Host              string     `json:"host"`
	Port              int        `json:"port"`
	Enabled           bool       `json:"enabled"`
	LastCheckedAt     *time.Time `json:"last_checked_at,omitempty"`
	ResolvedAddresses []string   `json:"resolved_addresses,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	ValidForHost      bool       `json:"valid_for_host"`
	Trusted           bool       `json:"trusted"`
	LastError         string     `json:"last_error,omitempty"`
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type HealthIssue struct {
	ID         string    `json:"id"`
	Severity   Severity  `json:"severity"`
	Kind       string    `json:"kind"`
	ResourceID string    `json:"resource_id"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail"`
	Action     string    `json:"action,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type JobState string

const (
	JobQueued        JobState = "queued"
	JobRunning       JobState = "running"
	JobWaitingForDNS JobState = "waiting_for_dns"
	JobSucceeded     JobState = "succeeded"
	JobFailed        JobState = "failed"
	JobCancelled     JobState = "cancelled"
)

type Job struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	State      JobState        `json:"state"`
	ResourceID string          `json:"resource_id,omitempty"`
	Progress   int             `json:"progress"`
	Message    string          `json:"message,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Error      string          `json:"error,omitempty"`
	RetryAt    *time.Time      `json:"retry_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type ChallengeJournal struct {
	ID           string     `json:"id"`
	JobID        string     `json:"job_id"`
	CredentialID string     `json:"credential_id,omitempty"`
	ZoneID       string     `json:"zone_id"`
	RecordID     string     `json:"record_id,omitempty"`
	FQDN         string     `json:"fqdn"`
	ValueHash    string     `json:"value_hash"`
	CreatedAt    time.Time  `json:"created_at"`
	CleanedAt    *time.Time `json:"cleaned_at,omitempty"`
}

type AuditEvent struct {
	ID         string          `json:"id"`
	Actor      string          `json:"actor"`
	Action     string          `json:"action"`
	ResourceID string          `json:"resource_id,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

type DashboardSnapshot struct {
	GeneratedAt         time.Time     `json:"generated_at"`
	Credentials         int           `json:"credentials"`
	Accounts            int           `json:"accounts"`
	Zones               int           `json:"zones"`
	DNSRecords          int           `json:"dns_records"`
	Certificates        int           `json:"certificates"`
	CertificatesDue     int           `json:"certificates_due"`
	CertificatesExpired int           `json:"certificates_expired"`
	ActiveJobs          int           `json:"active_jobs"`
	Issues              []HealthIssue `json:"issues"`
}
