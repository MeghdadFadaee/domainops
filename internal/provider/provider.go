package provider

import (
	"context"
	"errors"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

// CredentialVerificationAuthoritative is implemented by provider errors that
// prove the configured credential itself is unusable (for example, an
// authentication rejection). Transport failures, rate limits, server errors,
// and malformed responses must not implement this contract: they say nothing
// authoritative about a credential that was previously valid.
type CredentialVerificationAuthoritative interface {
	CredentialVerificationAuthoritative() bool
}

// AccessDenialAuthoritative is implemented only by provider errors that prove
// access to a specific resource is denied. It must not be implemented by rate
// limits, server failures, transport errors, or ambiguous responses.
type AccessDenialAuthoritative interface {
	AccessDenialAuthoritative() bool
}

// CredentialFailureIsAuthoritative reports whether a failed verification can
// safely transition a credential to invalid. Unknown errors are deliberately
// treated as transient so a healthy credential is not disabled during an
// upstream outage.
func CredentialFailureIsAuthoritative(err error) bool {
	var classified CredentialVerificationAuthoritative
	return errors.As(err, &classified) && classified.CredentialVerificationAuthoritative()
}

func AccessFailureIsAuthoritative(err error) bool {
	var classified AccessDenialAuthoritative
	return errors.As(err, &classified) && classified.AccessDenialAuthoritative()
}

type Auth struct {
	CredentialID string
	Token        string
	Kind         domain.CredentialKind
	AccountID    string
}

type Capabilities struct {
	ZoneRead bool     `json:"zone_read"`
	DNSRead  bool     `json:"dns_read"`
	DNSWrite bool     `json:"dns_write"`
	TLSRead  bool     `json:"tls_read"`
	TLSWrite bool     `json:"tls_write"`
	Names    []string `json:"names"`
}

type Verification struct {
	Status       domain.CredentialStatus `json:"status"`
	Capabilities Capabilities            `json:"capabilities"`
	Accounts     []domain.RemoteAccount  `json:"accounts,omitempty"`
}

type PageRequest struct {
	Cursor  string
	Page    int
	PerPage int
	Search  string
}

type ZonePage struct {
	Zones      []domain.Zone
	NextCursor string
	Page       int
	TotalPages int
}

type RecordPage struct {
	Records    []domain.DNSRecord
	NextCursor string
	Page       int
	TotalPages int
}

type CredentialVerifier interface {
	VerifyCredential(context.Context, Auth) (Verification, error)
}

type ZoneInventory interface {
	ListZones(context.Context, Auth, PageRequest) (ZonePage, error)
}

type DNSRecordService interface {
	ListDNSRecords(context.Context, Auth, string, PageRequest) (RecordPage, error)
	GetDNSRecord(context.Context, Auth, string, string) (domain.DNSRecord, error)
	CreateDNSRecord(context.Context, Auth, string, domain.DNSRecord) (domain.DNSRecord, error)
	PatchDNSRecord(context.Context, Auth, string, string, domain.DNSRecord) (domain.DNSRecord, error)
	DeleteDNSRecord(context.Context, Auth, string, string) error
}

type DNSBatchService interface {
	ApplyDNSBatch(context.Context, Auth, string, []domain.DNSMutation) ([]domain.DNSRecord, error)
}

type DNS01Solver interface {
	PresentDNS01(context.Context, Auth, string, string, string, string) (string, error)
	CleanupDNS01(context.Context, Auth, string, string) error
}

// DNS01Reconciler is an optional recovery capability for a provider that can
// locate a challenge after an ambiguous create response. Implementations must
// match the exact owner, job marker, and value hash and reject ambiguity.
type DNS01Reconciler interface {
	ReconcileDNS01(context.Context, Auth, string, string, string, string) (recordID string, found bool, err error)
}

type EdgeTLSService interface {
	GetEdgeTLSSettings(context.Context, Auth, string) (domain.EdgeTLSSettings, error)
	UpdateEdgeTLSSettings(context.Context, Auth, string, domain.EdgeTLSSettings, domain.EdgeTLSSettings) (domain.EdgeTLSSettings, error)
	ListEdgeCertificates(context.Context, Auth, string, PageRequest) ([]domain.EdgeCertificate, error)
}

type CloudProvider interface {
	CredentialVerifier
	ZoneInventory
	DNSRecordService
	DNSBatchService
	DNS01Solver
	EdgeTLSService
}
