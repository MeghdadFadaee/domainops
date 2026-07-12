package store

import (
	"context"
	"errors"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

// ErrACMEAccountConflict means an ACME environment already has an account.
// Account registration is insert-only because replacing the account ID would
// strand certificate lineages and leave the previous account key unreferenced.
var ErrACMEAccountConflict = errors.New("store: ACME account environment already registered")

type Repository interface {
	Close() error
	Migrate(context.Context) error

	SaveCredential(context.Context, domain.Credential) error
	ListCredentials(context.Context) ([]domain.Credential, error)
	GetCredential(context.Context, string) (domain.Credential, error)
	DeleteCredential(context.Context, string) error
	SaveCredentialZoneCapability(context.Context, string, string, string, time.Time) error
	HasCredentialZoneCapability(context.Context, string, string, string) (bool, error)
	GetCredentialZoneCapability(context.Context, string, string, string) (time.Time, bool, error)
	InvalidateCredentialZoneCapability(context.Context, string, string, string) error

	SaveAccounts(context.Context, []domain.RemoteAccount, []domain.AccountCredential) error
	ListAccounts(context.Context) ([]domain.RemoteAccount, error)
	SaveZones(context.Context, []domain.Zone) error
	ListZones(context.Context) ([]domain.Zone, error)
	GetZone(context.Context, string) (domain.Zone, error)

	ReplaceDNSRecords(context.Context, string, []domain.DNSRecord, time.Time) error
	ListDNSRecords(context.Context, string) ([]domain.DNSRecord, error)
	SaveDNSRecord(context.Context, domain.DNSRecord) error
	DeleteDNSRecord(context.Context, string) error

	SaveTLSSettings(context.Context, domain.EdgeTLSSettings) error
	GetTLSSettings(context.Context, string) (domain.EdgeTLSSettings, error)

	SaveACMEAccount(context.Context, domain.ACMEAccount) error
	CommitACMEAccount(context.Context, domain.ACMEAccount) error
	GetACMEAccountByEnvironment(context.Context, string) (domain.ACMEAccount, error)
	SaveACMEAccountCommitIntent(context.Context, domain.ACMEAccountCommitIntent) error
	ListACMEAccountCommitIntents(context.Context) ([]domain.ACMEAccountCommitIntent, error)
	DeleteACMEAccountCommitIntent(context.Context, string) error
	SaveCertificateLineage(context.Context, domain.CertificateLineage) error
	SaveCertificateVersion(context.Context, domain.CertificateVersion) error
	CommitCertificateVersion(context.Context, domain.CertificateLineage, domain.CertificateVersion) error
	SaveCertificateCommitIntent(context.Context, domain.CertificateCommitIntent) error
	ListCertificateCommitIntents(context.Context) ([]domain.CertificateCommitIntent, error)
	DeleteCertificateCommitIntent(context.Context, string) error
	ListCertificateLineages(context.Context) ([]domain.CertificateLineage, error)
	ListCertificateVersions(context.Context, string) ([]domain.CertificateVersion, error)
	GetCertificateLineage(context.Context, string) (domain.CertificateLineage, error)

	SaveEndpoint(context.Context, domain.ObservedEndpoint) error
	ListEndpoints(context.Context) ([]domain.ObservedEndpoint, error)
	SaveHealthIssues(context.Context, string, []domain.HealthIssue) error
	ListHealthIssues(context.Context) ([]domain.HealthIssue, error)

	SaveJob(context.Context, domain.Job) error
	GetJob(context.Context, string) (domain.Job, error)
	ListJobs(context.Context, int) ([]domain.Job, error)
	ListRecoverableJobs(context.Context) ([]domain.Job, error)
	ReconcileInterruptedJobs(context.Context, time.Time) (int64, error)
	SaveChallenge(context.Context, domain.ChallengeJournal) error
	ListOpenChallenges(context.Context) ([]domain.ChallengeJournal, error)
	MarkChallengeCleaned(context.Context, string, time.Time) error
	AppendAudit(context.Context, domain.AuditEvent) error
	ListAudit(context.Context, int) ([]domain.AuditEvent, error)

	Dashboard(context.Context, time.Time) (domain.DashboardSnapshot, error)
}

type SecretStore interface {
	// Put may return a non-empty reference together with an error when an
	// atomic secret-file replacement committed but its final durability check
	// failed. Callers must compensate that reference before abandoning metadata.
	Put(context.Context, string, []byte) (string, error)
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
	Locked() bool
	Unlock(context.Context, []byte) error
	Lock()
}
