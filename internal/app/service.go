package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
	"github.com/MeghdadFadaee/domainops/internal/provider"
	"github.com/MeghdadFadaee/domainops/internal/store"
	"golang.org/x/net/idna"
	"golang.org/x/sync/errgroup"
)

type Event struct {
	Kind    string      `json:"kind"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

type AddCredentialInput struct {
	Label     string
	Token     string
	Kind      domain.CredentialKind
	AccountID string
}

var (
	ErrDNSConflict = errors.New("DNS record changed remotely; synchronize and review before retrying")
	// ErrDNSMutationOutcomeUnknown means the provider may have applied a write
	// even though its response did not prove success or rejection. Retrying the
	// same request can create a duplicate or overwrite a newer value.
	ErrDNSMutationOutcomeUnknown = errors.New("DNS mutation outcome is unknown; do not retry without reviewing provider state")
	// ErrDNSMutationAppliedButUnreconciled means the provider confirmed the
	// mutation, but DomainOps could not refresh its local view completely.
	ErrDNSMutationAppliedButUnreconciled = errors.New("DNS mutation was applied at the provider but local reconciliation failed; do not retry")
	ErrTLSConflict                       = errors.New("Cloudflare TLS settings changed remotely; refresh and review before retrying")
	ErrTLSMutationOutcomeUnknown         = errors.New("Cloudflare TLS update outcome is unknown; review the refreshed state before retrying")
	ErrTLSMutationAppliedButUnreconciled = errors.New("Cloudflare TLS update was applied but local reconciliation failed; do not retry")
	ErrRecoveryRequired                  = errors.New("crash recovery requires attention; mutations are disabled until vault recovery succeeds")
)

const recoveryHealthOwner = "certificate-commit-recovery"

// RecoveryWarning means the vault was unlocked but crash recovery could not
// complete safely. Headless mutations should stop; interactive clients may
// continue in read-only/navigation mode while displaying the persisted issue.
type RecoveryWarning struct{ Err error }

func (e *RecoveryWarning) Error() string {
	return "vault unlocked, but recovery requires attention: " + e.Err.Error()
}
func (e *RecoveryWarning) Unwrap() error  { return e.Err }
func (e *RecoveryWarning) NonFatal() bool { return true }

func IsRecoveryWarning(err error) bool {
	var warning *RecoveryWarning
	return errors.As(err, &warning)
}

const (
	replacementWriteEvidenceMaxAge = 15 * time.Minute
	dnsMutationReconcileTimeout    = 30 * time.Second
)

type DNSBatchPlan struct {
	ZoneID    string               `json:"zone_id"`
	ZoneName  string               `json:"zone_name"`
	Mutations []domain.DNSMutation `json:"mutations"`
}

type DNSBatchResult struct {
	Plan           DNSBatchPlan       `json:"plan"`
	Applied        bool               `json:"applied"`
	OutcomeUnknown bool               `json:"outcome_unknown,omitempty"`
	Records        []domain.DNSRecord `json:"records,omitempty"`
}

type plannedDNSBatch struct {
	plan  DNSBatchPlan
	zone  domain.Zone
	cloud provider.Provider
	batch provider.DNSBatchService
	auth  provider.Auth
}

type Service struct {
	repo               store.Repository
	secrets            store.SecretStore
	providers          map[string]provider.Provider
	now                func() time.Time
	events             chan Event
	healthCheck        func(context.Context) error
	unlockHook         func(context.Context) error
	certificateService *CertificateService
	recoveryBlocked    atomic.Bool
}

var (
	_ provider.DNS01Solver     = (*Service)(nil)
	_ provider.DNS01Reconciler = (*Service)(nil)
)

func New(repo store.Repository, secrets store.SecretStore) *Service {
	return &Service{
		repo:      repo,
		secrets:   secrets,
		providers: make(map[string]provider.Provider),
		now:       time.Now,
		events:    make(chan Event, 128),
	}
}

func (s *Service) RegisterProvider(name string, value provider.Provider) {
	s.providers[name] = value
}

func (s *Service) Events() <-chan Event           { return s.events }
func (s *Service) Repository() store.Repository   { return s.repo }
func (s *Service) SecretStore() store.SecretStore { return s.secrets }
func (s *Service) VaultLocked() bool              { return s.secrets.Locked() }
func (s *Service) UnlockVault(ctx context.Context, passphrase []byte) error {
	if err := s.secrets.Unlock(ctx, passphrase); err != nil {
		return err
	}
	if s.unlockHook != nil {
		if err := s.unlockHook(ctx); err != nil {
			s.recoveryBlocked.Store(true)
			now := s.now().UTC()
			issue := domain.HealthIssue{
				ID:         stableID("health", recoveryHealthOwner),
				Severity:   domain.SeverityCritical,
				Kind:       "certificate_commit_recovery_failed",
				ResourceID: recoveryHealthOwner,
				Title:      "Crash recovery requires attention",
				Detail:     err.Error(),
				Action:     "Restart DomainOps and unlock the vault again to retry recovery; inspect the recovery journals if the warning persists.",
				ObservedAt: now,
			}
			persistErr := s.repo.SaveHealthIssues(context.WithoutCancel(ctx), recoveryHealthOwner, []domain.HealthIssue{issue})
			if persistErr != nil {
				persistErr = fmt.Errorf("persist recovery health issue: %w", persistErr)
			}
			warningErr := errors.Join(err, persistErr)
			warning := &RecoveryWarning{Err: warningErr}
			s.publish(Event{Kind: "recovery.warning", Message: warning.Error()})
			return warning
		}
		if err := s.repo.SaveHealthIssues(context.WithoutCancel(ctx), recoveryHealthOwner, nil); err != nil {
			s.recoveryBlocked.Store(true)
			warning := &RecoveryWarning{Err: fmt.Errorf("clear recovery health issue: %w", err)}
			s.publish(Event{Kind: "recovery.warning", Message: warning.Error()})
			return warning
		}
		s.recoveryBlocked.Store(false)
	}
	return nil
}
func (s *Service) LockVault()                                       { s.secrets.Lock() }
func (s *Service) SetHealthCheck(check func(context.Context) error) { s.healthCheck = check }
func (s *Service) SetUnlockHook(hook func(context.Context) error)   { s.unlockHook = hook }
func (s *Service) SetCertificateService(service *CertificateService) {
	s.certificateService = service
	if service != nil {
		service.JobObserver = func(job domain.Job) {
			s.publish(Event{Kind: "certificate.progress", Message: job.Message, Value: job})
		}
	}
}

func (s *Service) ResolveCredential(ctx context.Context, credentialID string) (provider.Auth, error) {
	credential, err := s.repo.GetCredential(ctx, credentialID)
	if err != nil {
		return provider.Auth{}, err
	}
	return s.auth(ctx, credential)
}

// PresentDNS01, CleanupDNS01, and ReconcileDNS01 make Service the provider
// router used by the ACME engine and crash recovery. Routing is based only on
// the provider identity bound into Auth; remote zone IDs are not globally
// unique and must never select a provider implicitly.
func (s *Service) PresentDNS01(ctx context.Context, auth provider.Auth, zoneID, fqdn, value, jobID string) (string, error) {
	p, err := s.dns01Provider(auth)
	if err != nil {
		return "", err
	}
	return p.PresentDNS01(ctx, auth, zoneID, fqdn, value, jobID)
}

func (s *Service) CleanupDNS01(ctx context.Context, auth provider.Auth, zoneID, recordID string) error {
	p, err := s.dns01Provider(auth)
	if err != nil {
		return err
	}
	return p.CleanupDNS01(ctx, auth, zoneID, recordID)
}

func (s *Service) ReconcileDNS01(ctx context.Context, auth provider.Auth, zoneID, fqdn, valueHash, jobID string) (string, bool, error) {
	p, err := s.dns01Provider(auth)
	if err != nil {
		return "", false, err
	}
	reconciler, ok := p.(provider.DNS01Reconciler)
	if !ok {
		return "", false, provider.Unsupported(auth.Provider, "DNS-01 reconciliation")
	}
	return reconciler.ReconcileDNS01(ctx, auth, zoneID, fqdn, valueHash, jobID)
}

func (s *Service) dns01Provider(auth provider.Auth) (provider.Provider, error) {
	providerName := strings.TrimSpace(auth.Provider)
	if providerName == "" {
		return nil, errors.New("DNS-01 credential has no provider identity")
	}
	p, ok := s.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("DNS-01 provider %q is not registered", providerName)
	}
	return p, nil
}

func (s *Service) IssueCertificates(ctx context.Context, request IssueZonesRequest) (IssueZonesResult, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return IssueZonesResult{}, err
	}
	if s.certificateService == nil {
		return IssueZonesResult{}, errors.New("certificate service is not configured")
	}
	return s.certificateService.IssueZones(ctx, request)
}

func (s *Service) ImportCertificateMetadata(ctx context.Context, path, name, zoneID string) (domain.CertificateLineage, domain.CertificateVersion, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, err
	}
	if s.certificateService == nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, errors.New("certificate service is not configured")
	}
	return s.certificateService.ImportMetadata(ctx, path, name, zoneID)
}

func (s *Service) ExportCertificate(ctx context.Context, lineageID, destination string) (string, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return "", err
	}
	if s.certificateService == nil {
		return "", errors.New("certificate service is not configured")
	}
	result, err := s.certificateService.Export(ctx, lineageID, destination)
	return result.VersionDirectory, err
}

func (s *Service) RevokeCertificate(ctx context.Context, lineageID, environment, confirmation string, reason *uint) error {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return err
	}
	if s.certificateService == nil {
		return errors.New("certificate service is not configured")
	}
	return s.certificateService.Revoke(ctx, lineageID, environment, confirmation, reason)
}

func (s *Service) RenewCertificates(ctx context.Context, environment string, confirmProduction bool) (IssueZonesResult, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return IssueZonesResult{}, err
	}
	if s.certificateService == nil {
		return IssueZonesResult{}, errors.New("certificate service is not configured")
	}
	return s.certificateService.RenewDue(ctx, environment, confirmProduction)
}

func (s *Service) publish(event Event) {
	select {
	case s.events <- event:
	default:
	}
}

func (s *Service) Dashboard(ctx context.Context) (domain.DashboardSnapshot, error) {
	return s.repo.Dashboard(ctx, s.now().UTC())
}

func (s *Service) Credentials(ctx context.Context) ([]domain.Credential, error) {
	return s.repo.ListCredentials(ctx)
}

func (s *Service) Accounts(ctx context.Context) ([]domain.RemoteAccount, error) {
	return s.repo.ListAccounts(ctx)
}

func (s *Service) Zones(ctx context.Context) ([]domain.Zone, error) {
	return s.repo.ListZones(ctx)
}

func (s *Service) DNSRecords(ctx context.Context, zoneID string) ([]domain.DNSRecord, error) {
	return s.repo.ListDNSRecords(ctx, zoneID)
}

func (s *Service) SetZonePreferredCredential(ctx context.Context, zoneID, credentialID string) (domain.Zone, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return domain.Zone{}, err
	}
	zone, err := s.repo.GetZone(ctx, zoneID)
	if err != nil {
		return domain.Zone{}, err
	}
	credential, err := s.repo.GetCredential(ctx, credentialID)
	if err != nil {
		return domain.Zone{}, err
	}
	if credential.Provider != zone.Provider || credential.Status != domain.CredentialValid {
		return domain.Zone{}, errors.New("credential provider/status is not valid for this zone")
	}
	cloud, ok := s.providers[credential.Provider]
	if !ok {
		return domain.Zone{}, fmt.Errorf("provider %q is not registered", credential.Provider)
	}
	auth, err := s.auth(ctx, credential)
	if err != nil {
		return domain.Zone{}, err
	}
	// A zone-list result is not DNS authority: Cloudflare policies can expose a
	// zone while denying its records. Probe this exact zone and persist the
	// successful observation before changing routing.
	if _, err := cloud.ListDNSRecords(ctx, auth, zone.ProviderID, provider.PageRequest{Page: 1, PerPage: 1}); err != nil {
		return domain.Zone{}, fmt.Errorf("verify credential DNS-read access to %s: %w", zone.Name, err)
	}
	if err := s.ObserveCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read"); err != nil {
		return domain.Zone{}, fmt.Errorf("record credential DNS-read access to %s: %w", zone.Name, err)
	}
	before := zone
	zone.PreferredCredentialID = credential.ID
	if err := s.repo.SaveZones(ctx, []domain.Zone{zone}); err != nil {
		return domain.Zone{}, err
	}
	s.audit(ctx, "zone.preferred_credential", zone.ID, before, zone)
	return zone, nil
}

func (s *Service) Certificates(ctx context.Context) ([]domain.CertificateLineage, error) {
	return s.repo.ListCertificateLineages(ctx)
}

func (s *Service) Jobs(ctx context.Context, limit int) ([]domain.Job, error) {
	return s.repo.ListJobs(ctx, limit)
}

// ReconcileInterruptedJobs is the final startup/unlock recovery step. Durable
// certificate and DNS-01 journals must be reconciled before calling it so the
// associated jobs remain visible until their external side effects are safe.
func (s *Service) ReconcileInterruptedJobs(ctx context.Context) error {
	count, err := s.repo.ReconcileInterruptedJobs(ctx, s.now().UTC())
	if err != nil {
		return err
	}
	if count > 0 {
		s.publish(Event{Kind: "job.interrupted", Message: fmt.Sprintf("Marked %d interrupted jobs as failed", count), Value: count})
	}
	return nil
}

func (s *Service) Audit(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	return s.repo.ListAudit(ctx, limit)
}

func (s *Service) AddCloudflareCredential(ctx context.Context, input AddCredentialInput) (domain.Credential, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return domain.Credential{}, err
	}
	if strings.TrimSpace(input.Token) == "" {
		return domain.Credential{}, errors.New("Cloudflare API token is required")
	}
	if input.Kind == "" {
		input.Kind = domain.CredentialUserToken
	}
	if input.Kind == domain.CredentialAccountToken && strings.TrimSpace(input.AccountID) == "" {
		return domain.Credential{}, errors.New("Cloudflare account ID is required for an account token")
	}
	p, ok := s.providers[domain.ProviderCloudflare]
	if !ok {
		return domain.Credential{}, errors.New("Cloudflare provider is not registered")
	}

	id := identifier.New("cred")
	auth := provider.Auth{Provider: domain.ProviderCloudflare, CredentialID: id, Token: strings.TrimSpace(input.Token), Kind: input.Kind, AccountID: strings.TrimSpace(input.AccountID)}
	verification, err := p.VerifyCredential(ctx, auth)
	if err != nil {
		return domain.Credential{}, fmt.Errorf("verify Cloudflare credential: %w", err)
	}
	knownAccounts := make(map[string]struct{})
	if len(verification.Accounts) > 0 {
		existingAccounts, listErr := s.repo.ListAccounts(ctx)
		if listErr != nil {
			return domain.Credential{}, listErr
		}
		for _, account := range existingAccounts {
			knownAccounts[account.ID] = struct{}{}
		}
	}
	secretRef, err := s.secrets.Put(ctx, "", []byte(auth.Token))
	if err != nil {
		var cleanupErr error
		if secretRef != "" {
			cleanupErr = compensateSecretDelete(context.WithoutCancel(ctx), s.secrets, secretRef)
			if cleanupErr != nil {
				cleanupErr = fmt.Errorf("remove possibly committed credential secret: %w", cleanupErr)
			}
		}
		return domain.Credential{}, errors.Join(fmt.Errorf("store Cloudflare credential: %w", err), cleanupErr)
	}

	now := s.now().UTC()
	label := strings.TrimSpace(input.Label)
	if label == "" {
		label = "Cloudflare"
	}
	credential := domain.Credential{
		ID:             id,
		Provider:       domain.ProviderCloudflare,
		Label:          label,
		Kind:           input.Kind,
		AccountHint:    auth.AccountID,
		SecretRef:      secretRef,
		Status:         verification.Status,
		Capabilities:   append([]string(nil), verification.Capabilities.Names...),
		CreatedAt:      now,
		LastVerifiedAt: &now,
	}
	if err := s.repo.SaveCredential(ctx, credential); err != nil {
		_ = s.secrets.Delete(ctx, secretRef)
		return domain.Credential{}, err
	}

	if len(verification.Accounts) > 0 {
		links := make([]domain.AccountCredential, 0, len(verification.Accounts))
		for i := range verification.Accounts {
			normalizeAccount(&verification.Accounts[i], domain.ProviderCloudflare)
			_, known := knownAccounts[verification.Accounts[i].ID]
			links = append(links, domain.AccountCredential{AccountID: verification.Accounts[i].ID, CredentialID: id, Preferred: !known})
		}
		if err := s.repo.SaveAccounts(ctx, verification.Accounts, links); err != nil {
			_ = s.repo.DeleteCredential(context.WithoutCancel(ctx), credential.ID)
			_ = s.secrets.Delete(context.WithoutCancel(ctx), secretRef)
			return domain.Credential{}, err
		}
	}
	s.publish(Event{Kind: "credential.added", Message: "Cloudflare credential added", Value: credential})
	s.audit(ctx, "credential.add", credential.ID, nil, credential)
	return credential, nil
}

func (s *Service) DeleteCredential(ctx context.Context, credentialID string) error {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return err
	}
	credential, err := s.repo.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	openChallenges, err := s.repo.ListOpenChallenges(ctx)
	if err != nil {
		return err
	}
	for _, challenge := range openChallenges {
		if challenge.CredentialID == credentialID {
			return fmt.Errorf("cannot remove %q while DNS-01 challenge %s still requires this credential", credential.Label, challenge.ID)
		}
	}
	zones, err := s.repo.ListZones(ctx)
	if err != nil {
		return err
	}
	credentials, err := s.repo.ListCredentials(ctx)
	if err != nil {
		return err
	}
	replacements := make([]domain.Zone, 0)
	for _, zone := range zones {
		if zone.PreferredCredentialID != credentialID {
			continue
		}
		var replacement string
		for _, candidate := range credentials {
			if candidate.ID == credentialID || candidate.Provider != zone.Provider || candidate.Status != domain.CredentialValid {
				continue
			}
			observedAt, observed, observationErr := s.repo.GetCredentialZoneCapability(ctx, candidate.ID, zone.ID, "dns:write")
			if observationErr != nil {
				return fmt.Errorf("check replacement DNS-write evidence for %s: %w", zone.Name, observationErr)
			}
			if !observed || s.now().UTC().Sub(observedAt) > replacementWriteEvidenceMaxAge {
				continue
			}
			cloud, ok := s.providers[candidate.Provider]
			if !ok {
				continue
			}
			auth, authErr := s.auth(ctx, candidate)
			if authErr != nil {
				continue
			}
			accessible, accessErr := credentialCanAccessZone(ctx, cloud, auth, zone)
			if accessErr != nil {
				continue
			}
			if !accessible {
				continue
			}
			if _, readErr := cloud.ListDNSRecords(ctx, auth, zone.ProviderID, provider.PageRequest{Page: 1, PerPage: 1}); readErr != nil {
				if provider.AccessFailureIsAuthoritative(readErr) {
					invalidateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					invalidateErr := s.repo.InvalidateCredentialZoneCapability(invalidateCtx, candidate.ID, zone.ID, "dns:read")
					cancel()
					if invalidateErr != nil {
						s.publish(Event{Kind: "credential.capability_warning", Message: fmt.Sprintf("invalidate denied replacement DNS access for %s: %v", zone.Name, invalidateErr)})
					}
				}
				continue
			}
			if err := s.repo.SaveCredentialZoneCapability(ctx, candidate.ID, zone.ID, "dns:read", s.now().UTC()); err != nil {
				return fmt.Errorf("record replacement DNS-read evidence for %s: %w", zone.Name, err)
			}
			replacement = candidate.ID
			break
		}
		if replacement == "" {
			return fmt.Errorf("cannot remove %q: zone %s has no other credential with recent observed DNS-write access and current DNS-read access; perform a successful DNS operation with a replacement first", credential.Label, zone.Name)
		}
		zone.PreferredCredentialID = replacement
		replacements = append(replacements, zone)
	}
	if len(replacements) > 0 {
		if err := s.repo.SaveZones(ctx, replacements); err != nil {
			return fmt.Errorf("reassign zones before credential removal: %w", err)
		}
	}
	if credential.SecretRef != "" {
		if err := s.secrets.Delete(ctx, credential.SecretRef); err != nil {
			return fmt.Errorf("remove credential secret before metadata: %w", err)
		}
	}
	if err := s.repo.DeleteCredential(ctx, credentialID); err != nil {
		return err
	}
	s.publish(Event{Kind: "credential.deleted", Message: "Credential removed"})
	s.audit(ctx, "credential.delete", credential.ID, credential, nil)
	return nil
}

func credentialCanAccessZone(ctx context.Context, cloud provider.ZoneInventory, auth provider.Auth, zone domain.Zone) (bool, error) {
	_, found, err := findCredentialZone(ctx, cloud, auth, zone)
	return found, err
}

func findCredentialZone(ctx context.Context, cloud provider.ZoneInventory, auth provider.Auth, zone domain.Zone) (domain.Zone, bool, error) {
	request := provider.PageRequest{Page: 1, PerPage: 50, Search: zone.Name}
	for {
		page, err := cloud.ListZones(ctx, auth, request)
		if err != nil {
			return domain.Zone{}, false, err
		}
		for _, candidate := range page.Zones {
			providerID := candidate.ProviderID
			if providerID == "" {
				providerID = candidate.ID
			}
			if providerID == zone.ProviderID {
				return candidate, true, nil
			}
		}
		if !advancePage(&request, page.NextCursor, page.Page, page.TotalPages) {
			return domain.Zone{}, false, nil
		}
	}
}

func (s *Service) SyncAll(ctx context.Context) ([]domain.Job, error) {
	credentials, err := s.repo.ListCredentials(ctx)
	if err != nil {
		return nil, err
	}
	jobs := make([]domain.Job, 0, len(credentials))
	var allErrs []error
	for _, credential := range credentials {
		job, syncErr := s.SyncCredential(ctx, credential.ID)
		jobs = append(jobs, job)
		if syncErr != nil {
			allErrs = append(allErrs, syncErr)
		}
	}
	if s.healthCheck != nil && ctx.Err() == nil {
		if healthErr := s.healthCheck(ctx); healthErr != nil {
			allErrs = append(allErrs, fmt.Errorf("public health checks: %w", healthErr))
		}
	}
	return jobs, errors.Join(allErrs...)
}

func compensateSecretDelete(ctx context.Context, secrets store.SecretStore, reference string) error {
	firstErr := secrets.Delete(ctx, reference)
	if firstErr == nil {
		return nil
	}
	if retryErr := secrets.Delete(ctx, reference); retryErr != nil {
		return errors.Join(firstErr, fmt.Errorf("retry secret deletion: %w", retryErr))
	}
	return nil
}

func (s *Service) SyncCredential(ctx context.Context, credentialID string) (domain.Job, error) {
	job := s.startJob(ctx, "provider.sync", credentialID, "Connecting to provider")
	fail := func(err error) (domain.Job, error) {
		job.State = domain.JobFailed
		job.Error = err.Error()
		job.Message = "Synchronization failed"
		now := s.now().UTC()
		job.FinishedAt = &now
		job.UpdatedAt = now
		finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = s.repo.SaveJob(finalizeCtx, job)
		cancel()
		s.publish(Event{Kind: "job.failed", Message: job.Message, Value: job})
		return job, err
	}

	credential, err := s.repo.GetCredential(ctx, credentialID)
	if err != nil {
		return fail(err)
	}
	job.Kind = credential.Provider + ".sync"
	job.Message = "Connecting to " + credential.Provider
	job.UpdatedAt = s.now().UTC()
	_ = s.repo.SaveJob(ctx, job)
	p, ok := s.providers[credential.Provider]
	if !ok {
		return fail(fmt.Errorf("provider %q is not registered", credential.Provider))
	}
	auth, err := s.auth(ctx, credential)
	if err != nil {
		return fail(err)
	}

	verification, err := p.VerifyCredential(ctx, auth)
	if err != nil {
		if provider.CredentialFailureIsAuthoritative(err) {
			credential.Status = domain.CredentialInvalid
		} else if credential.Status != domain.CredentialValid {
			credential.Status = domain.CredentialUnknown
		}
		credential.LastError = err.Error()
		_ = s.repo.SaveCredential(ctx, credential)
		return fail(fmt.Errorf("verify credential: %w", err))
	}
	verifiedAt := s.now().UTC()
	credential.LastVerifiedAt = &verifiedAt
	credential.Status = verification.Status
	credential.LastError = ""
	credential.Capabilities = mergeObservedWriteCapabilities(credential.Capabilities, verification)
	if err := s.repo.SaveCredential(ctx, credential); err != nil {
		return fail(err)
	}
	if credential.Status != domain.CredentialValid {
		return fail(errors.New("credential is inactive or invalid"))
	}

	job.Message = "Loading zones"
	job.Progress = 10
	job.UpdatedAt = s.now().UTC()
	_ = s.repo.SaveJob(ctx, job)
	zones, err := listAllZones(ctx, p, auth)
	if err != nil {
		return fail(fmt.Errorf("list zones: %w", err))
	}
	existingZones, err := s.repo.ListZones(ctx)
	if err != nil {
		return fail(fmt.Errorf("load existing zones: %w", err))
	}
	existingAccounts, err := s.repo.ListAccounts(ctx)
	if err != nil {
		return fail(fmt.Errorf("load existing accounts: %w", err))
	}
	credentials, err := s.repo.ListCredentials(ctx)
	if err != nil {
		return fail(fmt.Errorf("load configured credentials: %w", err))
	}
	credentialExists := make(map[string]struct{}, len(credentials))
	for _, configured := range credentials {
		credentialExists[configured.ID] = struct{}{}
	}
	existingZoneByProviderID := make(map[string]domain.Zone, len(existingZones))
	for _, existing := range existingZones {
		existingZoneByProviderID[existing.Provider+"\x00"+existing.ProviderID] = existing
	}
	knownAccounts := make(map[string]struct{}, len(existingAccounts))
	for _, existing := range existingAccounts {
		knownAccounts[existing.ID] = struct{}{}
	}

	accountByID := make(map[string]domain.RemoteAccount)
	for _, account := range verification.Accounts {
		normalizeAccount(&account, credential.Provider)
		accountByID[account.ID] = account
	}
	returnedZoneIDs := make(map[string]struct{}, len(zones))
	newZoneIDs := make(map[string]struct{}, len(zones))
	for i := range zones {
		accountProviderID := zones[i].AccountID
		normalizeZone(&zones[i], credential.Provider, "")
		key := zones[i].Provider + "\x00" + zones[i].ProviderID
		returnedZoneIDs[key] = struct{}{}
		if existing, known := existingZoneByProviderID[key]; known {
			// Existing zones never silently adopt whichever credential happened
			// to synchronize last. Preserve an explicit valid preference, or
			// preserve the empty state until the operator selects a replacement.
			zones[i].PreferredCredentialID = ""
			if _, configured := credentialExists[existing.PreferredCredentialID]; configured {
				zones[i].PreferredCredentialID = existing.PreferredCredentialID
			}
		} else {
			// New zones are intentionally unrouted until this credential proves
			// DNS-read authority for the exact provider zone below.
			newZoneIDs[zones[i].ID] = struct{}{}
		}
		if _, exists := accountByID[zones[i].AccountID]; !exists {
			providerID := accountProviderID
			if credential.Provider == domain.ProviderCloudflare {
				providerID = strings.TrimPrefix(zones[i].AccountID, "cfacct_")
			}
			accountByID[zones[i].AccountID] = domain.RemoteAccount{
				ID: zones[i].AccountID, Provider: credential.Provider,
				ProviderID: providerID, Name: credential.Provider + " account " + shortID(providerID), CreatedAt: s.now().UTC(),
			}
		}
	}
	// A successful full listing that no longer contains a zone proves this
	// credential cannot currently route it. Retain cached history, but clear the
	// stale preference so credential removal and future explicit reassignment do
	// not require manual database surgery.
	zonesToSave := append([]domain.Zone(nil), zones...)
	staleAt := s.now().UTC()
	for _, existing := range existingZones {
		if existing.Provider != credential.Provider || existing.PreferredCredentialID != credential.ID {
			continue
		}
		if _, returned := returnedZoneIDs[existing.Provider+"\x00"+existing.ProviderID]; returned {
			continue
		}
		existing.PreferredCredentialID = ""
		existing.Status = domain.ZoneUnknown
		for _, candidate := range credentials {
			if candidate.ID == credential.ID || candidate.Provider != existing.Provider || candidate.Status != domain.CredentialValid {
				continue
			}
			cloud, registered := s.providers[candidate.Provider]
			if !registered {
				continue
			}
			candidateAuth, authErr := s.auth(ctx, candidate)
			if authErr != nil {
				continue
			}
			visibleZone, visible, visibilityErr := findCredentialZone(ctx, cloud, candidateAuth, existing)
			if visibilityErr != nil || !visible {
				continue
			}
			normalizeZone(&visibleZone, candidate.Provider, "")
			visibleZone.PreferredCredentialID = ""
			visibleZone.LastSyncedAt = &staleAt
			existing = visibleZone
			break
		}
		existing.LastSyncedAt = &staleAt
		zonesToSave = append(zonesToSave, existing)
	}
	accounts := make([]domain.RemoteAccount, 0, len(accountByID))
	links := make([]domain.AccountCredential, 0, len(accountByID))
	for _, account := range accountByID {
		accounts = append(accounts, account)
		_, known := knownAccounts[account.ID]
		links = append(links, domain.AccountCredential{AccountID: account.ID, CredentialID: credential.ID, Preferred: !known})
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	if err := s.repo.SaveAccounts(ctx, accounts, links); err != nil {
		return fail(err)
	}
	if err := s.repo.SaveZones(ctx, zonesToSave); err != nil {
		return fail(err)
	}

	job.Message = fmt.Sprintf("Synchronizing %d zones", len(zones))
	job.Progress = 20
	job.UpdatedAt = s.now().UTC()
	_ = s.repo.SaveJob(ctx, job)

	var mu sync.Mutex
	completed := 0
	var syncErrs []error
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	for _, current := range zones {
		zone := current
		group.Go(func() error {
			records, listErr := listAllRecords(groupCtx, p, auth, zone.ProviderID)
			if listErr != nil && provider.AccessFailureIsAuthoritative(listErr) {
				invalidateCtx, cancel := context.WithTimeout(context.WithoutCancel(groupCtx), 5*time.Second)
				invalidateErr := s.repo.InvalidateCredentialZoneCapability(invalidateCtx, credential.ID, zone.ID, "dns:read")
				cancel()
				if invalidateErr != nil {
					listErr = errors.Join(listErr, fmt.Errorf("invalidate denied DNS-read route: %w", invalidateErr))
				} else {
					s.publish(Event{Kind: "zone.dns_access_revoked", Message: "Removed denied DNS route for " + zone.Name, Value: zone.ID})
				}
			}
			if listErr == nil {
				listErr = s.repo.SaveCredentialZoneCapability(groupCtx, credential.ID, zone.ID, "dns:read", s.now().UTC())
			}
			if listErr == nil {
				if _, isNew := newZoneIDs[zone.ID]; isNew {
					zone.PreferredCredentialID = credential.ID
					listErr = s.repo.SaveZones(groupCtx, []domain.Zone{zone})
				}
			}
			if listErr == nil {
				now := s.now().UTC()
				for i := range records {
					normalizeRecord(&records[i], zone.Provider, zone.ID)
					records[i].LastSyncedAt = &now
				}
				listErr = s.repo.ReplaceDNSRecords(groupCtx, zone.ID, records, now)
				if listErr == nil {
					listErr = s.ensureDefaultEndpoints(groupCtx, zone, records)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			completed++
			if listErr != nil {
				syncErrs = append(syncErrs, fmt.Errorf("%s: %w", zone.Name, listErr))
			}
			job.Progress = 20 + progress(completed, len(zones), 75)
			job.Message = fmt.Sprintf("Synchronized %d/%d zones", completed, len(zones))
			job.UpdatedAt = s.now().UTC()
			_ = s.repo.SaveJob(ctx, job)
			s.publish(Event{Kind: "sync.progress", Message: job.Message, Value: job})
			return nil
		})
	}
	_ = group.Wait()
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}

	now := s.now().UTC()
	job.Progress = 100
	job.FinishedAt = &now
	job.UpdatedAt = now
	if len(syncErrs) > 0 {
		job.State = domain.JobFailed
		job.Message = fmt.Sprintf("Synchronized with %d zone errors", len(syncErrs))
		job.Error = errors.Join(syncErrs...).Error()
	} else {
		job.State = domain.JobSucceeded
		job.Message = fmt.Sprintf("Synchronized %d zones", len(zones))
	}
	if err := s.repo.SaveJob(ctx, job); err != nil {
		return job, err
	}
	s.publish(Event{Kind: "sync.completed", Message: job.Message, Value: job})
	return job, errors.Join(syncErrs...)
}

func (s *Service) CreateDNSRecord(ctx context.Context, zoneID string, record domain.DNSRecord) (domain.DNSRecord, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return domain.DNSRecord{}, err
	}
	zone, p, auth, err := s.dnsZoneProvider(ctx, zoneID)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	record, err = prepareRecord(zone, record)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	created, mutationErr := p.CreateDNSRecord(ctx, auth, zone.ProviderID, record)
	if mutationErr != nil {
		if mutationFailureIsDefinitive(mutationErr) {
			return domain.DNSRecord{}, mutationErr
		}
		return domain.DNSRecord{}, s.dnsMutationOutcomeUnknownError(
			ctx, "create", zone.ID, nil, record, mutationErr, zone, p, auth,
		)
	}
	s.observeZoneCapability(context.WithoutCancel(ctx), auth.CredentialID, zone.ID, "dns:write")
	normalizeRecord(&created, zone.Provider, zone.ID)
	s.audit(context.WithoutCancel(ctx), "dns.create", created.ID, nil, created)
	if _, reconcileErr := s.reconcileDNSZone(ctx, zone, p, auth); reconcileErr != nil {
		return created, dnsMutationAppliedButUnreconciledError("create", reconcileErr)
	}
	return created, nil
}

func (s *Service) PatchDNSRecord(ctx context.Context, zoneID, recordID string, desired domain.DNSRecord) (domain.DNSRecord, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return domain.DNSRecord{}, err
	}
	zone, p, auth, err := s.dnsZoneProvider(ctx, zoneID)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	records, err := s.repo.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	var cached domain.DNSRecord
	for _, record := range records {
		if record.ID == recordID || record.ProviderID == recordID {
			cached = record
			break
		}
	}
	if cached.ProviderID == "" {
		return domain.DNSRecord{}, fmt.Errorf("DNS record %q not found", recordID)
	}
	remote, err := p.GetDNSRecord(ctx, auth, zone.ProviderID, cached.ProviderID)
	if err != nil {
		return domain.DNSRecord{}, fmt.Errorf("re-fetch DNS record: %w", err)
	}
	if remote.Managed || !remote.Type.Editable() {
		return domain.DNSRecord{}, fmt.Errorf("DNS record %s is provider-managed or read-only", cached.ID)
	}
	if !sameDNSRecordVersion(cached, remote) {
		return domain.DNSRecord{}, fmt.Errorf("%w: %s", ErrDNSConflict, cached.Name)
	}
	if desired.Type != remote.Type {
		return domain.DNSRecord{}, errors.New("changing a DNS record type in place is unsafe; delete it and create the new type")
	}
	desired, err = prepareRecord(zone, desired)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	if desired.Comment == "" {
		desired.Comment = remote.Comment
	}
	if desired.Tags == nil {
		desired.Tags = append([]string(nil), remote.Tags...)
	}
	reconcileStructuredRecordData(&desired, remote)
	desired.Raw = append(json.RawMessage(nil), remote.Raw...)
	desired.Proxiable = remote.Proxiable
	normalizeRecord(&remote, zone.Provider, zone.ID)
	updated, mutationErr := p.PatchDNSRecord(ctx, auth, zone.ProviderID, cached.ProviderID, desired)
	if mutationErr != nil {
		if mutationFailureIsDefinitive(mutationErr) {
			return domain.DNSRecord{}, mutationErr
		}
		return domain.DNSRecord{}, s.dnsMutationOutcomeUnknownError(
			ctx, "patch", cached.ID, remote, desired, mutationErr, zone, p, auth,
		)
	}
	s.observeZoneCapability(context.WithoutCancel(ctx), auth.CredentialID, zone.ID, "dns:write")
	normalizeRecord(&updated, zone.Provider, zone.ID)
	s.audit(context.WithoutCancel(ctx), "dns.patch", updated.ID, remote, updated)
	if _, reconcileErr := s.reconcileDNSZone(ctx, zone, p, auth); reconcileErr != nil {
		return updated, dnsMutationAppliedButUnreconciledError("patch", reconcileErr)
	}
	return updated, nil
}

func (s *Service) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return err
	}
	zone, p, auth, err := s.dnsZoneProvider(ctx, zoneID)
	if err != nil {
		return err
	}
	records, err := s.repo.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return err
	}
	var cached domain.DNSRecord
	for _, record := range records {
		if record.ID == recordID || record.ProviderID == recordID {
			cached = record
			break
		}
	}
	if cached.ProviderID == "" {
		return fmt.Errorf("DNS record %q not found", recordID)
	}
	if cached.Managed || !cached.Type.Editable() {
		return fmt.Errorf("DNS record %s is provider-managed or read-only", cached.ID)
	}
	remote, err := p.GetDNSRecord(ctx, auth, zone.ProviderID, cached.ProviderID)
	if err != nil {
		return fmt.Errorf("re-fetch DNS record: %w", err)
	}
	if remote.Managed || !remote.Type.Editable() {
		return fmt.Errorf("DNS record %s became provider-managed or read-only", cached.ID)
	}
	if !sameDNSRecordVersion(cached, remote) {
		return fmt.Errorf("%w: %s", ErrDNSConflict, cached.Name)
	}
	normalizeRecord(&remote, zone.Provider, zone.ID)
	if mutationErr := p.DeleteDNSRecord(ctx, auth, zone.ProviderID, cached.ProviderID); mutationErr != nil {
		if mutationFailureIsDefinitive(mutationErr) {
			return mutationErr
		}
		return s.dnsMutationOutcomeUnknownError(
			ctx, "delete", cached.ID, remote, nil, mutationErr, zone, p, auth,
		)
	}
	s.observeZoneCapability(context.WithoutCancel(ctx), auth.CredentialID, zone.ID, "dns:write")
	s.audit(context.WithoutCancel(ctx), "dns.delete", cached.ID, remote, nil)
	if _, reconcileErr := s.reconcileDNSZone(ctx, zone, p, auth); reconcileErr != nil {
		return dnsMutationAppliedButUnreconciledError("delete", reconcileErr)
	}
	return nil
}

// PlanDNSBatch validates a zone-scoped batch against the current local cache
// and freshly fetched provider records. It never submits a mutation.
func (s *Service) PlanDNSBatch(ctx context.Context, zoneID string, mutations []domain.DNSMutation) (DNSBatchPlan, error) {
	planned, err := s.planDNSBatch(ctx, zoneID, mutations)
	if err != nil {
		return DNSBatchPlan{}, err
	}
	return planned.plan, nil
}

// ApplyDNSBatch revalidates the complete batch, submits it as one provider
// transaction, then replaces the zone cache from a full provider read. Applied
// remains true if the provider committed but cache reconciliation later fails.
func (s *Service) ApplyDNSBatch(ctx context.Context, zoneID string, mutations []domain.DNSMutation) (DNSBatchResult, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return DNSBatchResult{}, err
	}
	planned, err := s.planDNSBatch(ctx, zoneID, mutations)
	if err != nil {
		return DNSBatchResult{}, err
	}
	result := DNSBatchResult{Plan: planned.plan}
	if _, applyErr := planned.batch.ApplyDNSBatch(ctx, planned.auth, planned.zone.ProviderID, planned.plan.Mutations); applyErr != nil {
		if mutationFailureIsDefinitive(applyErr) {
			return result, applyErr
		}
		result.OutcomeUnknown = true
		before, after := dnsBatchAuditSides(planned.plan.Mutations)
		s.audit(context.WithoutCancel(ctx), "dns.batch.outcome_unknown", planned.zone.ID, before, after)
		reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		records, refreshErr := listAllRecords(reconcileCtx, planned.cloud, planned.auth, planned.zone.ProviderID)
		if refreshErr == nil {
			now := s.now().UTC()
			for index := range records {
				normalizeRecord(&records[index], planned.zone.Provider, planned.zone.ID)
				records[index].LastSyncedAt = &now
			}
			result.Records = records
			if cacheErr := s.repo.ReplaceDNSRecords(reconcileCtx, planned.zone.ID, records, now); cacheErr != nil {
				refreshErr = fmt.Errorf("replace reconciled DNS cache: %w", cacheErr)
			} else if endpointErr := s.ensureDefaultEndpoints(reconcileCtx, planned.zone, records); endpointErr != nil {
				refreshErr = fmt.Errorf("reconcile generated health endpoints: %w", endpointErr)
			}
		}
		return result, errors.Join(
			fmt.Errorf("%s DNS batch outcome is unknown; synchronize and review before retrying: %w", planned.zone.Provider, applyErr),
			refreshErr,
		)
	}
	result.Applied = true
	s.observeZoneCapability(context.WithoutCancel(ctx), planned.auth.CredentialID, planned.zone.ID, "dns:write")
	before, after := dnsBatchAuditSides(planned.plan.Mutations)
	s.audit(ctx, "dns.batch", planned.zone.ID, before, after)

	records, err := listAllRecords(ctx, planned.cloud, planned.auth, planned.zone.ProviderID)
	if err != nil {
		return result, fmt.Errorf("DNS batch applied but provider refresh failed: %w", err)
	}
	now := s.now().UTC()
	for index := range records {
		normalizeRecord(&records[index], planned.zone.Provider, planned.zone.ID)
		records[index].LastSyncedAt = &now
	}
	result.Records = records
	if err := s.repo.ReplaceDNSRecords(ctx, planned.zone.ID, records, now); err != nil {
		return result, fmt.Errorf("DNS batch applied but cache reconciliation failed: %w", err)
	}
	if err := s.ensureDefaultEndpoints(ctx, planned.zone, records); err != nil {
		return result, fmt.Errorf("DNS batch applied but generated endpoint reconciliation failed: %w", err)
	}
	return result, nil
}

func mutationFailureIsDefinitive(err error) bool {
	type definitiveMutationError interface {
		MutationOutcomeDefinitive() bool
	}
	var definitive definitiveMutationError
	return errors.As(err, &definitive) && definitive.MutationOutcomeDefinitive()
}

// reconcileDNSZone replaces the complete local zone cache from the provider
// and then derives the generated apex/www health endpoints from that same
// snapshot. It deliberately outlives cancellation of the mutation request, but
// remains bounded so an interrupted client cannot leave reconciliation running
// indefinitely.
func (s *Service) reconcileDNSZone(ctx context.Context, zone domain.Zone, cloud provider.Provider, auth provider.Auth) ([]domain.DNSRecord, error) {
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsMutationReconcileTimeout)
	defer cancel()
	records, err := listAllRecords(reconcileCtx, cloud, auth, zone.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("refresh provider DNS records: %w", err)
	}
	now := s.now().UTC()
	for index := range records {
		normalizeRecord(&records[index], zone.Provider, zone.ID)
		records[index].LastSyncedAt = &now
	}
	cacheErr := s.repo.ReplaceDNSRecords(reconcileCtx, zone.ID, records, now)
	endpointErr := s.ensureDefaultEndpoints(reconcileCtx, zone, records)
	return records, errors.Join(
		wrapError("replace reconciled DNS cache", cacheErr),
		wrapError("reconcile generated health endpoints", endpointErr),
	)
}

func wrapError(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

func (s *Service) dnsMutationOutcomeUnknownError(
	ctx context.Context,
	action, resourceID string,
	before, after interface{},
	mutationErr error,
	zone domain.Zone,
	cloud provider.Provider,
	auth provider.Auth,
) error {
	s.audit(context.WithoutCancel(ctx), "dns."+action+".outcome_unknown", resourceID, before, after)
	_, reconcileErr := s.reconcileDNSZone(ctx, zone, cloud, auth)
	result := []error{
		fmt.Errorf("%w: %s request returned an ambiguous provider response", ErrDNSMutationOutcomeUnknown, action),
		fmt.Errorf("provider response: %w", mutationErr),
	}
	if reconcileErr != nil {
		result = append(result, fmt.Errorf("automatic reconciliation also failed: %w", reconcileErr))
	}
	return errors.Join(result...)
}

func dnsMutationAppliedButUnreconciledError(action string, reconcileErr error) error {
	return errors.Join(
		fmt.Errorf("%w: provider confirmed DNS %s", ErrDNSMutationAppliedButUnreconciled, action),
		reconcileErr,
	)
}

func (s *Service) planDNSBatch(ctx context.Context, zoneID string, mutations []domain.DNSMutation) (plannedDNSBatch, error) {
	if len(mutations) == 0 {
		return plannedDNSBatch{}, errors.New("DNS batch requires at least one mutation")
	}
	zone, cloud, auth, err := s.dnsZoneProvider(ctx, zoneID)
	if err != nil {
		return plannedDNSBatch{}, err
	}
	batch, ok := cloud.(provider.DNSBatchService)
	if !ok {
		return plannedDNSBatch{}, provider.Unsupported(zone.Provider, "DNS batch")
	}
	cachedRecords, err := s.repo.ListDNSRecords(ctx, zone.ID)
	if err != nil {
		return plannedDNSBatch{}, err
	}
	byID := make(map[string]domain.DNSRecord, len(cachedRecords)*2)
	for _, record := range cachedRecords {
		if record.ID != "" {
			byID[record.ID] = record
		}
		if record.ProviderID != "" {
			byID[record.ProviderID] = record
		}
	}

	plan := DNSBatchPlan{ZoneID: zone.ID, ZoneName: zone.Name, Mutations: make([]domain.DNSMutation, 0, len(mutations))}
	seenTargets := make(map[string]struct{})
	for index, mutation := range mutations {
		plannedMutation := domain.DNSMutation{Kind: mutation.Kind}
		switch mutation.Kind {
		case domain.MutationCreate:
			if mutation.After == nil {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: create requires an after record", index)
			}
			after := cloneDNSRecord(*mutation.After)
			if after.Managed {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: provider-managed records cannot be created", index)
			}
			after.ID, after.ProviderID, after.Raw = "", "", nil
			after, err = prepareRecord(zone, after)
			if err != nil {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: %w", index, err)
			}
			plannedMutation.After = &after

		case domain.MutationPatch, domain.MutationReplace, domain.MutationDelete:
			recordID := dnsMutationRecordID(mutation)
			cached, found := byID[recordID]
			if recordID == "" || !found {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: DNS record %q not found", index, recordID)
			}
			if _, duplicate := seenTargets[cached.ProviderID]; duplicate {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: DNS record %s appears more than once", index, cached.ID)
			}
			seenTargets[cached.ProviderID] = struct{}{}

			remote, getErr := cloud.GetDNSRecord(ctx, auth, zone.ProviderID, cached.ProviderID)
			if getErr != nil {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: re-fetch DNS record: %w", index, getErr)
			}
			if cached.Managed || !cached.Type.Editable() || remote.Managed || !remote.Type.Editable() {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: DNS record %s is provider-managed or read-only", index, cached.ID)
			}
			if !sameDNSRecordVersion(cached, remote) {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: %w: %s", index, ErrDNSConflict, cached.Name)
			}
			remoteForPlan := cloneDNSRecord(remote)
			normalizeRecord(&remoteForPlan, zone.Provider, zone.ID)
			plannedMutation.RecordID = cached.ProviderID
			plannedMutation.Before = &remoteForPlan
			if mutation.Kind == domain.MutationDelete {
				break
			}
			if mutation.After == nil {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: update requires an after record", index)
			}
			after := cloneDNSRecord(*mutation.After)
			if after.Type != remote.Type {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: changing a DNS record type in place is unsafe; delete it and create the new type", index)
			}
			after, err = prepareRecord(zone, after)
			if err != nil {
				return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: %w", index, err)
			}
			if mutation.Kind == domain.MutationPatch && after.Comment == "" {
				after.Comment = remote.Comment
			}
			if mutation.Kind == domain.MutationPatch && after.Tags == nil {
				after.Tags = append([]string(nil), remote.Tags...)
			} else if mutation.Kind == domain.MutationReplace && after.Tags == nil {
				after.Tags = []string{}
			}
			reconcileStructuredRecordData(&after, remote)
			after.ID, after.ProviderID, after.ZoneID = cached.ID, cached.ProviderID, zone.ID
			after.Raw = append(json.RawMessage(nil), remote.Raw...)
			after.Managed = false
			after.Proxiable = remote.Proxiable
			plannedMutation.After = &after

		default:
			return plannedDNSBatch{}, fmt.Errorf("DNS batch mutation %d: unknown mutation kind %q", index, mutation.Kind)
		}
		plan.Mutations = append(plan.Mutations, plannedMutation)
	}
	return plannedDNSBatch{plan: plan, zone: zone, cloud: cloud, batch: batch, auth: auth}, nil
}

func dnsMutationRecordID(mutation domain.DNSMutation) string {
	if mutation.RecordID != "" {
		return mutation.RecordID
	}
	for _, record := range []*domain.DNSRecord{mutation.Before, mutation.After} {
		if record == nil {
			continue
		}
		if record.ID != "" {
			return record.ID
		}
		if record.ProviderID != "" {
			return record.ProviderID
		}
	}
	return ""
}

func cloneDNSRecord(record domain.DNSRecord) domain.DNSRecord {
	copy := record
	if record.Priority != nil {
		priority := *record.Priority
		copy.Priority = &priority
	}
	copy.Tags = slices.Clone(record.Tags)
	copy.Data = append(json.RawMessage(nil), record.Data...)
	copy.Raw = append(json.RawMessage(nil), record.Raw...)
	return copy
}

func reconcileStructuredRecordData(desired *domain.DNSRecord, remote domain.DNSRecord) {
	if desired == nil {
		return
	}
	if desired.Type != domain.RecordCAA && desired.Type != domain.RecordSRV {
		desired.Data = nil
		return
	}
	// An omitted Data field means "preserve" only when the canonical content
	// is unchanged. If content changed, retaining remote Data would make
	// Cloudflare prefer the stale structured payload and silently ignore the
	// requested edit.
	if len(desired.Data) == 0 && desired.Content == remote.Content {
		desired.Data = append(json.RawMessage(nil), remote.Data...)
	}
}

func dnsBatchAuditSides(mutations []domain.DNSMutation) ([]domain.DNSMutation, []domain.DNSMutation) {
	before := make([]domain.DNSMutation, 0, len(mutations))
	after := make([]domain.DNSMutation, 0, len(mutations))
	for _, mutation := range mutations {
		beforeRecord := auditDNSRecord(mutation.Before)
		afterRecord := auditDNSRecord(mutation.After)
		before = append(before, domain.DNSMutation{Kind: mutation.Kind, RecordID: mutation.RecordID, Before: beforeRecord})
		after = append(after, domain.DNSMutation{Kind: mutation.Kind, RecordID: mutation.RecordID, After: afterRecord})
	}
	return before, after
}

func auditDNSRecord(record *domain.DNSRecord) *domain.DNSRecord {
	if record == nil {
		return nil
	}
	copy := cloneDNSRecord(*record)
	copy.Raw = nil
	return &copy
}

func (s *Service) TLSSettings(ctx context.Context, zoneID string, refresh bool) (domain.EdgeTLSSettings, error) {
	if !refresh {
		if value, err := s.repo.GetTLSSettings(ctx, zoneID); err == nil {
			return value, nil
		}
	}
	zone, p, auth, err := s.zoneProvider(ctx, zoneID)
	if err != nil {
		return domain.EdgeTLSSettings{}, err
	}
	tlsProvider, ok := p.(provider.EdgeTLSService)
	if !ok {
		return domain.EdgeTLSSettings{}, provider.Unsupported(zone.Provider, "edge TLS")
	}
	settings, err := tlsProvider.GetEdgeTLSSettings(ctx, auth, zone.ProviderID)
	if err != nil {
		return domain.EdgeTLSSettings{}, err
	}
	settings.ZoneID = zone.ID
	if settings.LastSyncedAt == nil {
		now := s.now().UTC()
		settings.LastSyncedAt = &now
	}
	if err := s.repo.SaveTLSSettings(ctx, settings); err != nil {
		return domain.EdgeTLSSettings{}, err
	}
	return settings, nil
}

func (s *Service) EdgeCertificates(ctx context.Context, zoneID string) ([]domain.EdgeCertificate, error) {
	zone, p, auth, err := s.zoneProvider(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	tlsProvider, ok := p.(provider.EdgeTLSService)
	if !ok {
		return nil, provider.Unsupported(zone.Provider, "edge TLS")
	}
	const pageSize = 50
	values := make([]domain.EdgeCertificate, 0, pageSize)
	for page := 1; page <= 200; page++ {
		batch, listErr := tlsProvider.ListEdgeCertificates(ctx, auth, zone.ProviderID, provider.PageRequest{Page: page, PerPage: pageSize})
		if listErr != nil {
			return nil, listErr
		}
		values = append(values, batch...)
		if len(batch) < pageSize {
			break
		}
		if page == 200 {
			return nil, errors.New("edge certificate inventory exceeded 10,000 entries")
		}
	}
	for i := range values {
		values[i].ZoneID = zone.ID
	}
	return values, nil
}

func (s *Service) UpdateTLSSettings(ctx context.Context, zoneID string, desired domain.EdgeTLSSettings) (domain.EdgeTLSSettings, error) {
	if err := s.ensureRecoveryReady(ctx); err != nil {
		return domain.EdgeTLSSettings{}, err
	}
	zone, p, auth, err := s.zoneProvider(ctx, zoneID)
	if err != nil {
		return domain.EdgeTLSSettings{}, err
	}
	tlsProvider, ok := p.(provider.EdgeTLSService)
	if !ok {
		return domain.EdgeTLSSettings{}, provider.Unsupported(zone.Provider, "edge TLS")
	}
	baseline, err := s.repo.GetTLSSettings(ctx, zone.ID)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("load displayed TLS baseline: %w", err)
	}
	if desired.LastSyncedAt != nil && baseline.LastSyncedAt != nil && !desired.LastSyncedAt.Equal(*baseline.LastSyncedAt) {
		return domain.EdgeTLSSettings{}, ErrTLSConflict
	}
	before, err := tlsProvider.GetEdgeTLSSettings(ctx, auth, zone.ProviderID)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("re-fetch Cloudflare TLS settings: %w", err)
	}
	before.ZoneID = zone.ID
	if before.LastSyncedAt == nil {
		now := s.now().UTC()
		before.LastSyncedAt = &now
	}
	if tlsRequestedFieldConflict(baseline, desired, before) {
		saveErr := s.repo.SaveTLSSettings(context.WithoutCancel(ctx), before)
		return before, errors.Join(ErrTLSConflict, wrapError("save refreshed TLS settings", saveErr))
	}
	if sameControlledTLS(baseline, desired) {
		if err := s.repo.SaveTLSSettings(ctx, before); err != nil {
			return before, err
		}
		return before, nil
	}
	desired.ZoneID = zone.ProviderID
	updated, updateErr := tlsProvider.UpdateEdgeTLSSettings(ctx, auth, zone.ProviderID, baseline, desired)
	if updateErr != nil {
		reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if mutationWasNotAttempted(updateErr) {
			// The provider guarantees no PATCH was sent. The live `before`
			// snapshot above is therefore still authoritative; do not turn a
			// second failed GET into an outcome-unknown mutation warning.
			saveErr := s.repo.SaveTLSSettings(reconcileCtx, before)
			return before, errors.Join(updateErr, wrapError("save unchanged TLS settings", saveErr))
		}
		effective, refreshErr := tlsProvider.GetEdgeTLSSettings(reconcileCtx, auth, zone.ProviderID)
		if refreshErr != nil {
			return domain.EdgeTLSSettings{}, errors.Join(
				ErrTLSMutationOutcomeUnknown,
				fmt.Errorf("provider update: %w", updateErr),
				fmt.Errorf("refresh effective TLS state: %w", refreshErr),
			)
		}
		effective.ZoneID = zone.ID
		if effective.LastSyncedAt == nil {
			now := s.now().UTC()
			effective.LastSyncedAt = &now
		}
		saveErr := s.repo.SaveTLSSettings(reconcileCtx, effective)
		if mutationFailureIsDefinitive(updateErr) && sameControlledTLS(before, effective) {
			return effective, errors.Join(updateErr, wrapError("save refreshed TLS settings", saveErr))
		}
		action := "tls.update.outcome_unknown"
		if !sameControlledTLS(before, effective) {
			s.observeZoneCapability(reconcileCtx, auth.CredentialID, zone.ID, "tls:write")
			if !sameControlledTLS(desired, effective) {
				action = "tls.update.partial"
			}
		}
		s.audit(reconcileCtx, action, zone.ID, before, effective)
		return effective, errors.Join(
			ErrTLSMutationOutcomeUnknown,
			fmt.Errorf("provider update: %w", updateErr),
			wrapError("save refreshed TLS settings", saveErr),
		)
	}
	s.observeZoneCapability(context.WithoutCancel(ctx), auth.CredentialID, zone.ID, "tls:write")
	updated.ZoneID = zone.ID
	finalizeCtx := context.WithoutCancel(ctx)
	if err := s.repo.SaveTLSSettings(finalizeCtx, updated); err != nil {
		return updated, errors.Join(ErrTLSMutationAppliedButUnreconciled, err)
	}
	s.audit(finalizeCtx, "tls.update", zone.ID, before, updated)
	return updated, nil
}

func sameControlledTLS(left, right domain.EdgeTLSSettings) bool {
	return strings.EqualFold(strings.TrimSpace(left.Mode), strings.TrimSpace(right.Mode)) &&
		left.AlwaysUseHTTPS == right.AlwaysUseHTTPS &&
		strings.TrimSpace(left.MinimumTLS) == strings.TrimSpace(right.MinimumTLS) &&
		left.TLS13 == right.TLS13
}

func tlsRequestedFieldConflict(baseline, desired, remote domain.EdgeTLSSettings) bool {
	return (!strings.EqualFold(strings.TrimSpace(baseline.Mode), strings.TrimSpace(desired.Mode)) && !strings.EqualFold(strings.TrimSpace(baseline.Mode), strings.TrimSpace(remote.Mode))) ||
		(baseline.AlwaysUseHTTPS != desired.AlwaysUseHTTPS && baseline.AlwaysUseHTTPS != remote.AlwaysUseHTTPS) ||
		(strings.TrimSpace(baseline.MinimumTLS) != strings.TrimSpace(desired.MinimumTLS) && strings.TrimSpace(baseline.MinimumTLS) != strings.TrimSpace(remote.MinimumTLS)) ||
		(baseline.TLS13 != desired.TLS13 && baseline.TLS13 != remote.TLS13)
}

func mutationWasNotAttempted(err error) bool {
	type notAttemptedError interface{ MutationNotAttempted() bool }
	var notAttempted notAttemptedError
	return errors.As(err, &notAttempted) && notAttempted.MutationNotAttempted()
}

func (s *Service) ensureRecoveryReady(ctx context.Context) error {
	if s.recoveryBlocked.Load() {
		return ErrRecoveryRequired
	}
	issues, err := s.repo.ListHealthIssues(ctx)
	if err != nil {
		return fmt.Errorf("verify crash-recovery state before mutation: %w", err)
	}
	for _, issue := range issues {
		if issue.Kind == "certificate_commit_recovery_failed" || issue.ResourceID == recoveryHealthOwner {
			return fmt.Errorf("%w: %s", ErrRecoveryRequired, issue.Detail)
		}
	}
	return nil
}

func (s *Service) startJob(ctx context.Context, kind, resourceID, message string) domain.Job {
	now := s.now().UTC()
	job := domain.Job{
		ID: identifier.New("job"), Kind: kind, State: domain.JobRunning, ResourceID: resourceID,
		Progress: 0, Message: message, CreatedAt: now, StartedAt: &now, UpdatedAt: now,
	}
	_ = s.repo.SaveJob(ctx, job)
	s.publish(Event{Kind: "job.started", Message: message, Value: job})
	return job
}

func mergeObservedWriteCapabilities(existing []string, verification provider.Verification) []string {
	names := append([]string(nil), verification.Capabilities.Names...)
	if verification.Status == domain.CredentialValid {
		if verification.Capabilities.DNSRead && slices.Contains(existing, "dns:write") {
			names = append(names, "dns:write")
		}
		if verification.Capabilities.TLSRead && slices.Contains(existing, "tls:write") {
			names = append(names, "tls:write")
		}
	}
	sort.Strings(names)
	return slices.Compact(names)
}

// ObserveCredentialZoneCapability records only provider operations that have
// actually succeeded for a specific credential and zone. Read-only
// verification probes never manufacture write capability.
func (s *Service) ObserveCredentialZoneCapability(ctx context.Context, credentialID, zoneReference, capability string) error {
	if credentialID == "" || zoneReference == "" ||
		(capability != "dns:read" && capability != "dns:write" && capability != "tls:read" && capability != "tls:write") {
		return errors.New("unsupported observed credential capability")
	}
	credential, err := s.repo.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	zone, err := s.repo.GetZone(ctx, zoneReference)
	if err != nil {
		zones, listErr := s.repo.ListZones(ctx)
		if listErr != nil {
			return listErr
		}
		zone = domain.Zone{}
		for _, candidate := range zones {
			if candidate.Provider == credential.Provider && candidate.ProviderID == zoneReference {
				zone = candidate
				break
			}
		}
		if zone.ID == "" {
			return fmt.Errorf("zone %q for observed capability was not found", zoneReference)
		}
	}
	if credential.Provider != zone.Provider {
		return errors.New("observed capability credential and zone providers differ")
	}
	if err := s.repo.SaveCredentialZoneCapability(ctx, credentialID, zone.ID, capability, s.now().UTC()); err != nil {
		return err
	}
	if slices.Contains(credential.Capabilities, capability) {
		return nil
	}
	credential.Capabilities = append(credential.Capabilities, capability)
	sort.Strings(credential.Capabilities)
	credential.Capabilities = slices.Compact(credential.Capabilities)
	return s.repo.SaveCredential(ctx, credential)
}

func (s *Service) observeZoneCapability(ctx context.Context, credentialID, zoneID, capability string) {
	if err := s.ObserveCredentialZoneCapability(ctx, credentialID, zoneID, capability); err != nil {
		s.publish(Event{Kind: "credential.capability_warning", Message: err.Error()})
	}
}

func (s *Service) auth(ctx context.Context, credential domain.Credential) (provider.Auth, error) {
	secret, err := s.secrets.Get(ctx, credential.SecretRef)
	if err != nil {
		return provider.Auth{}, fmt.Errorf("unlock credential %q: %w", credential.Label, err)
	}
	return provider.Auth{Provider: credential.Provider, CredentialID: credential.ID, Token: string(secret), Kind: credential.Kind, AccountID: credential.AccountHint}, nil
}

func (s *Service) zoneProvider(ctx context.Context, zoneID string) (domain.Zone, provider.Provider, provider.Auth, error) {
	zone, err := s.repo.GetZone(ctx, zoneID)
	if err != nil {
		return domain.Zone{}, nil, provider.Auth{}, err
	}
	credential, err := s.repo.GetCredential(ctx, zone.PreferredCredentialID)
	if err != nil {
		return domain.Zone{}, nil, provider.Auth{}, err
	}
	if credential.Status != domain.CredentialValid {
		return domain.Zone{}, nil, provider.Auth{}, fmt.Errorf("preferred credential %q is not valid", credential.Label)
	}
	if credential.Provider != zone.Provider {
		return domain.Zone{}, nil, provider.Auth{}, fmt.Errorf("preferred credential provider %q does not match zone provider %q", credential.Provider, zone.Provider)
	}
	p, ok := s.providers[zone.Provider]
	if !ok {
		return domain.Zone{}, nil, provider.Auth{}, fmt.Errorf("provider %q is not registered", zone.Provider)
	}
	auth, err := s.auth(ctx, credential)
	return zone, p, auth, err
}

func (s *Service) dnsZoneProvider(ctx context.Context, zoneID string) (domain.Zone, provider.Provider, provider.Auth, error) {
	zone, cloud, auth, err := s.zoneProvider(ctx, zoneID)
	if err != nil {
		return domain.Zone{}, nil, provider.Auth{}, err
	}
	observed, err := s.repo.HasCredentialZoneCapability(ctx, auth.CredentialID, zone.ID, "dns:read")
	if err != nil {
		return domain.Zone{}, nil, provider.Auth{}, fmt.Errorf("verify DNS-read routing evidence for %s: %w", zone.Name, err)
	}
	if !observed {
		return domain.Zone{}, nil, provider.Auth{}, fmt.Errorf("preferred credential has no observed DNS-read access to zone %s; synchronize or select it again", zone.Name)
	}
	return zone, cloud, auth, nil
}

// ResolveDNS01 selects the longest matching configured zone and its explicit
// preferred credential. It is safe for nested _acme-challenge names and never
// falls back to another credential after a zone is selected.
func (s *Service) ResolveDNS01(ctx context.Context, fqdn string) (provider.Auth, string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	name = strings.TrimPrefix(name, "*.")
	zones, err := s.repo.ListZones(ctx)
	if err != nil {
		return provider.Auth{}, "", err
	}
	var selected *domain.Zone
	for i := range zones {
		if zones[i].Status != domain.ZoneActive {
			continue
		}
		zoneName := strings.ToLower(strings.TrimSuffix(zones[i].Name, "."))
		if name != zoneName && !strings.HasSuffix(name, "."+zoneName) {
			continue
		}
		if selected == nil || len(zoneName) > len(selected.Name) {
			candidate := zones[i]
			selected = &candidate
		}
	}
	if selected == nil {
		return provider.Auth{}, "", fmt.Errorf("no configured zone owns %q", fqdn)
	}
	if selected.PreferredCredentialID == "" {
		return provider.Auth{}, "", fmt.Errorf("zone %s owns %q but has no preferred DNS credential", selected.Name, fqdn)
	}
	credential, err := s.repo.GetCredential(ctx, selected.PreferredCredentialID)
	if err != nil {
		return provider.Auth{}, "", fmt.Errorf("load preferred credential for %s: %w", selected.Name, err)
	}
	if credential.Status != domain.CredentialValid {
		return provider.Auth{}, "", fmt.Errorf("preferred credential for %s is not valid", selected.Name)
	}
	if credential.Provider != selected.Provider {
		return provider.Auth{}, "", fmt.Errorf("preferred credential provider %q does not match zone provider %q", credential.Provider, selected.Provider)
	}
	if _, registered := s.providers[selected.Provider]; !registered {
		return provider.Auth{}, "", fmt.Errorf("provider %q is not registered", selected.Provider)
	}
	observed, err := s.repo.HasCredentialZoneCapability(ctx, credential.ID, selected.ID, "dns:read")
	if err != nil {
		return provider.Auth{}, "", fmt.Errorf("verify DNS-read routing evidence for %s: %w", selected.Name, err)
	}
	if !observed {
		return provider.Auth{}, "", fmt.Errorf("preferred credential has no observed DNS-read access to zone %s", selected.Name)
	}
	auth, err := s.auth(ctx, credential)
	if err != nil {
		return provider.Auth{}, "", err
	}
	return auth, selected.ProviderID, nil
}

func listAllZones(ctx context.Context, p provider.ZoneInventory, auth provider.Auth) ([]domain.Zone, error) {
	var result []domain.Zone
	request := provider.PageRequest{Page: 1, PerPage: 50}
	for {
		page, err := p.ListZones(ctx, auth, request)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Zones...)
		if !advancePage(&request, page.NextCursor, page.Page, page.TotalPages) {
			break
		}
	}
	return result, nil
}

type dnsRecordLister interface {
	ListDNSRecords(context.Context, provider.Auth, string, provider.PageRequest) (provider.RecordPage, error)
}

func listAllRecords(ctx context.Context, p dnsRecordLister, auth provider.Auth, zoneID string) ([]domain.DNSRecord, error) {
	var result []domain.DNSRecord
	request := provider.PageRequest{Page: 1, PerPage: 500}
	for {
		page, err := p.ListDNSRecords(ctx, auth, zoneID, request)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Records...)
		if !advancePage(&request, page.NextCursor, page.Page, page.TotalPages) {
			break
		}
	}
	return result, nil
}

// advancePage keeps cursor-based and page-based providers in sync. Some APIs
// encode the next page as a numeric cursor, while others return an opaque
// cursor and no total page count. Clearing an exhausted cursor is essential:
// otherwise the final page can be requested repeatedly with a stale cursor.
func advancePage(request *provider.PageRequest, nextCursor string, responsePage, totalPages int) bool {
	if nextCursor != "" {
		request.Cursor = nextCursor
		if responsePage > 0 {
			request.Page = responsePage
		}
		return true
	}
	currentPage := responsePage
	if currentPage <= 0 {
		currentPage = request.Page
	}
	if totalPages > 0 && currentPage < totalPages {
		request.Cursor = ""
		request.Page = currentPage + 1
		return true
	}
	return false
}

func normalizeAccount(account *domain.RemoteAccount, providerName string) {
	if providerName == "" {
		providerName = account.Provider
	}
	if account.ProviderID == "" {
		account.ProviderID = account.ID
		if providerName == domain.ProviderCloudflare {
			account.ProviderID = strings.TrimPrefix(account.ProviderID, "cfacct_")
		}
	}
	account.Provider = providerName
	if providerName == domain.ProviderCloudflare {
		account.ID = "cfacct_" + account.ProviderID
	} else {
		account.ID = stableID("account", providerName, account.ProviderID)
	}
	if account.CreatedAt.IsZero() {
		account.CreatedAt = time.Now().UTC()
	}
}

func normalizeZone(zone *domain.Zone, providerName, credentialID string) {
	if providerName == "" {
		providerName = zone.Provider
	}
	if zone.ProviderID == "" {
		zone.ProviderID = zone.ID
		if providerName == domain.ProviderCloudflare {
			zone.ProviderID = strings.TrimPrefix(zone.ProviderID, "cfzone_")
		}
	}
	zone.Provider = providerName
	if providerName == domain.ProviderCloudflare {
		zone.ID = "cfzone_" + zone.ProviderID
		if !strings.HasPrefix(zone.AccountID, "cfacct_") {
			zone.AccountID = "cfacct_" + zone.AccountID
		}
	} else {
		zone.ID = stableID("zone", providerName, zone.ProviderID)
		zone.AccountID = stableID("account", providerName, zone.AccountID)
	}
	zone.PreferredCredentialID = credentialID
	if zone.Status == "" {
		zone.Status = domain.ZoneUnknown
	}
}

func normalizeRecord(record *domain.DNSRecord, providerName, zoneID string) {
	if record.ProviderID == "" {
		record.ProviderID = record.ID
		if providerName == domain.ProviderCloudflare {
			record.ProviderID = strings.TrimPrefix(record.ProviderID, "cfrecord_")
		}
	}
	if providerName == domain.ProviderCloudflare {
		record.ID = "cfrecord_" + record.ProviderID
	} else {
		record.ID = stableID("record", providerName, zoneID, record.ProviderID)
	}
	record.ZoneID = zoneID
	if unicodeName, err := idna.Lookup.ToUnicode(record.Name); err == nil {
		record.UnicodeName = unicodeName
	}
}

func prepareRecord(zone domain.Zone, record domain.DNSRecord) (domain.DNSRecord, error) {
	if !record.Type.Editable() {
		return domain.DNSRecord{}, fmt.Errorf("record type %s is read-only in this release", record.Type)
	}
	rawName := strings.TrimSpace(record.Name)
	absolute := strings.HasSuffix(rawName, ".")
	name := strings.TrimSuffix(rawName, ".")
	if name == "@" || name == "" {
		name = zone.Name
	} else if !absolute && !strings.EqualFold(name, zone.Name) && !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone.Name)) {
		name += "." + zone.Name
	}
	ascii, err := toASCIIDNSName(name)
	if err != nil {
		return domain.DNSRecord{}, fmt.Errorf("invalid DNS name: %w", err)
	}
	if ascii != zone.Name && !strings.HasSuffix(ascii, "."+zone.Name) {
		return domain.DNSRecord{}, fmt.Errorf("record name %q is outside zone %q", name, zone.Name)
	}
	record.Name = ascii
	record.ZoneID = zone.ID
	if record.TTL < 0 {
		return domain.DNSRecord{}, errors.New("TTL cannot be negative")
	}
	if err := validateRecordValue(&record); err != nil {
		return domain.DNSRecord{}, err
	}
	return record, nil
}

func validateRecordValue(record *domain.DNSRecord) error {
	content := strings.TrimSpace(record.Content)
	switch record.Type {
	case domain.RecordA:
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() == nil {
			return errors.New("A record content must be a valid IPv4 address")
		}
		record.Content = ip.To4().String()
	case domain.RecordAAAA:
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() != nil {
			return errors.New("AAAA record content must be a valid IPv6 address")
		}
		record.Content = ip.String()
	case domain.RecordCNAME, domain.RecordNS:
		if content == "" {
			return fmt.Errorf("%s record target is required", record.Type)
		}
	case domain.RecordMX:
		if content == "" || record.Priority == nil {
			return errors.New("MX record target and priority are required")
		}
	case domain.RecordCAA:
		if err := validateCAAValue(*record); err != nil {
			return err
		}
	case domain.RecordSRV:
		if err := validateSRVValue(*record); err != nil {
			return err
		}
	case domain.RecordTXT:
		// Empty TXT values are valid and intentionally preserved.
	}
	if record.Proxied && record.Type != domain.RecordA && record.Type != domain.RecordAAAA && record.Type != domain.RecordCNAME {
		return fmt.Errorf("record type %s cannot be proxied by this provider", record.Type)
	}
	if record.Priority != nil && record.Type != domain.RecordMX && record.Type != domain.RecordSRV {
		return fmt.Errorf("record type %s does not use priority", record.Type)
	}
	return nil
}

func validateCAAValue(record domain.DNSRecord) error {
	if len(record.Data) > 0 && string(record.Data) != "null" {
		var data struct {
			Flags uint8  `json:"flags"`
			Tag   string `json:"tag"`
			Value string `json:"value"`
		}
		if json.Unmarshal(record.Data, &data) != nil || strings.TrimSpace(data.Tag) == "" {
			return errors.New("CAA data must contain valid flags, tag, and value fields")
		}
		return nil
	}
	parts := strings.Fields(record.Content)
	if len(parts) < 3 {
		return errors.New("CAA content must be: flags tag value")
	}
	if _, err := strconv.ParseUint(parts[0], 10, 8); err != nil {
		return errors.New("CAA flags must be between 0 and 255")
	}
	return nil
}

func validateSRVValue(record domain.DNSRecord) error {
	if len(record.Data) > 0 && string(record.Data) != "null" {
		var data struct {
			Priority uint16 `json:"priority"`
			Weight   uint16 `json:"weight"`
			Port     uint16 `json:"port"`
			Target   string `json:"target"`
		}
		if json.Unmarshal(record.Data, &data) != nil || strings.TrimSpace(data.Target) == "" {
			return errors.New("SRV data must contain valid priority, weight, port, and target fields")
		}
		return nil
	}
	parts := strings.Fields(record.Content)
	start := 0
	if len(parts) == 3 && record.Priority != nil {
		start = -1
	} else if len(parts) != 4 {
		return errors.New("SRV content must be: priority weight port target")
	}
	for index, label := range []string{"priority", "weight", "port"} {
		if start == -1 && index == 0 {
			continue
		}
		partIndex := index
		if start == -1 {
			partIndex--
		}
		if _, err := strconv.ParseUint(parts[partIndex], 10, 16); err != nil {
			return fmt.Errorf("SRV %s must be between 0 and 65535", label)
		}
	}
	if strings.TrimSpace(parts[len(parts)-1]) == "" {
		return errors.New("SRV target is required")
	}
	return nil
}

func toASCIIDNSName(name string) (string, error) {
	labels := strings.Split(name, ".")
	for index, label := range labels {
		if label == "" {
			return "", errors.New("DNS name contains an empty label")
		}
		if label == "*" || strings.HasPrefix(label, "_") {
			labels[index] = strings.ToLower(label)
			continue
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", err
		}
		labels[index] = ascii
	}
	return strings.ToLower(strings.Join(labels, ".")), nil
}

func sameDNSRecordVersion(cached, remote domain.DNSRecord) bool {
	if cached.ModifiedAt != nil && remote.ModifiedAt != nil && !cached.ModifiedAt.Equal(*remote.ModifiedAt) {
		return false
	}
	if cached.Type != remote.Type ||
		!strings.EqualFold(strings.TrimSuffix(cached.Name, "."), strings.TrimSuffix(remote.Name, ".")) ||
		cached.Content != remote.Content || cached.TTL != remote.TTL ||
		cached.Proxied != remote.Proxied || cached.Proxiable != remote.Proxiable ||
		cached.Comment != remote.Comment || cached.Managed != remote.Managed ||
		!samePriority(cached.Priority, remote.Priority) || !sameJSON(cached.Data, remote.Data) {
		return false
	}
	cachedTags := slices.Clone(cached.Tags)
	remoteTags := slices.Clone(remote.Tags)
	slices.Sort(cachedTags)
	slices.Sort(remoteTags)
	return slices.Equal(cachedTags, remoteTags)
}

func samePriority(left, right *uint16) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func sameJSON(left, right json.RawMessage) bool {
	leftEmpty := len(left) == 0 || string(left) == "null"
	rightEmpty := len(right) == 0 || string(right) == "null"
	if leftEmpty || rightEmpty {
		return leftEmpty == rightEmpty
	}
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return string(left) == string(right)
	}
	leftCanonical, leftErr := json.Marshal(leftValue)
	rightCanonical, rightErr := json.Marshal(rightValue)
	return leftErr == nil && rightErr == nil && string(leftCanonical) == string(rightCanonical)
}

func (s *Service) ensureDefaultEndpoints(ctx context.Context, zone domain.Zone, records []domain.DNSRecord) error {
	zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
	targets := []string{zoneName, "www." + zoneName}
	targetSet := map[string]bool{targets[0]: true, targets[1]: true}
	active := make(map[string]bool, len(targets))
	for _, record := range records {
		recordName := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		if !targetSet[recordName] {
			continue
		}
		switch record.Type {
		case domain.RecordA, domain.RecordAAAA, domain.RecordCNAME:
		default:
			continue
		}
		active[recordName] = true
	}

	existing, err := s.repo.ListEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("list observed endpoints: %w", err)
	}
	zones, err := s.repo.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("list zones for endpoint ownership: %w", err)
	}
	byAddress := make(map[string]domain.ObservedEndpoint, len(existing))
	for _, endpoint := range existing {
		byAddress[endpointAddressKey(endpoint.Host, endpoint.Port)] = endpoint
	}
	var failures []error
	for _, host := range targets {
		owner, owned := longestEndpointOwner(zones, host)
		if !owned || owner.ID != zone.ID {
			// A nested active zone owns this host. Its reconciliation reuses the
			// retained UNIQUE(host,port) endpoint and controls its enabled state.
			continue
		}
		endpoint, exists := byAddress[endpointAddressKey(host, 443)]
		if !exists && !active[host] {
			continue
		}
		if !exists {
			endpoint = domain.ObservedEndpoint{ID: stableID("endpoint", zone.ID, host, "443"), Host: host, Port: 443}
		}
		// Preserve the endpoint ID and observation history when zone identity
		// changes; host+port is the durable physical endpoint identity.
		endpoint.ZoneID = zone.ID
		endpoint.Host = host
		endpoint.Port = 443
		endpoint.Enabled = active[host]
		if err := s.repo.SaveEndpoint(ctx, endpoint); err != nil {
			failures = append(failures, fmt.Errorf("save generated endpoint %s: %w", host, err))
			continue
		}
		if !endpoint.Enabled {
			if err := s.repo.SaveHealthIssues(ctx, endpoint.ID, nil); err != nil {
				failures = append(failures, fmt.Errorf("clear disabled endpoint issues %s: %w", host, err))
			}
		}
	}
	return errors.Join(failures...)
}

func endpointAddressKey(host string, port int) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), ".")) + "\x00" + strconv.Itoa(port)
}

func longestEndpointOwner(zones []domain.Zone, host string) (domain.Zone, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	var selected domain.Zone
	selectedName := ""
	for _, candidate := range zones {
		if candidate.Status != domain.ZoneActive || candidate.Paused {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(candidate.Name), "."))
		if host != name && !strings.HasSuffix(host, "."+name) {
			continue
		}
		if selected.ID == "" || len(name) > len(selectedName) || (len(name) == len(selectedName) && candidate.ID < selected.ID) {
			selected, selectedName = candidate, name
		}
	}
	return selected, selected.ID != ""
}

func stableID(prefix string, values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + "_" + hex.EncodeToString(sum[:12])
}

func shortID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

func progress(completed, total, span int) int {
	if total <= 0 {
		return span
	}
	return completed * span / total
}

func (s *Service) audit(ctx context.Context, action, resourceID string, before, after interface{}) {
	marshal := func(value interface{}) (json.RawMessage, error) {
		if value == nil {
			return nil, nil
		}
		return json.Marshal(value)
	}
	beforeJSON, beforeErr := marshal(before)
	afterJSON, afterErr := marshal(after)
	if err := errors.Join(beforeErr, afterErr); err != nil {
		s.publish(Event{Kind: "audit.warning", Message: "encode audit event: " + err.Error()})
		return
	}
	if err := s.repo.AppendAudit(ctx, domain.AuditEvent{
		ID: identifier.New("audit"), Actor: "local-user", Action: action,
		ResourceID: resourceID, Before: beforeJSON, After: afterJSON, CreatedAt: s.now().UTC(),
	}); err != nil {
		s.publish(Event{Kind: "audit.warning", Message: "persist audit event: " + err.Error()})
	}
}
