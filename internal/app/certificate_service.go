package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
	"github.com/MeghdadFadaee/domainops/internal/store"
	"golang.org/x/sync/errgroup"
)

type CertificateService struct {
	Repository  store.Repository
	Secrets     store.SecretStore
	Engine      *certificates.Engine
	Lifecycle   *certificates.Lifecycle
	ExportRoot  string
	Now         func() time.Time
	JobObserver func(domain.Job)
}

type IssueZonesRequest struct {
	ZoneIDs           []string
	NestedNames       []string
	Environment       string
	Email             string
	AcceptTerms       bool
	ConfirmProduction bool
	KeyAlgorithm      domain.KeyAlgorithm
}

type IssueZonesResult struct {
	Completed []certificates.CommitResult `json:"completed"`
	Failed    []IssueFailure              `json:"failed"`
}

func (r IssueZonesResult) WarningCount() int {
	total := 0
	for _, commit := range r.Completed {
		total += len(commit.Warnings)
	}
	return total
}

type IssueFailure struct {
	ZoneID string `json:"zone_id"`
	Name   string `json:"name"`
	Error  string `json:"error"`
}

func NewCertificateService(repository store.Repository, secrets store.SecretStore, engine *certificates.Engine, exportRoot string) *CertificateService {
	return &CertificateService{
		Repository: repository,
		Secrets:    secrets,
		Engine:     engine,
		Lifecycle:  &certificates.Lifecycle{Repository: repository, Secrets: secrets},
		ExportRoot: exportRoot,
		Now:        time.Now,
	}
}

func (s *CertificateService) RegisterAccount(ctx context.Context, environment, email string, acceptTerms bool) (domain.ACMEAccount, error) {
	if s == nil || s.Engine == nil {
		return domain.ACMEAccount{}, errors.New("certificate service is not configured")
	}
	if existing, err := s.Repository.GetACMEAccountByEnvironment(ctx, environment); err == nil {
		return domain.ACMEAccount{}, fmt.Errorf("a %s ACME account already exists (%s); account replacement is intentionally not automatic", environment, existing.Email)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEAccount{}, err
	}
	return s.Engine.Accounts().Register(ctx, certificates.RegisterAccountRequest{
		Environment: environment, Email: email, TermsOfServiceAgreed: acceptTerms,
	})
}

func (s *CertificateService) IssueZones(ctx context.Context, request IssueZonesRequest) (IssueZonesResult, error) {
	if s == nil || s.Repository == nil || s.Engine == nil || s.Lifecycle == nil {
		return IssueZonesResult{}, errors.New("certificate service is not configured")
	}
	if len(request.ZoneIDs) == 0 {
		return IssueZonesResult{}, errors.New("at least one zone is required")
	}
	if request.Environment == "" {
		request.Environment = certificates.EnvironmentStaging
	}
	if request.KeyAlgorithm == "" {
		request.KeyAlgorithm = domain.KeyECDSAP256
	}
	account, err := s.Repository.GetACMEAccountByEnvironment(ctx, request.Environment)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) || strings.TrimSpace(request.Email) == "" {
			return IssueZonesResult{}, fmt.Errorf("load %s ACME account (register it first or provide --email): %w", request.Environment, err)
		}
		account, err = s.RegisterAccount(ctx, request.Environment, request.Email, request.AcceptTerms)
		if err != nil {
			return IssueZonesResult{}, err
		}
	}

	lineages, err := s.Repository.ListCertificateLineages(ctx)
	if err != nil {
		return IssueZonesResult{}, err
	}
	existing := make(map[string]domain.CertificateLineage)
	for _, lineage := range lineages {
		if lineage.Source == domain.CertificateManaged && lineage.ZoneID != "" {
			existing[certificateLineageKey(lineage.ZoneID, lineage.ACMEAccountID)] = lineage
		}
	}

	type workItem struct {
		zone domain.Zone
		plan certificates.Plan
		job  domain.Job
	}
	items := make([]workItem, 0, len(request.ZoneIDs))
	seen := make(map[string]struct{})
	for _, zoneID := range request.ZoneIDs {
		if _, duplicate := seen[zoneID]; duplicate {
			continue
		}
		seen[zoneID] = struct{}{}
		zone, zoneErr := s.Repository.GetZone(ctx, zoneID)
		if zoneErr != nil {
			return IssueZonesResult{}, fmt.Errorf("load zone %s: %w", zoneID, zoneErr)
		}
		plan, planErr := certificates.NewWildcardPlan(zone.ID, zone.Name, request.NestedNames...)
		if planErr != nil {
			return IssueZonesResult{}, planErr
		}
		plan.KeyAlgorithm = request.KeyAlgorithm
		now := s.now().UTC()
		payload, _ := json.Marshal(map[string]any{"environment": request.Environment, "plan": plan})
		job := domain.Job{ID: identifier.New("job"), Kind: "certificate.issue", State: domain.JobRunning, ResourceID: zone.ID, Progress: 5, Message: "Preparing ACME order for " + zone.Name, Payload: payload, CreatedAt: now, StartedAt: &now, UpdatedAt: now}
		if err := s.saveJob(ctx, job); err != nil {
			return IssueZonesResult{}, err
		}
		items = append(items, workItem{zone: zone, plan: plan, job: job})
	}

	type zoneOutcome struct {
		commit  *certificates.CommitResult
		failure *IssueFailure
		err     error
	}
	outcomes := make([]zoneOutcome, len(items))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(3)
	for index := range items {
		index := index
		group.Go(func() error {
			item := items[index]
			job := item.job
			issued, issueErr := s.Engine.Issue(groupCtx, certificates.IssueRequest{
				JobID: item.job.ID, Environment: request.Environment, Plan: item.plan,
				ConfirmProduction: request.ConfirmProduction,
				Progress: func(progress certificates.IssueProgress) {
					job.Progress = progress.Percent
					job.Message = item.zone.Name + " · " + progress.Message
					job.UpdatedAt = s.now().UTC()
					if progress.WaitingDNS {
						job.State = domain.JobWaitingForDNS
					} else {
						job.State = domain.JobRunning
					}
					_ = s.saveJob(groupCtx, job)
				},
			})
			finished := s.now().UTC()
			if issueErr != nil {
				job.State, job.Progress = domain.JobFailed, 100
				job.Message, job.Error = "Certificate issuance failed", issueErr.Error()
				if errors.Is(issueErr, context.Canceled) {
					job.State, job.Message = domain.JobCancelled, "Certificate issuance cancelled after DNS cleanup"
				}
				job.FinishedAt, job.UpdatedAt = &finished, finished
				_ = s.saveJob(context.WithoutCancel(groupCtx), job)
				failure := IssueFailure{ZoneID: item.zone.ID, Name: item.zone.Name, Error: issueErr.Error()}
				outcomes[index] = zoneOutcome{failure: &failure, err: fmt.Errorf("%s: %w", item.zone.Name, issueErr)}
				return nil
			}

			// Once the CA has issued material, finalization must get a brief chance
			// to persist it even if the caller cancels the remaining bulk job.
			job.State, job.Progress = domain.JobRunning, 90
			job.Message, job.UpdatedAt = "Storing and activating issued certificate", s.now().UTC()
			_ = s.saveJob(context.WithoutCancel(groupCtx), job)
			finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(groupCtx), 2*time.Minute)
			defer cancel()
			var previous *domain.CertificateLineage
			if value, ok := existing[certificateLineageKey(item.zone.ID, account.ID)]; ok {
				copy := value
				previous = &copy
			}
			commit, commitErr := s.Lifecycle.CommitManaged(finalizeCtx, certificates.CommitRequest{
				ExistingLineage: previous,
				Plan:            item.plan,
				ACMEAccountID:   account.ID,
				Artifact:        issued.Artifact,
				RenewalWindow:   &issued.RenewalWindow,
				ExportRoot:      s.managedExportRoot(request.Environment, item.zone.Name),
			})
			finished = s.now().UTC()
			if commitErr != nil {
				job.State, job.Message, job.Error = domain.JobFailed, "Certificate storage failed", commitErr.Error()
				failure := IssueFailure{ZoneID: item.zone.ID, Name: item.zone.Name, Error: commitErr.Error()}
				outcomes[index] = zoneOutcome{failure: &failure, err: fmt.Errorf("%s: %w", item.zone.Name, commitErr)}
			} else {
				job.State, job.Message = domain.JobSucceeded, "Certificate issued and stored"
				if len(commit.Warnings) > 0 {
					job.Message = "Certificate issued and stored with activation warning"
				}
				outcomes[index].commit = &commit
				_ = s.Repository.AppendAudit(finalizeCtx, domain.AuditEvent{ID: identifier.New("audit"), Actor: "local-user", Action: "certificate.issue", ResourceID: commit.Lineage.ID, CreatedAt: finished})
			}
			job.Progress = 100
			job.FinishedAt, job.UpdatedAt = &finished, finished
			_ = s.saveJob(finalizeCtx, job)
			return nil
		})
	}
	groupErr := group.Wait()
	result := IssueZonesResult{}
	var failures []error
	for _, outcome := range outcomes {
		if outcome.commit != nil {
			result.Completed = append(result.Completed, *outcome.commit)
		}
		if outcome.failure != nil {
			result.Failed = append(result.Failed, *outcome.failure)
		}
		if outcome.err != nil {
			failures = append(failures, outcome.err)
		}
	}
	if groupErr != nil {
		failures = append(failures, groupErr)
	}
	return result, errors.Join(failures...)
}

func (s *CertificateService) saveJob(ctx context.Context, job domain.Job) error {
	err := s.Repository.SaveJob(ctx, job)
	if s.JobObserver != nil {
		s.JobObserver(job)
	}
	return err
}

func (s *CertificateService) RenewDue(ctx context.Context, environment string, confirmProduction bool) (IssueZonesResult, error) {
	if environment == "" {
		environment = certificates.EnvironmentProduction
	}
	account, err := s.Repository.GetACMEAccountByEnvironment(ctx, environment)
	if err != nil {
		return IssueZonesResult{}, fmt.Errorf("load %s ACME account: %w", environment, err)
	}
	lineages, err := s.Repository.ListCertificateLineages(ctx)
	if err != nil {
		return IssueZonesResult{}, err
	}
	now := s.now()
	type renewalItem struct {
		lineage        domain.CertificateLineage
		version        domain.CertificateVersion
		zone           domain.Zone
		certificatePEM []byte
	}
	var items []renewalItem
	for _, lineage := range lineages {
		if lineage.Source != domain.CertificateManaged || lineage.CurrentVersionID == "" || lineage.ACMEAccountID != account.ID {
			continue
		}
		versions, versionErr := s.Repository.ListCertificateVersions(ctx, lineage.ID)
		if versionErr != nil {
			return IssueZonesResult{}, versionErr
		}
		for _, version := range versions {
			if version.ID != lineage.CurrentVersionID {
				continue
			}
			if version.RevokedAt != nil || version.RevocationPendingAt != nil {
				continue
			}
			due := version.RenewalWindowStart
			if due == nil {
				value := version.NotBefore.Add(version.NotAfter.Sub(version.NotBefore) * 2 / 3)
				due = &value
			}
			if !now.Before(*due) {
				zone, zoneErr := s.Repository.GetZone(ctx, lineage.ZoneID)
				if zoneErr != nil {
					return IssueZonesResult{}, fmt.Errorf("load renewal zone for %s: %w", lineage.Name, zoneErr)
				}
				certificatePEM, readErr := os.ReadFile(version.CertificatePath)
				if readErr != nil {
					return IssueZonesResult{}, fmt.Errorf("read current certificate for %s: %w", lineage.Name, readErr)
				}
				items = append(items, renewalItem{lineage: lineage, version: version, zone: zone, certificatePEM: certificatePEM})
			}
		}
	}
	if len(items) == 0 {
		return IssueZonesResult{}, nil
	}
	result := IssueZonesResult{}
	var resultMu sync.Mutex
	var failures []error
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(3)
	for _, current := range items {
		item := current
		group.Go(func() error {
			started := s.now()
			job := domain.Job{ID: identifier.New("job"), Kind: "certificate.renew", State: domain.JobRunning, ResourceID: item.zone.ID, Progress: 5, Message: "Renewing " + item.lineage.Name, CreatedAt: started, StartedAt: &started, UpdatedAt: started}
			if saveErr := s.saveJob(groupCtx, job); saveErr != nil {
				return saveErr
			}
			plan := certificates.Plan{Name: item.lineage.Name, ZoneID: item.zone.ID, ZoneName: item.zone.Name, Identifiers: slices.Clone(item.lineage.Identifiers), KeyAlgorithm: item.lineage.KeyAlgorithm, Profile: item.lineage.Profile}
			issued, renewErr := s.Engine.Renew(groupCtx, certificates.RenewRequest{IssueRequest: certificates.IssueRequest{
				JobID: job.ID, Environment: environment, Plan: plan, ConfirmProduction: confirmProduction,
				Progress: func(progress certificates.IssueProgress) {
					job.Progress, job.Message, job.UpdatedAt = progress.Percent, item.lineage.Name+" · "+progress.Message, s.now().UTC()
					if progress.WaitingDNS {
						job.State = domain.JobWaitingForDNS
					} else {
						job.State = domain.JobRunning
					}
					_ = s.saveJob(groupCtx, job)
				},
			}, PreviousCertificatePEM: item.certificatePEM})
			finished := s.now()
			if renewErr != nil {
				job.State, job.Progress, job.Message, job.Error = domain.JobFailed, 100, "Certificate renewal failed", renewErr.Error()
				if errors.Is(renewErr, context.Canceled) {
					job.State, job.Message = domain.JobCancelled, "Certificate renewal cancelled after DNS cleanup"
				}
				job.FinishedAt, job.UpdatedAt = &finished, finished
				_ = s.saveJob(context.Background(), job)
				resultMu.Lock()
				result.Failed = append(result.Failed, IssueFailure{ZoneID: item.zone.ID, Name: item.lineage.Name, Error: renewErr.Error()})
				failures = append(failures, fmt.Errorf("%s: %w", item.lineage.Name, renewErr))
				resultMu.Unlock()
				return nil
			}
			job.State, job.Progress = domain.JobRunning, 90
			job.Message, job.UpdatedAt = "Storing and activating renewed certificate", s.now().UTC()
			_ = s.saveJob(context.WithoutCancel(groupCtx), job)
			finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(groupCtx), 2*time.Minute)
			defer cancel()
			exportRoot := s.managedExportRoot(environment, item.zone.Name)
			if item.version.ExportPath != "" {
				exportRoot = filepath.Dir(item.version.ExportPath)
			}
			commit, commitErr := s.Lifecycle.CommitManaged(finalizeCtx, certificates.CommitRequest{ExistingLineage: &item.lineage, Plan: plan, ACMEAccountID: account.ID, Artifact: issued.Artifact, RenewalWindow: &issued.RenewalWindow, ExportRoot: exportRoot})
			if commitErr != nil {
				job.State, job.Message, job.Error = domain.JobFailed, "Certificate renewal storage failed", commitErr.Error()
				resultMu.Lock()
				result.Failed = append(result.Failed, IssueFailure{ZoneID: item.zone.ID, Name: item.lineage.Name, Error: commitErr.Error()})
				failures = append(failures, fmt.Errorf("%s: %w", item.lineage.Name, commitErr))
				resultMu.Unlock()
			} else {
				job.State, job.Message = domain.JobSucceeded, "Certificate renewed and stored"
				if len(commit.Warnings) > 0 {
					job.Message = "Certificate renewed and stored with activation warning"
				}
				_ = s.Repository.AppendAudit(finalizeCtx, domain.AuditEvent{ID: identifier.New("audit"), Actor: "local-user", Action: "certificate.renew", ResourceID: commit.Lineage.ID, CreatedAt: finished})
				resultMu.Lock()
				result.Completed = append(result.Completed, commit)
				resultMu.Unlock()
			}
			job.Progress, job.FinishedAt, job.UpdatedAt = 100, &finished, finished
			_ = s.saveJob(finalizeCtx, job)
			return nil
		})
	}
	if groupErr := group.Wait(); groupErr != nil {
		failures = append(failures, groupErr)
	}
	return result, errors.Join(failures...)
}

func (s *CertificateService) ImportMetadata(ctx context.Context, path, name, zoneID string) (domain.CertificateLineage, domain.CertificateVersion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, fmt.Errorf("read certificate: %w", err)
	}
	lineage, version, err := certificates.ImportMetadata("", name, zoneID, data, s.now())
	if err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, err
	}
	dir := filepath.Join(s.ExportRoot, "imported", lineage.ID)
	certificatePath := filepath.Join(dir, version.ID+".pem")
	intent := domain.CertificateCommitIntent{
		VersionID: version.ID, LineageID: lineage.ID,
		ArtifactPath: certificatePath, CreatedAt: s.now(),
	}
	if err := s.Repository.SaveCertificateCommitIntent(ctx, intent); err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, fmt.Errorf("journal imported certificate: %w", err)
	}
	cleanup := func(importErr error) (domain.CertificateLineage, domain.CertificateVersion, error) {
		cleanupErr := certificates.CleanupCertificateCommitIntent(context.WithoutCancel(ctx), s.Lifecycle.Repository, s.Secrets, intent)
		return domain.CertificateLineage{}, domain.CertificateVersion{}, errors.Join(importErr, cleanupErr)
	}
	if err := certificates.EnsurePrivateDirectoryDurable(dir); err != nil {
		return cleanup(err)
	}
	if err := writeSyncedPrivateFile(certificatePath, data); err != nil {
		return cleanup(err)
	}
	version.CertificatePath = certificatePath
	auditAction := "certificate.import_metadata"
	if persistErr := s.Lifecycle.PersistImportedMetadata(ctx, lineage, version); persistErr != nil {
		pending, inspectErr := certificates.CertificateCommitIntentPending(context.WithoutCancel(ctx), s.Lifecycle.Repository, version.ID)
		if inspectErr != nil {
			// The transaction may have committed. Preserve the journal and PEM so
			// startup recovery can resolve the outcome without destroying a live
			// imported certificate.
			return domain.CertificateLineage{}, domain.CertificateVersion{}, errors.Join(
				fmt.Errorf("imported certificate commit outcome is unknown; artifact was preserved: %w", persistErr),
				fmt.Errorf("inspect certificate commit journal: %w", inspectErr),
			)
		}
		if pending {
			return cleanup(persistErr)
		}
		auditAction = "certificate.import_metadata.commit_reconciled"
	}
	_ = s.Repository.AppendAudit(ctx, domain.AuditEvent{ID: identifier.New("audit"), Actor: "local-user", Action: auditAction, ResourceID: lineage.ID, CreatedAt: s.now()})
	return lineage, version, nil
}

func writeSyncedPrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncPrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncPrivateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *CertificateService) Export(ctx context.Context, lineageID, destination string) (certificates.ExportResult, error) {
	lineage, err := s.Repository.GetCertificateLineage(ctx, lineageID)
	if err != nil {
		return certificates.ExportResult{}, err
	}
	if lineage.Source != domain.CertificateManaged {
		return certificates.ExportResult{}, errors.New("metadata-only certificates do not have an exportable private key")
	}
	versions, err := s.Repository.ListCertificateVersions(ctx, lineage.ID)
	if err != nil {
		return certificates.ExportResult{}, err
	}
	var version domain.CertificateVersion
	for _, candidate := range versions {
		if candidate.ID == lineage.CurrentVersionID {
			version = candidate
			break
		}
	}
	if version.ID == "" {
		return certificates.ExportResult{}, errors.New("current certificate version is missing")
	}
	if version.RevocationPendingAt != nil {
		return certificates.ExportResult{}, errors.New("current certificate revocation is pending; refusing to export deployable key material")
	}
	if version.RevokedAt != nil {
		return certificates.ExportResult{}, fmt.Errorf("current certificate was revoked at %s; refusing to export deployable key material", version.RevokedAt.UTC().Format(time.RFC3339))
	}
	certificatePEM, err := os.ReadFile(version.CertificatePath)
	if err != nil {
		return certificates.ExportResult{}, err
	}
	var chainPEM []byte
	if version.ChainPath != "" {
		chainPEM, err = os.ReadFile(version.ChainPath)
		if err != nil {
			return certificates.ExportResult{}, err
		}
	}
	keyPEM, err := s.Secrets.Get(ctx, version.PrivateKeyRef)
	if err != nil {
		return certificates.ExportResult{}, err
	}
	_, _, _, metadata, err := certificates.ParseCertificatePEM(append(slices.Clone(certificatePEM), chainPEM...))
	if err != nil {
		return certificates.ExportResult{}, err
	}
	artifact := certificates.Artifact{CertificatePEM: certificatePEM, ChainPEM: chainPEM, PrivateKeyPEM: keyPEM, Metadata: metadata}
	result, err := certificates.ExportVersion(filepath.Join(destination, lineage.Name), lineage, version, artifact, s.now().UTC())
	if err == nil {
		_ = s.Repository.AppendAudit(ctx, domain.AuditEvent{ID: identifier.New("audit"), Actor: "local-user", Action: "certificate.export", ResourceID: lineage.ID, CreatedAt: s.now()})
	}
	return result, err
}

// RepairManagedCurrentLinks converges filesystem convenience links from the
// authoritative lineage/version rows. It is safe to run repeatedly after a
// crash or a post-commit symlink failure.
func (s *CertificateService) RepairManagedCurrentLinks(ctx context.Context) error {
	lineages, err := s.Repository.ListCertificateLineages(ctx)
	if err != nil {
		return err
	}
	var repairErrors []error
	for _, lineage := range lineages {
		if lineage.Source != domain.CertificateManaged || lineage.CurrentVersionID == "" {
			continue
		}
		versions, listErr := s.Repository.ListCertificateVersions(ctx, lineage.ID)
		if listErr != nil {
			repairErrors = append(repairErrors, fmt.Errorf("%s: %w", lineage.Name, listErr))
			continue
		}
		for _, version := range versions {
			if version.ID != lineage.CurrentVersionID || version.ExportPath == "" {
				continue
			}
			if activateErr := certificates.ActivateVersion(filepath.Dir(version.ExportPath), version.ID); activateErr != nil {
				repairErrors = append(repairErrors, fmt.Errorf("%s: %w", lineage.Name, activateErr))
			}
			break
		}
	}
	return errors.Join(repairErrors...)
}

func (s *CertificateService) Revoke(ctx context.Context, lineageID, environment, confirmation string, reason *uint) error {
	lineage, err := s.Repository.GetCertificateLineage(ctx, lineageID)
	if err != nil {
		return err
	}
	if confirmation != lineage.Name {
		return fmt.Errorf("revocation confirmation must exactly match %q", lineage.Name)
	}
	if reason != nil && (*reason > 10 || *reason == 7) {
		return errors.New("revocation reason must be an RFC 5280 code from 0 through 10, excluding 7")
	}
	account, err := s.Repository.GetACMEAccountByEnvironment(ctx, environment)
	if err != nil {
		return fmt.Errorf("load %s ACME account: %w", environment, err)
	}
	if lineage.ACMEAccountID == "" || lineage.ACMEAccountID != account.ID {
		return fmt.Errorf("certificate %q is not owned by the selected %s ACME account", lineage.Name, environment)
	}
	versions, err := s.Repository.ListCertificateVersions(ctx, lineage.ID)
	if err != nil {
		return err
	}
	var version domain.CertificateVersion
	for _, candidate := range versions {
		if candidate.ID == lineage.CurrentVersionID {
			version = candidate
			break
		}
	}
	if version.ID == "" {
		return errors.New("current certificate version is missing")
	}
	if version.RevokedAt != nil {
		return fmt.Errorf("certificate %q was already revoked at %s", lineage.Name, version.RevokedAt.UTC().Format(time.RFC3339))
	}
	if version.RevocationPendingAt != nil && !sameRevocationReason(version.RevocationReason, reason) {
		return errors.New("a revocation intent already exists with a different reason; retry with the original reason")
	}
	certificatePEM, err := os.ReadFile(version.CertificatePath)
	if err != nil {
		return err
	}
	now := s.now()
	job := domain.Job{ID: identifier.New("job"), Kind: "certificate.revoke", State: domain.JobRunning, ResourceID: lineage.ID, Progress: 10, Message: "Revoking " + lineage.Name, CreatedAt: now, StartedAt: &now, UpdatedAt: now}
	if err := s.Repository.SaveJob(ctx, job); err != nil {
		return err
	}
	if version.RevocationPendingAt == nil {
		pendingAt := now
		version.RevocationPendingAt = &pendingAt
		if reason != nil {
			value := *reason
			version.RevocationReason = &value
		}
		if err := s.Repository.SaveCertificateVersion(ctx, version); err != nil {
			job.State, job.Progress, job.Message, job.Error = domain.JobFailed, 100, "Could not persist revocation intent", err.Error()
			finished := s.now()
			job.FinishedAt, job.UpdatedAt = &finished, finished
			_ = s.Repository.SaveJob(context.WithoutCancel(ctx), job)
			return fmt.Errorf("persist revocation intent before contacting CA: %w", err)
		}
	}
	revokeErr := s.Engine.Revoke(ctx, certificates.RevokeRequest{Environment: environment, Lineage: lineage, CertificatePEM: certificatePEM, Reason: reason, ConfirmRevocation: true})
	finished := s.now()
	if revokeErr == nil || certificates.IsAlreadyRevoked(revokeErr) {
		revokeErr = nil
		version.RevokedAt = &finished
		version.RevocationPendingAt = nil
		finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if saveErr := s.Repository.SaveCertificateVersion(finalizeCtx, version); saveErr != nil {
			revokeErr = fmt.Errorf("certificate was revoked by the CA but local state could not be updated: %w", saveErr)
		}
	}
	job.Progress, job.FinishedAt, job.UpdatedAt = 100, &finished, finished
	if revokeErr != nil {
		job.State, job.Message, job.Error = domain.JobFailed, "Certificate revocation failed", revokeErr.Error()
	} else {
		job.State, job.Message = domain.JobSucceeded, "Certificate revoked"
		_ = s.Repository.AppendAudit(context.WithoutCancel(ctx), domain.AuditEvent{ID: identifier.New("audit"), Actor: "local-user", Action: "certificate.revoke", ResourceID: lineage.ID, CreatedAt: finished})
	}
	_ = s.Repository.SaveJob(context.Background(), job)
	return revokeErr
}

func sameRevocationReason(left, right *uint) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func (s *CertificateService) ExpectedFingerprint(ctx context.Context, endpoint domain.ObservedEndpoint) (string, error) {
	// A proxied A/AAAA/CNAME endpoint serves Cloudflare's edge certificate, not
	// the locally stored origin certificate. Continue checking trust, hostname,
	// and expiry at the edge, but do not raise a false stale-origin warning.
	if endpoint.ZoneID != "" {
		records, recordErr := s.Repository.ListDNSRecords(ctx, endpoint.ZoneID)
		if recordErr != nil {
			return "", recordErr
		}
		host := strings.ToLower(strings.TrimSuffix(endpoint.Host, "."))
		for _, record := range records {
			recordHost := strings.ToLower(strings.TrimSuffix(record.Name, "."))
			if recordHost != host || !record.Proxied {
				continue
			}
			if record.Type == domain.RecordA || record.Type == domain.RecordAAAA || record.Type == domain.RecordCNAME {
				return "", nil
			}
		}
	}
	lineages, err := s.Repository.ListCertificateLineages(ctx)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSuffix(endpoint.Host, "."))
	productionAccountID := ""
	if account, accountErr := s.Repository.GetACMEAccountByEnvironment(ctx, certificates.EnvironmentProduction); accountErr == nil {
		productionAccountID = account.ID
	} else if !errors.Is(accountErr, sql.ErrNoRows) {
		return "", accountErr
	}
	type candidate struct {
		lineage domain.CertificateLineage
		score   int
	}
	var candidates []candidate
	for _, lineage := range lineages {
		if lineage.CurrentVersionID == "" || !identifiersCover(lineage.Identifiers, host) ||
			(endpoint.ZoneID != "" && lineage.ZoneID != "" && lineage.ZoneID != endpoint.ZoneID) {
			continue
		}
		score := identifierSpecificity(lineage.Identifiers, host)
		// Imports are not always associated with a managed zone. Keep them
		// eligible by identifier, but prefer an otherwise comparable lineage
		// that is explicitly owned by the endpoint's zone.
		if endpoint.ZoneID != "" && lineage.ZoneID == endpoint.ZoneID {
			score += 25
		}
		if lineage.Source == domain.CertificateManaged {
			score += 20
		} else if lineage.Source == domain.CertificateImported {
			score += 50
		}
		if productionAccountID != "" && lineage.ACMEAccountID == productionAccountID {
			score += 100
		}
		candidates = append(candidates, candidate{lineage: lineage, score: score})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].lineage.UpdatedAt.After(candidates[j].lineage.UpdatedAt)
	})
	for _, candidate := range candidates {
		lineage := candidate.lineage
		versions, versionErr := s.Repository.ListCertificateVersions(ctx, lineage.ID)
		if versionErr != nil {
			return "", versionErr
		}
		for _, version := range versions {
			if version.ID == lineage.CurrentVersionID {
				if version.RevokedAt != nil {
					return "revoked:" + version.FingerprintSHA256, nil
				}
				if version.RevocationPendingAt != nil {
					return "revocation-pending:" + version.FingerprintSHA256, nil
				}
				return version.FingerprintSHA256, nil
			}
		}
	}
	return "", nil
}

func identifierSpecificity(identifiers []string, host string) int {
	for _, value := range identifiers {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if value == host {
			return 10
		}
	}
	return 1
}

func identifiersCover(identifiers []string, host string) bool {
	for _, identifier := range identifiers {
		identifier = strings.ToLower(strings.TrimSuffix(identifier, "."))
		if identifier == host {
			return true
		}
		if strings.HasPrefix(identifier, "*.") {
			suffix := strings.TrimPrefix(identifier, "*.")
			if strings.HasSuffix(host, "."+suffix) && strings.Count(host, ".") == strings.Count(suffix, ".")+1 {
				return true
			}
		}
	}
	return false
}

func (s *CertificateService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func certificateLineageKey(zoneID, accountID string) string {
	return zoneID + "\x00" + accountID
}

func (s *CertificateService) managedExportRoot(environment, zoneName string) string {
	if environment == certificates.EnvironmentStaging {
		return filepath.Join(s.ExportRoot, "staging", zoneName)
	}
	return filepath.Join(s.ExportRoot, zoneName)
}
