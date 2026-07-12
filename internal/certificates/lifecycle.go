package certificates

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/identifier"
)

type CertificateRepository interface {
	SaveCertificateLineage(context.Context, domain.CertificateLineage) error
	SaveCertificateVersion(context.Context, domain.CertificateVersion) error
	CommitCertificateVersion(context.Context, domain.CertificateLineage, domain.CertificateVersion) error
	SaveCertificateCommitIntent(context.Context, domain.CertificateCommitIntent) error
	ListCertificateCommitIntents(context.Context) ([]domain.CertificateCommitIntent, error)
	DeleteCertificateCommitIntent(context.Context, string) error
}

type Lifecycle struct {
	Repository CertificateRepository
	Secrets    SecretStore
	Now        func() time.Time
}

type CommitRequest struct {
	ExistingLineage *domain.CertificateLineage
	Plan            Plan
	ACMEAccountID   string
	Artifact        Artifact
	RenewalWindow   *RenewalWindow
	ExportRoot      string
}

type CommitResult struct {
	Lineage  domain.CertificateLineage `json:"lineage"`
	Version  domain.CertificateVersion `json:"version"`
	Export   ExportResult              `json:"export"`
	Warnings []string                  `json:"warnings,omitempty"`
}

// CommitManaged validates and exports a new immutable version, stores the key
// in the encrypted vault, and advances the lineage only after the version row
// is durable. Previous versions are intentionally retained.
func (l *Lifecycle) CommitManaged(ctx context.Context, request CommitRequest) (CommitResult, error) {
	if l == nil || l.Repository == nil || l.Secrets == nil {
		return CommitResult{}, errors.New("certificate lifecycle is not fully configured")
	}
	if err := ValidatePlan(request.Plan); err != nil {
		return CommitResult{}, err
	}
	if request.ACMEAccountID == "" {
		return CommitResult{}, errors.New("ACME account ID is required")
	}
	if _, err := ValidateArtifact(request.Artifact, request.Plan.Identifiers); err != nil {
		return CommitResult{}, err
	}
	_, _, _, parsedMetadata, err := ParseCertificatePEM(append(slices.Clone(request.Artifact.CertificatePEM), request.Artifact.ChainPEM...))
	if err != nil {
		return CommitResult{}, err
	}
	if parsedMetadata.KeyAlgorithm != request.Plan.KeyAlgorithm {
		return CommitResult{}, fmt.Errorf("issued certificate key algorithm %s does not match plan %s", parsedMetadata.KeyAlgorithm, request.Plan.KeyAlgorithm)
	}
	// Never trust caller-supplied metadata for persistence or renewal timing;
	// it is only a convenience cache on Artifact.
	request.Artifact.Metadata = parsedMetadata
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	committedAt := now().UTC()

	lineage := domain.CertificateLineage{}
	if request.ExistingLineage != nil {
		lineage = *request.ExistingLineage
		lineage.Identifiers = slices.Clone(request.ExistingLineage.Identifiers)
		if lineage.Source != domain.CertificateManaged {
			return CommitResult{}, errors.New("an imported lineage cannot be converted to a managed lineage")
		}
		if lineage.ZoneID != "" && request.Plan.ZoneID != "" && lineage.ZoneID != request.Plan.ZoneID {
			return CommitResult{}, errors.New("certificate plan belongs to another zone")
		}
		if lineage.ACMEAccountID != "" && lineage.ACMEAccountID != request.ACMEAccountID {
			return CommitResult{}, errors.New("certificate lineage belongs to another ACME account")
		}
	} else {
		lineage.ID = identifier.New("lineage")
		lineage.Source = domain.CertificateManaged
		lineage.CreatedAt = committedAt
	}
	lineage.Name = request.Plan.Name
	lineage.ZoneID = request.Plan.ZoneID
	lineage.Identifiers = slices.Clone(request.Plan.Identifiers)
	lineage.KeyAlgorithm = request.Plan.KeyAlgorithm
	lineage.Profile = request.Plan.Profile
	lineage.ACMEAccountID = request.ACMEAccountID
	lineage.UpdatedAt = committedAt

	version := domain.CertificateVersion{
		ID:                identifier.New("certver"),
		LineageID:         lineage.ID,
		SerialNumber:      request.Artifact.Metadata.SerialNumber,
		FingerprintSHA256: request.Artifact.Metadata.FingerprintSHA256,
		Issuer:            request.Artifact.Metadata.Issuer,
		Identifiers:       slices.Clone(request.Artifact.Metadata.Identifiers),
		NotBefore:         request.Artifact.Metadata.NotBefore,
		NotAfter:          request.Artifact.Metadata.NotAfter,
		CreatedAt:         committedAt,
	}
	window := fallbackRenewalWindowFromMetadata(request.Artifact.Metadata)
	if request.RenewalWindow != nil {
		candidate := normalizeRenewalWindow(*request.RenewalWindow)
		if validRenewalWindow(candidate, request.Artifact.Metadata.NotBefore, request.Artifact.Metadata.NotAfter) {
			window = candidate
		}
	}
	version.RenewalWindowStart = &window.Start
	version.RenewalWindowEnd = &window.End

	intent := domain.CertificateCommitIntent{
		VersionID: version.ID, LineageID: lineage.ID,
		SecretRef:    "certificate-key/" + version.ID,
		ArtifactPath: filepath.Join(request.ExportRoot, version.ID), CreatedAt: committedAt,
	}
	if err := l.Repository.SaveCertificateCommitIntent(ctx, intent); err != nil {
		return CommitResult{}, fmt.Errorf("journal certificate commit intent: %w", err)
	}
	secretRef, err := l.Secrets.Put(ctx, intent.SecretRef, request.Artifact.PrivateKeyPEM)
	if err != nil {
		if secretRef != "" && secretRef != intent.SecretRef {
			err = errors.Join(err, fmt.Errorf("secret store returned unexpected reference %q", secretRef))
		}
		cleanupErr := cleanupCertificateCommitIntent(context.WithoutCancel(ctx), l.Repository, l.Secrets, intent)
		return CommitResult{}, errors.Join(fmt.Errorf("store certificate private key: %w", err), cleanupErr)
	}
	if secretRef != intent.SecretRef {
		return CommitResult{}, errors.Join(
			errors.New("secret store returned an unexpected certificate key reference"),
			cleanupCertificateCommitIntent(context.WithoutCancel(ctx), l.Repository, l.Secrets, intent),
		)
	}
	version.PrivateKeyRef = secretRef
	lineage.CurrentVersionID = version.ID
	lineage.UpdatedAt = committedAt

	exported, err := InstallVersion(request.ExportRoot, lineage, version, request.Artifact, committedAt)
	if err != nil {
		cleanupErr := cleanupCertificateCommitIntent(context.WithoutCancel(ctx), l.Repository, l.Secrets, intent)
		return CommitResult{}, errors.Join(err, cleanupErr)
	}
	version.CertificatePath = exported.CertificatePath
	version.ChainPath = exported.ChainPath
	version.ExportPath = exported.VersionDirectory
	version.ExportedAt = pointer(committedAt)
	result := CommitResult{Lineage: lineage, Version: version, Export: exported}
	if err := l.Repository.CommitCertificateVersion(ctx, lineage, version); err != nil {
		// A database commit may succeed durably and still return an I/O error to
		// the caller. The journal row is deleted in that same transaction, so it
		// is the authoritative commit-outcome marker. Never compensate until the
		// marker can be re-read and is confirmed to remain pending.
		pending, inspectErr := CertificateCommitIntentPending(context.WithoutCancel(ctx), l.Repository, version.ID)
		if inspectErr != nil {
			return CommitResult{}, errors.Join(
				fmt.Errorf("certificate commit outcome is unknown; artifacts were preserved: %w", err),
				fmt.Errorf("inspect certificate commit journal: %w", inspectErr),
			)
		}
		if pending {
			return CommitResult{}, errors.Join(
				fmt.Errorf("commit certificate version: %w", err),
				cleanupCertificateCommitIntent(context.WithoutCancel(ctx), l.Repository, l.Secrets, intent),
			)
		}
		result.Warnings = append(result.Warnings, "certificate commit returned an error, but the durable journal confirms it completed: "+err.Error())
	}
	if err := ActivateVersion(request.ExportRoot, version.ID); err != nil {
		// SQLite remains authoritative and startup reconciliation can retry this
		// local activation without obtaining another certificate.
		result.Warnings = append(result.Warnings, "certificate metadata committed, but current symlink activation failed: "+err.Error())
		return result, nil
	}
	result.Export.CurrentLink = filepath.Join(request.ExportRoot, "current")
	return result, nil
}

// SaveImportedMetadata persists an external lineage without a private key.
func (l *Lifecycle) SaveImportedMetadata(ctx context.Context, lineageID, name, zoneID string, certificatePEM []byte) (domain.CertificateLineage, domain.CertificateVersion, error) {
	if l == nil || l.Repository == nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, errors.New("certificate lifecycle repository is required")
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	lineage, version, err := ImportMetadata(lineageID, name, zoneID, certificatePEM, now().UTC())
	if err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, err
	}
	if err := l.PersistImportedMetadata(ctx, lineage, version); err != nil {
		return domain.CertificateLineage{}, domain.CertificateVersion{}, err
	}
	return lineage, version, nil
}

func (l *Lifecycle) PersistImportedMetadata(ctx context.Context, lineage domain.CertificateLineage, version domain.CertificateVersion) error {
	if l == nil || l.Repository == nil {
		return errors.New("certificate lifecycle repository is required")
	}
	if lineage.Source != domain.CertificateImported || lineage.CurrentVersionID != version.ID || version.LineageID != lineage.ID {
		return errors.New("imported certificate lineage/version relationship is invalid")
	}
	return l.Repository.CommitCertificateVersion(ctx, lineage, version)
}

func wrapCleanupError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

// RecoverCertificateCommitIntents removes vault/file artifacts whose SQLite
// lineage transaction never committed. The transaction deletes its intent in
// the same commit, so every row returned here is definitively orphaned.
func RecoverCertificateCommitIntents(ctx context.Context, repository CertificateRepository, secrets SecretStore, certificatesRoot string) error {
	if repository == nil || secrets == nil {
		return errors.New("certificate commit recovery is not fully configured")
	}
	if strings.TrimSpace(certificatesRoot) == "" {
		return errors.New("certificate commit recovery root is required")
	}
	if err := EnsurePrivateDirectoryDurable(certificatesRoot); err != nil {
		return fmt.Errorf("prepare certificate commit recovery root: %w", err)
	}
	intents, err := repository.ListCertificateCommitIntents(ctx)
	if err != nil {
		return fmt.Errorf("list certificate commit intents: %w", err)
	}
	var recoveryErrors []error
	for _, intent := range intents {
		if err := validateCertificateCommitIntentRecoveryRoot(intent, certificatesRoot); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recover certificate version %s: %w", intent.VersionID, err))
			continue
		}
		if err := cleanupCertificateCommitIntent(ctx, repository, secrets, intent); err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recover certificate version %s: %w", intent.VersionID, err))
		}
	}
	return errors.Join(recoveryErrors...)
}

func CleanupCertificateCommitIntent(ctx context.Context, repository CertificateRepository, secrets SecretStore, intent domain.CertificateCommitIntent) error {
	if repository == nil || secrets == nil {
		return errors.New("certificate commit cleanup is not fully configured")
	}
	return cleanupCertificateCommitIntent(ctx, repository, secrets, intent)
}

// CertificateCommitIntentPending checks the durable outcome marker for one
// certificate version. Absence means CommitCertificateVersion atomically
// installed the metadata and deleted the marker; presence means compensating
// cleanup is safe.
func CertificateCommitIntentPending(ctx context.Context, repository CertificateRepository, versionID string) (bool, error) {
	if repository == nil {
		return false, errors.New("certificate commit repository is required")
	}
	if versionID == "" {
		return false, errors.New("certificate version ID is required")
	}
	intents, err := repository.ListCertificateCommitIntents(ctx)
	if err != nil {
		return false, err
	}
	for _, intent := range intents {
		if intent.VersionID == versionID {
			return true, nil
		}
	}
	return false, nil
}

func cleanupCertificateCommitIntent(ctx context.Context, repository CertificateRepository, secrets SecretStore, intent domain.CertificateCommitIntent) error {
	if err := validateCertificateCommitIntentPath(intent); err != nil {
		return err
	}
	var cleanupErrors []error
	if intent.SecretRef != "" {
		if err := wrapCleanupError("delete orphaned certificate key", compensateSecretDelete(ctx, secrets, intent.SecretRef)); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	artifactDirectory := filepath.Dir(intent.ArtifactPath)
	paths := []string{
		intent.ArtifactPath,
		filepath.Join(artifactDirectory, ".tmp-"+intent.VersionID),
	}
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove orphaned certificate artifact %s: %w", filepath.Base(path), err))
		}
	}
	if err := syncDirectory(artifactDirectory); err != nil && !errors.Is(err, os.ErrNotExist) {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("sync orphan cleanup: %w", err))
	}
	if err := errors.Join(cleanupErrors...); err != nil {
		return err
	}
	if err := repository.DeleteCertificateCommitIntent(ctx, intent.VersionID); err != nil {
		return fmt.Errorf("close certificate commit intent: %w", err)
	}
	return nil
}

func validateCertificateCommitIntentPath(intent domain.CertificateCommitIntent) error {
	if intent.VersionID == "" || intent.ArtifactPath == "" {
		return errors.New("certificate commit intent is incomplete")
	}
	if err := safePathComponent(intent.VersionID); err != nil {
		return fmt.Errorf("certificate commit intent version ID: %w", err)
	}
	base := filepath.Base(filepath.Clean(intent.ArtifactPath))
	if base != intent.VersionID && base != intent.VersionID+".pem" {
		return errors.New("certificate commit intent artifact path does not match its version")
	}
	if base == intent.VersionID+".pem" {
		if intent.SecretRef != "" {
			return errors.New("imported certificate commit intent must not reference a vault secret")
		}
		return nil
	}
	expectedSecretRef := "certificate-key/" + intent.VersionID
	if intent.SecretRef != expectedSecretRef {
		return fmt.Errorf("managed certificate commit intent secret reference must equal %q", expectedSecretRef)
	}
	return nil
}

func validateCertificateCommitIntentRecoveryRoot(intent domain.CertificateCommitIntent, certificatesRoot string) error {
	if err := validateCertificateCommitIntentPath(intent); err != nil {
		return err
	}
	root, err := filepath.Abs(certificatesRoot)
	if err != nil {
		return fmt.Errorf("resolve certificate recovery root: %w", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("inspect certificate recovery root: %w", err)
	}
	if !rootInfo.IsDir() {
		return errors.New("certificate recovery root is not a directory")
	}
	artifact, err := filepath.Abs(intent.ArtifactPath)
	if err != nil {
		return fmt.Errorf("resolve certificate recovery artifact: %w", err)
	}
	if !pathContainedBy(root, artifact) {
		return errors.New("certificate commit intent artifact is outside the configured certificates root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve certificate recovery root links: %w", err)
	}
	existing := artifact
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect certificate recovery artifact path: %w", err)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return errors.New("certificate recovery artifact has no existing ancestor")
		}
		existing = parent
	}
	resolvedExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return fmt.Errorf("resolve certificate recovery artifact links: %w", err)
	}
	if !pathContainedBy(resolvedRoot, resolvedExisting) {
		return errors.New("certificate commit intent artifact resolves outside the configured certificates root")
	}
	return nil
}

func pathContainedBy(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || relative == ".." || filepath.IsAbs(relative) {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func fallbackRenewalWindowFromMetadata(metadata Metadata) RenewalWindow {
	return fallbackRenewalWindowForValidity(metadata.NotBefore, metadata.NotAfter)
}
