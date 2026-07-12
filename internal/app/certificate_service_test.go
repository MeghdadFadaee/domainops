package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
	"github.com/MeghdadFadaee/domainops/internal/secrets"
	"github.com/MeghdadFadaee/domainops/internal/store"
	sqlitestore "github.com/MeghdadFadaee/domainops/internal/store/sqlite"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
)

func TestIssueZonesPersistsCompletedCertificateBeforeBulkFinishes(t *testing.T) {
	ctx := context.Background()
	service, repository, backend, zones := newStreamingCertificateService(t)
	resultChannel := make(chan struct {
		result IssueZonesResult
		err    error
	}, 1)
	go func() {
		result, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID, zones[1].ID}, Environment: certificates.EnvironmentStaging})
		resultChannel <- struct {
			result IssueZonesResult
			err    error
		}{result, err}
	}()

	select {
	case <-backend.fastReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("fast ACME order did not return")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		lineages, err := repository.ListCertificateLineages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		persisted := false
		for _, lineage := range lineages {
			if lineage.ZoneID == zones[0].ID && lineage.CurrentVersionID != "" {
				persisted = true
				break
			}
		}
		if persisted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completed certificate was not persisted while the slow order remained active")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case outcome := <-resultChannel:
		t.Fatalf("bulk returned before slow order was released: %#v, %v", outcome.result, outcome.err)
	default:
	}
	close(backend.releaseSlow)
	outcome := <-resultChannel
	if outcome.err != nil || len(outcome.result.Completed) != 2 || len(outcome.result.Failed) != 0 {
		t.Fatalf("bulk outcome = %#v, %v", outcome.result, outcome.err)
	}
}

func TestRenewAndRevokeRejectDifferentACMEAccount(t *testing.T) {
	ctx := context.Background()
	service, repository, backend, zones := newStreamingCertificateService(t)
	close(backend.releaseSlow)
	issued, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID}, Environment: certificates.EnvironmentStaging})
	if err != nil || len(issued.Completed) != 1 {
		t.Fatalf("issue fixture = %#v, %v", issued, err)
	}
	lineage := issued.Completed[0].Lineage
	lineage.ACMEAccountID = "another-account"
	if err := repository.SaveCertificateLineage(ctx, lineage); err != nil {
		t.Fatal(err)
	}
	version := issued.Completed[0].Version
	due := time.Now().Add(-time.Hour)
	version.RenewalWindowStart = &due
	if err := repository.SaveCertificateVersion(ctx, version); err != nil {
		t.Fatal(err)
	}
	calls := backend.calls.Load()
	renewed, err := service.RenewDue(ctx, certificates.EnvironmentStaging, false)
	if err != nil || len(renewed.Completed) != 0 || len(renewed.Failed) != 0 || backend.calls.Load() != calls {
		t.Fatalf("mismatched renewal = %#v, %v, calls=%d→%d", renewed, err, calls, backend.calls.Load())
	}
	if err := service.Revoke(ctx, lineage.ID, certificates.EnvironmentStaging, lineage.Name, nil); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("mismatched revocation error = %v", err)
	}
}

func TestIssueZonesKeepsStagingAndProductionLineagesAndCurrentLinksSeparate(t *testing.T) {
	ctx := context.Background()
	service, repository, backend, zones := newStreamingCertificateService(t)
	registerTestACMEAccount(t, ctx, repository, service.Secrets, certificates.EnvironmentProduction, "acme-production")

	staging, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID}, Environment: certificates.EnvironmentStaging})
	if err != nil || len(staging.Completed) != 1 {
		t.Fatalf("staging issue = %#v, %v", staging, err)
	}
	production, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID}, Environment: certificates.EnvironmentProduction, ConfirmProduction: true})
	if err != nil || len(production.Completed) != 1 {
		t.Fatalf("production issue = %#v, %v", production, err)
	}
	stagingCommit, productionCommit := staging.Completed[0], production.Completed[0]
	if stagingCommit.Lineage.ID == productionCommit.Lineage.ID || stagingCommit.Lineage.ACMEAccountID == productionCommit.Lineage.ACMEAccountID {
		t.Fatalf("environments shared lineage/account: staging=%#v production=%#v", stagingCommit.Lineage, productionCommit.Lineage)
	}
	if !strings.Contains(stagingCommit.Version.ExportPath, string(filepath.Separator)+"staging"+string(filepath.Separator)) {
		t.Fatalf("staging export path was not isolated: %s", stagingCommit.Version.ExportPath)
	}
	if strings.Contains(productionCommit.Version.ExportPath, string(filepath.Separator)+"staging"+string(filepath.Separator)) {
		t.Fatalf("production export path entered staging tree: %s", productionCommit.Version.ExportPath)
	}
	for _, commit := range []certificates.CommitResult{stagingCommit, productionCommit} {
		target, readErr := filepath.EvalSymlinks(commit.Export.CurrentLink)
		wantTarget, wantErr := filepath.EvalSymlinks(commit.Version.ExportPath)
		if readErr != nil || wantErr != nil || target != wantTarget {
			t.Fatalf("current link %s = %s, %v; want %s, %v", commit.Export.CurrentLink, target, readErr, wantTarget, wantErr)
		}
	}

	stagingAgain, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID}, Environment: certificates.EnvironmentStaging})
	if err != nil || len(stagingAgain.Completed) != 1 || stagingAgain.Completed[0].Lineage.ID != stagingCommit.Lineage.ID {
		t.Fatalf("second staging issue = %#v, %v", stagingAgain, err)
	}
	storedProduction, err := repository.GetCertificateLineage(ctx, productionCommit.Lineage.ID)
	if err != nil || storedProduction.CurrentVersionID != productionCommit.Version.ID {
		t.Fatalf("staging issue changed production current version: %#v, %v", storedProduction, err)
	}
	due := time.Now().Add(-time.Hour)
	productionVersion := productionCommit.Version
	productionVersion.RenewalWindowStart = &due
	if err := repository.SaveCertificateVersion(ctx, productionVersion); err != nil {
		t.Fatal(err)
	}
	renewed, err := service.RenewDue(ctx, certificates.EnvironmentProduction, true)
	if err != nil || len(renewed.Completed) != 1 || renewed.Completed[0].Lineage.ID != productionCommit.Lineage.ID || renewed.Completed[0].Version.ID == productionCommit.Version.ID {
		t.Fatalf("production renewal = %#v, %v", renewed, err)
	}
	storedStaging, err := repository.GetCertificateLineage(ctx, stagingCommit.Lineage.ID)
	if err != nil || storedStaging.CurrentVersionID != stagingAgain.Completed[0].Version.ID {
		t.Fatalf("production renewal changed staging current version: %#v, %v", storedStaging, err)
	}
	if backend.calls.Load() != 4 {
		t.Fatalf("ACME calls = %d, want 4", backend.calls.Load())
	}
	endpoint := domain.ObservedEndpoint{ZoneID: zones[0].ID, Host: zones[0].Name}
	fingerprint, err := service.ExpectedFingerprint(ctx, endpoint)
	if err != nil || fingerprint != renewed.Completed[0].Version.FingerprintSHA256 {
		t.Fatalf("public fingerprint selection = %q, %v; want production %q", fingerprint, err, renewed.Completed[0].Version.FingerprintSHA256)
	}
}

func TestRevocationIntentConvergesAfterCASuccessAndLocalSaveFailure(t *testing.T) {
	ctx := context.Background()
	service, repository, backend, zones := newStreamingCertificateService(t)
	issued, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID}, Environment: certificates.EnvironmentStaging})
	if err != nil || len(issued.Completed) != 1 {
		t.Fatalf("issue fixture = %#v, %v", issued, err)
	}
	due := time.Now().Add(-time.Hour)
	dueVersion := issued.Completed[0].Version
	dueVersion.RenewalWindowStart = &due
	if err := repository.SaveCertificateVersion(ctx, dueVersion); err != nil {
		t.Fatal(err)
	}
	backend.alreadyRevokedAfterFirst = true
	flaky := &failNthVersionSaveRepository{Repository: repository, failAt: 2}
	service.Repository = flaky
	reason := uint(1)
	lineage := issued.Completed[0].Lineage
	err = service.Revoke(ctx, lineage.ID, certificates.EnvironmentStaging, lineage.Name, &reason)
	if err == nil || !strings.Contains(err.Error(), "revoked by the CA") {
		t.Fatalf("first revocation error = %v", err)
	}
	versions, err := repository.ListCertificateVersions(ctx, lineage.ID)
	if err != nil || len(versions) == 0 || versions[0].RevocationPendingAt == nil || versions[0].RevokedAt != nil {
		t.Fatalf("durable revocation intent = %#v, %v", versions, err)
	}
	if _, exportErr := service.Export(ctx, lineage.ID, t.TempDir()); exportErr == nil || !strings.Contains(exportErr.Error(), "revocation is pending") {
		t.Fatalf("pending-revocation certificate export = %v", exportErr)
	}
	issueCalls := backend.calls.Load()
	if result, renewErr := service.RenewDue(ctx, certificates.EnvironmentStaging, false); renewErr != nil || len(result.Completed) != 0 || backend.calls.Load() != issueCalls {
		t.Fatalf("pending revocation was renewed: %#v, %v, calls=%d→%d", result, renewErr, issueCalls, backend.calls.Load())
	}
	if err := service.Revoke(ctx, lineage.ID, certificates.EnvironmentStaging, lineage.Name, &reason); err != nil {
		t.Fatalf("retry after alreadyRevoked did not converge: %v", err)
	}
	versions, err = repository.ListCertificateVersions(ctx, lineage.ID)
	if err != nil || versions[0].RevocationPendingAt != nil || versions[0].RevokedAt == nil || versions[0].RevocationReason == nil || *versions[0].RevocationReason != reason {
		t.Fatalf("converged revocation state = %#v, %v", versions, err)
	}
	if _, exportErr := service.Export(ctx, lineage.ID, t.TempDir()); exportErr == nil || !strings.Contains(exportErr.Error(), "was revoked") {
		t.Fatalf("revoked certificate export = %v", exportErr)
	}
	if backend.revokeCalls.Load() != 2 {
		t.Fatalf("revocation calls = %d, want 2", backend.revokeCalls.Load())
	}
}

func TestImportMetadataCleansJournaledFileWhenDatabaseCommitFails(t *testing.T) {
	ctx := context.Background()
	service, repository, _, _ := newStreamingCertificateService(t)
	failing := &failCertificateCommitRepository{Repository: repository}
	service.Repository = failing
	service.Lifecycle.Repository = failing
	key, err := certificates.GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := certificateForAppTest(key, []string{"import.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source.pem")
	if err := os.WriteFile(source, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ImportMetadata(ctx, source, "import.example.com", ""); err == nil || !strings.Contains(err.Error(), "injected certificate commit failure") {
		t.Fatalf("import failure = %v", err)
	}
	intents, err := repository.ListCertificateCommitIntents(ctx)
	if err != nil || len(intents) != 0 {
		t.Fatalf("failed import retained commit intent: %#v, %v", intents, err)
	}
	var pemFiles []string
	_ = filepath.Walk(service.ExportRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info != nil && !info.IsDir() && strings.HasSuffix(path, ".pem") {
			pemFiles = append(pemFiles, path)
		}
		return nil
	})
	if len(pemFiles) != 0 {
		t.Fatalf("failed import retained PEM artifacts: %#v", pemFiles)
	}
}

func TestImportMetadataPreservesCertificateWhenCommitReturnsAmbiguousError(t *testing.T) {
	ctx := context.Background()
	service, repository, _, _ := newStreamingCertificateService(t)
	ambiguous := &ambiguousCertificateCommitRepository{Repository: repository}
	service.Repository = ambiguous
	service.Lifecycle.Repository = ambiguous
	key, err := certificates.GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := certificateForAppTest(key, []string{"import.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source.pem")
	if err := os.WriteFile(source, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	lineage, version, err := service.ImportMetadata(ctx, source, "import.example.com", "")
	if err != nil {
		t.Fatalf("reconciled import failed: %v", err)
	}
	if lineage.CurrentVersionID != version.ID {
		t.Fatalf("reconciled import relationship = %#v / %#v", lineage, version)
	}
	if _, err := os.Stat(version.CertificatePath); err != nil {
		t.Fatalf("reconciled import deleted committed PEM: %v", err)
	}
	intents, err := repository.ListCertificateCommitIntents(ctx)
	if err != nil || len(intents) != 0 {
		t.Fatalf("reconciled import journal = %#v, %v", intents, err)
	}
	stored, err := repository.GetCertificateLineage(ctx, lineage.ID)
	if err != nil || stored.CurrentVersionID != version.ID {
		t.Fatalf("reconciled imported lineage = %#v, %v", stored, err)
	}
	audit, err := repository.ListAudit(ctx, 1)
	if err != nil || len(audit) != 1 || audit[0].Action != "certificate.import_metadata.commit_reconciled" {
		t.Fatalf("reconciled import audit = %#v, %v", audit, err)
	}
}

func TestExpectedFingerprintPrefersImportedCurrentCertificateOverStaging(t *testing.T) {
	ctx := context.Background()
	service, repository, _, zones := newStreamingCertificateService(t)
	staging, err := service.IssueZones(ctx, IssueZonesRequest{ZoneIDs: []string{zones[0].ID}, Environment: certificates.EnvironmentStaging})
	if err != nil || len(staging.Completed) != 1 {
		t.Fatalf("staging fixture = %#v, %v", staging, err)
	}
	now := time.Now().UTC()
	lineage := domain.CertificateLineage{ID: "imported-current", Name: zones[0].Name, ZoneID: zones[0].ID, Source: domain.CertificateImported, Identifiers: []string{zones[0].Name}, KeyAlgorithm: domain.KeyECDSAP256, CurrentVersionID: "imported-version", CreatedAt: now, UpdatedAt: now}
	version := domain.CertificateVersion{ID: lineage.CurrentVersionID, LineageID: lineage.ID, FingerprintSHA256: "imported-fingerprint", Identifiers: lineage.Identifiers, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), CertificatePath: "/metadata/import.pem", CreatedAt: now}
	if err := repository.CommitCertificateVersion(ctx, lineage, version); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := service.ExpectedFingerprint(ctx, domain.ObservedEndpoint{ZoneID: zones[0].ID, Host: zones[0].Name})
	if err != nil || fingerprint != version.FingerprintSHA256 {
		t.Fatalf("expected fingerprint = %q, %v; want imported %q", fingerprint, err, version.FingerprintSHA256)
	}
}

func TestExpectedFingerprintSkipsOriginComparisonForProxiedEndpoint(t *testing.T) {
	ctx := context.Background()
	service, repository, _, zones := newStreamingCertificateService(t)
	now := time.Now().UTC()
	lineage := domain.CertificateLineage{
		ID: "proxied-origin", Name: zones[0].Name, ZoneID: zones[0].ID,
		Source: domain.CertificateImported, Identifiers: []string{zones[0].Name},
		KeyAlgorithm: domain.KeyECDSAP256, CurrentVersionID: "proxied-origin-version",
		CreatedAt: now, UpdatedAt: now,
	}
	version := domain.CertificateVersion{
		ID: lineage.CurrentVersionID, LineageID: lineage.ID, FingerprintSHA256: "origin-fingerprint",
		Identifiers: lineage.Identifiers, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		CertificatePath: "/metadata/origin.pem", CreatedAt: now,
	}
	if err := repository.CommitCertificateVersion(ctx, lineage, version); err != nil {
		t.Fatal(err)
	}
	record := domain.DNSRecord{
		ID: "cfrecord_proxied", ProviderID: "proxied", ZoneID: zones[0].ID,
		Type: domain.RecordA, Name: zones[0].Name, Content: "192.0.2.1", TTL: 1,
		Proxied: true, Proxiable: true,
	}
	if err := repository.SaveDNSRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	endpoint := domain.ObservedEndpoint{ZoneID: zones[0].ID, Host: zones[0].Name, Port: 443}
	fingerprint, err := service.ExpectedFingerprint(ctx, endpoint)
	if err != nil || fingerprint != "" {
		t.Fatalf("proxied endpoint expected fingerprint = %q, %v; want empty", fingerprint, err)
	}
	record.Proxied = false
	if err := repository.SaveDNSRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	fingerprint, err = service.ExpectedFingerprint(ctx, endpoint)
	if err != nil || fingerprint != version.FingerprintSHA256 {
		t.Fatalf("unproxied endpoint expected fingerprint = %q, %v; want %q", fingerprint, err, version.FingerprintSHA256)
	}
}

func TestExpectedFingerprintUsesZoneLessImportAndPrefersSameZoneImport(t *testing.T) {
	ctx := context.Background()
	service, repository, _, zones := newStreamingCertificateService(t)
	now := time.Now().UTC()
	zoneLess := domain.CertificateLineage{
		ID: "zone-less-import", Name: zones[0].Name, Source: domain.CertificateImported,
		Identifiers: []string{zones[0].Name}, KeyAlgorithm: domain.KeyECDSAP256,
		CurrentVersionID: "zone-less-version", CreatedAt: now, UpdatedAt: now,
	}
	zoneLessVersion := domain.CertificateVersion{
		ID: zoneLess.CurrentVersionID, LineageID: zoneLess.ID, FingerprintSHA256: "zone-less-fingerprint",
		Identifiers: zoneLess.Identifiers, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		CertificatePath: "/metadata/zone-less.pem", CreatedAt: now,
	}
	if err := repository.CommitCertificateVersion(ctx, zoneLess, zoneLessVersion); err != nil {
		t.Fatal(err)
	}
	endpoint := domain.ObservedEndpoint{ZoneID: zones[0].ID, Host: zones[0].Name}
	fingerprint, err := service.ExpectedFingerprint(ctx, endpoint)
	if err != nil || fingerprint != zoneLessVersion.FingerprintSHA256 {
		t.Fatalf("zone-less imported fingerprint = %q, %v; want %q", fingerprint, err, zoneLessVersion.FingerprintSHA256)
	}

	sameZone := domain.CertificateLineage{
		ID: "same-zone-import", Name: zones[0].Name, ZoneID: zones[0].ID, Source: domain.CertificateImported,
		Identifiers: []string{zones[0].Name}, KeyAlgorithm: domain.KeyECDSAP256,
		CurrentVersionID: "same-zone-version", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}
	sameZoneVersion := domain.CertificateVersion{
		ID: sameZone.CurrentVersionID, LineageID: sameZone.ID, FingerprintSHA256: "same-zone-fingerprint",
		Identifiers: sameZone.Identifiers, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(23 * time.Hour),
		CertificatePath: "/metadata/same-zone.pem", CreatedAt: now.Add(-time.Hour),
	}
	if err := repository.CommitCertificateVersion(ctx, sameZone, sameZoneVersion); err != nil {
		t.Fatal(err)
	}
	fingerprint, err = service.ExpectedFingerprint(ctx, endpoint)
	if err != nil || fingerprint != sameZoneVersion.FingerprintSHA256 {
		t.Fatalf("preferred imported fingerprint = %q, %v; want same-zone %q", fingerprint, err, sameZoneVersion.FingerprintSHA256)
	}
}

func registerTestACMEAccount(t *testing.T, ctx context.Context, repository *sqlitestore.Repository, secretStore store.SecretStore, environment, id string) {
	t.Helper()
	key, err := certificates.GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certificates.MarshalPrivateKeyPKCS8(key)
	if err != nil {
		t.Fatal(err)
	}
	keyRef, err := secretStore.Put(ctx, "", keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := json.Marshal(&acme.ExtendedAccount{Location: "https://acme.test/acct/" + id})
	if err := repository.SaveACMEAccount(ctx, domain.ACMEAccount{ID: id, Environment: environment, DirectoryURL: "https://acme.test/directory", Email: "ops@example.com", Registration: string(registration), SecretRef: keyRef, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

type failNthVersionSaveRepository struct {
	store.Repository
	mu     sync.Mutex
	calls  int
	failAt int
}

type failCertificateCommitRepository struct{ store.Repository }

func (r *failCertificateCommitRepository) CommitCertificateVersion(context.Context, domain.CertificateLineage, domain.CertificateVersion) error {
	return errors.New("injected certificate commit failure")
}

type ambiguousCertificateCommitRepository struct{ store.Repository }

func (r *ambiguousCertificateCommitRepository) CommitCertificateVersion(ctx context.Context, lineage domain.CertificateLineage, version domain.CertificateVersion) error {
	if err := r.Repository.CommitCertificateVersion(ctx, lineage, version); err != nil {
		return err
	}
	return errors.New("injected connection loss after certificate commit")
}

func (r *failNthVersionSaveRepository) SaveCertificateVersion(ctx context.Context, version domain.CertificateVersion) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == r.failAt {
		return errors.New("injected local save failure")
	}
	return r.Repository.SaveCertificateVersion(ctx, version)
}

func newStreamingCertificateService(t *testing.T) (*CertificateService, *sqlitestore.Repository, *streamingBackend, []domain.Zone) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	repository, err := sqlitestore.New(filepath.Join(root, "domainops.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(filepath.Join(root, "vault.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Unlock(ctx, []byte("long certificate test password")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Lock)
	credentialSecret, err := vault.Put(ctx, "", []byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credential := domain.Credential{ID: "credential", Provider: domain.ProviderCloudflare, Label: "CF", Kind: domain.CredentialUserToken, SecretRef: credentialSecret, Status: domain.CredentialValid, CreatedAt: now}
	if err := repository.SaveCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	account := domain.RemoteAccount{ID: "cfacct_account", Provider: domain.ProviderCloudflare, ProviderID: "account", Name: "Account", CreatedAt: now}
	if err := repository.SaveAccounts(ctx, []domain.RemoteAccount{account}, []domain.AccountCredential{{AccountID: account.ID, CredentialID: credential.ID, Preferred: true}}); err != nil {
		t.Fatal(err)
	}
	zones := []domain.Zone{
		{ID: "cfzone_fast", Provider: domain.ProviderCloudflare, ProviderID: "fast", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "fast.example.com", Status: domain.ZoneActive},
		{ID: "cfzone_slow", Provider: domain.ProviderCloudflare, ProviderID: "slow", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "slow.example.com", Status: domain.ZoneActive},
	}
	if err := repository.SaveZones(ctx, zones); err != nil {
		t.Fatal(err)
	}
	accountKey, err := certificates.GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyPEM, err := certificates.MarshalPrivateKeyPKCS8(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyRef, err := vault.Put(ctx, "", accountKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := json.Marshal(&acme.ExtendedAccount{Location: "https://acme.test/acct/1"})
	if err := repository.SaveACMEAccount(ctx, domain.ACMEAccount{ID: "acme-staging", Environment: certificates.EnvironmentStaging, DirectoryURL: "https://acme.test/directory", Email: "ops@example.com", Registration: string(registration), SecretRef: accountKeyRef, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	backend := &streamingBackend{releaseSlow: make(chan struct{}), fastReturned: make(chan struct{})}
	engine := certificates.NewEngine(repository, vault, noopDNS01Solver{}, func(context.Context, string) (provider.Auth, string, error) {
		return provider.Auth{CredentialID: credential.ID, Token: "token", Kind: credential.Kind}, "fast", nil
	}, certificates.WithBackendFactory(streamingBackendFactory{backend: backend}))
	return NewCertificateService(repository, vault, engine, filepath.Join(root, "certificates")), repository, backend, zones
}

type streamingBackendFactory struct{ backend *streamingBackend }

func (f streamingBackendFactory) New(context.Context, certificates.AccountMaterial, challenge.Provider) (certificates.CertificateBackend, error) {
	return f.backend, nil
}

type streamingBackend struct {
	releaseSlow              chan struct{}
	fastReturned             chan struct{}
	fastOnce                 sync.Once
	calls                    atomic.Int32
	revokeCalls              atomic.Int32
	alreadyRevokedAfterFirst bool
}

func (b *streamingBackend) Obtain(ctx context.Context, request certificate.ObtainRequest) (*certificate.Resource, error) {
	b.calls.Add(1)
	if strings.HasPrefix(request.Domains[0], "slow.") {
		select {
		case <-b.releaseSlow:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	certificatePEM, err := certificateForAppTest(request.PrivateKey, request.Domains)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(request.Domains[0], "fast.") {
		b.fastOnce.Do(func() { close(b.fastReturned) })
	}
	return &certificate.Resource{Certificate: certificatePEM, Domains: request.Domains}, nil
}

func (b *streamingBackend) RevokeWithReason(context.Context, []byte, *uint) error {
	call := b.revokeCalls.Add(1)
	if b.alreadyRevokedAfterFirst && call > 1 {
		return &acme.ProblemDetails{Type: acme.AlreadyRevokedErrorType, HTTPStatus: 400, Detail: "certificate already revoked"}
	}
	return nil
}
func (b *streamingBackend) GetRenewalInfo(context.Context, *x509.Certificate) (*certificate.RenewalInfo, error) {
	return nil, errors.New("ARI unavailable in test")
}

type noopDNS01Solver struct{}

func (noopDNS01Solver) PresentDNS01(context.Context, provider.Auth, string, string, string, string) (string, error) {
	return "record", nil
}
func (noopDNS01Solver) CleanupDNS01(context.Context, provider.Auth, string, string) error { return nil }

func certificateForAppTest(key crypto.Signer, identifiers []string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identifiers[0]}, DNSNames: append([]string(nil), identifiers...),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
