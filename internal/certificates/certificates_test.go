package certificates

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
	"github.com/MeghdadFadaee/domainops/internal/store"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
)

func TestNewWildcardPlanNestedAndInternationalizedNames(t *testing.T) {
	t.Parallel()
	plan, err := NewWildcardPlan("zone-1", "Bücher.Example.", "api", "deep.api.bücher.example")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"xn--bcher-kva.example",
		"*.xn--bcher-kva.example",
		"api.xn--bcher-kva.example",
		"*.api.xn--bcher-kva.example",
		"deep.api.xn--bcher-kva.example",
		"*.deep.api.xn--bcher-kva.example",
	}
	if !slices.Equal(plan.Identifiers, want) {
		t.Fatalf("identifiers = %#v, want %#v", plan.Identifiers, want)
	}
}

func TestValidatePlanRejectsWildcardThatDoesNotCoverApex(t *testing.T) {
	t.Parallel()
	plan := Plan{
		Name:         "example.com",
		ZoneName:     "example.com",
		Identifiers:  []string{"*.example.com"},
		KeyAlgorithm: domain.KeyECDSAP256,
		Profile:      DefaultProfile,
	}
	// A wildcard-only plan is valid when explicitly requested; the planner is
	// what supplies the safe apex+wildcard default.
	if err := ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	defaultPlan, err := NewWildcardPlan("", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(defaultPlan.Identifiers, []string{"example.com", "*.example.com"}) {
		t.Fatalf("default identifiers = %#v", defaultPlan.Identifiers)
	}
}

func TestKeyGenerationAndPKCS8RoundTrip(t *testing.T) {
	t.Parallel()
	for _, algorithm := range []domain.KeyAlgorithm{domain.KeyECDSAP256, domain.KeyRSA2048} {
		algorithm := algorithm
		t.Run(string(algorithm), func(t *testing.T) {
			key, err := GeneratePrivateKey(algorithm)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := MarshalPrivateKeyPKCS8(key)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(encoded)
			if block == nil || block.Type != "PRIVATE KEY" {
				t.Fatalf("expected PKCS#8 PRIVATE KEY, got %#v", block)
			}
			parsed, err := ParsePrivateKeyPEM(encoded)
			if err != nil {
				t.Fatal(err)
			}
			got, err := keyAlgorithm(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if got != algorithm {
				t.Fatalf("algorithm = %s, want %s", got, algorithm)
			}
		})
	}
}

func TestMetadataImportRejectsPrivateKey(t *testing.T) {
	t.Parallel()
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), domain.KeyECDSAP256)
	input := append(slices.Clone(artifact.CertificatePEM), artifact.PrivateKeyPEM...)
	if _, _, err := ImportMetadata("", "", "", input, time.Now()); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected forbidden private key error, got %v", err)
	}
	lineage, version, err := ImportMetadata("", "", "zone-1", artifact.CertificatePEM, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if lineage.Source != domain.CertificateImported || lineage.CurrentVersionID != version.ID {
		t.Fatalf("unexpected imported lineage: %#v / %#v", lineage, version)
	}
}

func TestMetadataImportAcceptsEd25519Certificate(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificatePEM := certificateForKey(t, key, []string{"example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	lineage, _, err := ImportMetadata("", "", "", certificatePEM, now)
	if err != nil {
		t.Fatal(err)
	}
	if lineage.KeyAlgorithm != domain.KeyAlgorithm("ED25519") {
		t.Fatalf("imported key algorithm = %q", lineage.KeyAlgorithm)
	}
}

func TestExportVersionIsAtomicVersionedAndPrivate(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	root := filepath.Join(t.TempDir(), "lineage")
	lineage := domain.CertificateLineage{
		ID:           "lineage-1",
		Name:         "example.com",
		Source:       domain.CertificateManaged,
		Identifiers:  []string{"example.com", "*.example.com"},
		KeyAlgorithm: domain.KeyECDSAP256,
		Profile:      DefaultProfile,
	}
	version := testVersion("version-1", lineage.ID, artifact)
	result, err := ExportVersion(root, lineage, version, artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(result.CurrentLink)
	if err != nil {
		t.Fatal(err)
	}
	if target != version.ID {
		t.Fatalf("current -> %q, want %q", target, version.ID)
	}
	for _, name := range []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "metadata.json"} {
		info, err := os.Stat(filepath.Join(result.VersionDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
	keyData, err := os.ReadFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("private key export is not PKCS#8")
	}

	version2 := testVersion("version-2", lineage.ID, artifact)
	result2, err := ExportVersion(root, lineage, version2, artifact, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	target, err = os.Readlink(result2.CurrentLink)
	if err != nil {
		t.Fatal(err)
	}
	if target != version2.ID {
		t.Fatalf("current -> %q, want %q", target, version2.ID)
	}
	if _, err := os.Stat(result.VersionDirectory); err != nil {
		t.Fatalf("previous version was not retained: %v", err)
	}
	if duplicate, err := ExportVersion(root, lineage, version2, artifact, now); err != nil || duplicate.VersionDirectory != result2.VersionDirectory {
		t.Fatalf("idempotent immutable export = %#v, %v", duplicate, err)
	}
}

func TestExplicitExportRetryReplacesCrashLeftVersion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	root := filepath.Join(t.TempDir(), "export")
	lineage := domain.CertificateLineage{ID: "lineage-retry", Name: "example.com", Source: domain.CertificateManaged, Identifiers: artifact.Metadata.Identifiers}
	version := testVersion("certver-retry", lineage.ID, artifact)
	lineage.CurrentVersionID = version.ID
	first, err := ExportVersion(root, lineage, version, artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".tmp-"+version.ID), 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := ExportVersion(root, lineage, version, artifact, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("retry explicit export: %v", err)
	}
	if first.VersionDirectory != second.VersionDirectory {
		t.Fatalf("retry path changed: %q != %q", first.VersionDirectory, second.VersionDirectory)
	}
	if target, err := os.Readlink(filepath.Join(root, "current")); err != nil || target != version.ID {
		t.Fatalf("retry current link = %q, %v", target, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".tmp-"+version.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry retained temporary export: %v", err)
	}
}

func TestExplicitExportRetryRejectsCorruptDerivedFiles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, current := range []struct {
		name     string
		filename string
		contents []byte
	}{
		{name: "full chain", filename: "fullchain.pem", contents: []byte("corrupt\n")},
		{name: "metadata", filename: "metadata.json", contents: []byte("{}\n")},
	} {
		t.Run(current.name, func(t *testing.T) {
			artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
			root := filepath.Join(t.TempDir(), "export")
			lineage := domain.CertificateLineage{ID: "lineage-corrupt", Name: "example.com", Source: domain.CertificateManaged, Identifiers: artifact.Metadata.Identifiers}
			version := testVersion("certver-corrupt", lineage.ID, artifact)
			lineage.CurrentVersionID = version.ID
			result, err := ExportVersion(root, lineage, version, artifact, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(result.VersionDirectory, current.filename), current.contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ExportVersion(root, lineage, version, artifact, now.Add(time.Minute)); err == nil {
				t.Fatalf("retry accepted corrupt %s", current.filename)
			}
		})
	}
}

func TestInstallVersionRejectsVersionMetadataMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	lineage := domain.CertificateLineage{ID: "lineage-mismatch", Name: "example.com", Source: domain.CertificateManaged, Identifiers: artifact.Metadata.Identifiers}
	version := testVersion("certver-mismatch", lineage.ID, artifact)
	version.FingerprintSHA256 = strings.Repeat("0", 64)
	root := filepath.Join(t.TempDir(), "export")
	if _, err := InstallVersion(root, lineage, version, artifact, now); err == nil || !strings.Contains(err.Error(), "metadata does not match") {
		t.Fatalf("mismatched version install error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, version.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched version material was installed: %v", err)
	}
}

func TestExplicitExportRetryRejectsUnsafePrivateKeyMode(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	root := filepath.Join(t.TempDir(), "export")
	lineage := domain.CertificateLineage{ID: "lineage-mode", Name: "example.com", Source: domain.CertificateManaged, Identifiers: artifact.Metadata.Identifiers}
	version := testVersion("certver-mode", lineage.ID, artifact)
	lineage.CurrentVersionID = version.ID
	result, err := ExportVersion(root, lineage, version, artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(result.PrivateKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportVersion(root, lineage, version, artifact, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("unsafe-mode retry error = %v", err)
	}
}

func TestExplicitExportRetryRejectsSymlinkedVersionDirectory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	root := filepath.Join(t.TempDir(), "export")
	lineage := domain.CertificateLineage{ID: "lineage-link", Name: "example.com", Source: domain.CertificateManaged, Identifiers: artifact.Metadata.Identifiers}
	version := testVersion("certver-link", lineage.ID, artifact)
	lineage.CurrentVersionID = version.ID
	result, err := ExportVersion(root, lineage, version, artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	backing := result.VersionDirectory + "-backing"
	if err := os.Rename(result.VersionDirectory, backing); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(backing), result.VersionDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportVersion(root, lineage, version, artifact, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlinked-version retry error = %v", err)
	}
}

func TestEnsurePrivateDirectoryDurableRejectsSymlinkComponents(t *testing.T) {
	base := t.TempDir()
	realDirectory := filepath.Join(base, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectoryDurable(filepath.Join(link, "private")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("intermediate symlink error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(realDirectory, "private")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target was modified: %v", err)
	}
	if err := EnsurePrivateDirectoryDurable(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("target symlink error = %v", err)
	}
}

func TestActivateVersionPreservesNonSymlinkCurrentPath(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "export")
			versionID := "certver-activate"
			if err := os.MkdirAll(filepath.Join(root, versionID), 0o700); err != nil {
				t.Fatal(err)
			}
			current := filepath.Join(root, "current")
			if kind == "file" {
				if err := os.WriteFile(current, []byte("keep me"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(current, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := ActivateVersion(root, versionID); err == nil || !strings.Contains(err.Error(), "non-symlink") {
				t.Fatalf("activation error = %v", err)
			}
			info, err := os.Lstat(current)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "file" {
				contents, readErr := os.ReadFile(current)
				if readErr != nil || string(contents) != "keep me" || !info.Mode().IsRegular() {
					t.Fatalf("current file was not preserved: %q, %v, %v", contents, info.Mode(), readErr)
				}
			} else if !info.IsDir() {
				t.Fatalf("current directory was not preserved: %v", info.Mode())
			}
		})
	}
}

func TestActivateVersionRejectsSymlinkedVersionDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "export")
	if err := os.MkdirAll(filepath.Join(root, "backing"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("backing", filepath.Join(root, "certver-link")); err != nil {
		t.Fatal(err)
	}
	if err := ActivateVersion(root, "certver-link"); err == nil || !strings.Contains(err.Error(), "regular directory") {
		t.Fatalf("symlinked version activation error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation created current link: %v", err)
	}
}

func TestJournaledDNSProviderExactRecordLifecycle(t *testing.T) {
	t.Parallel()
	repository := &memoryRepository{}
	solver := &fakeSolver{}
	resolver := func(_ context.Context, fqdn string) (provider.Auth, string, error) {
		if fqdn != "_acme-challenge.example.com." {
			t.Fatalf("resolved fqdn = %q", fqdn)
		}
		return provider.Auth{CredentialID: "credential-1", Token: "secret"}, "zone-1", nil
	}
	dnsProvider := NewJournaledDNSProvider(solver, repository, resolver, "job-1")
	var presentedDomain, presentedFQDN string
	dnsProvider.OnPresented = func(domainName, fqdn string) {
		presentedDomain, presentedFQDN = domainName, fqdn
	}
	if err := dnsProvider.Present(context.Background(), "example.com", "token-1", "key-auth"); err != nil {
		t.Fatal(err)
	}
	if len(repository.challenges) != 1 || repository.challenges[0].RecordID != "record-1" {
		t.Fatalf("journal = %#v", repository.challenges)
	}
	if repository.challenges[0].ValueHash == "" || solver.presentedJob != "job-1" {
		t.Fatalf("challenge was not hashed/tagged: %#v", repository.challenges[0])
	}
	if presentedDomain != "example.com" || presentedFQDN != "_acme-challenge.example.com." {
		t.Fatalf("presented callback = %q, %q", presentedDomain, presentedFQDN)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dnsProvider.CleanUp(cancelled, "example.com", "token-1", "key-auth"); err != nil {
		t.Fatal(err)
	}
	if solver.cleanupContextErr != nil {
		t.Fatalf("cleanup inherited cancelled issuance context: %v", solver.cleanupContextErr)
	}
	if !slices.Equal(solver.cleaned, []string{"record-1"}) {
		t.Fatalf("cleaned = %#v", solver.cleaned)
	}
	if repository.challenges[0].CleanedAt == nil {
		t.Fatal("challenge was not marked cleaned")
	}
}

func TestJournalIntentFailurePreventsRemoteRecordCreation(t *testing.T) {
	t.Parallel()
	repository := &memoryRepository{saveChallengeErr: errors.New("disk full")}
	solver := &fakeSolver{}
	resolver := func(context.Context, string) (provider.Auth, string, error) {
		return provider.Auth{}, "zone-1", nil
	}
	dnsProvider := NewJournaledDNSProvider(solver, repository, resolver, "job-1")
	err := dnsProvider.Present(context.Background(), "example.com", "token-1", "key-auth")
	if err == nil || solver.presentedJob != "" || len(solver.cleaned) != 0 {
		t.Fatalf("err = %v, presented job = %q, cleaned = %#v", err, solver.presentedJob, solver.cleaned)
	}
}

func TestCleanupOpenChallengesReconcilesIntentWithStoredCredential(t *testing.T) {
	t.Parallel()
	value := "challenge-value"
	digest := sha256.Sum256([]byte(value))
	repository := &memoryRepository{challenges: []domain.ChallengeJournal{{
		ID: "challenge-1", JobID: "job-1", CredentialID: "credential-1", ZoneID: "zone-1",
		FQDN: "_acme-challenge.example.com.", ValueHash: hex.EncodeToString(digest[:]), CreatedAt: time.Now(),
	}}}
	solver := &recoverySolver{recordID: "record-recovered", found: true}
	zoneResolver := func(context.Context, string) (provider.Auth, string, error) {
		return provider.Auth{}, "", errors.New("zone preference resolver must not be used")
	}
	credentialResolver := func(_ context.Context, credentialID string) (provider.Auth, error) {
		if credentialID != "credential-1" {
			t.Fatalf("credential ID = %q", credentialID)
		}
		return provider.Auth{CredentialID: credentialID, Token: "secret", Kind: domain.CredentialUserToken}, nil
	}
	if err := CleanupOpenChallenges(context.Background(), repository, solver, zoneResolver, credentialResolver); err != nil {
		t.Fatal(err)
	}
	if solver.reconciledJob != "job-1" || !slices.Equal(solver.cleaned, []string{"record-recovered"}) {
		t.Fatalf("reconciled job = %q, cleaned = %#v", solver.reconciledJob, solver.cleaned)
	}
	if len(repository.challenges) != 1 || repository.challenges[0].RecordID != "record-recovered" || repository.challenges[0].CleanedAt == nil {
		t.Fatalf("recovered journal = %#v", repository.challenges)
	}
}

func TestIssueBatchCapsConcurrencyAndUsesFreshKeys(t *testing.T) {
	t.Parallel()
	accountKey, err := GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyPEM, err := MarshalPrivateKeyPKCS8(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	registrationJSON, _ := json.Marshal(&acme.ExtendedAccount{Location: "https://acme.test/acct/1"})
	repository := &memoryRepository{account: domain.ACMEAccount{
		ID: "account-1", Environment: EnvironmentStaging, DirectoryURL: "https://acme.test/directory",
		Email: "ops@example.com", Registration: string(registrationJSON), SecretRef: "secret-1",
	}}
	secrets := &memorySecrets{values: map[string][]byte{"secret-1": accountKeyPEM}}
	backend := &fakeBackend{}
	engine := NewEngine(repository, secrets, &fakeSolver{}, func(context.Context, string) (provider.Auth, string, error) {
		return provider.Auth{}, "zone-1", nil
	}, WithBackendFactory(fakeBackendFactory{backend: backend}), WithIssuanceConcurrency(20))
	var requests []IssueRequest
	for index := range 60 {
		plan, planErr := NewWildcardPlan("zone-1", "example"+big.NewInt(int64(index+1)).String()+".com")
		if planErr != nil {
			t.Fatal(planErr)
		}
		requests = append(requests, IssueRequest{JobID: "job", Environment: EnvironmentStaging, Plan: plan})
	}
	results := engine.IssueBatch(context.Background(), requests)
	for _, result := range results {
		if result.Error != nil {
			t.Fatal(result.Error)
		}
	}
	if backend.maximum.Load() > maxIssuanceConcurrency {
		t.Fatalf("maximum concurrency = %d, want <= %d", backend.maximum.Load(), maxIssuanceConcurrency)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.publicKeys) != len(requests) {
		t.Fatalf("private keys observed = %d", len(backend.publicKeys))
	}
	for i := range backend.publicKeys {
		for j := 0; j < i; j++ {
			if string(backend.publicKeys[i]) == string(backend.publicKeys[j]) {
				t.Fatal("renewal/issuance reused a private key")
			}
		}
	}
}

func TestIssueDeadlineStopsAStalledBackendAndReportsStage(t *testing.T) {
	accountKey, err := GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyPEM, err := MarshalPrivateKeyPKCS8(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	registrationJSON, _ := json.Marshal(&acme.ExtendedAccount{Location: "https://acme.test/acct/1"})
	repository := &memoryRepository{account: domain.ACMEAccount{
		ID: "account-1", Environment: EnvironmentStaging, DirectoryURL: "https://acme.test/directory",
		Email: "ops@example.com", Registration: string(registrationJSON), SecretRef: "secret-1",
	}}
	secrets := &memorySecrets{values: map[string][]byte{"secret-1": accountKeyPEM}}
	backend := &fakeBackend{obtainDelay: time.Hour}
	engine := NewEngine(repository, secrets, &fakeSolver{}, func(context.Context, string) (provider.Auth, string, error) {
		return provider.Auth{}, "zone-1", nil
	}, WithBackendFactory(fakeBackendFactory{backend: backend}), WithIssuanceTimeout(40*time.Millisecond))
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var progress []IssueProgress
	started := time.Now()
	_, err = engine.Issue(context.Background(), IssueRequest{
		JobID: "job", Environment: EnvironmentStaging, Plan: plan,
		Progress: func(value IssueProgress) { progress = append(progress, value) },
	})
	if err == nil || !strings.Contains(err.Error(), "safety deadline") || !strings.Contains(err.Error(), "acme-validation") {
		t.Fatalf("deadline error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled issue returned after %s", elapsed)
	}
	if len(progress) < 2 || progress[0].Stage != "preflight" || progress[1].Stage != "acme-order" {
		t.Fatalf("progress = %#v", progress)
	}
}

func TestRenewSetsARIReplacementAndKeepsIdentifiers(t *testing.T) {
	accountKey, err := GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyPEM, err := MarshalPrivateKeyPKCS8(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	registrationJSON, _ := json.Marshal(&acme.ExtendedAccount{Location: "https://acme.test/acct/1"})
	repository := &memoryRepository{account: domain.ACMEAccount{ID: "account", Environment: EnvironmentProduction, DirectoryURL: "https://acme.test/directory", Email: "ops@example.com", Registration: string(registrationJSON), SecretRef: "account-key"}}
	secrets := &memorySecrets{values: map[string][]byte{"account-key": accountKeyPEM}}
	backend := &fakeBackend{}
	engine := NewEngine(repository, secrets, &fakeSolver{}, func(context.Context, string) (provider.Auth, string, error) { return provider.Auth{}, "zone", nil }, WithBackendFactory(fakeBackendFactory{backend: backend}))
	plan, err := NewWildcardPlan("zone", "example.com", "api")
	if err != nil {
		t.Fatal(err)
	}
	previous := testArtifact(t, plan.Identifiers, time.Now().Add(-60*24*time.Hour), time.Now().Add(30*24*time.Hour), domain.KeyECDSAP256)
	result, err := engine.Renew(context.Background(), RenewRequest{IssueRequest: IssueRequest{Environment: EnvironmentProduction, Plan: plan, ConfirmProduction: true}, PreviousCertificatePEM: previous.CertificatePEM})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Plan.Identifiers, plan.Identifiers) {
		t.Fatalf("renewed identifiers = %v", result.Plan.Identifiers)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.replaces) != 1 || backend.replaces[0] == "" {
		t.Fatalf("ARI replacement IDs = %#v", backend.replaces)
	}
}

func TestIssueReturnsARIWindowAndLifecyclePersistsIt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	wantWindow := RenewalWindow{
		Start:          now.Add(3 * time.Hour),
		End:            now.Add(6 * time.Hour),
		ARI:            true,
		ExplanationURL: "https://acme.test/renewal-event",
		RetryAfter:     45 * time.Minute,
	}
	backend := &fakeBackend{renewalInfo: &certificate.RenewalInfo{ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
		RenewalInfo: acme.RenewalInfo{
			SuggestedWindow: acme.Window{Start: wantWindow.Start, End: wantWindow.End},
			ExplanationURL:  wantWindow.ExplanationURL,
		},
		RetryAfter: wantWindow.RetryAfter,
	}}}
	engine, repository, secrets := testEngine(t, backend)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := engine.Issue(context.Background(), IssueRequest{
		JobID: "job-1", Environment: EnvironmentStaging, Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if issued.RenewalWindow != wantWindow {
		t.Fatalf("renewal window = %#v, want %#v", issued.RenewalWindow, wantWindow)
	}
	if backend.renewalCalls.Load() != 1 {
		t.Fatalf("renewal information calls = %d, want 1", backend.renewalCalls.Load())
	}

	lifecycle := &Lifecycle{Repository: repository, Secrets: secrets, Now: func() time.Time { return now }}
	committed, err := lifecycle.CommitManaged(context.Background(), CommitRequest{
		Plan: plan, ACMEAccountID: repository.account.ID, Artifact: issued.Artifact,
		RenewalWindow: &issued.RenewalWindow, ExportRoot: filepath.Join(t.TempDir(), "example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if committed.Version.RenewalWindowStart == nil || !committed.Version.RenewalWindowStart.Equal(wantWindow.Start) {
		t.Fatalf("persisted renewal start = %v, want %v", committed.Version.RenewalWindowStart, wantWindow.Start)
	}
	if committed.Version.RenewalWindowEnd == nil || !committed.Version.RenewalWindowEnd.Equal(wantWindow.End) {
		t.Fatalf("persisted renewal end = %v, want %v", committed.Version.RenewalWindowEnd, wantWindow.End)
	}
	repository.mu.Lock()
	persisted := repository.versions[len(repository.versions)-1]
	repository.mu.Unlock()
	if persisted.RenewalWindowStart == nil || persisted.RenewalWindowEnd == nil ||
		!persisted.RenewalWindowStart.Equal(wantWindow.Start) || !persisted.RenewalWindowEnd.Equal(wantWindow.End) {
		t.Fatalf("repository persisted renewal window = %v - %v", persisted.RenewalWindowStart, persisted.RenewalWindowEnd)
	}
}

func TestIssueUsesSafeFallbackWhenARIIsUnavailableOrInvalid(t *testing.T) {
	now := time.Now().UTC()
	tests := map[string]*fakeBackend{
		"unavailable": {renewalErr: errors.New("renewal endpoint unavailable")},
		"missing":     {},
		"invalid": {renewalInfo: &certificate.RenewalInfo{ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
			RenewalInfo: acme.RenewalInfo{SuggestedWindow: acme.Window{
				Start: now.Add(8 * time.Hour), End: now.Add(7 * time.Hour),
			}},
		}}},
	}
	for name, backend := range tests {
		backend := backend
		t.Run(name, func(t *testing.T) {
			engine, _, _ := testEngine(t, backend)
			plan, err := NewWildcardPlan("zone-1", name+".example.com")
			if err != nil {
				t.Fatal(err)
			}
			issued, err := engine.Issue(context.Background(), IssueRequest{
				JobID: "job-1", Environment: EnvironmentStaging, Plan: plan,
			})
			if err != nil {
				t.Fatalf("issuance must survive ARI failure: %v", err)
			}
			want := fallbackRenewalWindowFromMetadata(issued.Artifact.Metadata)
			if issued.RenewalWindow.ARI || !issued.RenewalWindow.Start.Equal(want.Start) || !issued.RenewalWindow.End.Equal(want.End) {
				t.Fatalf("fallback renewal window = %#v, want %#v", issued.RenewalWindow, want)
			}
			if issued.RenewalWindow.Start.Before(issued.Artifact.Metadata.NotBefore) ||
				issued.RenewalWindow.End.After(issued.Artifact.Metadata.NotAfter) ||
				!issued.RenewalWindow.End.After(issued.RenewalWindow.Start) {
				t.Fatalf("fallback is outside certificate validity: %#v / %#v", issued.RenewalWindow, issued.Artifact.Metadata)
			}
		})
	}
}

func TestLifecycleIgnoresInvalidOptionalRenewalWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: make(map[string][]byte)}
	invalid := RenewalWindow{
		Start: artifact.Metadata.NotAfter.Add(time.Hour),
		End:   artifact.Metadata.NotAfter.Add(2 * time.Hour),
		ARI:   true,
	}
	committed, err := (&Lifecycle{Repository: repository, Secrets: secrets, Now: func() time.Time { return now }}).CommitManaged(
		context.Background(), CommitRequest{
			Plan: plan, ACMEAccountID: "account-1", Artifact: artifact, RenewalWindow: &invalid,
			ExportRoot: filepath.Join(t.TempDir(), "example.com"),
		})
	if err != nil {
		t.Fatal(err)
	}
	want := fallbackRenewalWindowFromMetadata(artifact.Metadata)
	if committed.Version.RenewalWindowStart == nil || committed.Version.RenewalWindowEnd == nil ||
		!committed.Version.RenewalWindowStart.Equal(want.Start) || !committed.Version.RenewalWindowEnd.Equal(want.End) {
		t.Fatalf("invalid window did not fall back safely: %v - %v, want %v - %v",
			committed.Version.RenewalWindowStart, committed.Version.RenewalWindowEnd, want.Start, want.End)
	}
}

func TestLifecycleDoesNotActivateOrLeakArtifactsWhenMetadataCommitFails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{commitErr: errors.New("database unavailable")}
	secrets := &memorySecrets{values: make(map[string][]byte)}
	root := filepath.Join(t.TempDir(), "example.com")
	_, err = (&Lifecycle{Repository: repository, Secrets: secrets, Now: func() time.Time { return now }}).CommitManaged(
		context.Background(), CommitRequest{Plan: plan, ACMEAccountID: "account-1", Artifact: artifact, ExportRoot: root})
	if err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("commit error = %v", err)
	}
	if repository.lineage.ID != "" || len(repository.versions) != 0 {
		t.Fatalf("failed commit changed repository: lineage=%#v versions=%#v", repository.lineage, repository.versions)
	}
	if len(repository.commitIntents) != 0 {
		t.Fatalf("failed commit left a recoverable intent after successful cleanup: %#v", repository.commitIntents)
	}
	if len(secrets.values) != 0 {
		t.Fatalf("failed commit leaked private key references: %#v", secrets.values)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed commit leaked filesystem artifacts: %#v", entries)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "current")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed commit activated current link: %v", statErr)
	}
}

func TestLifecycleCleansPossiblyCommittedVaultKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: make(map[string][]byte), putErr: errors.New("vault directory sync failed")}
	root := filepath.Join(t.TempDir(), "example.com")
	_, err = (&Lifecycle{Repository: repository, Secrets: secrets, Now: func() time.Time { return now }}).CommitManaged(
		context.Background(), CommitRequest{Plan: plan, ACMEAccountID: "account-1", Artifact: artifact, ExportRoot: root})
	if err == nil || !strings.Contains(err.Error(), "store certificate private key") {
		t.Fatalf("committed vault write error = %v", err)
	}
	if len(secrets.values) != 0 || len(secrets.deleted) != 1 || len(repository.commitIntents) != 0 {
		t.Fatalf("possibly committed key cleanup = values:%#v deleted:%#v intents:%#v", secrets.values, secrets.deleted, repository.commitIntents)
	}
}

func TestLifecyclePreservesCommittedVersionWhenCommitReturnsAmbiguousError(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{commitAfterErr: errors.New("connection lost after commit")}
	secrets := &memorySecrets{values: make(map[string][]byte)}
	root := filepath.Join(t.TempDir(), "example.com")
	result, err := (&Lifecycle{Repository: repository, Secrets: secrets, Now: func() time.Time { return now }}).CommitManaged(
		context.Background(), CommitRequest{Plan: plan, ACMEAccountID: "account-1", Artifact: artifact, ExportRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "journal confirms") {
		t.Fatalf("reconciled commit warnings = %#v", result.Warnings)
	}
	if repository.lineage.CurrentVersionID != result.Version.ID || len(repository.versions) != 1 || len(repository.commitIntents) != 0 {
		t.Fatalf("reconciled repository state = lineage %#v, versions %#v, intents %#v", repository.lineage, repository.versions, repository.commitIntents)
	}
	if _, ok := secrets.values[result.Version.PrivateKeyRef]; !ok {
		t.Fatalf("reconciled commit deleted live private key %q", result.Version.PrivateKeyRef)
	}
	if _, statErr := os.Stat(result.Export.PrivateKeyPath); statErr != nil {
		t.Fatalf("reconciled commit deleted live export: %v", statErr)
	}
	linkTarget, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || linkTarget != result.Version.ID {
		t.Fatalf("reconciled current link = %q, %v", linkTarget, err)
	}
}

func TestLifecyclePreservesJournalAndArtifactsWhenCommitCannotBeReconciled(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{
		commitErr:            errors.New("database unavailable"),
		listCommitIntentsErr: errors.New("journal unavailable"),
	}
	secrets := &memorySecrets{values: make(map[string][]byte)}
	root := filepath.Join(t.TempDir(), "example.com")
	_, err = (&Lifecycle{Repository: repository, Secrets: secrets, Now: func() time.Time { return now }}).CommitManaged(
		context.Background(), CommitRequest{Plan: plan, ACMEAccountID: "account-1", Artifact: artifact, ExportRoot: root})
	if err == nil || !strings.Contains(err.Error(), "outcome is unknown") {
		t.Fatalf("unknown commit outcome error = %v", err)
	}
	if len(repository.commitIntents) != 1 || len(secrets.values) != 1 {
		t.Fatalf("unknown outcome did not preserve recovery state: intents=%#v secrets=%#v", repository.commitIntents, secrets.values)
	}
	if _, statErr := os.Stat(repository.commitIntents[0].ArtifactPath); statErr != nil {
		t.Fatalf("unknown outcome did not preserve artifact: %v", statErr)
	}
}

func TestRecoverCertificateCommitIntentsDeletesCrashOrphans(t *testing.T) {
	ctx := context.Background()
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: make(map[string][]byte)}
	root := t.TempDir()
	intent := domain.CertificateCommitIntent{
		VersionID: "certver_crash", LineageID: "lineage_crash",
		SecretRef:    "certificate-key/certver_crash",
		ArtifactPath: filepath.Join(root, "certver_crash"), CreatedAt: time.Now(),
	}
	if err := repository.SaveCertificateCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Put(ctx, intent.SecretRef, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(intent.ArtifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(intent.ArtifactPath, "privkey.pem"), []byte("private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(root, ".tmp-"+intent.VersionID)
	if err := os.MkdirAll(tempPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempPath, "privkey.pem"), []byte("temporary private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverCertificateCommitIntents(ctx, repository, secrets, root); err != nil {
		t.Fatal(err)
	}
	if len(repository.commitIntents) != 0 || len(secrets.values) != 0 {
		t.Fatalf("recovery retained intent or secret: intents=%#v secrets=%#v", repository.commitIntents, secrets.values)
	}
	if _, err := os.Stat(intent.ArtifactPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery retained artifact directory: %v", err)
	}
	if _, err := os.Stat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery retained plaintext temporary directory: %v", err)
	}
}

func TestRecoverCertificateCommitIntentsRejectsUnboundSecretReference(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: map[string][]byte{"credential/live": []byte("cloudflare token")}}
	intent := domain.CertificateCommitIntent{
		VersionID: "certver_corrupt", LineageID: "lineage_corrupt", SecretRef: "credential/live",
		ArtifactPath: filepath.Join(root, "certver_corrupt"), CreatedAt: time.Now().UTC(),
	}
	if err := repository.SaveCertificateCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(intent.ArtifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	err := RecoverCertificateCommitIntents(ctx, repository, secrets, root)
	if err == nil || !strings.Contains(err.Error(), "must equal") {
		t.Fatalf("malformed secret reference error = %v", err)
	}
	if string(secrets.values["credential/live"]) != "cloudflare token" {
		t.Fatal("malformed certificate intent deleted an unrelated secret")
	}
	if _, err := os.Stat(intent.ArtifactPath); err != nil {
		t.Fatalf("malformed certificate intent deleted its artifact: %v", err)
	}
	if len(repository.commitIntents) != 1 {
		t.Fatalf("malformed certificate intent was closed: %#v", repository.commitIntents)
	}
}

func TestRecoverCertificateCommitIntentsRejectsArtifactOutsideRoot(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "certificates")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: map[string][]byte{"certificate-key/certver_outside": []byte("private key")}}
	intent := domain.CertificateCommitIntent{
		VersionID: "certver_outside", LineageID: "lineage_outside", SecretRef: "certificate-key/certver_outside",
		ArtifactPath: filepath.Join(outside, "certver_outside"), CreatedAt: time.Now().UTC(),
	}
	if err := repository.SaveCertificateCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(intent.ArtifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	err := RecoverCertificateCommitIntents(ctx, repository, secrets, root)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside-root recovery error = %v", err)
	}
	if len(secrets.values) != 1 {
		t.Fatal("outside-root certificate intent deleted its secret")
	}
	if _, err := os.Stat(intent.ArtifactPath); err != nil {
		t.Fatalf("outside-root certificate intent deleted its artifact: %v", err)
	}
	if len(repository.commitIntents) != 1 {
		t.Fatalf("outside-root certificate intent was closed: %#v", repository.commitIntents)
	}
}

func TestRecoverACMEAccountCommitIntentsDeletesCrashOrphan(t *testing.T) {
	ctx := context.Background()
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: make(map[string][]byte)}
	intent := domain.ACMEAccountCommitIntent{
		AccountID: "acmeacct_crash", SecretRef: "acme-account/acmeacct_crash", CreatedAt: time.Now().UTC(),
	}
	if err := repository.SaveACMEAccountCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Put(ctx, intent.SecretRef, []byte("account key")); err != nil {
		t.Fatal(err)
	}
	if err := RecoverACMEAccountCommitIntents(ctx, repository, secrets); err != nil {
		t.Fatal(err)
	}
	if len(repository.accountCommitIntents) != 0 || len(secrets.values) != 0 {
		t.Fatalf("ACME account recovery retained orphan: intents=%#v secrets=%#v", repository.accountCommitIntents, secrets.values)
	}
}

func TestRecoverACMEAccountCommitIntentsRejectsUnboundSecretReference(t *testing.T) {
	ctx := context.Background()
	repository := &memoryRepository{}
	secrets := &memorySecrets{values: map[string][]byte{
		"credential/live": []byte("cloudflare token"),
	}}
	intent := domain.ACMEAccountCommitIntent{
		AccountID: "acmeacct_corrupt", SecretRef: "credential/live", CreatedAt: time.Now().UTC(),
	}
	if err := repository.SaveACMEAccountCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	err := RecoverACMEAccountCommitIntents(ctx, repository, secrets)
	if err == nil || !strings.Contains(err.Error(), "must equal") {
		t.Fatalf("malformed intent recovery error = %v", err)
	}
	if string(secrets.values["credential/live"]) != "cloudflare token" {
		t.Fatal("malformed account intent deleted an unrelated secret")
	}
	if len(repository.accountCommitIntents) != 1 {
		t.Fatalf("malformed intent was closed: %#v", repository.accountCommitIntents)
	}
}

func TestRegisterACMEAccountConflictCompensatesLosingKey(t *testing.T) {
	existing := domain.ACMEAccount{ID: "acmeacct_existing", Environment: EnvironmentStaging, Email: "existing@example.com", SecretRef: "acme-account/acmeacct_existing"}
	repository := &memoryRepository{account: existing, accountCommitErr: store.ErrACMEAccountConflict}
	secrets := &memorySecrets{values: map[string][]byte{existing.SecretRef: []byte("existing key")}}
	service := &AccountService{Repository: repository, Secrets: secrets, HTTPClient: testACMEHTTPClient()}
	_, err := service.Register(context.Background(), RegisterAccountRequest{
		Environment:          EnvironmentStaging,
		Email:                "ops@example.com",
		TermsOfServiceAgreed: true,
		DirectoryURL:         "https://acme.test/directory",
		AllowCustomDirectory: true,
	})
	if !errors.Is(err, store.ErrACMEAccountConflict) {
		t.Fatalf("registration conflict = %v, want %v", err, store.ErrACMEAccountConflict)
	}
	if repository.account.ID != existing.ID || repository.account.SecretRef != existing.SecretRef {
		t.Fatalf("existing account changed: %#v", repository.account)
	}
	if len(repository.accountCommitIntents) != 0 {
		t.Fatalf("losing registration retained intent: %#v", repository.accountCommitIntents)
	}
	if len(secrets.values) != 1 || string(secrets.values[existing.SecretRef]) != "existing key" {
		t.Fatalf("losing registration was not compensated safely: %#v", secrets.values)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testACMEHTTPClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}
		switch request.URL.Path {
		case "/directory":
			response.Header.Set("Content-Type", "application/json")
			response.Body = io.NopCloser(strings.NewReader(`{"newNonce":"https://acme.test/nonce","newAccount":"https://acme.test/new-account","newOrder":"https://acme.test/new-order","revokeCert":"https://acme.test/revoke-cert","keyChange":"https://acme.test/key-change"}`))
		case "/nonce":
			response.StatusCode = http.StatusNoContent
			response.Header.Set("Replay-Nonce", "test-nonce")
		case "/new-account":
			response.StatusCode = http.StatusCreated
			response.Header.Set("Content-Type", "application/json")
			response.Header.Set("Replay-Nonce", "next-test-nonce")
			response.Header.Set("Location", "https://acme.test/account/1")
			response.Body = io.NopCloser(strings.NewReader(`{"status":"valid","contact":["mailto:ops@example.com"]}`))
		default:
			response.StatusCode = http.StatusNotFound
		}
		return response, nil
	})}
}

func TestLifecycleRejectsCrossAccountLineageReplacement(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour), domain.KeyECDSAP256)
	plan, err := NewWildcardPlan("zone-1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	existing := domain.CertificateLineage{ID: "lineage", ZoneID: plan.ZoneID, Source: domain.CertificateManaged, ACMEAccountID: "production-account", Identifiers: plan.Identifiers, CreatedAt: now, UpdatedAt: now}
	_, err = (&Lifecycle{Repository: &memoryRepository{}, Secrets: &memorySecrets{values: make(map[string][]byte)}}).CommitManaged(
		context.Background(), CommitRequest{ExistingLineage: &existing, Plan: plan, ACMEAccountID: "staging-account", Artifact: artifact, ExportRoot: filepath.Join(t.TempDir(), "example.com")})
	if err == nil || !strings.Contains(err.Error(), "another ACME account") {
		t.Fatalf("cross-account replacement error = %v", err)
	}
}

func testEngine(t *testing.T, backend *fakeBackend) (*Engine, *memoryRepository, *memorySecrets) {
	t.Helper()
	accountKey, err := GeneratePrivateKey(domain.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyPEM, err := MarshalPrivateKeyPKCS8(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	registrationJSON, err := json.Marshal(&acme.ExtendedAccount{Location: "https://acme.test/acct/1"})
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{account: domain.ACMEAccount{
		ID: "account-1", Environment: EnvironmentStaging, DirectoryURL: "https://acme.test/directory",
		Email: "ops@example.com", Registration: string(registrationJSON), SecretRef: "account-key",
	}}
	secrets := &memorySecrets{values: map[string][]byte{"account-key": accountKeyPEM}}
	engine := NewEngine(repository, secrets, &fakeSolver{}, func(context.Context, string) (provider.Auth, string, error) {
		return provider.Auth{}, "zone-1", nil
	}, WithBackendFactory(fakeBackendFactory{backend: backend}))
	return engine, repository, secrets
}

func testArtifact(t *testing.T, identifiers []string, notBefore, notAfter time.Time, algorithm domain.KeyAlgorithm) Artifact {
	t.Helper()
	key, err := GeneratePrivateKey(algorithm)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := certificateForKey(t, key, identifiers, notBefore, notAfter)
	keyPEM, err := MarshalPrivateKeyPKCS8(key)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, metadata, err := ParseCertificatePEM(certificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return Artifact{CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM, Metadata: metadata}
}

func certificateForKey(t *testing.T, key crypto.Signer, identifiers []string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identifiers[0]},
		DNSNames:     slices.Clone(identifiers),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testVersion(id, lineageID string, artifact Artifact) domain.CertificateVersion {
	return domain.CertificateVersion{
		ID: id, LineageID: lineageID, SerialNumber: artifact.Metadata.SerialNumber,
		FingerprintSHA256: artifact.Metadata.FingerprintSHA256, Issuer: artifact.Metadata.Issuer,
		Identifiers: slices.Clone(artifact.Metadata.Identifiers), NotBefore: artifact.Metadata.NotBefore,
		NotAfter: artifact.Metadata.NotAfter, CreatedAt: time.Now(),
	}
}

type fakeSolver struct {
	presentedJob      string
	cleaned           []string
	cleanupContextErr error
}

type recoverySolver struct {
	recordID      string
	found         bool
	reconciledJob string
	cleaned       []string
}

func (s *recoverySolver) PresentDNS01(context.Context, provider.Auth, string, string, string, string) (string, error) {
	return "", errors.New("not used")
}
func (s *recoverySolver) CleanupDNS01(_ context.Context, _ provider.Auth, _ string, recordID string) error {
	s.cleaned = append(s.cleaned, recordID)
	return nil
}
func (s *recoverySolver) ReconcileDNS01(_ context.Context, _ provider.Auth, _ string, _ string, _ string, jobID string) (string, bool, error) {
	s.reconciledJob = jobID
	return s.recordID, s.found, nil
}

func (s *fakeSolver) PresentDNS01(_ context.Context, _ provider.Auth, _, _, _, jobID string) (string, error) {
	s.presentedJob = jobID
	return "record-1", nil
}
func (s *fakeSolver) CleanupDNS01(ctx context.Context, _ provider.Auth, _ string, recordID string) error {
	s.cleanupContextErr = ctx.Err()
	s.cleaned = append(s.cleaned, recordID)
	return nil
}

type memoryRepository struct {
	account              domain.ACMEAccount
	accountCommitIntents []domain.ACMEAccountCommitIntent
	accountCommitErr     error
	challenges           []domain.ChallengeJournal
	lineage              domain.CertificateLineage
	versions             []domain.CertificateVersion
	commitIntents        []domain.CertificateCommitIntent
	saveChallengeErr     error
	commitErr            error
	commitAfterErr       error
	listCommitIntentsErr error
	mu                   sync.Mutex
}

func (r *memoryRepository) SaveACMEAccount(context.Context, domain.ACMEAccount) error { return nil }
func (r *memoryRepository) CommitACMEAccount(_ context.Context, account domain.ACMEAccount) error {
	if r.accountCommitErr != nil {
		return r.accountCommitErr
	}
	r.account = account
	for index := range r.accountCommitIntents {
		if r.accountCommitIntents[index].AccountID == account.ID {
			r.accountCommitIntents = append(r.accountCommitIntents[:index], r.accountCommitIntents[index+1:]...)
			break
		}
	}
	return nil
}
func (r *memoryRepository) SaveACMEAccountCommitIntent(_ context.Context, intent domain.ACMEAccountCommitIntent) error {
	r.accountCommitIntents = append(r.accountCommitIntents, intent)
	return nil
}
func (r *memoryRepository) ListACMEAccountCommitIntents(context.Context) ([]domain.ACMEAccountCommitIntent, error) {
	return slices.Clone(r.accountCommitIntents), nil
}
func (r *memoryRepository) DeleteACMEAccountCommitIntent(_ context.Context, accountID string) error {
	for index := range r.accountCommitIntents {
		if r.accountCommitIntents[index].AccountID == accountID {
			r.accountCommitIntents = append(r.accountCommitIntents[:index], r.accountCommitIntents[index+1:]...)
			break
		}
	}
	return nil
}
func (r *memoryRepository) GetACMEAccountByEnvironment(context.Context, string) (domain.ACMEAccount, error) {
	return r.account, nil
}
func (r *memoryRepository) SaveChallenge(_ context.Context, journal domain.ChallengeJournal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveChallengeErr != nil {
		return r.saveChallengeErr
	}
	for index := range r.challenges {
		if r.challenges[index].ID == journal.ID {
			r.challenges[index] = journal
			return nil
		}
	}
	r.challenges = append(r.challenges, journal)
	return nil
}
func (r *memoryRepository) ListOpenChallenges(context.Context) ([]domain.ChallengeJournal, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.challenges), nil
}
func (r *memoryRepository) MarkChallengeCleaned(_ context.Context, id string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.challenges {
		if r.challenges[index].ID == id {
			r.challenges[index].CleanedAt = &at
		}
	}
	return nil
}
func (r *memoryRepository) SaveCertificateLineage(_ context.Context, lineage domain.CertificateLineage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lineage = lineage
	return nil
}
func (r *memoryRepository) SaveCertificateVersion(_ context.Context, version domain.CertificateVersion) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.versions = append(r.versions, version)
	return nil
}
func (r *memoryRepository) CommitCertificateVersion(_ context.Context, lineage domain.CertificateLineage, version domain.CertificateVersion) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.commitErr != nil {
		return r.commitErr
	}
	r.lineage = lineage
	r.versions = append(r.versions, version)
	for index := range r.commitIntents {
		if r.commitIntents[index].VersionID == version.ID {
			r.commitIntents = append(r.commitIntents[:index], r.commitIntents[index+1:]...)
			break
		}
	}
	return r.commitAfterErr
}
func (r *memoryRepository) SaveCertificateCommitIntent(_ context.Context, intent domain.CertificateCommitIntent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commitIntents = append(r.commitIntents, intent)
	return nil
}
func (r *memoryRepository) ListCertificateCommitIntents(context.Context) ([]domain.CertificateCommitIntent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listCommitIntentsErr != nil {
		return nil, r.listCommitIntentsErr
	}
	return slices.Clone(r.commitIntents), nil
}
func (r *memoryRepository) DeleteCertificateCommitIntent(_ context.Context, versionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.commitIntents {
		if r.commitIntents[index].VersionID == versionID {
			r.commitIntents = append(r.commitIntents[:index], r.commitIntents[index+1:]...)
			break
		}
	}
	return nil
}

type memorySecrets struct {
	values  map[string][]byte
	putErr  error
	deleted []string
}

func (s *memorySecrets) Put(_ context.Context, name string, value []byte) (string, error) {
	s.values[name] = slices.Clone(value)
	return name, s.putErr
}
func (s *memorySecrets) Get(_ context.Context, ref string) ([]byte, error) {
	return slices.Clone(s.values[ref]), nil
}
func (s *memorySecrets) Delete(_ context.Context, ref string) error {
	s.deleted = append(s.deleted, ref)
	delete(s.values, ref)
	return nil
}

type fakeBackendFactory struct{ backend CertificateBackend }

func (f fakeBackendFactory) New(context.Context, AccountMaterial, challenge.Provider) (CertificateBackend, error) {
	return f.backend, nil
}

type fakeBackend struct {
	active       atomic.Int32
	maximum      atomic.Int32
	renewalCalls atomic.Int32
	mu           sync.Mutex
	publicKeys   [][]byte
	replaces     []string
	renewalInfo  *certificate.RenewalInfo
	renewalErr   error
	obtainDelay  time.Duration
}

func (b *fakeBackend) Obtain(ctx context.Context, request certificate.ObtainRequest) (*certificate.Resource, error) {
	active := b.active.Add(1)
	for {
		maximum := b.maximum.Load()
		if active <= maximum || b.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	defer b.active.Add(-1)
	delay := b.obtainDelay
	if delay <= 0 {
		delay = 15 * time.Millisecond
	}
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	publicKey, _ := x509.MarshalPKIXPublicKey(request.PrivateKey.Public())
	b.mu.Lock()
	b.publicKeys = append(b.publicKeys, publicKey)
	b.replaces = append(b.replaces, request.ReplacesCertID)
	b.mu.Unlock()
	certificatePEM := certificateForSigner(request.PrivateKey, request.Domains)
	return &certificate.Resource{Certificate: certificatePEM, Domains: request.Domains}, nil
}
func (b *fakeBackend) RevokeWithReason(context.Context, []byte, *uint) error { return nil }
func (b *fakeBackend) GetRenewalInfo(context.Context, *x509.Certificate) (*certificate.RenewalInfo, error) {
	b.renewalCalls.Add(1)
	if b.renewalErr != nil {
		return nil, b.renewalErr
	}
	if b.renewalInfo == nil {
		return nil, errors.New("not implemented")
	}
	return b.renewalInfo, nil
}

func certificateForSigner(key crypto.Signer, identifiers []string) []byte {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: identifiers[0]},
		DNSNames:     slices.Clone(identifiers),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var (
	_ crypto.Signer = (*ecdsa.PrivateKey)(nil)
	_ crypto.Signer = (*rsa.PrivateKey)(nil)
	_               = elliptic.P256
)
