package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/store"
)

func openTestRepository(t *testing.T) *Repository {
	t.Helper()
	repository, err := New(filepath.Join(t.TempDir(), "state", "domainops.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	if err := repository.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := repository.Migrate(context.Background()); err != nil {
		t.Fatalf("second migration must be idempotent: %v", err)
	}
	return repository
}

func TestRepositoryUsesFullSynchronousDurability(t *testing.T) {
	r := openTestRepository(t)
	var synchronous int
	if err := r.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if synchronous != 2 {
		t.Fatalf("PRAGMA synchronous = %d, want FULL (2)", synchronous)
	}
}

func TestACMEAccountCommitClosesSecretIntentAtomically(t *testing.T) {
	ctx := context.Background()
	r := openTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	intent := domain.ACMEAccountCommitIntent{AccountID: "acme-journal", SecretRef: "acme-account/acme-journal", CreatedAt: now}
	if err := r.SaveACMEAccountCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	account := domain.ACMEAccount{ID: intent.AccountID, Environment: "staging", DirectoryURL: "https://ca.invalid/directory", Email: "ops@example.com", Registration: `{}`, SecretRef: intent.SecretRef, CreatedAt: now}
	if err := r.CommitACMEAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	intents, err := r.ListACMEAccountCommitIntents(ctx)
	if err != nil || len(intents) != 0 {
		t.Fatalf("ACME account intents = %#v, %v", intents, err)
	}
	loaded, err := r.GetACMEAccountByEnvironment(ctx, account.Environment)
	if err != nil || loaded.ID != account.ID || loaded.SecretRef != account.SecretRef {
		t.Fatalf("committed ACME account = %#v, %v", loaded, err)
	}
}

func TestACMEAccountCommitConflictPreservesExistingAccountAndIntent(t *testing.T) {
	ctx := context.Background()
	r := openTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	existing := domain.ACMEAccount{ID: "acme-existing", Environment: "staging", DirectoryURL: "https://ca.invalid/directory", Email: "existing@example.com", Registration: `{}`, SecretRef: "acme-account/acme-existing", CreatedAt: now}
	if err := r.SaveACMEAccount(ctx, existing); err != nil {
		t.Fatal(err)
	}
	intent := domain.ACMEAccountCommitIntent{AccountID: "acme-loser", SecretRef: "acme-account/acme-loser", CreatedAt: now.Add(time.Second)}
	if err := r.SaveACMEAccountCommitIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	challenger := domain.ACMEAccount{ID: intent.AccountID, Environment: existing.Environment, DirectoryURL: "https://ca.invalid/directory", Email: "loser@example.com", Registration: `{}`, SecretRef: intent.SecretRef, CreatedAt: intent.CreatedAt}
	if err := r.CommitACMEAccount(ctx, challenger); !errors.Is(err, store.ErrACMEAccountConflict) {
		t.Fatalf("commit conflict = %v, want %v", err, store.ErrACMEAccountConflict)
	}
	loaded, err := r.GetACMEAccountByEnvironment(ctx, existing.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != existing.ID || loaded.SecretRef != existing.SecretRef || loaded.Email != existing.Email {
		t.Fatalf("existing account was replaced: %#v", loaded)
	}
	intents, err := r.ListACMEAccountCommitIntents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].AccountID != intent.AccountID {
		t.Fatalf("losing commit intent = %#v, want %#v", intents, intent)
	}
}

func TestRepositoryInventoryDNSAndTLSRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := openTestRepository(t)
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	verified := now.Add(time.Minute)
	credential := domain.Credential{
		ID: "cred_1", Provider: domain.ProviderCloudflare, Label: "Production",
		Kind: domain.CredentialUserToken, SecretRef: "secret_1", Status: domain.CredentialValid,
		Capabilities: []string{"dns:read", "dns:write"}, CreatedAt: now, LastVerifiedAt: &verified,
	}
	if err := r.SaveCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	accounts := []domain.RemoteAccount{{ID: "cfacct_a", Provider: domain.ProviderCloudflare, ProviderID: "a", Name: "Account A", CreatedAt: now}}
	links := []domain.AccountCredential{{AccountID: "cfacct_a", CredentialID: credential.ID, Preferred: true}}
	if err := r.SaveAccounts(ctx, accounts, links); err != nil {
		t.Fatal(err)
	}
	zone := domain.Zone{
		ID: "cfzone_z", Provider: domain.ProviderCloudflare, ProviderID: "z", AccountID: "cfacct_a",
		PreferredCredentialID: credential.ID, Name: "example.com", Status: domain.ZoneActive,
		Plan: "Free", NameServers: []string{"ns1.example", "ns2.example"}, LastSyncedAt: &now,
	}
	if err := r.SaveZones(ctx, []domain.Zone{zone}); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:write", now); err != nil {
		t.Fatal(err)
	}
	if observed, err := r.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:write"); err != nil || !observed {
		t.Fatalf("credential zone capability = %v, %v", observed, err)
	}
	if observedAt, observed, err := r.GetCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:write"); err != nil || !observed || !observedAt.Equal(now) {
		t.Fatalf("credential zone capability observation = %v, %v, %v", observedAt, observed, err)
	}
	if observed, err := r.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "tls:write"); err != nil || observed {
		t.Fatalf("unobserved zone capability = %v, %v", observed, err)
	}
	if err := r.SaveCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read", now); err != nil {
		t.Fatal(err)
	}
	if err := r.InvalidateCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read"); err != nil {
		t.Fatal(err)
	}
	if observed, err := r.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read"); err != nil || observed {
		t.Fatalf("invalidated DNS-read capability = %v, %v", observed, err)
	}
	if observed, err := r.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:write"); err != nil || !observed {
		t.Fatalf("unrelated DNS-write capability changed = %v, %v", observed, err)
	}
	if detached, err := r.GetZone(ctx, zone.ID); err != nil || detached.PreferredCredentialID != "" {
		t.Fatalf("invalidated preferred route = %#v, %v", detached, err)
	}
	priority := uint16(10)
	records := []domain.DNSRecord{
		{ID: "cfrecord_1", ProviderID: "1", ZoneID: zone.ID, Type: domain.RecordA, Name: "example.com", Content: "192.0.2.1", TTL: 1, Proxied: true, Proxiable: true, Tags: []string{"owner:test"}},
		{ID: "cfrecord_2", ProviderID: "2", ZoneID: zone.ID, Type: domain.RecordMX, Name: "example.com", Content: "mail.example.com", TTL: 3600, Priority: &priority},
	}
	if err := r.ReplaceDNSRecords(ctx, zone.ID, records, now); err != nil {
		t.Fatal(err)
	}
	loaded, err := r.ListDNSRecords(ctx, zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded[0].ZoneID != zone.ID {
		t.Fatalf("loaded records = %#v", loaded)
	}
	if err := r.ReplaceDNSRecords(ctx, zone.ID, records[:1], now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = r.ListDNSRecords(ctx, zone.ID)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("replacement = %#v, %v", loaded, err)
	}

	settings := domain.EdgeTLSSettings{ZoneID: zone.ID, Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true, HasProxiedDNS: true, LastSyncedAt: &now}
	if err := r.SaveTLSSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	gotSettings, err := r.GetTLSSettings(ctx, zone.ID)
	if err != nil || gotSettings.Mode != "strict" || !gotSettings.TLS13 {
		t.Fatalf("TLS = %#v, %v", gotSettings, err)
	}

	gotCredential, err := r.GetCredential(ctx, credential.ID)
	if err != nil || gotCredential.SecretRef != "secret_1" || len(gotCredential.Capabilities) != 2 {
		t.Fatalf("credential = %#v, %v", gotCredential, err)
	}
	gotZone, err := r.GetZone(ctx, zone.ID)
	if err != nil || gotZone.Name != zone.Name || len(gotZone.NameServers) != 2 {
		t.Fatalf("zone = %#v, %v", gotZone, err)
	}
}

func TestRepositoryCertificatesJobsHealthAndDashboard(t *testing.T) {
	ctx := context.Background()
	r := openTestRepository(t)
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	credential := domain.Credential{ID: "cred", Provider: domain.ProviderCloudflare, Label: "CF", Kind: domain.CredentialUserToken, SecretRef: "secret", Status: domain.CredentialValid, CreatedAt: now}
	if err := r.SaveCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	account := domain.RemoteAccount{ID: "account", Provider: domain.ProviderCloudflare, ProviderID: "remote", Name: "Remote", CreatedAt: now}
	if err := r.SaveAccounts(ctx, []domain.RemoteAccount{account}, []domain.AccountCredential{{AccountID: account.ID, CredentialID: credential.ID, Preferred: true}}); err != nil {
		t.Fatal(err)
	}
	zone := domain.Zone{ID: "zone", Provider: domain.ProviderCloudflare, ProviderID: "remote-zone", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "example.com", Status: domain.ZoneActive}
	if err := r.SaveZones(ctx, []domain.Zone{zone}); err != nil {
		t.Fatal(err)
	}

	acme := domain.ACMEAccount{ID: "acme", Environment: "production", DirectoryURL: "https://ca.invalid/directory", Email: "ops@example.com", Registration: `{}`, SecretRef: "acme-secret", CreatedAt: now}
	if err := r.SaveACMEAccount(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if loaded, err := r.GetACMEAccountByEnvironment(ctx, "production"); err != nil || loaded.SecretRef != acme.SecretRef {
		t.Fatalf("ACME = %#v, %v", loaded, err)
	}

	lineage := domain.CertificateLineage{ID: "lineage", Name: "example.com", ZoneID: zone.ID, Source: domain.CertificateManaged, Identifiers: []string{"example.com", "*.example.com"}, KeyAlgorithm: domain.KeyECDSAP256, Profile: "classic", ACMEAccountID: acme.ID, CreatedAt: now, UpdatedAt: now}
	if err := r.SaveCertificateLineage(ctx, lineage); err != nil {
		t.Fatal(err)
	}
	due := now.Add(-time.Hour)
	version := domain.CertificateVersion{ID: "version", LineageID: lineage.ID, SerialNumber: "01", FingerprintSHA256: "abc", Issuer: "Test CA", Identifiers: lineage.Identifiers, NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), CertificatePath: "/tmp/cert.pem", ChainPath: "/tmp/chain.pem", PrivateKeyRef: "key", RenewalWindowStart: &due, CreatedAt: now}
	if err := r.SaveCertificateVersion(ctx, version); err != nil {
		t.Fatal(err)
	}
	revokedAt := now.Add(-2 * time.Hour)
	pendingAt := now.Add(-3 * time.Hour)
	reason := uint(1)
	revokedVersion := version
	revokedVersion.ID, revokedVersion.SerialNumber = "revoked-version", "02"
	revokedVersion.RevocationPendingAt, revokedVersion.RevokedAt, revokedVersion.RevocationReason = &pendingAt, &revokedAt, &reason
	if err := r.SaveCertificateVersion(ctx, revokedVersion); err != nil {
		t.Fatal(err)
	}
	versions, err := r.ListCertificateVersions(ctx, lineage.ID)
	if err != nil || len(versions) != 2 || versions[0].RevocationPendingAt == nil || versions[0].RevokedAt == nil || versions[0].RevocationReason == nil || *versions[0].RevocationReason != reason {
		t.Fatalf("revocation round trip = %#v, %v", versions, err)
	}
	lineage.CurrentVersionID = version.ID
	if err := r.SaveCertificateLineage(ctx, lineage); err != nil {
		t.Fatal(err)
	}

	endpoint := domain.ObservedEndpoint{ID: "endpoint", ZoneID: zone.ID, Host: "example.com", Port: 443, Enabled: true, FingerprintSHA256: "def", LastCheckedAt: &now}
	if err := r.SaveEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	issue := domain.HealthIssue{ID: "issue", Severity: domain.SeverityWarning, Kind: "stale", ResourceID: endpoint.ID, Title: "Certificate differs", Detail: "Observed fingerprint differs", ObservedAt: now}
	if err := r.SaveHealthIssues(ctx, endpoint.ID, []domain.HealthIssue{issue}); err != nil {
		t.Fatal(err)
	}
	job := domain.Job{ID: "job", Kind: "certificate.issue", State: domain.JobRunning, Progress: 50, Message: "Waiting", Payload: json.RawMessage(`{"safe":true}`), CreatedAt: now, StartedAt: &now, UpdatedAt: now}
	if err := r.SaveJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	challenge := domain.ChallengeJournal{ID: "challenge", JobID: job.ID, CredentialID: credential.ID, ZoneID: zone.ID, RecordID: "txt", FQDN: "_acme-challenge.example.com", ValueHash: "hash", CreatedAt: now}
	if err := r.SaveChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if err := r.AppendAudit(ctx, domain.AuditEvent{ID: "audit", Actor: "test", Action: "dns.patch", ResourceID: "record", Before: json.RawMessage(`{"a":1}`), After: json.RawMessage(`{"a":2}`), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := r.Dashboard(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Accounts != 1 || snapshot.Zones != 1 || snapshot.Certificates != 1 || snapshot.CertificatesDue != 1 || snapshot.ActiveJobs != 1 || len(snapshot.Issues) != 1 {
		t.Fatalf("dashboard = %#v", snapshot)
	}
	recoverable, err := r.ListRecoverableJobs(ctx)
	if err != nil || len(recoverable) != 1 {
		t.Fatalf("recoverable = %#v, %v", recoverable, err)
	}
	open, err := r.ListOpenChallenges(ctx)
	if err != nil || len(open) != 1 || open[0].CredentialID != credential.ID {
		t.Fatalf("open challenges = %#v, %v", open, err)
	}
	if err := r.MarkChallengeCleaned(ctx, challenge.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	open, err = r.ListOpenChallenges(ctx)
	if err != nil || len(open) != 0 {
		t.Fatalf("cleaned challenges = %#v, %v", open, err)
	}
	audit, err := r.ListAudit(ctx, 10)
	if err != nil || len(audit) != 1 || string(audit[0].Before) != `{"a":1}` {
		t.Fatalf("audit = %#v, %v", audit, err)
	}
}

func TestReconcileInterruptedJobsMarksOnlyActiveStatesFailed(t *testing.T) {
	ctx := context.Background()
	repository := openTestRepository(t)
	started := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	states := []domain.JobState{
		domain.JobQueued,
		domain.JobRunning,
		domain.JobWaitingForDNS,
		domain.JobSucceeded,
		domain.JobFailed,
	}
	for _, state := range states {
		job := domain.Job{ID: "job-" + string(state), Kind: "test", State: state, Message: string(state), CreatedAt: started, UpdatedAt: started}
		if state == domain.JobFailed {
			retry := started.Add(time.Hour)
			job.RetryAt = &retry
		}
		if err := repository.SaveJob(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	finished := started.Add(5 * time.Minute)
	count, err := repository.ReconcileInterruptedJobs(ctx, finished)
	if err != nil || count != 3 {
		t.Fatalf("reconciled count = %d, %v; want 3", count, err)
	}
	for _, state := range states {
		job, err := repository.GetJob(ctx, "job-"+string(state))
		if err != nil {
			t.Fatal(err)
		}
		switch state {
		case domain.JobQueued, domain.JobRunning, domain.JobWaitingForDNS:
			if job.State != domain.JobFailed || job.FinishedAt == nil || !job.FinishedAt.Equal(finished) || job.RetryAt != nil || !strings.Contains(job.Error, "interrupted") {
				t.Fatalf("active %s job after reconcile = %#v", state, job)
			}
		default:
			if job.State != state {
				t.Fatalf("terminal %s job changed to %s", state, job.State)
			}
		}
	}
}

func TestSaveEndpointReusesUniqueHostPortAcrossZoneReassignment(t *testing.T) {
	ctx := context.Background()
	repository := openTestRepository(t)
	now := time.Date(2026, 7, 12, 11, 0, 0, 0, time.UTC)
	credential := domain.Credential{ID: "cred-endpoint", Provider: domain.ProviderCloudflare, Label: "CF", Kind: domain.CredentialUserToken, SecretRef: "secret", Status: domain.CredentialValid, CreatedAt: now}
	if err := repository.SaveCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	account := domain.RemoteAccount{ID: "account-endpoint", Provider: domain.ProviderCloudflare, ProviderID: "account-endpoint", Name: "Endpoints", CreatedAt: now}
	if err := repository.SaveAccounts(ctx, []domain.RemoteAccount{account}, []domain.AccountCredential{{AccountID: account.ID, CredentialID: credential.ID}}); err != nil {
		t.Fatal(err)
	}
	zones := []domain.Zone{
		{ID: "zone-old", Provider: domain.ProviderCloudflare, ProviderID: "zone-old", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "example.com", Status: domain.ZoneUnknown},
		{ID: "zone-new", Provider: domain.ProviderCloudflare, ProviderID: "zone-new", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "www.example.com", Status: domain.ZoneActive},
	}
	if err := repository.SaveZones(ctx, zones); err != nil {
		t.Fatal(err)
	}
	old := domain.ObservedEndpoint{ID: "endpoint-old", ZoneID: zones[0].ID, Host: "www.example.com", Port: 443, Enabled: true, FingerprintSHA256: "old"}
	if err := repository.SaveEndpoint(ctx, old); err != nil {
		t.Fatal(err)
	}
	reassigned := domain.ObservedEndpoint{ID: "endpoint-new", ZoneID: zones[1].ID, Host: "www.example.com", Port: 443, Enabled: true, FingerprintSHA256: "new"}
	if err := repository.SaveEndpoint(ctx, reassigned); err != nil {
		t.Fatalf("host/port reassignment conflicted: %v", err)
	}
	endpoints, err := repository.ListEndpoints(ctx)
	if err != nil || len(endpoints) != 1 {
		t.Fatalf("reassigned endpoints = %#v, %v", endpoints, err)
	}
	if endpoints[0].ID != old.ID || endpoints[0].ZoneID != zones[1].ID || endpoints[0].FingerprintSHA256 != "new" {
		t.Fatalf("retained endpoint after reassignment = %#v", endpoints[0])
	}
}

func TestEndpointHostPortMigrationDeduplicatesLegacyDatabase(t *testing.T) {
	ctx := context.Background()
	repository, err := New(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	initial, err := migrationFiles.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(initial), "    last_error TEXT NOT NULL DEFAULT '',\n    UNIQUE(host, port)\n", "    last_error TEXT NOT NULL DEFAULT ''\n", 1)
	if legacy == string(initial) {
		t.Fatal("legacy schema fixture did not remove endpoint uniqueness")
	}
	if _, err := repository.db.ExecContext(ctx, legacy); err != nil {
		t.Fatalf("create legacy initial schema: %v", err)
	}
	if _, err := repository.db.ExecContext(ctx, `CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	legacyMigrations := []string{
		"001_initial.sql",
		"002_challenge_credential.sql",
		"003_certificate_revocation.sql",
		"004_revocation_intent.sql",
		"005_zone_capabilities.sql",
		"006_certificate_commit_journal.sql",
		"007_acme_account_commit_journal.sql",
	}
	for _, name := range legacyMigrations {
		if name != "001_initial.sql" {
			body, readErr := migrationFiles.ReadFile("migrations/" + name)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, execErr := repository.db.ExecContext(ctx, string(body)); execErr != nil {
				t.Fatalf("apply legacy migration %s: %v", name, execErr)
			}
		}
		if _, err := repository.db.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", name, encodeTime(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	credential := domain.Credential{ID: "legacy-cred", Provider: domain.ProviderCloudflare, Label: "Legacy", Kind: domain.CredentialUserToken, SecretRef: "secret", Status: domain.CredentialValid, CreatedAt: now}
	if err := repository.SaveCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	account := domain.RemoteAccount{ID: "legacy-account", Provider: domain.ProviderCloudflare, ProviderID: "legacy-account", Name: "Legacy", CreatedAt: now}
	if err := repository.SaveAccounts(ctx, []domain.RemoteAccount{account}, []domain.AccountCredential{{AccountID: account.ID, CredentialID: credential.ID}}); err != nil {
		t.Fatal(err)
	}
	zones := []domain.Zone{
		{ID: "legacy-zone-a", Provider: domain.ProviderCloudflare, ProviderID: "legacy-zone-a", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "example.com", Status: domain.ZoneActive},
		{ID: "legacy-zone-b", Provider: domain.ProviderCloudflare, ProviderID: "legacy-zone-b", AccountID: account.ID, PreferredCredentialID: credential.ID, Name: "www.example.com", Status: domain.ZoneActive},
	}
	if err := repository.SaveZones(ctx, zones); err != nil {
		t.Fatal(err)
	}
	insertEndpoint := `INSERT INTO endpoints (
		id, zone_id, host, port, enabled, resolved_addresses_json,
		fingerprint_sha256, issuer, valid_for_host, trusted, last_error
	) VALUES (?, ?, 'www.example.com', 443, ?, '[]', '', '', 0, 0, '')`
	if _, err := repository.db.ExecContext(ctx, insertEndpoint, "legacy-keeper", zones[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.db.ExecContext(ctx, insertEndpoint, "legacy-duplicate", zones[1].ID, false); err != nil {
		t.Fatalf("legacy schema unexpectedly enforced uniqueness: %v", err)
	}
	for _, endpointID := range []string{"legacy-keeper", "legacy-duplicate"} {
		if _, err := repository.db.ExecContext(ctx, `INSERT INTO health_issues (
			id, owner_id, severity, kind, resource_id, title, detail, action, observed_at
		) VALUES (?, ?, 'warning', 'legacy', ?, 'Legacy', 'Legacy issue', '', ?)`, "issue-"+endpointID, endpointID, endpointID, encodeTime(now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.Migrate(ctx); err != nil {
		t.Fatalf("upgrade legacy endpoint schema: %v", err)
	}
	endpoints, err := repository.ListEndpoints(ctx)
	if err != nil || len(endpoints) != 1 || endpoints[0].ID != "legacy-keeper" {
		t.Fatalf("deduplicated endpoints = %#v, %v", endpoints, err)
	}
	issues, err := repository.ListHealthIssues(ctx)
	if err != nil || len(issues) != 1 || issues[0].ResourceID != "legacy-keeper" {
		t.Fatalf("deduplicated health issues = %#v, %v", issues, err)
	}
	if _, err := repository.db.ExecContext(ctx, insertEndpoint, "legacy-third", zones[1].ID, true); err == nil {
		t.Fatal("upgraded schema accepted duplicate host/port")
	}
}

func TestRepositoryFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "domainops.db")
	r, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o", info.Mode().Perm())
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("database directory mode = %o", dir.Mode().Perm())
	}
}
