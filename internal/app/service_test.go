package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
	"github.com/MeghdadFadaee/domainops/internal/secrets"
	"github.com/MeghdadFadaee/domainops/internal/store"
	sqlitestore "github.com/MeghdadFadaee/domainops/internal/store/sqlite"
)

func TestServiceMultiCredentialSyncAndDNSLifecycle(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repository, err := sqlitestore.New(filepath.Join(root, "domainops.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(filepath.Join(root, "vault.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Unlock(ctx, []byte("long integration password")); err != nil {
		t.Fatal(err)
	}

	fake := newFakeCloudProvider()
	service := New(repository, vault)
	service.RegisterProvider(domain.ProviderCloudflare, fake)
	first, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Primary", Token: "token-one", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Secondary", Token: "token-two", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	if first.SecretRef == second.SecretRef {
		t.Fatal("separate Cloudflare credentials share one secret reference")
	}
	firstToken, _ := vault.Get(ctx, first.SecretRef)
	secondToken, _ := vault.Get(ctx, second.SecretRef)
	if string(firstToken) != "token-one" || string(secondToken) != "token-two" {
		t.Fatalf("stored tokens = %q / %q", firstToken, secondToken)
	}

	job, err := service.SyncCredential(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != domain.JobSucceeded || job.Progress != 100 {
		t.Fatalf("sync job = %#v", job)
	}
	zones, err := service.Zones(ctx)
	if err != nil || len(zones) != 1 || zones[0].Name != "example.com" {
		t.Fatalf("zones = %#v, %v", zones, err)
	}
	records, err := service.DNSRecords(ctx, zones[0].ID)
	if err != nil || len(records) != 1 || records[0].Content != "192.0.2.1" {
		t.Fatalf("records = %#v, %v", records, err)
	}
	endpoints, err := repository.ListEndpoints(ctx)
	if err != nil || len(endpoints) != 1 || endpoints[0].Host != "example.com" {
		t.Fatalf("endpoints = %#v, %v", endpoints, err)
	}

	created, err := service.CreateDNSRecord(ctx, zones[0].ID, domain.DNSRecord{Type: domain.RecordA, Name: "www", Content: "192.0.2.2", TTL: 300, Proxied: true})
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "www.example.com" || created.ProviderID == "" {
		t.Fatalf("created = %#v", created)
	}
	created.Content = "192.0.2.3"
	fake.mu.Lock()
	concurrent := fake.records[created.ProviderID]
	concurrent.Content = "192.0.2.99"
	fake.records[created.ProviderID] = concurrent
	fake.mu.Unlock()
	if _, err := service.PatchDNSRecord(ctx, zones[0].ID, created.ID, created); !errors.Is(err, ErrDNSConflict) {
		t.Fatalf("concurrent DNS patch error = %v", err)
	}
	fake.mu.Lock()
	concurrent.Content = "192.0.2.2"
	fake.records[created.ProviderID] = concurrent
	fake.mu.Unlock()
	updated, err := service.PatchDNSRecord(ctx, zones[0].ID, created.ID, created)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Content != "192.0.2.3" {
		t.Fatalf("updated = %#v", updated)
	}
	fake.mu.Lock()
	becameManaged := fake.records[updated.ProviderID]
	becameManaged.Managed = true
	fake.records[updated.ProviderID] = becameManaged
	fake.mu.Unlock()
	if err := service.DeleteDNSRecord(ctx, zones[0].ID, updated.ID); err == nil {
		t.Fatal("record that became managed was deleted")
	}
	fake.mu.Lock()
	becameManaged.Managed = false
	fake.records[updated.ProviderID] = becameManaged
	fake.mu.Unlock()
	if err := service.DeleteDNSRecord(ctx, zones[0].ID, updated.ID); err != nil {
		t.Fatal(err)
	}

	settings, err := service.TLSSettings(ctx, zones[0].ID, true)
	if err != nil || settings.Mode != "strict" {
		t.Fatalf("TLS = %#v, %v", settings, err)
	}
	settings.MinimumTLS = "1.3"
	settings, err = service.UpdateTLSSettings(ctx, zones[0].ID, settings)
	if err != nil || settings.MinimumTLS != "1.3" {
		t.Fatalf("updated TLS = %#v, %v", settings, err)
	}

	auth, providerZoneID, err := service.ResolveDNS01(ctx, "_acme-challenge.api.example.com.")
	if err != nil || auth.Token != "token-one" || providerZoneID != "zone-provider" {
		t.Fatalf("DNS-01 resolution = %#v, %q, %v", auth, providerZoneID, err)
	}

	if _, err := service.SyncCredential(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	zones, err = service.Zones(ctx)
	if err != nil || len(zones) != 1 || zones[0].PreferredCredentialID != first.ID {
		t.Fatalf("overlapping sync changed preferred credential: zones=%#v err=%v", zones, err)
	}
	auth, providerZoneID, err = service.ResolveDNS01(ctx, "_acme-challenge.api.example.com.")
	if err != nil || auth.Token != "token-one" || providerZoneID != "zone-provider" {
		t.Fatalf("stable DNS-01 resolution = %#v, %q, %v", auth, providerZoneID, err)
	}
	if _, err := service.SetZonePreferredCredential(ctx, zones[0].ID, second.ID); err != nil {
		t.Fatal(err)
	}
	auth, _, err = service.ResolveDNS01(ctx, "_acme-challenge.api.example.com.")
	if err != nil || auth.Token != "token-two" {
		t.Fatalf("explicit preferred credential was not used: %#v, %v", auth, err)
	}
	if _, err := service.CreateDNSRecord(ctx, zones[0].ID, domain.DNSRecord{Type: domain.RecordA, Name: "replacement-proof", Content: "192.0.2.40", TTL: 300}); err != nil {
		t.Fatalf("prove replacement zone write: %v", err)
	}
	if _, err := service.SetZonePreferredCredential(ctx, zones[0].ID, first.ID); err != nil {
		t.Fatal(err)
	}
	challenge := domain.ChallengeJournal{ID: "challenge-removal", JobID: "job", CredentialID: first.ID, ZoneID: "zone-provider", FQDN: "_acme-challenge.example.com.", ValueHash: "hash", CreatedAt: time.Now()}
	if err := repository.SaveChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteCredential(ctx, first.ID); err == nil || !strings.Contains(err.Error(), "still requires") {
		t.Fatalf("credential with an open challenge was removable: %v", err)
	}
	if err := repository.MarkChallengeCleaned(ctx, challenge.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteCredential(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	auth, providerZoneID, err = service.ResolveDNS01(ctx, "_acme-challenge.api.example.com.")
	if err != nil || auth.Token != "token-two" || providerZoneID != "zone-provider" {
		t.Fatalf("credential removal did not safely reassign zone = %#v, %q, %v", auth, providerZoneID, err)
	}
	if err := service.DeleteCredential(ctx, second.ID); err == nil || !strings.Contains(err.Error(), "no other credential with recent observed DNS-write access") {
		t.Fatalf("last usable credential was removable: %v", err)
	}
}

func TestUnlockRecoveryFailureIsVisibleAndClearsAfterRetry(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repository, err := sqlitestore.New(filepath.Join(root, "domainops.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New(filepath.Join(root, "vault.json"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	service := New(repository, vault)
	recoveryErr := errors.New("orphan cleanup failed")
	service.SetUnlockHook(func(context.Context) error { return recoveryErr })
	if err := service.UnlockVault(ctx, []byte("long recovery test password")); !IsRecoveryWarning(err) {
		t.Fatalf("recovery unlock warning = %v", err)
	}
	// The warning is repository-backed, so even a fresh read-only service (the
	// shape used by `status`) can report it without unlocking again.
	snapshot, err := New(repository, vault).Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Issues) != 1 || snapshot.Issues[0].Kind != "certificate_commit_recovery_failed" || snapshot.Issues[0].Severity != domain.SeverityCritical || !strings.Contains(snapshot.Issues[0].Detail, recoveryErr.Error()) {
		t.Fatalf("recovery dashboard issue = %#v", snapshot.Issues)
	}
	if _, mutationErr := service.AddCloudflareCredential(ctx, AddCredentialInput{Token: "blocked-token"}); !errors.Is(mutationErr, ErrRecoveryRequired) {
		t.Fatalf("mutation while recovery was unresolved = %v", mutationErr)
	}
	service.SetUnlockHook(func(context.Context) error { return nil })
	if err := service.UnlockVault(ctx, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err = service.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range snapshot.Issues {
		if issue.Kind == "certificate_commit_recovery_failed" {
			t.Fatalf("successful retry retained recovery warning: %#v", snapshot.Issues)
		}
	}
	if _, mutationErr := service.AddCloudflareCredential(ctx, AddCredentialInput{Token: "now-unblocked"}); errors.Is(mutationErr, ErrRecoveryRequired) {
		t.Fatalf("successful recovery left mutation guard active: %v", mutationErr)
	}
}

func TestReconcileInterruptedJobsClosesAbandonedActiveWork(t *testing.T) {
	ctx := context.Background()
	service, repository := newUnsyncedProviderService(t, newFakeCloudProvider())
	now := time.Now().Add(-time.Minute).UTC()
	for _, state := range []domain.JobState{domain.JobQueued, domain.JobRunning, domain.JobWaitingForDNS} {
		job := domain.Job{ID: "job-" + string(state), Kind: "test", State: state, Message: "active", CreatedAt: now, UpdatedAt: now}
		if err := repository.SaveJob(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	succeeded := domain.Job{ID: "job-succeeded", Kind: "test", State: domain.JobSucceeded, Message: "done", CreatedAt: now, UpdatedAt: now}
	if err := repository.SaveJob(ctx, succeeded); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(time.Minute) }
	if err := service.ReconcileInterruptedJobs(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, err := repository.ListJobs(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.ID == succeeded.ID {
			if job.State != domain.JobSucceeded {
				t.Fatalf("terminal job was changed: %#v", job)
			}
			continue
		}
		if job.State != domain.JobFailed || job.FinishedAt == nil || job.RetryAt != nil || !strings.Contains(job.Error, "interrupted") {
			t.Fatalf("abandoned job was not reconciled: %#v", job)
		}
	}
}

func TestTLSUpdateRejectsConcurrentChangeToRequestedField(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	baseline, err := service.TLSSettings(ctx, zone.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.tls.Mode = "flexible"
	fake.mu.Unlock()
	desired := baseline
	desired.Mode = "full"
	refreshed, err := service.UpdateTLSSettings(ctx, zone.ID, desired)
	if !errors.Is(err, ErrTLSConflict) || refreshed.Mode != "flexible" {
		t.Fatalf("TLS conflict result = %#v, %v", refreshed, err)
	}
	fake.mu.Lock()
	updateCalls := fake.tlsUpdateCalls
	fake.mu.Unlock()
	if updateCalls != 0 {
		t.Fatalf("provider update calls after conflict = %d", updateCalls)
	}
	cached, err := repository.GetTLSSettings(ctx, zone.ID)
	if err != nil || cached.Mode != "flexible" {
		t.Fatalf("refreshed TLS cache = %#v, %v", cached, err)
	}
}

func TestTLSUpdatePersistsAndAuditsPartialProviderState(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	baseline, err := service.TLSSettings(ctx, zone.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	desired := baseline
	desired.Mode = "full"
	desired.MinimumTLS = "1.3"
	partial := baseline
	partial.ZoneID = zone.ProviderID
	partial.Mode = "full"
	fake.mu.Lock()
	fake.tlsPartial = &partial
	fake.tlsUpdateErr = errors.New("connection lost during TLS update")
	fake.mu.Unlock()

	effective, err := service.UpdateTLSSettings(ctx, zone.ID, desired)
	if !errors.Is(err, ErrTLSMutationOutcomeUnknown) || effective.Mode != "full" || effective.MinimumTLS != "1.2" {
		t.Fatalf("partial TLS result = %#v, %v", effective, err)
	}
	cached, cacheErr := repository.GetTLSSettings(ctx, zone.ID)
	if cacheErr != nil || cached.Mode != effective.Mode || cached.MinimumTLS != effective.MinimumTLS {
		t.Fatalf("partial TLS cache = %#v, %v", cached, cacheErr)
	}
	audit, auditErr := repository.ListAudit(ctx, 20)
	if auditErr != nil {
		t.Fatal(auditErr)
	}
	found := false
	for _, event := range audit {
		found = found || event.Action == "tls.update.partial"
	}
	if !found {
		t.Fatalf("partial TLS audit missing: %#v", audit)
	}
}

func TestTLSUpdatePreflightFailureIsNotReportedAsAmbiguousMutation(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, _, zone := newBatchTestService(t, fake)
	baseline, err := service.TLSSettings(ctx, zone.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	desired := baseline
	desired.Mode = "full"
	fake.mu.Lock()
	fake.tlsUpdateErr = notAttemptedMutationError{message: "preflight read failed"}
	fake.tlsReadErrAfterUpdate = errors.New("provider still unavailable during refresh")
	fake.mu.Unlock()
	effective, err := service.UpdateTLSSettings(ctx, zone.ID, desired)
	if err == nil || errors.Is(err, ErrTLSMutationOutcomeUnknown) || effective.Mode != baseline.Mode {
		t.Fatalf("preflight TLS result = %#v, %v", effective, err)
	}
}

func TestEdgeCertificateInventoryPaginates(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, _, zone := newBatchTestService(t, fake)
	certificates := make([]domain.EdgeCertificate, 51)
	for index := range certificates {
		certificates[index] = domain.EdgeCertificate{ID: fmt.Sprintf("edge-%02d", index)}
	}
	fake.mu.Lock()
	fake.edgeCertificates = certificates
	fake.mu.Unlock()
	loaded, err := service.EdgeCertificates(ctx, zone.ID)
	if err != nil || len(loaded) != len(certificates) {
		t.Fatalf("paginated edge certificates = %d, %v", len(loaded), err)
	}
	for _, certificate := range loaded {
		if certificate.ZoneID != zone.ID {
			t.Fatalf("edge certificate zone = %q, want %q", certificate.ZoneID, zone.ID)
		}
	}
}

func TestPrepareRecordExpandsMultiLabelRelativeOwner(t *testing.T) {
	t.Parallel()
	zone := domain.Zone{ID: "zone", Name: "example.com"}
	record, err := prepareRecord(zone, domain.DNSRecord{Type: domain.RecordSRV, Name: "_https._tcp", Content: "10 5 443 target.example.com", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if record.Name != "_https._tcp.example.com" {
		t.Fatalf("relative SRV owner = %q", record.Name)
	}
	if _, err := prepareRecord(zone, domain.DNSRecord{Type: domain.RecordA, Name: "outside.test.", TTL: 300}); err == nil {
		t.Fatal("absolute out-of-zone owner was accepted")
	}
}

func TestPrepareRecordRejectsUnsafeValues(t *testing.T) {
	t.Parallel()
	zone := domain.Zone{ID: "zone", Name: "example.com"}
	for name, record := range map[string]domain.DNSRecord{
		"invalid IPv4": {Type: domain.RecordA, Name: "www", Content: "999.1.1.1", TTL: 300},
		"proxied TXT":  {Type: domain.RecordTXT, Name: "txt", Content: "value", TTL: 300, Proxied: true},
		"MX priority":  {Type: domain.RecordMX, Name: "@", Content: "mail.example.com", TTL: 300},
		"invalid SRV":  {Type: domain.RecordSRV, Name: "_https._tcp", Content: "not-an-srv", TTL: 300},
	} {
		if _, err := prepareRecord(zone, record); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := prepareRecord(zone, domain.DNSRecord{Type: domain.RecordSRV, Name: "_zero._tcp", Content: "0 0 0 .", TTL: 300}); err != nil {
		t.Fatalf("valid SRV port zero was rejected: %v", err)
	}
}

func TestDNSBatchPreviewAndApplyReconcilesZone(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.records["old-provider"] = domain.DNSRecord{
		ID: "old-provider", ProviderID: "old-provider", ZoneID: "zone-provider",
		Type: domain.RecordTXT, Name: "old.example.com", Content: "remove-me", TTL: 300,
	}
	service, repository, zone := newBatchTestService(t, fake)
	records, err := service.DNSRecords(ctx, zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	var apex, old domain.DNSRecord
	for _, record := range records {
		switch record.ProviderID {
		case "record-provider":
			apex = record
		case "old-provider":
			old = record
		}
	}
	if apex.ID == "" || old.ID == "" {
		t.Fatalf("batch fixtures missing: %#v", records)
	}
	patched := cloneDNSRecord(apex)
	patched.Content = "192.0.2.44"
	mutations := []domain.DNSMutation{
		{Kind: domain.MutationCreate, After: &domain.DNSRecord{Type: domain.RecordA, Name: "www", Content: "192.0.2.20", TTL: 300, Proxied: true}},
		{Kind: domain.MutationPatch, RecordID: apex.ID, After: &patched},
		{Kind: domain.MutationDelete, RecordID: old.ID},
	}

	plan, err := service.PlanDNSBatch(ctx, zone.ID, mutations)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ZoneID != zone.ID || plan.ZoneName != zone.Name || len(plan.Mutations) != 3 {
		t.Fatalf("plan = %#v", plan)
	}
	if got := plan.Mutations[0].After.Name; got != "www.example.com" {
		t.Fatalf("normalized create owner = %q", got)
	}
	if plan.Mutations[1].RecordID != "record-provider" || plan.Mutations[1].Before == nil || plan.Mutations[1].Before.ID != apex.ID {
		t.Fatalf("planned patch = %#v", plan.Mutations[1])
	}
	fake.mu.Lock()
	if fake.batchCalls != 0 || fake.records["record-provider"].Content != "192.0.2.1" || len(fake.getCalls) != 2 {
		fake.mu.Unlock()
		t.Fatalf("preview mutated provider: calls=%d gets=%v records=%#v", fake.batchCalls, fake.getCalls, fake.records)
	}
	fake.mu.Unlock()
	previewCached, err := service.DNSRecords(ctx, zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(previewCached) != 2 || !containsRecordContent(previewCached, "example.com", "192.0.2.1") || !containsProviderRecord(previewCached, "old-provider") {
		t.Fatalf("preview changed cache: %#v", previewCached)
	}
	previewAudit, err := repository.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range previewAudit {
		if event.Action == "dns.batch" {
			t.Fatalf("preview wrote batch audit event: %#v", event)
		}
	}

	result, err := service.ApplyDNSBatch(ctx, zone.ID, mutations)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || len(result.Records) != 2 {
		t.Fatalf("batch result = %#v", result)
	}
	fake.mu.Lock()
	if fake.batchCalls != 1 || len(fake.lastBatch) != 3 || fake.lastBatch[1].RecordID != "record-provider" || len(fake.getCalls) != 4 {
		fake.mu.Unlock()
		t.Fatalf("provider batch = calls:%d mutations:%#v", fake.batchCalls, fake.lastBatch)
	}
	if fake.records["record-provider"].Content != "192.0.2.44" {
		fake.mu.Unlock()
		t.Fatalf("provider patch not applied: %#v", fake.records["record-provider"])
	}
	if _, exists := fake.records["old-provider"]; exists {
		fake.mu.Unlock()
		t.Fatal("provider delete not applied")
	}
	if fake.listCalls != 2 {
		fake.mu.Unlock()
		t.Fatalf("provider list calls = %d, want sync + reconciliation", fake.listCalls)
	}
	fake.mu.Unlock()

	cached, err := service.DNSRecords(ctx, zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 2 || containsProviderRecord(cached, "old-provider") || !containsRecordContent(cached, "www.example.com", "192.0.2.20") {
		t.Fatalf("reconciled cache = %#v", cached)
	}
	endpoints, err := repository.ListEndpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !containsEndpoint(endpoints, "www.example.com") {
		t.Fatalf("batch did not create default endpoint: %#v", endpoints)
	}
	audit, err := repository.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var batchEvents []domain.AuditEvent
	for _, event := range audit {
		if event.Action == "dns.batch" {
			batchEvents = append(batchEvents, event)
		}
	}
	if len(batchEvents) != 1 {
		t.Fatalf("batch audit events = %#v", batchEvents)
	}
	var audited []domain.DNSMutation
	if err := json.Unmarshal(batchEvents[0].After, &audited); err != nil {
		t.Fatalf("decode batch audit: %v", err)
	}
	if len(audited) != 3 || audited[1].After == nil || len(audited[1].After.Raw) != 0 {
		t.Fatalf("unredacted batch audit = %#v", audited)
	}
}

func TestDNSBatchPlanRejectsManagedConflictingAndDuplicateTargets(t *testing.T) {
	t.Run("fresh managed state", func(t *testing.T) {
		fake := newFakeCloudProvider()
		service, _, zone := newBatchTestService(t, fake)
		record := mustBatchRecord(t, service, zone.ID, "record-provider")
		fake.mu.Lock()
		remote := fake.records[record.ProviderID]
		remote.Managed = true
		fake.records[record.ProviderID] = remote
		fake.mu.Unlock()
		_, err := service.PlanDNSBatch(context.Background(), zone.ID, []domain.DNSMutation{{Kind: domain.MutationDelete, RecordID: record.ID}})
		if err == nil || !strings.Contains(err.Error(), "provider-managed") {
			t.Fatalf("managed batch error = %v", err)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.batchCalls != 0 {
			t.Fatal("unsafe managed batch reached provider mutation")
		}
	})

	t.Run("remote conflict", func(t *testing.T) {
		fake := newFakeCloudProvider()
		service, _, zone := newBatchTestService(t, fake)
		record := mustBatchRecord(t, service, zone.ID, "record-provider")
		fake.mu.Lock()
		remote := fake.records[record.ProviderID]
		remote.Content = "192.0.2.99"
		fake.records[record.ProviderID] = remote
		fake.mu.Unlock()
		_, err := service.PlanDNSBatch(context.Background(), zone.ID, []domain.DNSMutation{{Kind: domain.MutationDelete, RecordID: record.ID}})
		if !errors.Is(err, ErrDNSConflict) {
			t.Fatalf("conflicting batch error = %v", err)
		}
	})

	t.Run("duplicate target", func(t *testing.T) {
		fake := newFakeCloudProvider()
		service, _, zone := newBatchTestService(t, fake)
		record := mustBatchRecord(t, service, zone.ID, "record-provider")
		desired := cloneDNSRecord(record)
		desired.Content = "192.0.2.55"
		_, err := service.PlanDNSBatch(context.Background(), zone.ID, []domain.DNSMutation{
			{Kind: domain.MutationPatch, RecordID: record.ID, After: &desired},
			{Kind: domain.MutationDelete, RecordID: record.ProviderID},
		})
		if err == nil || !strings.Contains(err.Error(), "appears more than once") {
			t.Fatalf("duplicate batch error = %v", err)
		}
	})
}

func TestStructuredRecordContentEditDoesNotReuseStaleData(t *testing.T) {
	ctx := context.Background()
	oldData := json.RawMessage(`{"flags":0,"tag":"issue","value":"letsencrypt.org"}`)
	for _, batch := range []bool{false, true} {
		name := "patch"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			fake := newFakeCloudProvider()
			fake.records = map[string]domain.DNSRecord{"caa-provider": {
				ID: "caa-provider", ProviderID: "caa-provider", ZoneID: "zone-provider",
				Type: domain.RecordCAA, Name: "example.com", Content: `0 issue "letsencrypt.org"`, Data: oldData, TTL: 300,
			}}
			service, _, zone := newBatchTestService(t, fake)
			cached := mustBatchRecord(t, service, zone.ID, "caa-provider")
			desired := cloneDNSRecord(cached)
			desired.Content = `0 issue "digicert.com"`
			desired.Data = nil
			if batch {
				plan, err := service.PlanDNSBatch(ctx, zone.ID, []domain.DNSMutation{{Kind: domain.MutationPatch, RecordID: cached.ID, After: &desired}})
				if err != nil {
					t.Fatal(err)
				}
				if got := plan.Mutations[0].After; got == nil || got.Content != desired.Content || len(got.Data) != 0 {
					t.Fatalf("content-only structured batch retained stale Data: %#v", got)
				}
				return
			}
			updated, err := service.PatchDNSRecord(ctx, zone.ID, cached.ID, desired)
			if err != nil {
				t.Fatal(err)
			}
			if updated.Content != desired.Content || len(updated.Data) != 0 {
				t.Fatalf("content-only structured patch retained stale Data: %#v", updated)
			}
		})
	}
}

func TestDNSBatchReplaceCanClearCommentAndTags(t *testing.T) {
	fake := newFakeCloudProvider()
	remote := fake.records["record-provider"]
	remote.Comment = "legacy comment"
	remote.Tags = []string{"owner:legacy"}
	fake.records[remote.ProviderID] = remote
	service, _, zone := newBatchTestService(t, fake)
	cached := mustBatchRecord(t, service, zone.ID, remote.ProviderID)
	desired := cloneDNSRecord(cached)
	desired.Comment = ""
	desired.Tags = nil
	plan, err := service.PlanDNSBatch(context.Background(), zone.ID, []domain.DNSMutation{{Kind: domain.MutationReplace, RecordID: cached.ID, After: &desired}})
	if err != nil {
		t.Fatal(err)
	}
	after := plan.Mutations[0].After
	if after == nil || after.Comment != "" || after.Tags == nil || len(after.Tags) != 0 {
		t.Fatalf("replace did not preserve explicit clear semantics: %#v", after)
	}
}

func TestDNSBatchAmbiguousResponseReconcilesWithoutClaimingNotApplied(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.batchErr = errors.New("connection reset after request body")
	service, repository, zone := newBatchTestService(t, fake)
	mutation := domain.DNSMutation{Kind: domain.MutationCreate, After: &domain.DNSRecord{Type: domain.RecordA, Name: "ambiguous", Content: "192.0.2.77", TTL: 300}}
	result, err := service.ApplyDNSBatch(ctx, zone.ID, []domain.DNSMutation{mutation})
	if err == nil || !strings.Contains(err.Error(), "outcome is unknown") {
		t.Fatalf("ambiguous batch error = %v", err)
	}
	if result.Applied || !result.OutcomeUnknown || !containsRecordContent(result.Records, "ambiguous.example.com", "192.0.2.77") {
		t.Fatalf("ambiguous batch result = %#v", result)
	}
	cached, err := service.DNSRecords(ctx, zone.ID)
	if err != nil || !containsRecordContent(cached, "ambiguous.example.com", "192.0.2.77") {
		t.Fatalf("ambiguous batch cache was not reconciled: %#v, %v", cached, err)
	}
	audit, err := repository.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range audit {
		found = found || event.Action == "dns.batch.outcome_unknown"
	}
	if !found {
		t.Fatalf("ambiguous batch audit missing: %#v", audit)
	}
}

func TestDNSBatchDefinitiveRejectionIsNotReportedAsAmbiguous(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.batchErr = definitiveMutationError{message: "forbidden"}
	fake.batchRejectBeforeApply = true
	service, repository, zone := newBatchTestService(t, fake)
	mutation := domain.DNSMutation{Kind: domain.MutationCreate, After: &domain.DNSRecord{Type: domain.RecordA, Name: "rejected", Content: "192.0.2.78", TTL: 300}}
	result, err := service.ApplyDNSBatch(ctx, zone.ID, []domain.DNSMutation{mutation})
	if err == nil || result.Applied || result.OutcomeUnknown {
		t.Fatalf("definitive batch result = %#v, %v", result, err)
	}
	audit, err := repository.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range audit {
		if event.Action == "dns.batch.outcome_unknown" {
			t.Fatalf("definitive rejection wrote ambiguity audit: %#v", event)
		}
	}
}

func TestIndividualDNSMutationAmbiguityRefreshesCompleteZone(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		ctx := context.Background()
		fake := newFakeCloudProvider()
		service, repository, zone := newBatchTestService(t, fake)
		fake.createErr = errors.New("connection reset after create")

		_, err := service.CreateDNSRecord(ctx, zone.ID, domain.DNSRecord{
			Type: domain.RecordA, Name: "www", Content: "192.0.2.70", TTL: 300,
		})
		assertUnknownDNSMutation(t, err)
		cached, listErr := service.DNSRecords(ctx, zone.ID)
		if listErr != nil || !containsRecordContent(cached, "www.example.com", "192.0.2.70") {
			t.Fatalf("ambiguous create cache = %#v, %v", cached, listErr)
		}
		assertAuditAction(t, repository, "dns.create.outcome_unknown")
	})

	t.Run("patch", func(t *testing.T) {
		ctx := context.Background()
		fake := newFakeCloudProvider()
		service, repository, zone := newBatchTestService(t, fake)
		cached := mustBatchRecord(t, service, zone.ID, "record-provider")
		desired := cloneDNSRecord(cached)
		desired.Content = "192.0.2.71"
		fake.patchErr = errors.New("connection reset after patch")

		_, err := service.PatchDNSRecord(ctx, zone.ID, cached.ID, desired)
		assertUnknownDNSMutation(t, err)
		refreshed := mustBatchRecord(t, service, zone.ID, "record-provider")
		if refreshed.Content != desired.Content {
			t.Fatalf("ambiguous patch cache = %#v", refreshed)
		}
		assertAuditAction(t, repository, "dns.patch.outcome_unknown")
	})

	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		fake := newFakeCloudProvider()
		service, repository, zone := newBatchTestService(t, fake)
		cached := mustBatchRecord(t, service, zone.ID, "record-provider")
		fake.deleteErr = errors.New("connection reset after delete")

		err := service.DeleteDNSRecord(ctx, zone.ID, cached.ID)
		assertUnknownDNSMutation(t, err)
		refreshed, listErr := service.DNSRecords(ctx, zone.ID)
		if listErr != nil || containsProviderRecord(refreshed, "record-provider") {
			t.Fatalf("ambiguous delete cache = %#v, %v", refreshed, listErr)
		}
		assertAuditAction(t, repository, "dns.delete.outcome_unknown")
	})
}

func TestIndividualDNSDefinitiveRejectionDoesNotRefreshOrAuditUnknown(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	fake.createErr = definitiveMutationError{message: "forbidden"}
	fake.mutationRejectBeforeApply = true
	listCalls := fake.listCalls

	_, err := service.CreateDNSRecord(ctx, zone.ID, domain.DNSRecord{
		Type: domain.RecordA, Name: "rejected", Content: "192.0.2.72", TTL: 300,
	})
	if err == nil || errors.Is(err, ErrDNSMutationOutcomeUnknown) {
		t.Fatalf("definitive create error = %v", err)
	}
	if fake.listCalls != listCalls {
		t.Fatalf("definitive rejection triggered refresh: calls=%d want=%d", fake.listCalls, listCalls)
	}
	audit, auditErr := repository.ListAudit(ctx, 100)
	if auditErr != nil {
		t.Fatal(auditErr)
	}
	for _, event := range audit {
		if event.Action == "dns.create.outcome_unknown" {
			t.Fatalf("definitive rejection wrote ambiguity audit: %#v", event)
		}
	}
}

func TestIndividualDNSProviderSuccessReportsLocalReconciliationFailure(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	reconcileErr := errors.New("injected cache replacement failure")
	service.repo = &failingDNSReconcileRepository{Repository: repository, err: reconcileErr}

	created, err := service.CreateDNSRecord(ctx, zone.ID, domain.DNSRecord{
		Type: domain.RecordA, Name: "applied", Content: "192.0.2.73", TTL: 300,
	})
	if created.ProviderID == "" || !errors.Is(err, ErrDNSMutationAppliedButUnreconciled) || !errors.Is(err, reconcileErr) {
		t.Fatalf("applied create result = %#v, %v", created, err)
	}
	if errors.Is(err, ErrDNSMutationOutcomeUnknown) {
		t.Fatalf("provider-confirmed create reported ambiguous: %v", err)
	}
	fake.mu.Lock()
	remote, exists := fake.records[created.ProviderID]
	fake.mu.Unlock()
	if !exists || remote.Content != created.Content {
		t.Fatalf("provider-confirmed create was not retained remotely: %#v", remote)
	}
}

func TestIndividualDNSCRUDReconcilesGeneratedEndpointAndClearsIssues(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	created, err := service.CreateDNSRecord(ctx, zone.ID, domain.DNSRecord{
		Type: domain.RecordA, Name: "www", Content: "192.0.2.74", TTL: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpointID := stableID("endpoint", zone.ID, "www."+zone.Name, "443")
	endpoint := mustEndpoint(t, repository, endpointID)
	if !endpoint.Enabled {
		t.Fatalf("created www endpoint is disabled: %#v", endpoint)
	}
	issue := domain.HealthIssue{
		ID: "stale-www-issue", Severity: domain.SeverityCritical, Kind: "tls",
		ResourceID: endpointID, Title: "stale", Detail: "stale", ObservedAt: time.Now().UTC(),
	}
	if err := repository.SaveHealthIssues(ctx, endpointID, []domain.HealthIssue{issue}); err != nil {
		t.Fatal(err)
	}

	if err := service.DeleteDNSRecord(ctx, zone.ID, created.ID); err != nil {
		t.Fatal(err)
	}
	endpoint = mustEndpoint(t, repository, endpointID)
	if endpoint.Enabled {
		t.Fatalf("deleted www endpoint remained enabled: %#v", endpoint)
	}
	issues, err := repository.ListHealthIssues(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, persisted := range issues {
		if persisted.ResourceID == endpointID || persisted.ID == issue.ID {
			t.Fatalf("disabled endpoint retained health issue: %#v", persisted)
		}
	}
}

func TestWriteCapabilityIsObservedOnlyAfterSuccessfulMutation(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.readOnlyVerification = true
	service, repository, zone := newBatchTestService(t, fake)
	credentials, err := service.Credentials(ctx)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credentials = %#v, %v", credentials, err)
	}
	credential := credentials[0]
	if slices.Contains(credential.Capabilities, "dns:write") {
		t.Fatalf("read probe manufactured DNS write: %#v", credential.Capabilities)
	}
	if _, err := service.SetZonePreferredCredential(ctx, zone.ID, credential.ID); err != nil {
		t.Fatalf("read-verified credential could not be explicitly routed: %v", err)
	}
	if _, err := service.CreateDNSRecord(ctx, zone.ID, domain.DNSRecord{Type: domain.RecordA, Name: "observe", Content: "192.0.2.88", TTL: 300}); err != nil {
		t.Fatal(err)
	}
	credential, err = repository.GetCredential(ctx, credential.ID)
	if err != nil || !slices.Contains(credential.Capabilities, "dns:write") {
		t.Fatalf("successful write was not observed: %#v, %v", credential, err)
	}
	zoneObserved, err := repository.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:write")
	if err != nil || !zoneObserved {
		t.Fatalf("successful write was not scoped to its zone: observed=%v err=%v", zoneObserved, err)
	}
	otherZone := zone
	otherZone.ID, otherZone.ProviderID, otherZone.Name = "cfzone_other", "other-provider", "other.example"
	if err := repository.SaveZones(ctx, []domain.Zone{otherZone}); err != nil {
		t.Fatal(err)
	}
	otherObserved, err := repository.HasCredentialZoneCapability(ctx, credential.ID, otherZone.ID, "dns:write")
	if err != nil || otherObserved {
		t.Fatalf("zone write evidence leaked to another zone: observed=%v err=%v", otherObserved, err)
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err != nil {
		t.Fatal(err)
	}
	credential, err = repository.GetCredential(ctx, credential.ID)
	if err != nil || !slices.Contains(credential.Capabilities, "dns:write") {
		t.Fatalf("successful write observation was lost on read verification: %#v, %v", credential, err)
	}
}

func TestSyncCredentialPreservesValidStatusOnTransientVerificationFailure(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	credential, err := repository.GetCredential(ctx, zone.PreferredCredentialID)
	if err != nil {
		t.Fatal(err)
	}
	lastVerified := credential.LastVerifiedAt

	fake.verifyErr = errors.New("temporary network failure")
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("transient verification unexpectedly succeeded")
	}
	preserved, err := repository.GetCredential(ctx, credential.ID)
	if err != nil || preserved.Status != domain.CredentialValid || !strings.Contains(preserved.LastError, "temporary network") ||
		lastVerified == nil || preserved.LastVerifiedAt == nil || !preserved.LastVerifiedAt.Equal(*lastVerified) {
		t.Fatalf("credential after transient failure = %#v, %v", preserved, err)
	}

	preserved.Status = domain.CredentialInvalid
	if err := repository.SaveCredential(ctx, preserved); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("second transient verification unexpectedly succeeded")
	}
	unknown, err := repository.GetCredential(ctx, credential.ID)
	if err != nil || unknown.Status != domain.CredentialUnknown {
		t.Fatalf("previously invalid credential after ambiguous verification = %#v, %v", unknown, err)
	}
	if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.example.com."); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("unknown credential remained routable: %v", err)
	}

	fake.verifyErr = authoritativeCredentialError{"token rejected"}
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("authoritative verification unexpectedly succeeded")
	}
	invalid, err := repository.GetCredential(ctx, credential.ID)
	if err != nil || invalid.Status != domain.CredentialInvalid {
		t.Fatalf("credential after authoritative rejection = %#v, %v", invalid, err)
	}

	fake.verifyErr = nil
	fake.verificationStatus = domain.CredentialInvalid
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("inactive verification error = %v", err)
	}
	inactive, err := repository.GetCredential(ctx, credential.ID)
	if err != nil || inactive.Status != domain.CredentialInvalid {
		t.Fatalf("inactive credential state = %#v, %v", inactive, err)
	}
}

func TestZoneReadOnlyCredentialDoesNotRouteZoneWithoutDNSReadProof(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.zoneReadOnlyVerification = true
	fake.dnsReadDenied = map[string]map[string]bool{"zone-only-token": {"zone-provider": true}}
	service, repository := newUnsyncedProviderService(t, fake)
	credential, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Zone only", Token: "zone-only-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	job, err := service.SyncCredential(ctx, credential.ID)
	if err == nil || job.State != domain.JobFailed || !strings.Contains(err.Error(), "denies DNS read") {
		t.Fatalf("zone-only sync = %#v, %v", job, err)
	}
	zones, err := repository.ListZones(ctx)
	if err != nil || len(zones) != 1 || zones[0].PreferredCredentialID != "" {
		t.Fatalf("zone-only routing = %#v, %v", zones, err)
	}
	observed, err := repository.HasCredentialZoneCapability(ctx, credential.ID, zones[0].ID, "dns:read")
	if err != nil || observed {
		t.Fatalf("denied zone DNS-read evidence = %v, %v", observed, err)
	}
	if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.example.com."); err == nil || !strings.Contains(err.Error(), "no preferred DNS credential") {
		t.Fatalf("unrouted DNS-01 resolution = %v", err)
	}
	// Even if stale metadata is manually pointed at this token, DNS and ACME
	// routes require the missing per-zone read observation.
	zones[0].PreferredCredentialID = credential.ID
	if err := repository.SaveZones(ctx, zones); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.example.com."); err == nil || !strings.Contains(err.Error(), "no observed DNS-read") {
		t.Fatalf("DNS-01 ignored missing zone evidence: %v", err)
	}
	if _, err := service.CreateDNSRecord(ctx, zones[0].ID, domain.DNSRecord{Type: domain.RecordA, Name: "blocked", Content: "192.0.2.8", TTL: 300}); err == nil || !strings.Contains(err.Error(), "no observed DNS-read") {
		t.Fatalf("DNS mutation ignored missing zone evidence: %v", err)
	}
}

func TestPolicyScopedDNSReadRoutesOnlyProvenZoneAndNeverFallsBackToParent(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.zones = []domain.Zone{
		{ID: "zone-parent", ProviderID: "zone-parent", Provider: domain.ProviderCloudflare, AccountID: "account-provider", Name: "example.com", Status: domain.ZoneActive},
		{ID: "zone-child", ProviderID: "zone-child", Provider: domain.ProviderCloudflare, AccountID: "account-provider", Name: "internal.example.com", Status: domain.ZoneActive},
	}
	fake.dnsReadDenied = map[string]map[string]bool{"policy-token": {"zone-child": true}}
	service, repository := newUnsyncedProviderService(t, fake)
	credential, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Policy scoped", Token: "policy-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("partially denied policy sync unexpectedly succeeded")
	}
	zones, err := repository.ListZones(ctx)
	if err != nil || len(zones) != 2 {
		t.Fatalf("policy zones = %#v, %v", zones, err)
	}
	byName := make(map[string]domain.Zone, len(zones))
	for _, zone := range zones {
		byName[zone.Name] = zone
	}
	parent, child := byName["example.com"], byName["internal.example.com"]
	if parent.PreferredCredentialID != credential.ID || child.PreferredCredentialID != "" {
		t.Fatalf("policy routing parent=%#v child=%#v", parent, child)
	}
	for _, check := range []struct {
		zone domain.Zone
		want bool
	}{{parent, true}, {child, false}} {
		observed, evidenceErr := repository.HasCredentialZoneCapability(ctx, credential.ID, check.zone.ID, "dns:read")
		if evidenceErr != nil || observed != check.want {
			t.Fatalf("DNS-read evidence for %s = %v, %v; want %v", check.zone.Name, observed, evidenceErr, check.want)
		}
	}
	if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.internal.example.com."); err == nil || !strings.Contains(err.Error(), "internal.example.com") {
		t.Fatalf("nested denied zone fell back to parent: %v", err)
	}
	if _, err := service.SetZonePreferredCredential(ctx, child.ID, credential.ID); err == nil || !strings.Contains(err.Error(), "DNS-read") {
		t.Fatalf("denied policy credential became preferred: %v", err)
	}
}

func TestSyncInvalidatesOnlyAuthoritativelyDeniedZoneReadEvidence(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	credential, err := repository.GetCredential(ctx, zone.PreferredCredentialID)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := repository.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read")
	if err != nil || !observed {
		t.Fatalf("initial DNS-read evidence = %v, %v", observed, err)
	}

	fake.dnsReadErrors = map[string]map[string]error{
		"batch-token": {"zone-provider": authoritativeAccessError{"DNS access forbidden"}},
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("authoritatively denied sync unexpectedly succeeded")
	}
	deniedZone, err := repository.GetZone(ctx, zone.ID)
	if err != nil || deniedZone.PreferredCredentialID != "" {
		t.Fatalf("denied zone routing = %#v, %v", deniedZone, err)
	}
	observed, err = repository.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read")
	if err != nil || observed {
		t.Fatalf("denied DNS-read evidence remained = %v, %v", observed, err)
	}
	if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.example.com."); err == nil {
		t.Fatal("DNS-01 remained routable after authoritative access denial")
	}

	// Restore authority explicitly, then prove a transient failure preserves
	// both the route and its last successful per-zone observation.
	fake.dnsReadErrors = nil
	if _, err := service.SetZonePreferredCredential(ctx, zone.ID, credential.ID); err != nil {
		t.Fatal(err)
	}
	fake.dnsReadErrors = map[string]map[string]error{
		"batch-token": {"zone-provider": errors.New("temporary network timeout")},
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("transiently failed sync unexpectedly succeeded")
	}
	preservedZone, err := repository.GetZone(ctx, zone.ID)
	if err != nil || preservedZone.PreferredCredentialID != credential.ID {
		t.Fatalf("transient failure changed route = %#v, %v", preservedZone, err)
	}
	observed, err = repository.HasCredentialZoneCapability(ctx, credential.ID, zone.ID, "dns:read")
	if err != nil || !observed {
		t.Fatalf("transient failure cleared DNS-read evidence = %v, %v", observed, err)
	}
}

func TestSetPreferredCredentialLiveProbePersistsZoneReadEvidence(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	candidate, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Unsynced candidate", Token: "candidate-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := repository.HasCredentialZoneCapability(ctx, candidate.ID, zone.ID, "dns:read")
	if err != nil || observed {
		t.Fatalf("candidate unexpectedly had zone evidence before probe: %v, %v", observed, err)
	}
	updated, err := service.SetZonePreferredCredential(ctx, zone.ID, candidate.ID)
	if err != nil || updated.PreferredCredentialID != candidate.ID {
		t.Fatalf("set preferred result = %#v, %v", updated, err)
	}
	observed, err = repository.HasCredentialZoneCapability(ctx, candidate.ID, zone.ID, "dns:read")
	if err != nil || !observed {
		t.Fatalf("live DNS probe evidence = %v, %v", observed, err)
	}
	candidate, err = repository.GetCredential(ctx, candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Provider = "different-provider"
	if err := repository.SaveCredential(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.example.com."); err == nil || !strings.Contains(err.Error(), "does not match zone provider") {
		t.Fatalf("provider-mismatched credential remained routable: %v", err)
	}
}

func TestCredentialDeleteKeepsMetadataWhenVaultDeleteFails(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, _ := newBatchTestService(t, fake)
	extra, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Disposable", Token: "disposable-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	originalSecrets := service.secrets
	failing := &failingDeleteSecretStore{SecretStore: originalSecrets, err: errors.New("vault fsync failed")}
	service.secrets = failing
	if err := service.DeleteCredential(ctx, extra.ID); err == nil || !strings.Contains(err.Error(), "remove credential secret") {
		t.Fatalf("vault deletion error = %v", err)
	}
	if _, err := repository.GetCredential(ctx, extra.ID); err != nil {
		t.Fatalf("credential metadata disappeared after vault failure: %v", err)
	}
	failing.err = nil
	if err := service.DeleteCredential(ctx, extra.ID); err != nil {
		t.Fatalf("credential deletion retry failed: %v", err)
	}
}

func TestCredentialAddCleansPossiblyCommittedSecret(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, _, _ := newBatchTestService(t, fake)
	store := &committedPutErrorSecretStore{SecretStore: service.secrets, err: errors.New("vault directory sync failed")}
	service.secrets = store
	_, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Uncertain", Token: "uncertain-token", Kind: domain.CredentialUserToken})
	if err == nil || !strings.Contains(err.Error(), "store Cloudflare credential") {
		t.Fatalf("committed secret write error = %v", err)
	}
	if store.reference == "" || store.deleted != store.reference {
		t.Fatalf("possibly committed secret was not compensated: ref=%q deleted=%q", store.reference, store.deleted)
	}
	if _, getErr := store.SecretStore.Get(ctx, store.reference); !errors.Is(getErr, secrets.ErrSecretNotFound) {
		t.Fatalf("compensated credential secret remains readable: %v", getErr)
	}
}

func TestSyncRetiresZonePreferenceWhenCredentialLosesAccess(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	credential, err := repository.GetCredential(ctx, zone.PreferredCredentialID)
	if err != nil {
		t.Fatal(err)
	}
	fake.hiddenTokens = map[string]bool{"batch-token": true}
	if _, err := service.SyncCredential(ctx, credential.ID); err != nil {
		t.Fatal(err)
	}
	retired, err := repository.GetZone(ctx, zone.ID)
	if err != nil || retired.PreferredCredentialID != "" || retired.Status != domain.ZoneUnknown {
		t.Fatalf("retired zone = %#v, %v", retired, err)
	}
	if err := service.DeleteCredential(ctx, credential.ID); err != nil {
		t.Fatalf("stale zone preference blocked credential removal: %v", err)
	}
}

func TestOverlappingSyncNeverRetiresVisibleZoneOrSilentlySwitchesPreference(t *testing.T) {
	for _, order := range []string{"replacement-first", "preferred-first"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			fake := newFakeCloudProvider()
			service, repository, zone := newBatchTestService(t, fake)
			preferredID := zone.PreferredCredentialID
			replacement, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Replacement", Token: "replacement-token", Kind: domain.CredentialUserToken})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.SyncCredential(ctx, replacement.ID); err != nil {
				t.Fatal(err)
			}
			fake.hiddenTokens = map[string]bool{"batch-token": true}
			if order == "replacement-first" {
				_, err = service.SyncCredential(ctx, replacement.ID)
				if err == nil {
					_, err = service.SyncCredential(ctx, preferredID)
				}
			} else {
				_, err = service.SyncCredential(ctx, preferredID)
				if err == nil {
					_, err = service.SyncCredential(ctx, replacement.ID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			visible, err := repository.GetZone(ctx, zone.ID)
			if err != nil {
				t.Fatal(err)
			}
			if visible.Status != domain.ZoneActive || visible.PreferredCredentialID != "" {
				t.Fatalf("visible zone after %s = %#v", order, visible)
			}
			if _, _, err := service.ResolveDNS01(ctx, "_acme-challenge.example.com."); err == nil {
				t.Fatalf("empty routing silently switched after %s: %v", order, err)
			}
		})
	}
}

func TestCredentialRemovalRejectsExpiredZoneWriteEvidence(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	first := zone.PreferredCredentialID
	second, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Replacement", Token: "replacement-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SyncCredential(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-replacementWriteEvidenceMaxAge - time.Minute)
	if err := repository.SaveCredentialZoneCapability(ctx, second.ID, zone.ID, "dns:write", old); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteCredential(ctx, first); err == nil || !strings.Contains(err.Error(), "recent observed DNS-write access") {
		t.Fatalf("expired write evidence allowed reassignment: %v", err)
	}
}

func TestCredentialRemovalRejectsReplacementWithDeniedLiveDNSRead(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	service, repository, zone := newBatchTestService(t, fake)
	first := zone.PreferredCredentialID
	replacement, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Replacement", Token: "replacement-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SyncCredential(ctx, replacement.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveCredentialZoneCapability(ctx, replacement.ID, zone.ID, "dns:write", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	fake.dnsReadErrors = map[string]map[string]error{
		"replacement-token": {"zone-provider": authoritativeAccessError{"DNS access forbidden"}},
	}
	if err := service.DeleteCredential(ctx, first); err == nil || !strings.Contains(err.Error(), "current DNS-read access") {
		t.Fatalf("denied-read replacement allowed credential removal: %v", err)
	}
	retained, err := repository.GetCredential(ctx, first)
	if err != nil || retained.ID != first {
		t.Fatalf("current credential was removed despite unsafe replacement: %#v, %v", retained, err)
	}
	routed, err := repository.GetZone(ctx, zone.ID)
	if err != nil || routed.PreferredCredentialID != first {
		t.Fatalf("unsafe replacement changed routing: %#v, %v", routed, err)
	}
	readObserved, err := repository.HasCredentialZoneCapability(ctx, replacement.ID, zone.ID, "dns:read")
	if err != nil || readObserved {
		t.Fatalf("authoritatively denied replacement retained DNS-read evidence: %v, %v", readObserved, err)
	}
	writeObserved, err := repository.HasCredentialZoneCapability(ctx, replacement.ID, zone.ID, "dns:write")
	if err != nil || !writeObserved {
		t.Fatalf("DNS-read invalidation changed write history: %v, %v", writeObserved, err)
	}
}

func TestListAllZonesDoesNotRepeatFinalCursorPage(t *testing.T) {
	t.Parallel()
	provider := &paginatedZoneProvider{}
	zones, err := listAllZones(context.Background(), provider, providerAuth())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := zoneIDs(zones), []string{"zone-1", "zone-2", "zone-3"}; !slices.Equal(got, want) {
		t.Fatalf("zone IDs = %v, want %v", got, want)
	}
	if got, want := provider.requests, []providerRequest{{Page: 1}, {Page: 1, Cursor: "2"}, {Page: 2, Cursor: "3"}}; !slices.Equal(got, want) {
		t.Fatalf("requests = %#v, want %#v", got, want)
	}
}

func TestListAllRecordsDoesNotRepeatFinalCursorPage(t *testing.T) {
	t.Parallel()
	provider := &paginatedRecordProvider{}
	records, err := listAllRecords(context.Background(), provider, providerAuth(), "zone")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordIDs(records), []string{"record-1", "record-2", "record-3"}; !slices.Equal(got, want) {
		t.Fatalf("record IDs = %v, want %v", got, want)
	}
	if got, want := provider.requests, []providerRequest{{Page: 1}, {Page: 1, Cursor: "2"}, {Page: 2, Cursor: "3"}}; !slices.Equal(got, want) {
		t.Fatalf("requests = %#v, want %#v", got, want)
	}
}

type providerRequest struct {
	Page   int
	Cursor string
}

type paginatedZoneProvider struct{ requests []providerRequest }

func (p *paginatedZoneProvider) ListZones(_ context.Context, _ provider.Auth, request provider.PageRequest) (provider.ZonePage, error) {
	p.requests = append(p.requests, providerRequest{Page: request.Page, Cursor: request.Cursor})
	page := requestedPage(request)
	result := provider.ZonePage{Page: page, TotalPages: 3, Zones: []domain.Zone{{ID: fmt.Sprintf("zone-%d", page)}}}
	if page < result.TotalPages {
		result.NextCursor = fmt.Sprintf("%d", page+1)
	}
	return result, nil
}

type paginatedRecordProvider struct{ requests []providerRequest }

func (p *paginatedRecordProvider) ListDNSRecords(_ context.Context, _ provider.Auth, _ string, request provider.PageRequest) (provider.RecordPage, error) {
	p.requests = append(p.requests, providerRequest{Page: request.Page, Cursor: request.Cursor})
	page := requestedPage(request)
	result := provider.RecordPage{Page: page, TotalPages: 3, Records: []domain.DNSRecord{{ID: fmt.Sprintf("record-%d", page)}}}
	if page < result.TotalPages {
		result.NextCursor = fmt.Sprintf("%d", page+1)
	}
	return result, nil
}

func requestedPage(request provider.PageRequest) int {
	if request.Cursor != "" {
		var page int
		_, _ = fmt.Sscanf(request.Cursor, "%d", &page)
		return page
	}
	return request.Page
}

func providerAuth() provider.Auth {
	return provider.Auth{Token: "test", Kind: domain.CredentialUserToken}
}

func zoneIDs(zones []domain.Zone) []string {
	result := make([]string, len(zones))
	for index := range zones {
		result[index] = zones[index].ID
	}
	return result
}

func recordIDs(records []domain.DNSRecord) []string {
	result := make([]string, len(records))
	for index := range records {
		result[index] = records[index].ID
	}
	return result
}

type fakeCloudProvider struct {
	mu                        sync.Mutex
	records                   map[string]domain.DNSRecord
	next                      int
	tls                       domain.EdgeTLSSettings
	batchCalls                int
	listCalls                 int
	getCalls                  []string
	lastBatch                 []domain.DNSMutation
	batchErr                  error
	batchRejectBeforeApply    bool
	createErr                 error
	patchErr                  error
	deleteErr                 error
	mutationRejectBeforeApply bool
	readOnlyVerification      bool
	zoneReadOnlyVerification  bool
	verifyErr                 error
	verificationStatus        domain.CredentialStatus
	hiddenTokens              map[string]bool
	zones                     []domain.Zone
	dnsReadDenied             map[string]map[string]bool
	dnsReadErrors             map[string]map[string]error
	tlsUpdateCalls            int
	tlsUpdateErr              error
	tlsReadErr                error
	tlsReadErrAfterUpdate     error
	tlsPartial                *domain.EdgeTLSSettings
	edgeCertificates          []domain.EdgeCertificate
}

func newFakeCloudProvider() *fakeCloudProvider {
	return &fakeCloudProvider{
		records: map[string]domain.DNSRecord{"record-provider": {ID: "record-provider", ProviderID: "record-provider", ZoneID: "zone-provider", Type: domain.RecordA, Name: "example.com", Content: "192.0.2.1", TTL: 1, Proxiable: true}},
		tls:     domain.EdgeTLSSettings{ZoneID: "zone-provider", Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true, HasProxiedDNS: true},
	}
}

func (f *fakeCloudProvider) VerifyCredential(_ context.Context, auth provider.Auth) (provider.Verification, error) {
	if f.verifyErr != nil {
		return provider.Verification{}, f.verifyErr
	}
	now := time.Now().UTC()
	capabilities := provider.Capabilities{ZoneRead: true, DNSRead: true, DNSWrite: true, TLSRead: true, TLSWrite: true, Names: []string{"dns:read", "dns:write", "tls:read", "tls:write", "zone:read"}}
	if f.readOnlyVerification {
		capabilities = provider.Capabilities{ZoneRead: true, DNSRead: true, TLSRead: true, Names: []string{"dns:read", "tls:read", "zone:read"}}
	}
	if f.zoneReadOnlyVerification {
		capabilities = provider.Capabilities{ZoneRead: true, Names: []string{"zone:read"}}
	}
	status := f.verificationStatus
	if status == "" {
		status = domain.CredentialValid
	}
	return provider.Verification{Status: status, Capabilities: capabilities, Accounts: []domain.RemoteAccount{{ID: "account-provider", ProviderID: "account-provider", Provider: domain.ProviderCloudflare, Name: "Example account", CreatedAt: now}}}, nil
}
func (f *fakeCloudProvider) ListZones(_ context.Context, auth provider.Auth, _ provider.PageRequest) (provider.ZonePage, error) {
	if f.hiddenTokens[auth.Token] {
		return provider.ZonePage{}, nil
	}
	if len(f.zones) > 0 {
		return provider.ZonePage{Zones: slices.Clone(f.zones)}, nil
	}
	return provider.ZonePage{Zones: []domain.Zone{{ID: "zone-provider", ProviderID: "zone-provider", Provider: domain.ProviderCloudflare, AccountID: "account-provider", Name: "example.com", Status: domain.ZoneActive}}}, nil
}
func (f *fakeCloudProvider) ListDNSRecords(_ context.Context, auth provider.Auth, zoneID string, _ provider.PageRequest) (provider.RecordPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.dnsReadDenied[auth.Token][zoneID] {
		return provider.RecordPage{}, errors.New("provider policy denies DNS read")
	}
	if err := f.dnsReadErrors[auth.Token][zoneID]; err != nil {
		return provider.RecordPage{}, err
	}
	values := make([]domain.DNSRecord, 0, len(f.records))
	for _, value := range f.records {
		values = append(values, value)
	}
	return provider.RecordPage{Records: values}, nil
}
func (f *fakeCloudProvider) GetDNSRecord(_ context.Context, _ provider.Auth, _, id string) (domain.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls = append(f.getCalls, id)
	return f.records[id], nil
}
func (f *fakeCloudProvider) CreateDNSRecord(_ context.Context, _ provider.Auth, zone string, record domain.DNSRecord) (domain.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil && f.mutationRejectBeforeApply {
		return domain.DNSRecord{}, f.createErr
	}
	f.next++
	record.ID = "created"
	record.ProviderID = "created"
	record.ZoneID = zone
	f.records[record.ProviderID] = record
	return record, f.createErr
}
func (f *fakeCloudProvider) PatchDNSRecord(_ context.Context, _ provider.Auth, zone, id string, record domain.DNSRecord) (domain.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.patchErr != nil && f.mutationRejectBeforeApply {
		return domain.DNSRecord{}, f.patchErr
	}
	record.ID, record.ProviderID, record.ZoneID = id, id, zone
	f.records[id] = record
	return record, f.patchErr
}
func (f *fakeCloudProvider) DeleteDNSRecord(_ context.Context, _ provider.Auth, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil && f.mutationRejectBeforeApply {
		return f.deleteErr
	}
	delete(f.records, id)
	return f.deleteErr
}
func (f *fakeCloudProvider) ApplyDNSBatch(_ context.Context, _ provider.Auth, zone string, mutations []domain.DNSMutation) ([]domain.DNSRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batchCalls++
	if f.batchErr != nil && f.batchRejectBeforeApply {
		return nil, f.batchErr
	}
	f.lastBatch = make([]domain.DNSMutation, len(mutations))
	for index, mutation := range mutations {
		copy := mutation
		if mutation.Before != nil {
			before := cloneDNSRecord(*mutation.Before)
			copy.Before = &before
		}
		if mutation.After != nil {
			after := cloneDNSRecord(*mutation.After)
			copy.After = &after
		}
		f.lastBatch[index] = copy
	}
	result := make([]domain.DNSRecord, 0, len(mutations))
	for _, mutation := range mutations {
		switch mutation.Kind {
		case domain.MutationCreate:
			f.next++
			record := cloneDNSRecord(*mutation.After)
			record.ID = fmt.Sprintf("batch-created-%d", f.next)
			record.ProviderID = record.ID
			record.ZoneID = zone
			f.records[record.ProviderID] = record
			result = append(result, record)
		case domain.MutationPatch, domain.MutationReplace:
			record := cloneDNSRecord(*mutation.After)
			record.ID, record.ProviderID, record.ZoneID = mutation.RecordID, mutation.RecordID, zone
			f.records[mutation.RecordID] = record
			result = append(result, record)
		case domain.MutationDelete:
			delete(f.records, mutation.RecordID)
		}
	}
	return result, f.batchErr
}
func (f *fakeCloudProvider) PresentDNS01(context.Context, provider.Auth, string, string, string, string) (string, error) {
	return "challenge", nil
}
func (f *fakeCloudProvider) CleanupDNS01(context.Context, provider.Auth, string, string) error {
	return nil
}
func (f *fakeCloudProvider) GetEdgeTLSSettings(context.Context, provider.Auth, string) (domain.EdgeTLSSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tls, f.tlsReadErr
}
func (f *fakeCloudProvider) UpdateEdgeTLSSettings(_ context.Context, _ provider.Auth, _ string, _ domain.EdgeTLSSettings, value domain.EdgeTLSSettings) (domain.EdgeTLSSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tlsUpdateCalls++
	if f.tlsReadErrAfterUpdate != nil {
		f.tlsReadErr = f.tlsReadErrAfterUpdate
	}
	if f.tlsPartial != nil {
		f.tls = *f.tlsPartial
	}
	if f.tlsUpdateErr != nil {
		return domain.EdgeTLSSettings{}, f.tlsUpdateErr
	}
	f.tls = value
	return value, nil
}
func (f *fakeCloudProvider) ListEdgeCertificates(_ context.Context, _ provider.Auth, _ string, request provider.PageRequest) ([]domain.EdgeCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	perPage := request.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	page := request.Page
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * perPage
	if start >= len(f.edgeCertificates) {
		return nil, nil
	}
	end := min(start+perPage, len(f.edgeCertificates))
	return slices.Clone(f.edgeCertificates[start:end]), nil
}

var _ provider.CloudProvider = (*fakeCloudProvider)(nil)

type failingDeleteSecretStore struct {
	store.SecretStore
	err error
}

type failingDNSReconcileRepository struct {
	store.Repository
	err error
}

func (r *failingDNSReconcileRepository) ReplaceDNSRecords(context.Context, string, []domain.DNSRecord, time.Time) error {
	return r.err
}

type committedPutErrorSecretStore struct {
	store.SecretStore
	err       error
	reference string
	deleted   string
}

func (s *committedPutErrorSecretStore) Put(ctx context.Context, reference string, value []byte) (string, error) {
	ref, err := s.SecretStore.Put(ctx, reference, value)
	if err != nil {
		return ref, err
	}
	s.reference = ref
	return ref, s.err
}

func (s *committedPutErrorSecretStore) Delete(ctx context.Context, reference string) error {
	s.deleted = reference
	return s.SecretStore.Delete(ctx, reference)
}

func (s *failingDeleteSecretStore) Delete(ctx context.Context, reference string) error {
	if s.err != nil {
		return s.err
	}
	return s.SecretStore.Delete(ctx, reference)
}

type definitiveMutationError struct{ message string }

func (e definitiveMutationError) Error() string                   { return e.message }
func (e definitiveMutationError) MutationOutcomeDefinitive() bool { return true }

type notAttemptedMutationError struct{ message string }

func (e notAttemptedMutationError) Error() string              { return e.message }
func (e notAttemptedMutationError) MutationNotAttempted() bool { return true }

type authoritativeCredentialError struct{ message string }

func (e authoritativeCredentialError) Error() string { return e.message }
func (e authoritativeCredentialError) CredentialVerificationAuthoritative() bool {
	return true
}

type authoritativeAccessError struct{ message string }

func (e authoritativeAccessError) Error() string                   { return e.message }
func (e authoritativeAccessError) AccessDenialAuthoritative() bool { return true }

func newUnsyncedProviderService(t *testing.T, fake *fakeCloudProvider) (*Service, *sqlitestore.Repository) {
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
	if err := vault.Unlock(ctx, []byte("long provider test password")); err != nil {
		t.Fatal(err)
	}
	service := New(repository, vault)
	service.RegisterProvider(domain.ProviderCloudflare, fake)
	return service, repository
}

func newBatchTestService(t *testing.T, fake *fakeCloudProvider) (*Service, *sqlitestore.Repository, domain.Zone) {
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
	if err := vault.Unlock(ctx, []byte("long batch integration password")); err != nil {
		t.Fatal(err)
	}
	service := New(repository, vault)
	service.RegisterProvider(domain.ProviderCloudflare, fake)
	credential, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Batch", Token: "batch-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err != nil {
		t.Fatal(err)
	}
	zones, err := service.Zones(ctx)
	if err != nil || len(zones) != 1 {
		t.Fatalf("batch zones = %#v, %v", zones, err)
	}
	return service, repository, zones[0]
}

func assertUnknownDNSMutation(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, ErrDNSMutationOutcomeUnknown) || !strings.Contains(err.Error(), "do not retry") {
		t.Fatalf("ambiguous DNS mutation error = %v", err)
	}
	if errors.Is(err, ErrDNSMutationAppliedButUnreconciled) {
		t.Fatalf("ambiguous DNS mutation was reported as confirmed: %v", err)
	}
}

func assertAuditAction(t *testing.T, repository store.Repository, action string) {
	t.Helper()
	audit, err := repository.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range audit {
		if event.Action == action {
			return
		}
	}
	t.Fatalf("audit action %q missing from %#v", action, audit)
}

func mustEndpoint(t *testing.T, repository store.Repository, endpointID string) domain.ObservedEndpoint {
	t.Helper()
	endpoints, err := repository.ListEndpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		if endpoint.ID == endpointID {
			return endpoint
		}
	}
	t.Fatalf("endpoint %q not found in %#v", endpointID, endpoints)
	return domain.ObservedEndpoint{}
}

func TestEnsureDefaultEndpointsDisablesOnlyObsoleteGeneratedEndpoints(t *testing.T) {
	ctx := context.Background()
	service, repository, zone := newBatchTestService(t, newFakeCloudProvider())
	apexID := stableID("endpoint", zone.ID, zone.Name, "443")
	wwwHost := "www." + zone.Name
	wwwID := stableID("endpoint", zone.ID, wwwHost, "443")
	service.ensureDefaultEndpoints(ctx, zone, []domain.DNSRecord{
		{Type: domain.RecordA, Name: zone.Name},
		{Type: domain.RecordCNAME, Name: wwwHost},
	})
	custom := domain.ObservedEndpoint{ID: "custom-www-endpoint", ZoneID: zone.ID, Host: wwwHost, Port: 8443, Enabled: true}
	if err := repository.SaveEndpoint(ctx, custom); err != nil {
		t.Fatal(err)
	}

	service.ensureDefaultEndpoints(ctx, zone, nil)
	endpoints, err := repository.ListEndpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]domain.ObservedEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		byID[endpoint.ID] = endpoint
	}
	if byID[apexID].Enabled || byID[wwwID].Enabled {
		t.Fatalf("obsolete generated endpoints remained enabled: apex=%#v www=%#v", byID[apexID], byID[wwwID])
	}
	if !byID[custom.ID].Enabled || byID[custom.ID].Port != custom.Port {
		t.Fatalf("custom endpoint was changed: %#v", byID[custom.ID])
	}
}

func TestEnsureDefaultEndpointsReusesEndpointForLongestNestedZoneOwner(t *testing.T) {
	ctx := context.Background()
	service, repository, parent := newBatchTestService(t, newFakeCloudProvider())
	host := "www." + parent.Name
	if err := service.ensureDefaultEndpoints(ctx, parent, []domain.DNSRecord{{Type: domain.RecordA, Name: host}}); err != nil {
		t.Fatal(err)
	}
	before := findEndpointByAddress(t, repository, host, 443)

	child := domain.Zone{
		ID: "cfzone_nested", Provider: parent.Provider, ProviderID: "nested",
		AccountID: parent.AccountID, PreferredCredentialID: parent.PreferredCredentialID,
		Name: host, Status: domain.ZoneActive,
	}
	if err := repository.SaveZones(ctx, []domain.Zone{child}); err != nil {
		t.Fatal(err)
	}
	if err := service.ensureDefaultEndpoints(ctx, child, []domain.DNSRecord{{Type: domain.RecordA, Name: host}}); err != nil {
		t.Fatal(err)
	}
	after := findEndpointByAddress(t, repository, host, 443)
	if after.ID != before.ID || after.ZoneID != child.ID || !after.Enabled {
		t.Fatalf("nested-zone endpoint was not retained/reassigned: before=%#v after=%#v", before, after)
	}
	// A later parent-zone sync must not steal or disable the child-owned host.
	if err := service.ensureDefaultEndpoints(ctx, parent, []domain.DNSRecord{{Type: domain.RecordA, Name: host}}); err != nil {
		t.Fatal(err)
	}
	stable := findEndpointByAddress(t, repository, host, 443)
	if stable.ID != before.ID || stable.ZoneID != child.ID || !stable.Enabled {
		t.Fatalf("parent sync stole nested endpoint: %#v", stable)
	}
	endpoints, err := repository.ListEndpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, endpoint := range endpoints {
		if endpointAddressKey(endpoint.Host, endpoint.Port) == endpointAddressKey(host, 443) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("host/port endpoint count = %d, want 1: %#v", count, endpoints)
	}
}

func mustBatchRecord(t *testing.T, service *Service, zoneID, providerID string) domain.DNSRecord {
	t.Helper()
	records, err := service.DNSRecords(context.Background(), zoneID)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.ProviderID == providerID {
			return record
		}
	}
	t.Fatalf("provider record %q not found in %#v", providerID, records)
	return domain.DNSRecord{}
}

func containsProviderRecord(records []domain.DNSRecord, providerID string) bool {
	for _, record := range records {
		if record.ProviderID == providerID {
			return true
		}
	}
	return false
}

func containsRecordContent(records []domain.DNSRecord, name, content string) bool {
	for _, record := range records {
		if record.Name == name && record.Content == content {
			return true
		}
	}
	return false
}

func containsEndpoint(endpoints []domain.ObservedEndpoint, host string) bool {
	for _, endpoint := range endpoints {
		if endpoint.Host == host {
			return true
		}
	}
	return false
}

func findEndpointByAddress(t *testing.T, repository store.Repository, host string, port int) domain.ObservedEndpoint {
	t.Helper()
	endpoints, err := repository.ListEndpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		if endpointAddressKey(endpoint.Host, endpoint.Port) == endpointAddressKey(host, port) {
			return endpoint
		}
	}
	t.Fatalf("endpoint %s:%d not found in %#v", host, port, endpoints)
	return domain.ObservedEndpoint{}
}
