package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func TestLetsEncryptCAAPreflightHonorsWildcardOverride(t *testing.T) {
	t.Parallel()
	records := []domain.DNSRecord{{
		Type: domain.RecordCAA, Name: "example.com",
		Data: mustJSON(t, map[string]any{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}),
	}, {
		Type: domain.RecordCAA, Name: "example.com",
		Data: mustJSON(t, map[string]any{"flags": 0, "tag": "issuewild", "value": "other-ca.example"}),
	}}
	err := validateLetsEncryptCAA("example.com", []string{"example.com", "*.example.com"}, records)
	if err == nil || !strings.Contains(err.Error(), "issuewild") {
		t.Fatalf("wildcard CAA error = %v", err)
	}
	records[1].Data = mustJSON(t, map[string]any{"flags": 0, "tag": "issuewild", "value": "letsencrypt.org; validationmethods=dns-01"})
	if err := validateLetsEncryptCAA("example.com", []string{"example.com", "*.example.com"}, records); err != nil {
		t.Fatal(err)
	}
}

func TestLetsEncryptCAAPreflightUsesClosestAncestorAndQuotedContent(t *testing.T) {
	t.Parallel()
	records := []domain.DNSRecord{
		{Type: domain.RecordCAA, Name: "example.com", Content: `0 issue "other-ca.example"`},
		{Type: domain.RecordCAA, Name: "api.example.com", Content: `0 issue "letsencrypt.org"`},
	}
	if err := validateLetsEncryptCAA("example.com", []string{"api.example.com", "*.api.example.com"}, records); err != nil {
		t.Fatal(err)
	}
	if err := validateLetsEncryptCAA("example.com", []string{"www.example.com"}, records); err == nil {
		t.Fatal("parent CAA denial was ignored")
	}
}

func TestLetsEncryptCAAPreflightHonorsDNS01MethodBinding(t *testing.T) {
	t.Parallel()
	record := domain.DNSRecord{
		Type: domain.RecordCAA, Name: "example.com",
		Content: `0 issue "letsencrypt.org; validationmethods=http-01,tls-alpn-01"`,
	}
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, []domain.DNSRecord{record}); err == nil || !strings.Contains(err.Error(), "validationmethods=dns-01") {
		t.Fatalf("non-DNS method binding error = %v", err)
	}
	record.Content = `0 issue "letsencrypt.org; validationmethods=http-01,dns-01"`
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, []domain.DNSRecord{record}); err != nil {
		t.Fatalf("DNS-01 method binding was rejected: %v", err)
	}
}

func TestLetsEncryptCAAPreflightRejectsUnknownCriticalProperty(t *testing.T) {
	t.Parallel()
	records := []domain.DNSRecord{
		{Type: domain.RecordCAA, Name: "example.com", Content: `0 issue "letsencrypt.org"`},
		{Type: domain.RecordCAA, Name: "example.com", Content: `128 futurepolicy "required"`},
	}
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, records); err == nil || !strings.Contains(err.Error(), "unknown issuer-critical tag") {
		t.Fatalf("unknown critical property error = %v", err)
	}
	records[1].Content = `0 futurepolicy "advisory"`
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, records); err != nil {
		t.Fatalf("noncritical unknown property was rejected: %v", err)
	}
	records[1].Content = `128 iodef "mailto:security@example.com"`
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, records); err != nil {
		t.Fatalf("known critical property was rejected: %v", err)
	}
}

func TestLetsEncryptCAAPreflightFailsClosedForUnverifiableAccountBinding(t *testing.T) {
	t.Parallel()
	bound := domain.DNSRecord{
		Type: domain.RecordCAA, Name: "example.com",
		Content: `0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123"`,
	}
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, []domain.DNSRecord{bound}); err == nil || !strings.Contains(err.Error(), "accounturi") {
		t.Fatalf("unverifiable account binding error = %v", err)
	}
	unrestricted := domain.DNSRecord{Type: domain.RecordCAA, Name: "example.com", Content: `0 issue "letsencrypt.org"`}
	if err := validateLetsEncryptCAA("example.com", []string{"example.com"}, []domain.DNSRecord{bound, unrestricted}); err != nil {
		t.Fatalf("unrestricted alternative did not authorize issuance: %v", err)
	}
}

func TestCertificatePreflightUsesExplicitZoneCredentialAndCachedCAA(t *testing.T) {
	ctx := context.Background()
	service, repository, zone := newBatchTestService(t, newFakeCloudProvider())
	plan, err := certificates.NewWildcardPlan(zone.ID, zone.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CertificatePreflight(ctx, plan); err != nil {
		t.Fatal(err)
	}
	records, err := service.DNSRecords(ctx, zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, domain.DNSRecord{ID: "cfrecord_caa", ProviderID: "caa", ZoneID: zone.ID, Type: domain.RecordCAA, Name: zone.Name, Content: `0 issue "other-ca.example"`, TTL: 300})
	if err := repository.ReplaceDNSRecords(ctx, zone.ID, records, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := service.CertificatePreflight(ctx, plan); err == nil || !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("CAA denial preflight error = %v", err)
	}
}

func TestCertificatePreflightUsesPerZoneDNSReadWhenGlobalFirstZoneProbeWasDenied(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCloudProvider()
	fake.zoneReadOnlyVerification = true // no credential-global dns:read claim
	fake.zones = []domain.Zone{
		{ID: "zone-denied", ProviderID: "zone-denied", Provider: domain.ProviderCloudflare, AccountID: "account-provider", Name: "denied.example", Status: domain.ZoneActive},
		{ID: "zone-allowed", ProviderID: "zone-allowed", Provider: domain.ProviderCloudflare, AccountID: "account-provider", Name: "allowed.example", Status: domain.ZoneActive},
	}
	fake.dnsReadDenied = map[string]map[string]bool{"scoped-token": {"zone-denied": true}}
	service, repository := newUnsyncedProviderService(t, fake)
	credential, err := service.AddCloudflareCredential(ctx, AddCredentialInput{Label: "Scoped", Token: "scoped-token", Kind: domain.CredentialUserToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SyncCredential(ctx, credential.ID); err == nil {
		t.Fatal("partially denied fixture sync unexpectedly succeeded")
	}
	zones, err := repository.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var allowed domain.Zone
	for _, zone := range zones {
		if zone.Name == "allowed.example" {
			allowed = zone
		}
	}
	if allowed.ID == "" || allowed.PreferredCredentialID != credential.ID {
		t.Fatalf("allowed zone routing = %#v", allowed)
	}
	plan, err := certificates.NewWildcardPlan(allowed.ID, allowed.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CertificatePreflight(ctx, plan); err != nil {
		t.Fatalf("per-zone-authorized certificate preflight failed: %v", err)
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
