package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/MeghdadFadaee/domainops/internal/app"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func TestModelRendersResponsiveOperationalViews(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{Version: "test"})
	now := time.Now().UTC()
	_, _ = model.Update(tea.WindowSizeMsg{Width: 132, Height: 38})
	_, _ = model.Update(loadMsg{
		dashboard:   domain.DashboardSnapshot{GeneratedAt: now, Accounts: 2, Zones: 60, DNSRecords: 420, Certificates: 12, CertificatesDue: 2, Issues: []domain.HealthIssue{{ID: "i", Severity: domain.SeverityWarning, Title: "Certificate differs", Detail: "public endpoint is stale"}}},
		credentials: []domain.Credential{{ID: "cred", Label: "Production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid}},
		accounts:    []domain.RemoteAccount{{ID: "account", Name: "Primary account"}},
		zones:       []domain.Zone{{ID: "zone", AccountID: "account", PreferredCredentialID: "cred", Name: "example.com", Status: domain.ZoneActive, Plan: "Pro"}},
		records:     []domain.DNSRecord{{ID: "record", ZoneID: "zone", Type: domain.RecordA, Name: "example.com", Content: "192.0.2.1", TTL: 1, Proxied: true}},
	})
	view := model.View().Content
	for _, expected := range []string{"DOMAINOPS", "Dashboard", "ACTION QUEUE", "Certificate differs", "60"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("dashboard does not contain %q", expected)
		}
	}

	model.screen = screenDNS
	view = model.View().Content
	for _, expected := range []string{"DNS · example.com", "192.0.2.1", "proxied"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("DNS view does not contain %q", expected)
		}
	}
	model.screen = screenZones
	view = model.View().Content
	for _, expected := range []string{"Primary account", "Production"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("zone ownership view does not contain %q", expected)
		}
	}

	_, _ = model.Update(tea.WindowSizeMsg{Width: 50, Height: 12})
	if view = model.View().Content; !strings.Contains(view, "terminal is too small") {
		t.Fatalf("small-terminal fallback missing: %q", view)
	}
}

func TestUndersizedTerminalRejectsAllHiddenInteractiveInput(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.width, model.height = 50, 12
	model.screen = screenDNS
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}
	model.activeDNSZoneID = "zone"
	model.records = []domain.DNSRecord{{ID: "record", ZoneID: "zone", Type: domain.RecordA, Name: "example.com"}}

	_, cmd := model.Update(tea.KeyPressMsg{Code: 'd', Text: "d"})
	if cmd != nil || model.confirmDelete {
		t.Fatalf("undersized view opened hidden delete confirmation: cmd=%v confirm=%v", cmd != nil, model.confirmDelete)
	}

	// A modal that became hidden after a resize must not accept confirmation input.
	model.confirmDelete = true
	_, cmd = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || backend.deleteCalls != 0 || !model.confirmDelete {
		t.Fatalf("undersized hidden confirmation mutated state: cmd=%v calls=%d confirm=%v", cmd != nil, backend.deleteCalls, model.confirmDelete)
	}

	locked := &fakeBackend{locked: true}
	unlockModel := New(locked, Options{})
	unlockModel.width, unlockModel.height = 40, 10
	unlockModel.unlockInputs[0].SetValue("secret")
	_, cmd = unlockModel.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || locked.unlockCalls != 0 || !unlockModel.unlock {
		t.Fatalf("undersized hidden unlock accepted input: cmd=%v calls=%d unlock=%v", cmd != nil, locked.unlockCalls, unlockModel.unlock)
	}
}

func TestRecordFormBuildsStructuredCAAAndSRVData(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}

	model.openRecordForm(false)
	model.recordInputs[0].SetValue("CAA")
	model.recordInputs[1].SetValue("@")
	model.recordInputs[2].SetValue("0 issue letsencrypt.org")
	model.recordInputs[3].SetValue("300")
	record, err := model.recordFromForm()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(record.Data), `"tag":"issue"`) || !strings.Contains(string(record.Data), `"value":"letsencrypt.org"`) {
		t.Fatalf("CAA data = %s", record.Data)
	}
	model.recordInputs[2].SetValue(`0 issue "letsencrypt.org"`)
	record, err = model.recordFromForm()
	if err != nil || !strings.Contains(string(record.Data), `"value":"letsencrypt.org"`) || strings.Contains(string(record.Data), `\\"letsencrypt.org\\"`) {
		t.Fatalf("quoted CAA value was not normalized: data=%s err=%v", record.Data, err)
	}

	model.recordInputs[0].SetValue("SRV")
	model.recordInputs[1].SetValue("_https._tcp")
	model.recordInputs[2].SetValue("10 5 443 target.example.com")
	record, err = model.recordFromForm()
	if err != nil {
		t.Fatal(err)
	}
	if record.Priority == nil || *record.Priority != 10 || !strings.Contains(string(record.Data), `"port":443`) {
		t.Fatalf("SRV record = %#v data=%s", record, record.Data)
	}
	model.recordInputs[2].SetValue("10 5 0 .")
	if _, err := model.recordFromForm(); err != nil {
		t.Fatalf("valid SRV port zero was rejected: %v", err)
	}
	model.records = []domain.DNSRecord{{
		ID: "srv", ZoneID: "zone", Type: domain.RecordSRV, Name: "_https._tcp.example.com",
		Priority: record.Priority, TTL: 300, Data: record.Data,
	}}
	model.openRecordForm(true)
	if got := model.recordInputs[2].Value(); got != "10 5 443 target.example.com" {
		t.Fatalf("structured SRV edit value = %q", got)
	}
}

func TestCertificateSelectionClampsAfterFiltering(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.screen = screenCertificates
	model.lineages = []domain.CertificateLineage{{ID: "first", Name: "first.example"}, {ID: "second", Name: "second.example"}}
	model.rowOffset = 1
	model.searchInput.SetValue("first")
	model.clampSelection()
	if model.rowOffset != 0 {
		t.Fatalf("filtered certificate selection = %d, want 0", model.rowOffset)
	}
	model.openCertificateForm("export")
	if model.certificateAction != "export" {
		t.Fatalf("certificate action = %q", model.certificateAction)
	}
}

func TestRecordFormOpensReviewBeforeMutation(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.screen = screenDNS
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}
	model.activeDNSZoneID = "zone"
	model.openRecordForm(false)
	model.recordInputs[0].SetValue("A")
	model.recordInputs[1].SetValue("www")
	model.recordInputs[2].SetValue("192.0.2.10")
	model.recordInputs[3].SetValue("300")
	model.recordFocus = len(model.recordInputs) - 1

	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || !model.confirmRecord || model.busy || model.editRecord {
		t.Fatalf("record skipped review: cmd=%v confirm=%v busy=%v edit=%v", cmd != nil, model.confirmRecord, model.busy, model.editRecord)
	}
	if view := model.View().Content; !strings.Contains(view, "APPLY DNS CHANGE?") || !strings.Contains(view, "192.0.2.10") {
		t.Fatalf("record review is incomplete: %q", view)
	}
}

func TestDNSFilterKeepsActiveZoneAndUsesStructuredContent(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.screen = screenDNS
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}
	model.activeDNSZoneID = "zone"
	model.records = []domain.DNSRecord{{
		ID: "caa", ZoneID: "zone", Type: domain.RecordCAA, Name: "example.com", TTL: 300,
		Data: []byte(`{"flags":0,"tag":"issue","value":"letsencrypt.org"}`),
	}}
	model.searchInput.SetValue("letsencrypt")
	view := model.View().Content
	if !strings.Contains(view, "DNS · example.com") || !strings.Contains(view, "letsencrypt.org") {
		t.Fatalf("DNS filter lost active zone or structured content: %q", view)
	}
}

func TestFiltersCoverVisibleOperationalFields(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.accounts = []domain.RemoteAccount{{ID: "account", Name: "Customer Production"}}
	model.credentials = []domain.Credential{{ID: "credential", Label: "Write Token", Kind: domain.CredentialAccountToken, Capabilities: []string{"dns:write"}}}
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com", AccountID: "account", PreferredCredentialID: "credential", Plan: "Business"}}
	model.searchInput.SetValue("customer production")
	if len(model.filteredZones()) != 1 {
		t.Fatal("zone filter ignored visible account name")
	}
	model.searchInput.SetValue("dns:write")
	if len(model.filteredCredentials()) != 1 {
		t.Fatal("account filter ignored visible capability")
	}
	model.lineages = []domain.CertificateLineage{{ID: "lineage", Name: "example.com"}}
	model.certificateItems = []app.CertificateInventoryItem{{Lineage: model.lineages[0], Environment: "production", Status: "valid", Current: &domain.CertificateVersion{Issuer: "Example Issuer"}}}
	model.searchInput.SetValue("example issuer")
	if len(model.filteredLineages()) != 1 {
		t.Fatal("certificate filter ignored visible issuer")
	}
	model.jobs = []domain.Job{{ID: "job", Kind: "cloudflare.sync", Message: "Loaded zones"}}
	model.searchInput.SetValue("loaded zones")
	if len(model.filteredJobs()) != 1 {
		t.Fatal("activity filter ignored visible job message")
	}
}

func TestLongZoneListKeepsSelectionVisible(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.screen = screenZones
	for index := range 60 {
		model.zones = append(model.zones, domain.Zone{ID: fmt.Sprintf("zone-%d", index), Name: fmt.Sprintf("zone-%02d.example", index)})
	}
	model.zoneIndex = 59
	model.width, model.height = 120, 18
	if view := model.View().Content; !strings.Contains(view, "zone-59.example") {
		t.Fatalf("selected zone is outside viewport: %q", view)
	}
}

func TestCertificateExportRequiresExplicitDestination(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.lineages = []domain.CertificateLineage{{ID: "lineage", Name: "example.com"}}
	model.openCertificateForm("export")
	if cmd := model.submitCertificateForm(); cmd != nil || model.err == nil || model.busy || model.certificateAction != "export" {
		t.Fatalf("empty export destination was accepted: cmd=%v err=%v busy=%v action=%q", cmd != nil, model.err, model.busy, model.certificateAction)
	}
}

func TestRevokeRequiresManuallyTypedExactLineageName(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenCertificates
	model.lineages = []domain.CertificateLineage{{ID: "lineage", Name: "example.com"}}
	model.certificateItems = []app.CertificateInventoryItem{{Lineage: model.lineages[0], Environment: "production"}}
	model.openCertificateForm("revoke")

	if got := model.certificateInputs[1].Value(); got != "" {
		t.Fatalf("exact-name revocation confirmation was prefilled: %q", got)
	}
	if view := model.View().Content; !strings.Contains(view, "Expected exact name:") || !strings.Contains(view, "example.com") {
		t.Fatalf("revocation form does not render expected name separately: %q", view)
	}
	if cmd := model.submitCertificateForm(); cmd != nil || model.certificateAction != "revoke" || model.err == nil {
		t.Fatalf("blank revocation confirmation was accepted: cmd=%v action=%q err=%v", cmd != nil, model.certificateAction, model.err)
	}

	model.certificateInputs[1].SetValue("example.com")
	cmd := model.submitCertificateForm()
	if cmd == nil {
		t.Fatalf("exact revocation confirmation did not submit: err=%v", model.err)
	}
	_ = cmd()
	if len(backend.revokeLineages) != 1 || backend.revokeLineages[0] != "lineage" || backend.revokeConfirmations[0] != "example.com" {
		t.Fatalf("revocation call = lineages:%v confirmations:%v", backend.revokeLineages, backend.revokeConfirmations)
	}
}

func TestDuplicateZoneNamesRequireIDsAndSelectedIssueRetainsLocalID(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenCertificates
	model.zones = []domain.Zone{
		{ID: "zone-account-a", AccountID: "account-a", Name: "shared.example"},
		{ID: "zone-account-b", AccountID: "account-b", Name: "shared.example"},
	}
	if _, err := model.resolveZoneValues([]string{"shared.example"}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate-name zone resolution = %v, want ambiguity", err)
	}
	if ids, err := model.resolveZoneValues([]string{"zone-account-a"}); err != nil || len(ids) != 1 || ids[0] != "zone-account-a" {
		t.Fatalf("explicit zone ID resolution = %v, %v", ids, err)
	}

	model.zoneIndex = 1
	model.openCertificateForm("issue")
	if got := model.certificateInputs[0].Value(); got != "zone-account-b" || model.certificateIssueZoneID != "zone-account-b" {
		t.Fatalf("selected issue zone was not retained by local ID: input=%q retained=%q", got, model.certificateIssueZoneID)
	}
	model.certificateInputs[2].SetValue("ops@example.com")
	cmd := model.submitCertificateForm()
	if cmd == nil {
		t.Fatalf("selected-ID issue did not submit: %v", model.err)
	}
	_ = cmd()
	if len(backend.issueRequests) != 1 || len(backend.issueRequests[0].ZoneIDs) != 1 || backend.issueRequests[0].ZoneIDs[0] != "zone-account-b" {
		t.Fatalf("issue request routed to wrong zone: %#v", backend.issueRequests)
	}
}

func TestBusyModelRejectsOverlappingMutation(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.screen = screenDNS
	model.busy = true
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}
	_, cmd := model.Update(tea.KeyPressMsg{Code: 'n', Text: "n"})
	if cmd != nil || model.editRecord {
		t.Fatalf("busy model opened another mutation: cmd=%v edit=%v", cmd != nil, model.editRecord)
	}
}

func TestZonesNavigationLoadsTheHighlightedZoneInsteadOfOldDNSZone(t *testing.T) {
	for _, test := range []struct {
		name string
		key  tea.KeyPressMsg
	}{
		{name: "enter", key: tea.KeyPressMsg{Code: tea.KeyEnter}},
		{name: "next screen", key: tea.KeyPressMsg{Code: 'l', Text: "l"}},
		{name: "DNS shortcut", key: tea.KeyPressMsg{Code: '4', Text: "4"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &fakeBackend{}
			model := New(backend, Options{})
			model.screen = screenZones
			model.zones = []domain.Zone{{ID: "zone-old", Name: "old.example"}, {ID: "zone-new", Name: "new.example"}}
			model.zoneIndex = 1
			model.activeDNSZoneID = "zone-old"

			_, cmd := model.Update(test.key)
			if cmd == nil {
				t.Fatal("navigation did not start DNS zone load")
			}
			_ = cmd()
			if model.screen != screenDNS {
				t.Fatalf("screen = %d, want DNS", model.screen)
			}
			if len(backend.dnsZones) == 0 || backend.dnsZones[len(backend.dnsZones)-1] != "zone-new" {
				t.Fatalf("DNS load zones = %#v, want zone-new", backend.dnsZones)
			}
		})
	}
}

func TestPaletteZonesNavigationLoadsHighlightedDNSZone(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenZones
	model.zones = []domain.Zone{{ID: "zone-old", Name: "old.example"}, {ID: "zone-new", Name: "new.example"}}
	model.zoneIndex = 1
	model.activeDNSZoneID = "zone-old"
	model.showPalette = true
	model.paletteIndex = int(screenDNS)

	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("palette navigation did not start DNS zone load")
	}
	_ = cmd()
	if model.screen != screenDNS || model.rowOffset != 0 {
		t.Fatalf("palette navigation state = screen:%d offset:%d", model.screen, model.rowOffset)
	}
	if len(backend.dnsZones) == 0 || backend.dnsZones[len(backend.dnsZones)-1] != "zone-new" {
		t.Fatalf("DNS load zones = %#v, want zone-new", backend.dnsZones)
	}
}

func TestTLSNavigationToDNSCarriesTheActiveTLSZone(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenTLS
	model.zones = []domain.Zone{{ID: "zone-old", Name: "old.example"}, {ID: "zone-new", Name: "new.example"}}
	model.activeDNSZoneID = "zone-old"
	model.activeTLSZoneID = "zone-new"
	model.zoneIndex = 1

	_, cmd := model.Update(tea.KeyPressMsg{Code: '4', Text: "4"})
	if cmd == nil || model.screen != screenDNS || model.activeDNSZoneID != "zone-new" {
		t.Fatalf("TLS→DNS navigation state = cmd:%v screen:%d DNS:%q", cmd != nil, model.screen, model.activeDNSZoneID)
	}
	_ = cmd()
	if len(backend.dnsZones) == 0 || backend.dnsZones[len(backend.dnsZones)-1] != "zone-new" {
		t.Fatalf("TLS→DNS loaded stale zone: %v", backend.dnsZones)
	}
}

func TestBackwardNavigationIntoTLSStartsZoneBoundLoad(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenActivity
	model.zones = []domain.Zone{{ID: "zone-a", Name: "alpha.example"}, {ID: "zone-b", Name: "beta.example"}}
	model.zoneIndex = 1

	_, cmd := model.Update(tea.KeyPressMsg{Code: 'h', Text: "h"})
	if cmd == nil || model.screen != screenTLS || model.activeTLSZoneID != "zone-b" || !model.loading {
		t.Fatalf("backward TLS navigation = cmd:%v screen:%d active:%q loading:%v", cmd != nil, model.screen, model.activeTLSZoneID, model.loading)
	}
	_ = cmd()
	if len(backend.tlsZones) == 0 || backend.tlsZones[len(backend.tlsZones)-1] != "zone-b" {
		t.Fatalf("backward TLS navigation loaded zones: %v", backend.tlsZones)
	}
}

func TestStaleZoneLoadCannotOverwriteLatestRequest(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	first := model.startLoad("zone-old", true, false)
	second := model.startLoad("zone-new", true, false)
	_, _ = model.Update(first())
	if !model.loading || model.tls.ZoneID != "" {
		t.Fatalf("stale load was accepted: loading=%v tls=%#v", model.loading, model.tls)
	}
	_, _ = model.Update(second())
	if model.loading || model.tls.ZoneID != "zone-new" {
		t.Fatalf("latest load was not accepted: loading=%v tls=%#v", model.loading, model.tls)
	}
}

func TestFailedTLSRefreshPreservesDraftButDisablesEditing(t *testing.T) {
	backend := &fakeBackend{tlsErr: errors.New("Cloudflare unavailable")}
	model := New(backend, Options{})
	model.screen = screenTLS
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}
	model.activeTLSZoneID = "zone"
	loadedAt := time.Now().UTC()
	model.tls = domain.EdgeTLSSettings{ZoneID: "zone", Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true}
	model.tlsDraft = model.tls
	model.tlsSnapshotReady = true
	model.tlsSnapshotZone = "zone"
	model.tlsSnapshotAt = loadedAt

	refresh := model.startLoad("zone", true, false)
	if model.tlsSnapshotReady {
		t.Fatal("refresh left the old snapshot marked ready")
	}
	_, _ = model.Update(refresh())
	if model.tlsDraft.Mode != "strict" || !model.tlsDraft.AlwaysUseHTTPS || !model.tlsDraft.TLS13 {
		t.Fatalf("failed refresh overwrote the prior draft: %#v", model.tlsDraft)
	}
	if model.tlsSnapshotReady {
		t.Fatal("failed refresh produced a ready snapshot")
	}

	_, cmd := model.Update(tea.KeyPressMsg{Code: 'm', Text: "m"})
	if cmd != nil || model.tlsDraft.Mode != "strict" {
		t.Fatalf("unready TLS draft was editable: cmd=%v draft=%#v", cmd != nil, model.tlsDraft)
	}
	_, cmd = model.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	if cmd != nil || model.confirmTLS || len(backend.updateTLSZones) != 0 {
		t.Fatalf("unready TLS snapshot was applicable: cmd=%v confirm=%v calls=%v", cmd != nil, model.confirmTLS, backend.updateTLSZones)
	}
}

func TestTLSSnapshotIsZoneBoundAndTimestamped(t *testing.T) {
	zones := []domain.Zone{{ID: "zone-a", Name: "alpha.example"}, {ID: "zone-b", Name: "beta.example"}}
	backend := &fakeBackend{zones: zones, tlsSettings: map[string]domain.EdgeTLSSettings{
		"zone-a": {Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true},
	}}
	model := New(backend, Options{})
	model.screen = screenTLS
	model.zones = zones
	model.activeTLSZoneID = "zone-a"

	load := model.startLoad("zone-a", true, false)
	_, _ = model.Update(load())
	if !model.tlsSnapshotReadyForSelectedZone() || model.tlsSnapshotZone != "zone-a" || model.tls.ZoneID != "zone-a" || model.tlsSnapshotAt.IsZero() {
		t.Fatalf("TLS snapshot metadata = ready:%v zone:%q settings:%#v at:%v", model.tlsSnapshotReady, model.tlsSnapshotZone, model.tls, model.tlsSnapshotAt)
	}

	model.activeTLSZoneID = "zone-b"
	_, cmd := model.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	if cmd != nil || model.confirmTLS {
		t.Fatalf("zone-mismatched TLS snapshot was applicable: cmd=%v confirm=%v", cmd != nil, model.confirmTLS)
	}
}

func TestTLSFilterZoneChangeReloadsAndEdgeFilterKeepsActiveZone(t *testing.T) {
	zones := []domain.Zone{{ID: "zone-a", Name: "alpha.example"}, {ID: "zone-b", Name: "beta.example"}}
	backend := &fakeBackend{zones: zones}
	model := New(backend, Options{})
	model.screen = screenTLS
	model.zones = zones
	model.activeTLSZoneID = "zone-a"
	model.zoneIndex = 0
	model.searching = true
	model.searchInput.Focus()
	model.searchInput.SetValue("bet")

	_, cmd := model.Update(tea.KeyPressMsg{Code: 'a', Text: "a"})
	if cmd == nil || model.activeTLSZoneID != "zone-b" || !model.loading {
		t.Fatalf("TLS zone filter did not schedule reload: cmd=%v active=%q loading=%v", cmd != nil, model.activeTLSZoneID, model.loading)
	}
	message := cmd()
	_, _ = model.Update(message)
	if len(backend.tlsZones) == 0 || backend.tlsZones[len(backend.tlsZones)-1] != "zone-b" || !model.tlsSnapshotReadyForSelectedZone() {
		t.Fatalf("TLS filter loaded zones=%v ready=%v snapshot=%q", backend.tlsZones, model.tlsSnapshotReady, model.tlsSnapshotZone)
	}

	model.edgeCertificates = []domain.EdgeCertificate{{ID: "edge", ZoneID: "zone-b", Type: "universal", Status: "active"}}
	model.searchInput.SetValue("universal")
	if reload := model.reloadTLSAfterFilterChange("zone-b"); reload != nil || model.activeTLSZoneID != "zone-b" {
		t.Fatalf("edge-only TLS filter changed the active zone: reload=%v active=%q", reload != nil, model.activeTLSZoneID)
	}
	if view := model.View().Content; !strings.Contains(view, "universal") || strings.Contains(view, "No zone selected") {
		t.Fatalf("edge-only filter hid the active TLS view: %q", view)
	}
}

func TestLoadingModelRejectsMutations(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.screen = screenTLS
	model.loading = true
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com"}}
	_, cmd := model.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	if cmd != nil || model.confirmTLS {
		t.Fatalf("loading model opened TLS confirmation: cmd=%v confirm=%v", cmd != nil, model.confirmTLS)
	}
	if model.toast != "Loading the latest zone state" {
		t.Fatalf("loading mutation toast = %q", model.toast)
	}
}

func TestUnlockEnterCannotStartConcurrentRecovery(t *testing.T) {
	backend := &fakeBackend{locked: true}
	model := New(backend, Options{})
	model.busy = true
	model.unlockInputs[0].SetValue("password")
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || backend.unlockCalls != 0 {
		t.Fatalf("busy unlock started again: cmd=%v calls=%d", cmd != nil, backend.unlockCalls)
	}
}

type nonFatalUnlockWarning struct{}

func (nonFatalUnlockWarning) Error() string  { return "recovery warning" }
func (nonFatalUnlockWarning) NonFatal() bool { return true }

func TestNonFatalRecoveryWarningLeavesUnlockScreen(t *testing.T) {
	model := New(&fakeBackend{locked: true}, Options{})
	_, cmd := model.Update(unlockMsg{err: nonFatalUnlockWarning{}})
	if cmd == nil || model.unlock || model.err == nil {
		t.Fatalf("nonfatal recovery state = cmd:%v unlock:%v err:%v", cmd != nil, model.unlock, model.err)
	}
	if model.toast != "Vault unlocked; recovery requires attention" {
		t.Fatalf("recovery warning toast = %q", model.toast)
	}
}

func TestPersistedRecoveryIssueBlocksTUIAndPaletteMutations(t *testing.T) {
	issue := domain.HealthIssue{Kind: "certificate_commit_recovery_failed", ResourceID: "certificate-commit-recovery"}
	for _, palette := range []bool{false, true} {
		model := New(&fakeBackend{}, Options{})
		_, _ = model.Update(loadMsg{dashboard: domain.DashboardSnapshot{Issues: []domain.HealthIssue{issue}}})
		model.screen = screenDashboard
		if palette {
			model.showPalette = true
			model.paletteIndex = len(screens)
		}
		key := tea.KeyPressMsg{Code: 'a', Text: "a"}
		if palette {
			key = tea.KeyPressMsg{Code: tea.KeyEnter}
		}
		_, cmd := model.Update(key)
		if cmd != nil || model.addCredential {
			t.Fatalf("recovery-blocked mutation (palette=%v) = cmd:%v form:%v", palette, cmd != nil, model.addCredential)
		}
		if !strings.Contains(model.toast, "Crash recovery") {
			t.Fatalf("recovery-blocked toast (palette=%v) = %q", palette, model.toast)
		}
	}
}

func TestRecoveryRetryUsesUnlockedVaultPathAndReloadsOnSuccess(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.recoveryBlocked = true

	_, cmd := model.Update(tea.KeyPressMsg{Code: 'R', Text: "R"})
	if cmd == nil || !model.busy {
		t.Fatalf("recovery retry did not start: cmd=%v busy=%v", cmd != nil, model.busy)
	}
	message := cmd()
	if backend.unlockNilCalls != 1 {
		t.Fatalf("recovery retry did not call UnlockVault with nil password: nil calls=%d", backend.unlockNilCalls)
	}
	_, reload := model.Update(message)
	if reload == nil || model.recoveryBlocked || !model.busy {
		t.Fatalf("successful recovery did not clear/reload safely: reload=%v blocked=%v busy=%v", reload != nil, model.recoveryBlocked, model.busy)
	}
	_, _ = model.Update(reload())
	if model.busy || model.recoveryBlocked {
		t.Fatalf("recovery reload did not settle: busy=%v blocked=%v", model.busy, model.recoveryBlocked)
	}
}

func TestRecoveryRetryWarningRetainsStickyBlockAndAdvertisesRetry(t *testing.T) {
	backend := &fakeBackend{unlockErr: nonFatalUnlockWarning{}}
	model := New(backend, Options{})
	model.recoveryBlocked = true

	if footer := model.renderFooter(); !strings.Contains(footer, "retry recovery") {
		t.Fatalf("recovery footer does not advertise retry: %q", footer)
	}
	model.showHelp = true
	if help := model.renderHelp(); !strings.Contains(help, "Retry blocked crash recovery") {
		t.Fatalf("recovery help does not advertise retry: %q", help)
	}
	model.showHelp = false

	_, cmd := model.Update(tea.KeyPressMsg{Code: 'R', Text: "R"})
	if cmd == nil {
		t.Fatal("recovery warning retry did not start")
	}
	_, reload := model.Update(cmd())
	if reload != nil || !model.recoveryBlocked || model.busy || model.err == nil {
		t.Fatalf("warning did not retain recovery block: reload=%v blocked=%v busy=%v err=%v", reload != nil, model.recoveryBlocked, model.busy, model.err)
	}
}

func TestUnrelatedLoadDoesNotReleaseBusyMutation(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.busy = true
	model.loading = true

	_, _ = model.Update(loadMsg{})
	if !model.busy {
		t.Fatal("unrelated load released the active mutation lock")
	}
	if model.loading {
		t.Fatal("completed load left the loading indicator active")
	}
}

func TestOperationReloadReleasesBusyOnlyAfterItsLoad(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.busy = true

	_, reload := model.Update(operationMsg{message: "saved", reload: true})
	if reload == nil || !model.busy || !model.loading {
		t.Fatalf("operation reload state = cmd:%v busy:%v loading:%v", reload != nil, model.busy, model.loading)
	}

	// A navigation/background load may finish before the operation's own reload.
	_, _ = model.Update(loadMsg{})
	if !model.busy {
		t.Fatal("unrelated load released the operation reload lock")
	}

	message := reload()
	completed, ok := message.(loadMsg)
	if !ok || !completed.releasesBusy {
		t.Fatalf("operation reload message = %#v", message)
	}
	_, _ = model.Update(completed)
	if model.busy || model.loading {
		t.Fatalf("operation reload did not release lock: busy:%v loading:%v", model.busy, model.loading)
	}
}

func TestNavigationLoadInheritsPendingOperationBusyRelease(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.busy = true
	_, operationReload := model.Update(operationMsg{message: "saved", reload: true})
	if operationReload == nil || !model.busyReleasePending {
		t.Fatalf("operation reload did not establish release obligation")
	}
	navigationLoad := model.startLoad("zone-new", true, false)
	_, _ = model.Update(operationReload())
	if !model.busy {
		t.Fatal("stale operation reload released busy before the latest load")
	}
	latest := navigationLoad()
	message, ok := latest.(loadMsg)
	if !ok || !message.releasesBusy {
		t.Fatalf("navigation load did not inherit busy release: %#v", latest)
	}
	_, _ = model.Update(message)
	if model.busy || model.busyReleasePending {
		t.Fatalf("latest navigation load left busy locked: busy=%v pending=%v", model.busy, model.busyReleasePending)
	}
}

func TestBusyCommandPaletteRejectsMutationEntries(t *testing.T) {
	for _, test := range []struct {
		name  string
		index int
	}{
		{name: "add credential", index: len(screens)},
		{name: "synchronize", index: len(screens) + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := New(&fakeBackend{}, Options{})
			model.busy = true
			model.showPalette = true
			model.paletteIndex = test.index

			_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			if cmd != nil || !model.busy || model.addCredential {
				t.Fatalf("busy palette mutation = cmd:%v busy:%v form:%v", cmd != nil, model.busy, model.addCredential)
			}
			if model.toast != "An operation is already running" {
				t.Fatalf("busy palette toast = %q", model.toast)
			}
		})
	}
}

func TestLoadingCommandPaletteRejectsMutationEntries(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	model.loading = true
	model.showPalette = true
	model.paletteIndex = len(screens) + 1
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || model.busy {
		t.Fatalf("loading palette started sync: cmd=%v busy=%v", cmd != nil, model.busy)
	}
	if model.toast != "Loading the latest zone state" {
		t.Fatalf("loading palette toast = %q", model.toast)
	}
}

func TestRemoveCredentialCapturesExactIDAndDisclosesAffectedRoutes(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenAccounts
	model.credentials = []domain.Credential{
		{ID: "credential-a", Label: "Primary", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
		{ID: "credential-b", Label: "Retiring", Provider: domain.ProviderCloudflare, Kind: domain.CredentialAccountToken, AccountHint: "account-main", Status: domain.CredentialValid},
	}
	model.zones = []domain.Zone{
		{ID: "zone-a", Name: "example.com", PreferredCredentialID: "credential-b"},
		{ID: "zone-b", Name: "example.net", PreferredCredentialID: "credential-b"},
	}
	model.rowOffset = 1

	_, blink := model.Update(tea.KeyPressMsg{Code: 'd', Text: "d"})
	if blink == nil || !model.removeCredential || model.removeCredentialID != "credential-b" || model.removeCredentialInput.Value() != "" {
		t.Fatalf("remove form = open:%v id:%q input:%q cmd:%v", model.removeCredential, model.removeCredentialID, model.removeCredentialInput.Value(), blink != nil)
	}
	view := model.View().Content
	for _, expected := range []string{"Retiring", "credential-b", "account_token", "account-main", "2 preferred zone route", "example.com", "example.net", "reassigned"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("remove form does not disclose %q: %q", expected, view)
		}
	}

	// A refresh/reorder after opening must not redirect removal to the new row.
	_, _ = model.Update(loadMsg{credentials: []domain.Credential{
		{ID: "credential-b", Label: "Retiring", Provider: domain.ProviderCloudflare, Kind: domain.CredentialAccountToken, AccountHint: "account-main", Status: domain.CredentialValid},
		{ID: "credential-a", Label: "Primary", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
	}, zones: model.zones})
	model.removeCredentialInput.SetValue("Retiring")
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || model.removeCredential || !model.busy {
		t.Fatalf("confirmed removal = cmd:%v open:%v busy:%v", cmd != nil, model.removeCredential, model.busy)
	}
	message, ok := cmd().(operationMsg)
	if !ok || !message.reload || message.err != nil {
		t.Fatalf("remove result = %#v", message)
	}
	if len(backend.deletedCredentials) != 1 || backend.deletedCredentials[0] != "credential-b" {
		t.Fatalf("deleted credential IDs = %v", backend.deletedCredentials)
	}
}

func TestRemoveCredentialCancellationAndStaleConnectionAreSafe(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenAccounts
	model.credentials = []domain.Credential{{ID: "credential", Label: "Production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid}}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'd', Text: "d"})
	model.removeCredentialInput.SetValue("Production")
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if model.removeCredential || model.removeCredentialID != "" || model.removeCredentialExpected != "" || model.removeCredentialInput.Value() != "" {
		t.Fatalf("cancel retained remove state: open=%v id=%q label=%q input=%q", model.removeCredential, model.removeCredentialID, model.removeCredentialExpected, model.removeCredentialInput.Value())
	}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'd', Text: "d"})
	model.removeCredentialInput.SetValue("Production")
	model.credentials = nil
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || model.err == nil || len(backend.deletedCredentials) != 0 {
		t.Fatalf("stale remove mutated: cmd=%v err=%v calls=%v", cmd != nil, model.err, backend.deletedCredentials)
	}
}

func TestRemoveCredentialRejectsChangedAffectedRoutes(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenAccounts
	model.credentials = []domain.Credential{{ID: "credential", Label: "Production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid}}
	model.zones = []domain.Zone{{ID: "zone-a", Name: "example.com", PreferredCredentialID: "credential"}}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'd', Text: "d"})
	model.removeCredentialInput.SetValue("Production")
	model.zones = append(model.zones, domain.Zone{ID: "zone-b", Name: "example.net", PreferredCredentialID: "credential"})
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || model.err == nil || !strings.Contains(model.err.Error(), "affected zone routes changed") || len(backend.deletedCredentials) != 0 {
		t.Fatalf("changed route disclosure mutated: cmd=%v err=%v calls=%v", cmd != nil, model.err, backend.deletedCredentials)
	}
}

func TestRemoveCredentialSurfacesFailClosedReplacementError(t *testing.T) {
	backend := &fakeBackend{deleteCredentialErr: errors.New("zone example.com has no proven replacement")}
	model := New(backend, Options{})
	model.screen = screenAccounts
	model.credentials = []domain.Credential{{ID: "credential", Label: "Production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid}}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'd', Text: "d"})
	model.removeCredentialInput.SetValue("Production")
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("confirmed removal did not call backend")
	}
	_, reload := model.Update(cmd())
	if reload == nil || model.err == nil || !strings.Contains(model.err.Error(), "no proven replacement") {
		t.Fatalf("replacement failure = reload:%v err:%v", reload != nil, model.err)
	}
}

func TestPreferredCredentialRejectsAmbiguousLabelAndInvalidCandidates(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	zone := domain.Zone{ID: "zone", Name: "example.com", Provider: domain.ProviderCloudflare}
	model.screen = screenZones
	model.zones = []domain.Zone{zone}
	model.credentials = []domain.Credential{
		{ID: "credential-a", Label: "Production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
		{ID: "credential-b", Label: "production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
		{ID: "credential-invalid", Label: "Invalid", Provider: domain.ProviderCloudflare, Status: domain.CredentialInvalid},
		{ID: "credential-other", Label: "Other", Provider: "other", Status: domain.CredentialValid},
	}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
	if model.preferCredentialInputs[0].Value() != "" || model.preferCredentialInputs[1].Value() != "" {
		t.Fatalf("preference confirmation was prefilled: %#v", model.preferCredentialInputs)
	}
	model.preferCredentialInputs[0].SetValue("Production")
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || model.preferCredentialFocus != 0 || model.err == nil || !strings.Contains(model.err.Error(), "ambiguous") {
		t.Fatalf("ambiguous label = cmd:%v focus:%d err:%v", cmd != nil, model.preferCredentialFocus, model.err)
	}
	for _, test := range []struct {
		value string
		want  string
	}{{"credential-invalid", "invalid"}, {"credential-other", "provider"}} {
		model.preferCredentialInputs[0].SetValue(test.value)
		_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
		if model.err == nil || !strings.Contains(model.err.Error(), test.want) {
			t.Fatalf("selector %q error = %v, want %q", test.value, model.err, test.want)
		}
	}
}

func TestPreferredCredentialCapturesIDAcrossRefreshAndCallsExactZone(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenZones
	model.zones = []domain.Zone{{ID: "zone-id", Name: "example.com", Provider: domain.ProviderCloudflare, PreferredCredentialID: "credential-old"}}
	model.credentials = []domain.Credential{
		{ID: "credential-old", Label: "Old", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
		{ID: "credential-selected", Label: "Replacement", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
	}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
	model.preferCredentialInputs[0].SetValue("Replacement")
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if model.preferCredentialFocus != 1 || model.preferResolvedCredentialID != "credential-selected" {
		t.Fatalf("captured credential = focus:%d id:%q err:%v", model.preferCredentialFocus, model.preferResolvedCredentialID, model.err)
	}

	// The label becomes ambiguous after capture. Final confirmation must retain
	// the immutable ID instead of resolving the label to a different row.
	_, _ = model.Update(loadMsg{zones: model.zones, credentials: []domain.Credential{
		{ID: "credential-new", Label: "Replacement", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
		{ID: "credential-selected", Label: "Replacement", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
		{ID: "credential-old", Label: "Old", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid},
	}})
	model.preferCredentialInputs[1].SetValue("example.com")
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || model.preferCredential || !model.busy {
		t.Fatalf("preference submit = cmd:%v open:%v busy:%v err:%v", cmd != nil, model.preferCredential, model.busy, model.err)
	}
	message, ok := cmd().(operationMsg)
	if !ok || !message.reload || message.err != nil {
		t.Fatalf("preference result = %#v", message)
	}
	if fmt.Sprint(backend.preferredZones) != "[zone-id]" || fmt.Sprint(backend.preferredCredentials) != "[credential-selected]" {
		t.Fatalf("preferred calls = zones:%v credentials:%v", backend.preferredZones, backend.preferredCredentials)
	}
}

func TestPreferredCredentialFormFitsMinimumTerminalAndShowsRoutingIdentity(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	_, _ = model.Update(tea.WindowSizeMsg{Width: 64, Height: 18})
	model.screen = screenZones
	model.accounts = []domain.RemoteAccount{{ID: "account-id", Name: "Primary"}}
	model.zones = []domain.Zone{{ID: "zone-id", Name: "example.com", Provider: domain.ProviderCloudflare, AccountID: "account-id", PreferredCredentialID: "credential-current"}}
	model.credentials = []domain.Credential{
		{ID: "credential-current", Label: "Current", Provider: domain.ProviderCloudflare, Kind: domain.CredentialUserToken, Status: domain.CredentialValid, Capabilities: []string{"dns:read", "dns:write"}},
		{ID: "credential-next", Label: "Next", Provider: domain.ProviderCloudflare, Kind: domain.CredentialAccountToken, AccountHint: "account-id", Status: domain.CredentialValid, Capabilities: []string{"dns:read"}},
	}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
	view := model.View().Content
	if height := lipgloss.Height(view); height > 18 {
		t.Fatalf("minimum-terminal preference modal height = %d\n%s", height, view)
	}
	for _, expected := range []string{"example.com", "zone-id", "Primary", "account-id", "credential-current", "Current", "current"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("preference form does not show %q: %q", expected, view)
		}
	}
}

func TestCertificateRunRendersBoundedProgressAndCancelsSafely(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	_, _ = model.Update(tea.WindowSizeMsg{Width: 64, Height: 18})
	ctx, cancel := context.WithCancel(context.Background())
	model.beginCertificateRun("ISSUING WILDCARD CERTIFICATES", 2, ctx, cancel)
	now := time.Now().UTC()
	model.applyBackendEvent(app.Event{Kind: "certificate.progress", Value: domain.Job{
		ID: "job-1", Kind: "certificate.issue", State: domain.JobWaitingForDNS,
		Progress: 45, Message: "DNS challenge published for _acme-challenge.example.com.; waiting for authoritative propagation", UpdatedAt: now,
	}})
	view := model.View().Content
	if height := lipgloss.Height(view); height > 18 {
		t.Fatalf("certificate progress height = %d\n%s", height, view)
	}
	for _, expected := range []string{"ISSUING WILDCARD CERTIFICATES", "DNS", "DNS challenge published", "45%", "cancel safely"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("certificate progress does not show %q: %q", expected, view)
		}
	}
	_, _ = model.Update(tea.KeyPressMsg{Code: 'b', Text: "b"})
	if model.certificateRun.Visible || !strings.Contains(model.View().Content, "progress") {
		t.Fatalf("backgrounded certificate run = visible:%v view:%q", model.certificateRun.Visible, model.View().Content)
	}
	_, quit := model.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if quit != nil || !model.certificateRun.Visible || !strings.Contains(model.toast, "DNS cleanup") {
		t.Fatalf("active certificate quit guard = cmd:%v visible:%v toast:%q", quit != nil, model.certificateRun.Visible, model.toast)
	}
	_, _ = model.Update(tea.KeyPressMsg{Code: 'b', Text: "b"})
	_, _ = model.Update(tea.KeyPressMsg{Code: 'o', Text: "o"})
	if !model.certificateRun.Visible {
		t.Fatal("certificate progress shortcut did not reopen the console")
	}

	_, command := model.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	if command != nil || !model.certificateRun.CancelRequested {
		t.Fatalf("cancel state = command:%v requested:%v", command != nil, model.certificateRun.CancelRequested)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("certificate run context was not cancelled")
	}
	if view := model.View().Content; !strings.Contains(view, "CANCELLING SAFELY") || !strings.Contains(view, "cleanup to finish") {
		t.Fatalf("cancelling progress view = %q", view)
	}
}

func TestCertificateRunCompletionKeepsSummaryUntilDismissed(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	model.beginCertificateRun("ISSUING WILDCARD CERTIFICATES", 1, ctx, cancel)
	_, _ = model.Update(operationMsg{message: "Issued 0 certificate(s)", err: errors.New("propagation deadline exceeded"), certificate: true})
	if model.certificateRun == nil || !model.certificateRun.Done || !strings.Contains(model.View().Content, "propagation deadline exceeded") {
		t.Fatalf("completion summary = %#v", model.certificateRun)
	}
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if model.certificateRun != nil {
		t.Fatal("completed certificate summary was not dismissed")
	}
}

func TestCertificateRunActivityCanScrollWithoutLosingTail(t *testing.T) {
	model := New(&fakeBackend{}, Options{})
	_, _ = model.Update(tea.WindowSizeMsg{Width: 76, Height: 18})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	model.beginCertificateRun("ISSUING WILDCARD CERTIFICATES", 1, ctx, cancel)
	for index := range 10 {
		model.applyBackendEvent(app.Event{Kind: "certificate.progress", Value: domain.Job{
			ID: "job", State: domain.JobRunning, Progress: index + 1,
			Message: fmt.Sprintf("stage-%02d", index), UpdatedAt: time.Now().Add(time.Duration(index) * time.Second),
		}})
	}
	if view := model.View().Content; !strings.Contains(view, "stage-09") {
		t.Fatalf("activity did not follow newest event: %q", view)
	}
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyHome})
	if view := model.View().Content; !strings.Contains(view, "stage-00") || strings.Contains(view, "stage-09") {
		t.Fatalf("activity home did not show oldest events: %q", view)
	}
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEnd})
	if view := model.View().Content; !strings.Contains(view, "stage-09") {
		t.Fatalf("activity end did not return to live tail: %q", view)
	}
}

func TestPreferredCredentialCancellationAndStaleRouteAreSafe(t *testing.T) {
	backend := &fakeBackend{}
	model := New(backend, Options{})
	model.screen = screenZones
	model.zones = []domain.Zone{{ID: "zone", Name: "example.com", Provider: domain.ProviderCloudflare, PreferredCredentialID: "old"}}
	model.credentials = []domain.Credential{{ID: "new", Label: "New", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid}}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
	model.preferCredentialInputs[0].SetValue("new")
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if model.preferCredential || model.preferZoneID != "" || model.preferResolvedCredentialID != "" || len(model.preferCredentialInputs) != 2 || model.preferCredentialInputs[0].Value() != "" {
		t.Fatalf("cancel retained preference state: %#v", model)
	}

	_, _ = model.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
	model.preferCredentialInputs[0].SetValue("new")
	_, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.zones[0].PreferredCredentialID = "changed-elsewhere"
	model.preferCredentialInputs[1].SetValue("example.com")
	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || model.err == nil || !strings.Contains(model.err.Error(), "route changed") || len(backend.preferredZones) != 0 {
		t.Fatalf("stale route mutated: cmd=%v err=%v calls=%v", cmd != nil, model.err, backend.preferredZones)
	}
}

func TestAccountAndZoneMutationsRespectRecoveryBusyAndLoadingGuards(t *testing.T) {
	tests := []struct {
		name    string
		screen  screen
		key     rune
		blocked func(*Model)
	}{
		{"remove recovery", screenAccounts, 'd', func(m *Model) { m.recoveryBlocked = true }},
		{"remove busy", screenAccounts, 'd', func(m *Model) { m.busy = true }},
		{"remove loading", screenAccounts, 'd', func(m *Model) { m.loading = true }},
		{"prefer recovery", screenZones, 'p', func(m *Model) { m.recoveryBlocked = true }},
		{"prefer busy", screenZones, 'p', func(m *Model) { m.busy = true }},
		{"prefer loading", screenZones, 'p', func(m *Model) { m.loading = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := New(&fakeBackend{}, Options{})
			model.screen = test.screen
			model.credentials = []domain.Credential{{ID: "credential", Label: "Production", Provider: domain.ProviderCloudflare, Status: domain.CredentialValid}}
			model.zones = []domain.Zone{{ID: "zone", Name: "example.com", Provider: domain.ProviderCloudflare}}
			test.blocked(model)
			_, cmd := model.Update(tea.KeyPressMsg{Code: test.key, Text: string(test.key)})
			if cmd != nil || model.removeCredential || model.preferCredential || model.toast == "" {
				t.Fatalf("blocked mutation = cmd:%v remove:%v prefer:%v toast:%q", cmd != nil, model.removeCredential, model.preferCredential, model.toast)
			}
		})
	}
}

func TestFirstRunVaultRequiresConfirmation(t *testing.T) {
	backend := &fakeBackend{locked: true}
	model := New(backend, Options{FirstRun: true})
	if !model.unlock || len(model.unlockInputs) != 2 {
		t.Fatalf("first-run unlock state = %#v", model)
	}
	view := model.View().Content
	if !strings.Contains(view, "CREATE LOCAL VAULT") || !strings.Contains(view, "Confirm password") {
		t.Fatalf("first-run view missing setup copy")
	}
}

func TestFirstRunRejectsShortVaultPassword(t *testing.T) {
	backend := &fakeBackend{locked: true}
	model := New(backend, Options{FirstRun: true})
	model.unlockInputs[0].SetValue("short")
	model.unlockInputs[1].SetValue("short")
	model.unlockFocus = 1

	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || model.err == nil || !strings.Contains(model.err.Error(), "at least 10") {
		t.Fatalf("short first-run password was not rejected: err=%v cmd=%v", model.err, cmd != nil)
	}
}

func TestExistingVaultAcceptsLegacyShortPassword(t *testing.T) {
	backend := &fakeBackend{locked: true}
	model := New(backend, Options{FirstRun: false})
	model.unlockInputs[0].SetValue("short")

	_, cmd := model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || model.err != nil {
		t.Fatalf("legacy password should be sent to the vault: err=%v cmd=%v", model.err, cmd != nil)
	}
	message := cmd()
	if result, ok := message.(unlockMsg); !ok || result.err != nil || backend.locked {
		t.Fatalf("unlock result = %#v, locked=%v", message, backend.locked)
	}
}

type fakeBackend struct {
	locked                 bool
	unlockCalls            int
	unlockNilCalls         int
	unlockErr              error
	dnsZones               []string
	zones                  []domain.Zone
	deleteCalls            int
	deletedCredentials     []string
	deleteCredentialErr    error
	preferredZones         []string
	preferredCredentials   []string
	preferredCredentialErr error
	tlsSettings            map[string]domain.EdgeTLSSettings
	tlsErr                 error
	tlsZones               []string
	updateTLSZones         []string
	updateTLSDrafts        []domain.EdgeTLSSettings
	issueRequests          []app.IssueZonesRequest
	revokeLineages         []string
	revokeConfirmations    []string
}

func (f *fakeBackend) VaultLocked() bool { return f.locked }
func (f *fakeBackend) UnlockVault(_ context.Context, password []byte) error {
	f.unlockCalls++
	if password == nil {
		f.unlockNilCalls++
	}
	if f.unlockErr == nil {
		f.locked = false
	}
	return f.unlockErr
}
func (f *fakeBackend) Dashboard(context.Context) (domain.DashboardSnapshot, error) {
	return domain.DashboardSnapshot{}, nil
}
func (f *fakeBackend) Credentials(context.Context) ([]domain.Credential, error) { return nil, nil }
func (f *fakeBackend) Accounts(context.Context) ([]domain.RemoteAccount, error) { return nil, nil }
func (f *fakeBackend) Zones(context.Context) ([]domain.Zone, error)             { return f.zones, nil }

func (f *fakeBackend) DNSRecords(_ context.Context, zoneID string) ([]domain.DNSRecord, error) {
	f.dnsZones = append(f.dnsZones, zoneID)
	return nil, nil
}
func (f *fakeBackend) Certificates(context.Context) ([]domain.CertificateLineage, error) {
	return nil, nil
}
func (f *fakeBackend) CertificateInventory(context.Context) ([]app.CertificateInventoryItem, error) {
	return nil, nil
}
func (f *fakeBackend) Jobs(context.Context, int) ([]domain.Job, error)         { return nil, nil }
func (f *fakeBackend) Audit(context.Context, int) ([]domain.AuditEvent, error) { return nil, nil }
func (f *fakeBackend) AddCloudflareCredential(context.Context, app.AddCredentialInput) (domain.Credential, error) {
	return domain.Credential{}, nil
}
func (f *fakeBackend) DeleteCredential(_ context.Context, credentialID string) error {
	f.deletedCredentials = append(f.deletedCredentials, credentialID)
	return f.deleteCredentialErr
}
func (f *fakeBackend) SetZonePreferredCredential(_ context.Context, zoneID, credentialID string) (domain.Zone, error) {
	f.preferredZones = append(f.preferredZones, zoneID)
	f.preferredCredentials = append(f.preferredCredentials, credentialID)
	return domain.Zone{ID: zoneID, PreferredCredentialID: credentialID}, f.preferredCredentialErr
}
func (f *fakeBackend) SyncAll(context.Context) ([]domain.Job, error) { return nil, nil }
func (f *fakeBackend) CreateDNSRecord(context.Context, string, domain.DNSRecord) (domain.DNSRecord, error) {
	return domain.DNSRecord{}, nil
}
func (f *fakeBackend) PatchDNSRecord(context.Context, string, string, domain.DNSRecord) (domain.DNSRecord, error) {
	return domain.DNSRecord{}, nil
}
func (f *fakeBackend) DeleteDNSRecord(context.Context, string, string) error {
	f.deleteCalls++
	return nil
}
func (f *fakeBackend) TLSSettings(_ context.Context, zoneID string, _ bool) (domain.EdgeTLSSettings, error) {
	f.tlsZones = append(f.tlsZones, zoneID)
	if f.tlsErr != nil {
		return domain.EdgeTLSSettings{}, f.tlsErr
	}
	if settings, ok := f.tlsSettings[zoneID]; ok {
		return settings, nil
	}
	return domain.EdgeTLSSettings{ZoneID: zoneID, Mode: "strict", MinimumTLS: "1.2", TLS13: true}, nil
}
func (f *fakeBackend) EdgeCertificates(context.Context, string) ([]domain.EdgeCertificate, error) {
	return nil, nil
}
func (f *fakeBackend) UpdateTLSSettings(_ context.Context, zoneID string, draft domain.EdgeTLSSettings) (domain.EdgeTLSSettings, error) {
	f.updateTLSZones = append(f.updateTLSZones, zoneID)
	f.updateTLSDrafts = append(f.updateTLSDrafts, draft)
	return draft, nil
}
func (f *fakeBackend) IssueCertificates(_ context.Context, request app.IssueZonesRequest) (app.IssueZonesResult, error) {
	f.issueRequests = append(f.issueRequests, request)
	return app.IssueZonesResult{}, nil
}
func (f *fakeBackend) ImportCertificateMetadata(context.Context, string, string, string) (domain.CertificateLineage, domain.CertificateVersion, error) {
	return domain.CertificateLineage{}, domain.CertificateVersion{}, nil
}
func (f *fakeBackend) ExportCertificate(context.Context, string, string) (string, error) {
	return "", nil
}
func (f *fakeBackend) RevokeCertificate(_ context.Context, lineageID, _ string, confirmation string, _ *uint) error {
	f.revokeLineages = append(f.revokeLineages, lineageID)
	f.revokeConfirmations = append(f.revokeConfirmations, confirmation)
	return nil
}
func (f *fakeBackend) RenewCertificates(context.Context, string, bool) (app.IssueZonesResult, error) {
	return app.IssueZonesResult{}, nil
}
