package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

func TestUpdateEdgeTLSSettingsMarksPreflightReadFailureNotAttempted(t *testing.T) {
	t.Parallel()
	var patches atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches.Add(1)
		}
		http.Error(w, "temporary provider failure", http.StatusBadGateway)
	})
	baseline := domain.EdgeTLSSettings{Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true}
	desired := baseline
	desired.Mode = "full"
	_, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone-1", baseline, desired)
	if err == nil {
		t.Fatal("preflight read failure unexpectedly succeeded")
	}
	var marker interface{ MutationNotAttempted() bool }
	if !errors.As(err, &marker) || !marker.MutationNotAttempted() {
		t.Fatalf("preflight error lacks MutationNotAttempted marker: %T %v", err, err)
	}
	if patches.Load() != 0 {
		t.Fatalf("patch count = %d, want 0", patches.Load())
	}
}

func TestGetEdgeTLSSettings(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"ssl":              "strict",
		"always_use_https": "on",
		"min_tls_version":  "1.2",
		"tls_1_3":          "zrt",
	}
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/client/v4/zones/zone-1/settings/"
		if r.Method == http.MethodGet && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			id := r.URL.Path[len(prefix):]
			value, ok := values[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeResult(t, w, map[string]any{"id": id, "value": value, "editable": true}, nil)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records" {
			if r.URL.Query().Get("proxied") != "true" || r.URL.Query().Get("per_page") != "1" {
				t.Errorf("proxied query = %v", r.URL.Query())
			}
			writeResult(t, w, []any{map[string]any{"id": "proxied-record"}}, map[string]any{"page": 1})
			return
		}
		http.NotFound(w, r)
	})

	settings, err := client.GetEdgeTLSSettings(context.Background(), testAuth(), "zone-1")
	if err != nil {
		t.Fatalf("GetEdgeTLSSettings: %v", err)
	}
	if settings.Mode != "strict" || !settings.AlwaysUseHTTPS || settings.MinimumTLS != "1.2" || !settings.TLS13 || !settings.HasProxiedDNS {
		t.Errorf("settings = %+v", settings)
	}
	if settings.LastSyncedAt == nil || !settings.LastSyncedAt.Equal(fixedNow) {
		t.Errorf("sync time = %v", settings.LastSyncedAt)
	}
}

func TestUpdateEdgeTLSSettings(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	updated := make(map[string]string)
	current := map[string]string{
		"ssl":              "flexible",
		"always_use_https": "off",
		"min_tls_version":  "1.2",
		"tls_1_3":          "on",
	}
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/client/v4/zones/zone-1/settings/"
		if r.Method == http.MethodGet && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			id := r.URL.Path[len(prefix):]
			value, ok := current[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeResult(t, w, map[string]any{"id": id, "value": value, "editable": true}, nil)
			return
		}
		if r.Method == http.MethodPatch && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			id := r.URL.Path[len(prefix):]
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode setting: %v", err)
			}
			mu.Lock()
			updated[id] = body["value"]
			current[id] = body["value"]
			mu.Unlock()
			writeResult(t, w, map[string]any{"id": id, "value": body["value"], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records" {
			writeResult(t, w, []any{}, map[string]any{"page": 1})
			return
		}
		http.NotFound(w, r)
	})

	baseline := domain.EdgeTLSSettings{Mode: "flexible", AlwaysUseHTTPS: false, MinimumTLS: "1.2", TLS13: true}
	settings, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone-1", baseline, domain.EdgeTLSSettings{
		Mode: "full", AlwaysUseHTTPS: true, MinimumTLS: "1.3", TLS13: false,
	})
	if err != nil {
		t.Fatalf("UpdateEdgeTLSSettings: %v", err)
	}
	if settings.Mode != "full" || !settings.AlwaysUseHTTPS || settings.MinimumTLS != "1.3" || settings.TLS13 || settings.HasProxiedDNS {
		t.Errorf("effective settings = %+v", settings)
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]string{
		"ssl": "full", "always_use_https": "on", "min_tls_version": "1.3", "tls_1_3": "off",
	}
	for id, value := range want {
		if updated[id] != value {
			t.Errorf("updated[%s] = %q, want %q", id, updated[id], value)
		}
	}
}

func TestUpdateEdgeTLSSettingsNoOpPreservesZRT(t *testing.T) {
	t.Parallel()
	current := map[string]string{
		"ssl":              "strict",
		"always_use_https": "on",
		"min_tls_version":  "1.2",
		"tls_1_3":          "zrt",
	}
	patches := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/client/v4/zones/zone-1/settings/"
		if r.Method == http.MethodGet && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			id := r.URL.Path[len(prefix):]
			writeResult(t, w, map[string]any{"id": id, "value": current[id], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodPatch && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			patches++
			http.Error(w, "unexpected patch", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records" {
			writeResult(t, w, []any{}, map[string]any{"page": 1})
			return
		}
		http.NotFound(w, r)
	})

	baseline := domain.EdgeTLSSettings{Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true}
	settings, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone-1", baseline, domain.EdgeTLSSettings{
		Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true,
	})
	if err != nil {
		t.Fatalf("UpdateEdgeTLSSettings: %v", err)
	}
	if patches != 0 {
		t.Fatalf("patch count = %d, want 0", patches)
	}
	if settings.Mode != "strict" || !settings.AlwaysUseHTTPS || settings.MinimumTLS != "1.2" || !settings.TLS13 {
		t.Errorf("effective settings = %+v", settings)
	}
}

func TestUpdateEdgeTLSSettingsEnablesTLS13FromOff(t *testing.T) {
	t.Parallel()
	current := map[string]string{
		"ssl":              "strict",
		"always_use_https": "on",
		"min_tls_version":  "1.2",
		"tls_1_3":          "off",
	}
	updated := make(map[string]string)
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/client/v4/zones/zone-1/settings/"
		if r.Method == http.MethodGet && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			id := r.URL.Path[len(prefix):]
			writeResult(t, w, map[string]any{"id": id, "value": current[id], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodPatch && len(r.URL.Path) > len(prefix) && r.URL.Path[:len(prefix)] == prefix {
			id := r.URL.Path[len(prefix):]
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode setting: %v", err)
			}
			updated[id] = body["value"]
			writeResult(t, w, map[string]any{"id": id, "value": body["value"], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records" {
			writeResult(t, w, []any{}, map[string]any{"page": 1})
			return
		}
		http.NotFound(w, r)
	})

	baseline := domain.EdgeTLSSettings{Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: false}
	settings, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone-1", baseline, domain.EdgeTLSSettings{
		Mode: "strict", AlwaysUseHTTPS: true, MinimumTLS: "1.2", TLS13: true,
	})
	if err != nil {
		t.Fatalf("UpdateEdgeTLSSettings: %v", err)
	}
	if len(updated) != 1 || updated[settingTLS13] != "on" {
		t.Fatalf("updated = %v, want only tls_1_3=on", updated)
	}
	if !settings.TLS13 {
		t.Errorf("effective settings = %+v", settings)
	}
}

func TestUpdateEdgeTLSSettingsPreservesUnrelatedConcurrentChange(t *testing.T) {
	t.Parallel()
	current := map[string]string{
		"ssl": "strict", "always_use_https": "on", "min_tls_version": "1.2", "tls_1_3": "zrt",
	}
	updated := make(map[string]string)
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/client/v4/zones/zone-1/settings/"
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, prefix) {
			id := strings.TrimPrefix(r.URL.Path, prefix)
			writeResult(t, w, map[string]any{"id": id, "value": current[id], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, prefix) {
			id := strings.TrimPrefix(r.URL.Path, prefix)
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			updated[id] = body["value"]
			current[id] = body["value"]
			writeResult(t, w, map[string]any{"id": id, "value": body["value"], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records" {
			writeResult(t, w, []any{}, map[string]any{"page": 1})
			return
		}
		http.NotFound(w, r)
	})

	baseline := domain.EdgeTLSSettings{Mode: "strict", AlwaysUseHTTPS: false, MinimumTLS: "1.2", TLS13: true}
	desired := baseline
	desired.Mode = "full"
	settings, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone-1", baseline, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 || updated[settingSSL] != "full" {
		t.Fatalf("patches = %#v, want only ssl=full", updated)
	}
	if !settings.AlwaysUseHTTPS || !settings.TLS13 {
		t.Fatalf("unrelated concurrent state was clobbered: %#v", settings)
	}
}

func TestUpdateEdgeTLSSettingsRejectsConcurrentChangeToRequestedFieldBeforePatching(t *testing.T) {
	t.Parallel()
	current := map[string]string{
		"ssl": "flexible", "always_use_https": "off", "min_tls_version": "1.2", "tls_1_3": "on",
	}
	patches := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/client/v4/zones/zone-1/settings/"
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, prefix) {
			id := strings.TrimPrefix(r.URL.Path, prefix)
			writeResult(t, w, map[string]any{"id": id, "value": current[id], "editable": true}, nil)
			return
		}
		if r.Method == http.MethodPatch {
			patches++
		}
		http.NotFound(w, r)
	})

	baseline := domain.EdgeTLSSettings{Mode: "strict", MinimumTLS: "1.2", TLS13: true}
	desired := baseline
	desired.Mode = "full"
	_, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone-1", baseline, desired)
	if err == nil || !strings.Contains(err.Error(), "changed remotely") || patches != 0 {
		t.Fatalf("concurrent field error = %v, patches=%d", err, patches)
	}
}

func TestUpdateEdgeTLSSettingsValidatesBeforeNetwork(t *testing.T) {
	t.Parallel()
	called := false
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	_, err := client.UpdateEdgeTLSSettings(context.Background(), testAuth(), "zone", domain.EdgeTLSSettings{}, domain.EdgeTLSSettings{Mode: "unsafe", MinimumTLS: "1.2"})
	if err == nil || called {
		t.Fatalf("error = %v, called = %v", err, called)
	}
}

func TestListEdgeCertificatesUsesEarliestPackExpiry(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/client/v4/zones/zone-1/ssl/certificate_packs" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("status") != "all" || r.URL.Query().Get("page") != "2" {
			t.Errorf("certificate query = %v", r.URL.Query())
		}
		writeResult(t, w, []any{
			map[string]any{
				"id": "pack-1", "type": "universal", "status": "active", "hosts": []string{"example.com"},
				"certificates": []any{
					map[string]any{"id": "rsa", "hosts": []string{"example.com", "*.example.com"}, "status": "active", "expires_on": "2026-10-01T00:00:00Z"},
					map[string]any{"id": "ecdsa", "hosts": []string{"example.com"}, "status": "active", "expires_on": "2026-09-01T00:00:00Z"},
				},
			},
			map[string]any{"id": "pack-other", "type": "advanced", "status": "active", "hosts": []string{"other.test"}},
		}, map[string]any{"page": 2, "total_pages": 2})
	})

	certificates, err := client.ListEdgeCertificates(context.Background(), testAuth(), "zone-1", provider.PageRequest{Page: 2, PerPage: 10, Search: "example"})
	if err != nil {
		t.Fatalf("ListEdgeCertificates: %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("certificates = %+v", certificates)
	}
	certificate := certificates[0]
	wantExpiry := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	if certificate.ID != "pack-1" || certificate.ExpiresAt == nil || !certificate.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("certificate = %+v", certificate)
	}
	if len(certificate.Hosts) != 2 || certificate.Hosts[1] != "*.example.com" {
		t.Errorf("hosts = %v", certificate.Hosts)
	}
}
