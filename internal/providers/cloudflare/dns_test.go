package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

func TestListDNSRecordsPreservesUnknownFields(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client/v4/zones/zone-1/dns_records" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("search"); got != "api" {
			t.Errorf("search = %q", got)
		}
		writeResult(t, w, []any{
			map[string]any{
				"id": "record-a", "type": "A", "name": "api.example.com", "content": "192.0.2.10",
				"ttl": 300, "proxied": true, "proxiable": true, "priority": 10,
				"comment": "primary", "tags": []string{"owner:ops"},
				"modified_on": "2026-07-01T12:00:00Z",
			},
			map[string]any{
				"id": "record-new", "type": "HTTPS", "name": "example.com", "content": ". alpn=h2",
				"ttl": 1, "locked": true,
				"meta":               map[string]any{"managed_by_apps": true},
				"data":               map[string]any{"priority": 1, "target": "."},
				"provider_new_field": map[string]any{"future": true},
			},
		}, map[string]any{"page": 1, "per_page": 2, "total_pages": 2})
	})

	page, err := client.ListDNSRecords(context.Background(), testAuth(), "zone-1", provider.PageRequest{PerPage: 2, Search: "api"})
	if err != nil {
		t.Fatalf("ListDNSRecords: %v", err)
	}
	if page.NextCursor != "2" || len(page.Records) != 2 {
		t.Fatalf("page = %+v", page)
	}
	first := page.Records[0]
	if first.ProviderID != "record-a" || first.Priority == nil || *first.Priority != 10 || !first.Proxied || !first.Proxiable {
		t.Errorf("first record = %+v", first)
	}
	unknown := page.Records[1]
	if unknown.Type != domain.RecordType("HTTPS") || unknown.Type.Editable() || !unknown.Managed {
		t.Errorf("unknown record = %+v", unknown)
	}
	if !strings.Contains(string(unknown.Raw), "provider_new_field") || !strings.Contains(string(unknown.Data), "target") {
		t.Errorf("raw/data not preserved: raw=%s data=%s", unknown.Raw, unknown.Data)
	}
	if unknown.LastSyncedAt == nil || !unknown.LastSyncedAt.Equal(fixedNow) {
		t.Errorf("sync time = %v", unknown.LastSyncedAt)
	}
}

func TestDNSRecordCRUDAndPayloadMapping(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	methods := make([]string, 0, 4)
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1":
			writeResult(t, w, map[string]any{"id": "record-1", "type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 1}, nil)
		case r.Method == http.MethodPost && r.URL.Path == "/client/v4/zones/zone-1/dns_records":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode create: %v", err)
			}
			if body["name"] != "xn--bcher-kva.example" || body["type"] != "A" || body["ttl"] != float64(1) || body["proxied"] != true {
				t.Errorf("create body = %#v", body)
			}
			writeResult(t, w, map[string]any{"id": "record-2", "type": "A", "name": body["name"], "content": body["content"], "ttl": 1, "proxied": true, "proxiable": true}, nil)
		case r.Method == http.MethodPatch && r.URL.Path == "/client/v4/zones/zone-1/dns_records/record-2":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode patch: %v", err)
			}
			if body["content"] != "192.0.2.22" || body["proxied"] != false || body["comment"] != "updated" {
				t.Errorf("patch body = %#v", body)
			}
			writeResult(t, w, map[string]any{"id": "record-2", "type": "A", "name": body["name"], "content": body["content"], "ttl": 300, "proxied": false, "comment": "updated"}, nil)
		case r.Method == http.MethodDelete && r.URL.Path == "/client/v4/zones/zone-1/dns_records/record-2":
			writeResult(t, w, map[string]any{"id": "record-2"}, nil)
		default:
			http.NotFound(w, r)
		}
	})

	got, err := client.GetDNSRecord(context.Background(), testAuth(), "zone-1", "record-1")
	if err != nil || got.Content != "192.0.2.1" {
		t.Fatalf("GetDNSRecord = %+v, %v", got, err)
	}
	created, err := client.CreateDNSRecord(context.Background(), testAuth(), "zone-1", domain.DNSRecord{
		Type: domain.RecordA, Name: "bücher.example", Content: "192.0.2.2", Proxied: true,
	})
	if err != nil || created.ProviderID != "record-2" || created.UnicodeName != "bücher.example" {
		t.Fatalf("CreateDNSRecord = %+v, %v", created, err)
	}
	patched, err := client.PatchDNSRecord(context.Background(), testAuth(), "zone-1", "record-2", domain.DNSRecord{
		Type: domain.RecordA, Name: "xn--bcher-kva.example", Content: "192.0.2.22", TTL: 300, Comment: "updated",
	})
	if err != nil || patched.Content != "192.0.2.22" || patched.Proxied {
		t.Fatalf("PatchDNSRecord = %+v, %v", patched, err)
	}
	if err := client.DeleteDNSRecord(context.Background(), testAuth(), "zone-1", "record-2"); err != nil {
		t.Fatalf("DeleteDNSRecord: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(methods) != 4 {
		t.Errorf("methods = %v", methods)
	}
}

func TestDNSBatchUsesCloudflareOperationBuckets(t *testing.T) {
	t.Parallel()
	priority := uint16(20)
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/client/v4/zones/zone-1/dns_records/batch" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Deletes []map[string]any `json:"deletes"`
			Patches []map[string]any `json:"patches"`
			Puts    []map[string]any `json:"puts"`
			Posts   []map[string]any `json:"posts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode batch: %v", err)
		}
		if len(body.Deletes) != 1 || body.Deletes[0]["id"] != "delete-id" ||
			len(body.Patches) != 1 || body.Patches[0]["id"] != "patch-id" ||
			len(body.Puts) != 1 || body.Puts[0]["id"] != "put-id" || len(body.Posts) != 1 {
			t.Errorf("batch body = %#v", body)
		}
		writeResult(t, w, map[string]any{
			"deletes": []any{map[string]any{"id": "delete-id"}},
			"patches": []any{map[string]any{"id": "patch-id", "type": "A", "name": "patch.example.com", "content": "192.0.2.20", "ttl": 60}},
			"puts":    []any{map[string]any{"id": "put-id", "type": "MX", "name": "example.com", "content": "mail.example.com", "priority": 20, "ttl": 300}},
			"posts":   []any{map[string]any{"id": "post-id", "type": "TXT", "name": "new.example.com", "content": "hello", "ttl": 60}},
		}, nil)
	})

	mutations := []domain.DNSMutation{
		{Kind: domain.MutationCreate, After: &domain.DNSRecord{Type: domain.RecordTXT, Name: "new.example.com", Content: "hello", TTL: 60}},
		{Kind: domain.MutationDelete, RecordID: "delete-id"},
		{Kind: domain.MutationReplace, RecordID: "put-id", After: &domain.DNSRecord{Type: domain.RecordMX, Name: "example.com", Content: "mail.example.com", Priority: &priority, TTL: 300}},
		{Kind: domain.MutationPatch, RecordID: "patch-id", After: &domain.DNSRecord{Type: domain.RecordA, Name: "patch.example.com", Content: "192.0.2.20", TTL: 60}},
	}
	records, err := client.ApplyDNSBatch(context.Background(), testAuth(), "zone-1", mutations)
	if err != nil {
		t.Fatalf("ApplyDNSBatch: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("records = %+v", records)
	}
	got := []string{records[0].ID, records[1].ID, records[2].ID, records[3].ID}
	want := []string{"delete-id", "patch-id", "put-id", "post-id"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result order = %v, want %v", got, want)
			break
		}
	}
}

func TestDNS01CleanupDeletesOnlyReturnedRecordID(t *testing.T) {
	t.Parallel()
	var calls []string
	var mu sync.Mutex
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/client/v4/zones/zone-1/dns_records":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode challenge: %v", err)
			}
			if body["type"] != "TXT" || body["name"] != "_acme-challenge.example.com" || body["content"] != "challenge-value" {
				t.Errorf("challenge body = %#v", body)
			}
			if !strings.Contains(body["comment"].(string), "job-42") {
				t.Errorf("challenge comment = %q", body["comment"])
			}
			writeResult(t, w, map[string]any{
				"id": "exact-created-id", "type": "TXT", "name": body["name"], "content": body["content"], "ttl": 60,
			}, nil)
		case r.Method == http.MethodDelete && r.URL.Path == "/client/v4/zones/zone-1/dns_records/exact-created-id":
			writeResult(t, w, map[string]any{"id": "exact-created-id"}, nil)
		default:
			http.NotFound(w, r)
		}
	})

	recordID, err := client.PresentDNS01(context.Background(), testAuth(), "zone-1", "_acme-challenge.example.com.", "challenge-value", "job-42")
	if err != nil || recordID != "exact-created-id" {
		t.Fatalf("PresentDNS01 = %q, %v", recordID, err)
	}
	if err := client.CleanupDNS01(context.Background(), testAuth(), "zone-1", recordID); err != nil {
		t.Fatalf("CleanupDNS01: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || strings.Contains(strings.Join(calls, " "), "GET") {
		t.Errorf("challenge calls = %v", calls)
	}
}

func TestDNS01RecoveryMatchesJobAndValueAndCleanupIsIdempotent(t *testing.T) {
	t.Parallel()
	value := "challenge-value"
	digest := sha256.Sum256([]byte(value))
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records":
			if r.URL.Query().Get("search") != "_acme-challenge.example.com" {
				t.Errorf("recovery search = %q", r.URL.Query().Get("search"))
			}
			writeResult(t, w, []any{
				map[string]any{"id": "other", "type": "TXT", "name": "_acme-challenge.example.com", "content": value, "comment": "DomainOps ACME DNS-01 job=another"},
				map[string]any{"id": "recovered", "type": "TXT", "name": "_acme-challenge.example.com", "content": value, "comment": "DomainOps ACME DNS-01 job=job-42"},
			}, map[string]any{"page": 1, "total_pages": 1})
		case r.Method == http.MethodDelete && r.URL.Path == "/client/v4/zones/zone-1/dns_records/recovered":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 81044, "message": "record does not exist"}}, "result": nil})
		default:
			http.NotFound(w, r)
		}
	})
	recordID, found, err := client.ReconcileDNS01(context.Background(), testAuth(), "zone-1", "_acme-challenge.example.com.", hex.EncodeToString(digest[:]), "job-42")
	if err != nil || !found || recordID != "recovered" {
		t.Fatalf("ReconcileDNS01 = %q, %v, %v", recordID, found, err)
	}
	if err := client.CleanupDNS01(context.Background(), testAuth(), "zone-1", recordID); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
}

func TestRejectsReadOnlyRecordsBeforeNetwork(t *testing.T) {
	t.Parallel()
	var called bool
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})

	_, err := client.CreateDNSRecord(context.Background(), testAuth(), "zone", domain.DNSRecord{Type: domain.RecordType("HTTPS"), Name: "example.com"})
	if !errors.Is(err, ErrUnsupportedRecordType) {
		t.Errorf("unknown type error = %v", err)
	}
	_, err = client.PatchDNSRecord(context.Background(), testAuth(), "zone", "record", domain.DNSRecord{Type: domain.RecordA, Name: "example.com", Managed: true})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Errorf("managed record error = %v", err)
	}
	if called {
		t.Error("read-only validation contacted Cloudflare")
	}
}

func TestStructuredRecordPayloadSelection(t *testing.T) {
	t.Parallel()
	caaData := json.RawMessage(`{"flags":0,"tag":"issue","value":"letsencrypt.org"}`)
	payload, err := makeRecordPayload(domain.DNSRecord{Type: domain.RecordCAA, Name: "example.com", Content: "ignored", Data: caaData})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["content"]; ok || payload["data"] == nil {
		t.Fatalf("structured CAA payload = %#v", payload)
	}

	payload, err = makeRecordPayload(domain.DNSRecord{Type: domain.RecordCAA, Name: "example.com", Content: `0 issue "letsencrypt.org"`, Data: json.RawMessage("null")})
	if err != nil {
		t.Fatal(err)
	}
	if payload["content"] == nil || payload["data"] != nil {
		t.Fatalf("CAA content fallback payload = %#v", payload)
	}

	payload, err = makeRecordPayload(domain.DNSRecord{Type: domain.RecordA, Name: "example.com", Content: "192.0.2.1", Data: caaData})
	if err != nil {
		t.Fatal(err)
	}
	if payload["content"] != "192.0.2.1" || payload["data"] != nil {
		t.Fatalf("unstructured A payload = %#v", payload)
	}
}
