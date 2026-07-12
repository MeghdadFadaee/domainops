package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

var fixedNow = time.Date(2026, time.July, 11, 9, 30, 0, 0, time.UTC)

func testAuth() provider.Auth {
	return provider.Auth{
		CredentialID: "cred-1",
		Token:        "test-secret-token",
		Kind:         domain.CredentialUserToken,
	}
}

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	client, err := NewWithOptions(Options{
		BaseURL:    "https://api.cloudflare.test/client/v4",
		HTTPClient: handlerDoer{handler: handler},
		UserAgent:  "DomainOps-test/1",
		Now:        func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	return client
}

type handlerDoer struct{ handler http.Handler }

func (d handlerDoer) Do(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	d.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func writeResult(t *testing.T, w http.ResponseWriter, result any, info any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{
		"success":  true,
		"errors":   []any{},
		"messages": []any{},
		"result":   result,
	}
	if info != nil {
		response["result_info"] = info
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func verifyRequestHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-secret-token" {
		t.Errorf("Authorization = %q", got)
	}
	if got := r.Header.Get("User-Agent"); got != "DomainOps-test/1" {
		t.Errorf("User-Agent = %q", got)
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
}

func TestNewWithOptionsRejectsInvalidBaseURL(t *testing.T) {
	t.Parallel()
	for _, baseURL := range []string{"ftp://api.example.test", "https:///missing-host", "https://example.test/?bad=1", "https://user:pass@example.test"} {
		if _, err := NewWithOptions(Options{BaseURL: baseURL}); err == nil {
			t.Errorf("NewWithOptions(%q) unexpectedly succeeded", baseURL)
		}
	}
}

func TestDNSNameConversionPreservesServiceAndWildcardLabels(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"*.bücher.example.":               "*.xn--bcher-kva.example",
		"_acme-challenge.bücher.example.": "_acme-challenge.xn--bcher-kva.example",
	} {
		got, err := toASCIIName(input)
		if err != nil {
			t.Errorf("toASCIIName(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("toASCIIName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVerifyCredentialUserTokenAndCapabilityProbes(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		verifyRequestHeaders(t, r)
		switch r.URL.Path {
		case "/client/v4/user/tokens/verify":
			writeResult(t, w, map[string]any{"id": "token-1", "status": "active"}, nil)
		case "/client/v4/accounts":
			writeResult(t, w, []any{
				map[string]any{"id": "acct-1", "name": "Production", "created_on": "2024-01-02T03:04:05Z"},
				map[string]any{"id": "acct-2", "name": "Labs"},
			}, map[string]any{"page": 1, "per_page": 50, "total_pages": 1})
		case "/client/v4/zones":
			if got := r.URL.Query().Get("per_page"); got != "50" {
				t.Errorf("zones per_page = %q", got)
			}
			writeResult(t, w, []any{map[string]any{
				"id": "zone-1", "name": "example.com", "status": "active",
				"account": map[string]any{"id": "acct-1", "name": "Production"},
			}}, map[string]any{"page": 1, "total_pages": 1})
		case "/client/v4/zones/zone-1/dns_records":
			writeResult(t, w, []any{}, map[string]any{"page": 1, "total_pages": 1})
		case "/client/v4/zones/zone-1/settings/ssl":
			writeResult(t, w, map[string]any{"id": "ssl", "value": "strict"}, nil)
		default:
			http.NotFound(w, r)
		}
	})

	verification, err := client.VerifyCredential(context.Background(), testAuth())
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if verification.Status != domain.CredentialValid {
		t.Fatalf("status = %q", verification.Status)
	}
	capabilities := verification.Capabilities
	if !capabilities.ZoneRead || !capabilities.DNSRead || capabilities.DNSWrite || !capabilities.TLSRead || capabilities.TLSWrite {
		t.Errorf("capabilities = %+v", capabilities)
	}
	if got, want := strings.Join(capabilities.Names, ","), "dns:read,tls:read,zone:read"; got != want {
		t.Errorf("capability names = %q, want %q", got, want)
	}
	if len(verification.Accounts) != 2 || verification.Accounts[0].ProviderID != "acct-1" {
		t.Fatalf("accounts = %+v", verification.Accounts)
	}
	if verification.Accounts[0].LastSyncedAt == nil || !verification.Accounts[0].LastSyncedAt.Equal(fixedNow) {
		t.Errorf("account sync timestamp = %v", verification.Accounts[0].LastSyncedAt)
	}
	if got := calls.Load(); got != 5 {
		t.Errorf("request count = %d, want 5", got)
	}
}

func TestVerifyCredentialAccountTokenUsesAccountNamespace(t *testing.T) {
	t.Parallel()
	auth := testAuth()
	auth.Kind = domain.CredentialAccountToken
	auth.AccountID = "account-owned"

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/v4/accounts/account-owned/tokens/verify":
			writeResult(t, w, map[string]any{"id": "token-2", "status": "active"}, nil)
		case "/client/v4/accounts/account-owned":
			writeResult(t, w, map[string]any{"id": "account-owned", "name": "Owned account"}, nil)
		case "/client/v4/zones":
			if got := r.URL.Query().Get("account.id"); got != "account-owned" {
				t.Errorf("account.id = %q", got)
			}
			writeResult(t, w, []any{}, map[string]any{"page": 1, "total_pages": 1})
		default:
			http.NotFound(w, r)
		}
	})

	verification, err := client.VerifyCredential(context.Background(), auth)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if verification.Status != domain.CredentialValid || len(verification.Accounts) != 1 {
		t.Fatalf("verification = %+v", verification)
	}
	if !verification.Capabilities.ZoneRead || verification.Capabilities.DNSRead {
		t.Errorf("capabilities = %+v", verification.Capabilities)
	}
}

func TestVerifyCredentialInactiveAndRejectsUnsupportedAuth(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writeResult(t, w, map[string]any{"id": "token", "status": "expired"}, nil)
	})

	verification, err := client.VerifyCredential(context.Background(), testAuth())
	if err != nil {
		t.Fatalf("expired token: %v", err)
	}
	if verification.Status != domain.CredentialInvalid || requests.Load() != 1 {
		t.Fatalf("verification = %+v, requests = %d", verification, requests.Load())
	}

	bad := testAuth()
	bad.Kind = domain.CredentialKind("global_api_key")
	_, err = client.VerifyCredential(context.Background(), bad)
	var validation *ValidationError
	if !errors.As(err, &validation) || requests.Load() != 1 {
		t.Fatalf("unsupported auth error = %v, requests = %d", err, requests.Load())
	}
}

func TestListZonesPaginationAndMapping(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client/v4/zones" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("page"); got != "2" {
			t.Errorf("page = %q", got)
		}
		if got := r.URL.Query().Get("name"); got != "example.com" {
			t.Errorf("name = %q", got)
		}
		writeResult(t, w, []any{map[string]any{
			"id": "zone-2", "name": "xn--bcher-kva.example", "status": "mystery", "paused": true,
			"modified_on": "2026-01-02T03:04:05.123Z",
			"account":     map[string]any{"id": "acct", "name": "Account"},
			"plan":        map[string]any{"name": "Pro"}, "name_servers": []string{"ada.ns.cloudflare.com"},
		}}, map[string]any{"page": 2, "per_page": 1, "total_pages": 3})
	})

	page, err := client.ListZones(context.Background(), testAuth(), provider.PageRequest{Cursor: "2", PerPage: 1, Search: "example.com"})
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if page.Page != 2 || page.NextCursor != "3" || page.TotalPages != 3 {
		t.Errorf("page metadata = %+v", page)
	}
	if len(page.Zones) != 1 {
		t.Fatalf("zones = %+v", page.Zones)
	}
	zone := page.Zones[0]
	if zone.ID != "zone-2" || zone.ProviderID != "zone-2" || zone.AccountID != "acct" || zone.Status != domain.ZoneUnknown || zone.Plan != "Pro" || !zone.Paused {
		t.Errorf("mapped zone = %+v", zone)
	}
	if zone.UnicodeName != "bücher.example" {
		t.Errorf("unicode name = %q", zone.UnicodeName)
	}
}

func TestStructuredAPIErrorsAndRateLimits(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.Header().Set("CF-Ray", "ray-test")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors": []any{map[string]any{
				"code": 1015, "message": "rate limit exceeded",
				"source": map[string]any{"pointer": "/zones"},
			}},
		})
	})

	_, err := client.ListZones(context.Background(), testAuth(), provider.PageRequest{})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error = %v", err)
	}
	var rateLimit *RateLimitError
	if !errors.As(err, &rateLimit) {
		t.Fatalf("not RateLimitError: %T", err)
	}
	if rateLimit.RetryAfter != 7*time.Second || !rateLimit.RetryAt.Equal(fixedNow.Add(7*time.Second)) {
		t.Errorf("rate metadata = %+v", rateLimit)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 1015 || apiErr.RequestID != "ray-test" || apiErr.Details[0].Pointer != "/zones" {
		t.Errorf("API error = %+v", apiErr)
	}
	if strings.Contains(err.Error(), testAuth().Token) {
		t.Error("error exposed API token")
	}
}

func TestSuccessfulHTTPEnvelopeRejectionIsDefinitive(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors": []any{map[string]any{
				"code": 1004, "message": "DNS validation failed",
			}},
		})
	})

	_, err := client.ListZones(context.Background(), testAuth(), provider.PageRequest{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", apiErr.StatusCode, http.StatusOK)
	}
	if !apiErr.MutationOutcomeDefinitive() {
		t.Fatal("HTTP 200 success:false rejection must be definitive")
	}
}

func TestSuccessfulHTTPEnvelopeRequiresExplicitSuccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing",
			body: map[string]any{"result": []any{}},
		},
		{
			name: "null",
			body: map[string]any{"success": nil, "result": []any{}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				if err := json.NewEncoder(w).Encode(test.body); err != nil {
					t.Errorf("encode response: %v", err)
				}
			})

			_, err := client.ListZones(context.Background(), testAuth(), provider.PageRequest{})
			var responseErr *ResponseError
			if !errors.As(err, &responseErr) {
				t.Fatalf("error = %T %v, want *ResponseError", err, err)
			}
			var definitive interface {
				MutationOutcomeDefinitive() bool
			}
			if errors.As(err, &definitive) && definitive.MutationOutcomeDefinitive() {
				t.Fatal("missing or null success must leave a mutation outcome ambiguous")
			}
		})
	}
}

func TestCredentialVerificationErrorClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "local invalid auth", err: &ValidationError{Field: "auth.kind", Message: "unsupported"}, want: true},
		{name: "unauthorized", err: &APIError{StatusCode: http.StatusUnauthorized}, want: true},
		{name: "forbidden", err: &APIError{StatusCode: http.StatusForbidden}, want: true},
		{name: "rate limited", err: newRateLimitError(&APIError{StatusCode: http.StatusTooManyRequests}, http.Header{}, fixedNow), want: false},
		{name: "server failure", err: &APIError{StatusCode: http.StatusBadGateway}, want: false},
		{name: "ambiguous response", err: &ResponseError{Resource: "token verification", Err: errors.New("malformed")}, want: false},
		{name: "network failure", err: errors.New("connection reset"), want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := provider.CredentialFailureIsAuthoritative(test.err); got != test.want {
				t.Fatalf("CredentialFailureIsAuthoritative(%T) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

func TestZoneAccessDenialClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "unauthorized", err: &APIError{StatusCode: http.StatusUnauthorized}, want: true},
		{name: "forbidden", err: &APIError{StatusCode: http.StatusForbidden}, want: true},
		{name: "rate limited", err: newRateLimitError(&APIError{StatusCode: http.StatusTooManyRequests}, http.Header{}, fixedNow), want: false},
		{name: "server failure", err: &APIError{StatusCode: http.StatusServiceUnavailable}, want: false},
		{name: "ambiguous response", err: &ResponseError{Resource: "DNS records", Err: errors.New("malformed")}, want: false},
		{name: "network failure", err: errors.New("connection reset"), want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := provider.AccessFailureIsAuthoritative(test.err); got != test.want {
				t.Fatalf("AccessFailureIsAuthoritative(%T) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
