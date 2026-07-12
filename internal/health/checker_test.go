package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func TestIssuesForObservation(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	endpoint := domain.ObservedEndpoint{
		ID: "endpoint", Host: "app.example.com", Port: 443,
		FingerprintSHA256: "bbbb", NotAfter: &expired, ValidForHost: false, Trusted: false,
	}
	issues := IssuesForObservation(endpoint, "aaaa", nil, now)
	want := map[string]bool{
		"served_certificate_expired":    false,
		"served_certificate_wrong_host": false,
		"served_certificate_untrusted":  false,
		"served_certificate_stale":      false,
	}
	for _, issue := range issues {
		if _, ok := want[issue.Kind]; ok {
			want[issue.Kind] = true
		}
		if issue.ID == "" || issue.ResourceID != endpoint.ID || !issue.ObservedAt.Equal(now) {
			t.Fatalf("invalid issue: %#v", issue)
		}
	}
	for kind, found := range want {
		if !found {
			t.Errorf("missing issue %s in %#v", kind, issues)
		}
	}

	revokedIssues := IssuesForObservation(domain.ObservedEndpoint{ID: "revoked-endpoint", Host: "example.com", FingerprintSHA256: "abcd", ValidForHost: true, Trusted: true}, "revoked:abcd", nil, now)
	if len(revokedIssues) != 1 || revokedIssues[0].Kind != "served_certificate_revoked" || revokedIssues[0].Severity != domain.SeverityCritical {
		t.Fatalf("revoked certificate issues = %#v", revokedIssues)
	}
	replacementIssues := IssuesForObservation(domain.ObservedEndpoint{ID: "replacement-endpoint", Host: "example.com", FingerprintSHA256: "ef01", ValidForHost: true, Trusted: true}, "revoked:abcd", nil, now)
	for _, issue := range replacementIssues {
		if issue.Kind == "served_certificate_stale" || issue.Kind == "served_certificate_revoked" {
			t.Fatalf("replacement for revoked certificate was flagged against the revoked fingerprint: %#v", replacementIssues)
		}
	}
	pendingIssues := IssuesForObservation(domain.ObservedEndpoint{ID: "pending-endpoint", Host: "example.com", FingerprintSHA256: "abcd", ValidForHost: true, Trusted: true}, "revocation-pending:abcd", nil, now)
	if len(pendingIssues) != 1 || pendingIssues[0].Kind != "certificate_revocation_pending" {
		t.Fatalf("pending revocation issues = %#v", pendingIssues)
	}

	failed := IssuesForObservation(endpoint, "", errors.New("connection refused"), now)
	if len(failed) != 1 || failed[0].Kind != "tls_probe_failed" || failed[0].Severity != domain.SeverityCritical {
		t.Fatalf("probe failure issues = %#v", failed)
	}
}

func TestCheckerUsesBoundedConcurrencyAndPersistsEveryEndpoint(t *testing.T) {
	var endpoints []domain.ObservedEndpoint
	for i := 0; i < 20; i++ {
		endpoints = append(endpoints, domain.ObservedEndpoint{ID: string(rune('a' + i)), ZoneID: "zone", Host: "example.com", Port: 443, Enabled: true})
	}
	repository := &checkerRepository{endpoints: endpoints}
	prober := &boundedProber{}
	checker := &Checker{Repository: repository, Prober: prober, Concurrency: 3, Now: func() time.Time { return time.Unix(100, 0).UTC() }}
	if err := checker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if maximum := prober.maximum.Load(); maximum > 3 {
		t.Fatalf("maximum concurrency = %d", maximum)
	}
	if got := repository.savedCount(); got != len(endpoints) {
		t.Fatalf("saved endpoints = %d, want %d", got, len(endpoints))
	}
}

type checkerRepository struct {
	mu        sync.Mutex
	endpoints []domain.ObservedEndpoint
	saved     []domain.ObservedEndpoint
	issues    map[string][]domain.HealthIssue
}

func (r *checkerRepository) ListEndpoints(context.Context) ([]domain.ObservedEndpoint, error) {
	return append([]domain.ObservedEndpoint(nil), r.endpoints...), nil
}
func (r *checkerRepository) SaveEndpoint(_ context.Context, endpoint domain.ObservedEndpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saved = append(r.saved, endpoint)
	return nil
}
func (r *checkerRepository) SaveHealthIssues(_ context.Context, owner string, issues []domain.HealthIssue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.issues == nil {
		r.issues = make(map[string][]domain.HealthIssue)
	}
	r.issues[owner] = append([]domain.HealthIssue(nil), issues...)
	return nil
}
func (r *checkerRepository) savedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.saved)
}

type boundedProber struct {
	active  atomic.Int32
	maximum atomic.Int32
}

func (p *boundedProber) Probe(ctx context.Context, endpoint domain.ObservedEndpoint) (domain.ObservedEndpoint, error) {
	active := p.active.Add(1)
	for {
		maximum := p.maximum.Load()
		if active <= maximum || p.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	defer p.active.Add(-1)
	select {
	case <-time.After(10 * time.Millisecond):
	case <-ctx.Done():
		return endpoint, ctx.Err()
	}
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	endpoint.LastCheckedAt = &now
	endpoint.NotAfter = &future
	endpoint.ValidForHost = true
	endpoint.Trusted = true
	return endpoint, nil
}
