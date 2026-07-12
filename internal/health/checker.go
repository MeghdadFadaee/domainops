package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

type EndpointRepository interface {
	ListEndpoints(context.Context) ([]domain.ObservedEndpoint, error)
	SaveEndpoint(context.Context, domain.ObservedEndpoint) error
	SaveHealthIssues(context.Context, string, []domain.HealthIssue) error
}

type EndpointProber interface {
	Probe(context.Context, domain.ObservedEndpoint) (domain.ObservedEndpoint, error)
}

// ExpectedFingerprint returns the locally managed fingerprint expected on an
// endpoint. An empty string means no comparison is configured.
type ExpectedFingerprint func(context.Context, domain.ObservedEndpoint) (string, error)

type Checker struct {
	Repository          EndpointRepository
	Prober              EndpointProber
	ExpectedFingerprint ExpectedFingerprint
	Concurrency         int
	Interval            time.Duration
	Now                 func() time.Time
	OnError             func(error)
}

// RunOnce checks enabled endpoints with bounded concurrency. Individual probe
// failures become persisted endpoint issues and do not cancel other checks.
func (c *Checker) RunOnce(ctx context.Context) error {
	if c == nil || c.Repository == nil {
		return errors.New("health checker repository is required")
	}
	if c.Prober == nil {
		return errors.New("health checker prober is required")
	}
	endpoints, err := c.Repository.ListEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("list observed endpoints: %w", err)
	}
	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}

	jobs := make(chan domain.ObservedEndpoint)
	errs := make(chan error, len(endpoints)*3)
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for endpoint := range jobs {
				if ctx.Err() != nil {
					return
				}
				observed, probeErr := c.Prober.Probe(ctx, endpoint)
				if saveErr := c.Repository.SaveEndpoint(ctx, observed); saveErr != nil {
					errs <- fmt.Errorf("save endpoint %s: %w", endpoint.ID, saveErr)
				}
				expected := ""
				if c.ExpectedFingerprint != nil {
					value, fingerprintErr := c.ExpectedFingerprint(ctx, observed)
					if fingerprintErr != nil {
						errs <- fmt.Errorf("expected fingerprint for %s: %w", endpoint.ID, fingerprintErr)
					} else {
						expected = value
					}
				}
				issues := IssuesForObservation(observed, expected, probeErr, now().UTC())
				if saveErr := c.Repository.SaveHealthIssues(ctx, endpoint.ID, issues); saveErr != nil {
					errs <- fmt.Errorf("save endpoint issues %s: %w", endpoint.ID, saveErr)
				}
			}
		}()
	}

send:
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		select {
		case jobs <- endpoint:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	close(errs)

	var combined []error
	for workerErr := range errs {
		combined = append(combined, workerErr)
	}
	if ctx.Err() != nil {
		combined = append(combined, ctx.Err())
	}
	return errors.Join(combined...)
}

// Run checks immediately and then on every interval until cancellation.
// Transient cycle failures are reported but monitoring continues.
func (c *Checker) Run(ctx context.Context) error {
	if c == nil {
		return errors.New("health checker is nil")
	}
	interval := c.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	report := func(err error) {
		if err != nil && c.OnError != nil {
			c.OnError(err)
		}
	}
	report(c.RunOnce(ctx))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			report(c.RunOnce(ctx))
		}
	}
}

func IssuesForObservation(endpoint domain.ObservedEndpoint, expectedFingerprint string, probeErr error, now time.Time) []domain.HealthIssue {
	var issues []domain.HealthIssue
	add := func(severity domain.Severity, kind, title, detail, action string) {
		issues = append(issues, domain.HealthIssue{
			ID:         issueID(endpoint.ID, kind),
			Severity:   severity,
			Kind:       kind,
			ResourceID: endpoint.ID,
			Title:      title,
			Detail:     detail,
			Action:     action,
			ObservedAt: now.UTC(),
		})
	}
	if probeErr != nil {
		add(domain.SeverityCritical, "tls_probe_failed", "TLS endpoint is unreachable", probeErr.Error(), "Check DNS, firewall, port, and server TLS configuration")
		return issues
	}
	if endpoint.NotAfter != nil && !endpoint.NotAfter.After(now) {
		add(domain.SeverityCritical, "served_certificate_expired", "Served certificate is expired", "The public endpoint serves a certificate that expired at "+endpoint.NotAfter.UTC().Format(time.RFC3339), "Deploy a valid certificate immediately")
	}
	if !endpoint.ValidForHost {
		add(domain.SeverityCritical, "served_certificate_wrong_host", "Served certificate does not cover the hostname", "The certificate SANs do not validate "+endpoint.Host, "Deploy a certificate containing this hostname")
	}
	if !endpoint.Trusted {
		add(domain.SeverityWarning, "served_certificate_untrusted", "Served certificate chain is not publicly trusted", "The endpoint did not present a chain trusted by the configured root store", "Install the complete public certificate chain")
	}
	lowerExpected := strings.ToLower(expectedFingerprint)
	revocationPending := strings.HasPrefix(lowerExpected, "revocation-pending:")
	revokedFingerprint := strings.HasPrefix(lowerExpected, "revoked:")
	expectedFingerprint = strings.TrimPrefix(lowerExpected, "revocation-pending:")
	expectedFingerprint = strings.TrimPrefix(expectedFingerprint, "revoked:")
	expectedFingerprint = strings.ReplaceAll(expectedFingerprint, ":", "")
	observedFingerprint := strings.ToLower(strings.ReplaceAll(endpoint.FingerprintSHA256, ":", ""))
	if revocationPending {
		add(domain.SeverityWarning, "certificate_revocation_pending", "Certificate revocation status is unresolved", "A revocation request was recorded but its final CA result has not been reconciled locally", "Retry the revocation with the original reason before renewing or deploying this lineage")
	} else if revokedFingerprint && expectedFingerprint != "" && expectedFingerprint == observedFingerprint {
		add(domain.SeverityCritical, "served_certificate_revoked", "Endpoint still serves a revoked certificate", "The observed certificate was revoked by its issuing CA", "Deploy a new certificate immediately")
	} else if !revokedFingerprint && expectedFingerprint != "" && observedFingerprint != "" && expectedFingerprint != observedFingerprint {
		add(domain.SeverityWarning, "served_certificate_stale", "Endpoint serves a different certificate", "The observed fingerprint differs from the current locally managed certificate", "Deploy the current certificate and recheck")
	}
	return issues
}

func issueID(resourceID, kind string) string {
	digest := sha256.Sum256([]byte(resourceID + "\x00" + kind))
	return "issue_" + hex.EncodeToString(digest[:12])
}
