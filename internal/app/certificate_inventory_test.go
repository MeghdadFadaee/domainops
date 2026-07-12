package app

import (
	"testing"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func TestCertificateStatus(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	notBefore, notAfter := now.Add(-60*24*time.Hour), now.Add(30*24*time.Hour)
	due := now.Add(-time.Hour)
	revoked := now.Add(-2 * time.Hour)
	for name, fixture := range map[string]struct {
		version domain.CertificateVersion
		want    string
	}{
		"valid":   {domain.CertificateVersion{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(89 * 24 * time.Hour)}, "valid"},
		"due":     {domain.CertificateVersion{NotBefore: notBefore, NotAfter: notAfter, RenewalWindowStart: &due}, "due"},
		"expired": {domain.CertificateVersion{NotBefore: notBefore, NotAfter: now.Add(-time.Second)}, "expired"},
		"revoked": {domain.CertificateVersion{NotBefore: notBefore, NotAfter: notAfter, RevokedAt: &revoked}, "revoked"},
		"pending": {domain.CertificateVersion{NotBefore: notBefore, NotAfter: notAfter, RevocationPendingAt: &revoked}, "revocation-pending"},
	} {
		if got := certificateStatus(fixture.version, now); got != fixture.want {
			t.Errorf("%s status = %q, want %q", name, got, fixture.want)
		}
	}
}
