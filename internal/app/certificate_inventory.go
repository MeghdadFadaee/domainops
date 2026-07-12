package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/certificates"
	"github.com/MeghdadFadaee/domainops/internal/domain"
)

type CertificateInventoryItem struct {
	Lineage     domain.CertificateLineage  `json:"lineage"`
	Current     *domain.CertificateVersion `json:"current,omitempty"`
	Environment string                     `json:"environment"`
	Status      string                     `json:"status"`
}

func (s *Service) CertificateInventory(ctx context.Context) ([]CertificateInventoryItem, error) {
	lineages, err := s.repo.ListCertificateLineages(ctx)
	if err != nil {
		return nil, err
	}
	environmentByAccount := make(map[string]string)
	for _, environment := range []string{certificates.EnvironmentStaging, certificates.EnvironmentProduction} {
		account, accountErr := s.repo.GetACMEAccountByEnvironment(ctx, environment)
		if accountErr == nil {
			environmentByAccount[account.ID] = environment
		} else if !errors.Is(accountErr, sql.ErrNoRows) {
			return nil, fmt.Errorf("load %s ACME account for inventory: %w", environment, accountErr)
		}
	}
	now := s.now().UTC()
	items := make([]CertificateInventoryItem, 0, len(lineages))
	for _, lineage := range lineages {
		item := CertificateInventoryItem{Lineage: lineage, Environment: environmentByAccount[lineage.ACMEAccountID], Status: "missing"}
		if lineage.Source == domain.CertificateImported {
			item.Environment = "external"
		}
		if item.Environment == "" {
			item.Environment = "unknown"
		}
		versions, versionErr := s.repo.ListCertificateVersions(ctx, lineage.ID)
		if versionErr != nil {
			return nil, versionErr
		}
		for index := range versions {
			if versions[index].ID != lineage.CurrentVersionID {
				continue
			}
			current := versions[index]
			item.Current = &current
			item.Status = certificateStatus(current, now)
			break
		}
		items = append(items, item)
	}
	return items, nil
}

func certificateStatus(version domain.CertificateVersion, now time.Time) string {
	if version.RevokedAt != nil {
		return "revoked"
	}
	if version.RevocationPendingAt != nil {
		return "revocation-pending"
	}
	if !now.Before(version.NotAfter) {
		return "expired"
	}
	due := version.RenewalWindowStart
	if due == nil {
		value := version.NotBefore.Add(version.NotAfter.Sub(version.NotBefore) * 2 / 3)
		due = &value
	}
	if !now.Before(*due) {
		return "due"
	}
	return "valid"
}
