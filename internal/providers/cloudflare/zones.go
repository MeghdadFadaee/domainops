package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

// ListZones lists one Cloudflare zone page and preserves the provider's stable
// zone and account identifiers for reconciliation.
func (c *Client) ListZones(ctx context.Context, auth provider.Auth, request provider.PageRequest) (provider.ZonePage, error) {
	wires, info, page, err := c.listZones(ctx, auth, request)
	if err != nil {
		return provider.ZonePage{}, err
	}
	syncedAt := c.now().UTC()
	zones := make([]domain.Zone, 0, len(wires))
	for _, wire := range wires {
		zones = append(zones, mapZone(wire, auth.CredentialID, syncedAt))
	}
	return provider.ZonePage{
		Zones:      zones,
		NextCursor: nextCursor(info, page, len(zones), queryPerPage(request, 50, 50)),
		Page:       page,
		TotalPages: info.TotalPages,
	}, nil
}

func (c *Client) listZones(ctx context.Context, auth provider.Auth, request provider.PageRequest) ([]zoneWire, resultInfo, int, error) {
	query, page := paginationQuery(request, 50, 50)
	if auth.AccountID != "" {
		query.Set("account.id", auth.AccountID)
	}
	if search := strings.TrimSpace(request.Search); search != "" {
		ascii, err := toASCIIName(search)
		if err != nil {
			return nil, resultInfo{}, 0, err
		}
		query.Set("name", ascii)
	}
	raw, info, err := c.do(ctx, auth, http.MethodGet, "zones", query, nil)
	if err != nil {
		return nil, resultInfo{}, 0, err
	}
	var zones []zoneWire
	if err := json.Unmarshal(raw, &zones); err != nil {
		return nil, resultInfo{}, 0, &ResponseError{Resource: "zones", Err: err}
	}
	return zones, info, page, nil
}

func queryPerPage(request provider.PageRequest, defaultValue, maximum int) int {
	value := request.PerPage
	if value <= 0 {
		value = defaultValue
	}
	if value > maximum {
		value = maximum
	}
	return value
}

func accountsFromZones(zones []zoneWire, syncedAt time.Time) []domain.RemoteAccount {
	seen := make(map[string]struct{})
	accounts := make([]domain.RemoteAccount, 0)
	for _, zone := range zones {
		if zone.Account.ID == "" {
			continue
		}
		if _, ok := seen[zone.Account.ID]; ok {
			continue
		}
		seen[zone.Account.ID] = struct{}{}
		account := mapAccount(zone.Account)
		timestamp := syncedAt
		account.LastSyncedAt = &timestamp
		accounts = append(accounts, account)
	}
	return accounts
}

func mergeAccounts(groups ...[]domain.RemoteAccount) []domain.RemoteAccount {
	byID := make(map[string]domain.RemoteAccount)
	order := make([]string, 0)
	for _, group := range groups {
		for _, account := range group {
			if account.ProviderID == "" {
				continue
			}
			if current, found := byID[account.ProviderID]; found {
				if current.Name == "" && account.Name != "" {
					current.Name = account.Name
				}
				if current.CreatedAt.IsZero() && !account.CreatedAt.IsZero() {
					current.CreatedAt = account.CreatedAt
				}
				if account.LastSyncedAt != nil {
					current.LastSyncedAt = account.LastSyncedAt
				}
				byID[account.ProviderID] = current
				continue
			}
			byID[account.ProviderID] = account
			order = append(order, account.ProviderID)
		}
	}
	result := make([]domain.RemoteAccount, 0, len(order))
	for _, id := range order {
		result = append(result, byID[id])
	}
	return result
}

func sortCapabilityNames(capabilities *provider.Capabilities) {
	capabilities.Names = capabilities.Names[:0]
	if capabilities.ZoneRead {
		capabilities.Names = append(capabilities.Names, "zone:read")
	}
	if capabilities.DNSRead {
		capabilities.Names = append(capabilities.Names, "dns:read")
	}
	if capabilities.DNSWrite {
		capabilities.Names = append(capabilities.Names, "dns:write")
	}
	if capabilities.TLSRead {
		capabilities.Names = append(capabilities.Names, "tls:read")
	}
	if capabilities.TLSWrite {
		capabilities.Names = append(capabilities.Names, "tls:write")
	}
	sort.Strings(capabilities.Names)
}
