package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

type tokenVerificationWire struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// VerifyCredential verifies the correct token namespace, discovers accessible
// accounts, and performs real zone/DNS/settings reads. Cloudflare's verification
// response does not expose effective permission groups, so read probes never
// claim write access. DomainOps records write capability only after a real write
// succeeds and Cloudflare remains authoritative for every mutation.
func (c *Client) VerifyCredential(ctx context.Context, auth provider.Auth) (provider.Verification, error) {
	verification := provider.Verification{Status: domain.CredentialInvalid}
	if err := validateAuth(auth); err != nil {
		return verification, err
	}

	verifyPath := "user/tokens/verify"
	if auth.Kind == domain.CredentialAccountToken {
		var err error
		verifyPath, err = apiPath("accounts", auth.AccountID, "tokens", "verify")
		if err != nil {
			return verification, err
		}
	}
	raw, _, err := c.do(ctx, auth, http.MethodGet, verifyPath, nil, nil)
	if err != nil {
		return verification, err
	}
	var token tokenVerificationWire
	if err := json.Unmarshal(raw, &token); err != nil {
		return verification, &ResponseError{Resource: "token verification", Err: err}
	}
	if !strings.EqualFold(token.Status, "active") {
		return verification, nil
	}
	verification.Status = domain.CredentialValid

	syncedAt := c.now().UTC()
	accounts, err := c.discoverAccounts(ctx, auth)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode >= http.StatusInternalServerError || apiErr.StatusCode == http.StatusTooManyRequests {
			return verification, fmt.Errorf("cloudflare: discover accounts: %w", err)
		}
		// Some Cloudflare bearer tokens cannot use the legacy account listing
		// endpoints. Zone results remain the source of truth for discovery.
		accounts = nil
	}

	zones, _, _, zoneErr := c.listZones(ctx, auth, provider.PageRequest{Page: 1, PerPage: 50})
	if zoneErr == nil {
		verification.Capabilities.ZoneRead = true
		accounts = mergeAccounts(accounts, accountsFromZones(zones, syncedAt))
	} else if !errors.Is(zoneErr, ErrForbidden) {
		return verification, fmt.Errorf("cloudflare: probe zone access: %w", zoneErr)
	}

	if len(accounts) == 0 && auth.AccountID != "" {
		lastSynced := syncedAt
		accounts = []domain.RemoteAccount{{
			ID:           auth.AccountID,
			Provider:     domain.ProviderCloudflare,
			ProviderID:   auth.AccountID,
			Name:         auth.AccountID,
			LastSyncedAt: &lastSynced,
		}}
	}
	verification.Accounts = accounts

	if len(zones) > 0 {
		zoneID := zones[0].ID
		if err := c.probeDNSAccess(ctx, auth, zoneID); err == nil {
			verification.Capabilities.DNSRead = true
		} else if !errors.Is(err, ErrForbidden) {
			return verification, fmt.Errorf("cloudflare: probe DNS access: %w", err)
		}

		if err := c.probeTLSAccess(ctx, auth, zoneID); err == nil {
			verification.Capabilities.TLSRead = true
		} else if !errors.Is(err, ErrForbidden) {
			return verification, fmt.Errorf("cloudflare: probe TLS access: %w", err)
		}
	}
	sortCapabilityNames(&verification.Capabilities)
	return verification, nil
}

func (c *Client) discoverAccounts(ctx context.Context, auth provider.Auth) ([]domain.RemoteAccount, error) {
	syncedAt := c.now().UTC()
	if auth.AccountID != "" {
		path, err := apiPath("accounts", auth.AccountID)
		if err != nil {
			return nil, err
		}
		raw, _, err := c.do(ctx, auth, http.MethodGet, path, nil, nil)
		if errors.Is(err, ErrForbidden) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var wire accountWire
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, &ResponseError{Resource: "account", Err: err}
		}
		account := mapAccount(wire)
		account.LastSyncedAt = &syncedAt
		return []domain.RemoteAccount{account}, nil
	}

	const maxPages = 100
	var accounts []domain.RemoteAccount
	for page := 1; page <= maxPages; page++ {
		query := url.Values{
			"page":     {strconv.Itoa(page)},
			"per_page": {"50"},
		}
		raw, info, err := c.do(ctx, auth, http.MethodGet, "accounts", query, nil)
		if errors.Is(err, ErrForbidden) {
			return accounts, nil
		}
		if err != nil {
			return nil, err
		}
		var wires []accountWire
		if err := json.Unmarshal(raw, &wires); err != nil {
			return nil, &ResponseError{Resource: "accounts", Err: err}
		}
		for _, wire := range wires {
			account := mapAccount(wire)
			account.LastSyncedAt = &syncedAt
			accounts = append(accounts, account)
		}
		if info.TotalPages > 0 {
			if page >= info.TotalPages {
				return accounts, nil
			}
		} else if len(wires) < 50 {
			return accounts, nil
		}
	}
	return nil, &ResponseError{Resource: "accounts", Err: errors.New("pagination exceeded 100 pages")}
}

func (c *Client) probeDNSAccess(ctx context.Context, auth provider.Auth, zoneID string) error {
	path, err := apiPath("zones", zoneID, "dns_records")
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, auth, http.MethodGet, path, url.Values{"page": {"1"}, "per_page": {"1"}}, nil)
	return err
}

func (c *Client) probeTLSAccess(ctx context.Context, auth provider.Auth, zoneID string) error {
	path, err := apiPath("zones", zoneID, "settings", "ssl")
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, auth, http.MethodGet, path, nil, nil)
	return err
}
