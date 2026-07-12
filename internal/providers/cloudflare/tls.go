package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

const (
	settingSSL         = "ssl"
	settingAlwaysHTTPS = "always_use_https"
	settingMinimumTLS  = "min_tls_version"
	settingTLS13       = "tls_1_3"
)

type zoneSettingWire struct {
	ID       string          `json:"id"`
	Value    json.RawMessage `json:"value"`
	Editable bool            `json:"editable"`
}

// GetEdgeTLSSettings reads the four intentionally supported Cloudflare zone
// controls and independently determines whether the zone has proxied DNS.
func (c *Client) GetEdgeTLSSettings(ctx context.Context, auth provider.Auth, zoneID string) (domain.EdgeTLSSettings, error) {
	mode, err := c.getZoneSetting(ctx, auth, zoneID, settingSSL)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: read SSL mode: %w", err)
	}
	alwaysHTTPS, err := c.getZoneSetting(ctx, auth, zoneID, settingAlwaysHTTPS)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: read Always Use HTTPS: %w", err)
	}
	minimumTLS, err := c.getZoneSetting(ctx, auth, zoneID, settingMinimumTLS)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: read minimum TLS: %w", err)
	}
	tls13, err := c.getZoneSetting(ctx, auth, zoneID, settingTLS13)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: read TLS 1.3: %w", err)
	}
	hasProxiedDNS, err := c.hasProxiedDNS(ctx, auth, zoneID)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: inspect proxied DNS: %w", err)
	}
	syncedAt := c.now().UTC()
	return domain.EdgeTLSSettings{
		ZoneID:         zoneID,
		Mode:           settingString(mode),
		AlwaysUseHTTPS: settingEnabled(alwaysHTTPS),
		MinimumTLS:     settingString(minimumTLS),
		TLS13:          settingEnabled(tls13),
		HasProxiedDNS:  hasProxiedDNS,
		LastSyncedAt:   &syncedAt,
	}, nil
}

// UpdateEdgeTLSSettings applies the complete provider-neutral settings model.
// Cloudflare exposes these as separate endpoints, so the current exact values
// are read first and only changed settings are patched. A failure names the
// setting that did not apply; callers can immediately refresh to reconcile
// partial state.
func (c *Client) UpdateEdgeTLSSettings(ctx context.Context, auth provider.Auth, zoneID string, baseline, settings domain.EdgeTLSSettings) (domain.EdgeTLSSettings, error) {
	mode := strings.ToLower(strings.TrimSpace(settings.Mode))
	if !oneOf(mode, "off", "flexible", "full", "strict", "origin_pull") {
		return domain.EdgeTLSSettings{}, &ValidationError{Field: "tls.mode", Message: "must be off, flexible, full, strict, or origin_pull"}
	}
	minimumTLS := strings.TrimSpace(settings.MinimumTLS)
	if !oneOf(minimumTLS, "1.0", "1.1", "1.2", "1.3") {
		return domain.EdgeTLSSettings{}, &ValidationError{Field: "tls.minimum_tls", Message: "must be 1.0, 1.1, 1.2, or 1.3"}
	}

	desired := []struct {
		id            string
		baselineValue string
		value         string
		changed       bool
	}{
		{id: settingSSL, baselineValue: strings.ToLower(strings.TrimSpace(baseline.Mode)), value: mode, changed: !strings.EqualFold(strings.TrimSpace(baseline.Mode), mode)},
		{id: settingAlwaysHTTPS, baselineValue: onOff(baseline.AlwaysUseHTTPS), value: onOff(settings.AlwaysUseHTTPS), changed: baseline.AlwaysUseHTTPS != settings.AlwaysUseHTTPS},
		{id: settingMinimumTLS, baselineValue: strings.TrimSpace(baseline.MinimumTLS), value: minimumTLS, changed: strings.TrimSpace(baseline.MinimumTLS) != minimumTLS},
		{id: settingTLS13, baselineValue: onOff(baseline.TLS13), value: onOff(settings.TLS13), changed: baseline.TLS13 != settings.TLS13},
	}

	effective := make(map[string]zoneSettingWire, len(desired))
	for _, setting := range desired {
		current, err := c.getZoneSetting(ctx, auth, zoneID, setting.id)
		if err != nil {
			return domain.EdgeTLSSettings{}, markMutationNotAttempted(fmt.Errorf("cloudflare: read zone setting %s before update: %w", setting.id, err))
		}
		effective[setting.id] = current
	}

	// Validate every requested field against the caller's displayed baseline
	// before applying the first patch. Unrelated concurrent provider changes are
	// preserved; a concurrent change to a requested field fails closed.
	for _, update := range desired {
		if !update.changed {
			continue
		}
		if !edgeTLSSettingMatches(update.id, effective[update.id], baseline, update.baselineValue) {
			return domain.EdgeTLSSettings{}, &ValidationError{
				Field:   "tls." + update.id,
				Message: "changed remotely; refresh before retrying",
			}
		}
	}
	for _, update := range desired {
		if !update.changed {
			continue
		}
		updated, err := c.patchZoneSetting(ctx, auth, zoneID, update.id, update.value)
		if err != nil {
			return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: update zone setting %s: %w", update.id, err)
		}
		effective[update.id] = updated
	}
	hasProxiedDNS, err := c.hasProxiedDNS(ctx, auth, zoneID)
	if err != nil {
		return domain.EdgeTLSSettings{}, fmt.Errorf("cloudflare: inspect proxied DNS after update: %w", err)
	}
	syncedAt := c.now().UTC()
	return domain.EdgeTLSSettings{
		ZoneID:         zoneID,
		Mode:           settingString(effective[settingSSL]),
		AlwaysUseHTTPS: settingEnabled(effective[settingAlwaysHTTPS]),
		MinimumTLS:     settingString(effective[settingMinimumTLS]),
		TLS13:          settingEnabled(effective[settingTLS13]),
		HasProxiedDNS:  hasProxiedDNS,
		LastSyncedAt:   &syncedAt,
	}, nil
}

func edgeTLSSettingMatches(settingID string, current zoneSettingWire, desired domain.EdgeTLSSettings, desiredValue string) bool {
	if settingID == settingTLS13 {
		// TLS 1.3's provider-neutral model intentionally collapses Cloudflare's
		// "on" and "zrt" modes. Preserve either enabled mode when the caller
		// continues to request TLS 1.3 instead of silently disabling 0-RTT.
		currentValue := strings.ToLower(strings.TrimSpace(settingString(current)))
		if desired.TLS13 {
			return currentValue == "on" || currentValue == "zrt"
		}
		return currentValue == "off"
	}
	return strings.EqualFold(strings.TrimSpace(settingString(current)), strings.TrimSpace(desiredValue))
}

func (c *Client) getZoneSetting(ctx context.Context, auth provider.Auth, zoneID, settingID string) (zoneSettingWire, error) {
	path, err := apiPath("zones", zoneID, "settings", settingID)
	if err != nil {
		return zoneSettingWire{}, err
	}
	raw, _, err := c.do(ctx, auth, http.MethodGet, path, nil, nil)
	if err != nil {
		return zoneSettingWire{}, err
	}
	var setting zoneSettingWire
	if err := json.Unmarshal(raw, &setting); err != nil {
		return zoneSettingWire{}, &ResponseError{Resource: "zone setting " + settingID, Err: err}
	}
	return setting, nil
}

func (c *Client) patchZoneSetting(ctx context.Context, auth provider.Auth, zoneID, settingID, value string) (zoneSettingWire, error) {
	path, err := apiPath("zones", zoneID, "settings", settingID)
	if err != nil {
		return zoneSettingWire{}, err
	}
	raw, _, err := c.do(ctx, auth, http.MethodPatch, path, nil, map[string]string{"value": value})
	if err != nil {
		return zoneSettingWire{}, err
	}
	var setting zoneSettingWire
	if err := json.Unmarshal(raw, &setting); err != nil {
		return zoneSettingWire{}, &ResponseError{Resource: "zone setting " + settingID, Err: err}
	}
	return setting, nil
}

func (c *Client) hasProxiedDNS(ctx context.Context, auth provider.Auth, zoneID string) (bool, error) {
	path, err := apiPath("zones", zoneID, "dns_records")
	if err != nil {
		return false, err
	}
	query := url.Values{"page": {"1"}, "per_page": {"1"}, "proxied": {"true"}}
	raw, _, err := c.do(ctx, auth, http.MethodGet, path, query, nil)
	if err != nil {
		return false, err
	}
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		return false, &ResponseError{Resource: "proxied DNS records", Err: err}
	}
	return len(records) > 0, nil
}

func settingString(setting zoneSettingWire) string {
	var value string
	_ = json.Unmarshal(setting.Value, &value)
	return value
}

func settingEnabled(setting zoneSettingWire) bool {
	switch strings.ToLower(settingString(setting)) {
	case "on", "true", "zrt":
		return true
	default:
		return false
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

type certificatePackWire struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Status       string   `json:"status"`
	Hosts        []string `json:"hosts"`
	ExpiresOn    string   `json:"expires_on"`
	Certificates []struct {
		ID        string   `json:"id"`
		Status    string   `json:"status"`
		Hosts     []string `json:"hosts"`
		ExpiresOn string   `json:"expires_on"`
	} `json:"certificates"`
}

// ListEdgeCertificates inventories Cloudflare certificate packs. Expiry is the
// earliest certificate expiry in a pack, which is the conservative operational
// value for dashboard warnings.
func (c *Client) ListEdgeCertificates(ctx context.Context, auth provider.Auth, zoneID string, request provider.PageRequest) ([]domain.EdgeCertificate, error) {
	path, err := apiPath("zones", zoneID, "ssl", "certificate_packs")
	if err != nil {
		return nil, err
	}
	query, _ := paginationQuery(request, 50, 50)
	query.Set("status", "all")
	raw, _, err := c.do(ctx, auth, http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}
	var wires []certificatePackWire
	if err := json.Unmarshal(raw, &wires); err != nil {
		return nil, &ResponseError{Resource: "edge certificates", Err: err}
	}
	search := strings.ToLower(strings.TrimSpace(request.Search))
	certificates := make([]domain.EdgeCertificate, 0, len(wires))
	for _, wire := range wires {
		certificate := mapCertificatePack(wire, zoneID)
		if search != "" && !certificateMatches(certificate, search) {
			continue
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func mapCertificatePack(wire certificatePackWire, zoneID string) domain.EdgeCertificate {
	hosts := append([]string(nil), wire.Hosts...)
	seenHosts := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		seenHosts[host] = struct{}{}
	}
	var expiry *time.Time
	considerExpiry := func(value string) {
		candidate := optionalTime(value)
		if candidate != nil && (expiry == nil || candidate.Before(*expiry)) {
			expiry = candidate
		}
	}
	considerExpiry(wire.ExpiresOn)
	for _, child := range wire.Certificates {
		considerExpiry(child.ExpiresOn)
		for _, host := range child.Hosts {
			if _, exists := seenHosts[host]; exists {
				continue
			}
			seenHosts[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return domain.EdgeCertificate{
		ID:        wire.ID,
		ZoneID:    zoneID,
		Type:      wire.Type,
		Status:    wire.Status,
		Hosts:     hosts,
		ExpiresAt: expiry,
	}
}

func certificateMatches(certificate domain.EdgeCertificate, search string) bool {
	if strings.Contains(strings.ToLower(certificate.ID), search) ||
		strings.Contains(strings.ToLower(certificate.Type), search) ||
		strings.Contains(strings.ToLower(certificate.Status), search) {
		return true
	}
	for _, host := range certificate.Hosts {
		if strings.Contains(strings.ToLower(host), search) {
			return true
		}
	}
	return false
}
