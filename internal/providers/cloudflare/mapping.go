package cloudflare

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"golang.org/x/net/idna"
)

type accountWire struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedOn string `json:"created_on"`
}

func mapAccount(w accountWire) domain.RemoteAccount {
	return domain.RemoteAccount{
		ID:         w.ID,
		Provider:   domain.ProviderCloudflare,
		ProviderID: w.ID,
		Name:       w.Name,
		CreatedAt:  parseTimeValue(w.CreatedOn),
	}
}

type zoneWire struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Status      string      `json:"status"`
	Paused      bool        `json:"paused"`
	NameServers []string    `json:"name_servers"`
	ModifiedOn  string      `json:"modified_on"`
	Account     accountWire `json:"account"`
	Plan        struct {
		Name string `json:"name"`
	} `json:"plan"`
}

func mapZone(w zoneWire, credentialID string, syncedAt time.Time) domain.Zone {
	modified := optionalTime(w.ModifiedOn)
	synced := syncedAt
	return domain.Zone{
		ID:                    w.ID,
		Provider:              domain.ProviderCloudflare,
		ProviderID:            w.ID,
		AccountID:             w.Account.ID,
		PreferredCredentialID: credentialID,
		Name:                  w.Name,
		UnicodeName:           toUnicodeName(w.Name),
		Status:                mapZoneStatus(w.Status),
		Paused:                w.Paused,
		Plan:                  w.Plan.Name,
		NameServers:           append([]string(nil), w.NameServers...),
		ModifiedAt:            modified,
		LastSyncedAt:          &synced,
	}
}

func mapZoneStatus(status string) domain.ZoneStatus {
	switch strings.ToLower(status) {
	case string(domain.ZoneActive):
		return domain.ZoneActive
	case string(domain.ZonePending):
		return domain.ZonePending
	case string(domain.ZoneInitializing):
		return domain.ZoneInitializing
	case string(domain.ZoneMoved):
		return domain.ZoneMoved
	case string(domain.ZoneDeactivated):
		return domain.ZoneDeactivated
	default:
		return domain.ZoneUnknown
	}
}

type recordWire struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Content    string          `json:"content"`
	Priority   json.Number     `json:"priority"`
	TTL        int             `json:"ttl"`
	Proxied    bool            `json:"proxied"`
	Proxiable  bool            `json:"proxiable"`
	Comment    string          `json:"comment"`
	Tags       []string        `json:"tags"`
	Locked     bool            `json:"locked"`
	Data       json.RawMessage `json:"data"`
	Meta       json.RawMessage `json:"meta"`
	ModifiedOn string          `json:"modified_on"`
}

func mapRecord(raw json.RawMessage, zoneID string, syncedAt time.Time) (domain.DNSRecord, error) {
	var w recordWire
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&w); err != nil {
		return domain.DNSRecord{}, fmt.Errorf("cloudflare: decode DNS record: %w", err)
	}
	priority := parsePriority(w.Priority)
	modified := optionalTime(w.ModifiedOn)
	synced := syncedAt
	return domain.DNSRecord{
		ID:           w.ID,
		ProviderID:   w.ID,
		ZoneID:       zoneID,
		Type:         domain.RecordType(strings.ToUpper(w.Type)),
		Name:         w.Name,
		UnicodeName:  toUnicodeName(w.Name),
		Content:      w.Content,
		Priority:     priority,
		TTL:          w.TTL,
		Proxied:      w.Proxied,
		Proxiable:    w.Proxiable,
		Comment:      w.Comment,
		Tags:         append([]string(nil), w.Tags...),
		Managed:      w.Locked || metaManaged(w.Meta),
		Data:         cloneRaw(w.Data),
		Raw:          cloneRaw(raw),
		ModifiedAt:   modified,
		LastSyncedAt: &synced,
	}, nil
}

func parsePriority(number json.Number) *uint16 {
	if number == "" {
		return nil
	}
	value, err := number.Int64()
	if err != nil || value < 0 || value > 65535 {
		return nil
	}
	priority := uint16(value)
	return &priority
}

func metaManaged(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var values map[string]any
	if json.Unmarshal(raw, &values) != nil {
		return false
	}
	for _, key := range []string{"auto_added", "managed_by_apps", "managed_by_argo_tunnel", "managed_by_tunnel"} {
		if value, ok := values[key].(bool); ok && value {
			return true
		}
	}
	return false
}

func parseTimeValue(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func optionalTime(value string) *time.Time {
	parsed := parseTimeValue(value)
	if parsed.IsZero() {
		return nil
	}
	return &parsed
}

func toASCIIName(name string) (string, error) {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	if name == "" {
		return "", &ValidationError{Field: "record.name", Message: "name is required"}
	}
	if isASCII(name) {
		return strings.ToLower(name), nil
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "" || label == "*" || strings.HasPrefix(label, "_") {
			continue
		}
		encoded, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", &ValidationError{Field: "record.name", Message: err.Error()}
		}
		labels[i] = encoded
	}
	return strings.ToLower(strings.Join(labels, ".")), nil
}

func toUnicodeName(name string) string {
	if !strings.Contains(strings.ToLower(name), "xn--") {
		return ""
	}
	labels := strings.Split(name, ".")
	changed := false
	for i, label := range labels {
		decoded, err := idna.Lookup.ToUnicode(label)
		if err == nil && decoded != label {
			labels[i] = decoded
			changed = true
		}
	}
	if !changed {
		return ""
	}
	return strings.Join(labels, ".")
}

func isASCII(value string) bool {
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r > 127 {
			return false
		}
		value = value[size:]
	}
	return true
}
