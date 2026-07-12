package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/provider"
)

// ListDNSRecords lists one record page. Every provider response is retained in
// DNSRecord.Raw so record types introduced by Cloudflare remain visible and can
// be round-tripped through DomainOps storage without lossy decoding.
func (c *Client) ListDNSRecords(ctx context.Context, auth provider.Auth, zoneID string, request provider.PageRequest) (provider.RecordPage, error) {
	path, err := apiPath("zones", zoneID, "dns_records")
	if err != nil {
		return provider.RecordPage{}, err
	}
	query, page := paginationQuery(request, 100, 5000)
	if search := strings.TrimSpace(request.Search); search != "" {
		query.Set("search", search)
	}
	raw, info, err := c.do(ctx, auth, http.MethodGet, path, query, nil)
	if err != nil {
		return provider.RecordPage{}, err
	}
	records, err := c.mapRecordArray(raw, zoneID)
	if err != nil {
		return provider.RecordPage{}, err
	}
	return provider.RecordPage{
		Records:    records,
		NextCursor: nextCursor(info, page, len(records), queryPerPage(request, 100, 5000)),
		Page:       page,
		TotalPages: info.TotalPages,
	}, nil
}

// GetDNSRecord retrieves one record by its exact Cloudflare identifier.
func (c *Client) GetDNSRecord(ctx context.Context, auth provider.Auth, zoneID, recordID string) (domain.DNSRecord, error) {
	path, err := apiPath("zones", zoneID, "dns_records", recordID)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	raw, _, err := c.do(ctx, auth, http.MethodGet, path, nil, nil)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	return mapRecord(raw, zoneID, c.now().UTC())
}

// CreateDNSRecord creates one editable provider-neutral record.
func (c *Client) CreateDNSRecord(ctx context.Context, auth provider.Auth, zoneID string, record domain.DNSRecord) (domain.DNSRecord, error) {
	payload, err := makeRecordPayload(record)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	path, err := apiPath("zones", zoneID, "dns_records")
	if err != nil {
		return domain.DNSRecord{}, err
	}
	raw, _, err := c.do(ctx, auth, http.MethodPost, path, nil, payload)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	return mapRecord(raw, zoneID, c.now().UTC())
}

// PatchDNSRecord updates one record without replacing provider-managed fields.
func (c *Client) PatchDNSRecord(ctx context.Context, auth provider.Auth, zoneID, recordID string, record domain.DNSRecord) (domain.DNSRecord, error) {
	payload, err := makeRecordPayload(record)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	path, err := apiPath("zones", zoneID, "dns_records", recordID)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	raw, _, err := c.do(ctx, auth, http.MethodPatch, path, nil, payload)
	if err != nil {
		return domain.DNSRecord{}, err
	}
	return mapRecord(raw, zoneID, c.now().UTC())
}

// DeleteDNSRecord permanently removes the exact record identifier.
func (c *Client) DeleteDNSRecord(ctx context.Context, auth provider.Auth, zoneID, recordID string) error {
	path, err := apiPath("zones", zoneID, "dns_records", recordID)
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, auth, http.MethodDelete, path, nil, nil)
	return err
}

type dnsBatchPayload struct {
	Deletes []map[string]any `json:"deletes,omitempty"`
	Patches []map[string]any `json:"patches,omitempty"`
	Puts    []map[string]any `json:"puts,omitempty"`
	Posts   []map[string]any `json:"posts,omitempty"`
}

type dnsBatchResult struct {
	Deletes []json.RawMessage `json:"deletes"`
	Patches []json.RawMessage `json:"patches"`
	Puts    []json.RawMessage `json:"puts"`
	Posts   []json.RawMessage `json:"posts"`
}

// ApplyDNSBatch sends a zone-scoped Cloudflare batch. Results follow
// Cloudflare's documented execution order: deletes, patches, puts, then posts.
func (c *Client) ApplyDNSBatch(ctx context.Context, auth provider.Auth, zoneID string, mutations []domain.DNSMutation) ([]domain.DNSRecord, error) {
	if len(mutations) == 0 {
		return []domain.DNSRecord{}, nil
	}
	payload := dnsBatchPayload{}
	for index, mutation := range mutations {
		switch mutation.Kind {
		case domain.MutationCreate:
			if mutation.After == nil {
				return nil, mutationError(index, "create requires an after record")
			}
			record, err := makeRecordPayload(*mutation.After)
			if err != nil {
				return nil, fmt.Errorf("cloudflare: batch mutation %d: %w", index, err)
			}
			payload.Posts = append(payload.Posts, record)
		case domain.MutationPatch, domain.MutationReplace:
			if mutation.After == nil {
				return nil, mutationError(index, "update requires an after record")
			}
			id := mutationRecordID(mutation)
			if id == "" {
				return nil, mutationError(index, "update requires a record ID")
			}
			record, err := makeRecordPayload(*mutation.After)
			if err != nil {
				return nil, fmt.Errorf("cloudflare: batch mutation %d: %w", index, err)
			}
			record["id"] = id
			if mutation.Kind == domain.MutationPatch {
				payload.Patches = append(payload.Patches, record)
			} else {
				payload.Puts = append(payload.Puts, record)
			}
		case domain.MutationDelete:
			id := mutationRecordID(mutation)
			if id == "" {
				return nil, mutationError(index, "delete requires a record ID")
			}
			payload.Deletes = append(payload.Deletes, map[string]any{"id": id})
		default:
			return nil, mutationError(index, "unknown mutation kind "+string(mutation.Kind))
		}
	}

	path, err := apiPath("zones", zoneID, "dns_records", "batch")
	if err != nil {
		return nil, err
	}
	raw, _, err := c.do(ctx, auth, http.MethodPost, path, nil, payload)
	if err != nil {
		return nil, err
	}
	var batch dnsBatchResult
	if err := json.Unmarshal(raw, &batch); err != nil {
		return nil, &ResponseError{Resource: "DNS batch", Err: err}
	}
	ordered := make([]json.RawMessage, 0, len(batch.Deletes)+len(batch.Patches)+len(batch.Puts)+len(batch.Posts))
	ordered = append(ordered, batch.Deletes...)
	ordered = append(ordered, batch.Patches...)
	ordered = append(ordered, batch.Puts...)
	ordered = append(ordered, batch.Posts...)
	return c.mapRecordWires(ordered, zoneID)
}

// PresentDNS01 creates a single TXT challenge and returns the exact Cloudflare
// ID. The job identifier is recorded only as a non-secret provider comment.
func (c *Client) PresentDNS01(ctx context.Context, auth provider.Auth, zoneID, fqdn, value, jobID string) (string, error) {
	comment := "DomainOps ACME DNS-01"
	if jobID = strings.TrimSpace(jobID); jobID != "" {
		comment += " job=" + jobID
	}
	// Cloudflare DNS comments are bounded; trimming affects only diagnostics,
	// never the challenge owner or value.
	if len(comment) > 100 {
		comment = comment[:100]
	}
	record, err := c.CreateDNSRecord(ctx, auth, zoneID, domain.DNSRecord{
		ZoneID:  zoneID,
		Type:    domain.RecordTXT,
		Name:    fqdn,
		Content: value,
		TTL:     60,
		Comment: comment,
	})
	if err != nil {
		return "", err
	}
	id := record.ProviderID
	if id == "" {
		id = record.ID
	}
	if id == "" {
		return "", &ResponseError{Resource: "DNS-01 create", Err: errors.New("response omitted record ID")}
	}
	return id, nil
}

// CleanupDNS01 deletes only the exact record ID returned by PresentDNS01. It
// never searches by owner name or TXT value, avoiding removal of concurrent
// ACME challenges.
func (c *Client) CleanupDNS01(ctx context.Context, auth provider.Auth, zoneID, recordID string) error {
	err := c.DeleteDNSRecord(ctx, auth, zoneID, recordID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// ReconcileDNS01 locates a challenge after an ambiguous create response. The
// job marker is diagnostic rather than secret; the plaintext TXT value is
// compared only through its journaled SHA-256 digest.
func (c *Client) ReconcileDNS01(ctx context.Context, auth provider.Auth, zoneID, fqdn, valueHash, jobID string) (string, bool, error) {
	owner, err := toASCIIName(fqdn)
	if err != nil {
		return "", false, err
	}
	request := provider.PageRequest{Page: 1, PerPage: 100, Search: owner}
	var matches []string
	for {
		page, listErr := c.ListDNSRecords(ctx, auth, zoneID, request)
		if listErr != nil {
			return "", false, listErr
		}
		for _, record := range page.Records {
			if record.Type != domain.RecordTXT || !strings.EqualFold(strings.TrimSuffix(record.Name, "."), owner) || !commentContainsJob(record.Comment, jobID) {
				continue
			}
			digest := sha256.Sum256([]byte(record.Content))
			if !strings.EqualFold(hex.EncodeToString(digest[:]), strings.TrimSpace(valueHash)) {
				continue
			}
			id := record.ProviderID
			if id == "" {
				id = record.ID
			}
			if id != "" {
				matches = append(matches, id)
			}
		}
		if page.NextCursor == "" {
			break
		}
		request.Cursor = page.NextCursor
		if page.Page > 0 {
			request.Page = page.Page
		}
	}
	if len(matches) > 1 {
		return "", false, fmt.Errorf("cloudflare: DNS-01 recovery matched %d records for job %s", len(matches), jobID)
	}
	if len(matches) == 0 {
		return "", false, nil
	}
	return matches[0], true, nil
}

func commentContainsJob(comment, jobID string) bool {
	want := "job=" + strings.TrimSpace(jobID)
	if want == "job=" {
		return false
	}
	for _, field := range strings.Fields(comment) {
		if field == want {
			return true
		}
	}
	return false
}

func makeRecordPayload(record domain.DNSRecord) (map[string]any, error) {
	if record.Managed {
		return nil, &ValidationError{Field: "record.managed", Message: "Cloudflare-managed records are read-only"}
	}
	recordType := domain.RecordType(strings.ToUpper(string(record.Type)))
	if !recordType.Editable() {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedRecordType, recordType)
	}
	name, err := toASCIIName(record.Name)
	if err != nil {
		return nil, err
	}
	if record.TTL < 0 {
		return nil, &ValidationError{Field: "record.ttl", Message: "TTL cannot be negative"}
	}
	ttl := record.TTL
	if ttl == 0 {
		ttl = 1
	}
	payload := map[string]any{
		"type":    string(recordType),
		"name":    name,
		"ttl":     ttl,
		"comment": record.Comment,
		"tags":    append([]string(nil), record.Tags...),
	}
	structured := recordType == domain.RecordCAA || recordType == domain.RecordSRV
	hasData := len(record.Data) > 0 && string(record.Data) != "null"
	if !structured || !hasData {
		payload["content"] = record.Content
	}
	if record.Priority != nil {
		payload["priority"] = *record.Priority
	}
	if structured && hasData {
		if !json.Valid(record.Data) {
			return nil, &ValidationError{Field: "record.data", Message: "must contain valid JSON"}
		}
		payload["data"] = cloneRaw(record.Data)
	}
	if recordType == domain.RecordA || recordType == domain.RecordAAAA || recordType == domain.RecordCNAME {
		payload["proxied"] = record.Proxied
	}
	if settings := rawRecordField(record.Raw, "settings"); len(settings) > 0 && string(settings) != "null" {
		payload["settings"] = settings
	}
	return payload, nil
}

func rawRecordField(raw json.RawMessage, field string) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return nil
	}
	return cloneRaw(values[field])
}

func mutationRecordID(mutation domain.DNSMutation) string {
	if mutation.RecordID != "" {
		return mutation.RecordID
	}
	for _, record := range []*domain.DNSRecord{mutation.After, mutation.Before} {
		if record == nil {
			continue
		}
		if record.ProviderID != "" {
			return record.ProviderID
		}
		if record.ID != "" {
			return record.ID
		}
	}
	return ""
}

func mutationError(index int, message string) error {
	return &ValidationError{Field: fmt.Sprintf("mutations[%d]", index), Message: message}
}

func (c *Client) mapRecordArray(raw json.RawMessage, zoneID string) ([]domain.DNSRecord, error) {
	var wires []json.RawMessage
	if err := json.Unmarshal(raw, &wires); err != nil {
		return nil, &ResponseError{Resource: "DNS records", Err: err}
	}
	return c.mapRecordWires(wires, zoneID)
}

func (c *Client) mapRecordWires(wires []json.RawMessage, zoneID string) ([]domain.DNSRecord, error) {
	syncedAt := c.now().UTC()
	records := make([]domain.DNSRecord, 0, len(wires))
	for _, wire := range wires {
		record, err := mapRecord(wire, zoneID, syncedAt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}
