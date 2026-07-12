package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func saveDNSRecord(ctx context.Context, exec sqlExecer, value domain.DNSRecord) error {
	tags, err := encodeJSON(value.Tags)
	if err != nil {
		return fmt.Errorf("encode tags: %w", err)
	}
	var priority any
	if value.Priority != nil {
		priority = int64(*value.Priority)
	}
	_, err = exec.ExecContext(ctx, `INSERT INTO dns_records (
        id, provider_id, zone_id, type, name, unicode_name, content, priority,
        ttl, proxied, proxiable, comment, tags_json, managed, data_json, raw_json,
        modified_at, last_synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET provider_id=excluded.provider_id,
        zone_id=excluded.zone_id, type=excluded.type, name=excluded.name,
        unicode_name=excluded.unicode_name, content=excluded.content,
        priority=excluded.priority, ttl=excluded.ttl, proxied=excluded.proxied,
        proxiable=excluded.proxiable, comment=excluded.comment, tags_json=excluded.tags_json,
        managed=excluded.managed, data_json=excluded.data_json, raw_json=excluded.raw_json,
        modified_at=excluded.modified_at, last_synced_at=excluded.last_synced_at`,
		value.ID, value.ProviderID, value.ZoneID, string(value.Type), value.Name,
		value.UnicodeName, value.Content, priority, value.TTL, value.Proxied,
		value.Proxiable, value.Comment, tags, value.Managed, rawOrNil(value.Data),
		rawOrNil(value.Raw), encodeOptionalTime(value.ModifiedAt), encodeOptionalTime(value.LastSyncedAt))
	return err
}

func (r *Repository) ReplaceDNSRecords(ctx context.Context, zoneID string, values []domain.DNSRecord, syncedAt time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin DNS replacement: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM dns_records WHERE zone_id = ?", zoneID); err != nil {
		return fmt.Errorf("sqlite: clear DNS records: %w", err)
	}
	for _, value := range values {
		if value.ZoneID != zoneID {
			return fmt.Errorf("sqlite: DNS record %s belongs to zone %s, expected %s", value.ID, value.ZoneID, zoneID)
		}
		value.LastSyncedAt = &syncedAt
		if err := saveDNSRecord(ctx, tx, value); err != nil {
			return fmt.Errorf("sqlite: replace DNS record %s: %w", value.ID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO zone_dns_sync(zone_id, synced_at) VALUES (?, ?)
        ON CONFLICT(zone_id) DO UPDATE SET synced_at=excluded.synced_at`, zoneID, encodeTime(syncedAt)); err != nil {
		return fmt.Errorf("sqlite: save DNS sync time: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit DNS replacement: %w", err)
	}
	return nil
}

const dnsColumns = `id, provider_id, zone_id, type, name, unicode_name, content,
    priority, ttl, proxied, proxiable, comment, tags_json, managed, data_json,
    raw_json, modified_at, last_synced_at`

func scanDNSRecord(scanner interface{ Scan(...any) error }) (domain.DNSRecord, error) {
	var value domain.DNSRecord
	var recordType, tags string
	var priority sql.NullInt64
	var data, raw []byte
	var modified, synced sql.NullString
	if err := scanner.Scan(&value.ID, &value.ProviderID, &value.ZoneID, &recordType,
		&value.Name, &value.UnicodeName, &value.Content, &priority, &value.TTL,
		&value.Proxied, &value.Proxiable, &value.Comment, &tags, &value.Managed,
		&data, &raw, &modified, &synced); err != nil {
		return value, err
	}
	value.Type = domain.RecordType(recordType)
	if priority.Valid {
		if priority.Int64 < 0 || priority.Int64 > math.MaxUint16 {
			return value, fmt.Errorf("invalid DNS priority %d", priority.Int64)
		}
		converted := uint16(priority.Int64)
		value.Priority = &converted
	}
	if err := decodeJSON(tags, &value.Tags); err != nil {
		return value, err
	}
	value.Data = copyRaw(data)
	value.Raw = copyRaw(raw)
	var err error
	if value.ModifiedAt, err = decodeOptionalTime(modified); err != nil {
		return value, err
	}
	if value.LastSyncedAt, err = decodeOptionalTime(synced); err != nil {
		return value, err
	}
	return value, nil
}

func (r *Repository) ListDNSRecords(ctx context.Context, zoneID string) ([]domain.DNSRecord, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+dnsColumns+` FROM dns_records
        WHERE zone_id = ? ORDER BY name COLLATE NOCASE, type, id`, zoneID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list DNS records: %w", err)
	}
	defer rows.Close()
	values := make([]domain.DNSRecord, 0)
	for rows.Next() {
		value, err := scanDNSRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan DNS record: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) SaveDNSRecord(ctx context.Context, value domain.DNSRecord) error {
	if err := saveDNSRecord(ctx, r.db, value); err != nil {
		return fmt.Errorf("sqlite: save DNS record: %w", err)
	}
	return nil
}

func (r *Repository) DeleteDNSRecord(ctx context.Context, id string) error {
	if _, err := r.db.ExecContext(ctx, "DELETE FROM dns_records WHERE id = ?", id); err != nil {
		return fmt.Errorf("sqlite: delete DNS record: %w", err)
	}
	return nil
}

func (r *Repository) SaveTLSSettings(ctx context.Context, value domain.EdgeTLSSettings) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO tls_settings (
        zone_id, mode, always_use_https, minimum_tls, tls_1_3, has_proxied_dns, last_synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(zone_id) DO UPDATE SET mode=excluded.mode,
        always_use_https=excluded.always_use_https, minimum_tls=excluded.minimum_tls,
        tls_1_3=excluded.tls_1_3, has_proxied_dns=excluded.has_proxied_dns,
        last_synced_at=excluded.last_synced_at`, value.ZoneID, value.Mode,
		value.AlwaysUseHTTPS, value.MinimumTLS, value.TLS13, value.HasProxiedDNS,
		encodeOptionalTime(value.LastSyncedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save TLS settings: %w", err)
	}
	return nil
}

func (r *Repository) GetTLSSettings(ctx context.Context, zoneID string) (domain.EdgeTLSSettings, error) {
	var value domain.EdgeTLSSettings
	var synced sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT zone_id, mode, always_use_https, minimum_tls,
        tls_1_3, has_proxied_dns, last_synced_at FROM tls_settings WHERE zone_id = ?`, zoneID).
		Scan(&value.ZoneID, &value.Mode, &value.AlwaysUseHTTPS, &value.MinimumTLS,
			&value.TLS13, &value.HasProxiedDNS, &synced)
	if err != nil {
		return value, fmt.Errorf("sqlite: get TLS settings: %w", err)
	}
	if value.LastSyncedAt, err = decodeOptionalTime(synced); err != nil {
		return value, fmt.Errorf("sqlite: decode TLS settings: %w", err)
	}
	return value, nil
}
