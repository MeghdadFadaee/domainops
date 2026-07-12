package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func (r *Repository) SaveCredential(ctx context.Context, value domain.Credential) error {
	capabilities, err := encodeJSON(value.Capabilities)
	if err != nil {
		return fmt.Errorf("sqlite: encode credential capabilities: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO credentials (
        id, provider, label, kind, account_hint, secret_ref, status, capabilities_json,
        created_at, last_verified_at, last_error
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        provider=excluded.provider, label=excluded.label, kind=excluded.kind,
        account_hint=excluded.account_hint, secret_ref=excluded.secret_ref,
        status=excluded.status, capabilities_json=excluded.capabilities_json,
        created_at=excluded.created_at, last_verified_at=excluded.last_verified_at,
        last_error=excluded.last_error`,
		value.ID, value.Provider, value.Label, string(value.Kind), value.AccountHint,
		value.SecretRef, string(value.Status), capabilities, encodeTime(value.CreatedAt),
		encodeOptionalTime(value.LastVerifiedAt), value.LastError)
	if err != nil {
		return fmt.Errorf("sqlite: save credential: %w", err)
	}
	return nil
}

func scanCredential(scanner interface{ Scan(...any) error }) (domain.Credential, error) {
	var value domain.Credential
	var kind, status, capabilities, created string
	var verified sql.NullString
	if err := scanner.Scan(&value.ID, &value.Provider, &value.Label, &kind, &value.AccountHint,
		&value.SecretRef, &status, &capabilities, &created, &verified, &value.LastError); err != nil {
		return value, err
	}
	value.Kind = domain.CredentialKind(kind)
	value.Status = domain.CredentialStatus(status)
	if err := decodeJSON(capabilities, &value.Capabilities); err != nil {
		return value, err
	}
	var err error
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, err
	}
	if value.LastVerifiedAt, err = decodeOptionalTime(verified); err != nil {
		return value, err
	}
	return value, nil
}

const credentialColumns = `id, provider, label, kind, account_hint, secret_ref, status,
    capabilities_json, created_at, last_verified_at, last_error`

func (r *Repository) ListCredentials(ctx context.Context) ([]domain.Credential, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+credentialColumns+" FROM credentials ORDER BY label COLLATE NOCASE, id")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list credentials: %w", err)
	}
	defer rows.Close()
	values := make([]domain.Credential, 0)
	for rows.Next() {
		value, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan credential: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) GetCredential(ctx context.Context, id string) (domain.Credential, error) {
	value, err := scanCredential(r.db.QueryRowContext(ctx, "SELECT "+credentialColumns+" FROM credentials WHERE id = ?", id))
	if err != nil {
		return value, fmt.Errorf("sqlite: get credential: %w", err)
	}
	return value, nil
}

func (r *Repository) DeleteCredential(ctx context.Context, id string) error {
	if _, err := r.db.ExecContext(ctx, "DELETE FROM credentials WHERE id = ?", id); err != nil {
		return fmt.Errorf("sqlite: delete credential: %w", err)
	}
	return nil
}

func (r *Repository) SaveCredentialZoneCapability(ctx context.Context, credentialID, zoneID, capability string, observedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO credential_zone_capabilities (
		credential_id, zone_id, capability, observed_at
	) VALUES (?, ?, ?, ?)
	ON CONFLICT(credential_id, zone_id, capability) DO UPDATE SET observed_at=excluded.observed_at`,
		credentialID, zoneID, capability, encodeTime(observedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save credential zone capability: %w", err)
	}
	return nil
}

func (r *Repository) HasCredentialZoneCapability(ctx context.Context, credentialID, zoneID, capability string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM credential_zone_capabilities
		WHERE credential_id = ? AND zone_id = ? AND capability = ?
	)`, credentialID, zoneID, capability).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("sqlite: get credential zone capability: %w", err)
	}
	return exists, nil
}

func (r *Repository) GetCredentialZoneCapability(ctx context.Context, credentialID, zoneID, capability string) (time.Time, bool, error) {
	var observedRaw string
	err := r.db.QueryRowContext(ctx, `SELECT observed_at FROM credential_zone_capabilities
		WHERE credential_id = ? AND zone_id = ? AND capability = ?`, credentialID, zoneID, capability).Scan(&observedRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("sqlite: get credential zone capability observation: %w", err)
	}
	observedAt, err := decodeTime(observedRaw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("sqlite: decode credential zone capability observation: %w", err)
	}
	return observedAt, true, nil
}

// InvalidateCredentialZoneCapability atomically removes exact per-zone
// authority and detaches the credential if it currently owns that route. The
// transaction prevents a crash between those two fail-closed state changes.
func (r *Repository) InvalidateCredentialZoneCapability(ctx context.Context, credentialID, zoneID, capability string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin credential zone capability invalidation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM credential_zone_capabilities
		WHERE credential_id = ? AND zone_id = ? AND capability = ?`, credentialID, zoneID, capability); err != nil {
		return fmt.Errorf("sqlite: delete credential zone capability: %w", err)
	}
	if capability == "dns:read" {
		if _, err := tx.ExecContext(ctx, `UPDATE zones SET preferred_credential_id = ''
			WHERE id = ? AND preferred_credential_id = ?`, zoneID, credentialID); err != nil {
			return fmt.Errorf("sqlite: detach invalid zone credential: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit credential zone capability invalidation: %w", err)
	}
	return nil
}

func (r *Repository) SaveAccounts(ctx context.Context, accounts []domain.RemoteAccount, links []domain.AccountCredential) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin account save: %w", err)
	}
	defer tx.Rollback()
	for _, value := range accounts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO accounts (
            id, provider, provider_id, name, created_at, last_synced_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,
            provider_id=excluded.provider_id, name=excluded.name,
            created_at=excluded.created_at, last_synced_at=excluded.last_synced_at`,
			value.ID, value.Provider, value.ProviderID, value.Name, encodeTime(value.CreatedAt),
			encodeOptionalTime(value.LastSyncedAt)); err != nil {
			return fmt.Errorf("sqlite: save account %s: %w", value.ID, err)
		}
	}
	for _, value := range links {
		if value.Preferred {
			if _, err := tx.ExecContext(ctx, "UPDATE account_credentials SET preferred = 0 WHERE account_id = ?", value.AccountID); err != nil {
				return fmt.Errorf("sqlite: reset preferred account credential: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO account_credentials(account_id, credential_id, preferred)
			VALUES (?, ?, ?)
			ON CONFLICT(account_id, credential_id) DO UPDATE SET preferred =
				CASE WHEN excluded.preferred = 1 THEN 1 ELSE account_credentials.preferred END`,
			value.AccountID, value.CredentialID, value.Preferred); err != nil {
			return fmt.Errorf("sqlite: save account credential: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit account save: %w", err)
	}
	return nil
}

func scanAccount(scanner interface{ Scan(...any) error }) (domain.RemoteAccount, error) {
	var value domain.RemoteAccount
	var created string
	var synced sql.NullString
	if err := scanner.Scan(&value.ID, &value.Provider, &value.ProviderID, &value.Name, &created, &synced); err != nil {
		return value, err
	}
	var err error
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, err
	}
	if value.LastSyncedAt, err = decodeOptionalTime(synced); err != nil {
		return value, err
	}
	return value, nil
}

func (r *Repository) ListAccounts(ctx context.Context) ([]domain.RemoteAccount, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, provider, provider_id, name, created_at, last_synced_at
        FROM accounts ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list accounts: %w", err)
	}
	defer rows.Close()
	values := make([]domain.RemoteAccount, 0)
	for rows.Next() {
		value, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan account: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) SaveZones(ctx context.Context, zones []domain.Zone) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin zone save: %w", err)
	}
	defer tx.Rollback()
	for _, value := range zones {
		servers, err := encodeJSON(value.NameServers)
		if err != nil {
			return fmt.Errorf("sqlite: encode zone name servers: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO zones (
            id, provider, provider_id, account_id, preferred_credential_id, name,
            unicode_name, status, paused, plan, name_servers_json, modified_at, last_synced_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,
            provider_id=excluded.provider_id, account_id=excluded.account_id,
            preferred_credential_id=excluded.preferred_credential_id, name=excluded.name,
            unicode_name=excluded.unicode_name, status=excluded.status, paused=excluded.paused,
            plan=excluded.plan, name_servers_json=excluded.name_servers_json,
            modified_at=excluded.modified_at, last_synced_at=excluded.last_synced_at`,
			value.ID, value.Provider, value.ProviderID, value.AccountID, value.PreferredCredentialID,
			value.Name, value.UnicodeName, string(value.Status), value.Paused, value.Plan,
			servers, encodeOptionalTime(value.ModifiedAt), encodeOptionalTime(value.LastSyncedAt)); err != nil {
			return fmt.Errorf("sqlite: save zone %s: %w", value.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit zone save: %w", err)
	}
	return nil
}

const zoneColumns = `id, provider, provider_id, account_id, preferred_credential_id, name,
    unicode_name, status, paused, plan, name_servers_json, modified_at, last_synced_at`

func scanZone(scanner interface{ Scan(...any) error }) (domain.Zone, error) {
	var value domain.Zone
	var status, servers string
	var modified, synced sql.NullString
	if err := scanner.Scan(&value.ID, &value.Provider, &value.ProviderID, &value.AccountID,
		&value.PreferredCredentialID, &value.Name, &value.UnicodeName, &status, &value.Paused,
		&value.Plan, &servers, &modified, &synced); err != nil {
		return value, err
	}
	value.Status = domain.ZoneStatus(status)
	if err := decodeJSON(servers, &value.NameServers); err != nil {
		return value, err
	}
	var err error
	if value.ModifiedAt, err = decodeOptionalTime(modified); err != nil {
		return value, err
	}
	if value.LastSyncedAt, err = decodeOptionalTime(synced); err != nil {
		return value, err
	}
	return value, nil
}

func (r *Repository) ListZones(ctx context.Context) ([]domain.Zone, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+zoneColumns+" FROM zones ORDER BY name COLLATE NOCASE, id")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list zones: %w", err)
	}
	defer rows.Close()
	values := make([]domain.Zone, 0)
	for rows.Next() {
		value, err := scanZone(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan zone: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) GetZone(ctx context.Context, id string) (domain.Zone, error) {
	value, err := scanZone(r.db.QueryRowContext(ctx, "SELECT "+zoneColumns+" FROM zones WHERE id = ?", id))
	if err != nil {
		return value, fmt.Errorf("sqlite: get zone: %w", err)
	}
	return value, nil
}
