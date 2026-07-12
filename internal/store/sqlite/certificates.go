package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/MeghdadFadaee/domainops/internal/domain"
	"github.com/MeghdadFadaee/domainops/internal/store"
)

func (r *Repository) SaveACMEAccount(ctx context.Context, value domain.ACMEAccount) error {
	return saveACMEAccount(ctx, r.db, value)
}

func saveACMEAccount(ctx context.Context, executor sqlExecutor, value domain.ACMEAccount) error {
	_, err := executor.ExecContext(ctx, `INSERT INTO acme_accounts (
        id, environment, directory_url, email, registration, secret_ref, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(environment) DO UPDATE SET id=excluded.id,
        directory_url=excluded.directory_url, email=excluded.email,
        registration=excluded.registration, secret_ref=excluded.secret_ref,
        created_at=excluded.created_at`, value.ID, value.Environment,
		value.DirectoryURL, value.Email, value.Registration, value.SecretRef,
		encodeTime(value.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save ACME account: %w", err)
	}
	return nil
}

func insertACMEAccount(ctx context.Context, executor sqlExecutor, value domain.ACMEAccount) error {
	result, err := executor.ExecContext(ctx, `INSERT INTO acme_accounts (
		id, environment, directory_url, email, registration, secret_ref, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(environment) DO NOTHING`, value.ID, value.Environment,
		value.DirectoryURL, value.Email, value.Registration, value.SecretRef,
		encodeTime(value.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: insert ACME account: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: inspect ACME account insert: %w", err)
	}
	if inserted != 1 {
		return fmt.Errorf("sqlite: %w: %s", store.ErrACMEAccountConflict, value.Environment)
	}
	return nil
}

// CommitACMEAccount installs account metadata and closes its secret intent in
// one FULL-synchronous SQLite transaction.
func (r *Repository) CommitACMEAccount(ctx context.Context, value domain.ACMEAccount) error {
	if value.ID == "" || value.Environment == "" || value.SecretRef == "" {
		return fmt.Errorf("sqlite: invalid ACME account commit")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin ACME account commit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertACMEAccount(ctx, tx, value); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM acme_account_commit_journal WHERE account_id = ?", value.ID); err != nil {
		return fmt.Errorf("sqlite: complete ACME account commit intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit ACME account: %w", err)
	}
	return nil
}

func (r *Repository) SaveACMEAccountCommitIntent(ctx context.Context, intent domain.ACMEAccountCommitIntent) error {
	if intent.AccountID == "" || intent.SecretRef == "" || intent.CreatedAt.IsZero() {
		return fmt.Errorf("sqlite: invalid ACME account commit intent")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO acme_account_commit_journal (account_id, secret_ref, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(account_id) DO UPDATE SET secret_ref=excluded.secret_ref, created_at=excluded.created_at`,
		intent.AccountID, intent.SecretRef, encodeTime(intent.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save ACME account commit intent: %w", err)
	}
	return nil
}

func (r *Repository) ListACMEAccountCommitIntents(ctx context.Context) ([]domain.ACMEAccountCommitIntent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT account_id, secret_ref, created_at
		FROM acme_account_commit_journal ORDER BY created_at, account_id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list ACME account commit intents: %w", err)
	}
	defer rows.Close()
	var intents []domain.ACMEAccountCommitIntent
	for rows.Next() {
		var intent domain.ACMEAccountCommitIntent
		var created string
		if err := rows.Scan(&intent.AccountID, &intent.SecretRef, &created); err != nil {
			return nil, fmt.Errorf("sqlite: scan ACME account commit intent: %w", err)
		}
		intent.CreatedAt, err = decodeTime(created)
		if err != nil {
			return nil, fmt.Errorf("sqlite: decode ACME account commit intent: %w", err)
		}
		intents = append(intents, intent)
	}
	return intents, rows.Err()
}

func (r *Repository) DeleteACMEAccountCommitIntent(ctx context.Context, accountID string) error {
	if _, err := r.db.ExecContext(ctx, "DELETE FROM acme_account_commit_journal WHERE account_id = ?", accountID); err != nil {
		return fmt.Errorf("sqlite: delete ACME account commit intent: %w", err)
	}
	return nil
}

func (r *Repository) GetACMEAccountByEnvironment(ctx context.Context, environment string) (domain.ACMEAccount, error) {
	var value domain.ACMEAccount
	var created string
	err := r.db.QueryRowContext(ctx, `SELECT id, environment, directory_url, email,
        registration, secret_ref, created_at FROM acme_accounts WHERE environment = ?`, environment).
		Scan(&value.ID, &value.Environment, &value.DirectoryURL, &value.Email,
			&value.Registration, &value.SecretRef, &created)
	if err != nil {
		return value, fmt.Errorf("sqlite: get ACME account: %w", err)
	}
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, fmt.Errorf("sqlite: decode ACME account: %w", err)
	}
	return value, nil
}

func (r *Repository) SaveCertificateLineage(ctx context.Context, value domain.CertificateLineage) error {
	return saveCertificateLineage(ctx, r.db, value)
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func saveCertificateLineage(ctx context.Context, executor sqlExecutor, value domain.CertificateLineage) error {
	identifiers, err := encodeJSON(value.Identifiers)
	if err != nil {
		return fmt.Errorf("sqlite: encode lineage identifiers: %w", err)
	}
	_, err = executor.ExecContext(ctx, `INSERT INTO certificate_lineages (
        id, name, zone_id, source, identifiers_json, key_algorithm, profile,
        acme_account_id, current_version_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET name=excluded.name, zone_id=excluded.zone_id,
        source=excluded.source, identifiers_json=excluded.identifiers_json,
        key_algorithm=excluded.key_algorithm, profile=excluded.profile,
        acme_account_id=excluded.acme_account_id,
        current_version_id=excluded.current_version_id, created_at=excluded.created_at,
        updated_at=excluded.updated_at`, value.ID, value.Name, value.ZoneID,
		string(value.Source), identifiers, string(value.KeyAlgorithm), value.Profile,
		value.ACMEAccountID, value.CurrentVersionID, encodeTime(value.CreatedAt),
		encodeTime(value.UpdatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save certificate lineage: %w", err)
	}
	return nil
}

const lineageColumns = `id, name, zone_id, source, identifiers_json, key_algorithm,
    profile, acme_account_id, current_version_id, created_at, updated_at`

func scanLineage(scanner interface{ Scan(...any) error }) (domain.CertificateLineage, error) {
	var value domain.CertificateLineage
	var source, identifiers, algorithm, created, updated string
	if err := scanner.Scan(&value.ID, &value.Name, &value.ZoneID, &source,
		&identifiers, &algorithm, &value.Profile, &value.ACMEAccountID,
		&value.CurrentVersionID, &created, &updated); err != nil {
		return value, err
	}
	value.Source = domain.CertificateSource(source)
	value.KeyAlgorithm = domain.KeyAlgorithm(algorithm)
	if err := decodeJSON(identifiers, &value.Identifiers); err != nil {
		return value, err
	}
	var err error
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = decodeTime(updated); err != nil {
		return value, err
	}
	return value, nil
}

func (r *Repository) ListCertificateLineages(ctx context.Context) ([]domain.CertificateLineage, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+lineageColumns+" FROM certificate_lineages ORDER BY name COLLATE NOCASE, id")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list certificate lineages: %w", err)
	}
	defer rows.Close()
	values := make([]domain.CertificateLineage, 0)
	for rows.Next() {
		value, err := scanLineage(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan certificate lineage: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) GetCertificateLineage(ctx context.Context, id string) (domain.CertificateLineage, error) {
	value, err := scanLineage(r.db.QueryRowContext(ctx, "SELECT "+lineageColumns+" FROM certificate_lineages WHERE id = ?", id))
	if err != nil {
		return value, fmt.Errorf("sqlite: get certificate lineage: %w", err)
	}
	return value, nil
}

func (r *Repository) SaveCertificateVersion(ctx context.Context, value domain.CertificateVersion) error {
	return saveCertificateVersion(ctx, r.db, value)
}

func (r *Repository) SaveCertificateCommitIntent(ctx context.Context, value domain.CertificateCommitIntent) error {
	if value.VersionID == "" || value.LineageID == "" || value.ArtifactPath == "" {
		return fmt.Errorf("sqlite: invalid certificate commit intent")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO certificate_commit_journal (
		version_id, lineage_id, secret_ref, artifact_path, created_at
	) VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(version_id) DO UPDATE SET lineage_id=excluded.lineage_id,
		secret_ref=excluded.secret_ref, artifact_path=excluded.artifact_path,
		created_at=excluded.created_at`, value.VersionID, value.LineageID,
		value.SecretRef, value.ArtifactPath, encodeTime(value.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save certificate commit intent: %w", err)
	}
	return nil
}

func (r *Repository) ListCertificateCommitIntents(ctx context.Context) ([]domain.CertificateCommitIntent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT version_id, lineage_id, secret_ref,
		artifact_path, created_at FROM certificate_commit_journal ORDER BY created_at, version_id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list certificate commit intents: %w", err)
	}
	defer rows.Close()
	var values []domain.CertificateCommitIntent
	for rows.Next() {
		var value domain.CertificateCommitIntent
		var created string
		if err := rows.Scan(&value.VersionID, &value.LineageID, &value.SecretRef, &value.ArtifactPath, &created); err != nil {
			return nil, fmt.Errorf("sqlite: scan certificate commit intent: %w", err)
		}
		value.CreatedAt, err = decodeTime(created)
		if err != nil {
			return nil, fmt.Errorf("sqlite: decode certificate commit intent: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) DeleteCertificateCommitIntent(ctx context.Context, versionID string) error {
	if _, err := r.db.ExecContext(ctx, "DELETE FROM certificate_commit_journal WHERE version_id = ?", versionID); err != nil {
		return fmt.Errorf("sqlite: delete certificate commit intent: %w", err)
	}
	return nil
}

func saveCertificateVersion(ctx context.Context, executor sqlExecutor, value domain.CertificateVersion) error {
	identifiers, err := encodeJSON(value.Identifiers)
	if err != nil {
		return fmt.Errorf("sqlite: encode certificate identifiers: %w", err)
	}
	_, err = executor.ExecContext(ctx, `INSERT INTO certificate_versions (
		id, lineage_id, serial_number, fingerprint_sha256, issuer, identifiers_json,
		not_before, not_after, certificate_path, chain_path, private_key_ref,
		renewal_window_start, renewal_window_end, revocation_pending_at, revoked_at,
		revocation_reason, exported_at, export_path, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET lineage_id=excluded.lineage_id,
        serial_number=excluded.serial_number, fingerprint_sha256=excluded.fingerprint_sha256,
        issuer=excluded.issuer, identifiers_json=excluded.identifiers_json,
        not_before=excluded.not_before, not_after=excluded.not_after,
        certificate_path=excluded.certificate_path, chain_path=excluded.chain_path,
		private_key_ref=excluded.private_key_ref,
		renewal_window_start=excluded.renewal_window_start,
		renewal_window_end=excluded.renewal_window_end,
		revocation_pending_at=excluded.revocation_pending_at, revoked_at=excluded.revoked_at,
		revocation_reason=excluded.revocation_reason, exported_at=excluded.exported_at,
        export_path=excluded.export_path, created_at=excluded.created_at`,
		value.ID, value.LineageID, value.SerialNumber, value.FingerprintSHA256,
		value.Issuer, identifiers, encodeTime(value.NotBefore), encodeTime(value.NotAfter),
		value.CertificatePath, value.ChainPath, value.PrivateKeyRef,
		encodeOptionalTime(value.RenewalWindowStart), encodeOptionalTime(value.RenewalWindowEnd),
		encodeOptionalTime(value.RevocationPendingAt), encodeOptionalTime(value.RevokedAt), optionalUint(value.RevocationReason),
		encodeOptionalTime(value.ExportedAt), value.ExportPath, encodeTime(value.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save certificate version: %w", err)
	}
	return nil
}

// CommitCertificateVersion installs a version row and advances its lineage in
// one SQLite transaction. Filesystem activation happens only after this method
// succeeds, so `current` can never point at an untracked version.
func (r *Repository) CommitCertificateVersion(ctx context.Context, lineage domain.CertificateLineage, version domain.CertificateVersion) error {
	if lineage.ID == "" || version.ID == "" || version.LineageID != lineage.ID || lineage.CurrentVersionID != version.ID {
		return fmt.Errorf("sqlite: invalid certificate lineage/version commit")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin certificate commit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	activeVersionID := lineage.CurrentVersionID
	lineage.CurrentVersionID = ""
	if err := saveCertificateLineage(ctx, tx, lineage); err != nil {
		return err
	}
	if err := saveCertificateVersion(ctx, tx, version); err != nil {
		return err
	}
	lineage.CurrentVersionID = activeVersionID
	if err := saveCertificateLineage(ctx, tx, lineage); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM certificate_commit_journal WHERE version_id = ?", version.ID); err != nil {
		return fmt.Errorf("sqlite: complete certificate commit intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit certificate version: %w", err)
	}
	return nil
}

const versionColumns = `id, lineage_id, serial_number, fingerprint_sha256, issuer,
	identifiers_json, not_before, not_after, certificate_path, chain_path,
	private_key_ref, renewal_window_start, renewal_window_end, revocation_pending_at,
	revoked_at, revocation_reason, exported_at,
    export_path, created_at`

func scanVersion(scanner interface{ Scan(...any) error }) (domain.CertificateVersion, error) {
	var value domain.CertificateVersion
	var identifiers, notBefore, notAfter, created string
	var renewalStart, renewalEnd, revocationPending, revoked, exported sql.NullString
	var revocationReason sql.NullInt64
	if err := scanner.Scan(&value.ID, &value.LineageID, &value.SerialNumber,
		&value.FingerprintSHA256, &value.Issuer, &identifiers, &notBefore, &notAfter,
		&value.CertificatePath, &value.ChainPath, &value.PrivateKeyRef, &renewalStart,
		&renewalEnd, &revocationPending, &revoked, &revocationReason, &exported, &value.ExportPath, &created); err != nil {
		return value, err
	}
	if err := decodeJSON(identifiers, &value.Identifiers); err != nil {
		return value, err
	}
	var err error
	if value.NotBefore, err = decodeTime(notBefore); err != nil {
		return value, err
	}
	if value.NotAfter, err = decodeTime(notAfter); err != nil {
		return value, err
	}
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, err
	}
	if value.RenewalWindowStart, err = decodeOptionalTime(renewalStart); err != nil {
		return value, err
	}
	if value.RenewalWindowEnd, err = decodeOptionalTime(renewalEnd); err != nil {
		return value, err
	}
	if value.RevocationPendingAt, err = decodeOptionalTime(revocationPending); err != nil {
		return value, err
	}
	if value.RevokedAt, err = decodeOptionalTime(revoked); err != nil {
		return value, err
	}
	if revocationReason.Valid {
		reason := uint(revocationReason.Int64)
		value.RevocationReason = &reason
	}
	if value.ExportedAt, err = decodeOptionalTime(exported); err != nil {
		return value, err
	}
	return value, nil
}

func optionalUint(value *uint) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func (r *Repository) ListCertificateVersions(ctx context.Context, lineageID string) ([]domain.CertificateVersion, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+versionColumns+` FROM certificate_versions
        WHERE lineage_id = ? ORDER BY created_at DESC, id`, lineageID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list certificate versions: %w", err)
	}
	defer rows.Close()
	values := make([]domain.CertificateVersion, 0)
	for rows.Next() {
		value, err := scanVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan certificate version: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
