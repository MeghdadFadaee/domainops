package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MeghdadFadaee/domainops/internal/domain"
)

func (r *Repository) SaveEndpoint(ctx context.Context, value domain.ObservedEndpoint) error {
	addresses, err := encodeJSON(value.ResolvedAddresses)
	if err != nil {
		return fmt.Errorf("sqlite: encode endpoint addresses: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO endpoints (
        id, zone_id, host, port, enabled, last_checked_at, resolved_addresses_json,
        fingerprint_sha256, issuer, not_after, valid_for_host, trusted, last_error
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	    ON CONFLICT(id) DO UPDATE SET zone_id=excluded.zone_id, host=excluded.host,
	        port=excluded.port, enabled=excluded.enabled,
        last_checked_at=excluded.last_checked_at,
        resolved_addresses_json=excluded.resolved_addresses_json,
        fingerprint_sha256=excluded.fingerprint_sha256, issuer=excluded.issuer,
	        not_after=excluded.not_after, valid_for_host=excluded.valid_for_host,
	        trusted=excluded.trusted, last_error=excluded.last_error
	    ON CONFLICT(host, port) DO UPDATE SET zone_id=excluded.zone_id,
	        enabled=excluded.enabled, last_checked_at=excluded.last_checked_at,
	        resolved_addresses_json=excluded.resolved_addresses_json,
	        fingerprint_sha256=excluded.fingerprint_sha256, issuer=excluded.issuer,
	        not_after=excluded.not_after, valid_for_host=excluded.valid_for_host,
	        trusted=excluded.trusted, last_error=excluded.last_error`,
		value.ID, value.ZoneID, value.Host, value.Port, value.Enabled,
		encodeOptionalTime(value.LastCheckedAt), addresses, value.FingerprintSHA256,
		value.Issuer, encodeOptionalTime(value.NotAfter), value.ValidForHost,
		value.Trusted, value.LastError)
	if err != nil {
		return fmt.Errorf("sqlite: save endpoint: %w", err)
	}
	return nil
}

func scanEndpoint(scanner interface{ Scan(...any) error }) (domain.ObservedEndpoint, error) {
	var value domain.ObservedEndpoint
	var checked, notAfter sql.NullString
	var addresses string
	if err := scanner.Scan(&value.ID, &value.ZoneID, &value.Host, &value.Port,
		&value.Enabled, &checked, &addresses, &value.FingerprintSHA256, &value.Issuer,
		&notAfter, &value.ValidForHost, &value.Trusted, &value.LastError); err != nil {
		return value, err
	}
	if err := decodeJSON(addresses, &value.ResolvedAddresses); err != nil {
		return value, err
	}
	var err error
	if value.LastCheckedAt, err = decodeOptionalTime(checked); err != nil {
		return value, err
	}
	if value.NotAfter, err = decodeOptionalTime(notAfter); err != nil {
		return value, err
	}
	return value, nil
}

const endpointColumns = `id, zone_id, host, port, enabled, last_checked_at,
    resolved_addresses_json, fingerprint_sha256, issuer, not_after,
    valid_for_host, trusted, last_error`

func (r *Repository) ListEndpoints(ctx context.Context) ([]domain.ObservedEndpoint, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+endpointColumns+" FROM endpoints ORDER BY host COLLATE NOCASE, port, id")
	if err != nil {
		return nil, fmt.Errorf("sqlite: list endpoints: %w", err)
	}
	defer rows.Close()
	values := make([]domain.ObservedEndpoint, 0)
	for rows.Next() {
		value, err := scanEndpoint(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan endpoint: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) SaveHealthIssues(ctx context.Context, ownerID string, values []domain.HealthIssue) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin health replacement: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM health_issues WHERE owner_id = ?", ownerID); err != nil {
		return fmt.Errorf("sqlite: clear health issues: %w", err)
	}
	for _, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO health_issues (
            id, owner_id, severity, kind, resource_id, title, detail, action, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.ID, ownerID,
			string(value.Severity), value.Kind, value.ResourceID, value.Title,
			value.Detail, value.Action, encodeTime(value.ObservedAt)); err != nil {
			return fmt.Errorf("sqlite: save health issue %s: %w", value.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit health replacement: %w", err)
	}
	return nil
}

func scanHealthIssue(scanner interface{ Scan(...any) error }) (domain.HealthIssue, error) {
	var value domain.HealthIssue
	var severity, observed string
	if err := scanner.Scan(&value.ID, &severity, &value.Kind, &value.ResourceID,
		&value.Title, &value.Detail, &value.Action, &observed); err != nil {
		return value, err
	}
	value.Severity = domain.Severity(severity)
	var err error
	value.ObservedAt, err = decodeTime(observed)
	return value, err
}

const healthColumns = `id, severity, kind, resource_id, title, detail, action, observed_at`
const healthOrder = `CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
    observed_at DESC, id`

func listHealthIssues(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]domain.HealthIssue, error) {
	rows, err := queryer.QueryContext(ctx, "SELECT "+healthColumns+" FROM health_issues ORDER BY "+healthOrder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]domain.HealthIssue, 0)
	for rows.Next() {
		value, err := scanHealthIssue(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) ListHealthIssues(ctx context.Context) ([]domain.HealthIssue, error) {
	values, err := listHealthIssues(ctx, r.db)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list health issues: %w", err)
	}
	return values, nil
}

func (r *Repository) SaveJob(ctx context.Context, value domain.Job) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO jobs (
        id, kind, state, resource_id, progress, message, payload_json, error,
        retry_at, created_at, started_at, finished_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, state=excluded.state,
        resource_id=excluded.resource_id, progress=excluded.progress,
        message=excluded.message, payload_json=excluded.payload_json,
        error=excluded.error, retry_at=excluded.retry_at, created_at=excluded.created_at,
        started_at=excluded.started_at, finished_at=excluded.finished_at,
        updated_at=excluded.updated_at`, value.ID, value.Kind, string(value.State),
		value.ResourceID, value.Progress, value.Message, rawOrNil(value.Payload), value.Error,
		encodeOptionalTime(value.RetryAt), encodeTime(value.CreatedAt),
		encodeOptionalTime(value.StartedAt), encodeOptionalTime(value.FinishedAt),
		encodeTime(value.UpdatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save job: %w", err)
	}
	return nil
}

const jobColumns = `id, kind, state, resource_id, progress, message, payload_json,
    error, retry_at, created_at, started_at, finished_at, updated_at`

func scanJob(scanner interface{ Scan(...any) error }) (domain.Job, error) {
	var value domain.Job
	var state, created, updated string
	var payload []byte
	var retry, started, finished sql.NullString
	if err := scanner.Scan(&value.ID, &value.Kind, &state, &value.ResourceID,
		&value.Progress, &value.Message, &payload, &value.Error, &retry, &created,
		&started, &finished, &updated); err != nil {
		return value, err
	}
	value.State = domain.JobState(state)
	value.Payload = copyRaw(payload)
	var err error
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = decodeTime(updated); err != nil {
		return value, err
	}
	if value.RetryAt, err = decodeOptionalTime(retry); err != nil {
		return value, err
	}
	if value.StartedAt, err = decodeOptionalTime(started); err != nil {
		return value, err
	}
	if value.FinishedAt, err = decodeOptionalTime(finished); err != nil {
		return value, err
	}
	return value, nil
}

func (r *Repository) GetJob(ctx context.Context, id string) (domain.Job, error) {
	value, err := scanJob(r.db.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id = ?", id))
	if err != nil {
		return value, fmt.Errorf("sqlite: get job: %w", err)
	}
	return value, nil
}

func (r *Repository) ListJobs(ctx context.Context, limit int) ([]domain.Job, error) {
	query := "SELECT " + jobColumns + " FROM jobs ORDER BY updated_at DESC, id"
	var args []any
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list jobs: %w", err)
	}
	defer rows.Close()
	values := make([]domain.Job, 0)
	for rows.Next() {
		value, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan job: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) ListRecoverableJobs(ctx context.Context) ([]domain.Job, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+jobColumns+` FROM jobs
        WHERE state IN ('queued', 'running', 'waiting_for_dns')
           OR (state = 'failed' AND retry_at IS NOT NULL)
        ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list recoverable jobs: %w", err)
	}
	defer rows.Close()
	values := make([]domain.Job, 0)
	for rows.Next() {
		value, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan recoverable job: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// ReconcileInterruptedJobs closes process-local work that cannot still be
// running after a new DomainOps process has acquired the data-directory lock.
// Journal recovery runs first; this final state transition prevents abandoned
// jobs from remaining permanently active on the dashboard.
func (r *Repository) ReconcileInterruptedJobs(ctx context.Context, now time.Time) (int64, error) {
	encodedNow := encodeTime(now.UTC())
	result, err := r.db.ExecContext(ctx, `UPDATE jobs
		SET state = 'failed',
			message = 'Interrupted by previous DomainOps shutdown',
			error = 'operation was interrupted; crash recovery completed but the operation itself was not resumed',
			retry_at = NULL,
			finished_at = ?,
			updated_at = ?
		WHERE state IN ('queued', 'running', 'waiting_for_dns')`, encodedNow, encodedNow)
	if err != nil {
		return 0, fmt.Errorf("sqlite: reconcile interrupted jobs: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: count reconciled interrupted jobs: %w", err)
	}
	return count, nil
}

func (r *Repository) SaveChallenge(ctx context.Context, value domain.ChallengeJournal) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO challenge_journal (
		id, job_id, credential_id, zone_id, record_id, fqdn, value_hash, created_at, cleaned_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET job_id=excluded.job_id, credential_id=excluded.credential_id, zone_id=excluded.zone_id,
		record_id=excluded.record_id, fqdn=excluded.fqdn,
		value_hash=excluded.value_hash, created_at=excluded.created_at,
		cleaned_at=excluded.cleaned_at`, value.ID, value.JobID, value.CredentialID, value.ZoneID,
		value.RecordID, value.FQDN, value.ValueHash, encodeTime(value.CreatedAt),
		encodeOptionalTime(value.CleanedAt))
	if err != nil {
		return fmt.Errorf("sqlite: save challenge journal: %w", err)
	}
	return nil
}

func scanChallenge(scanner interface{ Scan(...any) error }) (domain.ChallengeJournal, error) {
	var value domain.ChallengeJournal
	var created string
	var cleaned sql.NullString
	if err := scanner.Scan(&value.ID, &value.JobID, &value.CredentialID, &value.ZoneID, &value.RecordID,
		&value.FQDN, &value.ValueHash, &created, &cleaned); err != nil {
		return value, err
	}
	var err error
	if value.CreatedAt, err = decodeTime(created); err != nil {
		return value, err
	}
	if value.CleanedAt, err = decodeOptionalTime(cleaned); err != nil {
		return value, err
	}
	return value, nil
}

func (r *Repository) ListOpenChallenges(ctx context.Context) ([]domain.ChallengeJournal, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, job_id, credential_id, zone_id, record_id, fqdn,
        value_hash, created_at, cleaned_at FROM challenge_journal
        WHERE cleaned_at IS NULL ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list open challenges: %w", err)
	}
	defer rows.Close()
	values := make([]domain.ChallengeJournal, 0)
	for rows.Next() {
		value, err := scanChallenge(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan challenge: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) MarkChallengeCleaned(ctx context.Context, id string, cleanedAt time.Time) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE challenge_journal SET cleaned_at = ? WHERE id = ?`,
		encodeTime(cleanedAt), id); err != nil {
		return fmt.Errorf("sqlite: mark challenge cleaned: %w", err)
	}
	return nil
}

func (r *Repository) AppendAudit(ctx context.Context, value domain.AuditEvent) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_events (
        id, actor, action, resource_id, before_json, after_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`, value.ID, value.Actor, value.Action,
		value.ResourceID, rawOrNil(value.Before), rawOrNil(value.After), encodeTime(value.CreatedAt))
	if err != nil {
		return fmt.Errorf("sqlite: append audit event: %w", err)
	}
	return nil
}

func scanAudit(scanner interface{ Scan(...any) error }) (domain.AuditEvent, error) {
	var value domain.AuditEvent
	var before, after []byte
	var created string
	if err := scanner.Scan(&value.ID, &value.Actor, &value.Action, &value.ResourceID,
		&before, &after, &created); err != nil {
		return value, err
	}
	value.Before = copyRaw(before)
	value.After = copyRaw(after)
	var err error
	value.CreatedAt, err = decodeTime(created)
	return value, err
}

func (r *Repository) ListAudit(ctx context.Context, limit int) ([]domain.AuditEvent, error) {
	query := `SELECT id, actor, action, resource_id, before_json, after_json, created_at
        FROM audit_events ORDER BY created_at DESC, id`
	var args []any
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list audit events: %w", err)
	}
	defer rows.Close()
	values := make([]domain.AuditEvent, 0)
	for rows.Next() {
		value, err := scanAudit(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan audit event: %w", err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (r *Repository) Dashboard(ctx context.Context, now time.Time) (domain.DashboardSnapshot, error) {
	snapshot := domain.DashboardSnapshot{GeneratedAt: now}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snapshot, fmt.Errorf("sqlite: begin dashboard snapshot: %w", err)
	}
	defer tx.Rollback()
	counts := []struct {
		query string
		value *int
	}{
		{"SELECT COUNT(*) FROM credentials", &snapshot.Credentials},
		{"SELECT COUNT(*) FROM accounts", &snapshot.Accounts},
		{"SELECT COUNT(*) FROM zones", &snapshot.Zones},
		{"SELECT COUNT(*) FROM dns_records", &snapshot.DNSRecords},
		{"SELECT COUNT(*) FROM certificate_lineages", &snapshot.Certificates},
		{`SELECT COUNT(*) FROM jobs WHERE state IN ('queued', 'running', 'waiting_for_dns')`, &snapshot.ActiveJobs},
	}
	for _, item := range counts {
		if err := tx.QueryRowContext(ctx, item.query).Scan(item.value); err != nil {
			return snapshot, fmt.Errorf("sqlite: count dashboard resources: %w", err)
		}
	}

	rows, err := tx.QueryContext(ctx, `SELECT v.not_before, v.not_after, v.renewal_window_start
		FROM certificate_lineages l
		JOIN certificate_versions v ON v.id = l.current_version_id
		WHERE v.revoked_at IS NULL AND v.revocation_pending_at IS NULL`)
	if err != nil {
		return snapshot, fmt.Errorf("sqlite: load dashboard certificates: %w", err)
	}
	for rows.Next() {
		var notBeforeRaw, notAfterRaw string
		var renewalRaw sql.NullString
		if err := rows.Scan(&notBeforeRaw, &notAfterRaw, &renewalRaw); err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("sqlite: scan dashboard certificate: %w", err)
		}
		notBefore, err := decodeTime(notBeforeRaw)
		if err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("sqlite: decode dashboard certificate: %w", err)
		}
		notAfter, err := decodeTime(notAfterRaw)
		if err != nil {
			rows.Close()
			return snapshot, fmt.Errorf("sqlite: decode dashboard certificate: %w", err)
		}
		if !now.Before(notAfter) {
			snapshot.CertificatesExpired++
			continue
		}
		var dueAt time.Time
		if renewalRaw.Valid {
			dueAt, err = decodeTime(renewalRaw.String)
			if err != nil {
				rows.Close()
				return snapshot, fmt.Errorf("sqlite: decode renewal window: %w", err)
			}
		} else {
			dueAt = notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
		}
		if !now.Before(dueAt) {
			snapshot.CertificatesDue++
		}
	}
	if err := rows.Close(); err != nil {
		return snapshot, fmt.Errorf("sqlite: close dashboard certificates: %w", err)
	}
	if err := rows.Err(); err != nil {
		return snapshot, fmt.Errorf("sqlite: iterate dashboard certificates: %w", err)
	}
	snapshot.Issues, err = listHealthIssues(ctx, tx)
	if err != nil {
		return snapshot, fmt.Errorf("sqlite: load dashboard issues: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return snapshot, fmt.Errorf("sqlite: commit dashboard snapshot: %w", err)
	}
	return snapshot, nil
}
