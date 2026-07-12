CREATE TABLE certificate_commit_journal (
    version_id TEXT PRIMARY KEY,
    lineage_id TEXT NOT NULL,
    secret_ref TEXT NOT NULL DEFAULT '',
    artifact_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX certificate_commit_journal_created_idx
    ON certificate_commit_journal(created_at);
