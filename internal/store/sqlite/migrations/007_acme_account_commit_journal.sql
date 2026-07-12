CREATE TABLE acme_account_commit_journal (
    account_id TEXT PRIMARY KEY,
    secret_ref TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX acme_account_commit_journal_created_idx
    ON acme_account_commit_journal(created_at);
