CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    account_hint TEXT NOT NULL DEFAULT '',
    secret_ref TEXT NOT NULL,
    status TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    last_verified_at TEXT,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_synced_at TEXT,
    UNIQUE(provider, provider_id)
);

CREATE TABLE account_credentials (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    preferred INTEGER NOT NULL DEFAULT 0 CHECK (preferred IN (0, 1)),
    PRIMARY KEY (account_id, credential_id)
);
CREATE INDEX account_credentials_credential_idx ON account_credentials(credential_id);

CREATE TABLE zones (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    preferred_credential_id TEXT NOT NULL,
    name TEXT NOT NULL,
    unicode_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
    plan TEXT NOT NULL DEFAULT '',
    name_servers_json TEXT NOT NULL DEFAULT '[]',
    modified_at TEXT,
    last_synced_at TEXT,
    UNIQUE(provider, provider_id)
);
CREATE INDEX zones_account_idx ON zones(account_id);
CREATE INDEX zones_name_idx ON zones(name);

CREATE TABLE dns_records (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    unicode_name TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    priority INTEGER,
    ttl INTEGER NOT NULL,
    proxied INTEGER NOT NULL DEFAULT 0 CHECK (proxied IN (0, 1)),
    proxiable INTEGER NOT NULL DEFAULT 0 CHECK (proxiable IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    managed INTEGER NOT NULL DEFAULT 0 CHECK (managed IN (0, 1)),
    data_json BLOB,
    raw_json BLOB,
    modified_at TEXT,
    last_synced_at TEXT,
    UNIQUE(zone_id, provider_id)
);
CREATE INDEX dns_records_zone_idx ON dns_records(zone_id);
CREATE INDEX dns_records_lookup_idx ON dns_records(zone_id, name, type);

CREATE TABLE zone_dns_sync (
    zone_id TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    synced_at TEXT NOT NULL
);

CREATE TABLE tls_settings (
    zone_id TEXT PRIMARY KEY REFERENCES zones(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    always_use_https INTEGER NOT NULL DEFAULT 0 CHECK (always_use_https IN (0, 1)),
    minimum_tls TEXT NOT NULL,
    tls_1_3 INTEGER NOT NULL DEFAULT 0 CHECK (tls_1_3 IN (0, 1)),
    has_proxied_dns INTEGER NOT NULL DEFAULT 0 CHECK (has_proxied_dns IN (0, 1)),
    last_synced_at TEXT
);

CREATE TABLE acme_accounts (
    id TEXT PRIMARY KEY,
    environment TEXT NOT NULL UNIQUE,
    directory_url TEXT NOT NULL,
    email TEXT NOT NULL,
    registration TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE certificate_lineages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    zone_id TEXT,
    source TEXT NOT NULL,
    identifiers_json TEXT NOT NULL,
    key_algorithm TEXT NOT NULL,
    profile TEXT NOT NULL,
    acme_account_id TEXT,
    current_version_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX certificate_lineages_zone_idx ON certificate_lineages(zone_id);

CREATE TABLE certificate_versions (
    id TEXT PRIMARY KEY,
    lineage_id TEXT NOT NULL REFERENCES certificate_lineages(id) ON DELETE CASCADE,
    serial_number TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    issuer TEXT NOT NULL,
    identifiers_json TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    certificate_path TEXT NOT NULL,
    chain_path TEXT NOT NULL DEFAULT '',
    private_key_ref TEXT NOT NULL,
    renewal_window_start TEXT,
    renewal_window_end TEXT,
    exported_at TEXT,
    export_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX certificate_versions_lineage_idx ON certificate_versions(lineage_id, created_at DESC);
CREATE INDEX certificate_versions_expiry_idx ON certificate_versions(not_after);

CREATE TABLE endpoints (
    id TEXT PRIMARY KEY,
    zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_checked_at TEXT,
    resolved_addresses_json TEXT NOT NULL DEFAULT '[]',
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT '',
    not_after TEXT,
    valid_for_host INTEGER NOT NULL DEFAULT 0 CHECK (valid_for_host IN (0, 1)),
    trusted INTEGER NOT NULL DEFAULT 0 CHECK (trusted IN (0, 1)),
    last_error TEXT NOT NULL DEFAULT '',
    UNIQUE(host, port)
);
CREATE INDEX endpoints_zone_idx ON endpoints(zone_id);

CREATE TABLE health_issues (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX health_issues_owner_idx ON health_issues(owner_id);
CREATE INDEX health_issues_order_idx ON health_issues(severity, observed_at DESC);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    message TEXT NOT NULL DEFAULT '',
    payload_json BLOB,
    error TEXT NOT NULL DEFAULT '',
    retry_at TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX jobs_updated_idx ON jobs(updated_at DESC);
CREATE INDEX jobs_recoverable_idx ON jobs(state, retry_at, updated_at);

CREATE TABLE challenge_journal (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    fqdn TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    cleaned_at TEXT
);
CREATE INDEX challenge_journal_open_idx ON challenge_journal(cleaned_at, created_at);
CREATE INDEX challenge_journal_job_idx ON challenge_journal(job_id);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    before_json BLOB,
    after_json BLOB,
    created_at TEXT NOT NULL
);
CREATE INDEX audit_events_created_idx ON audit_events(created_at DESC);
