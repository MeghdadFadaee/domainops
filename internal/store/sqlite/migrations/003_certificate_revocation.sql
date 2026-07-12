ALTER TABLE certificate_versions ADD COLUMN revoked_at TEXT;
ALTER TABLE certificate_versions ADD COLUMN revocation_reason INTEGER;
