CREATE TABLE credential_zone_capabilities (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (credential_id, zone_id, capability)
);
CREATE INDEX credential_zone_capabilities_zone_idx
    ON credential_zone_capabilities(zone_id, capability);
