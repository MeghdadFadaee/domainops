-- Older development schemas did not enforce the physical endpoint identity.
-- Retain the most useful observation, remove duplicate-owned stale health
-- issues, and then make host+port safe for ON CONFLICT routing reassignment.
CREATE TEMP TABLE endpoint_deduplication AS
SELECT id AS duplicate_id, keeper_id
FROM (
    SELECT id,
           FIRST_VALUE(id) OVER (
               PARTITION BY host, port
               ORDER BY enabled DESC,
                        CASE WHEN last_checked_at IS NULL THEN 1 ELSE 0 END,
                        last_checked_at DESC,
                        id
           ) AS keeper_id
    FROM endpoints
)
WHERE id <> keeper_id;

DELETE FROM health_issues
WHERE owner_id IN (SELECT duplicate_id FROM endpoint_deduplication)
   OR resource_id IN (SELECT duplicate_id FROM endpoint_deduplication);

DELETE FROM endpoints
WHERE id IN (SELECT duplicate_id FROM endpoint_deduplication);

CREATE UNIQUE INDEX IF NOT EXISTS endpoints_host_port_unique_idx
    ON endpoints(host, port);

DROP TABLE endpoint_deduplication;
