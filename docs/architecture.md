# Architecture

DomainOps is a modular monolith. It deliberately keeps network providers, certificate automation, persistence, and terminal presentation behind provider-neutral contracts so the project can grow without becoming a set of distributed services.

## Runtime flow

```text
TUI / CLI
    │
Application services ───── Background health workers
    │                              │
Provider contracts          DNS + TLS probes
    │
Cloudflare REST adapter ─── ACME engine (lego)
    │                              │
Cloudflare API               Journaled DNS-01 solver

Application services ───── SQLite metadata/cache/jobs/audit
                     └──── Encrypted local secret vault
```

The TUI uses unidirectional Bubble Tea messages. Rendering reads in-memory state only; it never performs HTTP, DNS, TLS, SQLite, or cryptographic work. Commands execute application use cases and send typed results back to the model.

## Provider boundaries

The provider package defines focused capabilities:

- `CredentialVerifier`
- `ZoneInventory`
- `DNSRecordService`
- `DNSBatchService`
- `DNS01Solver`
- `EdgeTLSService`

Cloudflare is the first adapter. Its wire types do not escape the adapter. Unknown DNS record JSON is retained so new provider fields remain visible even before DomainOps adds an editor for them.

Credential identities and remote accounts are separate. One user token may expose several Cloudflare accounts, while an account token belongs to one account. A zone stores an explicit preferred credential; ACME and DNS writes never silently switch credentials.

After a successful full sync, a zone no longer visible to its preferred credential is retained as cached history but marked unknown and detached from that stale preference. DNS-read authority is also stored per credential and zone. An authoritative 401/403 on a later zone read atomically removes that evidence and detaches only the denied route, while transient transport, rate-limit, and server failures preserve the last successful observation. A later credential that rediscovers the zone can restore routing without trapping credential removal behind an unreachable zone.

Future providers should implement only their supported capabilities and register statically. A future third-party plugin system should be an out-of-process, versioned protocol rather than Go’s in-process plugin mechanism.

## Persistence

SQLite stores metadata, cached zones and records, public certificate metadata, endpoint observations, durable jobs, challenge journals, commit intents, and redacted audit events. Migrations are embedded and transactional, including forward-only repair of legacy duplicate endpoint identities before host/port uniqueness is enforced. WAL with full synchronous durability, foreign keys, a busy timeout, and bounded connections are enabled at open. The full durability setting is intentional: an acknowledged recovery journal or certificate commit must survive power loss before filesystem cleanup or activation can rely on it.

The encrypted vault is a separate atomic file. SQLite stores secret references only. A random 256-bit data key encrypts the vault payload with XChaCha20-Poly1305. Argon2id derives the passphrase wrapping key. OS keyrings are optional unlock slots, not a runtime requirement.

Only one DomainOps process can open a data directory at a time. This keeps vault, migration, cache, and certificate activation semantics deterministic. An advisory lock is used on macOS and Linux and is automatically released after a crash.

## DNS changes

Single changes follow this sequence:

1. Load the cached record and explicit zone credential.
2. Re-fetch the exact remote record ID.
3. Reject provider-managed/read-only records.
4. Validate and normalize the requested record.
5. Submit the mutation.
6. Reconcile the returned provider state into SQLite.
7. Attempt to append a redacted before/after audit event.

If a single write returns an ambiguous transport/server/schema result, DomainOps records an outcome-unknown audit event, reloads the complete provider zone into SQLite, reconciles generated health endpoints, and returns an explicit do-not-retry error. A provider-confirmed write whose local reconciliation fails is reported separately as applied-but-unreconciled.

Cloudflare batches are zone-scoped. The CLI previews a normalized plan first; apply repeats every fresh-read safety check, submits the provider batch, fully reloads the zone cache, and attempts to append one audit event. Fresh reads reject changes already visible before submission, but the Cloudflare API does not make the read-and-submit pair conditional, so a later change can race with apply. Audit persistence is best-effort and cannot roll back a provider mutation. Cross-zone automation should invoke independent batches because DNS propagation cannot be atomic across zones.

TLS changes carry the displayed baseline into the Cloudflare adapter. The adapter reads all supported settings, rejects a concurrent change to any requested field before the first patch, patches only fields the operator changed, and preserves unrelated settings—including Cloudflare's distinct TLS 1.3 `zrt` mode. Any later partial or ambiguous failure triggers a live refresh, cache update, and audit finding.

## Certificate lifecycle

Each lineage is an independent order, usually containing the apex plus its one-label wildcard. The engine caps issuance at three concurrent orders.

Before an order, local preflight checks active-zone state, exact credential routing, a DNS-access capability inferred from successful read probes, and cached CAA records. Cloudflare remains authoritative for write permission, and the CA performs the authoritative live DNS and CAA checks.

DNS-01 intent is journaled before the provider write, including the exact credential, zone, job marker, owner, and hashed value. The returned provider record ID is then attached before ACME validation proceeds. Ambiguous creates are reconciled by the job marker and value hash; cleanup deletes only the exact ID and treats an already-absent record as clean. Open rows are recovered after either password or keyring unlock.

Managed certificate keys are generated fresh for issuance and renewal. ACME account keys and certificate keys are stored in the vault. Account registration journals its key before contacting the CA, then insert-only account metadata and intent closure commit in one SQLite transaction. Certificate storage similarly writes a durable commit-intent row before a key or plaintext PEM appears. PEM exports are versioned, written and synced in a deterministic temporary directory, then renamed atomically. The lineage/version rows advance and delete that intent in one SQLite transaction before the `current` symlink changes, so filesystem activation can never expose an untracked certificate. On an ambiguous commit return, the intent is re-read before any compensation; unlock recovery validates secret bindings and configured-root containment, removes journaled orphan keys and both final and temporary PEM paths, then reconciles missing or stale links from the authoritative database. Interrupted jobs are finalized only after every journal, challenge, and link repair succeeds. Recovery failures are persisted as critical health findings. Staging and production use separate lineages and export roots.

Renewal timing prefers validated ACME Renewal Information and safely falls back to a two-thirds-lifetime window. Renewals send the previous certificate’s ARI replacement identifier and retain prior versions after success. Revocation is bound to the lineage’s original ACME account. Its intent and reason are durable before the CA call; a retry that receives the standard `alreadyRevoked` response completes the local state transition instead of leaving a split-brain lineage.

## Growth path

The current application is intentionally local-first. Natural next additions are unattended renewal through systemd/launchd, notifications and deployment hooks, DNSSEC, BIND import/export, additional provider adapters, registrar lifecycle data, and finally an optional remote control plane with RBAC.
