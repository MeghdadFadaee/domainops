# Changelog

## Unreleased

- Initial DomainOps implementation.
- Multi-account Cloudflare inventory and DNS management.
- Cloudflare core TLS controls and edge certificate inventory.
- Let’s Encrypt DNS-01 wildcard issuance, renewal, revocation primitives, import, and export.
- Isolated staging/production certificate lineages, transactional version activation, and durable revocation-intent recovery.
- Encrypted local vault, durable SQLite jobs, crash-safe challenge cleanup, and audit history.
- Background public TLS observations and actionable dashboard findings.
- Bubble Tea v2 TUI plus essential JSON CLI commands.
- Safe DNS batch preview/apply, stable overlapping-token routing, and remote-change conflict detection.
- Streaming per-certificate persistence for large batches, CAA/routing preflight, ARI scheduling, and durable revocation state.
- Intent-first DNS-01 recovery tied to the exact Cloudflare credential.
- Power-loss-durable certificate commit journals, deterministic orphan cleanup, and fail-closed recovery health guards.
- Reconciled single-record DNS outcomes and field-masked Cloudflare TLS updates with remote-conflict detection.
- Self-contained headless data directories, stable JSON envelopes, and documented automation exit statuses.
- Crash-durable ACME account-key commits, idempotent explicit exports, and stricter private-path validation.
- Per-zone DNS authority invalidation, nested endpoint ownership, and a forward migration for legacy endpoint duplicates.
- Zone-bound TLS drafts, blocked-recovery retry, undersized-terminal input safety, and ambiguity-safe certificate forms.
