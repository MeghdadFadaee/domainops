# Security Model

DomainOps manages credentials and private keys, so its defaults assume the local user account and operating system are trusted while backups, logs, shell history, and accidental file exposure are not.

## Protected material

The encrypted vault contains:

- Cloudflare API tokens
- Let’s Encrypt account private keys
- Managed certificate private keys

The metadata database never stores these values. JSON output, TUI views, audit events, and provider errors omit them.

The vault uses XChaCha20-Poly1305 authenticated encryption. A random data key encrypts all entries; Argon2id wraps that key with the local password. The file is replaced atomically and uses mode `0600` inside a `0700` directory.

OS keyrings may retain the random data key to provide automatic local unlock. `--no-keyring` disables this behavior. On a headless machine, a vault password is sufficient and no D-Bus/Secret Service process is required.

## Cloudflare access

Global API Keys are rejected. Use least-privilege API tokens scoped to the necessary accounts and zones. DNS issuance requires Zone Read and DNS Write. Cloudflare TLS changes require Zone Settings Write. The app verifies the token namespace and performs real read probes, which provide capability hints but cannot prove write access; Cloudflare remains authoritative for write permission enforcement. DomainOps records write capability only after a real provider mutation succeeds, scoped to that credential and zone, and credential removal requires matching evidence from the last 15 minutes.

Tokens are masked during entry. Headless use accepts a token file or vault-password file only when it is a regular file with no group/other permission bits. Literal secret flags are intentionally unavailable.

TUI connection removal and zone routing bind confirmation to immutable local IDs rather than filtered row positions or non-unique labels. Removal shows affected routes, uses a bounded long-running verification window, and refuses to remove a credential when any preferred zone lacks a live-readable replacement with recent observed write success. Explicit preference changes live-probe DNS read access and label write authority as unproven until an actual provider mutation succeeds.

## ACME safety

- Staging is the default issuance environment.
- Production issuance requires explicit confirmation.
- The first and renewed certificate keys are generated locally.
- Wildcard validation uses DNS-01 only.
- Each challenge TXT record is stored by exact Cloudflare record ID.
- Cleanup never deletes every TXT value at `_acme-challenge`.
- Open challenge journals survive crashes and are retried after unlock.
- ACME account keys are journaled before registration and account metadata closes that intent transactionally; a losing or failed registration is compensated without replacing an existing environment account.
- Certificate commit intents survive power loss and recover orphaned vault keys and plaintext temporary/final PEM paths before normal mutations resume.
- A failed recovery is persisted as a critical health finding; application-level mutation guards remain closed until a later unlock completes recovery successfully.
- Batches are bounded to three active orders.
- Renewals preserve identifier sets and use ARI replacement IDs.
- Every order preflights active-zone state, explicit credential routing, exact per-zone read-probed DNS access, and cached CAA records. An authoritative later access denial revokes that local evidence; transient provider failures do not. The advisory CAA check rejects unknown issuer-critical properties, incompatible validation methods, and unverifiable account-only bindings. Cloudflare and the CA remain authoritative for live write permission and CAA policy.
- Staging and production use different lineages and filesystem `current` links.
- Revocation intent is persisted before contacting the CA; an `alreadyRevoked` retry safely converges local state after a prior local-write failure.

Certificate names are public through Certificate Transparency; do not put private internal hostnames into a public ACME order.

## PEM export boundary

Server-ready `privkey.pem` files are intentionally unencrypted because common web servers need to read them unattended. DomainOps creates them in the managed certificate version directory during issuance and in any explicit export destination. Both locations are owner-only; export path components and immutable files are checked against symbolic-link redirection, unsafe types, altered permissions, and material/metadata mismatches. Pending or revoked versions are refused by explicit export. Backups still contain plaintext private keys: copy them through a trusted transport such as SFTP, verify fingerprints after deployment, and remove unnecessary copies.

Metadata-only imports refuse PEM blocks containing private keys.

## Operational recommendations

- Use separate staging and production ACME accounts.
- Start with a dedicated test zone.
- Prefer one certificate lineage per registered domain.
- Keep the DomainOps data directory out of general-purpose cloud synchronization.
- Protect password files with `chmod 600` and a restricted parent directory.
- Review the local audit view before applying another change after a timeout.
- Treat a public fingerprint mismatch as “not yet deployed” until verified.

## Non-goals in the current release

DomainOps is not a multi-user secrets server, HSM client, deployment agent, or continuous monitoring service. It does not protect against a fully compromised local account, a malicious kernel, or an attacker who can read the process memory while the vault is unlocked.
