# DomainOps

DomainOps is a local-first terminal console for managing domains, DNS, Cloudflare TLS, and locally owned ACME certificates. It is designed for operators with many zones across multiple accounts and remains usable over SSH on a minimal Linux server.

The default command opens a full-screen Bubble Tea v2 interface. The same engine also exposes stable JSON commands for scripts.

## Current capabilities

- Multiple Cloudflare user-owned or account-owned API tokens.
- Background account, zone, and DNS synchronization with a durable SQLite cache.
- Read visibility for every Cloudflare DNS record type.
- Structured create/edit support for A, AAAA, CNAME, TXT, MX, CAA, NS, and SRV records.
- Re-fetch-before-write conflict detection, managed-record protection, confirmation dialogs, and best-effort local audit history.
- Zone-scoped DNS batch preview/apply with fresh validation and full cache reconciliation.
- Cloudflare SSL mode, Always Use HTTPS, minimum TLS, TLS 1.3, proxied-DNS status, and edge certificate inventory support.
- Separate Let’s Encrypt staging and production accounts.
- Separate staging and production lineages and `current` links, so a staging test can never replace a production artifact.
- Apex-plus-wildcard certificates, nested wildcard pairs, EC P-256 or RSA 2048 keys, and batches capped at three concurrent ACME orders.
- Crash-safe DNS-01 journaling that removes only TXT records created by the exact job.
- ARI renewal windows and `replaces` identifiers for qualifying renewals.
- Active-zone, explicit credential routing, per-zone read-probed DNS access, and advisory cached CAA preflight before every ACME order.
- Versioned, integrity-checked PEM storage and export: `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`, and `metadata.json`; pending or revoked certificates are never re-exported as deployable material.
- Metadata-only PEM import without private keys.
- Background public DNS/TLS observations that compare the served certificate with the locally managed fingerprint.
- An encrypted XChaCha20-Poly1305 vault with Argon2id password wrapping and optional OS-keyring auto-unlock.
- macOS and Linux support without requiring containers, a database service, or a desktop keyring.

## Build and start

Go 1.26 or newer is required when building from source.

```bash
make build
./bin/domainops
```

The first run creates a local vault. On macOS or a desktop Linux session, DomainOps can use the OS keyring as an unlock convenience. On Debian, Ubuntu Server, Arch, or another headless installation, the same binary uses the password-backed vault directly:

```bash
./bin/domainops --no-keyring
```

No root privileges are required.

## Cloudflare token setup

Use a scoped API token, never a Global API Key. Recommended permissions are:

- Zone / Zone / Read
- Zone / DNS / Read
- Zone / DNS / Write
- Zone / Zone Settings / Read and Write for Cloudflare TLS controls
- SSL and Certificates / Read for edge certificate inventory

Restrict the token to only the accounts and zones DomainOps should manage. For an account-owned token, provide its Cloudflare account ID during onboarding. A user-owned token can discover zones from multiple visible accounts.

Press `a` on the Dashboard or Accounts screen to add a token. DomainOps masks it immediately and stores it only in the encrypted vault.

Cloudflare’s token-verification response does not disclose effective write scopes. DomainOps therefore labels reads from live probes and records `dns:write`/`tls:write` only after a real mutation succeeds, scoped to that credential and zone. An authoritative later DNS-access denial removes only that zone’s read evidence and detaches the denied route; network failures, rate limits, and Cloudflare 5xx responses preserve the last known-good route. Before removing a preferred connection, perform a successful DNS operation through its replacement on every affected zone within 15 minutes; DomainOps then re-probes exact-zone DNS read access, and removal otherwise fails closed.

## TUI workflow

| Key | Action |
| --- | --- |
| `1` … `7` | Navigate sections |
| `j` / `k` | Move selection |
| `/` | Filter the current view |
| `Ctrl+K` | Open the command palette |
| `r` | Synchronize Cloudflare and run public health checks |
| `R` | Retry blocked crash recovery after correcting the underlying problem |
| `a` | Add a Cloudflare connection |
| `n`, `e`, `d` | Create, edit, or delete a DNS record |
| `n`, `u`, `i`, `x`, `d` | Issue, renew due, import, export, or revoke a certificate in the Certificates view |
| `m`, `h`, `t`, `v` | Adjust the TLS mode, HTTPS, TLS 1.3, or minimum TLS version |
| `s` | Review and apply the Cloudflare TLS diff |
| `?` | Contextual help |
| `q` | Quit and restore the terminal |

Long-running synchronization, certificate, and public endpoint jobs run outside the render loop. The TUI remains navigable while they work.

## Certificate issuance

Wildcard certificates use DNS-01. A default plan for `example.com` contains both:

```text
example.com
*.example.com
```

`*.example.com` does not cover the apex or deeper names such as `a.api.example.com`. Add the nested label `api` to include `api.example.com` and `*.api.example.com`.

Always validate a new setup against Let’s Encrypt staging first:

```bash
domainops cert account-register \
  --environment staging \
  --email ops@example.com \
  --accept-tos

domainops cert issue \
  --zone example.com \
  --environment staging
```

Issue one independent wildcard lineage for every synchronized zone:

```bash
domainops cert issue \
  --all \
  --environment production \
  --email ops@example.com \
  --accept-tos \
  --confirm-production
```

Production issuance always requires explicit confirmation. A large selection creates independent certificates rather than one coupled SAN certificate.

Each order first verifies the active zone, exact preferred DNS credential, and nested challenge routing, then checks read-probed DNS-access and cached CAA signals. Cloudflare enforces write permission when the challenge is created, and Let’s Encrypt performs the authoritative live DNS and CAA checks.

Renew only certificates inside their stored renewal window:

```bash
domainops cert renew --due \
  --environment production \
  --confirm-production
```

## Files and headless automation

Default data locations:

- macOS: `~/Library/Application Support/DomainOps`
- Linux: `$XDG_DATA_HOME/domainops` or `~/.local/share/domainops`
- Override: `--data-dir PATH` or `DOMAINOPS_DATA_DIR`

An explicit data directory is self-contained and does not require `$HOME`, which makes it suitable for systemd services and containers with a single writable mount.

Each managed certificate has immutable version directories and an atomically updated `current` symlink. Production lives under `certificates/DOMAIN`; staging is isolated under `certificates/staging/DOMAIN`. Private-key files and their parent directories are owner-only. Export retries verify every file, its metadata, permissions, and certificate/key relationship; symbolic-link path redirection and replacement of a non-symlink `current` path are rejected.

Managed version directories contain an intentionally unencrypted `privkey.pem` for server deployment. The encrypted vault also retains the key, but backups of the certificate directory must be protected as sensitive material.

For a headless command, put the vault password in an owner-only file and pass its path rather than the password itself:

```bash
chmod 600 /etc/domainops/vault-password
domainops --no-keyring \
  --vault-password-file /etc/domainops/vault-password \
  sync --json
```

The password is never accepted as a literal command-line flag or printed in JSON.

If crash recovery cannot clean a journaled DNS challenge, ACME account-key commit, or certificate commit, DomainOps persists a critical dashboard finding and disables mutations in both the TUI and headless commands until recovery succeeds. In the TUI, correct the underlying provider/filesystem problem and press `R` to retry without restarting.

Headless exit statuses are stable: `0` means success, `1` means the operation failed before producing any per-item result, and `3` means a multi-item operation returned per-item failures, a provider outcome was partial/unknown, or certificate metadata committed with an activation warning. Inspect the JSON result and warnings before retrying an exit-`3` operation.

Useful commands:

```bash
domainops status --json
domainops account list --json
domainops account remove CREDENTIAL_ID --confirm 'Connection label'
domainops zone list --json
domainops zone prefer example.com --credential CREDENTIAL_ID --confirm example.com
domainops dns list --zone example.com --json
domainops sync --json
domainops cert list --json
domainops cert import --file fullchain.pem --zone example.com
domainops cert export LINEAGE_ID --to ./server-certs
domainops cert revoke LINEAGE_ID --environment production --confirm example.com
domainops health check --json
```

## Safe DNS batches

Use `domainops dns list` to obtain stable local record IDs, then create a zone-scoped mutation file:

```json
{
  "schema_version": 1,
  "mutations": [
    {
      "kind": "create",
      "after": {
        "type": "A",
        "name": "api",
        "content": "192.0.2.20",
        "ttl": 300,
        "proxied": true
      }
    },
    {
      "kind": "delete",
      "record_id": "cfrecord_REMOTE_ID"
    }
  ]
}
```

Preview is the default and performs fresh remote reads without changing Cloudflare:

```bash
domainops dns batch --zone example.com --file changes.json --json
domainops dns batch --zone example.com --file changes.json --apply --json
```

Apply revalidates the complete plan, submits one Cloudflare zone batch, reloads the full remote zone, replaces the local cache, and attempts to record one redacted audit event. Record changes detected during revalidation fail closed; a change made after the final read but before submission can still race with apply. A lost/ambiguous provider response is returned as `outcome_unknown: true`, triggers a best-effort full refresh, and must be reviewed before retrying.

## Verification

```bash
make test
make race
make check
```

The test suite covers Cloudflare request mapping and rate-limit errors, legacy SQLite upgrades and recovery state, encrypted-vault tampering, DNS-01 exact-record cleanup, 60-order bounded ACME batches, staging/production isolation, durable account/certificate commits and revocation retry, ARI renewal replacement, PEM validation/export, public TLS findings, non-blocking worker limits, CLI JSON envelopes, and responsive TUI rendering.

Live Cloudflare and Let’s Encrypt production operations should first be exercised with a dedicated test zone and the staging CA. The automated suite never issues a real production certificate.

See [architecture](docs/architecture.md) and [security](docs/security.md) for implementation boundaries and threat-model details.
