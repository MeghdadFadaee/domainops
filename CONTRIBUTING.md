# Contributing to DomainOps

DomainOps manages live DNS and private certificate material. Contributions are welcome, but changes to mutation, credential, vault, ACME, and recovery paths require conservative review.

## Development setup

Use Go 1.26 or newer.

```bash
git clone https://github.com/MeghdadFadaee/domainops.git
cd domainops
make verify
make build
```

Run the race detector before submitting changes to worker, event, synchronization, or TUI state code:

```bash
make race
```

Run the vulnerability scan when dependencies change:

```bash
make vuln
make licenses
```

Review the regenerated third-party license directory before committing it; generation is an aid, not a substitute for license review.

## Safety rules

- Never commit Cloudflare tokens, vault files or passwords, private keys, certificates, SQLite databases, or real infrastructure inventories.
- Use `example.com`, RFC 5737 IP addresses, fake provider IDs, and local HTTP test servers in tests and examples.
- Never add a test that contacts Cloudflare or a production ACME directory.
- Preserve explicit per-zone credential routing. A mutation must not silently fall back to another credential.
- Re-fetch provider state before destructive writes and treat ambiguous provider outcomes as unknown until reconciled.
- DNS-01 cleanup must delete only the record created or durably adopted by the exact challenge job.
- Keep staging and production ACME accounts, lineages, and filesystem activation paths isolated.
- Keep terminal mutations disabled while crash recovery is blocked.

## Pull requests

Keep changes focused and explain operator-visible behavior. Add tests for success, cancellation, stale state, provider denial, and ambiguous outcomes as applicable. Update `README.md`, `docs/`, and `CHANGELOG.md` when workflows or guarantees change.

Maintainers may ask for a design issue before accepting a new provider adapter or a change to the storage, vault, or release formats.

By submitting a contribution, you agree that it may be distributed under the project’s [MIT License](LICENSE), and you certify that you have the right to submit it.
