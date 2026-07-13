# Release process

Releases are built by GitHub Actions and GoReleaser for macOS and Linux on amd64 and arm64. Release archives contain the binary, README, changelog, project license, and third-party dependency notices, with a SHA-256 checksum manifest.

## Before tagging

1. Confirm the working tree contains no credentials, vaults, private keys, certificates, databases, or production inventory.
2. Regenerate `THIRD_PARTY_LICENSES` when dependencies change and review every detected license.
3. Move relevant entries from `Unreleased` in `CHANGELOG.md` into a versioned section.
4. Run:

   ```bash
   make verify
   make race
   make vuln
   goreleaser release --snapshot --clean
   ```

5. Inspect every snapshot archive and verify `domainops version` on a supported host.
6. Commit the release notes and create an annotated, signed semantic-version tag such as `v0.1.0`.

## Publishing

Push the commit first and wait for CI to pass. Then push the signed tag. The release workflow re-runs verification and publishes archives plus `checksums.txt`.

Never rebuild or replace an existing release tag. If a release is faulty, document it, publish a corrected version, and leave the original artifacts available for auditability.

## GitHub repository settings

For a public repository, enable:

- private vulnerability reporting;
- secret scanning and push protection;
- Dependabot alerts and security updates;
- branch protection or a ruleset requiring the CI checks and pull-request review;
- read-only default `GITHUB_TOKEN` permissions.

Protect tags matching `v*` from deletion or force updates.
