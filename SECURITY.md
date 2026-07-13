# Security Policy

DomainOps handles DNS authority, API credentials, ACME account keys, and deployable private keys. Please report suspected vulnerabilities privately and avoid testing against infrastructure you do not own.

## Supported versions

Before the first tagged release, security fixes are applied to the `main` branch. After releases begin, the latest published minor release and `main` are supported. Older prereleases and development snapshots are not supported.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/MeghdadFadaee/domainops/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Include:

- the affected version or commit;
- the operating system and architecture;
- a minimal reproduction using fake tokens, example domains, and non-production data;
- the security impact and any known mitigations.

Never send live Cloudflare tokens, vault passwords, vault/database files, ACME account keys, certificate private keys, or an unredacted production inventory. If sensitive material was exposed while reproducing an issue, revoke or rotate it immediately.

You should receive an acknowledgement within seven days. Validation and remediation timing depend on severity and complexity. Please allow time for a fix and coordinated disclosure before publishing details.

## Scope

Security reports are especially useful for:

- credential or private-key disclosure;
- vault, filesystem-permission, or path-traversal weaknesses;
- cross-account or cross-provider routing errors;
- DNS mutation conflict bypasses;
- DNS-01 cleanup deleting records it does not own;
- staging/production certificate isolation failures;
- crash-recovery bypasses or unsafe retry behavior.

Operational questions, provider outages, and feature requests belong in the public issue tracker after removing sensitive data.
