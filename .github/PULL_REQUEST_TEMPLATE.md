## Summary

Describe the operator-visible behavior and why the change is needed.

## Safety checklist

- [ ] I did not include API tokens, vault files, private keys, certificates, databases, or production-domain data.
- [ ] Provider mutations retain conflict checks, explicit credential routing, and fail-closed behavior.
- [ ] Certificate changes preserve staging/production isolation and exact DNS-01 cleanup ownership.
- [ ] I added or updated tests for the changed behavior.
- [ ] `make verify` passes locally.
- [ ] I updated documentation and the changelog when behavior changed.

## Testing

List the commands and environments used to validate this change.
