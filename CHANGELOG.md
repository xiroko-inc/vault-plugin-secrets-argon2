# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog][kac] and this project adheres to
[Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- Initial v0.1.0 scaffolding.
- Argon2id PHC primitives (`argon2id.go`) with hard parameter bounds
  per requirements §4.2 and a static reference vector pinned from the
  phc-winner-argon2 reference implementation.
- Vault secrets engine backend (`backend.go`) with `policy`, `hash`,
  and `verify` path tables.
- Plugin entry point at `cmd/vault-plugin-secrets-argon2/main.go`
  using `plugin.ServeMultiplex`.
- Unit tests for the cryptographic core and every path handler.
- Acceptance tests (`backend_test.go`, gated by `//go:build acceptance`)
  that build the plugin and run it under a real `vault server -dev`
  subprocess. Cover the §9.2 happy-path, policy-delete reference
  guarantee, list-returns-IDs-only, and audit-log password redaction
  against a real `file` audit device.
- CI workflows for build, static checks, schema validation, supply
  chain audit, and release. CI installs the vault binary via
  `hashicorp/setup-vault@v1` and runs the acceptance suite on every
  PR.
