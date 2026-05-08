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
- CI workflows for build, static checks, schema validation, supply
  chain audit, and release.
