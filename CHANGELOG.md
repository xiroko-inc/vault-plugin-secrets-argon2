# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog][kac] and this project adheres to
[Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- `docs/migration-from-in-process.md` — guide for services
  already using `golang.org/x/crypto/argon2` directly that want
  to move hash material into Vault behind this plugin. Covers
  before/after Go code shapes, two DB schema options, three
  rollout strategies (cutover, dual-read with lazy migration,
  bulk import) with explicit recommendations and a "we do not
  recommend Strategy C" note, operational considerations
  (Vault on the login path, audit volume, token renewal,
  rate-limit placement), and a verification checklist.

## [0.1.1] — 2026-05-08

### Added

- Fuzz tests on `ParsePHC` and `Verify` (`argon2id_fuzz_test.go`).
  Initial run: 6.07M `FuzzParsePHC` executions + 707K `FuzzVerify`
  executions over 10 minutes each, zero panics found. Seed corpus
  covers the canonical happy-path vector plus structural error
  classes (empty input, all-separator, wrong algorithm/version,
  malformed numerics, non-base64 segments, multi-byte runes,
  100KB-segment denial-of-service inputs).

## [0.1.0] — 2026-05-08

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
  chain audit, and release. CI installs the vault binary by
  downloading the pinned release archive from
  `releases.hashicorp.com` (verified against the published SHA-256
  sum) and runs the acceptance suite on every PR.
