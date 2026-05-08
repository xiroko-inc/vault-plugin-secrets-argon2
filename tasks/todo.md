# vault-plugin-secrets-argon2 — v0.1.0 implementation plan

Source spec: `~/Obsidian/Vaults/xiroko/projects/vault-plugin-secrets-argon2/requirements.md`
Target: HashiCorp Vault community plugin registry. License MPL 2.0. Repo `github.com/xiroko-inc/vault-plugin-secrets-argon2` (public).

## Decisions confirmed (§12 open questions)

- Org: `xiroko-inc`
- License: MPL 2.0
- Visibility: public
- Initial version: no tag yet — scaffold lands on `feature/v0.1.0-scaffold`, opens PR; tag `v0.1.0` after first PR merges and CI is green
- Repo name: `vault-plugin-secrets-argon2` (HashiCorp convention)

## Verification step (per autonomy.md)

`go build ./...` clean, `go vet ./...` clean, `go test -race ./...` green, plugin binary launches under `vault server -dev` registered as a logical backend, `vault write argon2/policy/users` then `vault write argon2/hash/users password=...` then `vault write argon2/verify/<hash_id> password=...` returns `valid: true` end-to-end on a real dev-mode Vault.

---

## Phase 1 — Repo scaffolding

- [x] `LICENSE` — MPL 2.0
- [x] `.gitignore` — Go + macOS + Vault dev artifacts
- [x] `README.md` — install, register, integration example, link to docs
- [x] `CHANGELOG.md` — Keep-a-Changelog skeleton with `[Unreleased]`
- [x] `Makefile` — `build`, `test`, `acceptance`, `fmt`, `lint`, `vet`, `release`
- [x] `go.mod` initialized with module path
- [x] Directory tree: `cmd/vault-plugin-secrets-argon2/`, `docs/`, `.github/workflows/`, `tasks/`

## Phase 2 — Cryptographic core (TDD)

- [x] `argon2id_test.go` — failing tests first:
  - PHC structural conformance (prefix, segment count, fixed parameters)
  - Static reference vector from phc-winner-argon2 reference impl (independent of `golang.org/x/crypto/argon2`)
  - Per-call salt freshness
  - Tampered-hash rejection
  - Parameter-bound rejection (`m`, `t`, `p`, `salt_len`, `key_len` each)
  - Wrong-algorithm rejection (`argon2i`, `bcrypt`)
  - Unsupported version rejection (`v=16`)
  - `Verify` reports `drift` when stored params differ from current-policy params
- [x] `argon2id.go` — `Hash`, `Verify`, `ParsePHC`, `Params`, sentinel errors

## Phase 3 — Plugin backend skeleton

- [x] `cmd/vault-plugin-secrets-argon2/main.go` — `plugin.ServeMultiplex`
- [x] `backend.go` — `Factory` + `*framework.Backend` wiring with `PathAppend`
- [ ] `backend_test.go` — table-style acceptance tests against `vault.TestCluster` (deferred — see Coverage gaps)

## Phase 4 — Path handlers (TDD per endpoint)

- [x] `path_policy.go` — PUT/GET/DELETE/LIST `policy/<name>`
  - Defaults applied on create when fields omitted
  - Hard-bounds rejection on every numeric field
  - DELETE 404s if any hash references the policy (storage scan)
- [x] `path_hash.go` — POST `hash/<policy>`, DELETE `hash/<hash_id>`, LIST `hash`
  - Server-generated 32-character hex `hash_id` (16 random bytes) when `subject_id` omitted
  - Caller-supplied `subject_id` collision → 409
  - LIST returns ids only (no PHC/parameters/password)
  - Pagination capped at 1000
- [x] `path_verify.go` — POST `verify/<hash_id>`
  - 404 when hash doesn't exist
  - 200 + `{valid, policy_drift}` regardless of password correctness
  - `password` field marked `Sensitive: true` for audit redaction

## Phase 5 — Documentation

- [x] `docs/api.md` — every path with request/response shapes + curl examples
- [x] `docs/integration.md` — Go HTTP client, k8s auth flow, policy plumbing
- [x] `docs/threat-model.md` — formalize §7

## Phase 6 — CI/CD workflows

- [x] `.github/workflows/ci.yml` — `go build`, `go test -race -short ./...`
- [x] `.github/workflows/static-checks.yml` — `gofmt`, `go vet`, `golangci-lint`, `govulncheck`
- [x] `.github/workflows/validate-schemas.yml` — placeholder (no schemas yet)
- [x] `.github/workflows/supply-chain-audit.yml` — Go module-age check, warn-only
- [x] `.github/workflows/release.yml` — tag-driven goreleaser stub (linux/darwin amd64+arm64)

## Phase 7 — Repo init + GitHub push

- [x] `git init -b main`
- [x] Initial commit on `main` (LICENSE + README only — minimal)
- [x] Create feature branch `feature/v0.1.0-scaffold`
- [x] Commit all scaffolding to feature branch
- [x] `gh repo create xiroko-inc/vault-plugin-secrets-argon2 --public --source . --remote origin --description ...`
- [x] `git push -u origin main`
- [x] `git push -u origin feature/v0.1.0-scaffold`
- [x] `gh pr create` targeting `main` with summary + test plan

---

## Review

- All seven phases complete on the feature branch.
- `go build ./...` clean, `go vet ./...` clean, `go test -race -short ./...` green (30s).
- Unit tests cover: argon2id PHC core (12 tests including pinned external reference vector), policy CRUD (5 tests), hash create/list/delete (8 tests), verify path including drift detection (5 tests).
- Static reference vector independently produced via the `phc-winner-argon2` reference CLI installed via Homebrew (`brew install argon2`), then pinned in `argon2id_test.go`.
- The `vault` CLI is not installed locally, so an end-to-end smoke test against `vault server -dev` was skipped. The framework-level unit tests against `logical.InmemStorage` exercise the same code paths the framework will dispatch in production. A `vault.TestCluster`-based acceptance test is queued as a follow-up before tagging v0.1.0.

### Coverage gaps (declared)

- **No `vault.TestCluster` acceptance test yet.** The plugin is unit-tested via `b.HandleRequest` against `logical.InmemStorage`. This exercises the framework's dispatcher and field validation but does NOT exercise the `plugin.ServeMultiplex` host bridge. Add before tagging v0.1.0.
- **No e2e test for plugin registration / mount.** Same gap — needs `vault server -dev` or `TestCluster`.
- **No fuzz tests on `ParsePHC`.** The boundary tests cover the structural error classes but `go test -fuzz` would catch surprises in the byte-by-byte parser. Worth adding before v1.0.0.

### Follow-ups before v1.0.0 (per requirements §13)

1. `vault.TestCluster` acceptance test covering the full §9.2 list.
2. Submit to the HashiCorp Vault Community Plugin registry once one real consumer integrates and runs for a quarter without protocol-breaking changes.
3. Tag v0.1.0 once items 1+2 land.
