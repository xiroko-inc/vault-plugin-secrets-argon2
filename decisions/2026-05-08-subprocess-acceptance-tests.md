## Decision: acceptance tests drive a `vault server -dev` subprocess instead of an in-process `vault.TestCluster`

## Context: the v0.1.0-acceptance-tests PR (PR #2) needed to close the §9.3 coverage gap from the original requirements doc. §9.3 names `vault.TestCluster` from `github.com/hashicorp/vault/vault` as the canonical pattern — spin up Vault in-process, mount the plugin via a `logical.Factory` map, exercise the API client against the in-memory cluster. That's the pattern most community plugins followed circa 2024.

When I tried it locally against `github.com/hashicorp/vault@v1.21.4` + `sdk@v0.25.1`, the build failed:

```
github.com/hashicorp/vault@v1.21.4/vault/acme_billing_system_view.go:76:12:
  undefined: logical.PkiCertificateCountSystemView
... (similar undefined-types + signature-mismatch errors)
```

Root cause: vault's own go.mod has `replace github.com/hashicorp/vault/sdk => ./sdk`. The replace only applies inside the vault repo's own build. Downstream consumers don't see it, so they end up trying to compile `vault@v1.21.4`'s `vault/` package against whichever SDK their own go.mod has pinned — and that SDK has API surface drift relative to whatever vault was built against internally. The `vault` package is structurally not designed for downstream import.

Downgrading SDK to match (e.g., v0.21.0) would have unwound four versions of bugfixes including the Sensitive: true annotation behavior we depend on. Adding a `replace` of our own would be brittle against future vault releases.

## Alternatives Considered

- **§9.3 in-process `vault.TestCluster`** — what the spec asked for. Doesn't compile against any current SDK release. Rejected.
- **Pin SDK to match vault's internal replace target** — downgrade SDK to whatever version vault@v1.21.4's internal `./sdk` corresponds to (≈ v0.21.0). Works in principle, but loses 4 versions of SDK fixes and would block any future SDK bump without a coordinated vault bump.
- **Vendor vault with a local replace** — add `replace github.com/hashicorp/vault/sdk => github.com/hashicorp/vault/sdk v0.25.1` in our go.mod. Brittle: every vault release requires re-validating that the replace target's API matches what vault's `vault/` package expects.
- **Skip in-process testing entirely, ship with only path-handler unit tests** — what we did pre-PR #2. Misses `plugin.ServeMultiplex` host-bridge coverage and real audit-device redaction.
- **`vault server -dev -dev-plugin-dir=<dir>` subprocess + the api client** — what we chose. Trade-off: requires a `vault` binary on PATH (installed in CI via direct release-archive download with SHA-256 verification; `brew install vault` for local dev).

## Reasoning: the subprocess approach matches the §9.3 *intent* ("exercise the plugin end-to-end against real Vault machinery") even though it diverges from the *mechanism*. The plugin runs in a real process under real `plugin.ServeMultiplex`; the API client talks real HTTP through the loopback listener; audit-device redaction is exercised against a real `file` audit device. None of that was reachable through the unit-test layer against `logical.InmemStorage`. The cost — a vault binary on PATH — is paid once per CI runner via `actions/setup-go` + the curl-from-releases.hashicorp.com install (currently pinned to vault v1.21.4 with SHA-256 verification).

## Trade-offs Accepted

- **CI must install the vault binary on every run** (~5 seconds: download, verify SHA, install). Cached across PRs via setup-go's cache key.
- **Local `make acceptance` requires `brew install vault`.** Documented in the Makefile target's comment.
- **Test setup is heavier than `vault.TestCluster` would be**: `t.TempDir` for the plugin dir, plugin build cache, free-port selection, subprocess launch, readiness polling, plugin registration with SHA, then mount. ~5 seconds of setup before any actual test logic, vs ~50ms for an in-process cluster.
- **macOS gotcha**: `$TMPDIR` is `/var/folders/...` but Vault resolves runtime paths to `/private/var/...`. Required `filepath.EvalSymlinks` on the plugin dir before passing it to the subprocess.
- **`-race` plugin build path takes ~90s instead of ~5s** because the plugin gets re-compiled with `-race` when the test binary itself is race-instrumented. Build-tag-driven `raceEnabled` const handles this. Acceptable cost — without it, the test's race detector wouldn't see across the subprocess boundary at all.

## Supersedes: None. This is the first decision file in the repo.

## Notes for revisiting

- If HashiCorp ever fixes the vault main module to be a clean library (no internal `replace`), revisit the in-process `vault.TestCluster` pattern — it would be faster and not require a vault binary in CI. The signal to watch for is the `replace` directive disappearing from vault's own go.mod, which would also mean the `vault/` package's API surface stabilizes against the public SDK.
- The `sdk/helper/testcluster/exec.go` helper in newer SDK versions provides a similar exec-based pattern with more polish (cluster-of-N, replication setup, etc.). Our simpler single-node implementation is ~300 LOC; switching to the helper would shed code but inherit its breakage profile.
- A v1.0.0 follow-up worth considering: package `pkg/testing/devvault` exposing the subprocess pattern as a public test helper for downstream consumers. Currently lives only in `backend_test.go`.
