## Decision: Move the module to `go 1.26.3` (latest patched line) and build golangci-lint FROM SOURCE in CI (`install-mode: goinstall`) so the linter compiles under the same 1.26.3 and accepts the newer target.

## Context: PR #7 (argon2 `overwrite` param) CI went red on `format-and-lint`

A fresh batch of Go security advisories landed on 2026-05-07:

- **GO-2026-5026** — `golang.org/x/net/idna`, fixed in `x/net v0.55.0`.
- **GO-2026-4971** — stdlib `net` (Dial/LookupPort NUL-byte panic on Windows),
  fixed in **go1.25.10 / go1.26.3**.
- **GO-2026-4918** — stdlib `net/http/internal` HTTP/2 transport infinite loop,
  fixed in **go1.25.10 / go1.26.3** (the `x/net` portion was already fixed in
  v0.53.0).

govulncheck (run in `static-checks.yml`'s `format-and-lint` job) flagged all
three. Bumping the dependencies cleared GO-2026-5026; the two stdlib CVEs
require the build/scan to run on a patched Go (1.25.10 or 1.26.3).

The first attempt — adding `toolchain go1.26.3` to `go.mod` — cleared
govulncheck but BROKE golangci-lint with:

> can't load config: the Go language version (go1.25) used to build
> golangci-lint is lower than the targeted Go version (1.26.3)

## The constraint that shapes this decision

golangci-lint **intentionally builds its released binaries with the previous
Go minor.** Its own `go.mod` carries the comment *"The minimum Go version must
always be latest-1 … Only golangci-lint maintainers are allowed to change it."*
The linter then **refuses to analyze any module whose targeted Go version (the
`go`/`toolchain` directive) exceeds the Go version the linter itself was built
with.** Consequences verified on 2026-06-01:

- No golangci-lint release will be built on Go 1.26.x while 1.26 is the current
  minor — so a `1.26.x` target is rejected by every prebuilt binary until Go
  1.27 ships (months away).
- Even the patched **1.25.10** is rejected: the newest release (v2.12.2,
  2026-05-06) predates the 1.25.10 security release (2026-05-07) by one day, so
  no prebuilt binary was compiled on 1.25.10 either.

So the prebuilt-binary path cannot lint a module that targets any Go new enough
to contain the stdlib fix. The two needs (patched scan-Go vs lint-acceptable
target-Go) are in direct tension *only* because of golangci-lint's
build-version ceiling.

## Alternatives Considered

- **A — Decouple: keep `go.mod` at `go 1.25.7`, pin only the govulncheck step
  to scan under `go1.25.10`.** Both checks green now, smallest diff, prebuilt
  linter unchanged (fast, reproducible). But it declares a Go minimum the
  project doesn't actually verify against and leaves the module nominally on an
  unpatched line — a bridge, not a destination.
- **B — Everything to latest, lint from source (chosen).** Bump `go.mod` to
  `go 1.26.3`; CI installs 1.26.3 via the existing `go-version-file: go.mod`;
  switch `golangci-lint-action` to `install-mode: goinstall` + `version: latest`
  so the linter is **compiled under the runner's 1.26.3** — build-Go then equals
  the target, lifting the ceiling.
- **C — Latest target, accept lint red / drop the lint step.** Unacceptable for
  a security-sensitive Vault plugin.

## Reasoning: B won

- **One toolchain, latest and patched, everywhere.** Build, test, vet,
  govulncheck, AND lint all run on go1.26.3 — no split-brain "scan on one
  patch, declare another." The `go.mod` directive honestly states the version
  the code is built and verified on.
- **It actually works.** Verified locally on 2026-06-01: `go install
  …/golangci-lint/v2/cmd/golangci-lint@latest` under go1.26.3 produced a binary
  reporting *"built with go1.26.3"* that linted the 1.26.3-target module with
  **0 issues**; `govulncheck` under 1.26.3 reported **0 affecting
  vulnerabilities**.
- **Self-healing.** Once a golangci-lint release built on Go 1.26 ships, the
  `goinstall` workaround can collapse back to a pinned binary
  (`version: vX.Y`, drop `install-mode`) with no other change.

## Trade-offs Accepted

- **CI cost:** `goinstall` compiles golangci-lint from source each run
  (~1–2 min added to `format-and-lint`) instead of pulling a cached binary.
- **Reproducibility:** `version: latest` floats to whatever golangci-lint tag
  is newest at run time, and `goinstall` is golangci-lint's non-recommended
  install mode. Acceptable for the duration of the bridge; revisit when pinning
  a 1.26-built binary becomes possible.
- **Fleet implication:** every other Go repo with a govulncheck gate hits the
  same 2026-05-07 advisory wall. This decision is the reference remediation —
  bump the module to the patched Go and lint from source until golangci-lint
  catches up.

## Supersedes: None. (Reverses the abandoned in-PR `toolchain go1.26.3` attempt
and the alternative-A "decouple govulncheck go-version-input" approach, neither
of which was committed.)
