#!/usr/bin/env python3
"""Assert every `go` and `toolchain` directive is visible to Renovate.

THE DEFECT THIS EXISTS FOR
--------------------------
Renovate parses the go.mod `go` directive with an END-ANCHORED regex
(`modules/manager/gomod/line-parser.js`):

    const goVersionRegex = regEx(/^\\s*go\\s+(?<version>[^\\s]+)\\s*$/);

An inline `//` comment breaks the match, and the directive is then not extracted
at all. Note the contrast at `line-parser.js:10`: `requireRegex` explicitly
tolerates a trailing comment. This one does not. (The line immediately above is
`toolRegex`, which is another end-anchored one — not the contrast.)

    go 1.26.5 // bump for govulncheck gate: ...   ->  INVISIBLE
    go 1.25.12                                    ->  DETECTED

`toolchain` has the identical anchor and the identical consequence.

WHY IT MATTERS MORE THAN A PARSE ERROR
--------------------------------------
**The `go` directive is where the stdlib security patch level lives.** When
Renovate cannot see it, reachable stdlib CVEs have no automated fix path at all —
silently and permanently, with no error, no warning and no Dependency Dashboard
entry.

It is also SELF-SEALING: three of the four instances that prompted this checker
were comments documenting a *previous* govulncheck-driven bump. The note
explaining why someone bumped Go by hand is the thing guaranteeing the next bump
must also be by hand.

And it HIDES BEHIND A MANAGER THAT STILL WORKS: the `golang` Docker base image is
extracted by a different manager and keeps producing PRs, so an affected repo
looks like its Go version is tracked. Compare two Dependency Dashboards — a
healthy repo lists both the image and the `go` directive; an affected one lists
only the image, and has never proposed a toolchain bump.

(Deliberately generic. This file is vendored into a PUBLIC repo, and the earlier
wording named two private repos and asserted one of them was running an unpatched
Go stdlib. The teaching point does not need the names.)

Full analysis: xiroko-inc/.github#25.

WHY THE REGEXES ARE COPIED HERE RATHER THAN READ FROM node_modules
------------------------------------------------------------------
This file is VENDORED VERBATIM into public repos, which cannot reach the private
`xiroko-inc/.github` from CI — a fork gets the whole tree and its CI must work
with nothing privileged, so a reference would break by construction. Vendored
copies therefore cannot read `node_modules/renovate`, and stdlib-only is a hard
requirement here.

The copy is kept honest by `test_check_go_directive.py`, which reads the real
regexes out of the pinned Renovate and fails if either has changed, and by the
fleet sweep, which asserts each vendored copy still matches this one. Drift is
loud, not silent.

**When this file changes, re-vendor it into every repo named in
`go-directive-vendored.json`.** That file is the only list — deliberately not
repeated here, because a second copy of the list is how the sweep quietly stops
covering a repo someone vendored by hand.

WHAT THIS IS
------------
A **tripwire**, not a boundary (security.md → *Guard design*). It catches the
careless reintroduction of an inline comment — which is how all four real
instances arrived, written by people documenting their work. It does not stop a
determined author, and a repo running neither PR-time check is covered only by
the weekly sweep.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Mirrors line-parser.js:15-16 exactly. Do not "improve" these — a divergence
# from upstream is the whole defect, and the test asserts byte-equality after
# translating JS named groups to Python's spelling.
GO_DIRECTIVE = re.compile(r"^\s*go\s+(?P<version>[^\s]+)\s*$")
TOOLCHAIN_DIRECTIVE = re.compile(r"^\s*toolchain\s+go(?P<version>[^\s]+)\s*$")

# Intent detectors. A line matching one of these is TRYING to be a directive;
# if the strict regex above then fails, Renovate silently drops it.
#
# `\s+` after the keyword is load-bearing: it is what stops `go.uber.org/zap
# v1.27.0` inside a require block, and `godebug default=go1.25`, from being read
# as directives. Both are ordinary go.mod content.
LOOSE_GO = re.compile(r"^\s*go\s+\S")
LOOSE_TOOLCHAIN = re.compile(r"^\s*toolchain\s+\S")

# `toolchain default` is valid go.mod and names no version to track, so the
# strict regex's missing `go` prefix is correct behaviour, not a hidden
# directive. Without this, the checker reports it "invisible to Renovate" and
# prescribes moving a comment that is not there.
TOOLCHAIN_DEFAULT = re.compile(r"^\s*toolchain\s+default\s*$")

# Renovate's `[^\s]+` swallows a comment that has no space before it, so
# `go 1.25.0//x` MATCHES the strict regex and yields the "version" `1.25.0//x`
# — which resolves to nothing, i.e. the same silent no-update outcome this
# checker exists to catch, reached through a passing match instead of a failing
# one. `go mod edit -fmt` rewrites that line (to a form we already flag), so
# only a never-formatted file carries it. Cheap to close, so close it.
PLAUSIBLE_VERSION = re.compile(r"^\d+(\.\d+)*([a-z0-9.\-]*)$")

REMEDY = (
    "Move the comment onto its own line ABOVE the directive. Nothing else "
    "changes, and no explanatory text is lost:\n"
    "        // bump for govulncheck gate: fixes GO-2026-...\n"
    "        go 1.26.7"
)

# A purely numeric dotted version, e.g. `1.27.0` or `1.26`. Anything carrying a
# prerelease or other suffix (`1.25.0-rc.1`, `1.27rc1`) matches PLAUSIBLE_VERSION
# but NOT this — see compare_go_versions for why that distinction is deliberate.
#
# Each component is length-bounded. `int()` raises above CPython's 4300-digit
# conversion limit, and this parses a go.mod fetched from any repo in the weekly
# sweep — an unbounded `\d+` turns crafted content into a traceback instead of
# the named, human-readable failure every other path here returns. It fails
# closed either way (the cron records the repo, CI reds the job), so this is
# posture, not a hole.
NUMERIC_VERSION = re.compile(r"^\d{1,10}(\.\d{1,10})*$")

ORDERING_REMEDY = (
    "Lower the `go` directive to a deliberate language FLOOR, strictly below "
    "`toolchain`. The floor is the minimum a consumer needs; `toolchain` is what "
    "the code actually builds with, and it does not propagate to consumers:\n"
    "        go 1.25.0\n"
    "        toolchain go1.27.0"
)


def compare_go_versions(left: str, right: str) -> int | None:
    """Order two Go versions. Returns -1/0/1, or None if not comparable.

    None is not "equal" and must never be treated as a pass. Go orders
    prereleases BEFORE their release (1.27rc1 < 1.27.0), and encoding that
    correctly here would mean reimplementing part of go/version against a
    format this checker never needs to see: no released Go toolchain is a
    prerelease, so a `toolchain` line naming one is already unusual enough to
    deserve a human. Refusing to compare sends it to one; guessing would let a
    collapsed pair through on the strength of a suffix nobody checked.

    Plain list comparison, deliberately NOT zero-padded to equal width. Go
    orders a bare language version BELOW its .0 release — `1.26 < 1.26.0` —
    and Python's lexicographic list compare reproduces that for free, because
    an equal shorter prefix sorts first. Padding `1.26` to `[1, 26, 0]` makes
    it compare EQUAL to `1.26.0`, which is wrong in the one direction that
    matters: `go 1.26` + `toolchain go1.26.0` survives `go mod tidy` (probed),
    so a padded comparison reports a deletion that never happens.
    """
    if not (NUMERIC_VERSION.match(left) and NUMERIC_VERSION.match(right)):
        return None
    lhs = [int(p) for p in left.split(".")]
    rhs = [int(p) for p in right.split(".")]
    return (lhs > rhs) - (lhs < rhs)


def check_gomod_text(text: str, label: str) -> list[str]:
    """Pure check over one go.mod's contents. `label` is used in messages.

    Returns a list of human-readable failures; empty means clean.
    """
    failures: list[str] = []
    saw_go_directive = False
    reported_hidden_go = False
    # (lineno, version) for the ordering check below. Only directives that both
    # matched strictly and carry a plausible version are recorded — a hidden or
    # garbage directive is already one reported defect, and comparing against a
    # version Renovate cannot read would add a second message about the first.
    go_seen: tuple[int, str] | None = None
    toolchain_seen: tuple[int, str] | None = None

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.rstrip("\n")

        for loose, strict, keyword in (
            (LOOSE_GO, GO_DIRECTIVE, "go"),
            (LOOSE_TOOLCHAIN, TOOLCHAIN_DIRECTIVE, "toolchain"),
        ):
            if not loose.match(stripped):
                continue
            if keyword == "toolchain" and TOOLCHAIN_DEFAULT.match(stripped):
                continue
            match = strict.match(stripped)
            if match:
                version = match.group("version")
                if not PLAUSIBLE_VERSION.match(version):
                    failures.append(
                        f"{label}:{lineno}: the `{keyword}` directive matches "
                        f"Renovate's regex but yields an unusable version.\n"
                        f"        {stripped.strip()}\n"
                        f"    Renovate would extract `{version}`, which is not a Go "
                        f"version and resolves to no update — the same silent outcome "
                        f"as hiding the directive, reached through a passing match. "
                        f"Almost always a `//` comment with no space before it, which "
                        f"the regex's `[^\\s]+` swallows whole.\n"
                        f"    {REMEDY}"
                    )
                    if keyword == "go":
                        reported_hidden_go = True
                    continue
                if keyword == "go":
                    saw_go_directive = True
                    go_seen = (lineno, version)
                else:
                    toolchain_seen = (lineno, version)
                continue
            if keyword == "go":
                reported_hidden_go = True
            failures.append(
                f"{label}:{lineno}: the `{keyword}` directive is invisible to "
                f"Renovate.\n"
                f"        {stripped.strip()}\n"
                f"    Renovate's {keyword} regex is end-anchored, so anything after "
                f"the version — almost always an inline `//` comment — means the "
                f"directive is not extracted at all. This repo then has no automated "
                f"path for Go toolchain updates, which is where the stdlib security "
                f"patch level lives. It fails silently: no error, no dashboard entry.\n"
                f"    {REMEDY}"
            )

    # Suppressed when a hidden directive was already reported: that is ONE defect
    # with one fix, and saying it twice per file would double the noise in the
    # fleet sweep for every affected repo. The absent case is still reported on
    # its own, because it has the same consequence and a different remedy.
    if not saw_go_directive and not reported_hidden_go:
        failures.append(
            f"{label}: no `go` directive at all.\n"
            "    A module with no `go` directive gets no toolchain updates from "
            "Renovate, which has the same consequence as hiding one: the stdlib "
            "patch level stops being tracked. Add one — `go mod tidy` writes it."
        )

    # ------------------------------------------------------------------ #
    # `toolchain` must be STRICTLY GREATER than `go`. The two ways it can
    # fail that have DIFFERENT consequences, so they get different messages.
    #
    # Reproduced against throwaway modules on go1.26.2 (re-runnable via
    # probe_toolchain_tidy.sh; recorded in xiroko-inc/.github ->
    # decisions/2026-08-23-go-toolchain-split-and-osv-coverage.md):
    #
    #   go 1.27.0 + toolchain go1.27.0  ->  toolchain REMOVED   (equal)
    #   go 1.27.0 + toolchain go1.26.2  ->  preserved, inert    (lower)
    #   go 1.26   + toolchain go1.26.0  ->  preserved           (1.26 < 1.26.0)
    #   go 1.26   + toolchain go1.26.1  ->  preserved           (two-comp go, three-comp tc)
    #   go 1.26.0 + toolchain go1.26.2  ->  preserved (holds at PATCH granularity)
    #   go 1.25.0 + toolchain go1.27.0  ->  preserved           (the target shape)
    #
    # TIDY DELETES ONLY THE EQUAL PAIR. "Not strictly greater implies deleted"
    # is false for the lower case and must not be written anywhere — it was, in
    # five places, and every one shipped a consequence the go command does not
    # produce.
    #
    # Why the EQUAL case is worth a checker rather than a comment: the deletion
    # is silent and self-concealing. Losing the `toolchain` line drops the
    # module back to depType `golang`, for which Renovate's OSV worker returns
    # null — so the stdlib security path goes away while `audit` stays green and
    # no dashboard entry appears.
    #
    # ⚠️ AND BE EXACT ABOUT WHAT THIS DOES NOT CATCH. It sees the UNTIDIED
    # precursor only. Once tidy has run, the collapse presents as a bare `go`
    # directive, which the branch below deliberately passes — indistinguishable
    # from a not-yet-migrated repo. On the bot path (the preset's grouped
    # golang+toolchain rule with `rangeStrategy: bump` plus `gomodTidy` raises
    # and strips inside ONE Renovate PR) this check never fires at all. The
    # load-bearing guard there is each migrated repo's repo-level rule disabling
    # depType `golang` — which no checker observes (the #11 class). This is a
    # tripwire over the hand-edit path, not a boundary over the bot path.
    #
    # Fires ONLY when a `toolchain` line exists. Modules with a bare `go`
    # directive are the fleet's current majority and are not the subject of
    # this rule; flagging them here would red every unmigrated repo at once
    # and bury the one signal this check exists to raise.
    # ------------------------------------------------------------------ #
    if go_seen and toolchain_seen:
        go_lineno, go_version = go_seen
        tc_lineno, tc_version = toolchain_seen
        order = compare_go_versions(tc_version, go_version)
        if order is None:
            failures.append(
                f"{label}:{tc_lineno}: cannot order `toolchain go{tc_version}` "
                f"against `go {go_version}` (line {go_lineno}).\n"
                f"    One of them is not a plain dotted-numeric version this "
                f"check will order — either it carries a prerelease or other "
                f"non-numeric suffix, or a component is longer than 10 digits. "
                f"Neither is guessed at: Go sorts prereleases BEFORE their "
                f"release, so a wrong guess would pass a pair that `go mod tidy` "
                f"then collapses, and an unbounded component would reach `int()` "
                f"above CPython's conversion limit.\n"
                f"    There is no hand-confirmation mechanism for this checker. "
                f"An over-long component cannot come from a real go.mod, so treat "
                f"it as malformed input. A deliberate prerelease pin is the case "
                f"this check cannot express — raise it rather than working around "
                f"it."
            )
        elif order == 0:
            failures.append(
                f"{label}:{tc_lineno}: `toolchain go{tc_version}` is equal to "
                f"`go {go_version}` (line {go_lineno}), so `go mod tidy` will "
                f"DELETE the toolchain line.\n"
                f"    The module then falls back to depType `golang`, for which "
                f"Renovate's OSV worker returns null — losing the stdlib security "
                f"path entirely, with a green `audit` check and nothing red to "
                f"signal it. The directive to bump on a recurring basis is "
                f"`toolchain`, not `go`.\n"
                f"    {ORDERING_REMEDY}"
            )
        elif order < 0:
            failures.append(
                f"{label}:{tc_lineno}: `toolchain go{tc_version}` is lower than "
                f"`go {go_version}` (line {go_lineno}), so it is INERT.\n"
                f"    `go mod tidy` preserves this line — it is not the collapse "
                f"case — but the go command needs at least the `go` directive, so "
                f"it upgrades past the named toolchain and this version is never "
                f"what builds. Renovate still tracks it, which means the thing "
                f"being kept current is not the thing being used.\n"
                f"    {ORDERING_REMEDY}"
            )

    return failures


def check_path(path: Path, label: str | None = None) -> list[str]:
    try:
        text = path.read_text()
    except OSError as exc:
        # Fail closed. A path we could not read is not a path that passed —
        # the same rule check_workflow_pins.py applies to an empty directory.
        return [f"{label or path}: could not be read: {exc}"]
    return check_gomod_text(text, label or str(path))


USAGE = "Usage: check_go_directive.py [--label <name>] <go.mod> [go.mod ...]"


def main(argv: list[str]) -> int:
    # --label renames the file in every message. The fleet sweep fetches each
    # go.mod to a scratch path and needs the report to name the REPO path, and
    # the alternative — rewriting the output afterwards with `sed` — meant
    # interpolating an arbitrary repo's file path into a sed expression. Paths
    # legally contain `|`, `&`, `*` and `[`; the first breaks the command and,
    # under GNU sed's `s///e`, can hand the substituted line to a shell. Passing
    # the label in as data removes that whole surface rather than escaping it.
    label: str | None = None
    if argv and argv[0] == "--label":
        if len(argv) < 3:
            print(f"FAIL — --label needs a value and at least one file.\n{USAGE}", file=sys.stderr)
            return 1
        label = argv[1]
        argv = argv[2:]
        if len(argv) > 1:
            # One label cannot honestly name several files.
            print(f"FAIL — --label takes exactly one file.\n{USAGE}", file=sys.stderr)
            return 1

    if not argv:
        print(
            "FAIL — no go.mod paths given, so nothing was examined. Refusing to "
            f"report success for a check that never ran.\n{USAGE}",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    for arg in argv:
        failures.extend(check_path(Path(arg), label))

    if failures:
        print(f"FAIL — {len(failures)} directive problem(s):\n")
        for f in failures:
            print(f"  * {f}\n")
        return 1

    noun = "file" if len(argv) == 1 else "files"
    print(f"OK — every go and toolchain directive in {len(argv)} {noun} is visible to Renovate")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
