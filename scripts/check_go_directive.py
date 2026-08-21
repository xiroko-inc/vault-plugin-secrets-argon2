#!/usr/bin/env python3
"""Assert every `go` and `toolchain` directive is visible to Renovate.

THE DEFECT THIS EXISTS FOR
--------------------------
Renovate parses the go.mod `go` directive with an END-ANCHORED regex
(`modules/manager/gomod/line-parser.js`):

    const goVersionRegex = regEx(/^\\s*go\\s+(?<version>[^\\s]+)\\s*$/);

An inline `//` comment breaks the match, and the directive is then not extracted
at all. Note the contrast one line up: `requireRegex` explicitly tolerates a
trailing comment. This one does not.

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
looks like its Go version is tracked. Compare two dashboards — `xiroko-wraith#141`
lists both the image and the directive; `doro#249` lists only the image, and never
proposed a toolchain bump.

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

REMEDY = (
    "Move the comment onto its own line ABOVE the directive. Nothing else "
    "changes, and no explanatory text is lost:\n"
    "        // bump for govulncheck gate: fixes GO-2026-...\n"
    "        go 1.26.7"
)


def check_gomod_text(text: str, label: str) -> list[str]:
    """Pure check over one go.mod's contents. `label` is used in messages.

    Returns a list of human-readable failures; empty means clean.
    """
    failures: list[str] = []
    saw_go_directive = False
    reported_hidden_go = False

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.rstrip("\n")

        for loose, strict, keyword in (
            (LOOSE_GO, GO_DIRECTIVE, "go"),
            (LOOSE_TOOLCHAIN, TOOLCHAIN_DIRECTIVE, "toolchain"),
        ):
            if not loose.match(stripped):
                continue
            if strict.match(stripped):
                if keyword == "go":
                    saw_go_directive = True
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

    return failures


def check_path(path: Path) -> list[str]:
    try:
        text = path.read_text()
    except OSError as exc:
        # Fail closed. A path we could not read is not a path that passed —
        # the same rule check_workflow_pins.py applies to an empty directory.
        return [f"{path}: could not be read: {exc}"]
    return check_gomod_text(text, str(path))


def main(argv: list[str]) -> int:
    if not argv:
        print(
            "FAIL — no go.mod paths given, so nothing was examined. Refusing to "
            "report success for a check that never ran.\n"
            "Usage: check_go_directive.py <go.mod> [go.mod ...]",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    for arg in argv:
        failures.extend(check_path(Path(arg)))

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
