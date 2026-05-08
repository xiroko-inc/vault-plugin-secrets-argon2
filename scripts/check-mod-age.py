#!/usr/bin/env python3
"""Flag Go module dependencies published within the last N days.

Reads the JSON-stream output of `go list -m -u -json all` from a file
path. The output is a sequence of full JSON objects (not an array);
parse it with json.JSONDecoder.raw_decode to walk the stream
object-by-object. Naive line-based splitting fails because nested
objects (Update, Replace, Origin) contain interior `}` lines.

Warn-only: emits ::warning:: directives for newly-published versions
and exits 0 regardless of how many were flagged. Adversarial supply
chain detection lives in a separate gate; this is informational.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path, help="path to `go list -m -u -json all` output")
    p.add_argument(
        "--max-days",
        type=int,
        default=3,
        help="flag any version published less than N days ago (default: 3)",
    )
    p.add_argument(
        "--warn-only",
        action="store_true",
        help="always exit 0; with this flag absent, exit 1 if any warnings fire",
    )
    return p.parse_args(argv)


def iter_modules(text: str):
    """Yield top-level JSON objects from a `go list -json` stream."""
    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)
    while idx < n:
        # Skip whitespace between objects.
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError as err:
            print(
                f"::error::JSON decode failed at offset {idx}: {err}",
                file=sys.stderr,
            )
            return
        yield obj
        idx = end


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    text = args.path.read_text()
    now = datetime.datetime.now(datetime.timezone.utc)
    flagged = 0
    for mod in iter_modules(text):
        if mod.get("Main"):
            continue
        # Indirect deps without an explicit version still appear in
        # the graph; Time is only present for actual module versions.
        ver_time = mod.get("Time")
        if not ver_time:
            continue
        try:
            published = datetime.datetime.fromisoformat(
                ver_time.replace("Z", "+00:00")
            )
        except ValueError:
            continue
        age_days = (now - published).days
        if age_days < args.max_days:
            print(
                f"::warning::{mod.get('Path')}@{mod.get('Version', '?')} "
                f"published {age_days}d ago — verify before relying on it"
            )
            flagged += 1
    print(
        f"supply-chain-audit: flagged {flagged} dependency version(s) "
        f"published in the last {args.max_days} days"
    )
    return 0 if args.warn_only or flagged == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
