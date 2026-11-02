#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize the ask log (lib/agent_policy/asklog.py): how often the policy
asked or refused, why, and on which commands.

  python3 tools/asks.py [--top N] < asks.jsonl

It reads the log on standard input and opens no file, so `make asks` hands
the test container that one file and nothing else. Standard library only.
"""

import argparse
import json
import sys
from collections import Counter


def read(lines):
    """The records among `lines`, and how many lines were not records."""
    records, skipped = [], 0
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        # The guard writes both on every line; anything else is not its.
        if isinstance(record, dict) and "source" in record and "decision" in record:
            records.append(record)
        else:
            skipped += 1
    return records, skipped


def _words(value):
    return [str(v) for v in value] if isinstance(value, list) else []


def summarize(records, top=20):
    """The report, as lines of text."""
    if not records:
        return ["asks: the log is empty"]
    stamps = sorted(str(r.get("ts", "")) for r in records)
    out = [f"asks: {len(records)} prompts or refusals, {stamps[0]} to {stamps[-1]}", ""]

    def table(title, counter):
        out.append(title)
        for key, count in counter.most_common(top):
            out.append(f"  {count:6}  {key}")
        out.append("")

    table(
        "By decision (source decision):",
        Counter(f"{r.get('source')} {r.get('decision')}" for r in records),
    )
    table(
        "By reason (source decision reason):",
        Counter(f"{r.get('source')} {r.get('decision')} {r.get('reason')}" for r in records),
    )
    unmatched = [r for r in records if r.get("decision") == "unmatched"]
    table(
        "No allow rule matched, by command:",
        Counter(name for r in unmatched for name in _words(r.get("unmatched"))),
    )
    table(
        "No allow rule matched, by variables set in front:",
        Counter(" ".join(_words(r.get("env"))) or "(none)" for r in unmatched),
    )
    table(
        "Every line, by the commands on it:",
        Counter(" ".join(_words(r.get("names"))) or "(none)" for r in records),
    )
    return out


def main(argv=None, stdin=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=20, help="rows per table (default 20)")
    args = parser.parse_args(argv)
    records, skipped = read(sys.stdin if stdin is None else stdin)
    print("\n".join(summarize(records, args.top)))
    if skipped:
        print(f"asks: skipped {skipped} lines that are not records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
