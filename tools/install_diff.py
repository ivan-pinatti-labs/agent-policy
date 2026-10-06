#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compare what `make install` would write with what is installed now.

Each argument is INSTALLED=SOURCE (a file or a folder), or, with --link,
LINK=TARGET for a symbolic link install creates. Every path is reported as

  new         nothing is installed there yet
  unchanged   the installed copy matches
  changed     it differs; its unified diff follows
  error       it could not be compared (unreadable, or a file where a
              folder is expected); the run then exits 1

Nothing is installed or changed. Runs on the host's own Python, since it
reads the installed files.
"""

import argparse
import difflib
import os
import sys
from pathlib import Path

SKIP = {"__pycache__"}


class CompareError(Exception):
    pass


def raise_error(err):
    raise err


def files_under(folder):
    """Relative paths of every file under folder, skipping SKIP folders."""
    out = set()
    for root, dirs, names in os.walk(folder, onerror=raise_error):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in names:
            out.add(os.path.relpath(os.path.join(root, name), folder))
    return out


def read(path):
    try:
        return Path(path).read_bytes()
    except OSError as err:
        raise CompareError(f"{path}: {err.strerror}") from err


def text_diff(old, new, old_name, new_name):
    lines = difflib.unified_diff(
        old.decode(errors="replace").splitlines(keepends=True),
        new.decode(errors="replace").splitlines(keepends=True),
        old_name,
        new_name,
    )
    return "".join(lines)


def compare(installed, source):
    """None when they match, else the diff text. Raises CompareError."""
    inst, src = Path(installed), Path(source)
    if inst.is_dir() != src.is_dir():
        raise CompareError(
            f"{installed} is a {'folder' if inst.is_dir() else 'file'}, the source is not"
        )
    if not inst.is_dir():
        old, new = read(inst), read(src)
        return None if old == new else text_diff(old, new, installed, source)
    try:
        names = files_under(inst) | files_under(src)
    except OSError as err:
        raise CompareError(f"{err.filename}: {err.strerror}") from err
    parts = []
    for name in sorted(names):
        a, b = inst / name, src / name
        if not a.exists():
            parts.append(f"only in the source: {b}\n")
        elif not b.exists():
            parts.append(f"only installed: {a}\n")
        else:
            old, new = read(a), read(b)
            if old != new:
                parts.append(text_diff(old, new, str(a), str(b)))
    return "".join(parts) or None


def compare_link(link, target):
    if not os.path.lexists(link):
        return "new", None
    if not os.path.islink(link):
        raise CompareError(f"{link} is not a symbolic link")
    actual = os.readlink(link)
    if actual == target:
        return "unchanged", None
    return "changed", f"points to {actual}, install links {target}\n"


def pair(text):
    left, sep, right = text.partition("=")
    if not sep or not left or not right:
        raise argparse.ArgumentTypeError(f"expected INSTALLED=SOURCE, got {text!r}")
    return left, right


def main(argv=None, out=sys.stdout):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pairs", nargs="*", type=pair, metavar="INSTALLED=SOURCE")
    parser.add_argument("--link", action="append", default=[], type=pair, metavar="LINK=TARGET")
    args = parser.parse_args(argv)
    counts = {"new": 0, "changed": 0, "unchanged": 0, "error": 0}

    def report(status, path, detail=None):
        counts[status] += 1
        print(f"  {status:<10} {path}", file=out)
        for line in (detail or "").splitlines():
            print(f"      {line}", file=out)

    for installed, source in args.pairs:
        try:
            if not os.path.lexists(installed):
                report("new", installed)
                continue
            detail = compare(installed, source)
            report("unchanged" if detail is None else "changed", installed, detail)
        except CompareError as err:
            report("error", installed, str(err))
    for link, target in args.link:
        try:
            status, detail = compare_link(link, target)
            report(status, link, detail)
        except CompareError as err:
            report("error", link, str(err))
    summary = ", ".join(f"{n} {k}" for k, n in counts.items() if k != "error" or n)
    print(f"diff: {summary}; nothing was installed (make install does that)", file=out)
    return 1 if counts["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
