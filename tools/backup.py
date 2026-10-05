#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Back up what `make install` and `make uninstall` touch, and restore it.

  backup.py create --dest DIR PATH...   copy every PATH (file, symlink or
                                        whole folder) into DIR, verify each
                                        copy, then write DIR/manifest.json
  backup.py restore DIR [--dry-run]     put every PATH back as it was: files,
                                        symlinks, modes and owners restored,
                                        and anything added since removed
  backup.py list [ROOT]                 the backups under ROOT, newest first

A backup counts only once its manifest exists, and the manifest is written
last, after every copy has been checked against its source. `create` exits
non-zero on any failure, so `make install` stops before writing anything.
A PATH that does not exist is recorded as absent, so restoring removes what
install created there. Standard library only: it runs on the host's system
Python, like the guard.
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

MANIFEST = "manifest.json"
FORMAT = 1


class BackupError(Exception):
    pass


def default_root():
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(Path.home(), ".local", "state")
    return Path(state) / "agent-policy" / "backups"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


def stored(dest, path):
    """Where the copy of absolute `path` lives inside the backup."""
    return Path(dest) / "files" / Path(path).relative_to("/")


def walk(root):
    """Every entry under `root` (itself included), symlinks not followed."""
    yield root
    if root.is_dir() and not root.is_symlink():
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in sorted(dirnames) + sorted(filenames):
                yield Path(dirpath) / name


def record(path):
    info = os.lstat(path)
    entry = {
        "path": str(path),
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
    }
    if stat.S_ISLNK(info.st_mode):
        entry.update(type="symlink", target=os.readlink(path))
    elif stat.S_ISDIR(info.st_mode):
        entry["type"] = "dir"
    elif stat.S_ISREG(info.st_mode):
        entry.update(type="file", sha256=sha256(path))
    else:
        raise BackupError(f"{path} is neither a file, a folder nor a symlink")
    return entry


def create(dest, paths):
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise BackupError(f"{dest} already exists and is not empty")
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(dest, 0o700)
    roots, entries = [], []
    for raw in paths:
        root = Path(os.path.abspath(raw))
        roots.append(str(root))
        if not os.path.lexists(root):
            entries.append({"path": str(root), "type": "absent"})
            continue
        for path in walk(root):
            entry = record(path)
            copy = stored(dest, path)
            copy.parent.mkdir(parents=True, exist_ok=True)
            if entry["type"] == "symlink":
                os.symlink(entry["target"], copy)
            elif entry["type"] == "dir":
                copy.mkdir(exist_ok=True)
            else:
                shutil.copyfile(path, copy)
                if sha256(copy) != entry["sha256"]:
                    raise BackupError(f"the copy of {path} does not match it")
            entries.append(entry)
    manifest = {
        "format": FORMAT,
        "created": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "roots": roots,
        "entries": entries,
    }
    partial = dest / (MANIFEST + ".partial")
    partial.write_text(json.dumps(manifest, indent=2) + "\n")
    os.replace(partial, dest / MANIFEST)
    return manifest


def load(dest):
    path = Path(dest) / MANIFEST
    if not path.is_file():
        raise BackupError(f"{dest} has no {MANIFEST}: it is not a complete backup")
    manifest = json.loads(path.read_text())
    if manifest.get("format") != FORMAT:
        raise BackupError(f"{path} has an unknown format")
    return manifest


def remove(path):
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)


def restore(dest, dry_run=False, log=print):
    """Return the list of actions; perform them unless dry_run."""
    manifest = load(dest)
    entries = manifest["entries"]
    # Paths the backup holds. An absent root is not one of them: if it
    # exists now, install created it, and it goes.
    known = {e["path"] for e in entries if e["type"] != "absent"}
    actions = []
    # Anything under a root that the backup does not know was added since:
    # remove it, deepest first.
    for root in manifest["roots"]:
        if not os.path.lexists(root):
            continue
        extra = [p for p in walk(Path(root)) if str(p) not in known]
        for path in sorted(extra, key=lambda p: len(p.parts), reverse=True):
            if os.path.lexists(path):
                actions.append(("remove", str(path)))
                if not dry_run:
                    remove(path)
    as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    for entry in entries:
        path = entry["path"]
        kind = entry["type"]
        if kind == "absent":
            continue
        current = os.path.lexists(path) and record(path)
        if current and current["type"] == kind and current == entry:
            continue
        actions.append(("restore", path))
        if dry_run:
            continue
        if current and (current["type"] != kind or kind == "symlink"):
            remove(path)
        if kind == "dir":
            os.makedirs(path, exist_ok=True)
        elif kind == "symlink":
            os.symlink(entry["target"], path)
        else:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(stored(dest, path), path)
        if kind != "symlink":
            os.chmod(path, entry["mode"])
        if as_root:
            os.lchown(path, entry["uid"], entry["gid"])
    for action, path in actions:
        log(f"{'would ' if dry_run else ''}{action} {path}")
    return actions


def list_backups(root):
    root = Path(root)
    if not root.is_dir():
        return []
    found = []
    for path in sorted(root.iterdir(), reverse=True):
        try:
            manifest = load(path)
        except (BackupError, ValueError):
            continue
        found.append((path, manifest))
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("create")
    make.add_argument("--dest", help="backup folder (default: a new timestamped one)")
    make.add_argument("--root", default=str(default_root()))
    make.add_argument("paths", nargs="+")
    back = sub.add_parser("restore")
    back.add_argument("dest")
    back.add_argument("--dry-run", action="store_true")
    show = sub.add_parser("list")
    show.add_argument("root", nargs="?", default=str(default_root()))
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
            dest = Path(args.dest) if args.dest else Path(args.root) / stamp
            manifest = create(dest, args.paths)
            saved = sum(1 for e in manifest["entries"] if e["type"] != "absent")
            print(f"backup: {saved} entries from {len(args.paths)} paths in {dest}")
        elif args.command == "restore":
            actions = restore(args.dest, dry_run=args.dry_run)
            print(f"restore: {len(actions)} changes{' (dry run)' if args.dry_run else ''}")
        else:
            for path, manifest in list_backups(args.root):
                print(f"{path}  {manifest['created']}  {len(manifest['roots'])} paths")
    except (BackupError, OSError) as err:
        print(f"backup: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
