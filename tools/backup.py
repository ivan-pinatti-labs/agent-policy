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

Restore runs as root on a folder its user can write, so it trusts nothing in
the manifest it was not told on the command line: every root must be one of
the --allow paths, every entry must sit inside its root once symlinks in its
parent are resolved, every stored copy must sit inside the backup, and the
backup itself must sit under --backup-root. A tampered manifest can at most
put back files under the paths install itself writes.
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

MANIFEST = "manifest.json"
FORMAT = 1


class BackupError(Exception):
    pass


def confine(path, bases, what):
    """`path` resolved, if it sits under one of the fixed `bases`; BackupError
    if not. Applied to every path the command line names, which an agent may
    write, before anything reads or writes it."""
    candidate = resolved_root(path)
    for base in bases:
        if candidate.is_relative_to(resolved_root(base)):
            return candidate
    raise BackupError(f"{what} {candidate} is outside {', '.join(map(str, bases))}")


def confine_source(path):
    """A path to back up or restore, kept as given (its own symlink is backed up
    as a symlink) once its folder is confirmed to sit under source_bases()."""
    absolute = Path(os.path.abspath(path))
    confine(absolute.parent, source_bases(), "the path")
    return absolute


def backup_bases():
    """Where backups may live: the default backup folder, or a temporary one."""
    return [default_root(), tempfile.gettempdir()]


def source_bases():
    """Where the paths install touches may live."""
    return ["/etc", "/usr/local", Path.home(), tempfile.gettempdir()]


def resolved_root(path):
    return Path(os.path.realpath(os.path.abspath(path)))


def inside(path, roots):
    """`path` with its parent's symlinks resolved, if it sits inside one of
    `roots` (already resolved); BackupError if not. The last component is not
    resolved, so a symlink is judged, and handled, as the symlink itself."""
    absolute = Path(os.path.abspath(path))
    checked = Path(os.path.realpath(absolute.parent)) / absolute.name
    for root in roots:
        if checked == root or checked.is_relative_to(root):
            return checked
    raise BackupError(f"{path} is outside the paths this backup may touch")


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
    base = resolved_root(Path(dest) / "files")
    copy = Path(os.path.normpath(base / Path(path).relative_to("/")))
    if not copy.is_relative_to(base):
        raise BackupError(f"{path} would be stored outside the backup")
    return copy


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
        root = inside(raw, [resolved_root(Path(raw).parent)])
        roots.append(str(root))
        if not os.path.lexists(root):
            entries.append({"path": str(root), "type": "absent"})
            continue
        for found in walk(root):
            path = inside(found, [root])
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


def load(dest, backup_root=None):
    if backup_root is not None:
        folder = resolved_root(dest)
        if not folder.is_relative_to(resolved_root(backup_root)):
            raise BackupError(f"{dest} is not under the backup root {backup_root}")
        dest = folder
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


def checked_manifest(manifest, allow):
    """The manifest's roots and entries, each confined to the --allow paths."""
    allowed = {str(inside(a, [resolved_root(Path(a).parent)])) for a in allow}
    roots = []
    for root in manifest["roots"]:
        if root not in allowed:
            raise BackupError(f"the backup names {root}, which is not an --allow path")
        roots.append(inside(root, [resolved_root(Path(root).parent)]))
    entries = []
    for entry in manifest["entries"]:
        # Lexically here (no `..`, inside a root); with symlinks resolved
        # again just before each write, once earlier steps have run.
        path = Path(os.path.normpath(os.path.abspath(entry["path"])))
        if not any(path == root or path.is_relative_to(root) for root in roots):
            raise BackupError(f"{entry['path']} is outside the paths this backup may touch")
        entry = dict(entry, path=str(path))
        if entry["type"] not in ("file", "dir", "symlink", "absent"):
            raise BackupError(f"unknown entry type for {entry['path']}")
        entries.append(entry)
    return roots, entries


def restore(dest, allow, dry_run=False, log=print, backup_root=None):
    """Return the list of actions; perform them unless dry_run."""
    manifest = load(dest, backup_root)
    roots, entries = checked_manifest(manifest, allow)
    # Paths the backup holds. An absent root is not one of them: if it
    # exists now, install created it, and it goes.
    known = {e["path"] for e in entries if e["type"] != "absent"}
    actions = []
    # Anything under a root that the backup does not know was added since:
    # remove it, deepest first.
    for root in roots:
        if not os.path.lexists(root):
            continue
        extra = [p for p in walk(Path(root)) if str(p) not in known]
        for found in sorted(extra, key=lambda p: len(p.parts), reverse=True):
            path = inside(found, roots)
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
        path = str(inside(path, roots))
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
    back.add_argument(
        "--allow",
        action="append",
        required=True,
        help="a path restore may touch; repeat for each (make passes them)",
    )
    back.add_argument("--backup-root", default=str(default_root()))
    back.add_argument("--dry-run", action="store_true")
    show = sub.add_parser("list")
    show.add_argument("root", nargs="?", default=str(default_root()))
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
            raw_dest = Path(args.dest) if args.dest else Path(args.root) / stamp
            dest = confine(raw_dest, backup_bases(), "the backup folder")
            paths = [confine_source(p) for p in args.paths]
            manifest = create(dest, paths)
            saved = sum(1 for e in manifest["entries"] if e["type"] != "absent")
            print(f"backup: {saved} entries from {len(args.paths)} paths in {dest}")
        elif args.command == "restore":
            dest = confine(args.dest, backup_bases(), "the backup folder")
            backup_root = confine(args.backup_root, backup_bases(), "the backup root")
            allow = [confine_source(p) for p in args.allow]
            actions = restore(dest, allow, dry_run=args.dry_run, backup_root=backup_root)
            print(f"restore: {len(actions)} changes{' (dry run)' if args.dry_run else ''}")
        else:
            root = confine(args.root, backup_bases(), "the backup root")
            for path, manifest in list_backups(root):
                print(f"{path}  {manifest['created']}  {len(manifest['roots'])} paths")
    except (BackupError, OSError) as err:
        print(f"backup: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
