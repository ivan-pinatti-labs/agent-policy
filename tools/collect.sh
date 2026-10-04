#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copy every agent permission rule on this machine into a staging folder,
# so tools/harvest.py can read them inside a container without mounting the
# home folder (or anything holding credentials). From a settings file only
# its `permissions` object is staged, never the rest (a settings file can
# carry an API key under `env`); Codex .rules files hold nothing but rules
# and are copied whole. The index maps each copy back to its original path,
# with the home folder written as ~.
#
#   tools/collect.sh <dest> [root...]      roots: folders to search for
#                                          project .claude/ settings
set -euo pipefail

dest="${1:?usage: collect.sh <dest> [root...]}"
shift
roots=("$@")

mkdir -p "$dest"
: >"$dest/index.tsv"
n=0

add() {
  local src="$1" name
  [ -f "$src" ] || return 0
  n=$((n + 1))
  name="$(printf '%03d' "$n")-$(basename "$src")"
  case "$src" in
  *.json) python3 -c '
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    data = {}
perms = data.get("permissions") if isinstance(data, dict) else None
json.dump({"permissions": perms if isinstance(perms, dict) else {}}, sys.stdout)
' "$src" >"$dest/$name" ;;
  *) cp -- "$src" "$dest/$name" ;;
  esac
  printf '%s\t%s\n' "$name" "${src/#$HOME/\~}" >>"$dest/index.tsv"
}

# Claude Code profiles: the default one, the one this shell points at, and
# any others listed (space separated) in CLAUDE_CONFIG_DIRS.
profiles=("$HOME/.claude")
[ -n "${CLAUDE_CONFIG_DIR:-}" ] && profiles+=("$CLAUDE_CONFIG_DIR")
# shellcheck disable=SC2206 # CLAUDE_CONFIG_DIRS is a space separated list
[ -n "${CLAUDE_CONFIG_DIRS:-}" ] && profiles+=($CLAUDE_CONFIG_DIRS)
for dir in "${profiles[@]}"; do
  add "$dir/settings.json"
done
for dir in "$HOME/.codex" ${CODEX_HOMES:-}; do
  for rules in "$dir"/rules/*.rules; do
    case "$rules" in */agent-policy.rules) continue ;; esac
    add "$rules"
  done
done
for root in "${roots[@]+"${roots[@]}"}"; do
  [ -d "$root" ] || continue
  while IFS= read -r -d '' file; do
    add "$file"
  done < <(find "$root" \( -name worktrees -o -name node_modules -o -name .git \) -prune -o \
    \( -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' \) \
    -print0 2>/dev/null)
done
echo "collect: $n files into $dest"
