#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copy every agent permission file on this machine into a staging folder,
# so tools/harvest.py can read them inside a container without mounting the
# home folder (or anything holding credentials). Only settings JSON and
# Codex .rules files are copied. The index maps each copy back to its
# original path, with the home folder written as ~.
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
  cp -- "$src" "$dest/$name"
  printf '%s\t%s\n' "$name" "${src/#$HOME/\~}" >>"$dest/index.tsv"
}

# Claude Code profiles: the default one, the one this shell points at, and
# any others listed (space separated) in CLAUDE_CONFIG_DIRS.
for dir in "$HOME/.claude" ${CLAUDE_CONFIG_DIR:-} ${CLAUDE_CONFIG_DIRS:-}; do
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
