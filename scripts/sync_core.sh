#!/usr/bin/env bash
# ==============================================================================
# sync_core.sh - Sync the vendored Go core (cmd/, internal/) from the upstream
# MasterDnsVPN desktop repo.
#
# The Go core is vendored as a source snapshot, not a module dependency.
# This script takes the state of internal/ and cmd/ from a fetched ref of the
# "gorepo" remote and stages it in this repo. It never edits go.mod/go.sum.
#
# Dependency policy:
#   - If the core INTRODUCES a module absent from this repo's go.mod, the sync
#     STOPS with an error: land it first as a dedicated chore(go) commit that
#     updates go.mod/go.sum directly (never via android/build_go_mobile.sh).
#   - Version drift on known modules (and expected mobile-only deps such as
#     tun2socks) is reported informationally; the sync continues.
#
# Usage:
#   bash ./scripts/sync_core.sh [ref]      # default ref: gorepo/main
#
# After syncing:
#   1. Review staged changes:   git diff --staged
#   2. Rebuild the AAR/APK:     bash ./android/build_go_mobile.sh
#                              cd android && ./gradlew :app:assembleDebug
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REMOTE="gorepo"
REMOTE_URL="https://github.com/taskkillstar/MasterDnsVPN.git"
REF="${1:-${REMOTE}/main}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: not inside a git work tree." >&2
  exit 1
fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "Remote '$REMOTE' is missing. One-time setup:" >&2
  echo "  git remote add $REMOTE $REMOTE_URL" >&2
  exit 1
fi

# Only require cleanliness in paths this script touches or depends on;
# unrelated local noise (e.g. android/.gradle state) must not block a sync.
require_clean_synced_paths() {
  if ! git diff --quiet -- internal cmd mobile go.mod go.sum \
     || ! git diff --cached --quiet -- internal cmd mobile go.mod go.sum; then
    echo "ERROR: working tree has uncommitted changes in synced paths." >&2
    echo "Commit or stash changes under internal/, cmd/, mobile/ and in" >&2
    echo "go.mod/go.sum before syncing the core." >&2
    git diff -- internal cmd mobile go.mod go.sum >&2 || true
    exit 1
  fi
}

# Staging sweeps everything under internal/ and cmd/, and `git checkout REF --
# <dir>` skips untracked paths that collide with upstream files (exit 0). An
# untracked scratch file could therefore silently replace upstream content in
# the sync commit, so refuse to proceed while any exist.
reject_untracked_synced_paths() {
  local untracked
  untracked="$(git ls-files --others --directory -- internal cmd)"
  if [ -n "$untracked" ]; then
    echo "ERROR: untracked files exist under synced paths:" >&2
    echo "$untracked" >&2
    echo "Remove them (or track/gitignore them) before syncing." >&2
    exit 1
  fi
}

require_clean_synced_paths

echo "Fetching $REMOTE..."
git fetch "$REMOTE" --no-tags

if ! git rev-parse --verify --quiet "$REF" >/dev/null; then
  echo "ERROR: ref '$REF' not found on remote '$REMOTE'." >&2
  echo "Available branches:" >&2
  git branch -r --list "${REMOTE}/*" >&2
  exit 1
fi

# TOCTOU guard: the network fetch above can take a while; re-verify nothing
# changed under the synced paths in the meantime before force-restaging them.
require_clean_synced_paths
reject_untracked_synced_paths

# Extract the direct-require lists ("module@version", sorted) from both go.mods.
require_list() {
  sed -n '/^require (/,/^)/p' "$1" \
    | grep -E '^[[:space:]]+[^/[:space:]]' \
    | sed 's|//.*||' \
    | awk '{print $1"@"$2}' \
    | sort
}
our_full="$(require_list go.mod)"
their_full="$(require_list <(git show "$REF:go.mod"))"
our_paths="$(printf '%s\n' "$our_full" | cut -d@ -f1 | sort -u)"
their_paths="$(printf '%s\n' "$their_full" | cut -d@ -f1 | sort -u)"

# Hard stop: the core needs a module this repo does not have at all. Version
# drift alone is fine to surface later via tests; a missing module is not.
missing="$(comm -13 <(printf '%s\n' "$our_paths") <(printf '%s\n' "$their_paths"))"
if [ -n "$missing" ]; then
  echo ""
  echo "======================================================================" >&2
  echo "STOP: $REF introduces dependencies absent from this repo's go.mod:" >&2
  echo "$missing" >&2
  echo "" >&2
  echo "Land them first as a dedicated chore(go) commit that updates" >&2
  echo "go.mod/go.sum directly (never via the gomobile build script)," >&2
  echo "then re-run this sync." >&2
  echo "======================================================================" >&2
  exit 1
fi

# Informational: versions differ between the repos. Expected here because this
# repo carries mobile-only deps (tun2socks and friends) next to the core's.
if [ "$our_full" != "$their_full" ]; then
  echo ""
  echo "NOTE: dependency versions differ between go.mod and $REF:go.mod"
  echo "(informational only; mobile-only deps are expected):"
  diff <(printf '%s\n' "$our_full") <(printf '%s\n' "$their_full") || true
  echo ""
fi

echo "Syncing internal/ and cmd/ from $REF..."

# git checkout of a directory does not delete files removed upstream, so
# remove those explicitly first.
while IFS=$'\t' read -r status path; do
  if [ "$status" = "D" ]; then
    git rm -q -- "$path"
  fi
done < <(git diff --name-status HEAD "$REF" -- internal cmd)

git checkout "$REF" -- internal cmd
git add internal cmd

# Scoped to the synced trees: unrelated changes staged elsewhere (e.g. docs)
# must not make a no-op sync look like it produced output.
if git diff --cached --quiet -- internal cmd; then
  echo "Already up to date with $REF."
  exit 0
fi

echo ""
echo "Staged changes:"
git diff --staged --stat -- internal cmd
echo ""

echo "Running Go tests (same set CI runs)..."
go test $(go list ./... | grep -v -e '^masterdnsvpn-go$' -e '^masterdnsvpn-go/mobile$')

# The bridge uses syscall.Dup and other Unix-only syscalls, so it only
# compiles for an Android/Linux target. Use the gomobile target explicitly
# instead of the host OS (host-native builds fail on Windows).
echo "Checking the gomobile bridge still compiles against the synced core..."
GOOS=android GOARCH=arm64 go build ./mobile/...

echo ""
echo "Sync complete. Changes are STAGED but NOT committed."
echo "Next steps:"
echo "  1. Review:                    git diff --staged"
echo "  2. Commit:                    git commit  (conventional commit, e.g. chore(core): sync ...)"
echo "  3. Rebuild AAR:               bash ./android/build_go_mobile.sh"
echo "  4. Rebuild APK / typecheck:   cd android && ./gradlew :app:assembleDebug"
