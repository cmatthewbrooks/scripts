#!/bin/bash
set -euo pipefail

# Interactive launcher for `claude`, the Claude Code CLI.
#
# Starting a new session against a repo means deciding on a session name and
# whether to isolate the work on a new branch or in a full git worktree, then
# remembering the right combination of `claude` flags (or `git` commands) to
# get there. This script asks three short questions and does the right thing,
# so none of that has to be re-derived by hand every time.
#
# Deliberately no manual "git worktree add" logic here: `claude` already has
# its own `-w/--worktree [name]` flag that creates and launches into a
# worktree, with its own naming/location conventions and its own cleanup path
# (`claude rm`). Reimplementing that here would just be a second, divergent
# copy of logic Claude Code already owns. The one thing `claude` has no flag
# for is "new branch, same working directory", which is why that mode alone
# does its own `git checkout -b` before handing off.

usage() {
    cat <<EOF
Usage: $(basename "$0") [-h]

Interactively launch a new Claude Code session: prompts for a session name
and an isolation mode (in place / new branch / new worktree), then execs
\`claude\` with the appropriate flags.

Options:
  -h  Show this help

This script takes no other flags: the whole point is the guided prompt flow.
Run it with no arguments from inside the repo you want to work in.
EOF
}

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

while getopts ':h' opt; do
    case "$opt" in
        h) usage; exit 0 ;;
        ?) usage >&2; die "Unknown option: -$OPTARG" ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -eq 0 ]] || { usage >&2; die "Unexpected argument '$1'."; }

command -v git >/dev/null 2>&1 || die "git not found in PATH."
command -v claude >/dev/null 2>&1 || die "claude not found in PATH."
git rev-parse --show-toplevel >/dev/null 2>&1 || die "Not inside a git repository."

# Turn free-typed text into a safe git branch component: lowercase, spaces and
# underscores to hyphens, drop anything else git branch names disallow, then
# trim leading/trailing/duplicate hyphens so "My Feature!!" becomes
# "my-feature" rather than "my-feature-" or "-my-feature".
slugify() {
    local s="$1"
    s="${s,,}"
    s="${s// /-}"
    s="${s//_/-}"
    s="$(printf '%s' "$s" | tr -cd 'a-z0-9-')"
    s="$(printf '%s' "$s" | sed -E 's/-+/-/g; s/^-+//; s/-+$//')"
    printf '%s' "$s"
}

DEFAULT_NAME="session-$(date -u +%Y%m%d-%H%M%S)"

read -r -p "Session name [$DEFAULT_NAME]: " SESSION_NAME
SESSION_NAME="${SESSION_NAME:-$DEFAULT_NAME}"

cat <<'EOF'

Isolation mode:
  1) Current branch, this directory (no git changes)
  2) New branch, this directory
  3) New worktree (claude handles creation via -w)
EOF
read -r -p "Choose [3]: " MODE
MODE="${MODE:-3}"

case "$MODE" in
    1|2|3) ;;
    *) die "Invalid mode '$MODE'. Choose 1, 2, or 3." ;;
esac

BASE_REF=""
BRANCH=""
if [[ "$MODE" == "2" ]]; then
    CURRENT_BRANCH="$(git branch --show-current)"
    DEFAULT_BASE="${CURRENT_BRANCH:-main}"
    read -r -p "Base ref [$DEFAULT_BASE]: " BASE_REF
    BASE_REF="${BASE_REF:-$DEFAULT_BASE}"

    SLUG="$(slugify "$SESSION_NAME")"
    [[ -n "$SLUG" ]] || die "Session name produces an empty branch slug; use some alphanumeric characters."
    BRANCH="claude/$SLUG"

    git rev-parse --verify --quiet "$BASE_REF" >/dev/null \
        || die "Base ref '$BASE_REF' does not exist."
    git rev-parse --verify --quiet "$BRANCH" >/dev/null 2>&1 \
        && die "Branch '$BRANCH' already exists. Choose a different session name or check it out yourself."
fi

printf '\n'
log "Session name: $SESSION_NAME"
case "$MODE" in
    1) log "Mode: current branch, this directory" ;;
    2) log "Mode: new branch '$BRANCH' from '$BASE_REF', this directory" ;;
    3) log "Mode: new worktree (delegated to 'claude -w')" ;;
esac
printf '\n'

if [[ "$MODE" == "2" ]]; then
    git checkout -b "$BRANCH" "$BASE_REF"
fi

# exec replaces this script's process with claude's, so exiting the session
# drops straight back to the parent shell instead of leaving this script on
# the stack.
case "$MODE" in
    1) exec claude -n "$SESSION_NAME" ;;
    2) exec claude -n "$SESSION_NAME" ;;
    3) exec claude -n "$SESSION_NAME" -w "$SESSION_NAME" ;;
esac
