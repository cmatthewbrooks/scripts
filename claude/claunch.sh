#!/bin/bash
set -euo pipefail

# Interactive launcher for `claude`, the Claude Code CLI.
#
# Starting a new session against a repo means deciding on a session name,
# whether to isolate the work on a new branch or in a full git worktree, and
# which model, effort level and permission mode the session should run with.
# That is a lot of flags (or `git` commands) to re-derive by hand every time.
# This script asks a short series of questions and does the right thing.
#
# Deliberately no manual "git worktree add" logic here: `claude` already has
# its own `-w/--worktree [name]` flag that creates and launches into a
# worktree, with its own naming/location conventions and its own cleanup path
# (`claude rm`). Reimplementing that here would just be a second, divergent
# copy of logic Claude Code already owns. The one thing `claude` has no flag
# for is "new branch, same working directory", which is why that mode alone
# does its own `git checkout -b` before handing off.
#
# The model/effort/permission choices are always passed explicitly rather than
# left to fall through to the global config, so what a session is running with
# is decided (and logged) at launch instead of being implicit.

usage() {
    cat <<EOF
Usage: $(basename "$0") [-h]

Interactively launch a new Claude Code session. Prompts for a session name,
an isolation mode (in place / new branch / new worktree), then a model,
effort level and permission mode, and execs \`claude\` with the appropriate
flags.

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

# Present a numbered menu and echo the selected value on stdout.
#
# Usage: choose <label> <default index> <entry>...
# Each entry is "value" or "value:annotation"; only the value is echoed, the
# annotation is display-only. An empty answer takes the default index; anything
# that is not an in-range number is fatal.
#
# The menu is written to stderr on purpose: stdout is consumed by the caller's
# command substitution, so prompting on stdout would swallow the menu.
choose() {
    local label="$1" default="$2"
    shift 2
    local entries=("$@")
    local count=${#entries[@]}

    printf '\n%s:\n' "$label" >&2
    local i value annotation
    for i in "${!entries[@]}"; do
        value="${entries[i]%%:*}"
        annotation="${entries[i]#*:}"
        if [[ "$annotation" == "${entries[i]}" ]]; then
            printf '  %d) %s\n' "$((i + 1))" "$value" >&2
        else
            printf '  %d) %-8s %s\n' "$((i + 1))" "$value" "$annotation" >&2
        fi
    done

    local reply
    read -r -p "Choose [$default]: " reply
    reply="${reply:-$default}"

    [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= count )) \
        || die "Invalid $label '$reply'. Choose 1-$count."

    printf '%s' "${entries[reply - 1]%%:*}"
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

MODEL="$(choose Model 1 opus sonnet fable haiku)"
EFFORT="$(choose Effort 3 low medium high xhigh max)"
# Only the three modes that are safe to pick by reflex. bypassPermissions,
# acceptEdits and dontAsk are intentionally not on this menu.
PERM_MODE="$(choose "Permission mode" 2 \
    "manual:(prompt before each tool use)" \
    "auto:(Claude Code decides)" \
    "plan:(read-only planning)")"

printf '\n'
log "Session name: $SESSION_NAME"
case "$MODE" in
    1) log "Mode: current branch, this directory" ;;
    2) log "Mode: new branch '$BRANCH' from '$BASE_REF', this directory" ;;
    3) log "Mode: new worktree (delegated to 'claude -w')" ;;
esac
log "Model: $MODEL"
log "Effort: $EFFORT"
log "Permission mode: $PERM_MODE"
printf '\n'

if [[ "$MODE" == "2" ]]; then
    git checkout -b "$BRANCH" "$BASE_REF"
fi

CLAUDE_ARGS=(-n "$SESSION_NAME"
             --model "$MODEL"
             --effort "$EFFORT"
             --permission-mode "$PERM_MODE")

# Modes 1 and 2 both land in the current directory and differ only in the
# branch checked out above; only mode 3 needs claude to build a worktree.
[[ "$MODE" == "3" ]] && CLAUDE_ARGS+=(-w "$SESSION_NAME")

# exec replaces this script's process with claude's, so exiting the session
# drops straight back to the parent shell instead of leaving this script on
# the stack.
exec claude "${CLAUDE_ARGS[@]}"
