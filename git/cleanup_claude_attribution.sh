#!/bin/bash
set -euo pipefail

# Normalize Claude authorship trailers across a repository's commit history.
#
# Claude Code writes two kinds of trailer that age badly. The co-author line
# carries the model that happened to write the commit:
#
#     Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
#
# which turns a changelog into a record of model releases, and spreads one
# contributor across as many shortlog entries as there were models. The session
# line carries a URL:
#
#     Claude-Session: https://claude.ai/code/session_01QiaxYZuPoi2em7BbAeXpJG
#
# which points at a private transcript nobody else can open, and leaks an
# identifier into a repo that may later go public.
#
# This rewrites every co-author line naming Claude to a single stable form,
# "Co-Authored-By: Claude via Claude Code", and deletes the session lines.
# Nothing else in any commit message is touched.
#
# WARNING: this rewrites history. Every commit from the earliest match onward
# gets a new hash, which breaks open pull requests, invalidates every existing
# clone, and requires a force push. It defaults to a dry run for that reason:
# nothing is modified until you pass -w. Read the DANGER section below before
# you do.

usage() {
    cat <<EOF
Usage: $(basename "$0") [-r REPO] [-w] [-b] [-B] [-a] [-c REV] [-q] [-h]

Rewrite Claude authorship trailers throughout a repo's git history.

Options:
  -r REPO    Repository to rewrite (default: current directory)
  -w         Write. Actually rewrite history. Without this the script only
             reports what would change and exits without touching anything
  -b         Back up the original refs to a bundle file before rewriting.
             Recommended, and free: see RECOVERY below
  -B         Skip filter-repo's fresh-clone safety check (passes --force).
             Needed to rewrite a repo with uncommitted changes or one that is
             not a fresh clone, which describes most working repos
  -a         Rewrite all refs, not just the current branch. Without it only
             HEAD's branch is rewritten, which leaves the same trailers in
             place on every other branch and tag
  -c REV     Limit the rewrite to a commit range, e.g. main~50..HEAD.
             Cannot be combined with -a
  -q         Quiet: suppress progress, report findings and errors only
  -h         Show this help

WHAT IS MATCHED

  Co-author lines, rewritten in place:

      Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
      Co-authored-by: Claude Sonnet 4.5 <noreply@anthropic.com>
      Co-Authored-By: Claude <noreply@anthropic.com>

  all become

      Co-Authored-By: Claude via Claude Code

  The trailer key is matched case-insensitively, since git treats trailer keys
  that way and both spellings occur in the wild. The value must be "Claude"
  followed by a word boundary, so "Claude Opus 5" and a bare "Claude" match
  while an unrelated human co-author named Claudia does not.

  A line already in the target form is left exactly as it is, so the script is
  idempotent: running it twice changes nothing the second time.

  Session lines, deleted entirely:

      Claude-Session: https://claude.ai/code/session_01QiaxYZuPoi2em7BbAeXpJG

  Any line whose first non-space characters are "Claude-Session" goes, along
  with the newline, matched case-insensitively.

  Should a commit carry several Claude co-author lines, they collapse to a
  single trailer rather than to duplicates of the same line.

  Trailing blank lines left behind by a deletion are trimmed, so removing the
  last trailer does not leave a commit message ending in whitespace.

DANGER

  History rewriting is not an edit. It builds new commits, and every commit
  after the first change gets a new hash:

    * Open pull requests against rewritten branches break.
    * Every existing clone diverges and must be re-cloned or hard reset.
      Anyone who pulls normally will merge the old history back in.
    * Signed commits lose their signatures, because the content they signed
      no longer exists.
    * Tags pointing at rewritten commits move (with -a) or dangle (without).
    * The push is a force push, and a force push can destroy commits on the
      remote that you never had locally.

  On a shared branch, coordinate with everyone who has a clone before pushing.
  On a solo repo, this is routine. Know which one you are in.

  Note also what this cannot do. Rewriting history does not unpublish anything.
  A session URL already pushed to a public forge may sit in a fork, a cached
  view, or someone's local clone, none of which this reaches.

RECOVERY

  With -b the original refs are written to a git bundle in the repo root before
  anything changes:

      claude-attribution-backup-YYYYMMDD-HHMMSS.bundle

  To inspect what the original history was:

      git bundle list-heads BACKUP.bundle

  To restore a branch from it:

      git fetch BACKUP.bundle 'refs/heads/*:refs/heads/restored/*'

  filter-repo also leaves the pre-rewrite refs under refs/original/ inside
  .git/filter-repo/, independently of -b. The bundle is the more portable of
  the two, and the one that survives a later gc.

REQUIREMENTS

  git-filter-repo is used when available and is strongly preferred: it is much
  faster and is the tool git's own documentation recommends. Install it with
  "brew install git-filter-repo".

  Without it the script falls back to "git filter-branch", which is slower by
  orders of magnitude on a large history and which git itself warns against.
  The fallback produces the same result and is fine for a few hundred commits.
  Pass -q to silence filter-branch's own deprecation warning.

Exit status: 0 on success or when a dry run finds nothing, 1 when a dry run
finds trailers to change (so it can gate CI), 2 on error.

Examples:
  # See what would change, touching nothing
  $(basename "$0") -r ~/src/myrepo

  # Rewrite the current branch, with a backup bundle
  $(basename "$0") -r ~/src/myrepo -w -b -B

  # Rewrite every branch and tag in the repo
  $(basename "$0") -r ~/src/myrepo -w -b -B -a

  # Only the commits not yet pushed
  $(basename "$0") -w -b -B -c origin/main..HEAD

After rewriting, verify before pushing:

  git log --format='%B' | grep -iE 'claude|anthropic'
  git push --force-with-lease

--force-with-lease rather than --force: it refuses the push if the remote moved
since your last fetch, which is the one check standing between a rewrite and
overwriting a colleague's work.
EOF
}

log() { [[ $QUIET -eq 1 ]] || printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

REPO="."
WRITE=0
BACKUP=0
FORCE=0
ALL_REFS=0
QUIET=0
RANGE=""

# The canonical replacement trailer. Deliberately without an email: the address
# was only ever a placeholder, and dropping it keeps forges from rendering the
# trailer as a link to an account that does not exist.
#
# The two rewrite engines each need this string in their own syntax (a Python
# bytes literal, a sed replacement), so it is repeated there rather than
# interpolated. Change it here and in both engines together.
readonly REPLACEMENT="Co-Authored-By: Claude via Claude Code"

# Matches a Claude co-author trailer. Broken out because both the scan and the
# rewrite must agree on what counts as a match; a difference between them would
# make the dry run lie about the rewrite.
#
# Matching is case-insensitive (count_matching applies /i), which covers the
# Co-Authored-By/Co-authored-by split, and \s* after the colon tolerates odd
# spacing. (?![A-Za-z]) keeps "Claude" and "Claude Opus 5" in while keeping a
# longer name such as "Claudia" out. It stands in for \b, which would not do
# the job: \b matches at the end of "Claude" in "Claude-Bot", since a hyphen is
# a non-word character, and a hyphenated name is exactly the case to exclude.
readonly CO_AUTHOR_RE='^\s*Co-Authored-By:\s*Claude(?![A-Za-z])'

# Matches a session trailer, whose whole line is removed.
readonly SESSION_RE='^\s*Claude-Session\s*:'

# Matches a co-author line already in the target form. Subtracted from the
# co-author count so an already-normalized commit reads as no work to do, which
# is what makes repeat runs idempotent.
readonly FINAL_RE='^\s*Co-Authored-By:\s*Claude via Claude Code\s*$'

while getopts ':r:wbBac:qh' opt; do
    case "$opt" in
        r) REPO="$OPTARG" ;;
        w) WRITE=1 ;;
        b) BACKUP=1 ;;
        B) FORCE=1 ;;
        a) ALL_REFS=1 ;;
        c) RANGE="$OPTARG" ;;
        q) QUIET=1 ;;
        h) usage; exit 0 ;;
        :) echo "Error: -$OPTARG requires an argument." >&2; usage >&2; exit 2 ;;
        ?) echo "Error: unknown option -$OPTARG." >&2; usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -eq 0 ]] || { echo "Error: unexpected argument '$1'." >&2; usage >&2; exit 2; }
[[ -n "$RANGE" && $ALL_REFS -eq 1 ]] && die "-c and -a are mutually exclusive."

command -v git >/dev/null 2>&1 || die "git not found in PATH."
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "'$REPO' is not a git repository."

# Resolve to an absolute path up front. filter-repo must run with the repo as
# its working directory, and a relative -r would break once we cd.
REPO="$(cd "$REPO" && pwd)"

git -C "$REPO" rev-parse HEAD >/dev/null 2>&1 || die "'$REPO' has no commits."

# Counting matches needs PCRE, for the lookahead that separates "Claude" from
# "Claudia". That rules out grep: BSD grep (the macOS default) has no -P at all,
# and it cannot even be probed with "grep -qP x", which exits 0 on the -q alone
# and reports PCRE support that is not there.
#
# perl is the portable answer. It ships with macOS, is standard on Linux, and
# runs the same regex dialect as the filter-repo callback below, so the dry run
# and the rewrite genuinely agree on what matches.
command -v perl >/dev/null 2>&1 || die "perl not found in PATH (needed for PCRE matching)."

# Count the lines of stdin matching a PCRE, case-insensitively. Always exits 0:
# a count of zero is an answer, not a failure, and under set -e a nonzero exit
# here would kill the script mid-scan.
count_matching() {
    perl -sne 'BEGIN{$n=0} $n++ if /$re/i; END{print "$n\n"}' -- -re="$1"
}

# Which commits the rewrite will cover. This drives both the scan and the tool
# invocation, so the report and the rewrite always describe the same set.
if [[ -n "$RANGE" ]]; then
    git -C "$REPO" rev-parse "$RANGE" >/dev/null 2>&1 || die "Bad revision range '$RANGE'."
    REV_ARGS=("$RANGE")
    SCOPE="range $RANGE"
elif [[ $ALL_REFS -eq 1 ]]; then
    REV_ARGS=(--all)
    SCOPE="all refs"
else
    REV_ARGS=(HEAD)
    SCOPE="$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
fi

# Count affected commits before doing anything. Beyond reporting, this is what
# lets the script decline to rewrite history that has nothing to fix, which is
# the difference between a no-op and a repo full of new hashes for no reason.
#
# The scan reads one commit at a time rather than streaming the whole log: a
# commit body contains arbitrary newlines, so no single-pass read loop can tell
# where one message ends and the next begins. A dry run is not the hot path.
CO_AUTHOR_COMMITS=0
SESSION_COMMITS=0
ALREADY_OK=0
TOTAL_COMMITS=0
MATCHED_SHAS=""

while IFS= read -r sha; do
    TOTAL_COMMITS=$((TOTAL_COMMITS + 1))
    body="$(git -C "$REPO" log -1 --format='%B' "$sha")"

    co_hits="$(printf '%s\n' "$body" | count_matching "$CO_AUTHOR_RE")"
    ses_hits="$(printf '%s\n' "$body" | count_matching "$SESSION_RE")"

    # A co-author line already in the final form is a match for the regex but
    # not a change, so it must not be counted as work to do. Without this the
    # script would report changes forever and never be idempotent.
    ok_hits="$(printf '%s\n' "$body" | count_matching "$FINAL_RE")"

    co_changes=$((co_hits - ok_hits))
    [[ $co_changes -lt 0 ]] && co_changes=0

    if [[ $co_changes -gt 0 ]]; then
        CO_AUTHOR_COMMITS=$((CO_AUTHOR_COMMITS + 1))
    fi
    if [[ $ses_hits -gt 0 ]]; then
        SESSION_COMMITS=$((SESSION_COMMITS + 1))
    fi
    if [[ $co_changes -gt 0 || $ses_hits -gt 0 ]]; then
        MATCHED_SHAS="${MATCHED_SHAS}${sha}"$'\n'
    elif [[ $ok_hits -gt 0 ]]; then
        ALREADY_OK=$((ALREADY_OK + 1))
    fi
done < <(git -C "$REPO" log "${REV_ARGS[@]}" --format='%H')

AFFECTED="$(printf '%s' "$MATCHED_SHAS" | grep -c . || true)"
AFFECTED="${AFFECTED:-0}"

log "Scanned $TOTAL_COMMITS commit(s) in $SCOPE."
log "  co-author trailers to rewrite: $CO_AUTHOR_COMMITS commit(s)"
log "  session trailers to remove:    $SESSION_COMMITS commit(s)"
[[ $ALREADY_OK -gt 0 ]] && log "  already in final form:         $ALREADY_OK commit(s)"

if [[ $AFFECTED -eq 0 ]]; then
    log "Nothing to change."
    exit 0
fi

# Dry run: show the commits that would change, then stop. Exit 1 marks "found
# something", which makes the dry run usable as a CI check.
if [[ $WRITE -eq 0 ]]; then
    printf '\n%s\n' "Commits that would be rewritten ($AFFECTED):"
    while IFS= read -r sha; do
        [[ -n "$sha" ]] || continue
        printf '  %s  %s\n' "${sha:0:12}" "$(git -C "$REPO" log -1 --format='%s' "$sha")"
    done <<< "$MATCHED_SHAS"
    printf '\n%s\n' "Dry run: nothing was modified. Re-run with -w to rewrite."
    printf '%s\n' "Rewriting changes every commit hash from the earliest match onward."
    exit 1
fi

# Refuse to rewrite on top of uncommitted work. filter-repo checks this itself
# and -B bypasses that check, so the guard is repeated here where -B cannot
# reach it: losing uncommitted changes to a history rewrite is unrecoverable in
# a way that a bad rewrite is not.
if ! git -C "$REPO" diff --quiet HEAD 2>/dev/null; then
    die "Working tree has uncommitted changes. Commit or stash them first."
fi

if [[ $BACKUP -eq 1 ]]; then
    bundle="$REPO/claude-attribution-backup-$(date +%Y%m%d-%H%M%S).bundle"
    log "Writing backup bundle to $bundle"
    git -C "$REPO" bundle create "$bundle" --all >/dev/null 2>&1 \
        || die "Failed to create backup bundle."
    log "Backup written. Restore with: git fetch '$bundle' 'refs/heads/*:refs/heads/restored/*'"
fi

log "Rewriting $AFFECTED commit(s)..."

# Probe the exact invocation used below, not just the binary's presence:
# git-filter-repo can be installed as a standalone script while "git
# filter-repo" still fails as a subcommand (it is not on git's exec path).
# Testing "command -v git-filter-repo" would pick this branch and then die,
# instead of falling back to filter-branch as intended.
if git filter-repo --version >/dev/null 2>&1; then
    log "Using git-filter-repo."

    # The callback body runs per commit inside filter-repo, which hands it
    # "message" as bytes and expects bytes back. Everything here is therefore
    # byte literals: mixing in a str raises deep inside filter-repo.
    #
    # re.MULTILINE anchors ^ at each line rather than only at the message start,
    # which is what makes the trailer patterns apply to the trailer block.
    callback=$(cat <<'PYEOF'
import re

co_re = re.compile(rb'(?im)^[ \t]*Co-Authored-By:[ \t]*Claude(?![A-Za-z])[^\n]*$')
ses_re = re.compile(rb'(?im)^[ \t]*Claude-Session[ \t]*:[^\n]*\n?')
replacement = b'Co-Authored-By: Claude via Claude Code'

# Session lines go first, whole line including its newline, so removing one
# does not leave a blank gap in the middle of the trailer block.
message = ses_re.sub(b'', message)
message = co_re.sub(replacement, message)

# Collapse duplicate co-author trailers. Several model-specific lines in one
# commit all rewrite to the same text, and the result should be one trailer,
# not the same line repeated.
lines = message.split(b'\n')
out = []
for line in lines:
    if line.strip() == replacement and out and out[-1].strip() == replacement:
        continue
    out.append(line)
message = b'\n'.join(out)

# Trim trailing blank lines left where a session trailer used to be, then
# restore the single newline a commit message ends with.
message = message.rstrip() + b'\n'
return message
PYEOF
)

    fr_args=(--message-callback "$callback")
    [[ $FORCE -eq 1 ]] && fr_args+=(--force)

    # --refs limits the rewrite and implies --partial. Without it filter-repo
    # rewrites everything and, by design, strips the origin remote; --partial
    # keeps the remote in place, which is what anyone rewriting a working clone
    # wants.
    if [[ -n "$RANGE" ]]; then
        fr_args+=(--refs "$RANGE")
    elif [[ $ALL_REFS -eq 0 ]]; then
        fr_args+=(--refs "$(git -C "$REPO" rev-parse --abbrev-ref HEAD)")
    else
        fr_args+=(--partial)
    fi

    if [[ $QUIET -eq 1 ]]; then
        fr_args+=(--quiet)
    fi

    # filter-repo insists on running from inside the repo.
    (cd "$REPO" && git filter-repo "${fr_args[@]}") \
        || die "git filter-repo failed. History was not rewritten (or was left mid-rewrite: check 'git log' and restore from the bundle if needed)."
else
    log "git-filter-repo not found, falling back to git filter-branch (slower)."
    log "Install it with 'brew install git-filter-repo' for a faster rewrite."

    # sed does the same two edits as the Python callback. The co-author line is
    # substituted in place and the session line deleted; the duplicate-trailer
    # collapse is handled by cat -s on the blank lines plus awk for the repeats.
    #
    # BSD and GNU sed differ on -E and on case-insensitive matching, so the
    # filter uses a portable POSIX ERE with explicit character classes rather
    # than an (?i) flag no sed supports.
    filter='
        sed -E -e "s/^[[:space:]]*[Cc][Oo]-[Aa][Uu][Tt][Hh][Oo][Rr][Ee][Dd]-[Bb][Yy]:[[:space:]]*Claude([^A-Za-z].*)?$/Co-Authored-By: Claude via Claude Code/" \
               -e "/^[[:space:]]*[Cc][Ll][Aa][Uu][Dd][Ee]-[Ss][Ee][Ss][Ss][Ii][Oo][Nn][[:space:]]*:/d" \
        | awk "BEGIN{prev=\"\"} {
                   if (\$0 == \"Co-Authored-By: Claude via Claude Code\" && prev == \$0) next
                   prev = \$0; print
               }"
    '

    fb_env=(FILTER_BRANCH_SQUELCH_WARNING=1)
    if [[ -n "$RANGE" ]]; then
        fb_refs=("$RANGE")
    elif [[ $ALL_REFS -eq 1 ]]; then
        fb_refs=(--all)
    else
        fb_refs=(HEAD)
    fi

    # -f overwrites a leftover refs/original/ from an earlier run, which would
    # otherwise make filter-branch refuse to start.
    (cd "$REPO" && env "${fb_env[@]}" \
        git filter-branch -f --msg-filter "$filter" -- "${fb_refs[@]}") \
        || die "git filter-branch failed. Check 'git log'; the original refs are under refs/original/."
fi

log "Rewrite complete."

# Verify rather than assert. A rewrite that silently did nothing looks exactly
# like a successful one from the exit status alone.
remaining=0
while IFS= read -r sha; do
    body="$(git -C "$REPO" log -1 --format='%B' "$sha")"
    hits="$(printf '%s\n' "$body" | count_matching "$SESSION_RE")"
    [[ $hits -gt 0 ]] && remaining=$((remaining + 1))
    hits="$(printf '%s\n' "$body" | count_matching "$CO_AUTHOR_RE")"
    ok="$(printf '%s\n' "$body" | count_matching "$FINAL_RE")"
    [[ $hits -gt $ok ]] && remaining=$((remaining + 1))
done < <(git -C "$REPO" log "${REV_ARGS[@]}" --format='%H')

if [[ $remaining -gt 0 ]]; then
    die "$remaining commit(s) still carry unnormalized trailers. Inspect with: git log --format='%B' | grep -i claude"
fi

log "Verified: no unnormalized Claude trailers remain in $SCOPE."
cat >&2 <<EOF

Next steps:
  1. Review the result:   git log --format='%H %s%n%b' | grep -iB2 claude
  2. Push:                git push --force-with-lease
     Every rewritten commit has a new hash. Anyone else with a clone needs to
     re-clone or reset; a plain pull will merge the old history back in.
EOF
exit 0
