#!/bin/bash
set -euo pipefail

# Scan a repository's entire git history for secrets and PII: tokens, keys,
# email addresses, local filesystem paths, IPs and similar.
#
# Working-tree scanners miss the thing that actually matters here. A secret
# removed in a later commit is still in the object database, still served by a
# clone, and still readable by anyone who ever fetched the repo. So this scans
# the content of every commit rather than the working tree: every version of
# every path, including files deleted years ago. With -a it also reaches
# commits that no branch points at any more.
#
# Detection is regex-based, so it reports candidates, not confirmed leaks.
# Expect false positives (example keys in docs, test fixtures) and accept false
# negatives (a password in a variable named "foo"). Triage the output by hand.

usage() {
    cat <<EOF
Usage: $(basename "$0") [-r REPO] [-a] [-f FILE] [-c REV] [-t TYPE] [-x REGEX]
       [-m BYTES] [-C NUM] [-q] [-l]

Search a repo's git history for potential secrets and PII.

Options:
  -r REPO    Repository to scan (default: current directory)
  -a         Scan all refs, the reflog, and unreachable commits, not just HEAD.
             Slower, but this is where rewritten history hides. Reflogs are
             local and never cloned, so run this in the original repo
  -f FILE    Also search for the patterns in FILE, one per line. Repeatable.
             See CUSTOM PATTERNS below
  -c REV     Scan a specific commit or range instead, e.g. main~50..main.
             Repeatable
  -t TYPE    Only run the named check. Repeatable. -l lists the names
  -x REGEX   Exclude paths matching this POSIX ERE, e.g. '(^|/)vendor/'.
             Repeatable
  -m BYTES   Skip blobs larger than this (default: 1048576). Minified bundles
             and lockfiles generate noise far out of proportion to their size
  -C NUM     Lines of context around each match (default: 0)
  -q         Quiet: findings only, no progress or summary
  -l         List the available checks and exit
  -h         Show this help

CUSTOM PATTERNS

  -f reads a text file of extra things to search for, one per line, and runs
  them alongside the built-in checks:

      # Lines starting with # are comments, blank lines are skipped.
      hunter2
      ACME-INTERNAL-[0-9]{6}
      badger=\bBadgerCorp\b

  Each line is a PCRE, and a literal string is already a valid one, so
  "hunter2" matches itself. Regex metacharacters are live: to search for the
  literal IP 10.0.0.1, escape the dots as 10\.0\.0\.1, or the unescaped dots
  will also match 10x0y0z1.

  A line may be written as name=pattern to label the check. The name appears
  in the CHECK column and can be selected with -t, which is what you want when
  a file carries more than a couple of patterns. Unnamed patterns are called
  custom-1, custom-2 and so on, numbered in load order across all -f files.
  Names must be unique across every check, builtins included.

  That rule is why a pattern beginning with an identifier followed by "=" is
  read as a name. A line like

      GH_TOKEN=[A-Za-z0-9_]+

  defines a check named GH_TOKEN searching for [A-Za-z0-9_]+, which is almost
  certainly not the intent. To search for that text literally, escape the "="
  (GH_TOKEN\=[A-Za-z0-9_]+) or give the check its own name first
  (ghvar=GH_TOKEN=[A-Za-z0-9_]+). -l shows how every line was parsed.

  Patterns are validated when the file loads, so a malformed regex is reported
  with its file and line rather than failing partway through a long scan.

  Since a patterns file names the very things you consider sensitive, it is
  worth keeping out of the repo it describes.

Output is one finding per line:

  CHECK <TAB> COMMIT <TAB> PATH <TAB> LINE <TAB> TEXT

which is greppable, sortable and cuttable. Match text is truncated to keep a
recovered secret from scrolling across a shared terminal, and long opaque
strings are elided entirely. Redirect to a file to keep the full lines.

The commit shown is the first commit found containing that blob, so it is where
the content was introduced, not necessarily where it still lives.

Exit status: 0 if no findings, 1 if any finding, 2 on error. The nonzero status
on findings makes this usable as a CI gate.

Runtime scales with commits x checks, because "git grep <commit>" scans that
commit's whole tree. A few thousand commits is fine. On a repo with tens of
thousands, scope it with -c or narrow it with -t rather than scanning
everything at once.

WARNING: findings are unredacted secrets. A log of this output is as sensitive
as the repo it came from. Do not paste it into a ticket or CI job that is more
widely readable than the repo itself.

Example:
  # Full audit of a clone, skipping vendored code
  $(basename "$0") -r ~/src/myrepo -a -x '(^|/)(vendor|node_modules)/' > audit.txt

  # Gate a PR on the new commits only
  $(basename "$0") -c origin/main..HEAD -q

  # Add project-specific strings: internal hostnames, a legacy password, names
  $(basename "$0") -a -f ~/private/our-secrets.txt

  # Run only the custom patterns, skipping every builtin
  $(basename "$0") -a -f patterns.txt -t custom-1 -t custom-2

If this finds a real secret: rotate the credential first. Purging history with
git-filter-repo or BFG rewrites every commit hash, which breaks open PRs and
every existing clone, and it does nothing about the copies already fetched. The
rotation is the fix. The rewrite is cleanup.
EOF
}

log()  { [[ $QUIET -eq 1 ]] || printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# Checks are "name|description|PCRE". git grep -P is used throughout: these
# patterns need lookarounds and lazy quantifiers that POSIX ERE cannot express.
#
# Each pattern is tightened well past the obvious version, because a check that
# fires on every third line gets ignored, and an ignored check finds nothing.
readonly CHECKS=(
"aws-key|AWS access key ID|\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\\b"

"aws-secret|AWS secret access key|(?i)aws.{0,20}?(?:secret|private).{0,20}?['\\\"][A-Za-z0-9/+=]{40}['\\\"]"

"gh-token|GitHub token|\\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255}\\b"

"slack-token|Slack token or webhook|\\bxox[abposr]-[A-Za-z0-9-]{10,}\\b|https://hooks\\.slack\\.com/services/[A-Za-z0-9/+]{20,}"

"google-key|Google API key|\\bAIza[0-9A-Za-z_-]{35}\\b"

"stripe-key|Stripe secret key|\\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\\b"

"openai-key|OpenAI or Anthropic API key|\\b(?:sk-(?:proj-|ant-)?|sk-ant-api[0-9]{2}-)[A-Za-z0-9_-]{20,}\\b"

"npm-token|npm access token|\\bnpm_[A-Za-z0-9]{36}\\b"

"jwt|JSON Web Token|\\bey[A-Za-z0-9_-]{10,}\\.ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"

"private-key|Private key block|-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"

"putty-key|PuTTY private key|PuTTY-User-Key-File-[0-9]"

# Requires quote-then-value: 'password = $PASSWORD' and 'password:' with a
# lookup are the common legitimate forms, and both lack the literal.
"generic-secret|Assigned password, secret or token literal|(?i)\\b(?:passwd|password|passphrase|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\\b\\s*[:=]\\s*['\\\"][^'\\\"[:space:]]{8,}['\\\"]"

# Credentials inside a URL. Excludes the placeholder forms that dominate docs.
"url-creds|Credentials embedded in a URL|(?i)\\b[a-z][a-z0-9+.-]*://[^/\\s:@]+:(?!(?:password|passwd|pass|secret|token|xxx+|\\*+|<|%24|\\\$|\\{))[^/\\s:@]{3,}@"

"connection-string|Database connection string with password|(?i)\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp|mssql|jdbc:[a-z]+)://[^/\\s:@]+:[^/\\s:@]{3,}@"

# Excludes the reserved example domains and the noreply addresses git itself
# generates, which otherwise swamp the real addresses.
"email|Email address|(?i)\\b[A-Za-z0-9._%+-]+@(?!(?:example|test|localhost|invalid|domain|email|yourdomain|mydomain|sentry)\\.)(?!users\\.noreply\\.)[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"

# Local paths leak usernames, directory layout and sometimes employer.
"local-path|Local filesystem path|(?:/(?:Users|home)/(?!(?:user|username|youruser|me|root|ubuntu|runner|node|app|test)\\b)[A-Za-z0-9._-]+|[Cc]:\\\\+Users\\\\+(?!(?:user|username|Public|Default|Administrator)\\b)[A-Za-z0-9._-]+)"

# Private and loopback ranges are excluded: they are configuration, not PII.
"ip-address|Public IPv4 address|(?<![0-9.])(?!0\\.|10\\.|127\\.|169\\.254\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|22[4-9]\\.|2[3-5][0-9]\\.|255\\.)(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![0-9.])"

"phone|North American phone number|(?<![0-9-])(?:\\+1[ .-]?)?\\(?[2-9][0-9]{2}\\)?[ .-][2-9][0-9]{2}[ .-][0-9]{4}(?![0-9-])"

"ssn|US Social Security number|(?<![0-9-])(?!000|666|9[0-9]{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?![0-9-])"

# Luhn is not checked here, so this leans on the issuer prefixes to stay sane.
"credit-card|Credit card number|(?<![0-9-])(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6011)[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{1,4}(?![0-9-])"
)

# Built at run time from CHECKS plus anything -f supplies. CHECKS itself stays
# readonly so a malformed patterns file cannot quietly redefine a builtin.
ALL_CHECKS=()
ALL_COUNT=0
# Numbering for unnamed patterns runs across every -f file, not per file, so
# two unnamed files can be combined without both claiming custom-1.
CUSTOM_SEQ=0

REPO="."
ALL_REFS=0
QUIET=0
CONTEXT=0
MAX_BYTES=1048576
# Commits per git grep invocation. Large enough that a big repo takes few
# passes, small enough to stay well clear of ARG_MAX at 40 bytes per SHA.
readonly BATCH_SIZE=500
# bash 3.2 (macOS system bash) errors on "${arr[@]}" for an empty array under
# set -u, so each array carries an explicit count used to guard expansion.
WANTED=(); WANTED_COUNT=0
EXCLUDES=(); EXCLUDES_COUNT=0
REVS=(); REV_COUNT=0
PATTERN_FILES=(); PATTERN_FILE_COUNT=0

list_checks() {
    local entry
    printf '%-20s %s\n' "CHECK" "DESCRIPTION"
    for entry in "${ALL_CHECKS[@]}"; do
        printf '%-20s %s\n' "${entry%%|*}" "$(cut -d'|' -f2 <<<"$entry")"
    done
}

# Load one patterns file into ALL_CHECKS.
#
# Format is one pattern per line. A line may be a bare pattern, or "name=pattern"
# to give the check a name that -t can select and that labels its findings.
# Blank lines and lines whose first non-space character is # are skipped, so a
# file can be commented; a pattern that must start with a literal # can be
# written as an escaped \# or named.
#
# Each line is a PCRE, which a literal string already is: "hunter2" is a valid
# pattern matching itself. Only regex metacharacters ( . * + ? [ ] ( ) | \ etc )
# need escaping, so a literal search for "10.0.0.1" wants "10\.0\.0\.1" unless
# the dots-match-anything reading is acceptable.
load_pattern_file() {
    local file="$1"
    local line name pattern lineno=0 loaded=0
    local label st

    [[ -r "$file" ]] || die "Cannot read patterns file '$file'."
    label="$(basename "$file")"

    # A missing trailing newline would otherwise drop the final pattern, so the
    # loop condition also accepts a last line that read returns non-zero on.
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno + 1))

        # Strip a trailing CR so a CRLF file does not embed \r in every pattern,
        # where it would silently match nothing.
        line="${line%$'\r'}"

        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "${line#"${line%%[![:space:]]*}"}" == \#* ]] && continue

        # "name=pattern" only when the name is a plain identifier. This keeps a
        # pattern that merely contains "=" (a query string, an assignment) from
        # being split at the wrong place.
        if [[ "$line" =~ ^([A-Za-z][A-Za-z0-9_-]*)=(.*)$ ]]; then
            name="${BASH_REMATCH[1]}"
            pattern="${BASH_REMATCH[2]}"
        else
            CUSTOM_SEQ=$((CUSTOM_SEQ + 1))
            name="custom-$CUSTOM_SEQ"
            pattern="$line"
        fi

        [[ -n "$pattern" ]] || die "Empty pattern at $file:$lineno."

        # A "|" would be read as a field separator by the check parser below.
        # Rejecting it here beats a check that silently scans the wrong regex;
        # PCRE alternation is still available as (?:a|b) via a named entry, so
        # this only forbids the unescaped bare form.
        case "$name" in
            *'|'*) die "Check name may not contain '|' at $file:$lineno." ;;
        esac

        # Reject a pattern git cannot compile, naming the file and line. Left to
        # the scan, the same mistake would surface as an opaque failure much
        # later, after other checks had already run.
        #
        # The status is captured on its own line: "local st=$?" would assign the
        # exit status of local itself, which is always 0.
        set +e
        git -C "$REPO" grep -P -q -e "$pattern" HEAD \
            -- ':(glob)__sh_pcre_probe__' >/dev/null 2>&1
        st=$?
        set -e
        [[ $st -le 1 ]] || die "Invalid regex at $file:$lineno: $pattern"

        ALL_CHECKS+=("$name|Custom pattern from $label|$pattern")
        ALL_COUNT=$((ALL_COUNT + 1))
        loaded=$((loaded + 1))
    done < "$file"

    [[ $loaded -gt 0 ]] || die "No usable patterns in '$file'."
    log "Loaded $loaded custom pattern(s) from $file."
}

LIST_ONLY=0
while getopts ':r:af:c:t:x:m:C:qlh' opt; do
    case "$opt" in
        r) REPO="$OPTARG" ;;
        a) ALL_REFS=1 ;;
        f) PATTERN_FILES+=("$OPTARG"); PATTERN_FILE_COUNT=$((PATTERN_FILE_COUNT + 1)) ;;
        c) REVS+=("$OPTARG"); REV_COUNT=$((REV_COUNT + 1)) ;;
        t) WANTED+=("$OPTARG"); WANTED_COUNT=$((WANTED_COUNT + 1)) ;;
        x) EXCLUDES+=("$OPTARG"); EXCLUDES_COUNT=$((EXCLUDES_COUNT + 1)) ;;
        m) MAX_BYTES="$OPTARG" ;;
        C) CONTEXT="$OPTARG" ;;
        q) QUIET=1 ;;
        l) LIST_ONLY=1 ;;
        h) usage; exit 0 ;;
        :) echo "Error: -$OPTARG requires an argument." >&2; usage >&2; exit 2 ;;
        ?) echo "Error: unknown option -$OPTARG." >&2; usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -eq 0 ]] || { echo "Error: unexpected argument '$1'." >&2; usage >&2; exit 2; }
[[ "$MAX_BYTES" =~ ^[0-9]+$ ]] || die "-m expects a byte count, got '$MAX_BYTES'."
[[ "$CONTEXT"   =~ ^[0-9]+$ ]] || die "-C expects a line count, got '$CONTEXT'."

command -v git >/dev/null 2>&1 || die "git not found in PATH."
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "'$REPO' is not a git repository."

# git grep -P is optional at build time. Without it every pattern below fails
# to compile and the scan reports a clean, reassuring, entirely false "no
# findings", so refuse to run rather than mislead.
#
# The probe uses a lookahead, which only PCRE compiles. Matching nothing (1) is
# the success case here; a git without PCRE dies with 128 instead.
#
# The pathspec cannot match any real file, which keeps this to a regex compile.
# Probing against a bare HEAD would walk the entire tree first: on a large repo
# that is 20+ seconds spent proving something about the regex engine.
set +e
git -C "$REPO" grep -P -q -e '(?=x)y' HEAD -- ':(glob)__sh_pcre_probe__' >/dev/null 2>&1
probe_status=$?
set -e
[[ $probe_status -le 1 ]] || \
    die "This git lacks PCRE support (git grep -P). Install a git built with pcre2."

# Builtins first, so a custom check with a colliding name is reported as the
# duplicate it is rather than silently shadowing one.
for entry in "${CHECKS[@]}"; do
    ALL_CHECKS+=("$entry")
    ALL_COUNT=$((ALL_COUNT + 1))
done

# Custom patterns load after the PCRE probe, since the loader validates each
# pattern with git grep -P and that is only meaningful once -P is known to work.
if [[ $PATTERN_FILE_COUNT -gt 0 ]]; then
    for pf in "${PATTERN_FILES[@]}"; do
        load_pattern_file "$pf"
    done

    # Two checks sharing a name would make -t ambiguous and the output
    # unreadable, so say which name collided instead of scanning anyway.
    dupe=$(printf '%s\n' "${ALL_CHECKS[@]}" | cut -d'|' -f1 | sort | uniq -d | head -1)
    [[ -z "$dupe" ]] || die "Duplicate check name '$dupe'. Rename it in the patterns file."
fi

# -l is deferred to here so it lists custom checks too, not just the builtins.
if [[ $LIST_ONLY -eq 1 ]]; then
    list_checks
    exit 0
fi

# Validate -t names up front. A typo here would otherwise mean a silent,
# reassuring, completely empty scan.
if [[ $WANTED_COUNT -gt 0 ]]; then
    known=()
    for entry in "${ALL_CHECKS[@]}"; do known+=("${entry%%|*}"); done
    for want in "${WANTED[@]}"; do
        [[ " ${known[*]} " == *" $want "* ]] || die "Unknown check '$want'. Use -l to list."
    done
fi

# -x takes an ERE, which git's :(exclude) pathspec cannot express, so path
# exclusion is applied as a filter on results rather than as a pathspec.

# Commit lists get long, so they are written to a file and batched into git
# grep through xargs rather than passed as one argument vector.
COMMIT_FILE="$(mktemp -t sensitive_history)"
RESULTS="$(mktemp -t sensitive_history_out)"
SEEN="$(mktemp -t sensitive_history_seen)"
DATES="$(mktemp -t sensitive_history_dates)"
trap 'rm -f "$COMMIT_FILE" "$RESULTS" "$SEEN" "$DATES"' EXIT

# Blobs are deduplicated by git grep when several commits share one, so the
# cost tracks distinct content rather than commit count.
if [[ $REV_COUNT -gt 0 ]]; then
    for rev in "${REVS[@]}"; do
        git -C "$REPO" rev-parse --verify --quiet "$rev" >/dev/null 2>&1 \
            || git -C "$REPO" rev-list --quiet "$rev" >/dev/null 2>&1 \
            || die "Cannot resolve revision '$rev'."
    done
    git -C "$REPO" rev-list "${REVS[@]}" > "$COMMIT_FILE"
    log "Scanning $(printf '%s ' "${REVS[@]}")($(wc -l < "$COMMIT_FILE" | tr -d ' ') commits)."
elif [[ $ALL_REFS -eq 1 ]]; then
    # --all covers every ref. The other two sources are the interesting part:
    # an amended or force-pushed commit leaves its old version off all refs but
    # still in the object database, and that is precisely the commit someone
    # "removed" a secret from.
    #
    # --reflog and fsck --unreachable are both needed and neither subsumes the
    # other: while the reflog entry lives, the old commit is reachable and fsck
    # stays silent about it; once the reflog expires or is dropped, the commit
    # becomes unreachable and only fsck reports it.
    #
    # Local reflogs are not cloned, so run this in the original working repo.
    # A fresh clone of a repo cannot show what its owner amended away.
    {
        git -C "$REPO" rev-list --all --reflog 2>/dev/null || git -C "$REPO" rev-list --all
        git -C "$REPO" fsck --unreachable --no-progress 2>/dev/null \
            | awk '$2 == "commit" { print $3 }' || true
    } | sort -u > "$COMMIT_FILE"
    log "Scanning all refs and unreachable commits ($(wc -l < "$COMMIT_FILE" | tr -d ' ') commits)."
else
    git -C "$REPO" rev-list HEAD > "$COMMIT_FILE"
    log "Scanning HEAD history ($(wc -l < "$COMMIT_FILE" | tr -d ' ') commits). Use -a for all refs."
fi

[[ -s "$COMMIT_FILE" ]] || { log "No commits to scan."; exit 0; }


# Truncate match text before it reaches the terminal, and elide anything that
# looks like a raw high-entropy secret. The finding tells you where to look;
# it does not need to reprint the key in full.
redact() {
    awk -v max=120 '
    {
        line = $0
        # Collapse long unbroken token-like runs to a prefix plus a marker.
        while (match(line, /[A-Za-z0-9_\/+=-]{28,}/)) {
            tok = substr(line, RSTART, RLENGTH)
            line = substr(line, 1, RSTART + 7) "...[" (RLENGTH - 8) " more]" \
                   substr(line, RSTART + RLENGTH)
        }
        if (length(line) > max) line = substr(line, 1, max) "..."
        print line
    }'
}

FOUND=0

for entry in "${ALL_CHECKS[@]}"; do
    name="${entry%%|*}"
    rest="${entry#*|}"
    desc="${rest%%|*}"
    pattern="${rest#*|}"

    if [[ $WANTED_COUNT -gt 0 && " ${WANTED[*]} " != *" $name "* ]]; then
        continue
    fi

    log "Checking: $name ($desc)"

    # -I skips binaries, -n gives line numbers. Commits are passed as arguments
    # (git grep has no --stdin) and batched through xargs, since a large repo's
    # full commit list would otherwise overflow the argument vector.
    #
    # No trailing "--": it would be read as a pathspec and match nothing.
    #
    # A check that matches nothing exits 1, which is not an error here. xargs
    # returns 123 when any batch exits nonzero, so 123 is also expected: it
    # means at least one batch simply had no match.
    set +e
    xargs -n "$BATCH_SIZE" git -C "$REPO" grep \
        -P -I -n -C "$CONTEXT" --no-color \
        -e "$pattern" \
        < "$COMMIT_FILE" > "$RESULTS" 2>/dev/null
    status=$?
    set -e
    [[ $status -eq 0 || $status -eq 1 || $status -eq 123 ]] \
        || die "git grep failed on check '$name' (status $status)."
    [[ -s "$RESULTS" ]] || continue

    # git grep reports a hit once per commit containing the blob, so an old
    # secret in a long history produces hundreds of identical lines. Report
    # each distinct (path, line, content) once, attributed to the earliest
    # commit that carries it. Commit date orders the candidates, since the
    # commit file is not always in rev-list's newest-first order (-a sorts it
    # to dedupe the three sources).
    : > "$SEEN"
    while IFS= read -r raw; do
        # Format is COMMIT:PATH:LINE:TEXT, and PATH may itself contain colons.
        commit="${raw%%:*}"
        remainder="${raw#*:}"
        # Peel the trailing :LINE:TEXT off the right so a colon in PATH is safe.
        text="${remainder#*:}"
        lineno="${text%%:*}"
        [[ "$lineno" =~ ^[0-9]+$ ]] || continue   # skip context separator lines
        path="${remainder%%:"$lineno":*}"
        text="${text#*:}"

        skip=0
        if [[ $EXCLUDES_COUNT -gt 0 ]]; then
            for ex in "${EXCLUDES[@]}"; do
                [[ "$path" =~ $ex ]] && { skip=1; break; }
            done
        fi
        [[ $skip -eq 1 ]] && continue

        # Size filter is per blob, applied here so the check runs once.
        size=$(git -C "$REPO" cat-file -s "$commit:$path" 2>/dev/null || echo 0)
        [[ "$size" -gt "$MAX_BYTES" ]] && continue

        # Commit timestamps are cached in a file rather than an associative
        # array, which bash 3.2 does not have. A "git show" per finding would
        # otherwise dominate runtime on a repo with many hits.
        # || true: a cache miss exits 1, which set -e would treat as fatal.
        cdate="$(grep -m1 "^$commit " "$DATES" 2>/dev/null | cut -d' ' -f2 || true)"
        if [[ -z "$cdate" ]]; then
            cdate="$(git -C "$REPO" show -s --format=%ct "$commit" 2>/dev/null || echo 0)"
            printf '%s %s\n' "$commit" "$cdate" >> "$DATES"
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$path" "$lineno" "$text" "$commit" "$name" "$cdate" >> "$SEEN"
    done < "$RESULTS"

    # Pick the earliest commit per identical finding, preserving the order in
    # which findings were first seen.
    if [[ -s "$SEEN" ]]; then
        while IFS=$'\t' read -r path lineno text commit cname; do
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$cname" "${commit:0:12}" "$path" "$lineno" \
                "$(printf '%s' "$text" | redact)"
            FOUND=$((FOUND + 1))
        done < <(awk -F'\t' '{
                     key = $1 FS $2 FS $3
                     if (!(key in order)) order[key] = NR
                     # $6 is the commit timestamp. +0 forces a numeric compare
                     # even if a failed lookup left a non-numeric value there.
                     if (!(key in best) || ($6 + 0) < (bestdate[key] + 0)) {
                         best[key] = $0; bestdate[key] = $6
                     }
                 }
                 END { for (k in best) print order[k] "\t" best[k] }' "$SEEN" \
                 | sort -n | cut -f2- | cut -f1-5)
    fi
done

if [[ $FOUND -gt 0 ]]; then
    log "$FOUND finding(s). These are candidates: verify before acting."
    log "Rotate any confirmed credential before rewriting history."
    exit 1
fi

log "No findings."
exit 0
