# Twitter / X

## sync_followers_list.py

Mirrors the accounts you follow on X into one of your X Lists. This is useful
when using Readwise's Reader to consume messages from accounts you follow
directly.

Usage:

```sh
./sync_followers_list.py --dry-run          # show the plan, write nothing
./sync_followers_list.py                    # add missing members
./sync_followers_list.py --prune            # also remove stale members
```

| Flag | Effect |
| --- | --- |
| `--list-id ID` | Sync into this List id, skipping the lookup by name |
| `--list-name NAME` | List to resolve or create by name (default: `Following`) |
| `--prune` | Also remove members you no longer follow. Off by default |
| `--private` / `--public` | Visibility when creating the List (default: private) |
| `--description TEXT` | Description to use when creating the List |
| `--dry-run` | Show the plan and estimated cost without making changes |
| `--yes` | Skip the cost confirmation prompt |
| `--max-wait SECONDS` | Longest to sleep through a rate-limit window (default: 900) |
| `--max-adds N` | Add at most N members this run, deferring the rest to `--resume` |
| `--resume` | Continue a rate-limited run without re-confirming the cost |
| `--credentials-file PATH` | JSON file holding the credentials (default: `~/.twitter_x/credentials.json`) |
| `--state-file PATH` | Where to keep resolved ids and pending work |
| `--json` | Emit JSON instead of a formatted report |
| `--verbose` | List every affected account rather than a sample |
| `--log-level LEVEL` | Logging verbosity (default: `WARNING`) |

Exit codes follow the same convention as the other scripts here: `0` when the
List matches your following set, `1` when work was left unfinished, and `2` on a
credential or access failure.

### Setting up credentials

The script uses OAuth 1.0a user context. In the X developer console, create a
project and an app, then:

1. Set the app's **User authentication settings** to **Read and Write**.
2. *Then* generate the Access Token and Secret under **Keys and Tokens**.

Order matters. An access token minted while the app was read-only stays
read-only even after you change the app permission, and the failure shows up
later as a confusing 403 on the first member add rather than at login. If you
generated the token first, regenerate it after changing the permission.

Write the four values to `~/.twitter_x/credentials.json`:

```sh
mkdir -p ~/.twitter_x
cat > ~/.twitter_x/credentials.json <<'EOF'
{
  "consumer_key": "...",
  "consumer_secret": "...",
  "access_token": "...",
  "access_token_secret": "..."
}
EOF
chmod 600 ~/.twitter_x/credentials.json
```

The keys map to the console's API Key, API Key Secret, Access Token, and Access
Token Secret respectively. Unrecognized keys are ignored, so you can keep notes
or an unused bearer token in the same file.

Pass `--credentials-file PATH` to read from somewhere else. The script warns
when the file is readable by other users but still runs, so a wrong mode does
not block you mid-task.

Keep the file outside the repository. `git/sensitive_history.sh` scans for this
shape of assigned literal, and the gitignored `local/` directory is the place
for anything credential-adjacent that does need to live alongside the code.

The **app-only Bearer token will not work** for this script. The list membership
endpoints accept only user-context auth, and an app-only token has no user
identity, so it cannot resolve whose following set to read in the first place.

### Large first syncs

Adding members is one request per account with no bulk endpoint, and the write
side carries an undocumented 24-hour cap (reportedly around 100 adds per day)
that sits well below the published 300 per 15 minutes. A first sync of several
hundred accounts therefore cannot finish in one run, no matter how patient the
client is.

Ration it deliberately instead of discovering the cap:

```sh
./sync_followers_list.py --max-adds 90            # day one
./sync_followers_list.py --max-adds 90 --resume   # day two, and so on
```

The diff is recomputed from the live List on every run, so `--resume` never
replays stale work: it simply finds fewer accounts missing each time. Once the
List has caught up, ordinary incremental runs are small enough that none of this
matters.

If a run does hit the cap, it stops as soon as the API says so, records the
remainder as pending, and prints when the allowance resets. That is a normal
outcome rather than a failure, though the exit code is still 1 because work was
left unfinished.

### Cost

The X API bills per use rather than by subscription. Reading your own data is an
"Owned Read" at about $0.001 per account returned, and list membership changes
run about $0.005 each.

A first sync of a few hundred accounts therefore costs a few dollars, and later
runs cost cents because only the difference is written. The script prints an
estimate and asks for confirmation before spending anything; `--dry-run` shows
the same estimate and never writes.

Treat the estimate as indicative. The per-write figure is inferred from the
pricing docs' "List: Manage" line rather than published for these exact
endpoints.

### If the endpoint is not enrolled

`GET /2/users/:id/following` sometimes returns a 403 `client-not-enrolled` even
with credits available. This is an app provisioning problem, separate from
billing and from your auth method. The script probes the endpoint with a
single-result request before any bulk read, so this fails for the price of one
resource rather than after a full paginated fetch. Check the project's endpoint
access in the developer portal if you hit it.

### Removal safety

Additions and removals are deliberately asymmetric.

By default the script **only adds**. The default code path issues no DELETE
requests at all, so no rate limit, partial fetch, or bug in it can drop members
from a List you have curated. Accounts in the List that you no longer follow are
reported, not touched.

Passing `--prune` enables removal, but only when the following fetch completed
cleanly, meaning pagination ended because the API ran out of results rather than
because the script hit a retry ceiling, a page cap, or the `--max-wait` budget.
If the fetch was cut short, every member that was not seen looks stale, so
pruning is skipped, the reason is printed, and the run exits non-zero.

### Notes

- Accounts are matched on numeric user id, not handle, so someone changing their
  username does not churn the List.
- Protected and suspended accounts cannot be added. These are reported as
  "skipped" rather than "failed", since it is expected rather than an error.
- Rate limits are per 15 minutes and per endpoint: 900 for reading List
  members, 300 for reading your following set, and 300 for each membership
  change. The reads are never the constraint. A sync of a few thousand accounts
  is a few dozen read requests, because pages hold up to 1000 (following) or 100
  (List members) accounts each. Every membership change, by contrast, is one
  request per account, and there is no bulk endpoint.
- The published 300/15min is not what a bulk sync actually hits. The write
  endpoints are also subject to a **24-hour cap** enforced by anti-spam, which
  community reports put near 100 List adds per day. It is undocumented, so the
  only trustworthy statement of your own allowance is the
  `x-user-limit-24hour-limit` and `x-user-limit-24hour-remaining` headers on a
  429.
- The script sleeps through an ordinary 15-minute window, up to `--max-wait`,
  then records what is left and exits 1. Re-run with `--resume` to continue.
- A rate-limit wait is shown on the progress bar as a live countdown, and the
  reason is printed above it, so a run that pauses for a quarter of an hour says
  so rather than looking like it has frozen. The wait is interruptible: Ctrl+C
  lands immediately instead of being swallowed until the window resets.
- Rate-limit waits have their own budget, separate from the retries used for
  network errors and 5xx responses. A first sync can therefore sit through
  several windows without a run of rate limits being mistaken for a failing
  request. Once that budget is spent, the remaining accounts are recorded as
  pending rather than failed, which is what makes `--resume` pick them up.
- A 429 from the daily cap is detected and handled differently from a window
  limit. Such a response still carries an `x-rate-limit-reset` pointing at the
  next 15-minute boundary, because that is the only window that header knows
  about, so waiting on it sleeps a quarter of an hour and retries into another
  instant 429. The script reads the 24-hour headers instead, stops immediately,
  and reports when the allowance resets rather than waiting for something that
  cannot arrive in time.
- Progress is checkpointed to the state file as the run proceeds, not only at
  the end, so a run killed part way through does not lose the record of what it
  already changed.
- State lives in `~/.local/state/x-sync/state.json` and holds only resolved list
  ids and bookkeeping, never credentials.
