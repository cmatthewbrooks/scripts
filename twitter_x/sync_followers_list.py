#!/usr/bin/env python3
"""Mirror the accounts you follow on X into one of your X Lists.

Reads your following set and the target List's members, then adds everyone you
follow who is not already a member. Removal of members you no longer follow is
opt-in via ``--prune`` and is skipped whenever the following fetch came back
incomplete, so a rate-limited or partial run can never empty a curated List.

Authenticates with OAuth 1.0a user context, reading four values from a JSON
file at ``~/.twitter_x/credentials.json`` (override with --credentials-file)::

    {
      "consumer_key": "...",
      "consumer_secret": "...",
      "access_token": "...",
      "access_token_secret": "..."
    }

Generate these in the X developer console and ``chmod 600`` the file. The app
must be set to Read and Write *before* the access token is generated; a token
minted while the app was read-only stays read-only and fails on the first add
with a confusing 403.

The X API bills per use. Reading your own data is an "Owned Read" at roughly
$0.001 per account returned, and list membership changes cost roughly $0.005
each, so a first sync of a few hundred accounts costs a few dollars and later
runs cost cents. The script probes for access and prints an estimate before
spending anything.

Typical usage::

    ./sync_followers_list.py --dry-run          # show the plan, write nothing
    ./sync_followers_list.py                    # add missing members
    ./sync_followers_list.py --prune            # also remove stale members
    ./sync_followers_list.py --json             # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# `X | Y` unions in annotations evaluated at runtime by dataclasses, plus
# `list[str]` builtin generics, require Python 3.10+.
if sys.version_info < (3, 10):
    sys.exit("error: python 3.10 or newer is required")

import requests
from requests_oauthlib import OAuth1
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

API_BASE = "https://api.x.com/2"

# Seconds to wait on any single HTTP request. The X API occasionally stalls
# rather than failing outright, which would otherwise hang an unattended run.
REQUEST_TIMEOUT = 30

# Retries for transient 5xx responses, using exponential backoff. Rate limits
# (429) are handled separately, by sleeping until the reset timestamp instead.
MAX_RETRIES = 3
BACKOFF_BASE = 2.0

# Rate-limit waits get their own budget rather than sharing the retry counter.
# A 429 means "come back later", not "this request is failing", so waiting one
# out should not spend a retry that a genuine 5xx might need. A large first sync
# legitimately spans several 15-minute windows.
MAX_RATE_LIMIT_WAITS = 10

# Granularity of a rate-limit sleep. Waking roughly once a second keeps the
# countdown moving and leaves Ctrl+C responsive, instead of blocking for the
# full window in one uninterruptible call.
RATE_LIMIT_TICK = 1.0

# Headers describing the 24-hour cap, which is enforced separately from the
# published 15-minute window and is what a bulk sync actually runs into. The
# write endpoints are additionally subject to an anti-spam daily allowance that
# X does not document; the only reliable statement of it is these headers on a
# 429, so read them rather than hard-coding a guess.
DAILY_REMAINING_HEADERS = ("x-user-limit-24hour-remaining", "x-app-limit-24hour-remaining")
DAILY_RESET_HEADERS = ("x-user-limit-24hour-reset", "x-app-limit-24hour-reset")
DAILY_LIMIT_HEADERS = ("x-user-limit-24hour-limit", "x-app-limit-24hour-limit")

# How often the add/remove passes checkpoint their progress, in accounts. Small
# enough that an interrupted run loses little, large enough to avoid writing the
# state file on every single membership change.
CHECKPOINT_EVERY = 25

# Page sizes. `/following` accepts up to 1000 per page; the list endpoints cap
# at 100. Larger pages mean fewer requests against the 15-minute rate budget.
FOLLOWING_PAGE_SIZE = 1000
LIST_PAGE_SIZE = 100

# Pagination safety valve. Hit only by a runaway `next_token` loop, and it marks
# the fetch truncated, which in turn disables pruning.
MAX_PAGES = 200

# Pay-per-usage pricing, from the X API pricing docs. Owned reads are billed per
# resource returned; list writes per request. The write figure is inferred from
# the docs' "List: Manage" line rather than stated for these exact endpoints, so
# any estimate built from it is presented as approximate.
OWNED_READ_PER_RESOURCE = 0.001
LIST_MANAGE_PER_OP = 0.005
LIST_CREATE_PER_OP = 0.010

# Keys expected in the credentials JSON file. Order matters only for the error
# message listing whatever is missing.
CREDENTIAL_KEYS = (
    "consumer_key",
    "consumer_secret",
    "access_token",
    "access_token_secret",
)

DEFAULT_CREDENTIALS_FILE = Path.home() / ".twitter_x" / "credentials.json"
DEFAULT_STATE_FILE = Path.home() / ".local" / "state" / "x-sync" / "state.json"

SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "error": ("bold red", "✖"),
    "warning": ("yellow", "▲"),
    "note": ("cyan", "•"),
    "ok": ("green", "✔"),
}


class SyncError(Exception):
    """Base class for failures that should be reported without a traceback."""


class AuthError(SyncError):
    """The credentials were rejected, or lack the permissions required."""


class AccessError(SyncError):
    """The endpoint is not available to this app, or access was forbidden."""


class RateLimitError(SyncError):
    """A rate limit that could not be waited out within the configured budget.

    Distinct from a generic `SyncError` because the work is not failing, only
    deferred: the caller records whatever is left as pending so `--resume` can
    finish it, rather than marking those accounts failed.
    """


class DailyCapError(RateLimitError):
    """The 24-hour allowance for an endpoint is exhausted.

    A subclass of `RateLimitError` because the remaining work is still merely
    deferred, but it must be distinguished from a 15-minute window: waiting is
    pointless for hours, so the run stops and says when to come back instead of
    sleeping against a reset that cannot arrive in time.

    Attributes:
        reset_at: Unix timestamp when the daily allowance refreshes, or None if
            the API did not say.
    """

    def __init__(self, message: str, reset_at: float | None = None) -> None:
        """Record the message and, where known, the reset time.

        Args:
            message: Human-readable explanation.
            reset_at: Unix timestamp of the cap reset, if the API supplied one.
        """
        super().__init__(message)
        self.reset_at = reset_at


@dataclass
class Credentials:
    """OAuth 1.0a user-context credentials for a single X account.

    Attributes:
        consumer_key: The app's API key.
        consumer_secret: The app's API key secret.
        access_token: The access token representing the authorizing account.
        access_token_secret: The secret paired with that access token.
    """

    consumer_key: str
    consumer_secret: str
    access_token: str
    access_token_secret: str


@dataclass(frozen=True)
class XUser:
    """A single X account, as returned by the users and list endpoints.

    Attributes:
        id: The numeric account id, stable across username changes.
        username: The @handle, without the leading @.
        name: The account's display name.
    """

    id: str
    username: str
    name: str

    @property
    def handle(self) -> str:
        """Format the account as an @handle.

        Returns:
            The username prefixed with "@".
        """
        return f"@{self.username}"


@dataclass
class SyncPlan:
    """The difference between the following set and the List's membership.

    Attributes:
        to_add: Accounts followed but not yet in the List.
        stale: Accounts in the List that are no longer followed. These are
            removal *candidates* only; they are deleted solely when --prune is
            passed and the following fetch completed cleanly.
        unchanged: Count of accounts already correctly in the List.
        following_complete: Whether the following fetch paginated to the end.
            False means the API cut us short, so `stale` cannot be trusted.
    """

    to_add: list[XUser] = field(default_factory=list)
    stale: list[XUser] = field(default_factory=list)
    unchanged: int = 0
    following_complete: bool = True

    @property
    def prune_allowed(self) -> bool:
        """Report whether deleting the stale accounts would be safe.

        A truncated following fetch makes every List member look stale, so
        pruning is refused outright rather than deleting real members.

        Returns:
            True when the following set is known to be complete.
        """
        return self.following_complete

    @property
    def is_empty(self) -> bool:
        """Report whether the List already matches the following set.

        Returns:
            True when there is nothing to add and nothing stale.
        """
        return not self.to_add and not self.stale


@dataclass
class CostEstimate:
    """An approximate price for the API calls a run will make.

    Attributes:
        read_resources: Number of billable resources expected from reads.
        write_ops: Number of billable write requests expected.
        create_ops: Number of list-creation requests expected.
    """

    read_resources: int = 0
    write_ops: int = 0
    create_ops: int = 0

    @property
    def dollars(self) -> float:
        """Total the estimate in US dollars.

        Returns:
            The approximate cost of the run.
        """
        return (
            self.read_resources * OWNED_READ_PER_RESOURCE
            + self.write_ops * LIST_MANAGE_PER_OP
            + self.create_ops * LIST_CREATE_PER_OP
        )


@dataclass
class SyncResult:
    """What actually happened when a plan was applied.

    Attributes:
        added: Accounts successfully added to the List.
        removed: Accounts successfully removed from the List.
        skipped: Accounts the API refused to add, typically protected or
            suspended. Expected, and not counted as a failure.
        failed: Accounts that errored for any other reason.
        pending: Accounts left unprocessed, usually because a rate-limit wait
            exceeded --max-wait. Written to the state file for --resume.
        errors: Human-readable error messages, one per failure.
    """

    added: list[XUser] = field(default_factory=list)
    removed: list[XUser] = field(default_factory=list)
    skipped: list[XUser] = field(default_factory=list)
    failed: list[XUser] = field(default_factory=list)
    pending: list[XUser] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """Report whether every intended change was applied.

        Returns:
            True when nothing failed and nothing was left pending.
        """
        return not self.failed and not self.pending


CREDENTIALS_TEMPLATE = """{
  "consumer_key": "...",
  "consumer_secret": "...",
  "access_token": "...",
  "access_token_secret": "..."
}"""


def load_credentials(path: Path) -> Credentials:
    """Read the OAuth 1.0a credentials from a JSON file.

    Args:
        path: Location of the credentials file.

    Returns:
        The populated `Credentials`.

    Raises:
        AuthError: If the file is absent, unreadable, not valid JSON, not a
            JSON object, or missing any of the four keys. Every missing key is
            reported at once rather than one per run.
    """
    logger.debug("loading credentials from %s", path)

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise AuthError(
            f"no credentials file at {path}\n"
            f"Create it with the four values from the X developer console:\n\n"
            f"{CREDENTIALS_TEMPLATE}\n\n"
            f"Then restrict it: chmod 600 {path}"
        ) from None
    except OSError as exc:
        raise AuthError(f"could not read {path}: {exc}") from exc

    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise AuthError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise AuthError(f"{path} must contain a JSON object, not {type(payload).__name__}")

    # Coerce rather than demand strings, so a value that arrives as a number
    # from a hand-edited file still works instead of failing at signing time.
    values = {key: str(payload.get(key, "")).strip() for key in CREDENTIAL_KEYS}
    missing = [key for key, value in values.items() if not value]

    if missing:
        raise AuthError(
            f"{path} is missing or has empty value(s) for: " + ", ".join(missing) + "\n"
            "Generate these in the X developer console under Keys and Tokens."
        )

    _warn_if_world_readable(path)

    logger.debug("all %d credential keys present", len(CREDENTIAL_KEYS))
    return Credentials(
        consumer_key=values["consumer_key"],
        consumer_secret=values["consumer_secret"],
        access_token=values["access_token"],
        access_token_secret=values["access_token_secret"],
    )


def _warn_if_world_readable(path: Path) -> None:
    """Warn when the credentials file is readable by other users.

    Long-lived OAuth tokens in a file on disk are worth protecting, but a wrong
    mode is not a reason to refuse to run, so this only warns.

    Args:
        path: The credentials file to inspect.
    """
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        logger.debug("could not stat %s: %s", path, exc)
        return

    # Group or other holding any permission bit.
    if mode & 0o077:
        logger.warning(
            "%s is readable by other users (mode %o); run: chmod 600 %s",
            path,
            mode & 0o777,
            path,
        )


def parse_user(payload: dict[str, Any]) -> XUser:
    """Build an `XUser` from a user object in an API response.

    Args:
        payload: A single user object from the `data` array.

    Returns:
        The parsed user. Missing optional fields fall back to empty strings.
    """
    return XUser(
        id=str(payload.get("id", "")),
        username=str(payload.get("username", "")),
        name=str(payload.get("name", "")),
    )


class WaitReporter:
    """Reports a blocking wait through a live `Progress` display.

    The client sleeps far below the UI layer, so without something like this a
    rate-limit wait is invisible: the bar simply stops moving. This narrows that
    coupling to one small object the client can call without knowing whether a
    progress bar exists, what task it is drawing, or whether output is a
    terminal at all.

    Attributes:
        progress: The live display to draw on.
        task: The task whose description is rewritten while waiting.
        base: The description to restore once the wait is over.
    """

    def __init__(self, progress: Progress, task: TaskID, base: str) -> None:
        """Bind a reporter to one progress task.

        Args:
            progress: The live display to draw on.
            task: The task being tracked.
            base: The task's normal description, restored after each wait.
        """
        self.progress = progress
        self.task = task
        self.base = base

    def notice(self, message: str) -> None:
        """Print a one-off message above the live display.

        Args:
            message: The text to print.
        """
        # Printing via the Progress console rather than the bare console keeps
        # the live region intact; a plain print would be overwritten by the
        # next refresh.
        self.progress.console.print(render_severity("warning", message))

    def countdown(self, remaining: float, reason: str) -> None:
        """Update the task description with the time left to wait.

        Args:
            remaining: Seconds still to wait.
            reason: Short phrase naming what is being waited on.
        """
        minutes, seconds = divmod(max(int(remaining), 0), 60)
        clock = f"{minutes:d}:{seconds:02d}"
        self.progress.update(
            self.task,
            description=(
                f"{self.base} [yellow]({reason}, resuming in {clock})[/yellow]"
            ),
        )

    def clear(self) -> None:
        """Restore the task's normal description after a wait."""
        self.progress.update(self.task, description=self.base)


class XClient:
    """A thin, rate-limit-aware client for the handful of X API v2 endpoints.

    Wraps a `requests.Session` whose `auth` is a single OAuth1 signer, so every
    request is signed transparently. All traffic funnels through `request()`,
    which is the only place that retries, sleeps on rate limits, or translates
    an HTTP status into one of this module's typed errors.

    Attributes:
        max_wait: Longest a single rate-limit sleep may last, in seconds.
        requests_made: Count of HTTP requests issued, for reporting.
        waiter: Optional sink for "I am waiting" messages. Long sleeps happen
            deep in this class but are a user-facing event, so the caller
            supplies somewhere to report them that composes with whatever it is
            drawing. None sends them to the log only.
    """

    def __init__(self, credentials: Credentials, max_wait: float = 900.0) -> None:
        """Build a signed session.

        Args:
            credentials: The OAuth 1.0a credentials to sign with.
            max_wait: Cap on any single rate-limit sleep. A required wait
                longer than this aborts the call instead of blocking.
        """
        self.max_wait = max_wait
        self.requests_made = 0
        self.waiter: WaitReporter | None = None
        self._session = requests.Session()
        self._session.auth = OAuth1(
            credentials.consumer_key,
            credentials.consumer_secret,
            credentials.access_token,
            credentials.access_token_secret,
        )
        logger.debug("client initialized, max_wait=%.0fs", max_wait)

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Issue one signed API request, retrying where it is safe to do so.

        Query parameters must be passed via `params` rather than baked into
        `path`: OAuth 1.0a signs the query string, and oauthlib only sees
        parameters it is given, so a hand-appended `?pagination_token=...`
        produces a signature mismatch and an opaque 401 on the second page.

        Args:
            method: HTTP verb, e.g. "GET" or "POST".
            path: Path below the API base, e.g. "/users/me".
            params: Query parameters, or None.
            json_body: JSON request body, or None.

        Returns:
            The decoded response body. An empty dict for a 204.

        Raises:
            AuthError: On 401, or on 403 that names a permissions problem.
            AccessError: On 403 for an endpoint this app cannot use.
            RateLimitError: When a rate limit cannot be waited out in budget.
            SyncError: On a non-retryable error, or after exhausting retries.
        """
        url = f"{API_BASE}{path}"

        # Two independent budgets. `attempt` covers things that went wrong
        # (network errors, 5xx) and is spent by retrying; `waits` covers a 429,
        # which is the server working correctly and telling us to come back.
        # Sharing one counter, as this once did, let a few rate limits exhaust
        # the retries and surface as a spurious "giving up" failure.
        attempt = 0
        waits = 0

        while True:
            try:
                self.requests_made += 1
                response = self._session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as exc:
                # Network-level failure. Worth one more try for transient DNS
                # or connection resets, but not worth burning every retry.
                logger.warning("request to %s failed: %s", path, exc)
                if attempt >= MAX_RETRIES:
                    raise SyncError(f"network error calling {path}: {exc}") from exc
                self._backoff(attempt)
                attempt += 1
                continue

            logger.debug("%s %s -> %d", method, path, response.status_code)

            if response.status_code == 429:
                if waits >= MAX_RATE_LIMIT_WAITS:
                    raise RateLimitError(
                        f"rate limited on {path} {waits} times; giving up for now "
                        f"so the remaining work can be resumed"
                    )
                if not self._handle_rate_limit(response, path):
                    raise RateLimitError(
                        f"rate limited on {path} and the reset is further out than "
                        f"--max-wait ({self.max_wait:.0f}s)"
                    )
                waits += 1
                continue

            if response.status_code >= 500:
                logger.warning("server error %d on %s", response.status_code, path)
                if attempt >= MAX_RETRIES:
                    raise SyncError(
                        f"{path} returned {response.status_code} after "
                        f"{MAX_RETRIES} retries"
                    )
                self._backoff(attempt)
                attempt += 1
                continue

            if response.status_code in (401, 403):
                raise self._auth_failure(response, path)

            if not response.ok:
                raise SyncError(f"{path} returned {response.status_code}: {self._detail(response)}")

            if response.status_code == 204 or not response.content:
                return {}

            try:
                return response.json()
            except ValueError as exc:
                raise SyncError(f"{path} returned a non-JSON body") from exc

    def _backoff(self, attempt: int) -> None:
        """Sleep for an exponentially increasing interval.

        Args:
            attempt: Zero-based retry number.
        """
        delay = BACKOFF_BASE ** attempt
        # Warning rather than info: the caller is stalled, and at the default
        # log level an info message would make this look like a hang.
        logger.warning("retrying in %.1fs", delay)
        if self.waiter:
            self.waiter.notice(f"request failed, retrying in {delay:.0f}s")
        time.sleep(delay)

    @staticmethod
    def _header_float(response: requests.Response, names: tuple[str, ...]) -> float | None:
        """Read the first of several headers that parses as a number.

        Args:
            response: The response to inspect.
            names: Header names to try, in order of preference.

        Returns:
            The parsed value, or None if none of the headers was usable.
        """
        for name in names:
            raw = response.headers.get(name)
            if raw is None:
                continue
            try:
                return float(raw)
            except ValueError:
                logger.debug("header %s was not numeric: %r", name, raw)
        return None

    def _check_daily_cap(self, response: requests.Response, path: str) -> None:
        """Raise if this 429 came from the 24-hour cap rather than the window.

        The two are easy to confuse and the remedies are opposite. A 429 from
        the daily cap still carries an `x-rate-limit-reset` pointing at the next
        15-minute boundary, because that is the only window that header knows
        about, so a client that reads it alone sleeps a quarter of an hour,
        retries into another instant 429, and makes no progress for as long as
        its budget lasts. The daily headers are the only reliable signal.

        Args:
            response: The 429 response.
            path: The path being called, for the message.

        Raises:
            DailyCapError: When the 24-hour allowance is exhausted.
        """
        remaining = self._header_float(response, DAILY_REMAINING_HEADERS)
        if remaining is None or remaining > 0:
            return

        reset_at = self._header_float(response, DAILY_RESET_HEADERS)
        limit = self._header_float(response, DAILY_LIMIT_HEADERS)

        allowance = f"{limit:.0f} request(s)" if limit is not None else "the daily allowance"
        when = ""
        if reset_at is not None:
            hours = max(reset_at - time.time(), 0) / 3600
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(reset_at))
            when = f", which resets at {stamp} (in about {hours:.1f}h)"

        logger.warning("daily cap reached on %s%s", path, when)
        raise DailyCapError(
            f"the 24-hour cap on {path} is used up ({allowance}){when}. "
            f"Waiting will not help until then; re-run with --resume afterwards "
            f"to continue where this left off.",
            reset_at=reset_at,
        )

    def _handle_rate_limit(self, response: requests.Response, path: str) -> bool:
        """Sleep until a rate-limit window resets, if that is within budget.

        Sleeps in short ticks rather than one long call, so the wait can be
        reported as it counts down and a Ctrl+C lands promptly instead of being
        swallowed for up to `max_wait` seconds.

        Args:
            response: The 429 response, carrying `x-rate-limit-reset`.
            path: The path being called, for logging.

        Returns:
            True if the window was waited out and the call should be retried,
            False if the required wait exceeds `max_wait`.

        Raises:
            DailyCapError: When the 429 came from the 24-hour cap, where
                sleeping through the 15-minute window would achieve nothing.
        """
        # Check this first: a daily-cap 429 looks like an ordinary one, and
        # waiting on its 15-minute header is exactly the futile loop to avoid.
        self._check_daily_cap(response, path)

        reset_header = response.headers.get("x-rate-limit-reset", "")
        try:
            # The header is an absolute Unix timestamp, not a duration.
            wait = float(reset_header) - time.time()
        except ValueError:
            # Header missing or malformed; fall back to a full window.
            wait = 60.0

        # A reset that has already passed still needs a moment of slack, since
        # the server's clock and ours will not agree exactly.
        wait = max(wait, 1.0) + 1.0

        if wait > self.max_wait:
            logger.warning("rate limited on %s, reset in %.0fs, over budget", path, wait)
            return False

        # Warning rather than info so the reason for the stall survives the
        # default log level. Waiting minutes in silence is what made this look
        # like a hang rather than a rate limit.
        logger.warning("rate limited on %s, sleeping %.0fs", path, wait)
        if self.waiter:
            self.waiter.notice(
                f"rate limited by the API, waiting {wait:.0f}s for the window to reset"
            )

        deadline = time.monotonic() + wait
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if self.waiter:
                    self.waiter.countdown(remaining, "rate limited")
                time.sleep(min(RATE_LIMIT_TICK, remaining))
        finally:
            if self.waiter:
                self.waiter.clear()

        return True

    def _auth_failure(self, response: requests.Response, path: str) -> SyncError:
        """Translate a 401 or 403 into an error the user can act on.

        Args:
            response: The failing response.
            path: The path being called.

        Returns:
            The error to raise. Not raised here so the caller keeps its
            control flow explicit.
        """
        detail = self._detail(response)

        if response.status_code == 401:
            return AuthError(
                f"authentication rejected on {path}: {detail}\n"
                "Check the four values in the credentials file. If they look right, the "
                "access token may predate the app being set to Read and Write; "
                "regenerate it in the developer console."
            )

        # 403 covers two very different problems, and the remedies differ, so
        # separate them on the API's own wording rather than guessing.
        lowered = detail.lower()
        if "not enrolled" in lowered or "client-not-enrolled" in lowered:
            return AccessError(
                f"this app is not enrolled for {path}: {detail}\n"
                "The endpoint is not provisioned for your project, which is separate "
                "from having API credits. Check the project's access in the developer "
                "portal."
            )

        return AuthError(
            f"forbidden on {path}: {detail}\n"
            "The app likely lacks Read and Write permission, or the access token was "
            "generated before that permission was granted."
        )

    @staticmethod
    def _detail(response: requests.Response) -> str:
        """Extract the most useful error text from a response body.

        Args:
            response: Any response.

        Returns:
            The API's `detail`, `title`, or first error message; failing that,
            a truncated copy of the raw body.
        """
        try:
            body = response.json()
        except ValueError:
            return response.text.strip()[:200] or "(empty response body)"

        if isinstance(body, dict):
            for key in ("detail", "title", "error_description", "error"):
                value = body.get(key)
                if isinstance(value, str) and value:
                    return value
            errors = body.get("errors")
            if isinstance(errors, list) and errors:
                first = errors[0]
                if isinstance(first, dict):
                    for key in ("detail", "message", "title"):
                        value = first.get(key)
                        if isinstance(value, str) and value:
                            return value

        return str(body)[:200]

    def paginate(
        self,
        path: str,
        params: dict[str, Any],
        limit: int | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Follow `next_token` pagination and collect every item.

        Args:
            path: Path below the API base.
            params: Query parameters, excluding `pagination_token`.
            limit: Stop after collecting this many items, marking the result
                truncated. None collects everything.

        Returns:
            A tuple of (items, complete). `complete` is True only when
            pagination ended because the API stopped supplying a `next_token`.
            Anything else (a page cap, a caller limit) yields False, which the
            caller must treat as "this set may be missing entries".
        """
        items: list[dict[str, Any]] = []
        token: str | None = None
        complete = False

        for page in range(MAX_PAGES):
            page_params = dict(params)
            if token:
                page_params["pagination_token"] = token

            payload = self.request("GET", path, params=page_params)
            data = payload.get("data") or []
            items.extend(data)
            logger.debug("page %d of %s yielded %d item(s)", page + 1, path, len(data))

            if limit is not None and len(items) >= limit:
                logger.debug("hit caller limit of %d on %s", limit, path)
                return items[:limit], False

            token = (payload.get("meta") or {}).get("next_token")
            if not token:
                # The only path that proves we saw the whole collection.
                complete = True
                break
        else:
            logger.warning("stopped paginating %s at the %d page cap", path, MAX_PAGES)

        return items, complete

    def get_me(self) -> XUser:
        """Look up the account the credentials belong to.

        Returns:
            The authenticated user.

        Raises:
            SyncError: If the response contains no user object.
        """
        payload = self.request("GET", "/users/me", params={"user.fields": "username,name"})
        data = payload.get("data")
        if not isinstance(data, dict) or not data.get("id"):
            raise SyncError("could not determine the authenticated account from /users/me")
        user = parse_user(data)
        logger.info("authenticated as %s (%s)", user.handle, user.id)
        return user

    def probe_following_access(self, user_id: str) -> None:
        """Confirm the following endpoint is usable before spending on it.

        Requests a single result, so a misconfigured app fails for the price of
        one resource rather than a full paginated read.

        Args:
            user_id: The account whose following set will be read.

        Raises:
            AccessError: If the app is not enrolled for the endpoint.
            AuthError: If the credentials lack the necessary permission.
        """
        logger.debug("probing /following access for %s", user_id)
        self.request(
            "GET",
            f"/users/{user_id}/following",
            params={"max_results": 1},
        )
        logger.info("following endpoint is accessible")

    def get_following(self, user_id: str) -> tuple[list[XUser], bool]:
        """Read every account the given user follows.

        Args:
            user_id: The account whose following set to read.

        Returns:
            A tuple of (accounts, complete). See `paginate` for what
            `complete` guarantees; it gates whether pruning may run.
        """
        raw, complete = self.paginate(
            f"/users/{user_id}/following",
            {"max_results": FOLLOWING_PAGE_SIZE, "user.fields": "username,name"},
        )
        users = [parse_user(item) for item in raw]
        logger.info("fetched %d followed account(s), complete=%s", len(users), complete)
        return users, complete

    def get_owned_lists(self, user_id: str) -> list[dict[str, Any]]:
        """Read the Lists owned by the given user.

        Args:
            user_id: The owning account.

        Returns:
            The raw list objects, each with at least `id` and `name`.
        """
        raw, _ = self.paginate(
            f"/users/{user_id}/owned_lists",
            {"max_results": LIST_PAGE_SIZE, "list.fields": "name,private,member_count"},
        )
        logger.info("found %d owned list(s)", len(raw))
        return raw

    def create_list(self, name: str, description: str, private: bool) -> str:
        """Create a new List.

        Args:
            name: The List name, 1-25 characters.
            description: The List description, up to 100 characters.
            private: Whether the List should be private.

        Returns:
            The new List's id.

        Raises:
            SyncError: If the response contains no list id.
        """
        body: dict[str, Any] = {"name": name, "private": private}
        if description:
            body["description"] = description

        payload = self.request("POST", "/lists", json_body=body)
        list_id = ((payload.get("data") or {}).get("id")) or ""
        if not list_id:
            raise SyncError(f"list creation returned no id: {payload}")

        logger.info("created list %r with id %s", name, list_id)
        return str(list_id)

    def get_list_members(self, list_id: str) -> tuple[list[XUser], bool]:
        """Read the current members of a List.

        Args:
            list_id: The List to read.

        Returns:
            A tuple of (members, complete).
        """
        raw, complete = self.paginate(
            f"/lists/{list_id}/members",
            {"max_results": LIST_PAGE_SIZE, "user.fields": "username,name"},
        )
        users = [parse_user(item) for item in raw]
        logger.info("list %s has %d member(s), complete=%s", list_id, len(users), complete)
        return users, complete

    def add_list_member(self, list_id: str, user_id: str) -> bool:
        """Add one account to a List.

        Args:
            list_id: The target List.
            user_id: The account to add.

        Returns:
            True if the account is now a member.
        """
        payload = self.request(
            "POST",
            f"/lists/{list_id}/members",
            json_body={"user_id": user_id},
        )
        return bool((payload.get("data") or {}).get("is_member", False))

    def remove_list_member(self, list_id: str, user_id: str) -> bool:
        """Remove one account from a List.

        Args:
            list_id: The target List.
            user_id: The account to remove.

        Returns:
            True if the account is no longer a member.
        """
        payload = self.request("DELETE", f"/lists/{list_id}/members/{user_id}")
        return not bool((payload.get("data") or {}).get("is_member", True))


def build_plan(
    following: list[XUser],
    members: list[XUser],
    following_complete: bool,
) -> SyncPlan:
    """Diff the following set against the List's membership.

    Pure: no I/O, no network, no clock. Everything that decides whether data
    gets deleted is computed here, so the safety behavior is testable without
    credentials.

    Accounts are matched on id rather than username, because usernames change
    while ids do not; matching on handles would churn the List every rename.

    Args:
        following: Accounts the user follows.
        members: Accounts currently in the List.
        following_complete: Whether `following` is known to be the whole set.

    Returns:
        The populated plan.
    """
    following_by_id = {user.id: user for user in following}
    member_ids = {user.id for user in members}

    to_add = [user for user in following if user.id not in member_ids]
    stale = [user for user in members if user.id not in following_by_id]
    unchanged = len(following_by_id) - len(to_add)

    logger.info(
        "plan: %d to add, %d stale, %d unchanged, following_complete=%s",
        len(to_add),
        len(stale),
        unchanged,
        following_complete,
    )
    return SyncPlan(
        to_add=to_add,
        stale=stale,
        unchanged=max(unchanged, 0),
        following_complete=following_complete,
    )


def estimate_cost(
    following_count: int,
    member_count: int,
    write_ops: int,
    create_ops: int = 0,
) -> CostEstimate:
    """Approximate what a run will cost in API charges.

    Args:
        following_count: Accounts expected from the following read.
        member_count: Accounts expected from the List members read.
        write_ops: Membership changes expected.
        create_ops: List creations expected.

    Returns:
        The estimate. Treat it as indicative: the per-write price is inferred
        from the pricing docs' "List: Manage" line rather than published for
        these endpoints specifically.
    """
    return CostEstimate(
        read_resources=following_count + member_count,
        write_ops=write_ops,
        create_ops=create_ops,
    )


def resolve_list(
    client: XClient,
    user_id: str,
    list_id: str | None,
    list_name: str,
    description: str,
    private: bool,
    dry_run: bool,
) -> tuple[str, bool]:
    """Find the target List, creating it when necessary.

    Args:
        client: The API client.
        user_id: The authenticated account's id.
        list_id: An explicit List id, which short-circuits the lookup.
        list_name: The List name to match or create.
        description: Description to use when creating.
        private: Visibility to use when creating.
        dry_run: When True, report that creation is needed but do not create.

    Returns:
        A tuple of (list id, created). The id is empty only under `dry_run`
        when the List does not exist yet.
    """
    if list_id:
        logger.debug("using explicit list id %s", list_id)
        return list_id, False

    for entry in client.get_owned_lists(user_id):
        if str(entry.get("name", "")) == list_name:
            found = str(entry.get("id", ""))
            logger.info("matched existing list %r -> %s", list_name, found)
            return found, False

    if dry_run:
        logger.info("list %r does not exist; would create it", list_name)
        return "", True

    return client.create_list(list_name, description, private), True


def apply_plan(
    client: XClient,
    list_id: str,
    plan: SyncPlan,
    console: Console,
    prune: bool,
    dry_run: bool,
    checkpoint: Callable[[SyncResult], None] | None = None,
    max_adds: int | None = None,
) -> SyncResult:
    """Carry out a plan against the List.

    Additions always run. Removals run only when `prune` is set *and* the plan
    permits it, so a truncated following fetch cannot cause deletions no matter
    what flags were passed.

    Args:
        client: The API client.
        list_id: The target List.
        plan: The plan to apply.
        console: Console for the progress display.
        prune: Whether the caller asked for stale members to be removed.
        dry_run: When True, make no requests at all.
        checkpoint: Optional callback invoked periodically with the partial
            result, so an interrupted run can be resumed. Taking a callback
            rather than a path keeps this function free of state-file layout.
        max_adds: Stop after adding this many members, recording the remainder
            as pending. None adds everything the plan calls for.

    Returns:
        What happened, including anything left pending.

    Raises:
        KeyboardInterrupt: Re-raised after the partial result is checkpointed,
            so an interrupt still reaches `main` and reports as one.
    """
    result = SyncResult()

    if dry_run:
        logger.info("dry run: no changes will be made")
        return result

    to_add = plan.to_add
    if max_adds is not None and len(to_add) > max_adds:
        # Deferred, not dropped: the remainder is pending so --resume finishes
        # it on a later day, which is the point of rationing the adds at all.
        deferred = to_add[max_adds:]
        to_add = to_add[:max_adds]
        result.pending.extend(deferred)
        logger.info(
            "limiting this run to %d add(s); %d deferred by --max-adds",
            len(to_add),
            len(deferred),
        )

    if to_add:
        _run_pass(
            client=client,
            users=to_add,
            description=f"Adding {len(to_add)} member(s)",
            action=lambda user: client.add_list_member(list_id, user.id),
            verb="add",
            # A 200 reporting is_member false means the API accepted the call
            # but declined the membership; protected and suspended accounts
            # land here, which is expected rather than a failure.
            on_declined=result.skipped,
            console=console,
            result=result,
            checkpoint=checkpoint,
        )

    if not plan.stale:
        return result

    if not prune:
        logger.info("%d stale member(s) left in place (--prune not given)", len(plan.stale))
        return result

    if not plan.prune_allowed:
        # The guard that matters: an incomplete read makes every member look
        # stale, so refuse rather than delete.
        logger.warning("refusing to prune: the following fetch was incomplete")
        result.errors.append(
            "pruning skipped: the following list came back incomplete, so members "
            "that look stale may simply be missing from the fetch"
        )
        return result

    _run_pass(
        client=client,
        users=plan.stale,
        description=f"Removing {len(plan.stale)} member(s)",
        action=lambda user: client.remove_list_member(list_id, user.id),
        verb="remove",
        # A removal that leaves the account a member is a real failure, unlike
        # a declined add, so there is no separate bucket for it.
        on_declined=None,
        console=console,
        result=result,
        checkpoint=checkpoint,
    )

    return result


def _run_pass(
    client: XClient,
    users: list[XUser],
    description: str,
    action: Callable[[XUser], bool],
    verb: str,
    on_declined: list[XUser] | None,
    console: Console,
    result: SyncResult,
    checkpoint: Callable[[SyncResult], None] | None,
) -> None:
    """Apply one membership action across a set of accounts.

    The add and remove passes differ only in which API call they make and how
    they read a refusal, so they share this loop rather than duplicating the
    rate-limit, checkpoint, and interrupt handling twice.

    Args:
        client: The API client, wired to the progress display for the duration.
        users: The accounts to process, in order.
        description: Progress bar label.
        action: The call to make per account, returning whether it took effect.
        verb: Word for log messages, e.g. "add".
        on_declined: Bucket for accounts the API declined without erroring, or
            None to treat a decline as a failure.
        console: Console for the progress display.
        result: Accumulates outcomes; mutated in place.
        checkpoint: Optional periodic save callback.

    Raises:
        KeyboardInterrupt: Re-raised once the partial result is recorded.
    """
    succeeded = result.added if verb == "add" else result.removed

    with _progress(console) as progress:
        task = progress.add_task(description, total=len(users))
        # Give the client somewhere to announce its sleeps for the life of this
        # pass, so a rate-limit wait shows up on the bar instead of freezing it.
        client.waiter = WaitReporter(progress, task, description)
        try:
            for index, user in enumerate(users):
                try:
                    if action(user):
                        succeeded.append(user)
                    elif on_declined is not None:
                        on_declined.append(user)
                        logger.info("%s was declined by the API (%s)", user.handle, verb)
                    else:
                        result.failed.append(user)
                        result.errors.append(f"{user.handle}: still a member after removal")
                except RateLimitError as exc:
                    # Not a failure: the work is deferred. Recording it as
                    # pending is what lets --resume finish the job.
                    result.pending.extend(users[index:])
                    result.errors.append(str(exc))
                    logger.warning("stopping the %s pass: %s", verb, exc)
                    break
                except SyncError as exc:
                    result.failed.append(user)
                    result.errors.append(f"{user.handle}: {exc}")
                    logger.warning("failed to %s %s: %s", verb, user.handle, exc)
                except KeyboardInterrupt:
                    # Whatever is left, including the account in flight, is
                    # unfinished rather than failed.
                    result.pending.extend(users[index:])
                    if checkpoint:
                        checkpoint(result)
                    raise
                finally:
                    progress.advance(task)

                if checkpoint and (index + 1) % CHECKPOINT_EVERY == 0:
                    checkpoint(result)
        finally:
            client.waiter = None

    if checkpoint:
        checkpoint(result)


def _progress(console: Console) -> Progress:
    """Build the progress display used for add and remove passes.

    Args:
        console: The console to draw on.

    Returns:
        A configured `Progress` context manager.
    """
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )


def load_state(path: Path) -> dict[str, Any]:
    """Read the persisted state file.

    Args:
        path: Location of the state file.

    Returns:
        The decoded state, or an empty dict when absent or unreadable.
    """
    try:
        with path.open(encoding="utf-8") as handle:
            state = json.load(handle)
    except FileNotFoundError:
        logger.debug("no state file at %s", path)
        return {}
    except (OSError, ValueError) as exc:
        # Corrupt state is not worth failing a run over; it is only a cache.
        logger.warning("ignoring unreadable state file %s: %s", path, exc)
        return {}

    return state if isinstance(state, dict) else {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    """Write the state file, creating its directory as needed.

    Args:
        path: Location of the state file.
        state: The state to persist.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
    except OSError as exc:
        # Losing the checkpoint degrades --resume but does not invalidate the
        # work already done, so warn rather than fail.
        logger.warning("could not write state file %s: %s", path, exc)


def render_plan(
    console: Console,
    plan: SyncPlan,
    estimate: CostEstimate,
    prune: bool,
    max_adds: int | None = None,
) -> None:
    """Print the plan and its estimated cost.

    Args:
        console: The console to print to.
        plan: The plan to describe.
        estimate: The cost estimate for carrying it out.
        prune: Whether removals were requested.
        max_adds: The per-run add limit, if one was given.
    """
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="dim", no_wrap=True)
    table.add_column(overflow="fold")

    if max_adds is not None and len(plan.to_add) > max_adds:
        deferred = len(plan.to_add) - max_adds
        note = f"of {len(plan.to_add)}, limited by --max-adds"
        table.add_row("to add", _annotated(max_adds, note))
        table.add_row("deferred", _annotated(deferred, "re-run with --resume to continue"))
    else:
        table.add_row("to add", str(len(plan.to_add)))
    table.add_row("already present", str(plan.unchanged))

    if prune and plan.prune_allowed:
        table.add_row("to remove", str(len(plan.stale)))
    elif plan.stale:
        reason = "--prune not given" if not prune else "following fetch incomplete"
        table.add_row("stale (kept)", _annotated(len(plan.stale), reason))

    if not plan.following_complete:
        table.add_row("", render_severity("warning", "the following list came back incomplete"))

    table.add_row("", "")
    table.add_row(
        "est. cost",
        f"~${estimate.dollars:.2f}  "
        f"({estimate.read_resources} reads, {estimate.write_ops} writes)",
    )
    table.add_row("", Text("approximate; write pricing is inferred from the docs", style="dim"))

    console.print(Panel(table, title="Sync plan", title_align="left", border_style="cyan"))


def _annotated(count: int, note: str) -> Text:
    """Render a count beside a dim parenthetical note.

    Built as `Text` rather than a markup string because the notes contain
    square brackets and flag names, which rich would otherwise try to parse as
    style tags and silently swallow.

    Args:
        count: The number to show.
        note: Explanatory text shown dimmed alongside it.

    Returns:
        Styled `Text` ready to place in a table cell.
    """
    text = Text(str(count))
    text.append(f"  ({note})", style="dim")
    return text


def render_severity(severity: str, message: str) -> Text:
    """Format a message with its severity marker.

    Args:
        severity: One of the keys in `SEVERITY_STYLES`.
        message: The text to show.

    Returns:
        Styled `Text` ready to print.
    """
    style, marker = SEVERITY_STYLES.get(severity, ("white", "•"))
    text = Text()
    text.append(f"{marker} ", style=style)
    text.append(message, style=style)
    return text


def render_result(
    console: Console,
    result: SyncResult,
    plan: SyncPlan,
    verbose: bool = False,
) -> None:
    """Print the outcome of a sync.

    Args:
        console: The console to print to.
        result: What happened.
        plan: The plan that was applied, for context on skipped removals.
        verbose: List every affected account rather than a sample.
    """
    table = Table(
        title="Sync result",
        title_justify="left",
        header_style="bold",
        expand=True,
    )
    table.add_column("Outcome", no_wrap=True)
    table.add_column("Count", justify="right", no_wrap=True)
    # Under --verbose the full handle list must wrap rather than be cut off,
    # since listing everything is the whole point of the flag.
    table.add_column("Accounts", ratio=1, overflow="fold" if verbose else "ellipsis")

    rows = (
        ("added", result.added, "green"),
        ("removed", result.removed, "yellow"),
        ("skipped", result.skipped, "dim"),
        ("failed", result.failed, "red"),
        ("pending", result.pending, "red"),
    )
    for label, users, style in rows:
        if not users:
            continue
        if verbose:
            sample = ", ".join(user.handle for user in users)
        else:
            sample = ", ".join(user.handle for user in users[:8])
            if len(users) > 8:
                sample += f", ... (+{len(users) - 8})"
        table.add_row(label, str(len(users)), sample, style=style)

    if not any(users for _, users, _ in rows):
        table.add_row("no changes", "0", "the list already matches your following set")

    console.print(table)

    if plan.stale and not plan.prune_allowed:
        console.print(
            render_severity(
                "warning",
                f"{len(plan.stale)} member(s) look stale but were kept: the following "
                "fetch was incomplete, so they may be false positives.",
            )
        )

    for message in result.errors:
        console.print(render_severity("error", message))


def plan_to_dict(plan: SyncPlan, estimate: CostEstimate) -> dict[str, Any]:
    """Convert a plan and its estimate into JSON-serializable form.

    Args:
        plan: The plan.
        estimate: Its cost estimate.

    Returns:
        A dictionary suitable for `json.dumps`.
    """
    return {
        "to_add": [{"id": u.id, "username": u.username, "name": u.name} for u in plan.to_add],
        "stale": [{"id": u.id, "username": u.username, "name": u.name} for u in plan.stale],
        "unchanged": plan.unchanged,
        "following_complete": plan.following_complete,
        "prune_allowed": plan.prune_allowed,
        "estimated_cost_usd": round(estimate.dollars, 4),
        "estimated_read_resources": estimate.read_resources,
        "estimated_write_ops": estimate.write_ops,
    }


def result_to_dict(result: SyncResult) -> dict[str, Any]:
    """Convert a sync result into JSON-serializable form.

    Args:
        result: The result to serialize.

    Returns:
        A dictionary suitable for `json.dumps`.
    """
    return {
        "added": [u.id for u in result.added],
        "removed": [u.id for u in result.removed],
        "skipped": [u.id for u in result.skipped],
        "failed": [u.id for u in result.failed],
        "pending": [u.id for u in result.pending],
        "errors": result.errors,
    }


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser.

    Returns:
        The configured `ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        description="Mirror the accounts you follow on X into one of your X Lists.",
    )
    parser.add_argument(
        "--list-id",
        default=None,
        help="Sync into this List id, skipping the lookup by name.",
    )
    parser.add_argument(
        "--list-name",
        default="Following",
        help="List to resolve or create by name (default: Following).",
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        help="Also remove members you no longer follow. Off by default.",
    )
    visibility = parser.add_mutually_exclusive_group()
    visibility.add_argument(
        "--private",
        action="store_true",
        default=True,
        help="Create the List as private (default).",
    )
    visibility.add_argument(
        "--public",
        action="store_false",
        dest="private",
        help="Create the List as public.",
    )
    parser.add_argument(
        "--description",
        default="Accounts I follow, synced automatically.",
        help="Description to use when creating the List.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the plan and estimated cost without making any changes.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the cost confirmation prompt.",
    )
    parser.add_argument(
        "--max-wait",
        type=float,
        default=900.0,
        help="Longest to sleep through a rate-limit window, in seconds (default: 900).",
    )
    parser.add_argument(
        "--max-adds",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Add at most N members this run, then stop and record the rest as "
            "pending. Use it to spread a large first sync across several days, "
            "since the write endpoints enforce an undocumented 24-hour cap well "
            "below the published 300/15min. Re-run with --resume to continue."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Continue a previous rate-limited run without re-confirming the cost. "
            "The work itself is recomputed from the live list, not replayed."
        ),
    )
    parser.add_argument(
        "--credentials-file",
        type=Path,
        default=DEFAULT_CREDENTIALS_FILE,
        help=f"JSON file holding the OAuth 1.0a credentials (default: {DEFAULT_CREDENTIALS_FILE}).",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=DEFAULT_STATE_FILE,
        help=f"Where to keep resolved ids and pending work (default: {DEFAULT_STATE_FILE}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of a formatted report.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include every affected account in the report.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING).",
    )
    return parser


def run_sync(
    args: argparse.Namespace,
    console: Console,
) -> tuple[SyncPlan, SyncResult, CostEstimate, int]:
    """Execute the whole sync and report what happened.

    Args:
        args: Parsed command-line arguments.
        console: Console for status output.

    Returns:
        A tuple of (plan, result, estimate, exit code).

    Raises:
        SyncError: On any failure that should abort the run.
    """
    credentials = load_credentials(args.credentials_file.expanduser())
    client = XClient(credentials, max_wait=args.max_wait)
    state = load_state(args.state_file)

    me = client.get_me()
    console.print(render_severity("ok", f"authenticated as {me.handle}"))

    # Cheapest possible check that the endpoint is usable, before any bulk read.
    client.probe_following_access(me.id)

    list_id, would_create = resolve_list(
        client,
        me.id,
        args.list_id,
        args.list_name,
        args.description,
        args.private,
        args.dry_run,
    )

    following, following_complete = client.get_following(me.id)

    # A List that does not exist yet has no members, and asking for them with
    # an empty id would 404.
    if list_id:
        members, _ = client.get_list_members(list_id)
    else:
        members = []

    plan = build_plan(following, members, following_complete)

    # Only writes that will actually run should be priced in, which means
    # respecting --max-adds as well as the prune guard.
    planned_adds = len(plan.to_add)
    if args.max_adds is not None:
        planned_adds = min(planned_adds, args.max_adds)
    write_ops = planned_adds
    if args.prune and plan.prune_allowed:
        write_ops += len(plan.stale)
    estimate = estimate_cost(
        len(following),
        len(members),
        write_ops,
        create_ops=1 if would_create else 0,
    )

    if not args.as_json:
        render_plan(console, plan, estimate, args.prune, args.max_adds)

    if plan.is_empty:
        logger.info("nothing to do")
        return plan, SyncResult(), estimate, 0

    # --resume continues work the user already approved, so it does not ask
    # again. The pending queue is not replayed: the diff above was computed
    # from the live List, so anything left unfinished is already in `to_add`.
    previous_pending = (state.get(list_id or args.list_name, {}) or {}).get("pending") or []
    if args.resume and previous_pending:
        logger.info("resuming; %d account(s) were pending", len(previous_pending))

    if not args.dry_run and not args.yes and not args.resume and not args.as_json:
        if not _confirm(console, estimate):
            console.print(render_severity("note", "aborted, nothing was changed"))
            return plan, SyncResult(), estimate, 0

    def checkpoint(partial: SyncResult) -> None:
        """Persist progress so an interrupted run can be resumed.

        Args:
            partial: The result so far.
        """
        entry = state.setdefault(list_id or args.list_name, {})
        entry["list_id"] = list_id
        entry["list_name"] = args.list_name
        entry["last_sync"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        entry["pending"] = [u.id for u in partial.pending]
        save_state(args.state_file, state)

    result = apply_plan(
        client,
        list_id,
        plan,
        console,
        args.prune,
        args.dry_run,
        checkpoint=None if args.dry_run else checkpoint,
        max_adds=args.max_adds,
    )

    exit_code = 0 if (result.is_clean and following_complete) else 1
    return plan, result, estimate, exit_code


def _confirm(console: Console, estimate: CostEstimate) -> bool:
    """Ask the user to approve the estimated spend.

    Args:
        console: Console to prompt on.
        estimate: The cost estimate to quote.

    Returns:
        True if the user approved, False otherwise. A non-interactive stdin
        counts as approval refused, so an unattended run must pass --yes.
    """
    if not sys.stdin.isatty():
        logger.warning("stdin is not a terminal; pass --yes to run unattended")
        return False

    console.print(f"\nThis run will cost roughly [bold]${estimate.dollars:.2f}[/bold].")
    try:
        answer = input("Proceed? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def main() -> int:
    """Run the follower-to-List sync.

    Returns:
        Process exit code: 0 on a complete sync, 1 when work was left
        unfinished, 2 on a configuration or access failure.
    """
    args = build_parser().parse_args()

    # JSON output must stay clean, so send status to stderr when it is on.
    console = Console(stderr=args.as_json)

    # Route logging through rich on the same console the progress bar uses.
    # A bare StreamHandler writes straight past the live display and corrupts
    # it; RichHandler prints above the bar instead.
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    logger.debug("starting with prune=%s, dry_run=%s", args.prune, args.dry_run)

    if args.max_adds is not None and args.max_adds < 1:
        console.print(render_severity("error", "--max-adds must be at least 1"))
        return 2

    try:
        plan, result, estimate, exit_code = run_sync(args, console)
    except (AuthError, AccessError) as exc:
        console.print(render_severity("error", str(exc)))
        return 2
    except DailyCapError as exc:
        # Distinct from a generic failure: nothing is wrong, the allowance is
        # simply spent, so say when to come back rather than printing an error.
        console.print(render_severity("warning", str(exc)))
        return 1
    except SyncError as exc:
        console.print(render_severity("error", str(exc)))
        return 1
    except KeyboardInterrupt:
        console.print(render_severity("note", "interrupted"))
        return 1

    if args.as_json:
        print(
            json.dumps(
                {"plan": plan_to_dict(plan, estimate), "result": result_to_dict(result)},
                indent=2,
            )
        )
    else:
        out = Console()
        out.print()
        render_result(out, result, plan, args.verbose)
        out.print()

    logger.debug("returning exit code %d", exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
