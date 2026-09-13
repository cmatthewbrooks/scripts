#!/usr/bin/env python3
"""Audit $PATH entries and report where each one likely originates.

Helps clean up an accumulated PATH by showing, for every entry: whether the
directory still exists, whether it is a duplicate, how many executables it
contributes, and which config file (or `path_helper` source) most likely
added it.

Typical usage::

    ./path_audit.py                # audit the inherited $PATH
    ./path_audit.py --problems     # only show entries worth cleaning up
    ./path_audit.py --json         # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# `X | Y` type unions in annotations evaluated at runtime by dataclasses, plus
# the modern `list[str]` builtin generics, require Python 3.10+.
if sys.version_info < (3, 10):
    sys.exit("error: python 3.10 or newer is required")

logger = logging.getLogger(__name__)

# macOS `path_helper` seeds PATH from these before any shell rc file runs.
SYSTEM_PATH_FILES: tuple[Path, ...] = (Path("/etc/paths"),)
SYSTEM_PATH_DIRS: tuple[Path, ...] = (Path("/etc/paths.d"),)

# Shell config files scanned for PATH assignments, in rough load order. Each
# entry is (path, description) so reports can name the file meaningfully.
SHELL_CONFIG_FILES: tuple[tuple[str, str], ...] = (
    ("/etc/zshenv", "system zsh env"),
    ("/etc/zprofile", "system zsh profile"),
    ("/etc/zshrc", "system zsh rc"),
    ("/etc/profile", "system sh profile"),
    ("/etc/bashrc", "system bash rc"),
    ("~/.zshenv", "user zsh env"),
    ("~/.zprofile", "user zsh profile"),
    ("~/.zshrc", "user zsh rc"),
    ("~/.zlogin", "user zsh login"),
    ("~/.profile", "user sh profile"),
    ("~/.bash_profile", "user bash profile"),
    ("~/.bashrc", "user bash rc"),
    ("~/.config/zsh/.zshrc", "user zsh rc (XDG)"),
)

# Directories whose *.zsh / *.sh fragments are commonly sourced by rc files.
SHELL_CONFIG_GLOBS: tuple[tuple[str, str, str], ...] = (
    ("~/.oh-my-zsh/custom", "**/*.zsh", "oh-my-zsh custom"),
    ("~/.zshrc.d", "*", "zshrc.d fragment"),
    ("~/.config/zsh/conf.d", "*", "zsh conf.d fragment"),
)

# Well-known tools that inject PATH entries at shell-init time. These are
# matched against the PATH entry itself, as a fallback when no config file
# textually mentions the directory.
KNOWN_TOOL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/\.pyenv/", "pyenv shim/version dir (pyenv init)"),
    (r"/\.rbenv/", "rbenv shim/version dir (rbenv init)"),
    (r"/\.nodenv/", "nodenv shim/version dir (nodenv init)"),
    (r"/\.nvm/", "nvm-managed node version"),
    (r"/\.cargo/bin", "rustup/cargo installer"),
    (r"/\.rustup/", "rustup toolchain"),
    (r"/\.local/bin", "PEP 370 user install dir (pipx, uv, pip --user)"),
    (r"/\.bun/bin", "bun installer"),
    (r"/\.deno/bin", "deno installer"),
    (r"/\.krew/bin", "kubectl krew plugin manager"),
    (r"/\.poetry/bin", "poetry installer"),
    (r"/\.orbstack/bin", "OrbStack"),
    (r"/\.docker/bin", "Docker Desktop"),
    (r"/google-cloud-sdk/", "Google Cloud SDK installer"),
    (r"/\.gem/", "RubyGems user install dir"),
    (r"/go/bin", "Go workspace bin (GOPATH/GOBIN)"),
    (r"^/opt/homebrew/", "Homebrew (Apple Silicon) via brew shellenv"),
    (r"^/usr/local/(bin|sbin)", "Homebrew (Intel) or manual /usr/local install"),
    (r"^/opt/local/", "MacPorts"),
    (r"/Library/Frameworks/Python\.framework/", "python.org Python installer"),
    (r"/Applications/", "an installed macOS application"),
    (r"/\.vscode/", "VS Code"),
    (r"/Postgres\.app/", "Postgres.app"),
    (r"/\.fzf/bin", "fzf installer"),
    (r"/\.antigen|/\.oh-my-zsh", "oh-my-zsh / zsh plugin manager"),
)

# Any line that plausibly assigns to PATH. Covers `export PATH=...`,
# `PATH=...`, `path+=(...)`, `setenv PATH ...`, and `export PATH="$PATH:x"`.
PATH_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+|setenv\s+|typeset\s+-\w+\s+)?"
    r"(?:PATH|path)\s*(?:\+?=|\s)",
)


@dataclass
class Origin:
    """A single guess at where a PATH entry came from.

    Attributes:
        source: Human-readable name of the file or mechanism.
        detail: Extra context, such as the matching line or line number.
        confidence: One of "exact", "likely", or "guess".
    """

    source: str
    detail: str = ""
    confidence: str = "likely"


@dataclass
class PathEntry:
    """One directory from $PATH, plus everything we learned about it.

    Attributes:
        raw: The entry exactly as it appeared in $PATH.
        index: Zero-based position within $PATH.
        exists: Whether the directory exists on disk.
        is_dir: Whether the entry resolves to a directory.
        executables: Count of executable files directly inside it.
        duplicate_of: Index of the earlier identical entry, if any.
        shadowed_by: Indexes of earlier entries providing the same commands.
        origins: Ranked guesses at what added this entry.
    """

    raw: str
    index: int
    exists: bool = False
    is_dir: bool = False
    executables: int = 0
    duplicate_of: int | None = None
    shadowed_by: list[int] = field(default_factory=list)
    origins: list[Origin] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        """Summarize why this entry might deserve cleanup.

        Returns:
            A list of short problem labels; empty if the entry looks healthy.
        """
        issues: list[str] = []
        if not self.raw:
            issues.append("empty entry (means current directory - security risk)")
        elif not self.exists:
            issues.append("does not exist")
        elif not self.is_dir:
            issues.append("not a directory")
        elif self.executables == 0:
            issues.append("no executables")
        if self.duplicate_of is not None:
            issues.append(f"duplicate of entry #{self.duplicate_of + 1}")
        if self.shadowed_by:
            shadowers = ", ".join(f"#{i + 1}" for i in self.shadowed_by)
            issues.append(f"all commands shadowed by {shadowers}")
        return issues


def read_system_path_entries() -> dict[str, str]:
    """Collect PATH entries seeded by macOS `path_helper`.

    Reads /etc/paths and every file in /etc/paths.d, which `path_helper`
    concatenates to build the base PATH for login shells.

    Returns:
        A mapping of directory string to the file that declared it.
    """
    logger.debug("reading system path files: %s, %s", SYSTEM_PATH_FILES, SYSTEM_PATH_DIRS)
    entries: dict[str, str] = {}

    candidates: list[Path] = list(SYSTEM_PATH_FILES)
    for directory in SYSTEM_PATH_DIRS:
        if directory.is_dir():
            candidates.extend(sorted(p for p in directory.iterdir() if p.is_file()))

    for candidate in candidates:
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            logger.warning("could not read %s: %s", candidate, exc)
            continue
        for line in lines:
            entry = line.strip()
            # path_helper ignores blank lines; it has no comment syntax, but
            # skipping '#' lines avoids noise from hand-edited files.
            if entry and not entry.startswith("#"):
                entries.setdefault(entry, str(candidate))

    logger.debug("found %d system path entries", len(entries))
    return entries


def iter_config_files() -> list[tuple[Path, str]]:
    """Build the list of shell config files to scan.

    Returns:
        A list of (resolved path, description) pairs for files that exist.
    """
    logger.debug("building shell config file list")
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    for raw_path, description in SHELL_CONFIG_FILES:
        path = Path(raw_path).expanduser()
        if path.is_file() and path not in seen:
            seen.add(path)
            found.append((path, description))

    for raw_dir, pattern, description in SHELL_CONFIG_GLOBS:
        directory = Path(raw_dir).expanduser()
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                found.append((path, description))

    logger.debug("scanning %d shell config files", len(found))
    return found


def scan_config_files() -> list[tuple[Path, str, int, str]]:
    """Extract every PATH-related line from the shell config files.

    Returns:
        A list of (file path, description, line number, line text) tuples.
    """
    logger.debug("scanning config files for PATH assignments")
    hits: list[tuple[Path, str, int, str]] = []

    for path, description in iter_config_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("could not read %s: %s", path, exc)
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Keep any line that assigns PATH, or that merely mentions PATH
            # (e.g. `eval "$(brew shellenv)"` won't match, but a directory
            # literal appearing anywhere still helps attribute an entry).
            if PATH_ASSIGNMENT_RE.search(line) or "PATH" in line:
                hits.append((path, description, lineno, stripped))

    logger.debug("found %d candidate PATH lines in config files", len(hits))
    return hits


def expand_for_match(entry: str) -> list[str]:
    """Produce string variants of a PATH entry to search config text for.

    A config file may write `$HOME/bin`, `~/bin`, or `/Users/me/bin` for the
    same directory, so we search for all of them.

    Args:
        entry: A single PATH directory.

    Returns:
        A list of candidate substrings to grep for, longest first.
    """
    home = str(Path.home())
    variants = {entry}

    if entry.startswith(home):
        suffix = entry[len(home):]
        variants.update({f"~{suffix}", f"$HOME{suffix}", f"${{HOME}}{suffix}"})

    return sorted(variants, key=len, reverse=True)


def mentions_path(line: str, candidate: str) -> str | None:
    """Check whether a config line refers to a path as a whole token.

    A plain substring test is far too loose: `/bin` occurs inside almost any
    path literal, and `/usr/local/bin` would match `~/.local/bin`. The match
    must therefore start and end at a path component boundary.

    Args:
        line: A line of shell config text.
        candidate: The path string to look for.

    Returns:
        "exact" if the line names this path, "likely" if it names a
        subdirectory of it, or None if it does not reference it at all.
    """
    best: str | None = None
    for match in re.finditer(re.escape(candidate), line):
        before = line[match.start() - 1] if match.start() > 0 else ""
        after = line[match.end()] if match.end() < len(line) else ""
        # `/` or a word character before the match means we matched the tail
        # of a longer path (e.g. `/bin` inside `/usr/local/bin`), which is
        # not evidence for this entry at all.
        if before and (before == "/" or before.isalnum() or before in "._-~$"):
            continue
        # A continuation within the same component likewise means a
        # different, longer path (e.g. `/bin` inside `/bin-extra`).
        if after and (after.isalnum() or after in "._-"):
            continue
        # A trailing `/` means the line names a subdirectory of this entry.
        # That still hints at the same installer, but it is weaker evidence.
        if after == "/":
            best = best or "likely"
            continue
        return "exact"
    return best


def attribute_entry(
    entry: str,
    system_entries: dict[str, str],
    config_hits: list[tuple[Path, str, int, str]],
) -> list[Origin]:
    """Determine the most likely origins of a single PATH entry.

    Checks, in order: macOS `path_helper` files, literal mentions in shell
    config files, and finally a pattern match against well-known installers.

    Args:
        entry: The PATH directory to attribute.
        system_entries: Mapping from `read_system_path_entries`.
        config_hits: Scanned config lines from `scan_config_files`.

    Returns:
        A ranked list of `Origin` objects; empty if nothing matched.
    """
    logger.debug("attributing PATH entry: %s", entry)
    origins: list[Origin] = []

    if entry in system_entries:
        origins.append(
            Origin(
                source=system_entries[entry],
                detail="listed for macOS path_helper",
                confidence="exact",
            )
        )

    variants = expand_for_match(entry)
    for path, description, lineno, line in config_hits:
        confidence = next(
            (c for c in (mentions_path(line, v) for v in variants) if c is not None),
            None,
        )
        if confidence is None:
            continue
        origins.append(
            Origin(
                source=f"{path}:{lineno}",
                detail=f"[{description}] {line}",
                confidence=confidence,
            )
        )

    if not origins:
        for pattern, description in KNOWN_TOOL_PATTERNS:
            if re.search(pattern, entry):
                origins.append(
                    Origin(source=description, detail="inferred from path shape", confidence="guess")
                )
                break

    logger.debug("found %d origin(s) for %s", len(origins), entry)
    return origins


def count_executables(directory: Path) -> int:
    """Count executable files directly inside a directory.

    Args:
        directory: The directory to inspect.

    Returns:
        The number of entries that are executable by the current user.
    """
    try:
        return sum(1 for p in directory.iterdir() if os.access(p, os.X_OK) and not p.is_dir())
    except OSError as exc:
        logger.warning("could not list %s: %s", directory, exc)
        return 0


def command_names(directory: Path) -> set[str]:
    """List the names of executables directly inside a directory.

    Args:
        directory: The directory to inspect.

    Returns:
        A set of executable file names, empty if the directory is unreadable.
    """
    try:
        return {p.name for p in directory.iterdir() if os.access(p, os.X_OK) and not p.is_dir()}
    except OSError:
        return set()


def analyze_path(path_value: str) -> list[PathEntry]:
    """Analyze a PATH string end to end.

    Args:
        path_value: The raw PATH string, colon-separated.

    Returns:
        A list of fully populated `PathEntry` objects, in PATH order.
    """
    logger.debug("analyzing PATH with %d characters", len(path_value))
    system_entries = read_system_path_entries()
    config_hits = scan_config_files()

    raw_entries = path_value.split(os.pathsep)
    results: list[PathEntry] = []
    seen: dict[str, int] = {}
    commands_so_far: dict[str, int] = {}

    for index, raw in enumerate(raw_entries):
        entry = PathEntry(raw=raw, index=index)

        if raw in seen:
            entry.duplicate_of = seen[raw]
        else:
            seen[raw] = index

        if raw:
            directory = Path(raw)
            entry.exists = directory.exists()
            entry.is_dir = directory.is_dir()
            if entry.is_dir:
                names = command_names(directory)
                entry.executables = len(names)
                # An entry is fully shadowed when every command it offers is
                # already provided by an earlier entry, making it dead weight.
                if names and entry.duplicate_of is None:
                    if all(n in commands_so_far for n in names):
                        entry.shadowed_by = sorted({commands_so_far[n] for n in names})
                for name in names:
                    commands_so_far.setdefault(name, index)

            entry.origins = attribute_entry(raw, system_entries, config_hits)

        results.append(entry)

    logger.info("analyzed %d PATH entries", len(results))
    return results


def format_report(entries: list[PathEntry], problems_only: bool, verbose: bool) -> str:
    """Render the analysis as human-readable text.

    Args:
        entries: Analyzed PATH entries.
        problems_only: Show only entries that have problems.
        verbose: Include every matching origin rather than the top three.

    Returns:
        The formatted report as a single string.
    """
    logger.debug("formatting report for %d entries", len(entries))
    lines: list[str] = []
    shown = 0

    for entry in entries:
        issues = entry.problems
        if problems_only and not issues:
            continue
        shown += 1

        marker = "!" if issues else " "
        label = entry.raw or "(empty)"
        lines.append(f"{marker} #{entry.index + 1:<3} {label}")

        if entry.raw:
            status = "exists" if entry.exists else "MISSING"
            lines.append(f"      status: {status}, {entry.executables} executable(s)")

        for issue in issues:
            lines.append(f"      problem: {issue}")

        origins = entry.origins if verbose else entry.origins[:3]
        if origins:
            for origin in origins:
                lines.append(f"      from ({origin.confidence}): {origin.source}")
                if origin.detail:
                    lines.append(f"            {origin.detail}")
            hidden = len(entry.origins) - len(origins)
            if hidden > 0:
                lines.append(f"      ... {hidden} more match(es), use --verbose")
        elif entry.raw:
            lines.append("      from: unknown (not found in any scanned config)")

        lines.append("")

    total_issues = sum(1 for e in entries if e.problems)
    header = [
        f"PATH entries: {len(entries)}   with problems: {total_issues}   shown: {shown}",
        "=" * 72,
        "",
    ]
    return "\n".join(header + lines)


def entries_to_dicts(entries: list[PathEntry]) -> list[dict[str, object]]:
    """Convert analyzed entries into JSON-serializable dictionaries.

    Args:
        entries: Analyzed PATH entries.

    Returns:
        A list of plain dictionaries suitable for `json.dumps`.
    """
    logger.debug("serializing %d entries to dicts", len(entries))
    return [
        {
            "index": e.index,
            "path": e.raw,
            "exists": e.exists,
            "is_dir": e.is_dir,
            "executables": e.executables,
            "duplicate_of": e.duplicate_of,
            "shadowed_by": e.shadowed_by,
            "problems": e.problems,
            "origins": [
                {"source": o.source, "detail": o.detail, "confidence": o.confidence}
                for o in e.origins
            ],
        }
        for e in entries
    ]


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser.

    Returns:
        The configured `ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        description="Report where each $PATH entry originates, to help clean up PATH.",
    )
    parser.add_argument(
        "--path",
        default=None,
        help="PATH string to analyze (default: the inherited $PATH).",
    )
    parser.add_argument(
        "--problems",
        action="store_true",
        help="Only show entries that are missing, empty, duplicated, or shadowed.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON instead of a text report.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show every matching config line, not just the first few.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING).",
    )
    return parser


def main() -> int:
    """Run the PATH audit.

    Returns:
        Process exit code: 0 if no problems were found, 1 otherwise.
    """
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.debug("starting with problems_only=%s, as_json=%s", args.problems, args.as_json)

    path_value = args.path if args.path is not None else os.environ.get("PATH", "")
    if not path_value:
        logger.error("PATH is empty or unset; nothing to audit")
        return 1

    entries = analyze_path(path_value)

    if args.as_json:
        print(json.dumps(entries_to_dicts(entries), indent=2))
    else:
        print(format_report(entries, args.problems, args.verbose))

    problem_count = sum(1 for e in entries if e.problems)
    logger.debug("returning exit code based on %d problem entries", problem_count)
    return 1 if problem_count else 0


if __name__ == "__main__":
    sys.exit(main())
