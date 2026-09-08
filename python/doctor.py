#!/usr/bin/env python3
"""Diagnose the Python installations on this machine, `brew doctor` style.

Discovers every Python interpreter reachable from $PATH, from well-known
install locations (Homebrew, python.org frameworks, Xcode/CLT, pyenv, uv,
conda, MacPorts), and from the active virtualenv, then reports how each one
is configured and which of them are likely to cause trouble.

For every interpreter it reports the version, real location, prefix,
site-packages directories, whether it is PEP 668 externally managed, how
many third-party packages are installed, and which `pip` it pairs with.
It then raises warnings for the usual sources of confusion: shadowed
`python3` resolution, end-of-life or unsupported versions, user site-packages
that silently leak into every interpreter of the same minor version, stale
virtualenvs pointing at deleted interpreters, and broken symlinks.

Typical usage::

    ./doctor.py                 # full diagnostic report
    ./doctor.py --problems      # only interpreters with warnings
    ./doctor.py --json          # machine-readable output
    ./doctor.py --quick         # skip package counts (much faster)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

# `X | Y` unions in annotations evaluated at runtime by dataclasses, plus
# `list[str]` builtin generics and `functools.cache`, require Python 3.10+.
if sys.version_info < (3, 10):
    sys.exit("error: python 3.10 or newer is required")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

# Seconds to wait on any interpreter we shell out to. A broken or network
# mounted interpreter can hang indefinitely, which would stall the report.
PROBE_TIMEOUT = 15

# Python releases and their end-of-support dates (PEP 664 and friends).
# Used to flag interpreters that no longer receive security fixes. Versions
# newer than the newest key are assumed supported.
EOL_DATES: dict[tuple[int, int], date] = {
    (2, 7): date(2020, 1, 1),
    (3, 0): date(2009, 6, 27),
    (3, 1): date(2012, 4, 9),
    (3, 2): date(2016, 2, 20),
    (3, 3): date(2017, 9, 29),
    (3, 4): date(2019, 3, 18),
    (3, 5): date(2020, 9, 30),
    (3, 6): date(2021, 12, 23),
    (3, 7): date(2023, 6, 27),
    (3, 8): date(2024, 10, 7),
    (3, 9): date(2025, 10, 31),
    (3, 10): date(2026, 10, 31),
    (3, 11): date(2027, 10, 31),
    (3, 12): date(2028, 10, 31),
    (3, 13): date(2029, 10, 31),
    (3, 14): date(2030, 10, 31),
}

# Directories searched for interpreters in addition to $PATH. Globs are
# expanded relative to the user's home where the pattern starts with `~`.
EXTRA_SEARCH_GLOBS: tuple[str, ...] = (
    "/Library/Frameworks/Python.framework/Versions/*/bin",
    "/opt/homebrew/Frameworks/Python.framework/Versions/*/bin",
    "/opt/homebrew/bin",
    "/opt/homebrew/opt/python@*/bin",
    "/usr/local/Frameworks/Python.framework/Versions/*/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/opt/local/bin",
    "/Applications/Xcode.app/Contents/Developer/usr/bin",
    "/Library/Developer/CommandLineTools/usr/bin",
    "~/.pyenv/versions/*/bin",
    "~/.local/share/uv/python/*/bin",
    "~/anaconda3/bin",
    "~/miniconda3/bin",
    "~/miniforge3/bin",
    "~/mambaforge/bin",
    "/opt/anaconda3/bin",
    "/opt/miniconda3/bin",
)

# Matches the interpreter names worth probing: `python`, `python3`,
# `python3.12`, `python3.13t` (free-threaded builds). Deliberately excludes
# `python3-config`, `pythonw`, and similar helper executables.
INTERPRETER_NAME_RE = re.compile(r"^python(\d+(\.\d+)?t?)?$")

# Classifies an interpreter by where it lives. Ordered most specific first,
# since several of these prefixes are nested inside one another.
INSTALL_KIND_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/\.pyenv/versions/", "pyenv"),
    (r"/(anaconda|miniconda|miniforge|mambaforge)\d*/", "conda"),
    (r"/\.local/share/uv/python/", "uv-managed"),
    (r"^/opt/homebrew/", "homebrew (arm64)"),
    (r"^/usr/local/Cellar/", "homebrew (x86_64)"),
    (r"^/usr/local/(bin|opt)/", "homebrew (x86_64) or manual"),
    (r"^/Library/Frameworks/Python\.framework/", "python.org installer"),
    (r"^/Applications/Xcode\.app/", "Xcode toolchain"),
    (r"^/Library/Developer/CommandLineTools/", "command line tools"),
    (r"^/System/Library/Frameworks/", "macOS system (unsupported)"),
    (r"^/usr/bin/", "Apple stub / command line tools"),
    (r"^/opt/local/", "macports"),
    (r"/\.rye/", "rye-managed"),
    (r"/\.asdf/", "asdf-managed"),
)

# Code run inside each interpreter to extract its configuration. Printed as
# a single JSON object so the parent can parse one line of stdout.
PROBE_SOURCE = r"""
import json, os, sys
info = {
    "version": "%d.%d.%d" % sys.version_info[:3],
    "version_info": list(sys.version_info[:3]),
    "executable": sys.executable or "",
    "prefix": sys.prefix,
    "base_prefix": getattr(sys, "base_prefix", sys.prefix),
    "implementation": sys.implementation.name,
    "platform": sys.platform,
}
try:
    import sysconfig
    info["purelib"] = sysconfig.get_path("purelib")
    info["platlib"] = sysconfig.get_path("platlib")
    info["stdlib"] = sysconfig.get_path("stdlib")
    info["scripts"] = sysconfig.get_path("scripts")
    info["abiflags"] = sysconfig.get_config_var("abiflags") or ""
    info["free_threaded"] = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
except Exception as exc:
    info["sysconfig_error"] = str(exc)
try:
    import site
    info["user_site"] = site.getusersitepackages()
    info["user_base"] = site.getuserbase()
    info["user_site_enabled"] = site.ENABLE_USER_SITE
    info["site_packages"] = list(site.getsitepackages())
except Exception as exc:
    info["site_error"] = str(exc)
# PEP 668: distros mark interpreters they manage so pip refuses to install
# into them without --break-system-packages.
try:
    marker = os.path.join(info.get("stdlib", ""), "EXTERNALLY-MANAGED")
    info["externally_managed"] = os.path.exists(marker)
except Exception:
    info["externally_managed"] = False
info["sys_path"] = [p for p in sys.path if p]
print(json.dumps(info))
"""

# Counts installed distributions without importing pip, which is slow and may
# not be present. Falls back gracefully when importlib.metadata is missing.
COUNT_SOURCE = r"""
import json
try:
    from importlib.metadata import distributions
    names = set()
    for dist in distributions():
        name = (dist.metadata["Name"] or "").strip()
        if name:
            names.add(name.lower())
    print(json.dumps({"count": len(names), "names": sorted(names)}))
except Exception as exc:
    print(json.dumps({"error": str(exc)}))
"""


@dataclass
class Warning_:
    """A single diagnostic finding about an interpreter or the environment.

    Attributes:
        severity: One of "error", "warning", or "note".
        message: Short description of what is wrong.
        hint: Optional suggested remedy.
    """

    severity: str
    message: str
    hint: str = ""


@dataclass
class Interpreter:
    """A discovered Python interpreter and everything probed about it.

    Attributes:
        path: The path at which the interpreter was discovered.
        real_path: The fully resolved path after following symlinks.
        aliases: Other discovered paths that resolve to the same real path.
        kind: Human-readable install source, e.g. "homebrew (arm64)".
        version: Dotted version string, empty if the probe failed.
        version_info: Version as a (major, minor, micro) tuple.
        prefix: `sys.prefix` for this interpreter.
        base_prefix: `sys.base_prefix`; differs from prefix inside a venv.
        purelib: Pure-Python site-packages directory.
        platlib: Platform-specific site-packages directory.
        stdlib: Standard library directory.
        user_site: PEP 370 per-user site-packages directory.
        user_site_exists: Whether that user site directory exists on disk.
        user_site_enabled: Whether the interpreter honors the user site dir.
        externally_managed: Whether a PEP 668 marker is present.
        free_threaded: Whether this is a free-threaded (no-GIL) build.
        implementation: Interpreter implementation, e.g. "cpython".
        package_count: Number of installed distributions, or None if unknown.
        pip_path: Path of the `pip` that installs into this interpreter.
        on_path: Whether this interpreter was found via $PATH.
        path_index: Position in $PATH of the directory it was found in.
        probe_error: Error text if the interpreter could not be probed.
        warnings: Findings attached to this interpreter.
    """

    path: Path
    real_path: Path
    aliases: list[Path] = field(default_factory=list)
    kind: str = "unknown"
    version: str = ""
    version_info: tuple[int, ...] = ()
    prefix: str = ""
    base_prefix: str = ""
    purelib: str = ""
    platlib: str = ""
    stdlib: str = ""
    user_site: str = ""
    user_site_exists: bool = False
    user_site_enabled: bool = True
    externally_managed: bool = False
    free_threaded: bool = False
    implementation: str = "cpython"
    package_count: int | None = None
    pip_path: str = ""
    on_path: bool = False
    path_index: int | None = None
    probe_error: str = ""
    warnings: list[Warning_] = field(default_factory=list)

    @property
    def minor(self) -> tuple[int, int] | None:
        """Return the (major, minor) version pair, if known.

        Returns:
            The version pair, or None when the probe failed.
        """
        if len(self.version_info) >= 2:
            return (self.version_info[0], self.version_info[1])
        return None

    @property
    def is_venv(self) -> bool:
        """Report whether this interpreter belongs to a virtual environment.

        Returns:
            True when `sys.prefix` and `sys.base_prefix` differ.
        """
        return bool(self.prefix and self.base_prefix and self.prefix != self.base_prefix)

    @property
    def friendly_path(self) -> Path:
        """Pick the most recognizable path for this interpreter.

        Homebrew and framework installs resolve to deep Cellar or
        Versions directories; the short symlink the user actually types is
        more useful in a summary.

        Returns:
            The shortest known path referring to this interpreter.
        """
        candidates = [self.path, *self.aliases, self.real_path]
        return min(candidates, key=lambda p: (len(str(p)), str(p)))

    @property
    def display_name(self) -> str:
        """Build a short label for this interpreter.

        Returns:
            A string such as "Python 3.13.1 (homebrew (arm64))".
        """
        version = self.version or "unknown version"
        return f"Python {version} ({self.kind})"


def classify_install(real_path: Path) -> str:
    """Determine how an interpreter was installed from its location.

    Args:
        real_path: The fully resolved interpreter path.

    Returns:
        A human-readable install-source label, or "unknown".
    """
    logger.debug("classifying install for %s", real_path)
    text = str(real_path)
    for pattern, label in INSTALL_KIND_PATTERNS:
        if re.search(pattern, text):
            logger.debug("classified %s as %s", real_path, label)
            return label
    return "unknown"


def iter_search_dirs() -> list[tuple[Path, int | None]]:
    """Build the ordered list of directories to search for interpreters.

    $PATH entries come first, in order, so that shadowing can be detected;
    the well-known install locations follow.

    Returns:
        A list of (directory, path index) pairs. The index is the position
        in $PATH, or None for directories found only via the extra globs.
    """
    logger.debug("building interpreter search directory list")
    dirs: list[tuple[Path, int | None]] = []
    seen: set[Path] = set()

    for index, raw in enumerate(os.environ.get("PATH", "").split(os.pathsep)):
        if not raw:
            continue
        directory = Path(raw)
        # Resolve so that /usr/local/bin and a symlink to it collapse into
        # one entry, but keep the first-seen index for shadowing purposes.
        try:
            key = directory.resolve()
        except OSError:
            key = directory
        if key in seen or not directory.is_dir():
            continue
        seen.add(key)
        dirs.append((directory, index))

    for pattern in EXTRA_SEARCH_GLOBS:
        expanded = os.path.expanduser(pattern)
        # Path.glob needs a root plus a relative pattern; splitting on the
        # first wildcard keeps this simple for the absolute patterns above.
        if "*" in expanded:
            root, _, tail = expanded.partition("*")
            base = Path(root).parent if not root.endswith("/") else Path(root)
            try:
                candidates = sorted(base.glob("*" + tail if tail else "*"))
            except OSError as exc:
                logger.warning("could not glob %s: %s", pattern, exc)
                continue
        else:
            candidates = [Path(expanded)]
        for directory in candidates:
            if not directory.is_dir():
                continue
            try:
                key = directory.resolve()
            except OSError:
                key = directory
            if key in seen:
                continue
            seen.add(key)
            dirs.append((directory, None))

    logger.debug("searching %d directories", len(dirs))
    return dirs


def find_interpreters() -> list[Interpreter]:
    """Discover candidate Python interpreters on this machine.

    Scans $PATH and the well-known install locations, deduplicating by
    resolved path so that the many symlinks pointing at one real interpreter
    are reported as a single entry with aliases.

    Returns:
        A list of `Interpreter` objects with location fields populated.
    """
    logger.debug("scanning for interpreters")
    by_real: dict[Path, Interpreter] = {}

    for directory, path_index in iter_search_dirs():
        try:
            children = sorted(directory.iterdir())
        except OSError as exc:
            logger.warning("could not list %s: %s", directory, exc)
            continue

        for child in children:
            if not INTERPRETER_NAME_RE.match(child.name):
                continue
            if not os.access(child, os.X_OK) or child.is_dir():
                continue

            try:
                real = child.resolve()
            except OSError as exc:
                logger.warning("could not resolve %s: %s", child, exc)
                continue

            # A venv's interpreters symlink to the install it was built from,
            # so resolving them would merge the venv into that base install
            # and mislabel the base as a virtualenv. pyvenv.cfg marks the venv
            # root; key every interpreter inside one by its own path, after
            # collapsing the venv-internal python -> python3 -> python3.x
            # symlink chain so a single venv is not reported three times.
            if (child.parent.parent / "pyvenv.cfg").is_file():
                real = child
                while real.is_symlink():
                    target = Path(os.readlink(real))
                    if not target.is_absolute():
                        target = real.parent / target
                    # Stop at the venv boundary: beyond it lies the base
                    # interpreter, which is a separate installation.
                    if target.parent.parent / "pyvenv.cfg" != child.parent.parent / "pyvenv.cfg":
                        break
                    if not (target.parent.parent / "pyvenv.cfg").is_file():
                        break
                    real = target

            existing = by_real.get(real)
            if existing is None:
                interpreter = Interpreter(
                    path=child,
                    real_path=real,
                    kind=classify_install(real),
                    on_path=path_index is not None,
                    path_index=path_index,
                )
                by_real[real] = interpreter
                logger.debug("found interpreter %s -> %s", child, real)
            else:
                existing.aliases.append(child)
                # A later discovery via $PATH still makes this interpreter
                # PATH-reachable, and the earliest index is what matters.
                if path_index is not None:
                    if existing.path_index is None or path_index < existing.path_index:
                        existing.path_index = path_index
                    existing.on_path = True

    interpreters = list(by_real.values())
    logger.debug("discovered %d unique interpreters", len(interpreters))
    return interpreters


def run_probe(executable: Path, source: str) -> dict[str, object] | None:
    """Execute a snippet inside an interpreter and parse its JSON output.

    Args:
        executable: The interpreter to run.
        source: Python source printing a single JSON object to stdout.

    Returns:
        The decoded object, or None if the interpreter failed or timed out.
    """
    logger.debug("probing %s", executable)
    try:
        completed = subprocess.run(
            [str(executable), "-I", "-c", source],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
            # A stray interactive prompt would otherwise block the probe.
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("probe failed for %s: %s", executable, exc)
        return None

    if completed.returncode != 0:
        logger.warning(
            "probe for %s exited %d: %s",
            executable,
            completed.returncode,
            completed.stderr.strip()[:200],
        )
        return None

    # Some interpreters emit warnings before our JSON; take the last line.
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        logger.warning("could not parse probe output from %s: %s", executable, exc)
        return None


def probe_interpreter(interpreter: Interpreter, count_packages: bool) -> None:
    """Populate an interpreter's configuration fields by running it.

    Args:
        interpreter: The interpreter to probe, modified in place.
        count_packages: Whether to also count installed distributions.
    """
    logger.debug("gathering details for %s", interpreter.path)
    info = run_probe(interpreter.path, PROBE_SOURCE)
    if info is None:
        interpreter.probe_error = "interpreter could not be executed"
        logger.info("could not probe %s", interpreter.path)
        return

    interpreter.version = str(info.get("version", ""))
    raw_version = info.get("version_info") or []
    if isinstance(raw_version, list):
        interpreter.version_info = tuple(int(part) for part in raw_version)
    interpreter.prefix = str(info.get("prefix", ""))
    interpreter.base_prefix = str(info.get("base_prefix", ""))
    interpreter.purelib = str(info.get("purelib", ""))
    interpreter.platlib = str(info.get("platlib", ""))
    interpreter.stdlib = str(info.get("stdlib", ""))
    interpreter.user_site = str(info.get("user_site", ""))
    interpreter.user_site_enabled = bool(info.get("user_site_enabled", True))
    interpreter.externally_managed = bool(info.get("externally_managed", False))
    interpreter.free_threaded = bool(info.get("free_threaded", False))
    interpreter.implementation = str(info.get("implementation", "cpython"))

    if interpreter.user_site:
        interpreter.user_site_exists = Path(interpreter.user_site).is_dir()

    # The paired pip lives beside the interpreter; report the versioned name
    # when present since bare `pip` is often a different interpreter's.
    bin_dir = interpreter.real_path.parent
    minor = interpreter.minor
    candidates = [f"pip{minor[0]}.{minor[1]}", "pip3", "pip"] if minor else ["pip3", "pip"]
    for name in candidates:
        candidate = bin_dir / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            interpreter.pip_path = str(candidate)
            break

    if count_packages:
        counts = run_probe(interpreter.path, COUNT_SOURCE)
        if counts is not None and "count" in counts:
            interpreter.package_count = int(counts["count"])  # type: ignore[arg-type]

    logger.debug("probed %s as version %s", interpreter.path, interpreter.version or "?")


def check_eol(interpreter: Interpreter, today: date) -> None:
    """Flag interpreters whose Python version is past end of life.

    Args:
        interpreter: The interpreter to check, modified in place.
        today: The date to compare release support windows against.
    """
    minor = interpreter.minor
    if minor is None:
        return

    if minor[0] < 3:
        interpreter.warnings.append(
            Warning_(
                severity="error",
                message=f"Python {minor[0]}.{minor[1]} is long past end of life",
                hint="Remove this interpreter or migrate anything still using it.",
            )
        )
        return

    eol = EOL_DATES.get(minor)
    if eol is None:
        return
    if today >= eol:
        interpreter.warnings.append(
            Warning_(
                severity="warning",
                message=f"Python {minor[0]}.{minor[1]} reached end of life on {eol.isoformat()}",
                hint="It no longer receives security fixes; upgrade or uninstall it.",
            )
        )


def check_interpreter(interpreter: Interpreter, today: date) -> None:
    """Attach per-interpreter diagnostics.

    Args:
        interpreter: The interpreter to inspect, modified in place.
        today: The date used for end-of-life comparisons.
    """
    logger.debug("checking interpreter %s", interpreter.path)

    if interpreter.probe_error:
        interpreter.warnings.append(
            Warning_(
                severity="error",
                message=interpreter.probe_error,
                hint="The file is executable but does not run; it may be a broken symlink.",
            )
        )
        return

    check_eol(interpreter, today)

    # Apple's /usr/bin/python3 is a stub that may trigger a Command Line
    # Tools install prompt, and Apple explicitly tells users not to rely on it.
    if str(interpreter.real_path).startswith("/usr/bin/") or "command line tools" in interpreter.kind:
        interpreter.warnings.append(
            Warning_(
                severity="note",
                message="Apple-supplied Python; Apple advises against depending on it",
                hint="Prefer a Homebrew, python.org, uv, or pyenv interpreter for your own work.",
            )
        )

    if interpreter.externally_managed:
        interpreter.warnings.append(
            Warning_(
                severity="note",
                message="externally managed (PEP 668); pip refuses to install into it",
                hint="Use a virtualenv, `uv tool install`, or `pipx` instead.",
            )
        )

    if interpreter.user_site_exists and interpreter.user_site_enabled:
        interpreter.warnings.append(
            Warning_(
                severity="warning",
                message=f"user site-packages in use: {interpreter.user_site}",
                hint=(
                    "Every interpreter of this minor version imports it, so a stale "
                    "package here breaks unrelated environments. Consider removing it."
                ),
            )
        )

    if interpreter.is_venv and not Path(interpreter.base_prefix).exists():
        interpreter.warnings.append(
            Warning_(
                severity="error",
                message="virtualenv points at a base interpreter that no longer exists",
                hint=f"Missing base prefix: {interpreter.base_prefix}. Recreate the venv.",
            )
        )

    # purelib and platlib usually point at the same directory; report it once.
    missing_libs: dict[str, list[str]] = {}
    for label, location in (("purelib", interpreter.purelib), ("platlib", interpreter.platlib)):
        if location and not Path(location).exists():
            missing_libs.setdefault(location, []).append(label)
    for location, labels in missing_libs.items():
        interpreter.warnings.append(
            Warning_(
                severity="warning",
                message=f"{'/'.join(labels)} directory does not exist: {location}",
                hint="Nothing is installed yet, or the install is incomplete.",
            )
        )

    if interpreter.free_threaded:
        interpreter.warnings.append(
            Warning_(
                severity="note",
                message="free-threaded (no-GIL) build",
                hint="Some C extensions do not yet support this build.",
            )
        )

    if interpreter.implementation != "cpython":
        interpreter.warnings.append(
            Warning_(
                severity="note",
                message=f"non-CPython implementation: {interpreter.implementation}",
            )
        )


def check_environment(interpreters: list[Interpreter]) -> list[Warning_]:
    """Produce diagnostics about the environment as a whole.

    Covers `python3` shadowing on $PATH, a missing bare `python`, conflicting
    environment variables, an active virtualenv that is not first on $PATH,
    and duplicate installs of the same minor version.

    Args:
        interpreters: All discovered interpreters, already probed.

    Returns:
        A list of environment-level warnings.
    """
    logger.debug("running environment-level checks over %d interpreters", len(interpreters))
    findings: list[Warning_] = []

    resolved_python3 = shutil.which("python3")
    resolved_python = shutil.which("python")

    if resolved_python3 is None:
        findings.append(
            Warning_(
                severity="error",
                message="no `python3` found on $PATH",
                hint="Install one with `brew install python` or `uv python install`.",
            )
        )
    if resolved_python is None:
        findings.append(
            Warning_(
                severity="note",
                message="no bare `python` on $PATH",
                hint=(
                    "Scripts with a `#!/usr/bin/env python` shebang will fail. "
                    "This is normal on modern macOS."
                ),
            )
        )

    # Interpreters that share a command name earlier on $PATH shadow later
    # ones; that is the single most common source of "wrong Python" surprise.
    by_name: dict[str, list[Interpreter]] = {}
    for interpreter in interpreters:
        if not interpreter.on_path:
            continue
        for candidate in [interpreter.path, *interpreter.aliases]:
            by_name.setdefault(candidate.name, []).append(interpreter)

    for name, group in sorted(by_name.items()):
        # Deduplicate by real path: one interpreter reachable under several
        # names or symlinks does not shadow itself.
        unique: dict[Path, Interpreter] = {}
        for candidate in group:
            if candidate.path_index is None:
                continue
            unique.setdefault(candidate.real_path, candidate)
        on_path = list(unique.values())
        if len(on_path) < 2:
            continue
        on_path.sort(key=lambda i: i.path_index or 0)
        winner, *losers = on_path
        shadowed = ", ".join(f"{i.real_path} ({i.version or '?'})" for i in losers)
        findings.append(
            Warning_(
                severity="note",
                message=(
                    f"`{name}` resolves to {winner.real_path} "
                    f"({winner.version or '?'}), shadowing {len(losers)} other install(s)"
                ),
                hint=f"Also on $PATH: {shadowed}",
            )
        )

    for variable in ("PYTHONPATH", "PYTHONHOME"):
        value = os.environ.get(variable)
        if not value:
            continue
        severity = "warning" if variable == "PYTHONPATH" else "error"
        findings.append(
            Warning_(
                severity=severity,
                message=f"{variable} is set to {value!r}",
                hint=(
                    "It applies to every interpreter you run and is a frequent cause of "
                    "cross-environment import bugs."
                ),
            )
        )

    active_venv = os.environ.get("VIRTUAL_ENV")
    if active_venv:
        venv_python = Path(active_venv) / "bin" / "python"
        if not venv_python.exists():
            findings.append(
                Warning_(
                    severity="error",
                    message=f"VIRTUAL_ENV points at {active_venv}, which has no bin/python",
                    hint="The virtualenv was deleted or moved; deactivate and recreate it.",
                )
            )
        elif resolved_python3 and not resolved_python3.startswith(active_venv):
            findings.append(
                Warning_(
                    severity="warning",
                    message=(
                        f"a virtualenv is active ({active_venv}) but `python3` resolves to "
                        f"{resolved_python3}"
                    ),
                    hint="The venv's bin directory is not first on $PATH.",
                )
            )

    if os.environ.get("CONDA_PREFIX") and active_venv:
        findings.append(
            Warning_(
                severity="warning",
                message="both a conda environment and a virtualenv are active",
                hint="Stacked environments make import resolution hard to predict.",
            )
        )

    # Several installs of the same minor version are legal but are worth
    # surfacing, since packages installed into one are invisible to the rest.
    by_minor: dict[tuple[int, int], list[Interpreter]] = {}
    for interpreter in interpreters:
        minor = interpreter.minor
        if minor is not None and not interpreter.is_venv:
            by_minor.setdefault(minor, []).append(interpreter)

    for minor, group in sorted(by_minor.items()):
        if len(group) < 2:
            continue
        locations = ", ".join(str(i.real_path) for i in group)
        findings.append(
            Warning_(
                severity="note",
                message=f"{len(group)} separate installs of Python {minor[0]}.{minor[1]}",
                hint=f"Packages installed into one are not visible to the others: {locations}",
            )
        )

    logger.debug("environment checks produced %d findings", len(findings))
    return findings


SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "error": ("bold red", "✖"),
    "warning": ("yellow", "▲"),
    "note": ("cyan", "•"),
}


def render_warning(finding: Warning_) -> Text:
    """Format a single finding as styled terminal text.

    Args:
        finding: The finding to render.

    Returns:
        A `rich` `Text` object with the severity marker applied.
    """
    style, marker = SEVERITY_STYLES.get(finding.severity, ("white", "•"))
    text = Text()
    text.append(f"{marker} ", style=style)
    text.append(finding.message, style=style)
    if finding.hint:
        text.append(f"\n  {finding.hint}", style="dim")
    return text


def render_interpreter(console: Console, interpreter: Interpreter, verbose: bool) -> None:
    """Print the full diagnostic block for one interpreter.

    Args:
        console: The rich console to print to.
        interpreter: The interpreter to render.
        verbose: Whether to include aliases and extra site directories.
    """
    logger.debug("rendering interpreter %s", interpreter.path)
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="dim", no_wrap=True)
    table.add_column(overflow="fold")

    table.add_row("path", str(interpreter.path))
    if interpreter.real_path != interpreter.path:
        table.add_row("resolves to", str(interpreter.real_path))
    table.add_row("source", interpreter.kind)

    if interpreter.probe_error:
        table.add_row("status", Text(interpreter.probe_error, style="bold red"))
    else:
        table.add_row("prefix", interpreter.prefix)
        if interpreter.is_venv:
            table.add_row("base prefix", interpreter.base_prefix)
        table.add_row("site-packages", interpreter.purelib or "(unknown)")
        if verbose and interpreter.platlib and interpreter.platlib != interpreter.purelib:
            table.add_row("platlib", interpreter.platlib)
        if verbose and interpreter.stdlib:
            table.add_row("stdlib", interpreter.stdlib)

        user_site = interpreter.user_site or "(unknown)"
        user_state = "present" if interpreter.user_site_exists else "absent"
        if not interpreter.user_site_enabled:
            user_state += ", disabled"
        table.add_row("user site", f"{user_site}  [{user_state}]")

        table.add_row("pip", interpreter.pip_path or "(none alongside interpreter)")
        if interpreter.package_count is not None:
            table.add_row("packages", str(interpreter.package_count))
        if interpreter.is_venv:
            table.add_row("virtualenv", "yes")

    if verbose and interpreter.aliases:
        table.add_row("aliases", "\n".join(str(a) for a in interpreter.aliases))

    if interpreter.warnings:
        table.add_row("", "")
        for finding in interpreter.warnings:
            table.add_row("", render_warning(finding))

    severity = max_severity(interpreter.warnings)
    border = {"error": "red", "warning": "yellow"}.get(severity, "green")
    title = interpreter.display_name
    if interpreter.free_threaded:
        title += " [free-threaded]"

    console.print(Panel(table, title=title, title_align="left", border_style=border))


def max_severity(findings: list[Warning_]) -> str:
    """Return the most serious severity in a list of findings.

    Args:
        findings: The findings to inspect.

    Returns:
        "error", "warning", "note", or "ok" when the list is empty.
    """
    if any(f.severity == "error" for f in findings):
        return "error"
    if any(f.severity == "warning" for f in findings):
        return "warning"
    if findings:
        return "note"
    return "ok"


def render_summary(console: Console, interpreters: list[Interpreter]) -> None:
    """Print the overview table of every discovered interpreter.

    Args:
        console: The rich console to print to.
        interpreters: All discovered interpreters.
    """
    logger.debug("rendering summary for %d interpreters", len(interpreters))
    table = Table(
        title="Discovered Python interpreters",
        title_justify="left",
        header_style="bold",
        expand=True,
    )
    table.add_column("Version", no_wrap=True)
    table.add_column("Source", max_width=22, overflow="ellipsis")
    # Paths are the widest column and the one worth reading in full, so let it
    # absorb the leftover width and truncate from the left, keeping the tail
    # (the interpreter name) visible when the terminal is narrow.
    table.add_column("Path", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("Pkgs", justify="right", no_wrap=True)
    table.add_column("PATH", justify="center", no_wrap=True)
    table.add_column("Issues", justify="center", no_wrap=True)

    for interpreter in interpreters:
        severity = max_severity(interpreter.warnings)
        style = {"error": "red", "warning": "yellow"}.get(severity, "")
        real_issues = [w for w in interpreter.warnings if w.severity in ("error", "warning")]
        table.add_row(
            interpreter.version or "?",
            interpreter.kind,
            str(interpreter.friendly_path),
            "-" if interpreter.package_count is None else str(interpreter.package_count),
            "yes" if interpreter.on_path else "no",
            str(len(real_issues)) if real_issues else "-",
            style=style,
        )

    console.print(table)


def sort_key(interpreter: Interpreter) -> tuple[object, ...]:
    """Order interpreters for display: newest first, PATH-reachable first.

    Args:
        interpreter: The interpreter to compute a sort key for.

    Returns:
        A tuple suitable for `list.sort`.
    """
    return (
        0 if interpreter.on_path else 1,
        tuple(-part for part in interpreter.version_info) or (0,),
        str(interpreter.real_path),
    )


def to_dicts(interpreters: list[Interpreter], environment: list[Warning_]) -> dict[str, object]:
    """Convert the full report into a JSON-serializable structure.

    Args:
        interpreters: All discovered interpreters.
        environment: Environment-level findings.

    Returns:
        A dictionary suitable for `json.dumps`.
    """
    logger.debug("serializing %d interpreters to dicts", len(interpreters))
    return {
        "environment": [
            {"severity": w.severity, "message": w.message, "hint": w.hint} for w in environment
        ],
        "interpreters": [
            {
                "path": str(i.path),
                "real_path": str(i.real_path),
                "aliases": [str(a) for a in i.aliases],
                "kind": i.kind,
                "version": i.version,
                "prefix": i.prefix,
                "base_prefix": i.base_prefix,
                "purelib": i.purelib,
                "platlib": i.platlib,
                "stdlib": i.stdlib,
                "user_site": i.user_site,
                "user_site_exists": i.user_site_exists,
                "externally_managed": i.externally_managed,
                "free_threaded": i.free_threaded,
                "implementation": i.implementation,
                "package_count": i.package_count,
                "pip": i.pip_path,
                "on_path": i.on_path,
                "is_venv": i.is_venv,
                "probe_error": i.probe_error,
                "warnings": [
                    {"severity": w.severity, "message": w.message, "hint": w.hint}
                    for w in i.warnings
                ],
            }
            for i in interpreters
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser.

    Returns:
        The configured `ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        description="Diagnose the Python installations on this machine.",
    )
    parser.add_argument(
        "--problems",
        action="store_true",
        help="Only show interpreters that have warnings or errors.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip counting installed packages, which runs each interpreter twice.",
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
        help="Include aliases, platlib, and stdlib paths for each interpreter.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING).",
    )
    return parser


def main() -> int:
    """Run the Python installation diagnostic.

    Returns:
        Process exit code: 0 when nothing worse than a note was found,
        1 when any warning or error was reported.
    """
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.debug("starting with problems=%s, quick=%s", args.problems, args.quick)

    # JSON output must stay clean, so send progress and logs to stderr.
    console = Console(stderr=args.as_json)

    interpreters = find_interpreters()
    if not interpreters:
        console.print("[bold red]No Python interpreters found.[/bold red]")
        return 1

    with console.status("Probing interpreters..."):
        for interpreter in interpreters:
            probe_interpreter(interpreter, count_packages=not args.quick)

    today = date.today()
    for interpreter in interpreters:
        check_interpreter(interpreter, today)

    environment = check_environment(interpreters)
    interpreters.sort(key=sort_key)

    if args.as_json:
        print(json.dumps(to_dicts(interpreters, environment), indent=2))
    else:
        out = Console()
        out.print()
        render_summary(out, interpreters)
        out.print()

        shown = [
            i
            for i in interpreters
            if not args.problems
            or any(w.severity in ("error", "warning") for w in i.warnings)
        ]
        for interpreter in shown:
            render_interpreter(out, interpreter, args.verbose)

        if environment:
            body = Text()
            for index, finding in enumerate(environment):
                if index:
                    body.append("\n")
                body.append_text(render_warning(finding))
            out.print(
                Panel(
                    body,
                    title="Environment",
                    title_align="left",
                    border_style=(
                        "red" if max_severity(environment) == "error" else "yellow"
                    ),
                )
            )

        all_findings = [w for i in interpreters for w in i.warnings] + environment
        errors = sum(1 for w in all_findings if w.severity == "error")
        warnings = sum(1 for w in all_findings if w.severity == "warning")
        if errors or warnings:
            out.print(
                f"\n[bold]{errors}[/bold] error(s), [bold]{warnings}[/bold] warning(s) "
                f"across [bold]{len(interpreters)}[/bold] interpreter(s).\n"
            )
        else:
            out.print("\n[bold green]Your Python installations look healthy.[/bold green]\n")

    all_findings = [w for i in interpreters for w in i.warnings] + environment
    problem_count = sum(1 for w in all_findings if w.severity in ("error", "warning"))
    logger.debug("returning exit code based on %d problems", problem_count)
    return 1 if problem_count else 0


if __name__ == "__main__":
    sys.exit(main())
