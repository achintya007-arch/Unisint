"""Run external CLI tools as async subprocesses with timeouts.

Tools are preferred from the dedicated venv at ~/.unisint/tools/venv/bin,
then from PATH. This keeps UNISINT's own environment clean and lets the
tool manager upgrade tools independently.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
from pathlib import Path

from .config import TOOLS_DIR

VENV_BIN = TOOLS_DIR / "venv" / "bin"
GO_BIN = TOOLS_DIR / "go" / "bin"

# Tools installed from source into their own venv (e.g. theHarvester 5.x via
# `uv sync`, which needs its own Python and dependency set).
SOURCE_VENVS = {
    "theHarvester": TOOLS_DIR / "theHarvester-src" / ".venv" / "bin",
}


def search_dirs(name: str) -> list[Path]:
    """Directories searched for ``name``, in priority order."""
    dirs: list[Path] = []
    for d in os.environ.get("UNISINT_TOOL_PATHS", "").split(os.pathsep):
        if d.strip():
            dirs.append(Path(d.strip()).expanduser())
    if name in SOURCE_VENVS:
        dirs.append(SOURCE_VENVS[name])
    dirs += [VENV_BIN, GO_BIN, Path.home() / "go" / "bin"]
    return dirs

# In-memory record of tools that ran but failed this session (crash, timeout,
# or nonzero exit), keyed by the basename of the command. Surfaced in the
# ARSENAL so a tool that is installed but misbehaving is visible, not silent.
_FAILURES: dict[str, int] = {}


_SUCCESSES: dict[str, int] = {}


def record_failure(binary: str) -> None:
    name = os.path.basename(binary)
    _FAILURES[name] = _FAILURES.get(name, 0) + 1


def record_success(binary: str) -> None:
    name = os.path.basename(binary)
    _SUCCESSES[name] = _SUCCESSES.get(name, 0) + 1


def failure_counts() -> dict[str, int]:
    return dict(_FAILURES)


def success_counts() -> dict[str, int]:
    return dict(_SUCCESSES)


class UnsafeArgument(ValueError):
    """User/tool-derived value that is not safe to pass to a CLI tool."""


_ARG_PATTERNS = {
    "username": re.compile(r"^[A-Za-z0-9._\-]{1,64}$"),
    "domain": re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                         r"[A-Za-z]{2,63}$"),
    "email": re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~\-]{1,64}@"
                        r"[A-Za-z0-9.\-]{1,253}$"),
    "digits": re.compile(r"^[0-9]{1,15}$"),
}


def safe_arg(value: str, kind: str) -> str:
    """Validate a value before it becomes a CLI argument.

    Arguments are always passed as a list (never through a shell), so the
    remaining risks are option injection (values starting with '-') and
    values that a tool would misinterpret. Anything not matching the strict
    pattern for its kind is refused.
    """
    v = (value or "").strip()
    if not v or v.startswith("-"):
        raise UnsafeArgument(f"refused {kind} argument: {value!r}")
    pat = _ARG_PATTERNS.get(kind)
    if pat is None or not pat.match(v):
        raise UnsafeArgument(f"refused {kind} argument: {value!r}")
    return v


def which(name: str) -> str | None:
    """Locate a tool: explicit overrides, managed dirs, then PATH."""
    for base in search_dirs(name):
        cand = base / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which(name)


async def run(
    cmd: list[str],
    *,
    timeout: float = 120.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    track: bool = True,
) -> tuple[int, str, str]:
    """Execute ``cmd``; return (returncode, stdout, stderr).

    A timeout kills the process and returns code 124. ``track=False`` keeps
    health checks out of the operational success/failure counters.
    """
    full_env = {**os.environ, **(env or {})}
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=full_env,
        )
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"

    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        if track:
            record_failure(cmd[0])
        return 124, "", f"timeout after {timeout}s"

    rc = proc.returncode or 0
    if track:
        (record_failure if rc != 0 else record_success)(cmd[0])
    return (
        rc,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


def tmp_dir(name: str) -> Path:
    base = TOOLS_DIR.parent / "scratch"
    base.mkdir(parents=True, exist_ok=True)
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    return d
