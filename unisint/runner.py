"""Run external CLI tools as async subprocesses with timeouts.

Tools are preferred from the dedicated venv at ~/.unisint/tools/venv/bin,
then from PATH. This keeps UNISINT's own environment clean and lets the
tool manager upgrade tools independently.
"""
from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

from .config import TOOLS_DIR

VENV_BIN = TOOLS_DIR / "venv" / "bin"
GO_BIN = TOOLS_DIR / "go" / "bin"


def which(name: str) -> str | None:
    """Locate a tool, preferring UNISINT's managed dirs."""
    for base in (VENV_BIN, GO_BIN):
        cand = base / name
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which(name)


async def run(
    cmd: list[str],
    *,
    timeout: float = 120.0,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Execute ``cmd``; return (returncode, stdout, stderr).

    A timeout kills the process group and returns code 124.
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
        return 124, "", f"timeout after {timeout}s"

    return (
        proc.returncode or 0,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


def tmp_dir(name: str) -> Path:
    base = TOOLS_DIR.parent / "scratch"
    base.mkdir(parents=True, exist_ok=True)
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    return d
