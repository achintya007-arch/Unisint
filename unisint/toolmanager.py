"""Detect and install the external tools UNISINT wraps.

pip tools go into a dedicated venv (~/.unisint/tools/venv) to avoid clashing
with UNISINT's own deps; Go tools install into ~/.unisint/tools/go.
Everything is optional — missing tools are simply skipped at scan time.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from dataclasses import dataclass

from .config import TOOLS_DIR
from .runner import GO_BIN, VENV_BIN, run, which

VENV_PY = VENV_BIN / "python"


@dataclass
class Tool:
    name: str            # binary name
    label: str
    kind: str            # pip | go | system
    spec: str            # pip package / go module / system pkg
    purpose: str


CATALOG: list[Tool] = [
    Tool("sherlock", "Sherlock", "pip", "sherlock-project",
         "usernames across social networks"),
    Tool("maigret", "Maigret", "pip", "maigret",
         "3000+ sites, pulls profile data"),
    Tool("holehe", "holehe", "pip", "holehe",
         "sites an email is registered on"),
    Tool("socialscan", "socialscan", "pip", "socialscan",
         "username/email availability"),
    Tool("ignorant", "ignorant", "pip", "ignorant",
         "sites a phone is registered on"),
    Tool("theHarvester", "theHarvester", "pip", "theHarvester",
         "domain emails & hosts"),
    Tool("subfinder", "subfinder", "go",
         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
         "passive subdomain enumeration"),
    Tool("amass", "Amass", "go",
         "github.com/owasp-amass/amass/v4/...@master",
         "passive DNS / attack surface"),
    Tool("exiftool", "exiftool", "system", "libimage-exiftool-perl",
         "rich file metadata"),
]


def status() -> list[dict]:
    rows = []
    for t in CATALOG:
        path = which(t.name)
        rows.append({
            "name": t.name, "label": t.label, "kind": t.kind,
            "purpose": t.purpose, "installed": bool(path),
            "path": path or "", "spec": t.spec,
        })
    return rows


async def _ensure_venv() -> None:
    if not VENV_PY.exists():
        await run([sys.executable, "-m", "venv", str(TOOLS_DIR / "venv")],
                  timeout=120)


async def install(name: str) -> dict:
    tool = next((t for t in CATALOG if t.name == name), None)
    if not tool:
        return {"ok": False, "msg": f"unknown tool {name}"}

    if tool.kind == "pip":
        await _ensure_venv()
        code, so, se = await run(
            [str(VENV_PY), "-m", "pip", "install", "-U", tool.spec],
            timeout=600)
        ok = code == 0 and bool(which(tool.name))
        return {"ok": ok, "msg": (se or so)[-800:]}

    if tool.kind == "go":
        go = shutil.which("go")
        if not go:
            return {"ok": False,
                    "msg": "Go toolchain not found; install Go first."}
        env = {"GOBIN": str(GO_BIN)}
        code, so, se = await run([go, "install", tool.spec],
                                 timeout=900, env=env)
        ok = code == 0 and bool(which(tool.name))
        return {"ok": ok, "msg": (se or so)[-800:]}

    # system
    return {"ok": False,
            "msg": f"Install via your package manager: {tool.spec} "
                   f"(e.g. apt install {tool.spec})"}


async def install_all() -> dict[str, dict]:
    results = {}
    for t in CATALOG:
        if which(t.name):
            results[t.name] = {"ok": True, "msg": "already installed"}
            continue
        results[t.name] = await install(t.name)
    return results
