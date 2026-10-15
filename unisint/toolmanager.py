"""Detect, health-check and install the external tools UNISINT wraps.

States (an installed file is not proof the tool works):
  unavailable   no executable found
  installed     executable found, health not yet checked
  runnable      health command (e.g. --version) exits 0 within the timeout
  misconfigured executable found but the health command fails/hangs
  operational   runnable AND a real run this session completed successfully
  failing       real runs this session failed more often than they succeeded

Install methods:
  pip     into the private venv ~/.unisint/tools/venv
  uv-git  theHarvester: current source needs Python >= 3.14, so it is cloned
          to ~/.unisint/tools/theHarvester-src and installed with ``uv sync``
          (uv provisions the interpreter). Executable: .venv/bin/theHarvester
  go      ``go install`` into ~/.unisint/tools/go/bin (needs Go >= 1.21 so the
          toolchain the module requires can be fetched automatically)
  system  package manager (exiftool)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import sys
import time
from dataclasses import dataclass

from .config import TOOLS_DIR
from .runner import (GO_BIN, VENV_BIN, failure_counts, run, success_counts,
                     which)

VENV_PY = VENV_BIN / "python"
HARVESTER_DIR = TOOLS_DIR / "theHarvester-src"
HARVESTER_REPO = "https://github.com/laramies/theHarvester"
MIN_GO = (1, 21)   # first Go with automatic toolchain switching


@dataclass
class Tool:
    name: str            # binary name
    label: str
    kind: str            # pip | uv-git | go | system
    spec: str            # pip package / go module / system package / git repo
    purpose: str
    health: tuple[str, ...] = ("--version",)


CATALOG: list[Tool] = [
    Tool("sherlock", "Sherlock", "pip", "sherlock-project",
         "username → sites where the handle exists"),
    Tool("maigret", "Maigret", "pip", "maigret",
         "username → 3000+ sites, extracts profile fields"),
    Tool("holehe", "holehe", "pip", "holehe",
         "email → sites it is registered on", ("--help",)),
    Tool("socialscan", "socialscan", "pip", "socialscan",
         "username/email in use on major platforms"),
    Tool("ignorant", "ignorant", "pip", "ignorant",
         "phone → sites it is registered on", ("--help",)),
    Tool("theHarvester", "theHarvester", "uv-git", HARVESTER_REPO,
         "domain → emails & hosts (passive sources)", ("-h",)),
    Tool("subfinder", "subfinder", "go",
         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
         "domain → passive subdomains", ("-version",)),
    Tool("amass", "Amass", "go",
         "github.com/owasp-amass/amass/v4/...@master",
         "domain → passive DNS names", ("-version",)),
    Tool("exiftool", "exiftool", "system", "libimage-exiftool-perl",
         "file → metadata", ("-ver",)),
]

_HEALTH: dict[str, dict] = {}       # name -> {state, detail, checked_at}
HEALTH_TTL = 600.0


def _tool(name: str) -> Tool | None:
    return next((t for t in CATALOG if t.name == name), None)


async def health_check(name: str, *, force: bool = False,
                       timeout: float = 20.0) -> dict:
    """Run the tool's harmless health command; cache the outcome."""
    t = _tool(name)
    if t is None:
        return {"state": "unavailable", "detail": "unknown tool"}
    cached = _HEALTH.get(name)
    if cached and not force and time.time() - cached["checked_at"] < HEALTH_TTL:
        return cached
    path = which(name)
    if not path:
        res = {"state": "unavailable", "detail": "executable not found"}
    else:
        code, so, se = await run([path, *t.health], timeout=timeout, track=False)
        out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", so + se).strip()
        if code == 0:
            lines = [l.strip(" *\t") for l in out.splitlines() if l.strip(" *\t")]
            ver = next((l for l in lines if re.search(r"\d+\.\d+", l)), None)
            res = {"state": "runnable", "detail": (ver or (lines[0] if lines else "ok"))[:120]}
        elif code == 124:
            res = {"state": "misconfigured", "detail": f"health check hung >{timeout}s"}
        else:
            res = {"state": "misconfigured",
                   "detail": f"exit {code}: {out[-200:] or 'no output'}"}
    res["checked_at"] = time.time()
    res["path"] = path or ""
    _HEALTH[name] = res
    return res


async def health_all(force: bool = False) -> dict[str, dict]:
    names = [t.name for t in CATALOG]
    results = await asyncio.gather(*(health_check(n, force=force) for n in names))
    return dict(zip(names, results))


def _state(name: str, path: str | None) -> tuple[str, str]:
    if not path:
        return "unavailable", "executable not found"
    h = _HEALTH.get(name)
    ok, bad = success_counts().get(name, 0), failure_counts().get(name, 0)
    if h and h["state"] == "misconfigured":
        return "misconfigured", h["detail"]
    if bad > ok:
        return "failing", f"{bad} failed / {ok} ok real run(s) this session"
    if ok:
        return "operational", f"{ok} successful run(s) this session"
    if h:
        return h["state"], h.get("detail", "")
    return "installed", "not health-checked yet"


def status() -> list[dict]:
    fails, oks = failure_counts(), success_counts()
    rows = []
    for t in CATALOG:
        path = which(t.name)
        state, detail = _state(t.name, path)
        rows.append({
            "name": t.name, "label": t.label, "kind": t.kind,
            "purpose": t.purpose, "installed": bool(path),
            "path": path or "", "spec": t.spec, "state": state,
            "detail": detail, "failures": fails.get(t.name, 0),
            "successes": oks.get(t.name, 0),
        })
    return rows


# ---- installation -----------------------------------------------------------

def parse_go_version(text: str) -> tuple[int, int] | None:
    m = re.search(r"go(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


async def go_check() -> tuple[bool, str]:
    go = shutil.which("go")
    if not go:
        return False, ("Go not found. Install a current Go from https://go.dev/dl/ "
                       "(distribution packages are often too old).")
    code, so, se = await run([go, "version"], timeout=20, track=False)
    v = parse_go_version(so)
    if not v:
        return False, f"could not read Go version: {(so + se).strip()[:120]}"
    if v < MIN_GO:
        return False, (f"Go {v[0]}.{v[1]} is too old: subfinder needs Go >= 1.26 and "
                       f"Go < 1.21 cannot fetch that toolchain automatically. Install "
                       f"Go from https://go.dev/dl/ (apt's golang-go is too old).")
    return True, f"go{v[0]}.{v[1]}"


async def _ensure_venv() -> None:
    if not VENV_PY.exists():
        await run([sys.executable, "-m", "venv", str(TOOLS_DIR / "venv")],
                  timeout=180, track=False)


async def _install_harvester() -> dict:
    uv = shutil.which("uv")
    git = shutil.which("git")
    if not git:
        return {"ok": False, "msg": "git is required to install theHarvester."}
    if not uv:
        return {"ok": False, "msg": (
            "theHarvester's current source requires Python >= 3.14. Install uv "
            "(curl -LsSf https://astral.sh/uv/install.sh | sh), then retry — uv "
            "provisions the right Python automatically.")}
    if (HARVESTER_DIR / ".git").exists():
        code, so, se = await run([git, "-C", str(HARVESTER_DIR), "pull", "--ff-only"],
                                 timeout=300, track=False)
    else:
        code, so, se = await run([git, "clone", "--depth", "1", HARVESTER_REPO,
                                  str(HARVESTER_DIR)], timeout=600, track=False)
    if code != 0:
        return {"ok": False, "msg": f"git failed: {(se or so)[-600:]}"}
    code, so, se = await run([uv, "sync", "--directory", str(HARVESTER_DIR)],
                             timeout=1200, track=False)
    if code != 0:
        return {"ok": False, "msg": f"uv sync failed: {(se or so)[-800:]}"}
    _HEALTH.pop("theHarvester", None)
    h = await health_check("theHarvester", force=True)
    return {"ok": h["state"] == "runnable", "msg": h["detail"] or "installed"}


async def install(name: str) -> dict:
    tool = _tool(name)
    if not tool:
        return {"ok": False, "msg": f"unknown tool {name}"}

    if tool.kind == "pip":
        await _ensure_venv()
        code, so, se = await run(
            [str(VENV_PY), "-m", "pip", "install", "-U", tool.spec],
            timeout=900, track=False)
        if code != 0:
            return {"ok": False, "msg": (se or so)[-800:]}
    elif tool.kind == "uv-git":
        return await _install_harvester()
    elif tool.kind == "go":
        ok, why = await go_check()
        if not ok:
            return {"ok": False, "msg": why}
        GO_BIN.mkdir(parents=True, exist_ok=True)
        code, so, se = await run([shutil.which("go"), "install", "-v", tool.spec],
                                 timeout=1500, env={"GOBIN": str(GO_BIN)},
                                 track=False)
        if code != 0:
            # Verbatim tail of go's error: usually a version/toolchain/network cause.
            return {"ok": False, "msg": (se or so)[-800:]}
    else:
        return {"ok": False,
                "msg": f"Install via your package manager, e.g. "
                       f"`sudo apt install {tool.spec}` (or `brew install exiftool`)."}

    _HEALTH.pop(name, None)
    h = await health_check(name, force=True)
    return {"ok": h["state"] == "runnable",
            "msg": f"{h['state']}: {h.get('detail', '')}"}


async def install_all() -> dict[str, dict]:
    results = {}
    for t in CATALOG:
        if which(t.name) and (await health_check(t.name))["state"] == "runnable":
            results[t.name] = {"ok": True, "msg": "already runnable"}
            continue
        results[t.name] = await install(t.name)
    return results
