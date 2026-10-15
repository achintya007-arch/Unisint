"""`unisint doctor` — a self-check that maps what works and what's missing.

Prints OK/WARN/FAIL lines for the Python runtime, every registered module,
every wrapped tool, and live reachability of the key public endpoints the
native modules use. Writes the same report to ~/.unisint/doctor-report.txt so
it's easy to paste back when reporting gaps.
"""
from __future__ import annotations

import asyncio
import platform
import sys

from . import base, config, toolmanager

# Endpoints the native keyless modules depend on. Reachability here predicts
# whether a real scan will return results on this network.
ENDPOINTS = [
    ("GitHub API", "https://api.github.com"),
    ("GitLab API", "https://gitlab.com/api/v4/version"),
    ("Gravatar", "https://en.gravatar.com/"),
    ("Reddit", "https://www.reddit.com/user/reddit/about.json"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames=max"),
    ("crt.sh", "https://crt.sh/?q=example.com&output=json"),
    ("Shodan InternetDB", "https://internetdb.shodan.io/8.8.8.8"),
    ("ip-api", "http://ip-api.com/json/8.8.8.8"),
    ("RDAP", "https://rdap.org/domain/example.com"),
    ("Wayback", "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1"),
]

OK, WARN, FAIL = "OK  ", "WARN", "FAIL"


class _Stub:
    """Minimal stand-in so Module.available() can read config without an Engine."""

    def __init__(self) -> None:
        self.config = config.load()


def _line(status: str, label: str, detail: str = "") -> str:
    return f"  [{status}] {label}" + (f" — {detail}" if detail else "")


async def _check_endpoints() -> list[tuple[str, str, str]]:
    import httpx

    out: list[tuple[str, str, str]] = []
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True,
                                 headers={"User-Agent": "UNISINT-doctor/1.0"}) as cx:
        async def one(name: str, url: str) -> tuple[str, str, str]:
            try:
                r = await cx.get(url)
                if r.status_code < 400:
                    return (OK, name, f"HTTP {r.status_code}")
                return (WARN, name, f"HTTP {r.status_code}")
            except Exception as exc:
                return (FAIL, name, type(exc).__name__)
        out = await asyncio.gather(*(one(n, u) for n, u in ENDPOINTS))
    return list(out)


async def _run() -> tuple[str, dict[str, int]]:
    lines: list[str] = []
    tally = {"ok": 0, "warn": 0, "fail": 0}

    def rec(status: str, label: str, detail: str = "") -> None:
        lines.append(_line(status, label, detail))
        if status == OK:
            tally["ok"] += 1
        elif status == WARN:
            tally["warn"] += 1
        else:
            tally["fail"] += 1

    lines.append("UNISINT DOCTOR")
    lines.append("=" * 48)

    # Runtime
    lines.append("\n[ RUNTIME ]")
    pyver = sys.version_info
    if pyver >= (3, 10):
        rec(OK, f"Python {platform.python_version()}")
    else:
        rec(FAIL, f"Python {platform.python_version()}", "need >= 3.10")
    rec(OK, f"Platform {platform.system()} {platform.release()}")

    # Modules
    base.load_all()
    stub = _Stub()
    lines.append("\n[ MODULES ]")
    mods = sorted(base.all_modules(), key=lambda m: (m.category, m.name))
    for m in mods:
        ok, why = await m.available(stub)
        rec(OK if ok else WARN, f"{m.label} ({m.category})",
            "ready" if ok else why)

    # Wrapped tools
    lines.append("\n[ WRAPPED TOOLS ]  (health-checked, not just 'file exists')")
    await toolmanager.health_all(force=True)
    for t in toolmanager.status():
        st, det = t["state"], t["detail"]
        if st in ("runnable", "operational"):
            rec(OK, t["label"], f"{st} — {det}" if det else st)
        elif st == "unavailable":
            rec(WARN, t["label"], f"not installed — ARSENAL or install_tools.sh ({t['kind']})")
        else:
            rec(FAIL, t["label"], f"{st} — {det}")
    for t in toolmanager.CATALOG:
        if t.kind == "go":
            ok, why = await toolmanager.go_check(t.name)
            rec(OK if ok else WARN, f"Go for {t.label} {t.spec.rsplit('@', 1)[-1]}", why)
    import shutil as _sh
    rec(OK if _sh.which("uv") else WARN, "uv (for theHarvester, needs Python 3.14)",
        "found" if _sh.which("uv") else "not found — https://docs.astral.sh/uv/")

    # Search providers (configuration only; `unisint search-test` runs a query)
    lines.append("\n[ SEARCH PROVIDERS ]")
    from .search import configured_providers
    cfg = config.load()
    provs = configured_providers(cfg)
    if provs:
        for p in provs:
            rec(OK, f"{p.name} configured", "run `unisint search-test example.com` to verify live")
    else:
        rec(WARN, "no web-search provider configured",
            "set UNISINT_BRAVE_API_KEY, or UNISINT_GOOGLE_CSE_KEY+_CX, or UNISINT_SEARXNG_URL")

    # Network
    lines.append("\n[ NETWORK REACHABILITY ]")
    for status, name, detail in await _check_endpoints():
        rec(status, name, detail)

    lines.append("\n" + "=" * 48)
    lines.append(f"SUMMARY: {tally['ok']} OK · {tally['warn']} WARN · "
                 f"{tally['fail']} FAIL")
    return "\n".join(lines), tally


def run() -> int:
    """Entry point for `unisint doctor`. Returns a process exit code."""
    report, tally = asyncio.run(_run())
    print(report)
    try:
        config._ensure_dirs()
        path = config.HOME / "doctor-report.txt"
        path.write_text(report)
        print(f"\nReport written to {path}")
    except Exception:
        pass
    return 1 if tally["fail"] else 0
