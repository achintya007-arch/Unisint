"""User config + case storage under ~/.unisint.

Holds optional API keys and saved cases. Nothing here is required; every
key-gated adapter simply stays dormant until a key is present.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

HOME = Path(os.environ.get("UNISINT_HOME", Path.home() / ".unisint"))
CONFIG_PATH = HOME / "config.json"
TOOLS_DIR = HOME / "tools"
CASES_DIR = HOME / "cases"

DEFAULTS: dict[str, Any] = {
    "api_keys": {            # all optional
        "shodan": "",
        "hibp": "",
        "hunter": "",
        "virustotal": "",
        "anthropic": "",
        "brave": "",          # Brave Search API (web_search)
        "google_cse_key": "", # Google Programmable Search JSON API key
        "google_cse_cx": "",  # Programmable Search Engine ID
    },
    "searxng_url": "",       # your own SearXNG instance (JSON format enabled)
    # Allow link checks to hosts this machine can't resolve when a proxy is
    # configured (the proxy resolves them). Off by default: safer.
    "trust_proxy_resolution": False,
    "effects": True,         # UI eye-candy on by default
    "max_concurrency": 20,
}

SETTABLE = ("effects", "max_concurrency", "searxng_url", "trust_proxy_resolution")

# Credentials may come from the environment instead of the config file, so a
# key never has to be written to disk. Env values override the file and are
# NEVER persisted by save().
ENV_KEYS = {"brave": "UNISINT_BRAVE_API_KEY",
            "google_cse_key": "UNISINT_GOOGLE_CSE_KEY",
            "google_cse_cx": "UNISINT_GOOGLE_CSE_CX"}
ENV_SETTINGS = {"searxng_url": "UNISINT_SEARXNG_URL"}


def _ensure_dirs() -> None:
    for d in (HOME, TOOLS_DIR, CASES_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load(include_env: bool = True) -> dict[str, Any]:
    _ensure_dirs()
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    if CONFIG_PATH.exists():
        try:
            saved = json.loads(CONFIG_PATH.read_text())
            cfg["api_keys"].update(saved.get("api_keys", {}))
            for k in SETTABLE:
                if k in saved:
                    cfg[k] = saved[k]
        except (json.JSONDecodeError, OSError):
            pass
    sources = {k: ("file" if v else None) for k, v in cfg["api_keys"].items()}
    sources.update({k: ("file" if cfg.get(k) else None) for k in ENV_SETTINGS})
    if include_env:
        for k, var in ENV_KEYS.items():
            if os.environ.get(var):
                cfg["api_keys"][k] = os.environ[var].strip()
                sources[k] = "env"
        for k, var in ENV_SETTINGS.items():
            if os.environ.get(var):
                cfg[k] = os.environ[var].strip()
                sources[k] = "env"
    cfg["_sources"] = sources
    return cfg


def save(cfg: dict[str, Any]) -> None:
    _ensure_dirs()
    cfg = json.loads(json.dumps(cfg))
    srcs = cfg.pop("_sources", {}) or {}
    if any(v == "env" for v in srcs.values()):
        # Never write env-provided secrets: keep whatever the file had.
        disk = load(include_env=False)
        for k, v in srcs.items():
            if v != "env":
                continue
            if k in cfg.get("api_keys", {}):
                cfg["api_keys"][k] = disk["api_keys"].get(k, "")
            elif k in cfg:
                cfg[k] = disk.get(k, "")
    # Contains API keys: create/keep it readable by the owner only.
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(cfg, indent=2))
    os.chmod(CONFIG_PATH, 0o600)


def secrets(cfg: dict[str, Any]) -> list[str]:
    """Configured secret values (for log redaction)."""
    return [v for v in (cfg.get("api_keys") or {}).values()
            if isinstance(v, str) and len(v) >= 6]


def redact(text: str, cfg: dict[str, Any]) -> str:
    for s in secrets(cfg):
        text = text.replace(s, "***")
    return text


def api_key(name: str) -> str:
    return (load().get("api_keys", {}) or {}).get(name, "") or ""


def save_case(name: str, data: dict[str, Any]) -> Path:
    _ensure_dirs()
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "case"
    path = CASES_DIR / f"{safe}-{int(time.time())}.json"
    path.write_text(json.dumps(data, indent=2))
    return path


GAPS_PATH = HOME / "gaps.md"


def add_gap(what: str, missing: str, severity: str = "medium") -> dict[str, Any]:
    """Append a timestamped gap note to ~/.unisint/gaps.md."""
    _ensure_dirs()
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = (f"\n### {stamp} · {severity.upper()}\n"
             f"- **Tried:** {what.strip() or '(unspecified)'}\n"
             f"- **Missing / wrong:** {missing.strip() or '(unspecified)'}\n")
    if not GAPS_PATH.exists():
        GAPS_PATH.write_text("# UNISINT — gaps found while testing\n")
    with GAPS_PATH.open("a") as fh:
        fh.write(entry)
    return {"when": stamp, "what": what, "missing": missing,
            "severity": severity}


def list_gaps() -> dict[str, Any]:
    """Return the raw gaps markdown and a count."""
    if not GAPS_PATH.exists():
        return {"text": "", "count": 0, "path": str(GAPS_PATH)}
    text = GAPS_PATH.read_text()
    return {"text": text, "count": text.count("\n### "), "path": str(GAPS_PATH)}


def list_cases() -> list[dict[str, Any]]:
    _ensure_dirs()
    out = []
    for p in sorted(CASES_DIR.glob("*.json"), reverse=True):
        try:
            d = json.loads(p.read_text())
            out.append({"file": p.name, "target": d.get("target"),
                        "mode": d.get("mode"), "when": d.get("when")})
        except (json.JSONDecodeError, OSError):
            continue
    return out
