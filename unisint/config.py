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
    },
    "effects": True,         # UI eye-candy on by default
    "max_concurrency": 20,
}


def _ensure_dirs() -> None:
    for d in (HOME, TOOLS_DIR, CASES_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load() -> dict[str, Any]:
    _ensure_dirs()
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    if CONFIG_PATH.exists():
        try:
            saved = json.loads(CONFIG_PATH.read_text())
            cfg["api_keys"].update(saved.get("api_keys", {}))
            for k in ("effects", "max_concurrency"):
                if k in saved:
                    cfg[k] = saved[k]
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save(cfg: dict[str, Any]) -> None:
    _ensure_dirs()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def api_key(name: str) -> str:
    return (load().get("api_keys", {}) or {}).get(name, "") or ""


def save_case(name: str, data: dict[str, Any]) -> Path:
    _ensure_dirs()
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "case"
    path = CASES_DIR / f"{safe}-{int(time.time())}.json"
    path.write_text(json.dumps(data, indent=2))
    return path


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
