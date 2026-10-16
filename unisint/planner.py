"""Investigation plan: what will actually run for a given input, before ENGAGE.

Pure-ish (only calls ``Module.available`` which may check installed tools/keys)
so the UI can preview a run: which modules will run, which need credentials or
a tool, which are unavailable, which are active probes limited to authorized
scope, and which the chosen preset skips. The same data the engine uses to
dispatch (``base.modules_for`` + ``Module.available`` + the scope policy) drives
this, so the preview cannot drift from the real run.
"""
from __future__ import annotations

from typing import Any

from . import base
from .detect import detect
from .models import Entity, EntityType
from .scope import ScopePolicy

# status vocabulary for a planned module
WILL_RUN = "will_run"
NEEDS_CREDENTIALS = "needs_credentials"
UNAVAILABLE = "unavailable"
SKIPPED_PRESET = "skipped_preset"
NEEDS_AUTHORIZATION = "needs_authorization"


class _Stub:
    def __init__(self, cfg: dict):
        self.config = cfg


async def plan_for_target(value: str, etype: EntityType, mode: str, *,
                          weight_cap: int, config: dict,
                          scope: ScopePolicy) -> dict[str, Any]:
    stub = _Stub(config)
    seed = Entity(type=etype, value=value, basis="seed")
    modules = []
    for m in base.modules_for(etype, mode):
        active = bool(getattr(m, "active", False))
        ok, why = await m.available(stub)
        needs_creds = bool(m.requires_key) or any(
            w in why.lower() for w in ("api key", "provider", "configured",
                                       "cx", "credential", "searxng"))
        if m.weight > weight_cap:
            status, detail = SKIPPED_PRESET, f"heavier than this preset (weight {m.weight})"
        elif not ok and needs_creds:
            status, detail = NEEDS_CREDENTIALS, why
        elif not ok:
            status, detail = UNAVAILABLE, why
        elif active and not scope.classify(seed).allow_active:
            status, detail = NEEDS_AUTHORIZATION, (
                "active probe — only runs on assets you are authorized to test")
        else:
            status, detail = WILL_RUN, ("active probe on your authorized target"
                                        if active else "ready")
        modules.append({
            "name": m.name, "label": m.label, "category": m.category,
            "active": active, "passive": not active,
            "needs_tool": m.requires_tool, "needs_key": m.requires_key,
            "weight": m.weight, "status": status, "detail": detail,
        })
    modules.sort(key=lambda x: (x["category"], x["name"]))
    return {"value": value, "type": etype.value, "modules": modules}


async def build_plan(targets: list[str], mode: str, *, weight_cap: int,
                     config: dict) -> dict[str, Any]:
    """Build the full plan for one or more seed inputs."""
    base.load_all()
    scope = ScopePolicy(mode=mode)
    parsed: list[tuple[str, EntityType]] = []
    for t in targets:
        if isinstance(t, dict):               # image upload {type,value,path}
            etype = EntityType(t.get("type", "image"))
            val = t.get("value", "")
        else:
            val = str(t)
            etype = detect(val)
        parsed.append((val, etype))
        scope.add_seed(Entity(type=etype, value=val, basis="seed"))

    target_plans = [await plan_for_target(v, et, mode, weight_cap=weight_cap,
                                          config=config, scope=scope)
                    for v, et in parsed]
    counts: dict[str, int] = {}
    for tp in target_plans:
        for m in tp["modules"]:
            counts[m["status"]] = counts.get(m["status"], 0) + 1
    return {"mode": mode, "targets": target_plans, "counts": counts,
            "authorized": sorted(scope.domains | scope.ips)}
