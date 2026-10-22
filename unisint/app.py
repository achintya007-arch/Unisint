"""FastAPI app: serves the console UI and streams a scan over a WebSocket."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from fastapi import FastAPI, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import base, config, toolmanager
from .detect import detect
from .engine import Engine
from .pivot import Limits
from .models import EntityType
from .runner import tmp_dir
from .synthesis import build_dossier

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="UNISINT")
base.load_all()

PRESETS = {
    "quick": {"depth": 1, "weight_cap": 1, "time_budget": 90,
              "max_entities": 150, "per_module_runs": 15},
    "standard": {"depth": 2, "weight_cap": 2, "time_budget": 240,
                 "max_entities": 400, "per_module_runs": 40},
    "deep": {"depth": 2, "weight_cap": 3, "time_budget": 480,
             "max_entities": 800, "per_module_runs": 80},
}


@app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text())


@app.get("/api/arsenal")
async def arsenal() -> JSONResponse:
    mods = []
    cfg = config.load()
    eng_stub = type("S", (), {"config": cfg})()
    for m in base.all_modules():
        ok, why = await m.available(eng_stub)
        mods.append({"name": m.name, "label": m.label, "category": m.category,
                     "modes": sorted(m.modes), "weight": m.weight,
                     "available": ok, "why": why,
                     "needs_tool": m.requires_tool, "needs_key": m.requires_key})
    await toolmanager.health_all()          # cached; cheap after first call
    return JSONResponse({"tools": toolmanager.status(), "modules": mods})


@app.post("/api/health")
async def recheck_health() -> JSONResponse:
    await toolmanager.health_all(force=True)
    return JSONResponse({"tools": toolmanager.status()})


@app.post("/api/install/{name}")
async def install_tool(name: str) -> JSONResponse:
    res = await toolmanager.install(name)
    return JSONResponse(res)


@app.get("/api/config")
async def get_config() -> JSONResponse:
    cfg = config.load()
    # Mask key presence, never return the secrets themselves.
    keys = {k: bool(v) for k, v in cfg.get("api_keys", {}).items()}
    sources = cfg.get("_sources", {})
    return JSONResponse({"api_keys_set": keys, "effects": cfg.get("effects"),
                         "key_sources": {k: sources.get(k) for k in keys},
                         "searxng_url": cfg.get("searxng_url", ""),
                         "searxng_source": sources.get("searxng_url"),
                         "trust_proxy_resolution": cfg.get("trust_proxy_resolution", False),
                         "cases": config.list_cases()})


@app.post("/api/config")
async def set_config(payload: dict) -> JSONResponse:
    cfg = config.load(include_env=False)   # never round-trip env secrets
    for k, v in (payload.get("api_keys") or {}).items():
        if k in cfg["api_keys"] and isinstance(v, str) and v.strip():
            cfg["api_keys"][k] = v.strip()
    for k in payload.get("clear_keys") or []:
        if k in cfg["api_keys"]:
            cfg["api_keys"][k] = ""
    if "effects" in payload:
        cfg["effects"] = bool(payload["effects"])
    if "searxng_url" in payload:
        u = str(payload["searxng_url"] or "").strip()
        cfg["searxng_url"] = u if u.startswith(("http://", "https://")) or not u else cfg["searxng_url"]
    if "trust_proxy_resolution" in payload:
        cfg["trust_proxy_resolution"] = bool(payload["trust_proxy_resolution"])
    config.save(cfg)
    return JSONResponse({"ok": True})


@app.post("/api/dossier")
async def dossier_preview(payload: dict) -> JSONResponse:
    """Build a dossier from a (live, partial) snapshot. The UI uses this so the
    server remains the single dossier builder for display and export."""
    snap = {"mode": payload.get("mode", "self"),
            "entities": payload.get("entities") or [],
            "pivots": payload.get("pivots") or [],
            "scope": payload.get("scope"),
            "module_status": payload.get("module_status") or {}}
    return JSONResponse(build_dossier(snap))


@app.post("/api/export/{fmt}")
async def export(fmt: str, payload: dict):
    from fastapi.responses import Response

    from .report import render_csv, render_html
    d = payload.get("dossier") or {}
    if fmt == "csv":
        return Response(render_csv(d), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=unisint-evidence.csv"})
    if fmt == "html":
        return Response(render_html(d), media_type="text/html",
                        headers={"Content-Disposition": "attachment; filename=unisint-dossier.html"})
    return JSONResponse({"error": "unknown format"}, status_code=400)


@app.post("/api/gap")
async def report_gap(payload: dict) -> JSONResponse:
    rec = config.add_gap(
        payload.get("what", ""), payload.get("missing", ""),
        payload.get("severity", "medium"))
    return JSONResponse({"ok": True, "gap": rec, **config.list_gaps()})


@app.get("/api/gaps")
async def get_gaps() -> JSONResponse:
    return JSONResponse(config.list_gaps())


@app.post("/api/detect")
async def detect_type(payload: dict) -> JSONResponse:
    val = payload.get("value", "")
    return JSONResponse({"type": detect(val).value})


@app.post("/api/plan")
async def plan(payload: dict) -> JSONResponse:
    """Preview what a run would do: which modules run / need credentials /
    are unavailable / do active probing, for the given targets + preset."""
    from .planner import build_plan
    targets = payload.get("targets") or ([payload["value"]] if payload.get("value") else [])
    mode = payload.get("mode", base.MODE_SELF)
    if mode not in (base.MODE_SELF, base.MODE_RECON):
        mode = base.MODE_SELF
    preset = PRESETS.get(payload.get("preset", "standard"), PRESETS["standard"])
    return JSONResponse(await build_plan(targets, mode, weight_cap=preset["weight_cap"],
                                         config=config.load()))


@app.post("/api/rerun-source")
async def rerun_source(payload: dict) -> JSONResponse:
    """Re-run ONE module against the original seed targets (depth 0) and return
    the entities it produced plus its source-run status. The UI merges these
    into the live snapshot and re-renders via /api/dossier — no full re-scan."""
    name = str(payload.get("module", "")).strip()
    mod = next((m for m in base.all_modules() if m.name == name), None)
    if not mod:
        return JSONResponse({"error": f"unknown module: {name}"}, status_code=400)
    mode = payload.get("mode", base.MODE_SELF)
    if mode not in (base.MODE_SELF, base.MODE_RECON):
        mode = base.MODE_SELF
    targets = payload.get("targets") or ([payload["value"]] if payload.get("value") else [])
    if not targets:
        return JSONResponse({"error": "no targets"}, status_code=400)

    events: list[dict] = []

    async def emit(p: dict) -> None:
        events.append(p)

    # Let the one module run regardless of the preset's depth tier; cap the
    # run to its seeds (depth 0) so a retry never fans out into a new scan.
    engine = Engine(mode=mode, config=config.load(), emit=emit,
                    weight_cap=max(mod.weight, 1),
                    limits=Limits(depth=0, time_budget=120),
                    only_modules={name})
    for t in targets:
        if isinstance(t, dict):
            try:
                etype = EntityType(t["type"])
            except (KeyError, ValueError):
                continue
            engine.add_entity(etype, t["value"], source="input",
                              meta={"path": t.get("path")} if t.get("path") else {})
        else:
            engine.add_entity(detect(t), t, source="input")
    await engine.run()

    snap = engine.snapshot()
    produced = [e for e in snap["entities"] if e.get("source") != "input"]
    status = engine.module_status.get(
        name, {"state": "skipped", "label": mod.label, "category": mod.category,
               "active": bool(mod.active),
               "last_error": "module did not accept any of the given targets"})
    return JSONResponse({"module": name, "status": status, "entities": produced})


@app.post("/api/upload")
async def upload(file: UploadFile) -> JSONResponse:
    dest = tmp_dir("uploads") / f"{int(time.time())}-{file.filename}"
    dest.write_bytes(await file.read())
    return JSONResponse({"path": str(dest), "name": file.filename})


@app.websocket("/ws")
async def ws(sock: WebSocket) -> None:
    await sock.accept()
    try:
        req = await sock.receive_json()
    except Exception:
        await sock.close()
        return

    mode = req.get("mode", base.MODE_SELF)
    if mode not in (base.MODE_SELF, base.MODE_RECON):
        mode = base.MODE_SELF
    preset = PRESETS.get(req.get("preset", "standard"), PRESETS["standard"])
    cfg = config.load()

    if not req.get("authorized"):
        await sock.send_json({"type": "log", "level": "err",
                              "msg": "authorization not confirmed; aborting"})
        await sock.close()
        return

    async def emit(payload: dict) -> None:
        try:
            await sock.send_json(payload)
        except Exception:
            pass

    limits = Limits(depth=preset["depth"], time_budget=preset["time_budget"],
                    max_entities=preset["max_entities"],
                    per_module_runs=preset["per_module_runs"],
                    validate_links=bool(req.get("validate_links")))
    engine = Engine(mode=mode, config=cfg, emit=emit, limits=limits,
                    weight_cap=preset["weight_cap"],
                    concurrency=cfg.get("max_concurrency", 20))

    # Seed inputs.
    targets = req.get("targets", [])
    if isinstance(targets, str):
        targets = [targets]
    for t in targets:
        if isinstance(t, dict):  # {"type":..,"value":..,"path":..}
            etype = EntityType(t["type"])
            engine.add_entity(etype, t["value"], source="input",
                                    confidence=1.0,
                                    meta={"path": t.get("path")} if t.get("path") else {})
        else:
            engine.add_entity(detect(t), t, source="input", confidence=1.0)

    # Allow a cancel message to arrive concurrently.
    async def listen_cancel() -> None:
        try:
            while True:
                msg = await sock.receive_json()
                if msg.get("action") == "cancel":
                    engine.cancel()
                    return
        except (WebSocketDisconnect, Exception):
            engine.cancel()

    cancel_task = asyncio.create_task(listen_cancel())
    try:
        await engine.run()
    except Exception:
        # A disconnect or runtime error must not lose what was found so far.
        engine.cancel()
    finally:
        cancel_task.cancel()
        # Build + persist whatever the engine collected, even on a drop/cancel.
        snap = engine.snapshot()
        snap["target"] = targets
        snap["mode"] = mode
        dossier = build_dossier(snap)
        await emit({"type": "dossier", "dossier": dossier})

        label = (targets[0] if targets else "case")
        label = label.get("value") if isinstance(label, dict) else str(label)
        try:
            config.save_case(label, {**snap, "dossier": dossier})
        except Exception:
            pass
        try:
            await sock.close()
        except Exception:
            pass


app.mount("/", StaticFiles(directory=str(STATIC)), name="static")
