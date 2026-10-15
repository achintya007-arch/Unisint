"""FastAPI app: serves the console UI and streams a scan over a WebSocket."""
from __future__ import annotations

import asyncio
import json
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
    return JSONResponse({"api_keys_set": keys, "effects": cfg.get("effects"),
                         "searxng_url": cfg.get("searxng_url", ""),
                         "trust_proxy_resolution": cfg.get("trust_proxy_resolution", False),
                         "cases": config.list_cases()})


@app.post("/api/config")
async def set_config(payload: dict) -> JSONResponse:
    cfg = config.load()
    for k, v in (payload.get("api_keys") or {}).items():
        if v:  # only overwrite when a non-empty value is supplied
            cfg["api_keys"][k] = v
    if "effects" in payload:
        cfg["effects"] = bool(payload["effects"])
    if "searxng_url" in payload:
        u = str(payload["searxng_url"] or "").strip()
        cfg["searxng_url"] = u if u.startswith(("http://", "https://")) or not u else cfg["searxng_url"]
    if "trust_proxy_resolution" in payload:
        cfg["trust_proxy_resolution"] = bool(payload["trust_proxy_resolution"])
    config.save(cfg)
    return JSONResponse({"ok": True})


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
            ent = engine.add_entity(etype, t["value"], source="input",
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
