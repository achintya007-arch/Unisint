"""Investigation engine: queue, de-dup, auto-pivot, streaming.

The engine holds an entity graph, dispatches each new entity to every module
that accepts it (respecting scan mode + depth), and streams events through an
async callback so the web UI can render them live.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

import httpx

from . import base
from .base import Context, Module
from .models import Entity, EntityType, Link

EventCb = Callable[[dict[str, Any]], Awaitable[None]]

USER_AGENT = "UNISINT/1.0 (+authorized-self-audit)"


class Engine:
    def __init__(
        self,
        *,
        mode: str,
        config: dict[str, Any],
        emit: EventCb,
        max_depth: int = 2,
        weight_cap: int = 3,
        concurrency: int = 20,
    ):
        self.mode = mode
        self.config = config
        self._emit = emit
        self.max_depth = max_depth
        self.weight_cap = weight_cap

        self.entities: dict[tuple[str, str], Entity] = {}
        self.links: list[Link] = []
        self.logs: list[dict] = []

        self._queue: asyncio.Queue[Entity] = asyncio.Queue()
        self._seen_jobs: set[tuple[str, str, str]] = set()
        self._sem = asyncio.Semaphore(concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._cancelled = False
        self._pending = 0

        self.http = httpx.AsyncClient(
            timeout=20.0,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    # ---- event helpers -------------------------------------------------
    def emit_log(self, msg: str, *, level: str = "info", module: str = "") -> None:
        rec = {"t": time.time(), "msg": msg, "level": level, "module": module}
        self.logs.append(rec)
        self._schedule({"type": "log", **rec})

    def _schedule(self, payload: dict) -> None:
        # Fire-and-forget emit; keep ordering best-effort.
        task = asyncio.create_task(self._emit(payload))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ---- graph ---------------------------------------------------------
    def add_entity(
        self,
        etype: EntityType,
        value: str,
        *,
        source: str,
        confidence: float = 0.5,
        parent: Entity | None = None,
        rel: str = "related",
        meta: dict | None = None,
    ) -> Entity | None:
        value = (value or "").strip()
        if not value:
            return None
        ent = Entity(
            type=etype, value=value, source=source,
            confidence=confidence, meta=meta or {},
            depth=(parent.depth + 1) if parent else 0,
        )
        existing = self.entities.get(ent.key)
        if existing:
            # Merge: raise confidence when corroborated by a new source.
            if source not in existing.meta.get("sources", []):
                existing.meta.setdefault("sources", []).append(source)
                existing.confidence = min(
                    1.0, existing.confidence + 0.15 * confidence + 0.05
                )
                self._schedule({"type": "entity", "entity": existing.to_dict()})
            if parent:
                self._add_link(parent.id, existing.id, rel, source)
            return existing

        ent.meta.setdefault("sources", [source])
        self.entities[ent.key] = ent
        self._schedule({"type": "entity", "entity": ent.to_dict()})
        if parent:
            self._add_link(parent.id, ent.id, rel, source)

        # Queue for pivoting unless it exceeds depth.
        if ent.depth <= self.max_depth:
            self._queue.put_nowait(ent)
            self._pending += 1
        return ent

    def _add_link(self, src: str, dst: str, rel: str, source: str) -> None:
        link = Link(src=src, dst=dst, rel=rel, source=source)
        self.links.append(link)
        self._schedule({"type": "link", "link": link.to_dict()})

    # ---- main loop -----------------------------------------------------
    async def seed(self, etype: EntityType, value: str) -> None:
        self.add_entity(etype, value, source="input", confidence=1.0)

    async def run(self) -> None:
        self.emit_log(f"engine online — mode={self.mode} depth={self.max_depth}",
                      level="ok")
        workers = [asyncio.create_task(self._worker(i)) for i in range(8)]
        # Wait until queue drained and all jobs done.
        while self._pending > 0 and not self._cancelled:
            await asyncio.sleep(0.1)
        for w in workers:
            w.cancel()
        # let pending emits flush
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        await self.http.aclose()
        self.emit_log("scan complete", level="ok")
        self._schedule({"type": "done",
                        "entities": len(self.entities),
                        "links": len(self.links)})
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def _worker(self, idx: int) -> None:
        while not self._cancelled:
            try:
                ent = await asyncio.wait_for(self._queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            try:
                await self._dispatch(ent)
            finally:
                self._pending -= 1
                self._queue.task_done()

    async def _dispatch(self, ent: Entity) -> None:
        mods = [
            m for m in base.modules_for(ent.type, self.mode)
            if m.weight <= self.weight_cap
        ]
        if not mods:
            return
        await asyncio.gather(*(self._run_module(m, ent) for m in mods))

    async def _run_module(self, mod: Module, ent: Entity) -> None:
        job = (mod.name, ent.type.value, ent.value.lower())
        if job in self._seen_jobs:
            return
        self._seen_jobs.add(job)

        ok, why = await mod.available(self)
        if not ok:
            self.emit_log(f"[{mod.label}] skip ({why})", level="warn",
                          module=mod.name)
            return

        async with self._sem:
            if self._cancelled:
                return
            self.emit_log(f"[{mod.label}] -> {ent.type}:{ent.value}",
                          level="run", module=mod.name)
            # Mark entity source so emitted children attribute correctly.
            probe = Entity(type=ent.type, value=ent.value, source=mod.name,
                           confidence=ent.confidence, depth=ent.depth,
                           id=ent.id, meta=ent.meta)
            ctx = Context(self, probe)
            try:
                await mod.run(ctx)
            except Exception as exc:  # modules must never crash the engine
                self.emit_log(f"[{mod.label}] error: {exc}", level="err",
                              module=mod.name)

    def cancel(self) -> None:
        self._cancelled = True
        self.emit_log("cancel requested", level="warn")

    # ---- export --------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return {
            "entities": [e.to_dict() for e in self.entities.values()],
            "links": [l.to_dict() for l in self.links],
            "logs": self.logs,
            "mode": self.mode,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
