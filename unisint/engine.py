"""Investigation engine: queue, de-dup with provenance, bounded pivots, streaming.

Flow: seeds → queue → for each entity, ``pivot.decide`` picks which modules may
run (with a recorded reason) → modules emit observations → observations are
merged (provenance kept, never overwritten) → optional link validation →
snapshot for the dossier.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

import httpx

from . import base, pivot
from .base import Context, Module
from .models import Basis, Entity, EntityType, Link
from .pivot import Limits
from .scope import ScopePolicy

EventCb = Callable[[dict[str, Any]], Awaitable[None]]

USER_AGENT = "UNISINT/2.0 (+public-source research)"

# Heuristic sort weight per basis — for ordering only, never shown as a
# probability. Corroboration is reported as a count of independent sources.
BASIS_WEIGHT = {"seed": 1.0, "observed": 0.6, "derived": 0.4, "candidate": 0.25}
BASIS_RANK = {"candidate": 0, "derived": 1, "observed": 2, "seed": 3}

# The full source-run status vocabulary surfaced to the UI/dossier.
SOURCE_STATES = ("ok", "empty", "partial", "error", "blocked", "rate_limited",
                 "auth_error", "unavailable", "not_configured", "timeout",
                 "skipped")
_EXPLICIT_STATES = {"blocked", "rate_limited", "auth_error", "not_configured",
                    "timeout", "skipped"}


def _refine_status(derived: str, explicit: str | None, st: dict) -> str:
    """Pick the source-run status. An explicit status a module set wins over
    the derived ok/empty/partial/error — unless some run of the module produced
    findings (then it genuinely succeeded)."""
    if explicit in _EXPLICIT_STATES and not st.get("ok"):
        return explicit
    return derived


class Engine:
    def __init__(
        self,
        *,
        mode: str,
        config: dict[str, Any],
        emit: EventCb,
        limits: Limits | None = None,
        weight_cap: int = 3,
        concurrency: int = 20,
        max_depth: int | None = None,      # back-compat
        http: httpx.AsyncClient | None = None,
        safe_http: httpx.AsyncClient | None = None,
        only_modules: set[str] | None = None,
    ):
        self.mode = mode
        self.config = config
        self._emit = emit
        self.limits = limits or Limits()
        if max_depth is not None:
            self.limits.depth = max_depth
        self.weight_cap = weight_cap
        # When set, only these module names may run (used by single-source
        # re-run, so one failed/partial source can be retried without a
        # full re-scan). None = every module that accepts the entity.
        self.only_modules = only_modules
        self.scope = ScopePolicy(mode=self.mode)

        self.entities: dict[tuple[str, str], Entity] = {}
        self.by_id: dict[str, Entity] = {}
        self.links: list[Link] = []
        self.logs: list[dict] = []
        self.pivots: list[dict] = []
        self.module_runs: dict[str, int] = {}
        self.module_status: dict[str, dict] = {}

        self._queue: asyncio.Queue[Entity] = asyncio.Queue()
        self._seen_jobs: set[tuple[str, str]] = set()
        self._sem = asyncio.Semaphore(concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._cancelled = False
        self._pending = 0
        self._cap_logged = False
        self._backlog: list[dict] = []
        self.started = time.time()

        self.http = http or httpx.AsyncClient(
            timeout=20.0, follow_redirects=True,
            headers={"User-Agent": USER_AGENT})
        self._safe_http = safe_http

    @property
    def safe_http(self) -> httpx.AsyncClient:
        """SSRF-guarded client for any user/target-controlled destination."""
        if self._safe_http is None:
            from .urls import make_safe_client
            self._safe_http = make_safe_client()
        return self._safe_http

    @property
    def max_depth(self) -> int:  # back-compat for older callers
        return self.limits.depth

    # ---- event helpers -------------------------------------------------
    def emit_log(self, msg: str, *, level: str = "info", module: str = "") -> None:
        from .config import redact
        msg = redact(str(msg), self.config)
        rec = {"t": time.time(), "msg": msg, "level": level, "module": module}
        self.logs.append(rec)
        self._schedule({"type": "log", **rec})

    def _schedule(self, payload: dict) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # Seeded before the loop started: buffer, flushed by run().
            self._backlog.append(payload)
            return
        task = asyncio.create_task(self._emit(payload))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _emit_entity(self, ent: Entity) -> None:
        self._schedule({"type": "entity", "entity": ent.to_dict()})

    # ---- graph ---------------------------------------------------------
    def add_entity(
        self,
        etype: EntityType,
        value: str,
        *,
        source: str,
        confidence: float | None = None,     # ignored beyond back-compat
        parent: Entity | None = None,
        rel: str = "related",
        meta: dict | None = None,
        basis: str | None = None,
        provenance: dict | None = None,
    ) -> Entity | None:
        value = (value or "").strip()
        if not value:
            return None
        meta = dict(meta or {})
        if basis is None:
            basis = Basis.SEED.value if (parent is None and source == "input") \
                else Basis.OBSERVED.value
        prov = {
            "source": source,
            "observed_at": time.time(),
            "parent_id": parent.id if parent else None,
            "parent_value": parent.value if parent else None,
            "parent_type": parent.type.value if parent else None,
            "rel": rel,
            "source_url": meta.get("url") or None,
        }
        prov.update(provenance or {})

        ent = Entity(type=etype, value=value, source=source, meta=meta,
                     depth=(parent.depth + 1) if parent else 0, basis=basis,
                     confidence=BASIS_WEIGHT.get(basis, 0.5),
                     provenance=[prov])
        existing = self.entities.get(ent.key)
        if existing:
            self._merge(existing, ent, prov)
            if parent:
                self._add_link(parent.id, existing.id, rel, source, basis)
            return existing

        if len(self.entities) >= self.limits.max_entities:
            if not self._cap_logged:
                self._cap_logged = True
                self.emit_log(f"entity cap {self.limits.max_entities} reached — "
                              "further results dropped (partial investigation)",
                              level="warn")
            return None

        ent.meta.setdefault("sources", [source])
        self.entities[ent.key] = ent
        self.by_id[ent.id] = ent
        if parent is None and basis == Basis.SEED.value:
            ent.meta.setdefault("identity_link", "seed")
            self.scope.add_seed(ent)
        # An IP a *seeded* host resolves to is authorized for active probing;
        # a third-party host discovered via a pivot does not drag its IP in.
        if etype == EntityType.IP and rel == "resolves_to" and parent:
            self.scope.authorize_resolved_ip(value, parent)
        self._emit_entity(ent)
        if parent:
            self._add_link(parent.id, ent.id, rel, source, basis)
        self._queue.put_nowait(ent)
        self._pending += 1
        return ent

    def _merge(self, existing: Entity, new: Entity, prov: dict) -> None:
        """Merge a repeat observation without losing earlier provenance."""
        changed = False
        sources = existing.meta.setdefault("sources", [existing.source])
        if new.source not in sources:
            sources.append(new.source)
            existing.provenance.append(prov)
            changed = True
        if BASIS_RANK.get(new.basis, 0) > BASIS_RANK.get(existing.basis, 0):
            existing.basis = new.basis
            existing.confidence = BASIS_WEIGHT[new.basis]
            changed = True
        # Keep the strongest identity link seen.
        order = ["", "weak", "handle_match", "handle_profile", "handle_proof",
                 "profile", "proof", "seed"]
        old_l = existing.meta.get("identity_link", "")
        new_l = new.meta.get("identity_link", "")
        if new_l in order and order.index(new_l) > (order.index(old_l) if old_l in order else 0):
            existing.meta["identity_link"] = new_l
            changed = True
        for k, v in new.meta.items():
            if k not in existing.meta and v not in (None, "", []):
                existing.meta[k] = v
                changed = True
        if changed:
            self._emit_entity(existing)

    def _add_link(self, src: str, dst: str, rel: str, source: str, basis: str) -> None:
        if src == dst:
            return
        for l in self.links:
            if l.src == src and l.dst == dst and l.rel == rel and l.source == source:
                return
        link = Link(src=src, dst=dst, rel=rel, source=source, basis=basis)
        self.links.append(link)
        self._schedule({"type": "link", "link": link.to_dict()})

    # ---- main loop -----------------------------------------------------
    async def seed(self, etype: EntityType, value: str) -> None:
        self.add_entity(etype, value, source="input")

    async def run(self) -> None:
        backlog, self._backlog = self._backlog, []
        for payload in backlog:
            self._schedule(payload)
        L = self.limits
        self.emit_log(f"engine online — mode={self.mode} depth={L.depth} "
                      f"budget={int(L.time_budget)}s cap={L.max_entities}",
                      level="ok")
        deadline = time.monotonic() + L.time_budget
        workers = [asyncio.create_task(self._worker(i)) for i in range(8)]
        try:
            while self._pending > 0 and not self._cancelled:
                if time.monotonic() > deadline:
                    self.emit_log("time budget exhausted — stopping with partial "
                                  "results", level="warn")
                    self._cancelled = True
                    break
                await asyncio.sleep(0.1)
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        if L.validate_links and not self._user_cancelled:
            await self.validate_links()
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        await self.http.aclose()
        if self._safe_http is not None:
            await self._safe_http.aclose()
        self.emit_log("scan complete", level="ok")
        self._schedule({"type": "done", "entities": len(self.entities),
                        "links": len(self.links)})
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    _user_cancelled = False

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
        mods = [m for m in base.modules_for(ent.type, self.mode)
                if m.weight <= self.weight_cap
                and (self.only_modules is None or m.name in self.only_modules)]
        if not mods:
            return
        run, skipped = [], []
        for m in mods:
            ok, reason = pivot.decide(ent, m, mode=self.mode, limits=self.limits,
                                      scope=self.scope, module_runs=self.module_runs)
            (run if ok else skipped).append((m, reason))
        record = {
            "entity_id": ent.id, "entity": f"{ent.type.value}:{ent.value}",
            "parent_id": (ent.provenance[0].get("parent_id") if ent.provenance else None),
            "basis": ent.basis, "depth": ent.depth, "t": time.time(),
            "ran": [{"module": m.name, "reason": r} for m, r in run],
            "skipped": [{"module": m.name, "reason": r} for m, r in skipped],
        }
        self.pivots.append(record)
        self._schedule({"type": "pivot", "pivot": record})
        if skipped and not run:
            self.emit_log(f"not expanded {ent.type.value}:{ent.value} — "
                          f"{skipped[0][1]}", level="muted")
        await asyncio.gather(*(self._run_module(m, ent) for m, _ in run))

    async def _run_module(self, mod: Module, ent: Entity) -> None:
        job = (mod.name, f"{ent.type.value}:{ent.key[1]}")
        if job in self._seen_jobs:
            return
        self._seen_jobs.add(job)

        ok, why = await mod.available(self)
        if not ok:
            needs_creds = any(w in why.lower() for w in (
                "api key", "provider", "configured", "cx", "credential", "searxng"))
            self.module_status[mod.name] = {
                "state": "not_configured" if needs_creds else "unavailable",
                "last_error": why, "label": mod.label, "category": mod.category,
                "active": bool(mod.active), "contacted": False, "live": True,
                "findings": 0, "runs": 0, "target_type": ent.type.value}
            self.emit_log(f"[{mod.label}] skip ({why})", level="warn",
                          module=mod.name)
            return

        async with self._sem:
            if self._cancelled:
                return
            self.module_runs[mod.name] = self.module_runs.get(mod.name, 0) + 1
            self.emit_log(f"[{mod.label}] -> {ent.type}:{ent.value}",
                          level="run", module=mod.name)
            probe = Entity(type=ent.type, value=ent.value, source=mod.name,
                           depth=ent.depth, id=ent.id, meta=ent.meta,
                           basis=ent.basis, provenance=ent.provenance)
            ctx = Context(self, probe)
            started = time.time()
            st = self.module_status.setdefault(
                mod.name, {"runs": 0, "ok": 0, "empty": 0, "partial": 0,
                           "errors": 0, "last_error": "", "label": mod.label,
                           "category": mod.category, "active": bool(mod.active),
                           "contacted": False, "live": True, "truncated": False,
                           "findings": 0, "results_retrieved": 0})
            st["runs"] += 1
            st["target_type"] = ent.type.value
            explicit = None
            try:
                await mod.run(ctx)
                explicit = ctx.explicit_status
                if ctx.failed:
                    st["errors"] += 1
                    st["last_error"] = ctx.failed[:200]
                elif ctx.partial_reason:
                    st["partial"] += 1
                    st["last_error"] = ctx.partial_reason[:200]
                elif ctx.added:
                    st["ok"] += 1
                else:
                    st["empty"] += 1      # ran fine, found nothing
            except Exception as exc:  # modules must never crash the engine
                st["errors"] += 1
                st["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
                self.emit_log(f"[{mod.label}] error: {exc}", level="err",
                              module=mod.name)
            finally:
                st["last_ms"] = int((time.time() - started) * 1000)
                st["findings"] += ctx.added
                st["contacted"] = st["contacted"] or ctx.contacted
                st["live"] = st["live"] and ctx.live
                st["truncated"] = st["truncated"] or ctx.truncated
                if ctx.result_count is not None:
                    st["results_retrieved"] += ctx.result_count
                good = st["ok"] or st["empty"] or st["partial"]
                derived = ("error" if st["errors"] and not good
                           else "partial" if st["errors"] or st["partial"]
                           else "ok" if st["ok"] else "empty")
                # An explicit status from the module (blocked/rate_limited/
                # auth_error/not_configured/timeout) wins unless a later run
                # of the same module produced results.
                st["state"] = _refine_status(derived, explicit, st)

    # ---- link validation (opt-in) ---------------------------------------
    async def validate_links(self) -> None:
        from .urls import HostLimiter, validate_url
        targets = [e for e in self.entities.values()
                   if e.type in (EntityType.ACCOUNT, EntityType.URL)
                   and e.validation is None]
        # Most useful first: seeds/observed before candidates.
        targets.sort(key=lambda e: -BASIS_RANK.get(e.basis, 0))
        targets = targets[: self.limits.max_validations]
        if not targets:
            return
        from .urls import GuardUnavailable
        try:
            client = self.safe_http
        except GuardUnavailable as exc:
            self.emit_log(f"link validation skipped: {exc}", level="err")
            return
        self.emit_log(f"validating {len(targets)} link(s) (rate-limited per host)",
                      level="run")
        limiter = HostLimiter(min_interval=1.0)
        allow_unresolved = bool(self.config.get("trust_proxy_resolution"))

        async def one(e: Entity):
            url = e.meta.get("url") or e.value
            v = await validate_url(url, client, limiter=limiter,
                                   allow_unresolved=allow_unresolved)
            e.validation = v.to_dict()
            self._emit_entity(e)

        await asyncio.gather(*(one(e) for e in targets))

    def cancel(self) -> None:
        self._cancelled = True
        self._user_cancelled = True
        self.emit_log("cancel requested", level="warn")

    # ---- export --------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return {
            "entities": [e.to_dict() for e in self.entities.values()],
            "links": [l.to_dict() for l in self.links],
            "logs": self.logs,
            "pivots": self.pivots,
            "module_status": self.module_status,
            "scope": self.scope.to_dict(),
            "limits": vars(self.limits),
            "mode": self.mode,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
