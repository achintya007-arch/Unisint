"""Module framework: a common base for every capability.

A *module* accepts one or more entity types and, given such an entity,
emits log lines plus new entities and links. Wrapped external tools and
native Python checks share the same interface so the engine treats them
identically.
"""
from __future__ import annotations

from typing import Callable

from .models import Entity, EntityType

# Scan modes. SELF = auditing your own footprint; RECON = authorized
# assessment of a domain/IP you own or are contracted to test.
MODE_SELF = "self"
MODE_RECON = "recon"

Emit = Callable[..., None]


class Context:
    """Passed to every module run. Provides emit helpers + shared services."""

    def __init__(self, engine, entity: Entity):
        self._engine = engine
        self.entity = entity
        self.http = engine.http
        self.config = engine.config
        self.mode = engine.mode

    def log(self, msg: str, level: str = "info") -> None:
        self._engine.emit_log(msg, level=level, module=self.entity.source)

    def error(self, msg: str) -> None:
        """Report that this run FAILED (network/HTTP/parse), so the run is
        recorded as an error — not as a successful lookup with no results."""
        self.failed = msg
        self.contacted = True
        self._engine.emit_log(msg, level="err", module=self.entity.source)

    failed: str | None = None
    partial_reason: str | None = None
    added: int = 0
    # Source-run contract signals (read back by the engine):
    contacted: bool = False       # did we actually reach out to the source?
    live: bool = True             # false only when a fixture backed the run
    truncated: bool = False       # results were capped
    result_count: int | None = None   # raw results retrieved (pre-dedup)
    explicit_status: str | None = None  # override the derived status

    def partial(self, msg: str) -> None:
        """Report that this run completed but upstream sources were degraded
        (some failed, were rate-limited, or their status is unknown). Results
        that were returned are still recorded."""
        self.partial_reason = msg
        self.contacted = True
        self._engine.emit_log(msg, level="warn", module=self.entity.source)

    def mark_contacted(self, *, live: bool = True) -> None:
        """A request/tool invocation actually went out."""
        self.contacted = True
        self.live = self.live and live

    def mark_truncated(self, retrieved: int, kept: int) -> None:
        """Results were capped: ``retrieved`` available, ``kept`` recorded."""
        if retrieved > kept:
            self.truncated = True
        self.result_count = retrieved

    def status(self, code: str, detail: str = "") -> None:
        """Set an explicit source-run status from the vocabulary
        (blocked/rate_limited/auth_error/not_configured/timeout/skipped/…)."""
        self.explicit_status = code
        self.contacted = True
        if detail:
            self._engine.emit_log(f"{self.entity.source}: {code} — {detail}",
                                  level="warn", module=self.entity.source)

    def check_http(self, resp, service: str) -> bool:
        """True for 200. 404 = an honest 'not found' (empty run); 429 and any
        other status = a failed lookup, recorded as an error."""
        code = resp.status_code
        self.contacted = True        # we reached the service, whatever it said
        if code == 200:
            return True
        reason = ""
        try:
            body = resp.json()
            if isinstance(body, dict):
                reason = str(body.get("message") or body.get("error") or "")[:140]
        except Exception:
            pass
        if code == 404:
            self.log(f"{service}: not found", level="muted")
        elif code == 429:
            self.error(f"{service}: rate limited (HTTP 429)")
        else:
            self.error(f"{service}: HTTP {code}" + (f" — {reason}" if reason else ""))
        return False

    def add_entity(self, etype: EntityType, value: str, *, source: str,
                   confidence: float | None = None, rel: str = "related",
                   meta: dict | None = None, basis: str | None = None,
                   identity_link: str | None = None,
                   source_url: str | None = None) -> Entity | None:
        """Record an observation made while processing ``self.entity``.

        basis: observed (default) | candidate | derived.
        identity_link: how strongly this ties to the parent's owner —
          'profile' (stated on the parent's own profile), 'proof'
          (cryptographically verified), 'handle_match' (same handle elsewhere),
          'weak'. Only profile/proof may be expanded further.
        source_url: the URL the source itself supplied (never manufactured).
        """
        meta = dict(meta or {})
        if identity_link:
            meta["identity_link"] = identity_link
        prov = {"source_url": source_url} if source_url else None
        ent = self._engine.add_entity(
            etype, value, source=source, parent=self.entity, rel=rel,
            meta=meta, basis=basis, provenance=prov,
        )
        if ent is not None:
            self.added += 1   # observations made by THIS run (not global count)
        return ent

    def finding(self, text: str, *, source: str, meta: dict | None = None,
                confidence: float | None = None, basis: str = "observed",
                source_url: str | None = None) -> None:
        """Record a metadata finding attached to this entity."""
        self.add_entity(EntityType.METADATA, text, source=source,
                        rel="finding", meta=meta, basis=basis,
                        source_url=source_url)


class Module:
    name: str = "module"
    label: str = "Module"
    category: str = "misc"            # username/email/phone/domain/ip/image/person
    accepts: set[EntityType] = set()
    modes: set[str] = {MODE_SELF, MODE_RECON}
    # Which tool binary / api key this needs; None = pure-python, always on.
    requires_tool: str | None = None
    requires_key: str | None = None
    # Depth tier: higher = heavier; presets filter on this.
    weight: int = 1
    # True if the module connects to the target itself (not a third-party
    # API). Active modules only run on in-scope assets (see pivot.Scope).
    active: bool = False

    async def available(self, engine) -> tuple[bool, str]:
        """Return (is_available, human message)."""
        if self.requires_key:
            if not engine.config.get("api_keys", {}).get(self.requires_key):
                return False, f"needs API key: {self.requires_key}"
        if self.requires_tool:
            from .runner import which
            if not which(self.requires_tool):
                return False, f"not installed: {self.requires_tool}"
        return True, "ready"

    async def run(self, ctx: Context) -> None:  # pragma: no cover - interface
        raise NotImplementedError


_REGISTRY: list[Module] = []


def register(mod_cls: type[Module]) -> type[Module]:
    _REGISTRY.append(mod_cls())
    return mod_cls


def all_modules() -> list[Module]:
    return list(_REGISTRY)


def modules_for(entity_type: EntityType, mode: str) -> list[Module]:
    return [
        m for m in _REGISTRY
        if entity_type in m.accepts and mode in m.modes
    ]


def load_all() -> None:
    """Import every adapter and native module so they self-register."""
    import importlib
    import pkgutil

    from . import adapters, native

    for pkg in (adapters, native):
        for _, name, _ in pkgutil.iter_modules(pkg.__path__):
            importlib.import_module(f"{pkg.__name__}.{name}")
