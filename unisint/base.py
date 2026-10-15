"""Module framework: a common base for every capability.

A *module* accepts one or more entity types and, given such an entity,
emits log lines plus new entities and links. Wrapped external tools and
native Python checks share the same interface so the engine treats them
identically.
"""
from __future__ import annotations

from typing import Awaitable, Callable, Iterable

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

    def add_entity(self, etype: EntityType, value: str, *, source: str,
                   confidence: float = 0.5, rel: str = "related",
                   meta: dict | None = None) -> Entity | None:
        return self._engine.add_entity(
            etype, value, source=source, confidence=confidence,
            parent=self.entity, rel=rel, meta=meta or {},
        )

    def finding(self, text: str, *, source: str, meta: dict | None = None,
                confidence: float = 0.7) -> None:
        """Record a free-form metadata finding attached to this entity."""
        self._engine.add_entity(
            EntityType.METADATA, text, source=source, confidence=confidence,
            parent=self.entity, rel="finding", meta=meta or {},
        )


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
