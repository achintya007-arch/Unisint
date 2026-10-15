"""Common data model shared by every module: entities and links.

Everything a module discovers is expressed as an :class:`Entity`. Relationships
between entities (``account_of``, ``resolves_to`` ...) are :class:`Link`.
The engine stores these in a graph and streams them to the UI.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class EntityType(str, Enum):
    USERNAME = "username"
    FULL_NAME = "full_name"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    ACCOUNT = "account"      # a profile found on a specific site
    HOST = "host"            # subdomain / hostname
    LOCATION = "location"
    ORG = "org"
    IMAGE = "image"
    METADATA = "metadata"    # free-form finding (open port, tech, cert ...)

    def __str__(self) -> str:  # nicer logs
        return self.value


class Basis(str, Enum):
    """How we came to know an entity. Only SEED/OBSERVED may drive pivots."""
    SEED = "seed"            # entered by the user
    OBSERVED = "observed"    # returned by a source/tool about a looked-up entity
    CANDIDATE = "candidate"  # generated guess or unverified search hit
    DERIVED = "derived"      # computed by UNISINT (e.g. phone region)

    def __str__(self) -> str:
        return self.value


def _norm(value: str) -> str:
    return value.strip().lower()


def normalize_value(etype: "EntityType", value: str) -> str:
    """Type-aware canonical form used for de-duplication."""
    v = (value or "").strip()
    if etype in (EntityType.ACCOUNT, EntityType.URL):
        from .urls import normalize_url
        n = normalize_url(v)
        return (n or v).lower()
    if etype in (EntityType.DOMAIN, EntityType.HOST):
        return v.lower().rstrip(".")
    if etype == EntityType.PHONE:
        return "".join(c for c in v if c.isdigit() or c == "+")
    if etype == EntityType.FULL_NAME:
        return " ".join(v.lower().split())
    return v.lower()


@dataclass
class Entity:
    type: EntityType
    value: str
    source: str = "input"            # which module/tool produced it
    # Heuristic sort weight only — NOT a calibrated probability. The UI shows
    # basis/labels and evidence, never this number as "confidence".
    confidence: float = 0.5
    meta: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: float = field(default_factory=time.time)
    basis: str = Basis.OBSERVED.value
    # Where it came from: source, source_url, canonical_url, parent_id,
    # parent_value, query, observed_at. One record per independent source.
    provenance: list[dict[str, Any]] = field(default_factory=list)
    # urls.Validation.to_dict() once checked; None = never checked.
    validation: dict[str, Any] | None = None
    rationale: str = ""

    @property
    def key(self) -> tuple[str, str]:
        """Identity used for de-duplication."""
        return (self.type.value, normalize_value(self.type, self.value))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Link:
    """A graph edge. Every edge is backed by the evidence that created it:
    the module (`source`) that observed `dst` while processing `src`."""
    src: str                         # entity id
    dst: str                         # entity id
    rel: str = "related"
    source: str = ""
    basis: str = Basis.OBSERVED.value
    created: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
