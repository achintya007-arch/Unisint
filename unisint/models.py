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
from typing import Any, Optional


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


def _norm(value: str) -> str:
    return value.strip().lower()


@dataclass
class Entity:
    type: EntityType
    value: str
    source: str = "input"            # which module/tool produced it
    confidence: float = 0.5          # 0..1
    meta: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: float = field(default_factory=time.time)

    @property
    def key(self) -> tuple[str, str]:
        """Identity used for de-duplication."""
        return (self.type.value, _norm(self.value))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Link:
    src: str                         # entity id
    dst: str                         # entity id
    rel: str = "related"
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
