"""Pivot policy: decides, with a stated reason, whether a module may run on an
entity. Pure and deterministic so it can be unit-tested without the network.

Principles
* Seeds (what the user entered) are always expanded.
* Only OBSERVED entities with an established identity link may be expanded
  further. Candidates (generated guesses, unverified search hits) and derived
  values are recorded, never expanded.
* A handle that merely exists on another site ("handle_match") is not proof
  it belongs to the same person, so nothing found through it is expanded.
* Names, locations and organisations are search keys / attributes, not pivots.
* Active probes (modules that connect to the target itself) only run on
  in-scope assets: the seed domain, its subdomains and IPs they resolve to.
* Hard limits: depth, per-module run count, total entities, time budget.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Basis, Entity, EntityType
# Scope policy lives in scope.py; re-exported here so existing imports
# (`from .pivot import Scope, Limits`) keep working.
from .scope import ScopePolicy as Scope  # noqa: F401

# Identity links strong enough to expand from (set by first-party modules).
EXPANDABLE_LINKS = {"profile", "proof", "seed"}

NEVER_EXPAND = {EntityType.FULL_NAME, EntityType.LOCATION, EntityType.ORG,
                EntityType.METADATA, EntityType.ACCOUNT, EntityType.IMAGE}

# People-identifiers found during infrastructure recon are recorded only.
RECON_RECORD_ONLY = {EntityType.EMAIL, EntityType.PHONE, EntityType.USERNAME,
                     EntityType.FULL_NAME}


@dataclass
class Limits:
    depth: int = 2
    max_entities: int = 400
    per_module_runs: int = 40
    time_budget: float = 240.0      # seconds for discovery
    validate_links: bool = False
    max_validations: int = 60


def decide(ent: Entity, module, *, mode: str, limits: Limits, scope: "Scope",
           module_runs: dict[str, int]) -> tuple[bool, str]:
    """Return (allowed, reason). Reasons are shown to the user verbatim."""
    if module_runs.get(module.name, 0) >= limits.per_module_runs:
        return False, f"{module.name} run cap ({limits.per_module_runs}) reached"

    if getattr(module, "active", False):
        # Active probes touch the target itself: the scope policy decides, and
        # records, whether that target is authorized.
        dec = scope.classify(ent)
        if not dec.allow_active:
            return False, f"active probe blocked ({dec.target_class}): {dec.reason}"

    if ent.basis == Basis.SEED.value or ent.depth == 0:
        return True, "seed entered by user"

    if ent.depth > limits.depth:
        return False, f"depth limit {limits.depth}"
    if ent.basis == Basis.CANDIDATE.value:
        return False, "candidate (unconfirmed) — recorded, not expanded"
    if ent.basis == Basis.DERIVED.value:
        return False, "derived value — recorded, not expanded"
    if ent.type in NEVER_EXPAND:
        return False, f"{ent.type.value} is an attribute/search key, not a pivot"
    if mode == "recon" and ent.type in RECON_RECORD_ONLY:
        return False, "people identifiers are recorded, not expanded, in RECON"

    if ent.type in (EntityType.HOST, EntityType.DOMAIN, EntityType.IP, EntityType.URL):
        # Infrastructure: expand only within scope.
        if scope.contains(ent):
            return True, "in-scope infrastructure"
        return False, "out-of-scope infrastructure — recorded only"

    link = (ent.meta or {}).get("identity_link", "")
    if link in EXPANDABLE_LINKS:
        return True, f"identity link '{link}' from a seeded profile"
    return False, (f"identity link '{link or 'none'}' is too weak to expand "
                   "(e.g. same handle on another site is not proof of identity)")
