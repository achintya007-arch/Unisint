"""Explainable, deterministic labels for how an entity relates to the seeds.

This is deliberately conservative self-audit logic, not identity resolution:
a name or handle is a search key, never proof. Every label comes with the
evidence that supports it, the evidence that conflicts with it, and what is
still unknown — each item attributed to its source.

Labels (strongest → weakest):
  seeded                  you entered it
  linked_proof            cryptographically verified link from a strong chain
  linked_profile          stated on a profile already tied to your seeds
  corroborated_handle     same handle elsewhere AND that profile lists one of
                          your seeds (e.g. your seeded email)
  handle_match            same handle exists elsewhere — ownership unconfirmed
  weak                    only appears in related activity
  candidate               generated guess or unverified search result
plus an overlay ``conflicting`` when evidence points the other way.
A missing attribute is *unknown*, never a mismatch.
"""
from __future__ import annotations

from dataclasses import dataclass, field

LABELS = {
    "seeded": "Seeded (you entered this)",
    "linked_proof": "Linked — verified proof",
    "linked_profile": "Linked — stated on your profile",
    "corroborated_handle": "Handle match — corroborated",
    "handle_match": "Handle match — unconfirmed",
    "weak": "Weak association",
    "candidate": "Candidate — unverified",
}

_LINK_TO_LABEL = {
    "seed": "seeded", "proof": "linked_proof", "profile": "linked_profile",
    "handle_match": "handle_match", "handle_profile": "handle_match",
    "handle_proof": "handle_match", "weak": "weak",
}


@dataclass
class Assessment:
    label: str
    title: str
    conflicting: bool = False
    supports: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"label": self.label, "title": self.title,
                "conflicting": self.conflicting, "supports": self.supports,
                "conflicts": self.conflicts, "unknown": self.unknown}


def _tokens(name: str) -> set[str]:
    return {t for t in "".join(c.lower() if c.isalnum() else " " for c in name).split()
            if len(t) > 1}


def _parent(e: dict) -> str | None:
    prov = e.get("provenance") or [{}]
    return prov[0].get("parent_id")


def names_for_account(acc: dict, entities: list[dict]) -> list[dict]:
    """Display names observed on the same profile as ``acc``.

    Same producing module and same parent lookup; for multi-site tools
    (Maigret) the name's ``on`` field must also name the account's site.
    """
    site = (acc.get("meta") or {}).get("site", "").lower()
    out = []
    for e in entities:
        if e["type"] != "full_name" or e.get("basis") == "seed":
            continue
        if e.get("source") != acc.get("source") or _parent(e) != _parent(acc):
            continue
        on = ((e.get("meta") or {}).get("on") or "").lower()
        if acc.get("source") == "maigret" and site and site not in on:
            continue
        out.append(e)
    return out


def assess(ent: dict, entities: list[dict]) -> Assessment:
    meta = ent.get("meta") or {}
    sources = meta.get("sources") or [ent.get("source")]
    if ent.get("basis") == "seed":
        label = "seeded"
    elif ent.get("basis") == "candidate":
        label = "candidate"
    else:
        label = _LINK_TO_LABEL.get(meta.get("identity_link", ""), "weak")

    a = Assessment(label=label, title=LABELS[label])
    via = (ent.get("provenance") or [{}])[0]
    if label != "seeded":
        a.supports.append(f"observed by {', '.join(sources)}"
                          + (f" via {via.get('rel')} of {via.get('parent_value')}"
                             if via.get("parent_value") else ""))
    if meta.get("url_origin"):
        a.supports.append(f"URL supplied by {meta['url_origin']}")

    seeds = [e for e in entities if e.get("basis") == "seed"]
    seed_values = {e["value"].strip().lower() for e in seeds}
    seed_names = [e for e in seeds if e["type"] == "full_name"]

    # Corroboration of a handle match: its profile lists one of your seeds.
    # The listing usually merges into the seed entity itself, so search every
    # provenance record, not just the first.
    if label == "handle_match" and ent["type"] == "account":
        def listed_here(e: dict) -> bool:
            if e["value"].strip().lower() not in seed_values:
                return False
            if (_parent(e) == _parent(ent) and e.get("source") == ent.get("source")
                    and (e.get("meta") or {}).get("identity_link") == "handle_profile"):
                return True
            return any(p.get("source") == ent.get("source")
                       and p.get("parent_id") == _parent(ent)
                       and p.get("rel") == "listed_on_profile"
                       for p in e.get("provenance") or [])
        listed = [e for e in entities if listed_here(e)]
        if listed:
            a.label, a.title = "corroborated_handle", LABELS["corroborated_handle"]
            for e in listed:
                a.supports.append(f"profile lists your seeded {e['type']} {e['value']}")
        else:
            a.unknown.append("ownership not confirmed — the same handle can belong "
                             "to different people on different sites")

    # Link validation state.
    v = ent.get("validation") or None
    if ent["type"] in ("account", "url"):
        if not v:
            a.unknown.append("link not checked")
        elif v.get("state") == "reachable":
            a.supports.append(f"link reachable (HTTP {v.get('http_status')}) — "
                              "page loads; not proof of ownership")
        elif v.get("state") in ("not_found", "soft_404"):
            a.conflicts.append(f"link check: {v['state']} ({v.get('detail', '')})")
        else:
            a.unknown.append(f"link check inconclusive: {v.get('state')} "
                             f"({v.get('detail', '')})")

    # Name consistency (accounts only). Missing name = unknown, not mismatch.
    if ent["type"] == "account" and seed_names:
        names = names_for_account(ent, entities)
        if not names:
            a.unknown.append("no display name on this profile to compare")
        for n in names:
            nt = _tokens(n["value"])
            for s in seed_names:
                if nt & _tokens(s["value"]):
                    a.supports.append(f"profile name '{n['value']}' shares a token "
                                      f"with your seeded name (weak: names are common)")
                else:
                    a.conflicts.append(f"profile name '{n['value']}' shares nothing "
                                       f"with your seeded name '{s['value']}'")

    if ent["type"] == "url" and meta.get("kind") == "search_result":
        a.unknown.append(meta.get("caveat") or "search result — relevance unverified")
        if meta.get("term_in_snippet") is False:
            a.unknown.append("search term not visible in title/snippet")

    a.conflicting = bool(a.conflicts)
    return a
