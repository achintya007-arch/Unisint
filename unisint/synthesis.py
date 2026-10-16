"""Build the dossier from the engine snapshot.

Rules:
* Every item carries its provenance (sources, parent, relation) and, for
  links, its validation state. The UI and every export render this same
  structure, so what you see is what you export.
* Observations are separated from conclusions: accounts are grouped by an
  explainable label (unisint.resolve), candidates and search results get
  their own sections, and display names are reported as "shown on profile X"
  — never as "the subject's name".
* Nothing absent is filled in; failures are listed, not hidden.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .remediation import build_remediation
from .resolve import LABELS, assess

LABEL_ORDER = list(LABELS)


def _prov(e: dict) -> dict:
    p = (e.get("provenance") or [{}])[0]
    return {"sources": (e.get("meta") or {}).get("sources") or [e.get("source")],
            "via": p.get("rel"), "parent": p.get("parent_value"),
            "source_url": next((x.get("source_url") for x in e.get("provenance") or []
                                if x.get("source_url")), None),
            "observed_at": p.get("observed_at")}


def _item(e: dict, entities: list[dict]) -> dict:
    meta = e.get("meta") or {}
    a = assess(e, entities)
    return {
        "id": e["id"], "type": e["type"], "value": e["value"], "basis": e.get("basis"),
        "site": meta.get("site"), "url": meta.get("url") or (
            e["value"] if e["type"] in ("account", "url") else None),
        "validation": e.get("validation"), "provenance": _prov(e),
        "assessment": a.to_dict(), "meta": {k: v for k, v in meta.items()
                                            if k not in ("sources", "hits")},
    }


def _derive_scope(ents: list[dict]) -> dict:
    """Scope from seeds when the snapshot lacks it (e.g. live previews):
    seed domains/hosts/URL hosts, seed IPs, and IPs those resolve to."""
    from .urls import url_host
    domains, ips = set(), set()
    for e in ents:
        if e.get("basis") != "seed":
            continue
        v = e["value"].strip().lower().rstrip(".")
        if e["type"] in ("domain", "host"):
            domains.add(v)
        elif e["type"] == "ip":
            ips.add(v)
        elif e["type"] == "url" and url_host(e["value"]):
            domains.add(url_host(e["value"]))
    ids_in = {e["id"] for e in ents if e["type"] in ("domain", "host")
              and any(e["value"].lower().rstrip(".") == d
                      or e["value"].lower().rstrip(".").endswith("." + d) for d in domains)}
    for e in ents:
        p = (e.get("provenance") or [{}])[0]
        if e["type"] == "ip" and p.get("rel") == "resolves_to" and p.get("parent_id") in ids_in:
            ips.add(e["value"])
    return {"domains": sorted(domains), "ips": sorted(ips)}


def build_dossier(snapshot: dict[str, Any]) -> dict[str, Any]:
    ents: list[dict] = snapshot.get("entities", [])
    mode = snapshot.get("mode", "self")
    by_type: dict[str, list[dict]] = defaultdict(list)
    for e in ents:
        by_type[e["type"]].append(e)
    scope = snapshot.get("scope") or _derive_scope(ents)

    def in_scope_host(h: str) -> bool:
        h = h.lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in scope.get("domains", []))

    seeds = [_item(e, ents) for e in ents if e.get("basis") == "seed"]

    # Accounts & links grouped by label.
    accounts = [_item(e, ents) for e in by_type.get("account", [])]
    accounts.sort(key=lambda i: (LABEL_ORDER.index(i["assessment"]["label"]),
                                 i["assessment"]["conflicting"], i["site"] or "", i["value"]))
    groups: dict[str, list] = {k: [] for k in LABEL_ORDER}
    for a in accounts:
        groups[a["assessment"]["label"]].append(a)

    urls = [_item(e, ents) for e in by_type.get("url", [])]
    search_results = [u for u in urls if u["meta"].get("kind") == "search_result"]
    linked_urls = [u for u in urls if u["meta"].get("kind") != "search_result"]

    findings_all = [_item(e, ents) for e in by_type.get("metadata", [])]
    registrations = [f for f in findings_all if f["meta"].get("kind") == "registration"]
    provider_status = [f for f in findings_all if f["meta"].get("kind") == "provider_status"]
    manual_links = [f for f in findings_all if f["meta"].get("kind") == "manual_search_links"]
    findings = [f for f in findings_all if f not in registrations
                and f not in provider_status and f not in manual_links]

    identifiers = {t: [_item(e, ents) for e in by_type.get(t, []) if e.get("basis") != "seed"]
                   for t in ("email", "phone", "username")}
    names_on_profiles = [{"name": e["value"],
                          "on": (e.get("meta") or {}).get("on") or e.get("source"),
                          "source": e.get("source"), "basis": e.get("basis")}
                         for e in by_type.get("full_name", []) if e.get("basis") != "seed"]

    hosts = by_type.get("host", []) + [e for e in by_type.get("domain", [])
                                       if e.get("basis") != "seed"]
    infra = {
        "in_scope_hosts": sorted({h["value"] for h in hosts if in_scope_host(h["value"])
                                  and h.get("basis") != "candidate"}),
        "candidate_hosts": sorted({h["value"] for h in hosts if h.get("basis") == "candidate"}),
        "out_of_scope_hosts": sorted({h["value"] for h in hosts
                                      if not in_scope_host(h["value"])}),
        "ips": sorted({e["value"] for e in by_type.get("ip", [])}),
        "in_scope_ips": sorted(scope.get("ips", [])),
    }

    # Active-probe authorization audit (from the central scope policy).
    audit = scope.get("audit", []) if isinstance(scope, dict) else []
    scope_blocks = [a for a in audit if not a.get("allow_active")]
    scope_report = {
        "mode": scope.get("mode") if isinstance(scope, dict) else None,
        "authorized_domains": sorted(scope.get("domains", [])),
        "authorized_ips": sorted(scope.get("ips", [])),
        "active_allowed": [a for a in audit if a.get("allow_active")],
        "active_blocked": scope_blocks,
        "blocked_count": len(scope_blocks),
    }

    pivots = snapshot.get("pivots", [])
    skip_reasons = Counter(s["reason"] for p in pivots for s in p.get("skipped", []))
    module_status = snapshot.get("module_status", {})
    status_counts = Counter(v.get("state", "?") for v in module_status.values())

    # Risk flags — only from observed evidence.
    risk = []
    leaked = [i for i in identifiers["email"] if i["meta"].get("note")]
    if leaked:
        risk.append(f"{len(leaked)} email(s) seen in public commit metadata "
                    "(may include other contributors)")
    cves = [f for f in findings if f["value"].startswith("CVE:")]
    if cves:
        risk.append(f"{len(cves)} CVE id(s) reported by Shodan InternetDB for "
                    "in-scope IPs (unverified; check exposure)")
    if any(isinstance(e.get("meta"), dict) and "lat" in e["meta"]
           and e.get("source") in ("exif", "exiftool") for e in by_type.get("location", [])):
        risk.append("GPS coordinates found in image metadata")
    broken = [a for a in accounts + linked_urls
              if (a.get("validation") or {}).get("state") in ("not_found", "soft_404")]
    if broken:
        risk.append(f"{len(broken)} link(s) failed validation (shown, marked broken)")

    dossier = {
        "mode": mode,
        "seeds": seeds,
        "scope": scope,
        "account_groups": {k: v for k, v in groups.items() if v},
        "accounts": accounts,
        "linked_urls": linked_urls,
        "registrations": registrations,
        "identifiers": identifiers,
        "names_on_profiles": names_on_profiles,
        "infrastructure": infra,
        "scope_report": scope_report,
        "search_results": search_results,
        "provider_status": provider_status,
        "manual_links": manual_links,
        "findings": findings,
        "locations": [{"value": e["value"], "basis": e.get("basis"),
                       "source": e.get("source"), "meta": e.get("meta") or {}}
                      for e in by_type.get("location", [])],
        "orgs": [{"value": e["value"], "source": e.get("source"),
                  "on": (e.get("meta") or {}).get("on")} for e in by_type.get("org", [])],
        "module_status": module_status,
        "status_counts": dict(status_counts),
        "pivot_summary": {"expanded": sum(1 for p in pivots if p.get("ran")),
                          "not_expanded": sum(1 for p in pivots if not p.get("ran")),
                          "skip_reasons": skip_reasons.most_common(12)},
        "risk_flags": risk,
        "counts": {"accounts": len(accounts),
                   "accounts_strong": sum(len(groups[k]) for k in
                                          ("seeded", "linked_proof", "linked_profile",
                                           "corroborated_handle")),
                   "registrations": len(registrations),
                   "search_results": len(search_results)},
    }
    # Back-compat for older UI code paths.
    dossier["exposure_count"] = dossier["counts"]["accounts"]
    dossier["remediation"] = build_remediation(dossier) if mode == "self" else []
    return dossier
