"""Turn the raw entity graph into a human-readable dossier / subject profile.

Groups findings by category, ranks by confidence, and produces a compact
summary of the strongest signals (names, accounts, locations, exposures).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import EntityType
from .remediation import build_remediation


def build_dossier(snapshot: dict[str, Any]) -> dict[str, Any]:
    ents = snapshot.get("entities", [])
    by_type: dict[str, list[dict]] = defaultdict(list)
    for e in ents:
        by_type[e["type"]].append(e)

    def top(t: str, n: int = 50) -> list[dict]:
        rows = sorted(by_type.get(t, []),
                      key=lambda e: e.get("confidence", 0), reverse=True)
        return rows[:n]

    accounts = top(EntityType.ACCOUNT.value)
    # Count exposures: accounts + registrations + leaked emails.
    exposures = len(accounts)

    profile = {
        "names": [e["value"] for e in top(EntityType.FULL_NAME.value, 8)],
        "usernames": [e["value"] for e in top(EntityType.USERNAME.value, 15)],
        "emails": [e["value"] for e in top(EntityType.EMAIL.value, 15)],
        "phones": [e["value"] for e in top(EntityType.PHONE.value, 8)],
        "locations": [e["value"] for e in top(EntityType.LOCATION.value, 10)],
        "orgs": [e["value"] for e in top(EntityType.ORG.value, 8)],
        "domains": [e["value"] for e in top(EntityType.DOMAIN.value, 10)],
        "hosts": [e["value"] for e in top(EntityType.HOST.value, 100)],
        "ips": [e["value"] for e in top(EntityType.IP.value, 20)],
        "accounts": [
            {"site": e["meta"].get("site", "?"),
             "url": e["meta"].get("url", e["value"]),
             "confidence": round(e.get("confidence", 0), 2),
             "sources": e["meta"].get("sources", [])}
            for e in accounts
        ],
        "findings": [
            {"text": e["value"], "source": e["source"],
             "meta": e["meta"], "confidence": round(e.get("confidence", 0), 2)}
            for e in top(EntityType.METADATA.value, 200)
        ],
    }

    # Risk/exposure headline for self-audit framing.
    risk = []
    emails_in_commits = [e for e in by_type.get(EntityType.EMAIL.value, [])
                         if e["meta"].get("note")]
    if emails_in_commits:
        risk.append(f"{len(emails_in_commits)} email(s) exposed in public commits")
    vulns = [f for f in profile["findings"] if f["text"].startswith("CVE:")]
    if vulns:
        risk.append(f"{len(vulns)} known CVE(s) on exposed hosts")
    has_gps = any(
        isinstance(e.get("meta"), dict) and "lat" in e["meta"]
        for e in by_type.get(EntityType.LOCATION.value, [])
    )
    if has_gps:
        risk.append("GPS coordinates found in image metadata")

    profile["exposure_count"] = exposures
    profile["risk_flags"] = risk

    # Remediation guidance is only meaningful for self-audit (your own assets).
    if snapshot.get("mode") == "self":
        profile["remediation"] = build_remediation(profile)
    else:
        profile["remediation"] = []
    return profile
