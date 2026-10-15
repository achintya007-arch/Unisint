"""Turn self-audit findings into concrete 'fix this' guidance.

This is a post-processing layer over the dossier: it maps discovered accounts
and findings to actionable remediation steps (where to delete/lock down an
account, how to scrub metadata, how to rotate a leaked commit email, and
where to file data-broker opt-outs). Public, advice-only — it performs no
actions and queries nothing.
"""
from __future__ import annotations

from typing import Any

# Per-site account settings / deletion / privacy pages. Keys are matched
# case-insensitively against the account's `site` or its URL host.
SITE_ADVICE: dict[str, dict[str, str]] = {
    "github": {
        "action": "Review public profile, make your email private "
                  "(Settings → Emails → 'Keep my email addresses private'), "
                  "and prune public repos/gists that leak personal data.",
        "url": "https://github.com/settings/emails",
    },
    "gitlab": {
        "action": "Set profile to private and restrict visible activity.",
        "url": "https://gitlab.com/-/profile",
    },
    "reddit": {
        "action": "Review post/comment history; delete or edit revealing "
                  "posts and consider a fresh pseudonymous account.",
        "url": "https://www.reddit.com/settings/privacy",
    },
    "gravatar": {
        "action": "Gravatar is tied to your email and is PUBLIC by its hash. "
                  "Remove personal images/links or delete the profile.",
        "url": "https://gravatar.com/profile",
    },
    "keybase": {
        "action": "Keybase publishes linked-account proofs. Revoke proofs you "
                  "don't want publicly correlated.",
        "url": "https://keybase.io/account/settings",
    },
    "twitter": {"action": "Lock down or deactivate; review tagged photos/location.",
                "url": "https://twitter.com/settings/account"},
    "instagram": {"action": "Set account private; remove location tags.",
                  "url": "https://www.instagram.com/accounts/privacy_and_security/"},
    "spotify": {"action": "Make playlists/profile private; hide recently played.",
                "url": "https://www.spotify.com/account/privacy/"},
}

# Generic fallbacks per finding kind.
GENERIC_ACCOUNT = {
    "action": "If you don't use this account, delete it; otherwise set it "
              "private and remove personal details. Search the site for "
              "'delete account' in its settings.",
    "url": "",
}

# Data-broker opt-out starting points (people-search sites aggregate public
# records about you). Generic, not the result of any query.
DATA_BROKERS = [
    {"name": "Spokeo", "url": "https://www.spokeo.com/optout"},
    {"name": "Whitepages", "url": "https://www.whitepages.com/suppression-requests"},
    {"name": "BeenVerified", "url": "https://www.beenverified.com/app/optout/search"},
    {"name": "Intelius", "url": "https://www.intelius.com/opt-out/"},
    {"name": "Radaris", "url": "https://radaris.com/control/privacy"},
    {"name": "Google results removal", "url": "https://support.google.com/websearch/answer/9673730"},
]


def _severity(count_sources: int) -> str:
    return "high" if count_sources >= 2 else "medium"


def _advice_for(site: str, url: str) -> dict:
    key = (site or "").lower()
    host = (url or "").split("//")[-1].split("/")[0].lower()
    for known, a in SITE_ADVICE.items():
        if known in key or known in host:
            return a
    return GENERIC_ACCOUNT


STRONG = {"seeded", "linked_proof", "linked_profile", "corroborated_handle"}


def build_remediation(dossier: dict[str, Any]) -> list[dict[str, Any]]:
    """Ordered {title, action, url, severity[, links]} steps from evidence."""
    steps: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. Accounts. Confirmed/corroborated ones get direct advice; handle
    #    matches are phrased conditionally — they may be someone else's.
    for acc in dossier.get("accounts", []):
        site, url = acc.get("site") or "", acc.get("url") or acc.get("value", "")
        label = (acc.get("assessment") or {}).get("label", "handle_match")
        host = url.split("//")[-1].split("/")[0].lower()
        key = f"acct:{(site or host).lower()}"
        if key in seen or label == "candidate":
            continue
        seen.add(key)
        advice = _advice_for(site, url)
        strong = label in STRONG
        steps.append({
            "title": (f"Lock down / review your {site or host} account" if strong
                      else f"If {url} is yours: lock it down or delete it"),
            "action": advice["action"] if strong else
            ("This is only a handle match — it may belong to someone else. "
             "If it is yours: " + advice["action"]),
            "url": advice["url"] or url,
            "severity": "medium" if strong else "low",
        })

    # 2. Registrations found for your email/phone (holehe/ignorant).
    for reg in dossier.get("registrations", []):
        dom = (reg.get("meta") or {}).get("domain")
        if not dom or f"reg:{dom}" in seen:
            continue
        seen.add(f"reg:{dom}")
        steps.append({
            "title": f"Account registered on {dom}",
            "action": "If you no longer use it, delete it; otherwise enable 2FA "
                      "and check the recovery email/phone are current.",
            "url": f"https://{dom}", "severity": "low",
        })

    # 3. Emails seen in public commit metadata.
    leaked = [i for i in (dossier.get("identifiers") or {}).get("email", [])
              if (i.get("meta") or {}).get("note")]
    if leaked:
        steps.append({
            "title": "Email address visible in public commit metadata",
            "action": "If any of these are yours: set a noreply commit email "
                      "(`git config --global user.email ID+user@users.noreply."
                      "github.com`) and enable 'Block command line pushes that "
                      "expose my email'. Seen: " + ", ".join(i["value"] for i in leaked[:5]),
            "url": "https://docs.github.com/en/account-and-profile/"
                   "setting-up-and-managing-your-personal-account-on-github/"
                   "managing-email-preferences/setting-your-commit-email-address",
            "severity": "high",
        })

    # 4. GPS in photo metadata.
    if any(l.get("source") in ("exif", "exiftool") and "lat" in (l.get("meta") or {})
           for l in dossier.get("locations", [])):
        steps.append({
            "title": "Strip location metadata from photos before sharing",
            "action": "Your image carried GPS coordinates. Remove EXIF with "
                      "`exiftool -gps:all= -xmp:geolocation= FILE`, and disable "
                      "location tagging in your camera app.",
            "url": "", "severity": "high",
        })

    # 5. Email hygiene when an email was in scope of the audit.
    if any(s["type"] == "email" for s in dossier.get("seeds", [])):
        steps.append({
            "title": "Reduce email exposure",
            "action": "Use aliases for sign-ups, enable breach monitoring, and "
                      "turn on 2FA wherever this address is used.",
            "url": "https://haveibeenpwned.com/", "severity": "medium",
        })

    # 6. Always: data-broker opt-outs (generic starting points, not results).
    steps.append({
        "title": "File data-broker / people-search opt-outs",
        "action": "People-search sites aggregate public records. These are "
                  "generic starting points — UNISINT did not query them.",
        "url": "", "severity": "medium", "links": DATA_BROKERS,
    })
    return steps
