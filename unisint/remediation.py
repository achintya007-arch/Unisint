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


def build_remediation(dossier: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce an ordered list of {title, action, url, severity} steps."""
    steps: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. Accounts -> lock down / delete.
    for acc in dossier.get("accounts", []):
        site = (acc.get("site") or "").strip()
        url = acc.get("url", "")
        key = site.lower()
        host = url.split("//")[-1].split("/")[0].lower()
        advice = None
        for known, a in SITE_ADVICE.items():
            if known in key or known in host:
                advice = a
                break
        advice = advice or GENERIC_ACCOUNT
        dedupe = f"acct:{key or host}"
        if dedupe in seen:
            continue
        seen.add(dedupe)
        steps.append({
            "title": f"Lock down / review your {site or host} account",
            "action": advice["action"],
            "url": advice["url"] or url,
            "severity": "medium",
        })

    # 2. Email exposed in public commits -> rotate.
    for f in dossier.get("findings", []):
        meta = f.get("meta") or {}
        if meta.get("note") and "commit" in str(meta.get("note")).lower():
            steps.append({
                "title": "Rotate the email address exposed in public commits",
                "action": "Set a noreply commit email "
                          "(`git config --global user.email "
                          "ID+user@users.noreply.github.com`), enable "
                          "'Block command line pushes that expose my email', "
                          "and rewrite history only if necessary.",
                "url": "https://docs.github.com/en/account-and-profile/"
                       "setting-up-and-managing-your-personal-account-on-github/"
                       "managing-email-preferences/setting-your-commit-email-address",
                "severity": "high",
            })
            break

    # 3. GPS in image metadata -> scrub.
    has_gps = any(
        isinstance((f.get("meta") or {}), dict) and ("lat" in (f.get("meta") or {}))
        for f in dossier.get("findings", [])
    ) or any("," in loc and loc.replace(",", "").replace(".", "").replace("-", "").isdigit()
             for loc in dossier.get("locations", []))
    if has_gps:
        steps.append({
            "title": "Strip location metadata from photos before sharing",
            "action": "Your image carried GPS coordinates. Remove EXIF with "
                      "`exiftool -gps:all= -xmp:geolocation= FILE`, and disable "
                      "location tagging in your camera app.",
            "url": "",
            "severity": "high",
        })

    # 4. Emails surfaced anywhere -> general hygiene + broker opt-out.
    if dossier.get("emails"):
        steps.append({
            "title": "Reduce email exposure",
            "action": "Use address aliases for signups, enable breach "
                      "monitoring, and turn on 2FA everywhere this address is "
                      "used.",
            "url": "https://haveibeenpwned.com/",
            "severity": "medium",
        })

    # 5. Always-on: data-broker opt-outs for self-audit.
    steps.append({
        "title": "File data-broker / people-search opt-outs",
        "action": "People-search sites aggregate public records about you. "
                  "Submit removal requests at the brokers listed.",
        "url": "",
        "severity": "medium",
        "links": DATA_BROKERS,
    })

    return steps
