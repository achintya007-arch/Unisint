"""Native public-API lookups for usernames and emails (keyless).

Provenance rules used here:
* URLs come from the API response (``html_url``, ``web_url``, ``profileUrl``,
  ``service_url``). Where a site has no URL field we use its documented
  profile pattern *only after the API confirmed the account exists*, and mark
  ``url_origin='pattern'``.
* A username lookup only proves that *a* account with that handle exists:
  ``identity_link='handle_match'``. Items that account lists about itself are
  ``'handle_profile'`` and Keybase proofs on it ``'handle_proof'`` — strong
  relative to that account, but only as strong as the handle match itself,
  so they are recorded, not expanded.
* Gravatar is keyed by the email's own hash, so what it lists is tied to the
  email: ``'profile'`` (expandable when the email is a seed).
* ``'weak'`` = merely appears in related activity (e.g. commit author emails,
  which can belong to other contributors).
"""
from __future__ import annotations

import hashlib

from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType


@register
class Gravatar(Module):
    name = "gravatar"
    label = "Gravatar"
    category = "email"
    accepts = {EntityType.EMAIL}
    modes = {MODE_SELF}
    weight = 1

    async def run(self, ctx: Context) -> None:
        email = ctx.entity.value.strip().lower()
        h = hashlib.md5(email.encode()).hexdigest()
        try:
            r = await ctx.http.get(f"https://en.gravatar.com/{h}.json")
        except Exception as exc:
            ctx.error(f"gravatar request failed: {exc}")
            return
        if r.status_code == 404:
            ctx.log("no public gravatar profile", level="muted")
            return
        if not ctx.check_http(r, "gravatar"):
            return
        try:
            data = r.json()["entry"][0]
        except Exception:
            ctx.log("gravatar: unexpected response shape", level="warn")
            return
        prof_url = data.get("profileUrl") or f"https://gravatar.com/{h}"
        ctx.add_entity(EntityType.ACCOUNT, prof_url, source=self.name,
                       rel="account_of", identity_link="profile",
                       source_url=prof_url,
                       meta={"site": "Gravatar", "url": prof_url,
                             "url_origin": "api" if data.get("profileUrl") else "pattern"})
        if data.get("displayName"):
            ctx.add_entity(EntityType.FULL_NAME, data["displayName"],
                           source=self.name, rel="display_name",
                           meta={"on": "Gravatar profile"})
        for acc in data.get("accounts", []) or []:
            if acc.get("url"):
                ctx.add_entity(EntityType.ACCOUNT, acc["url"], source=self.name,
                               rel="listed_on_profile", identity_link="profile",
                               source_url=acc["url"],
                               meta={"site": acc.get("shortname", ""),
                                     "url": acc["url"], "url_origin": "api"})
        if data.get("thumbnailUrl"):
            ctx.finding("avatar: " + data["thumbnailUrl"], source=self.name,
                        meta={"avatar": data["thumbnailUrl"]})


@register
class GitHub(Module):
    name = "github"
    label = "GitHub"
    category = "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}
    weight = 1

    async def run(self, ctx: Context) -> None:
        u = ctx.entity.value
        try:
            r = await ctx.http.get(f"https://api.github.com/users/{u}")
        except Exception as exc:
            ctx.error(f"github request failed: {exc}")
            return
        if r.status_code == 404:
            ctx.log(f"github: no user '{u}'", level="muted")
            return
        if r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0":
            ctx.error("github: API rate limit exhausted (60/h unauthenticated)")
            return
        if not ctx.check_http(r, "github"):
            return
        d = r.json()
        url = d.get("html_url")
        if not url:
            return
        ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                       rel="account_of", identity_link="handle_match", source_url=url,
                       meta={"site": "GitHub", "url": url, "url_origin": "api",
                             "created_at": d.get("created_at"),
                             "followers": d.get("followers"), "bio": d.get("bio")})
        if d.get("name"):
            ctx.add_entity(EntityType.FULL_NAME, d["name"], source=self.name,
                           rel="display_name", meta={"on": f"GitHub @{u}"})
        if d.get("blog"):
            blog = d["blog"] if "://" in d["blog"] else "https://" + d["blog"]
            ctx.add_entity(EntityType.URL, blog, source=self.name,
                           rel="listed_on_profile", identity_link="handle_profile",
                           source_url=url,
                           meta={"url": blog, "on": f"GitHub @{u}",
                                 "url_origin": "profile field"})
        if d.get("email"):
            ctx.add_entity(EntityType.EMAIL, d["email"], source=self.name,
                           rel="listed_on_profile", identity_link="handle_profile",
                           source_url=url, meta={"on": f"GitHub @{u}"})
        if d.get("location"):
            ctx.add_entity(EntityType.LOCATION, d["location"], source=self.name,
                           rel="stated_location", meta={"on": f"GitHub @{u}"})
        if d.get("company"):
            ctx.add_entity(EntityType.ORG, d["company"].lstrip("@"),
                           source=self.name, rel="stated_affiliation",
                           meta={"on": f"GitHub @{u}"})

        # Commit emails in public push events. Weak: pushes can contain commits
        # authored by other people, so these are recorded but never expanded.
        try:
            ev = await ctx.http.get(f"https://api.github.com/users/{u}/events/public")
            if ev.status_code == 200:
                seen: dict[str, str] = {}
                for item in ev.json():
                    repo = (item.get("repo") or {}).get("name", "")
                    for c in (item.get("payload", {}) or {}).get("commits", []):
                        a = (c.get("author", {}) or {}).get("email", "")
                        if a and "noreply" not in a and a not in seen:
                            seen[a] = repo
                for e, repo in list(seen.items())[:5]:
                    ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                   rel="commit_author_email",
                                   identity_link="weak",
                                   source_url=f"https://github.com/{repo}" if repo else None,
                                   meta={"note": "exposed in public commits",
                                         "caveat": "commit author may be another contributor",
                                         "repo": repo})
        except Exception:
            pass


@register
class GitLab(Module):
    name = "gitlab"
    label = "GitLab"
    category = "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}
    weight = 1

    async def run(self, ctx: Context) -> None:
        u = ctx.entity.value
        try:
            r = await ctx.http.get("https://gitlab.com/api/v4/users",
                                   params={"username": u})
        except Exception as exc:
            ctx.error(f"gitlab request failed: {exc}")
            return
        if not ctx.check_http(r, "gitlab"):
            return
        arr = r.json()
        if not arr:
            return
        d = arr[0]
        url = d.get("web_url")
        if not url:
            return
        ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                       rel="account_of", source_url=url,
                       identity_link="handle_match",
                       meta={"site": "GitLab", "url": url, "url_origin": "api"})
        if d.get("name"):
            ctx.add_entity(EntityType.FULL_NAME, d["name"], source=self.name,
                           rel="display_name", meta={"on": f"GitLab @{u}"})


@register
class Reddit(Module):
    name = "reddit"
    label = "Reddit"
    category = "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}
    weight = 2

    async def run(self, ctx: Context) -> None:
        u = ctx.entity.value
        try:
            r = await ctx.http.get(f"https://www.reddit.com/user/{u}/about.json",
                                   headers={"User-Agent": "unisint/2.0"})
        except Exception as exc:
            ctx.error(f"reddit request failed: {exc}")
            return
        if not ctx.check_http(r, "reddit"):
            return
        try:
            d = r.json()["data"]
        except Exception:
            return
        if d.get("is_suspended"):
            ctx.log(f"reddit: u/{u} is suspended", level="muted")
        name = d.get("name") or u
        # Reddit's API has no profile-URL field; the pattern is documented and
        # used only after the API confirmed the account.
        url = f"https://www.reddit.com/user/{name}/"
        ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                       rel="account_of",
                       identity_link="handle_match",
                       meta={"site": "Reddit", "url": url, "url_origin": "pattern",
                             "karma": d.get("total_karma"),
                             "created": d.get("created_utc")})


@register
class Keybase(Module):
    name = "keybase"
    label = "Keybase"
    category = "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}
    weight = 2

    async def run(self, ctx: Context) -> None:
        u = ctx.entity.value
        try:
            r = await ctx.http.get("https://keybase.io/_/api/1.0/user/lookup.json",
                                   params={"usernames": u})
        except Exception as exc:
            ctx.error(f"keybase request failed: {exc}")
            return
        if not ctx.check_http(r, "keybase"):
            return
        try:
            them = r.json().get("them", [])
        except Exception:
            return
        for person in them:
            if not person:
                continue
            url = f"https://keybase.io/{u}"
            ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                           rel="account_of",
                           identity_link="handle_match",
                           meta={"site": "Keybase", "url": url, "url_origin": "pattern"})
            proofs = (person.get("proofs_summary", {}) or {}).get("all", [])
            for p in proofs:
                if p.get("service_url"):
                    # Keybase proofs are cryptographically signed claims.
                    ctx.add_entity(EntityType.ACCOUNT, p["service_url"],
                                   source=self.name, rel="verified_proof",
                                   identity_link="handle_proof",
                                   source_url=p.get("proof_url") or p["service_url"],
                                   meta={"site": p.get("proof_type", ""),
                                         "url": p["service_url"],
                                         "url_origin": "api",
                                         "proof_url": p.get("proof_url")})
