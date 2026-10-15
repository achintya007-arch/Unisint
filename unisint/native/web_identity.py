"""Native public-API lookups for usernames and emails (keyless)."""
from __future__ import annotations

import hashlib

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
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
        url = f"https://en.gravatar.com/{h}.json"
        try:
            r = await ctx.http.get(url)
        except Exception as exc:
            ctx.log(f"gravatar request failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            ctx.log("no public gravatar profile", level="muted")
            return
        try:
            data = r.json()["entry"][0]
        except Exception:
            return
        prof_url = f"https://gravatar.com/{h}"
        ctx.add_entity(EntityType.ACCOUNT, prof_url, source=self.name,
                       confidence=0.9, rel="account_of",
                       meta={"site": "Gravatar", "url": prof_url})
        if data.get("displayName"):
            ctx.add_entity(EntityType.FULL_NAME, data["displayName"],
                           source=self.name, confidence=0.6, rel="name_of")
        for acc in data.get("accounts", []) or []:
            if acc.get("url"):
                ctx.add_entity(EntityType.ACCOUNT, acc["url"], source=self.name,
                               confidence=0.7, rel="linked_account",
                               meta={"site": acc.get("shortname", "")})
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
            ctx.log(f"github request failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            return
        d = r.json()
        url = d.get("html_url", f"https://github.com/{u}")
        ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                       confidence=0.9, rel="account_of",
                       meta={"site": "GitHub", "url": url,
                             "followers": d.get("followers"),
                             "bio": d.get("bio")})
        if d.get("name"):
            ctx.add_entity(EntityType.FULL_NAME, d["name"], source=self.name,
                           confidence=0.55, rel="name_of")
        if d.get("blog"):
            blog = d["blog"]
            if blog.startswith("http"):
                ctx.add_entity(EntityType.URL, blog, source=self.name,
                               confidence=0.6, rel="linked_site")
        if d.get("email"):
            ctx.add_entity(EntityType.EMAIL, d["email"], source=self.name,
                           confidence=0.8, rel="email_of")
        if d.get("location"):
            ctx.add_entity(EntityType.LOCATION, d["location"], source=self.name,
                           confidence=0.5, rel="location_of")
        if d.get("company"):
            ctx.add_entity(EntityType.ORG, d["company"].lstrip("@"),
                           source=self.name, confidence=0.5, rel="works_at")

        # Commit author emails (self-audit: find exposed personal emails).
        try:
            ev = await ctx.http.get(
                f"https://api.github.com/users/{u}/events/public")
            if ev.status_code == 200:
                emails: set[str] = set()
                for item in ev.json():
                    for c in (item.get("payload", {}) or {}).get("commits", []):
                        a = (c.get("author", {}) or {}).get("email", "")
                        if a and "noreply" not in a:
                            emails.add(a)
                for e in list(emails)[:5]:
                    ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                   confidence=0.75, rel="commit_email",
                                   meta={"note": "exposed in public commits"})
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
            r = await ctx.http.get(
                f"https://gitlab.com/api/v4/users?username={u}")
        except Exception as exc:
            ctx.log(f"gitlab request failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            return
        arr = r.json()
        if not arr:
            return
        d = arr[0]
        url = d.get("web_url", f"https://gitlab.com/{u}")
        ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                       confidence=0.85, rel="account_of",
                       meta={"site": "GitLab", "url": url})
        if d.get("name"):
            ctx.add_entity(EntityType.FULL_NAME, d["name"], source=self.name,
                           confidence=0.5, rel="name_of")


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
            r = await ctx.http.get(
                f"https://www.reddit.com/user/{u}/about.json",
                headers={"User-Agent": "unisint/1.0"})
        except Exception as exc:
            ctx.log(f"reddit request failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            return
        try:
            d = r.json()["data"]
        except Exception:
            return
        url = f"https://reddit.com/user/{u}"
        ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                       confidence=0.85, rel="account_of",
                       meta={"site": "Reddit", "url": url,
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
            r = await ctx.http.get(
                "https://keybase.io/_/api/1.0/user/lookup.json"
                f"?usernames={u}")
        except Exception as exc:
            ctx.log(f"keybase request failed: {exc}", level="warn")
            return
        if r.status_code != 200:
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
                           confidence=0.9, rel="account_of",
                           meta={"site": "Keybase", "url": url})
            proofs = (person.get("proofs_summary", {}) or {}).get("all", [])
            for p in proofs:
                if p.get("service_url"):
                    ctx.add_entity(EntityType.ACCOUNT, p["service_url"],
                                   source=self.name, confidence=0.85,
                                   rel="verified_proof",
                                   meta={"site": p.get("proof_type", "")})
