"""Adapters for username-scanning tools: Sherlock, Maigret, socialscan."""
from __future__ import annotations

import csv
import json

from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType
from ..runner import run, tmp_dir, which


@register
class Sherlock(Module):
    name = "sherlock"
    label = "Sherlock"
    category = "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}
    requires_tool = "sherlock"
    weight = 2

    async def run(self, ctx: Context) -> None:
        user = ctx.entity.value
        out = tmp_dir(f"sherlock-{user}")
        bin_ = which("sherlock")
        code, so, se = await run(
            [bin_, user, "--print-found", "--no-color", "--local",
             "--timeout", "15", "--csv", "--folderoutput", str(out)],
            timeout=240,
        )
        csv_path = out / f"{user}.csv"
        if not csv_path.exists():
            ctx.log(f"sherlock produced no csv (code {code})", level="warn")
            return
        hits = 0
        with csv_path.open() as fh:
            for row in csv.DictReader(fh):
                if str(row.get("exists", "")).lower() in ("true", "claimed"):
                    hits += 1
                    url = row.get("url_user", "")
                    ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                                   confidence=0.75, rel="account_of",
                                   meta={"site": row.get("name", ""),
                                         "url": url})
        ctx.log(f"sherlock: {hits} accounts")


@register
class Maigret(Module):
    name = "maigret"
    label = "Maigret"
    category = "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}
    requires_tool = "maigret"
    weight = 3

    async def run(self, ctx: Context) -> None:
        user = ctx.entity.value
        out = tmp_dir(f"maigret-{user}")
        bin_ = which("maigret")
        code, so, se = await run(
            [bin_, user, "--top-sites", "100", "-J", "simple",
             "-fo", str(out), "--no-color", "--no-progressbar",
             "--no-autoupdate", "--timeout", "15", "-n", "20"],
            timeout=300,
        )
        report = out / f"report_{user}_simple.json"
        if not report.exists():
            ctx.log(f"maigret produced no report (code {code})", level="warn")
            return
        try:
            data = json.loads(report.read_text())
        except Exception:
            return
        hits = 0
        for site, info in data.items():
            status = (info.get("status") or {}).get("status", "")
            if status != "Claimed":
                continue
            hits += 1
            url = info.get("url_user", "")
            ctx.add_entity(EntityType.ACCOUNT, url, source=self.name,
                           confidence=0.8, rel="account_of",
                           meta={"site": site, "url": url,
                                 "tags": info.get("status", {}).get("tags", [])})
            # Extracted identity fields pivot further.
            ids = (info.get("status") or {}).get("ids", {}) or {}
            for key, val in ids.items():
                if not isinstance(val, str) or not val:
                    continue
                lk = key.lower()
                if "name" in lk and " " in val:
                    ctx.add_entity(EntityType.FULL_NAME, val, source=self.name,
                                   confidence=0.5, rel="name_of")
                elif "email" in lk and "@" in val:
                    ctx.add_entity(EntityType.EMAIL, val, source=self.name,
                                   confidence=0.6, rel="email_of")
                elif lk in ("username", "uid") and val != user:
                    ctx.add_entity(EntityType.USERNAME, val, source=self.name,
                                   confidence=0.45, rel="alias")
        ctx.log(f"maigret: {hits} accounts")


@register
class SocialScan(Module):
    name = "socialscan"
    label = "socialscan"
    category = "username"
    accepts = {EntityType.USERNAME, EntityType.EMAIL}
    modes = {MODE_SELF}
    requires_tool = "socialscan"
    weight = 2

    async def run(self, ctx: Context) -> None:
        q = ctx.entity.value
        out = tmp_dir(f"socialscan-{q}") / "result.json"
        bin_ = which("socialscan")
        code, so, se = await run(
            [bin_, q, "--json", str(out), "--show-urls"],
            timeout=120,
        )
        if not out.exists():
            return
        try:
            data = json.loads(out.read_text())
        except Exception:
            return
        for query, results in data.items():
            for res in results:
                # available == False means the handle is in use (exists).
                if res.get("available") is False and res.get("success"):
                    plat = res.get("platform", "")
                    url = res.get("link") or ""
                    ctx.add_entity(EntityType.ACCOUNT,
                                   url or f"{plat}:{query}",
                                   source=self.name, confidence=0.7,
                                   rel="account_of",
                                   meta={"site": plat, "url": url})
