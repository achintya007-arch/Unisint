"""Adapters for username-enumeration tools: Sherlock, Maigret, socialscan.

These tools report that a *handle exists* on a site. That is a fact about the
site, not proof the account belongs to the person who owns the seed — so every
account they report carries ``identity_link='handle_match'`` and is never
expanded further. URLs are exactly what the tool returned (``url_origin=
'tool'``); none are constructed here. Parsing is split into pure functions so
it can be tested against captured output.
"""
from __future__ import annotations

import csv
import io
import json

from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType
from ..runner import UnsafeArgument, run, safe_arg, tmp_dir, which
from ..urls import normalize_url


# ---- pure parsers ---------------------------------------------------------

def parse_sherlock_csv(text: str) -> list[dict]:
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        if str(row.get("exists", "")).strip().lower() not in ("claimed", "true"):
            continue
        url = normalize_url(row.get("url_user", ""))
        if url:
            out.append({"site": row.get("name", "").strip(), "url": url})
    return out


def parse_maigret_report(data: dict) -> list[dict]:
    out = []
    for site, info in (data or {}).items():
        if not isinstance(info, dict):
            continue
        status = info.get("status") or {}
        if status.get("status") != "Claimed":
            continue
        url = normalize_url(info.get("url_user") or status.get("url") or "")
        if not url:
            continue
        ids = status.get("ids") or {}
        out.append({"site": site, "url": url,
                    "tags": status.get("tags") or [],
                    "ids": {k: v for k, v in ids.items()
                            if isinstance(v, str) and v.strip()}})
    return out


def parse_socialscan_json(data: dict) -> list[dict]:
    """Rows where the handle/email is *in use*. ``url`` only if provided."""
    out = []
    for query, results in (data or {}).items():
        for res in results or []:
            avail = str(res.get("available", "")).lower()
            ok = str(res.get("success", "")).lower()
            if avail == "false" and ok == "true":
                out.append({"query": query, "platform": res.get("platform", ""),
                            "url": normalize_url(res.get("link") or "")})
    return out


# ---- modules ----------------------------------------------------------------

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
        try:
            user = safe_arg(ctx.entity.value, "username")
        except UnsafeArgument as exc:
            ctx.log(str(exc), level="warn")
            return
        out = tmp_dir(f"sherlock-{user}")
        csv_path = out / f"{user}.csv"
        csv_path.unlink(missing_ok=True)
        base = [which("sherlock"), "--print-found", "--no-color",
                "--timeout", "15", "--csv", "--folderoutput", str(out)]
        code, so, se = await run(base + ["--", user], timeout=300)
        if not csv_path.exists() and "data file" in (so + se).lower():
            ctx.log("sherlock: remote site list unreachable, retrying with "
                    "bundled list (--local)", level="warn")
            code, so, se = await run(base + ["--local", "--", user], timeout=300)
        if not csv_path.exists():
            ctx.log(f"sherlock produced no CSV (exit {code}): "
                    f"{(se or so).strip()[-160:]}", level="err")
            raise RuntimeError(f"sherlock exit {code}")
        hits = parse_sherlock_csv(csv_path.read_text(errors="replace"))
        for h in hits:
            ctx.add_entity(EntityType.ACCOUNT, h["url"], source=self.name,
                           rel="handle_exists_on", identity_link="handle_match",
                           source_url=h["url"],
                           meta={"site": h["site"], "url": h["url"],
                                 "url_origin": "tool"})
        ctx.log(f"sherlock: handle found on {len(hits)} site(s)")


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
        try:
            user = safe_arg(ctx.entity.value, "username")
        except UnsafeArgument as exc:
            ctx.log(str(exc), level="warn")
            return
        out = tmp_dir(f"maigret-{user}")
        report = out / f"report_{user}_simple.json"
        report.unlink(missing_ok=True)
        code, so, se = await run(
            [which("maigret"), "--top-sites", "100", "-J", "simple",
             "-fo", str(out), "--no-color", "--no-progressbar",
             "--timeout", "15", "-n", "20", "--", user],
            timeout=420)
        if not report.exists():
            ctx.log(f"maigret produced no report (exit {code}): "
                    f"{(se or so).strip()[-160:]}", level="err")
            raise RuntimeError(f"maigret exit {code}")
        try:
            data = json.loads(report.read_text(errors="replace"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"maigret report unparseable: {exc}") from exc
        hits = parse_maigret_report(data)
        for h in hits:
            ctx.add_entity(EntityType.ACCOUNT, h["url"], source=self.name,
                           rel="handle_exists_on", identity_link="handle_match",
                           source_url=h["url"],
                           meta={"site": h["site"], "url": h["url"],
                                 "url_origin": "tool", "tags": h["tags"]})
            # Data Maigret extracted from that page describes *that account*,
            # whose ownership is unconfirmed — recorded, never expanded.
            for key, val in h["ids"].items():
                lk = key.lower()
                where = {"on": f"{h['site']} (handle match)", "field": key}
                if "name" in lk and " " in val.strip():
                    ctx.add_entity(EntityType.FULL_NAME, val, source=self.name,
                                   rel="display_name", meta=where)
                elif "email" in lk and "@" in val:
                    ctx.add_entity(EntityType.EMAIL, val, source=self.name,
                                   rel="listed_on_profile",
                                   identity_link="handle_profile", meta=where)
        ctx.log(f"maigret: handle found on {len(hits)} site(s)")


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
        kind = "email" if ctx.entity.type == EntityType.EMAIL else "username"
        try:
            q = safe_arg(ctx.entity.value, kind)
        except UnsafeArgument as exc:
            ctx.log(str(exc), level="warn")
            return
        out = tmp_dir(f"socialscan-{q}") / "result.json"
        out.unlink(missing_ok=True)
        code, so, se = await run(
            [which("socialscan"), "--json", str(out), "--show-urls", "--", q],
            timeout=150)
        if not out.exists():
            raise RuntimeError(f"socialscan produced no JSON (exit {code})")
        try:
            rows = parse_socialscan_json(json.loads(out.read_text()))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"socialscan JSON unparseable: {exc}") from exc
        for r in rows:
            if r["url"]:
                ctx.add_entity(EntityType.ACCOUNT, r["url"], source=self.name,
                               rel="handle_exists_on",
                               identity_link="handle_match", source_url=r["url"],
                               meta={"site": r["platform"], "url": r["url"],
                                     "url_origin": "tool"})
            else:
                # No URL supplied by the tool: record the fact, don't invent a link.
                ctx.finding(f"{kind} in use on {r['platform']}", source=self.name,
                            meta={"kind": "in_use", "platform": r["platform"]})
