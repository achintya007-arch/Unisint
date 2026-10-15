"""Adapters for domain/host recon tools: theHarvester, subfinder, amass,
and exiftool for richer file metadata."""
from __future__ import annotations

import json
import re

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType
from ..runner import run, tmp_dir, which

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@register
class Subfinder(Module):
    name = "subfinder"
    label = "subfinder"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    requires_tool = "subfinder"
    weight = 3

    async def run(self, ctx: Context) -> None:
        dom = ctx.entity.value
        bin_ = which("subfinder")
        code, so, se = await run([bin_, "-d", dom, "-silent"], timeout=240)
        subs = [s.strip().lower() for s in so.splitlines() if s.strip()]
        ctx.log(f"subfinder: {len(subs)} subdomains")
        for s in subs[:100]:
            ctx.add_entity(EntityType.HOST, s, source=self.name,
                           confidence=0.85, rel="subdomain")


@register
class Amass(Module):
    name = "amass"
    label = "Amass (passive)"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_RECON}
    requires_tool = "amass"
    weight = 3

    async def run(self, ctx: Context) -> None:
        dom = ctx.entity.value
        bin_ = which("amass")
        code, so, se = await run(
            [bin_, "enum", "-passive", "-norecursive", "-d", dom],
            timeout=300)
        subs = {l.strip().lower() for l in so.splitlines()
                if l.strip().endswith(dom)}
        ctx.log(f"amass: {len(subs)} subdomains")
        for s in sorted(subs)[:100]:
            ctx.add_entity(EntityType.HOST, s, source=self.name,
                           confidence=0.85, rel="subdomain")


@register
class TheHarvester(Module):
    name = "theharvester"
    label = "theHarvester"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    requires_tool = "theHarvester"
    weight = 3

    async def available(self, engine):
        from ..runner import which as _which
        if _which("theHarvester") or _which("theharvester"):
            return True, "ready"
        return False, "not installed: theHarvester"

    async def run(self, ctx: Context) -> None:
        dom = ctx.entity.value
        out = tmp_dir(f"harvester-{dom}") / "result"
        bin_ = which("theHarvester") or which("theharvester")
        code, so, se = await run(
            [bin_, "-d", dom, "-b", "crtsh,hackertarget,rapiddns,otx",
             "-f", str(out)],
            timeout=300)
        jpath = out.with_suffix(".json")
        emails, hosts = set(), set()
        if jpath.exists():
            try:
                d = json.loads(jpath.read_text())
                emails = set(d.get("emails", []))
                hosts = set(d.get("hosts", []))
            except Exception:
                pass
        if not emails and not hosts:
            emails = set(EMAIL_RE.findall(so))
        for e in emails:
            ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                           confidence=0.6, rel="harvested")
        for h in list(hosts)[:100]:
            host = h.split(":")[0].strip().lower()
            if host.endswith(dom):
                ctx.add_entity(EntityType.HOST, host, source=self.name,
                               confidence=0.75, rel="subdomain")
        ctx.log(f"theHarvester: {len(emails)} emails, {len(hosts)} hosts")


@register
class ExifTool(Module):
    name = "exiftool"
    label = "exiftool"
    category = "image"
    accepts = {EntityType.IMAGE}
    modes = {MODE_SELF}
    requires_tool = "exiftool"
    weight = 1

    async def run(self, ctx: Context) -> None:
        path = ctx.entity.meta.get("path")
        if not path:
            return
        bin_ = which("exiftool")
        code, so, se = await run([bin_, "-json", "-n", path], timeout=60)
        try:
            meta = json.loads(so)[0]
        except Exception:
            return
        interesting = ("Make", "Model", "GPSLatitude", "GPSLongitude",
                       "CreateDate", "Artist", "Copyright", "Software",
                       "SerialNumber", "OwnerName")
        for k in interesting:
            if meta.get(k) not in (None, ""):
                ctx.finding(f"{k}: {meta[k]}", source=self.name,
                            confidence=0.7)
        lat, lon = meta.get("GPSLatitude"), meta.get("GPSLongitude")
        if lat and lon:
            ctx.add_entity(EntityType.LOCATION, f"{lat},{lon}",
                           source=self.name, confidence=0.95,
                           rel="photo_location",
                           meta={"lat": lat, "lon": lon})
