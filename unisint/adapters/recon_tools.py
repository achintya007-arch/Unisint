"""Adapters for domain/host recon tools: subfinder, Amass, theHarvester, exiftool.

All are passive with respect to the target (they query third-party datasets),
so they may run on the seed domain. Results are filtered to the queried domain
before being recorded; anything else is dropped (not silently attributed).
"""
from __future__ import annotations

import json
import re

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType
from ..runner import UnsafeArgument, run, safe_arg, tmp_dir, which

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _in_domain(host: str, dom: str) -> bool:
    h = host.lower().rstrip(".")
    return h == dom or h.endswith("." + dom)


# ---- pure parsers ---------------------------------------------------------

def parse_subfinder(text: str, dom: str) -> list[dict]:
    """subfinder -oJ lines ({"host","source"}) or plain host lines."""
    seen: dict[str, set] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        host, src = line, ""
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                host, src = obj.get("host", ""), obj.get("source", "")
            except json.JSONDecodeError:
                continue
        host = host.lower().rstrip(".")
        if _in_domain(host, dom):
            seen.setdefault(host, set())
            if src:
                seen[host].add(src)
    return [{"host": h, "sources": sorted(s)} for h, s in sorted(seen.items())]


def parse_amass(text: str, dom: str) -> list[str]:
    """Extract FQDNs under ``dom`` from any Amass output format.

    v4 prints graph lines like ``www.x.com (FQDN) --> a_record --> 1.2.3.4
    (IPAddress)``; older versions print bare names. Both are handled.
    """
    pat = re.compile(r"(?<![a-z0-9.-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*"
                     + re.escape(dom.lower()) + r")(?![a-z0-9-])", re.I)
    found = set()
    for line in _ANSI.sub("", text or "").splitlines():
        for m in pat.finditer(line.lower()):
            found.add(m.group(1).rstrip("."))
    return sorted(found)


def parse_harvester_json(data: dict, dom: str) -> dict:
    emails = sorted({e.strip().lower() for e in data.get("emails", []) or []
                     if EMAIL_RE.fullmatch(e.strip())})
    hosts = set()
    for h in data.get("hosts", []) or []:
        host = str(h).split(":")[0].strip().lower()
        if _in_domain(host, dom):
            hosts.add(host)
    return {"emails": emails, "hosts": sorted(hosts),
            "ips": sorted(set(data.get("ips", []) or []))}


# ---- modules ----------------------------------------------------------------

def _domain_arg(ctx: Context) -> str | None:
    try:
        return safe_arg(ctx.entity.value.lower().rstrip("."), "domain")
    except UnsafeArgument as exc:
        ctx.log(str(exc), level="warn")
        return None


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
        dom = _domain_arg(ctx)
        if not dom:
            return
        code, so, se = await run([which("subfinder"), "-d", dom, "-silent", "-oJ"],
                                 timeout=300)
        rows = parse_subfinder(so, dom)
        if code != 0 and not rows:
            raise RuntimeError(f"subfinder exit {code}: {(se or so).strip()[-160:]}")
        ctx.log(f"subfinder: {len(rows)} subdomains")
        for r in rows[:150]:
            ctx.add_entity(EntityType.HOST, r["host"], source=self.name,
                           rel="subdomain",
                           meta={"upstream_sources": r["sources"]})


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
        dom = _domain_arg(ctx)
        if not dom:
            return
        code, so, se = await run(
            [which("amass"), "enum", "-passive", "-d", dom], timeout=420)
        hosts = parse_amass(so, dom)
        if code != 0 and not hosts:
            raise RuntimeError(f"amass exit {code}: {(se or so).strip()[-160:]}")
        ctx.log(f"amass: {len(hosts)} names")
        for h in hosts[:150]:
            if h != dom:
                ctx.add_entity(EntityType.HOST, h, source=self.name, rel="subdomain")


@register
class TheHarvester(Module):
    name = "theharvester"
    label = "theHarvester"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    requires_tool = "theHarvester"
    weight = 3
    # Keyless passive sources only. Breach/credential sources are never used.
    SOURCES = "crtsh,hackertarget,rapiddns,otx,certspotter"

    async def run(self, ctx: Context) -> None:
        dom = _domain_arg(ctx)
        if not dom:
            return
        out = tmp_dir(f"harvester-{dom}") / "result"
        jpath = out.with_suffix(".json")
        jpath.unlink(missing_ok=True)
        code, so, se = await run(
            [which("theHarvester"), "-d", dom, "-b", self.SOURCES, "-f", str(out)],
            timeout=420)
        if not jpath.exists():
            raise RuntimeError(f"theHarvester wrote no JSON (exit {code}): "
                               f"{(se or so).strip()[-200:]}")
        try:
            res = parse_harvester_json(json.loads(jpath.read_text()), dom)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"theHarvester JSON unparseable: {exc}") from exc
        for e in res["emails"]:
            ctx.add_entity(EntityType.EMAIL, e, source=self.name, rel="harvested",
                           meta={"from_sources": self.SOURCES})
        for h in res["hosts"][:150]:
            if h != dom:
                ctx.add_entity(EntityType.HOST, h, source=self.name, rel="subdomain")
        ctx.log(f"theHarvester: {len(res['emails'])} emails, "
                f"{len(res['hosts'])} hosts")


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
        code, so, se = await run([which("exiftool"), "-json", "-n", "--", path],
                                 timeout=60)
        try:
            meta = json.loads(so)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            raise RuntimeError(f"exiftool output unparseable (exit {code})")
        interesting = ("Make", "Model", "GPSLatitude", "GPSLongitude",
                       "CreateDate", "Artist", "Copyright", "Software",
                       "SerialNumber", "OwnerName")
        for k in interesting:
            if meta.get(k) not in (None, ""):
                ctx.finding(f"{k}: {meta[k]}", source=self.name,
                            meta={"kind": "exif", "tag": k})
        lat, lon = meta.get("GPSLatitude"), meta.get("GPSLongitude")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            ctx.add_entity(EntityType.LOCATION, f"{lat},{lon}",
                           source=self.name, rel="photo_location",
                           meta={"lat": lat, "lon": lon})
