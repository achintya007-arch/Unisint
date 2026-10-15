"""Domain recon: DNS, RDAP/WHOIS, certificate-transparency subdomains,
Wayback, and a light HTTP tech fingerprint. Keyless and public-source."""
from __future__ import annotations

import json
import re

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@register
class Dns(Module):
    name = "dns"
    label = "DNS Records"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    weight = 1

    async def run(self, ctx: Context) -> None:
        import asyncio

        import dns.asyncresolver

        dom = ctx.entity.value
        res = dns.asyncresolver.Resolver()
        res.lifetime = 8.0
        found = 0
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                ans = await res.resolve(dom, rtype)
            except Exception:
                continue
            for rec in ans:
                txt = rec.to_text()
                found += 1
                if rtype in ("A", "AAAA"):
                    ctx.add_entity(EntityType.IP, txt, source=self.name,
                                   confidence=0.9, rel="resolves_to")
                elif rtype == "MX":
                    host = txt.split()[-1].rstrip(".")
                    ctx.add_entity(EntityType.HOST, host, source=self.name,
                                   confidence=0.7, rel="mail_server")
                elif rtype == "NS":
                    ctx.add_entity(EntityType.HOST, txt.rstrip("."),
                                   source=self.name, confidence=0.6,
                                   rel="name_server")
                else:  # TXT
                    ctx.finding(f"TXT: {txt[:120]}", source=self.name,
                                meta={"rtype": "TXT"}, confidence=0.5)
                    for e in EMAIL_RE.findall(txt):
                        ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                       confidence=0.5, rel="mentioned")
        ctx.log(f"DNS: {found} records")


@register
class Rdap(Module):
    name = "rdap"
    label = "RDAP / WHOIS"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    weight = 1

    async def run(self, ctx: Context) -> None:
        dom = ctx.entity.value
        try:
            r = await ctx.http.get(f"https://rdap.org/domain/{dom}")
        except Exception as exc:
            ctx.log(f"rdap failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            ctx.log("no RDAP record", level="muted")
            return
        try:
            d = r.json()
        except Exception:
            return
        for ev in d.get("events", []):
            if ev.get("eventAction") in ("registration", "expiration"):
                ctx.finding(f"{ev['eventAction']}: {ev.get('eventDate')}",
                            source=self.name, meta=ev, confidence=0.7)
        for ent in d.get("entities", []):
            for item in ent.get("vcardArray", [[], []])[1:]:
                for row in item:
                    if row and row[0] == "fn" and len(row) > 3:
                        ctx.add_entity(EntityType.ORG, row[3], source=self.name,
                                       confidence=0.4, rel="registrant")
        raw = json.dumps(d)
        for e in set(EMAIL_RE.findall(raw)):
            ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                           confidence=0.5, rel="whois_contact")


@register
class CrtSh(Module):
    name = "crtsh"
    label = "crt.sh Subdomains"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    weight = 2

    async def run(self, ctx: Context) -> None:
        dom = ctx.entity.value
        try:
            r = await ctx.http.get(
                f"https://crt.sh/?q=%25.{dom}&output=json", timeout=30.0)
        except Exception as exc:
            ctx.log(f"crt.sh failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            return
        try:
            rows = r.json()
        except Exception:
            return
        subs: set[str] = set()
        for row in rows:
            for name in (row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(dom) and name != dom:
                    subs.add(name)
        ctx.log(f"crt.sh: {len(subs)} unique subdomains")
        for s in sorted(subs)[:50]:
            ctx.add_entity(EntityType.HOST, s, source=self.name,
                           confidence=0.8, rel="subdomain")


@register
class Wayback(Module):
    name = "wayback"
    label = "Wayback Machine"
    category = "domain"
    accepts = {EntityType.DOMAIN, EntityType.URL}
    modes = {MODE_SELF, MODE_RECON}
    weight = 2

    async def run(self, ctx: Context) -> None:
        target = ctx.entity.value.replace("https://", "").replace("http://", "")
        try:
            r = await ctx.http.get(
                "https://web.archive.org/cdx/search/cdx"
                f"?url={target}&output=json&limit=200&collapse=urlkey")
        except Exception as exc:
            ctx.log(f"wayback failed: {exc}", level="warn")
            return
        if r.status_code != 200:
            return
        try:
            rows = r.json()
        except Exception:
            return
        if len(rows) <= 1:
            return
        ctx.log(f"wayback: {len(rows) - 1} archived URLs")
        first = rows[1][1] if len(rows[1]) > 1 else ""
        ctx.finding(f"earliest archive: {first}", source=self.name,
                    meta={"timestamp": first}, confidence=0.6)


@register
class HttpFingerprint(Module):
    name = "httpfp"
    label = "HTTP Fingerprint"
    category = "domain"
    accepts = {EntityType.DOMAIN, EntityType.HOST}
    modes = {MODE_SELF, MODE_RECON}
    weight = 2

    async def run(self, ctx: Context) -> None:
        host = ctx.entity.value
        for scheme in ("https", "http"):
            try:
                r = await ctx.http.get(f"{scheme}://{host}", timeout=12.0)
            except Exception:
                continue
            server = r.headers.get("server", "")
            powered = r.headers.get("x-powered-by", "")
            tech = ", ".join(t for t in (server, powered) if t)
            if tech:
                ctx.finding(f"tech: {tech}", source=self.name,
                            meta={"server": server, "x-powered-by": powered},
                            confidence=0.6)
            # security.txt
            try:
                st = await ctx.http.get(
                    f"{scheme}://{host}/.well-known/security.txt", timeout=10.0)
                if st.status_code == 200:
                    for e in set(EMAIL_RE.findall(st.text)):
                        ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                       confidence=0.6, rel="security_contact")
            except Exception:
                pass
            # emails on the landing page
            for e in list(set(EMAIL_RE.findall(r.text)))[:10]:
                ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                               confidence=0.45, rel="on_site")
            return
