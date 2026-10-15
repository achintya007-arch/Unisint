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
        import dns.asyncresolver
        import dns.exception
        import dns.resolver

        dom = ctx.entity.value
        res = dns.asyncresolver.Resolver()
        res.lifetime = 8.0
        found, failures = 0, {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                ans = await res.resolve(dom, rtype)
            except dns.resolver.NoAnswer:
                continue                       # record type simply absent
            except dns.resolver.NXDOMAIN:
                ctx.log(f"DNS: {dom} does not exist (NXDOMAIN)", level="muted")
                return
            except (dns.exception.DNSException, OSError) as exc:
                failures[rtype] = type(exc).__name__
                continue
            for rec in ans:
                txt = rec.to_text()
                found += 1
                if rtype in ("A", "AAAA"):
                    ctx.add_entity(EntityType.IP, txt, source=self.name,
                                   rel="resolves_to")
                elif rtype == "MX":
                    host = txt.split()[-1].rstrip(".")
                    ctx.add_entity(EntityType.HOST, host, source=self.name,
                                   rel="mail_server")
                elif rtype == "NS":
                    ctx.add_entity(EntityType.HOST, txt.rstrip("."),
                                   source=self.name, rel="name_server")
                else:  # TXT
                    ctx.finding(f"TXT: {txt[:120]}", source=self.name,
                                meta={"rtype": "TXT"})
                    for e in EMAIL_RE.findall(txt):
                        ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                       rel="mentioned")
        if failures and not found:
            ctx.error(f"DNS lookups failed for {dom}: {failures}")
            return
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
            ctx.error(f"rdap failed: {exc}")
            return
        if not ctx.check_http(r, "rdap"):
            return
        try:
            d = r.json()
        except Exception:
            return
        for ev in d.get("events", []):
            if ev.get("eventAction") in ("registration", "expiration"):
                ctx.finding(f"{ev['eventAction']}: {ev.get('eventDate')}",
                            source=self.name, meta=ev)
        for ent in d.get("entities", []):
            for item in ent.get("vcardArray", [[], []])[1:]:
                for row in item:
                    if row and row[0] == "fn" and len(row) > 3:
                        ctx.add_entity(EntityType.ORG, row[3], source=self.name,
                                       rel="registrant")
        raw = json.dumps(d)
        for e in set(EMAIL_RE.findall(raw)):
            ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                           rel="whois_contact")


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
            ctx.error(f"crt.sh failed: {exc}")
            return
        if not ctx.check_http(r, "crt.sh"):
            return
        try:
            rows = r.json()
        except Exception:
            ctx.error("crt.sh: unparseable JSON (service often returns HTML when overloaded)")
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
                           rel="subdomain")


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
            ctx.error(f"wayback failed: {exc}")
            return
        if not ctx.check_http(r, "wayback"):
            return
        try:
            rows = r.json()
        except Exception:
            ctx.error("wayback: unparseable response")
            return
        if len(rows) <= 1:
            return
        ctx.log(f"wayback: {len(rows) - 1} archived URLs")
        first = rows[1][1] if len(rows[1]) > 1 else ""
        ctx.finding(f"earliest archive: {first}", source=self.name,
                    meta={"timestamp": first})


@register
class HttpFingerprint(Module):
    name = "httpfp"
    label = "HTTP Fingerprint"
    category = "domain"
    accepts = {EntityType.DOMAIN, EntityType.HOST}
    modes = {MODE_SELF, MODE_RECON}
    weight = 2
    active = True

    async def run(self, ctx: Context) -> None:
        # Active probe: only reached for in-scope assets (pivot policy), and
        # every request goes through the SSRF-guarded client with redirects
        # re-validated hop by hop.
        from ..urls import UnsafeTarget, safe_get

        host = ctx.entity.value.strip().lower().rstrip(".")
        allow_unresolved = bool(ctx.config.get("trust_proxy_resolution"))
        errors: dict[str, str] = {}
        for scheme in ("https", "http"):
            base_url = f"{scheme}://{host}/"
            try:
                r, final, hops, body = await safe_get(
                    ctx._engine.safe_http, base_url,
                    allow_unresolved=allow_unresolved)
            except UnsafeTarget as exc:
                ctx.log(f"httpfp refused {host}: {exc}", level="warn")
                return
            except Exception as exc:
                errors[scheme] = f"{type(exc).__name__}: {exc}"[:120]
                continue
            server = r.headers.get("server", "")
            powered = r.headers.get("x-powered-by", "")
            tech = ", ".join(t for t in (server, powered) if t)
            if tech:
                ctx.finding(f"tech: {tech}", source=self.name, source_url=final,
                            meta={"server": server, "x-powered-by": powered,
                                  "http_status": r.status_code})
            try:
                st, st_final, _, st_body = await safe_get(
                    ctx._engine.safe_http, f"{scheme}://{host}/.well-known/security.txt",
                    allow_unresolved=allow_unresolved)
                if st.status_code == 200 and "contact:" in st_body.lower():
                    for e in sorted(set(EMAIL_RE.findall(st_body))):
                        ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                       rel="security_contact", source_url=st_final)
            except Exception:
                pass
            for e in sorted(set(EMAIL_RE.findall(body)))[:10]:
                ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                               rel="on_site", source_url=final)
            return
        ctx.error(f"httpfp: {host} unreachable over https/http — {errors}")
