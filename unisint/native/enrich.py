"""Key-gated enrichment APIs: Shodan (full host API), Have I Been Pwned
(breach *names* for an email), Hunter.io (emails for a domain) and VirusTotal
(domain / IP reputation + passive DNS).

Each module declares ``requires_key``; the base ``Module.available`` keeps it
dormant (and shown as "needs API key" in the ARSENAL / PLAN) until the matching
key is present in config or the environment. Keys are read from
``ctx.config['api_keys']`` and never logged (logs are redacted, and request
URLs carrying a key are never emitted).

Scope / ethics: these use *public* and account-holder-authorized data only.
HIBP here returns the **names and metadata** of breaches an address appears in
— never passwords or breached contents. No module bypasses authentication,
rate limits, or a vendor's terms.

Status is reported through the source-run contract (``mark_contacted`` /
``status`` / ``mark_truncated``): a bad key is ``auth_error``, throttling is
``rate_limited``, a clean "nothing found" is ``empty`` — never a silent "ok".
"""
from __future__ import annotations

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType

UA = "UNISINT/3.0 (+public-source OSINT; authorized use only)"


def _auth_rate(ctx: Context, r, service: str) -> bool:
    """Map auth/throttle statuses onto the vocabulary. Returns False only when
    it handled an auth/rate status; True otherwise (incl. other errors, which
    the caller then passes to check_http so they're recorded honestly)."""
    code = r.status_code
    if code in (401, 403):
        ctx.status("auth_error", f"{service}: HTTP {code} — check the API key")
        return False
    if code == 429:
        retry = r.headers.get("retry-after") or r.headers.get("Retry-After") or ""
        ctx.status("rate_limited", f"{service}: HTTP 429 rate limited"
                   + (f" (retry-after {retry}s)" if retry else ""))
        return False
    return True


@register
class ShodanHost(Module):
    """Full Shodan host API (api.shodan.io) — richer than the keyless
    InternetDB module: service banners, product/version, vulns, org/ASN."""
    name = "shodan"
    label = "Shodan (host API)"
    category = "ip"
    accepts = {EntityType.IP}
    modes = {MODE_SELF, MODE_RECON}
    requires_key = "shodan"
    weight = 2

    async def run(self, ctx: Context) -> None:
        key = ctx.config.get("api_keys", {}).get("shodan", "")
        ip = ctx.entity.value
        try:
            r = await ctx.http.get(f"https://api.shodan.io/shodan/host/{ip}",
                                   params={"key": key}, headers={"User-Agent": UA})
        except Exception as exc:
            ctx.error(f"shodan request failed: {exc}")
            return
        ctx.mark_contacted()
        if r.status_code == 404:
            ctx.log(f"shodan: no host data for {ip}", level="muted")
            return
        if not _auth_rate(ctx, r, "shodan"):
            return
        if not ctx.check_http(r, "shodan"):
            return
        try:
            d = r.json()
        except Exception:
            ctx.error("shodan: unparseable response")
            return
        ports = d.get("ports") or []
        if ports:
            ctx.finding(f"open ports: {', '.join(map(str, sorted(ports)))}",
                        source=self.name, meta={"ports": ports})
        if d.get("org") or d.get("isp"):
            ctx.add_entity(EntityType.ORG, d.get("org") or d.get("isp"),
                           source=self.name, rel="hosted_by", basis="derived")
        if d.get("asn"):
            ctx.finding(f"ASN: {d['asn']}", source=self.name, meta={"asn": d["asn"]})
        for host in (d.get("hostnames") or []):
            ctx.add_entity(EntityType.HOST, host, source=self.name, rel="hostname_of")
        # vulns: a list of CVE ids, or a dict keyed by CVE with cvss details.
        vulns = d.get("vulns") or []
        items = vulns.items() if isinstance(vulns, dict) else [(c, {}) for c in vulns]
        for cve, info in list(items)[:30]:
            cvss = (info or {}).get("cvss") if isinstance(info, dict) else None
            ctx.finding(f"CVE: {cve}" + (f" (CVSS {cvss})" if cvss else ""),
                        source=self.name,
                        meta={"cve": cve, "cvss": cvss, "severity": "see-nvd"})
        # One line per exposed service (bounded).
        services = d.get("data") or []
        ctx.mark_truncated(len(services), 25)
        for svc in services[:25]:
            tech = " ".join(str(x) for x in (svc.get("product"), svc.get("version")) if x)
            port = svc.get("port")
            if tech or port:
                ctx.finding(f"service :{port} {tech}".strip(), source=self.name,
                            meta={"port": port, "product": svc.get("product"),
                                  "version": svc.get("version"),
                                  "transport": svc.get("transport")})


@register
class HIBP(Module):
    """Have I Been Pwned (api v3) — which breaches an email appears in.
    Names + metadata only; never passwords or breached contents."""
    name = "hibp"
    label = "Have I Been Pwned"
    category = "email"
    accepts = {EntityType.EMAIL}
    modes = {MODE_SELF}
    requires_key = "hibp"
    weight = 2

    async def run(self, ctx: Context) -> None:
        key = ctx.config.get("api_keys", {}).get("hibp", "")
        email = ctx.entity.value.strip().lower()
        try:
            r = await ctx.http.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": key, "User-Agent": UA})
        except Exception as exc:
            ctx.error(f"hibp request failed: {exc}")
            return
        ctx.mark_contacted()
        if r.status_code == 404:
            ctx.log("hibp: no breaches for this address", level="muted")
            return
        if not _auth_rate(ctx, r, "hibp"):
            return
        if not ctx.check_http(r, "hibp"):
            return
        try:
            breaches = r.json()
        except Exception:
            ctx.error("hibp: unparseable response")
            return
        ctx.mark_truncated(len(breaches), len(breaches))  # all kept; records count
        for b in breaches:
            classes = ", ".join(b.get("DataClasses") or [])
            title = b.get("Title") or b.get("Name") or "?"
            ctx.finding(
                f"breach: {title} ({b.get('BreachDate', '?')})"
                + (f" — exposed: {classes}" if classes else ""),
                source=self.name, basis="derived",
                meta={"kind": "breach", "name": b.get("Name"), "title": title,
                      "breach_date": b.get("BreachDate"),
                      "data_classes": b.get("DataClasses"),
                      "pwn_count": b.get("PwnCount"),
                      "is_verified": b.get("IsVerified")})
        if breaches:
            ctx.log(f"hibp: {len(breaches)} breach(es) — rotate credentials and "
                    "enable 2FA on affected sites", level="warn")


@register
class Hunter(Module):
    """Hunter.io domain-search (api v2) — public email addresses for a domain,
    with the sources that mention them. Discovered addresses are candidates."""
    name = "hunter"
    label = "Hunter.io"
    category = "domain"
    accepts = {EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    requires_key = "hunter"
    weight = 2

    async def run(self, ctx: Context) -> None:
        key = ctx.config.get("api_keys", {}).get("hunter", "")
        dom = ctx.entity.value
        try:
            r = await ctx.http.get("https://api.hunter.io/v2/domain-search",
                                   params={"domain": dom, "api_key": key, "limit": 100},
                                   headers={"User-Agent": UA})
        except Exception as exc:
            ctx.error(f"hunter request failed: {exc}")
            return
        ctx.mark_contacted()
        if not _auth_rate(ctx, r, "hunter"):
            return
        if not ctx.check_http(r, "hunter"):
            return
        try:
            data = r.json().get("data") or {}
        except Exception:
            ctx.error("hunter: unparseable response")
            return
        if data.get("organization"):
            ctx.add_entity(EntityType.ORG, data["organization"], source=self.name,
                           rel="owns_domain", basis="derived")
        if data.get("pattern"):
            ctx.finding(f"email pattern: {data['pattern']}", source=self.name,
                        meta={"pattern": data["pattern"]})
        emails = data.get("emails") or []
        ctx.mark_truncated(len(emails), 100)
        for e in emails[:100]:
            val = e.get("value")
            if not val:
                continue
            srcs = e.get("sources") or []
            ctx.add_entity(EntityType.EMAIL, val, source=self.name,
                           rel="domain_email", basis="candidate",
                           source_url=(srcs[0].get("uri") if srcs else None),
                           meta={"confidence": e.get("confidence"),
                                 "type": e.get("type"),
                                 "position": e.get("position"),
                                 "first_name": e.get("first_name"),
                                 "last_name": e.get("last_name"),
                                 "num_sources": len(srcs),
                                 "caveat": "address published for this domain; "
                                           "not verified to belong to a specific person"})


@register
class VirusTotal(Module):
    """VirusTotal (api v3) — reputation + passive DNS for a domain or IP."""
    name = "virustotal"
    label = "VirusTotal"
    category = "domain"
    accepts = {EntityType.DOMAIN, EntityType.IP}
    modes = {MODE_SELF, MODE_RECON}
    requires_key = "virustotal"
    weight = 2

    async def run(self, ctx: Context) -> None:
        key = ctx.config.get("api_keys", {}).get("virustotal", "")
        val = ctx.entity.value
        is_ip = ctx.entity.type == EntityType.IP
        path = f"ip_addresses/{val}" if is_ip else f"domains/{val}"
        try:
            r = await ctx.http.get(f"https://www.virustotal.com/api/v3/{path}",
                                   headers={"x-apikey": key, "User-Agent": UA})
        except Exception as exc:
            ctx.error(f"virustotal request failed: {exc}")
            return
        ctx.mark_contacted()
        if r.status_code == 404:
            ctx.log(f"virustotal: no record for {val}", level="muted")
            return
        if not _auth_rate(ctx, r, "virustotal"):
            return
        if not ctx.check_http(r, "virustotal"):
            return
        try:
            attrs = (r.json().get("data") or {}).get("attributes") or {}
        except Exception:
            ctx.error("virustotal: unparseable response")
            return
        stats = attrs.get("last_analysis_stats") or {}
        total = sum(v for v in stats.values() if isinstance(v, (int, float)))
        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
        ctx.finding(
            f"VT reputation {attrs.get('reputation', 0)} · "
            f"{mal} malicious / {susp} suspicious of {total} engines",
            source=self.name, basis="derived",
            meta={"malicious": mal, "suspicious": susp, "engines": total,
                  "reputation": attrs.get("reputation")})
        cats = attrs.get("categories") or {}
        if cats:
            ctx.finding("categories: " + ", ".join(sorted(set(cats.values())))[:200],
                        source=self.name, meta={"categories": cats})
        # Passive DNS from the record itself (domain → A/AAAA; IP → not here).
        for rec in (attrs.get("last_dns_records") or [])[:40]:
            rtype, rval = rec.get("type"), rec.get("value")
            if not rval:
                continue
            if rtype in ("A", "AAAA"):
                ctx.add_entity(EntityType.IP, rval, source=self.name, rel="resolves_to")
            elif rtype in ("CNAME", "MX", "NS"):
                ctx.add_entity(EntityType.HOST, rval.rstrip("."), source=self.name,
                               rel=rtype.lower())
