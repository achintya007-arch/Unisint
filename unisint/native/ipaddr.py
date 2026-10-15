"""IP recon: geolocation / ASN (ip-api, keyless) and open ports / known
CVEs via Shodan InternetDB (keyless). Reverse DNS."""
from __future__ import annotations

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType


@register
class IpGeo(Module):
    name = "ipgeo"
    label = "IP Geo / ASN"
    category = "ip"
    accepts = {EntityType.IP}
    modes = {MODE_SELF, MODE_RECON}
    weight = 1

    async def run(self, ctx: Context) -> None:
        ip = ctx.entity.value
        try:
            r = await ctx.http.get(
                f"http://ip-api.com/json/{ip}"
                "?fields=status,country,regionName,city,isp,org,as,reverse,lat,lon")
        except Exception as exc:
            ctx.error(f"ip-api failed: {exc}")
            return
        if not ctx.check_http(r, "ip-api"):
            return
        d = r.json()
        if d.get("status") != "success":
            ctx.error(f"ip-api: {d.get('message', 'lookup failed')}")
            return
        loc = ", ".join(x for x in (d.get("city"), d.get("regionName"),
                                    d.get("country")) if x)
        if loc:
            ctx.add_entity(EntityType.LOCATION, loc, source=self.name,
                           rel="geolocated", basis="derived",
                           meta={"lat": d.get("lat"), "lon": d.get("lon"),
                                 "note": "IP geolocation estimate (ip-api)"})
        if d.get("org") or d.get("isp"):
            ctx.add_entity(EntityType.ORG, d.get("org") or d.get("isp"),
                           source=self.name, rel="hosted_by")
        if d.get("as"):
            ctx.finding(f"ASN: {d['as']}", source=self.name)
        if d.get("reverse"):
            ctx.add_entity(EntityType.HOST, d["reverse"], source=self.name,
                           rel="reverse_dns")


@register
class InternetDb(Module):
    name = "internetdb"
    label = "Shodan InternetDB"
    category = "ip"
    accepts = {EntityType.IP}
    modes = {MODE_SELF, MODE_RECON}
    weight = 2

    async def run(self, ctx: Context) -> None:
        ip = ctx.entity.value
        try:
            r = await ctx.http.get(f"https://internetdb.shodan.io/{ip}")
        except Exception as exc:
            ctx.error(f"internetdb failed: {exc}")
            return
        if r.status_code == 404:
            ctx.log("internetdb: no data for this IP", level="muted")
            return
        if not ctx.check_http(r, "internetdb"):
            return
        d = r.json()
        ports = d.get("ports", [])
        if ports:
            ctx.finding(f"open ports: {', '.join(map(str, ports))}",
                        source=self.name, meta={"ports": ports})
        for cve in (d.get("vulns") or [])[:20]:
            ctx.finding(f"CVE: {cve}", source=self.name,
                        meta={"cve": cve, "severity": "see-nvd"})
        for host in (d.get("hostnames") or []):
            ctx.add_entity(EntityType.HOST, host, source=self.name,
                           rel="hostname_of")
