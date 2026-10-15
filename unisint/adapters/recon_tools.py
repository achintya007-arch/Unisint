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


# ---- upstream-source status (tools exit 0 even when every source fails) ----

FAILED_STATES = {"failed", "rate-limited"}


def summarize_sources(execs: dict[str, dict]) -> tuple[str, str]:
    """Aggregate per-source outcomes → (status, human detail).

    ``execs`` maps source → {"status": completed|partial|failed|rate-limited|
    skipped, "detail": str}. Returns status in:
      complete — every attempted source completed
      partial  — some sources failed/partial (results may be incomplete)
      failed   — every attempted source failed
      unknown  — no per-source information available
    """
    attempted = {k: v for k, v in execs.items() if v.get("status") != "skipped"}
    if not attempted:
        return ("unknown", "no per-source status reported") if not execs else \
            ("failed", "every source was skipped (missing keys?)")
    bad = {k: v for k, v in attempted.items() if v.get("status") in FAILED_STATES}
    part = {k: v for k, v in attempted.items() if v.get("status") == "partial"}

    def fmt(d):
        return ", ".join(f"{k} ({v.get('detail') or v.get('status')})" for k, v in sorted(d.items()))
    if len(bad) == len(attempted):
        return "failed", f"all {len(attempted)} source(s) failed: {fmt(bad)}"
    if bad or part:
        return "partial", (f"{len(bad)} of {len(attempted)} source(s) failed"
                           + (f": {fmt(bad)}" if bad else "")
                           + (f"; partial: {fmt(part)}" if part else ""))
    return "complete", f"{len(attempted)} source(s) completed"


def parse_harvester_summary(jsonl_text: str) -> dict | None:
    """theHarvester >= 5 writes a ``type: summary`` record to NAME.jsonl with
    ``source_executions`` (status ∈ completed/partial/failed/rate-limited/
    skipped, stop_reason, result_count) and ``evidence_status``."""
    for line in (jsonl_text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") == "summary":
            execs = {}
            for e in rec.get("source_executions") or []:
                if e.get("source"):
                    execs[e["source"]] = {
                        "status": e.get("status", ""),
                        "detail": e.get("stop_reason") or e.get("error_type") or "",
                        "results": e.get("result_count", 0)}
            return {"evidence_status": rec.get("evidence_status"),
                    "result_count": rec.get("result_count"), "executions": execs}
    return None


_SF_HEADER = re.compile(r"^\s*Source\s+Duration\s+Results\s+Requests\s+Errors\s*$")
_SF_ROW = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")


def parse_subfinder_stats(stderr: str) -> dict[str, dict] | None:
    """Parse the ``-stats`` table (Source/Duration/Results/Requests/Errors).

    subfinder has no machine-readable stats output; the table is printed with
    a fixed format. We anchor on the exact header and require each row to
    match the column shape — if the header is absent we return None
    ("unknown"), never "success".
    """
    lines = _ANSI.sub("", stderr or "").splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if _SF_HEADER.match(l))
    except StopIteration:
        return None
    out: dict[str, dict] = {}
    for l in lines[start + 1:]:
        if set(l.strip()) <= {"─", "-", ""}:
            continue
        m = _SF_ROW.match(l)
        if not m:
            break                       # end of table (e.g. "skipped" list)
        name, _dur, res, req, err = m.groups()
        res, req, err = int(res), int(req), int(err)
        if req == 0:
            status, detail = "skipped", "no requests"
        elif err and not res:
            status, detail = "failed", f"{err} error(s) / {req} request(s)"
        elif err:
            status, detail = "partial", f"{err} error(s) / {req} request(s)"
        else:
            status, detail = "completed", ""
        out[name] = {"status": status, "detail": detail, "results": res}
    return out


def report_upstream(ctx: Context, tool: str, execs: dict | None, n_results: int) -> None:
    """Translate upstream status into the module's run status."""
    if execs is None:
        ctx.partial(f"{tool}: upstream source status unknown (no stats emitted); "
                    "an empty result cannot be trusted")
        return
    status, detail = summarize_sources(execs)
    if status == "failed" and n_results == 0:
        ctx.error(f"{tool}: {detail}")
    elif status in ("failed", "partial", "unknown"):
        ctx.partial(f"{tool}: {detail} — results may be incomplete")


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
        # Not -silent: -stats (per-source Results/Requests/Errors) is only
        # printed without it. JSON results go to stdout, logs+stats to stderr.
        code, so, se = await run([which("subfinder"), "-d", dom, "-oJ", "-nc",
                                  "-stats"], timeout=300)
        rows = parse_subfinder(so, dom)
        if code != 0 and not rows:
            raise RuntimeError(f"subfinder exit {code}: {(se or so).strip()[-160:]}")
        ctx.log(f"subfinder: {len(rows)} subdomains")
        for r in rows[:150]:
            ctx.add_entity(EntityType.HOST, r["host"], source=self.name,
                           rel="subdomain",
                           meta={"upstream_sources": r["sources"]})
        report_upstream(ctx, "subfinder", parse_subfinder_stats(se), len(rows))


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
        # theHarvester >= 5 strips directories from -f (os.path.basename) and
        # writes NAME.json / NAME.jsonl into the *current directory*, so run it
        # inside a scratch dir and pass a bare name.
        work = tmp_dir(f"harvester-{dom}")
        for ext in (".json", ".jsonl", ".xml"):
            (work / f"result{ext}").unlink(missing_ok=True)
        code, so, se = await run(
            [which("theHarvester"), "-d", dom, "-b", self.SOURCES, "-f", "result"],
            timeout=420, cwd=str(work))
        jpath = work / "result.json"
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
        lpath = work / "result.jsonl"
        summary = parse_harvester_summary(lpath.read_text()) if lpath.exists() else None
        report_upstream(ctx, "theHarvester", summary["executions"] if summary else None,
                        len(res["emails"]) + len(res["hosts"]))
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
