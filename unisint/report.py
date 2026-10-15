"""Exports rendered server-side from the *same* dossier the UI displays.

Both the HTML report and the CSV are produced from ``build_dossier`` output,
so exported links, labels and validation states are identical to the UI.
All untrusted text is HTML-escaped and only http(s) URLs become links.
"""
from __future__ import annotations

import csv
import io
import time
from html import escape
from typing import Iterable

from .urls import normalize_url

CSV_COLUMNS = ["section", "type", "value", "label", "conflicting", "basis",
               "validation_state", "http_status", "final_url", "validated_at",
               "sources", "via", "parent", "source_url", "site", "url"]


def _safe_url(u: str | None) -> str | None:
    return normalize_url(u) if u else None


def _rows(d: dict) -> Iterable[tuple[str, dict]]:
    for item in d.get("seeds", []):
        yield "seed", item
    for item in d.get("accounts", []):
        yield "account", item
    for item in d.get("linked_urls", []):
        yield "linked_url", item
    for t, items in (d.get("identifiers") or {}).items():
        for item in items:
            yield f"identifier:{t}", item
    for item in d.get("registrations", []):
        yield "registration", item
    for item in d.get("search_results", []):
        yield "search_result", item
    for item in d.get("findings", []):
        yield "finding", item


def render_csv(d: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for section, it in _rows(d):
        v = it.get("validation") or {}
        p = it.get("provenance") or {}
        a = it.get("assessment") or {}
        row = [section, it.get("type"), it.get("value"), a.get("label", ""),
               a.get("conflicting", False), it.get("basis"), v.get("state", "unchecked"),
               v.get("http_status") or "", v.get("final_url") or "",
               time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(v["checked_at"]))
               if v.get("checked_at") else "",
               "|".join(p.get("sources") or []), p.get("via") or "",
               p.get("parent") or "", p.get("source_url") or "",
               it.get("site") or "", it.get("url") or ""]
        # Neutralise spreadsheet formula injection from untrusted values.
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@")
                    else c for c in row])
    return buf.getvalue()


def _link(url: str | None, text: str | None = None) -> str:
    safe = _safe_url(url)
    label = escape(text or url or "")
    if not safe:
        return f'<span class="nolink" title="not a valid http(s) URL">{label}</span>'
    return f'<a href="{escape(safe, quote=True)}" rel="noopener noreferrer">{label}</a>'


def _vbadge(v: dict | None) -> str:
    if not v:
        return '<span class="b unchecked">unchecked</span>'
    st = escape(v.get("state", "?"))
    det = escape(v.get("detail", ""))
    return f'<span class="b v-{st}" title="{det}">{st}</span>'


def _why(it: dict) -> str:
    a = it.get("assessment") or {}
    p = it.get("provenance") or {}
    parts = []
    for k, cls in (("supports", "sup"), ("conflicts", "con"), ("unknown", "unk")):
        for line in a.get(k) or []:
            parts.append(f'<li class="{cls}">{escape(k[:-1] if k != "unknown" else "unknown")}: '
                         f'{escape(line)}</li>')
    src = escape(", ".join(p.get("sources") or []))
    parts.append(f'<li class="prov">sources: {src}; via {escape(str(p.get("via")))} of '
                 f'{escape(str(p.get("parent")))}'
                 + (f'; source URL {_link(p.get("source_url"))}' if p.get("source_url") else "")
                 + "</li>")
    return "<ul class='why'>" + "".join(parts) + "</ul>"


def _item_li(it: dict) -> str:
    a = it.get("assessment") or {}
    label = escape(a.get("title", ""))
    conflict = ' <span class="b con">conflicting evidence</span>' if a.get("conflicting") else ""
    site = f"<b>{escape(it['site'])}</b> " if it.get("site") else ""
    target = _link(it.get("url"), it.get("url")) if it.get("url") else escape(it.get("value", ""))
    return (f"<li>{site}{target} {_vbadge(it.get('validation'))} "
            f'<span class="b lab">{label}</span>{conflict}{_why(it)}</li>')


def render_html(d: dict) -> str:
    sec: list[str] = []

    def section(title: str, body: str) -> None:
        if body:
            sec.append(f"<h2>{escape(title)}</h2>{body}")

    section("Seeds", "<ul>" + "".join(f"<li>{escape(s['type'])}: {escape(s['value'])}</li>"
                                     for s in d.get("seeds", [])) + "</ul>")
    for key, items in (d.get("account_groups") or {}).items():
        title = (items[0]["assessment"]["title"] if items else key)
        section(f"Accounts — {title} ({len(items)})",
                "<ul>" + "".join(_item_li(i) for i in items) + "</ul>")
    section("Links listed on profiles",
            "<ul>" + "".join(_item_li(i) for i in d.get("linked_urls", [])) + "</ul>"
            if d.get("linked_urls") else "")
    regs = d.get("registrations", [])
    section("Registrations (site domain only — no profile URL is known)",
            "<ul>" + "".join(f"<li>{escape(r['value'])} "
                             f"<small>({escape(', '.join(r['provenance']['sources']))})</small></li>"
                             for r in regs) + "</ul>" if regs else "")
    for t, items in (d.get("identifiers") or {}).items():
        section(f"{t.title()}s found", "<ul>" + "".join(_item_li(i) for i in items) + "</ul>"
                if items else "")
    names = d.get("names_on_profiles", [])
    section("Names shown on profiles (not evidence of who you are)",
            "<ul>" + "".join(f"<li>{escape(n['name'])} — on {escape(str(n['on']))}</li>"
                             for n in names) + "</ul>" if names else "")
    inf = d.get("infrastructure") or {}
    if any(inf.values()):
        body = "".join(f"<p><b>{escape(k.replace('_', ' '))}</b>: "
                       f"{escape(', '.join(v)) or '—'}</p>" for k, v in inf.items())
        section("Infrastructure", body)
    sr = d.get("search_results", [])
    section("Search results (candidates — unverified)",
            "<ul>" + "".join(
                f"<li>{_link(i['url'], i['meta'].get('title') or i['url'])} "
                f"<small>[{escape(', '.join(i['meta'].get('providers', [])))}]</small> "
                f"{_vbadge(i.get('validation'))}<br><small>{escape(i['meta'].get('snippet', ''))}"
                f"</small>{_why(i)}</li>" for i in sr) + "</ul>" if sr else "")
    fnd = d.get("findings", [])
    section("Findings", "<ul>" + "".join(
        f"<li>[{escape(f['provenance']['sources'][0] if f['provenance']['sources'] else '?')}] "
        f"{escape(f['value'])}</li>" for f in fnd) + "</ul>" if fnd else "")
    ms = d.get("module_status", {})
    section("Module status", "<table>" + "".join(
        f"<tr><td>{escape(k)}</td><td>{escape(str(v.get('state')))}</td>"
        f"<td>{escape(str(v.get('last_error') or ''))}</td></tr>"
        for k, v in sorted(ms.items())) + "</table>" if ms else "")
    ps = d.get("pivot_summary") or {}
    if ps:
        section("Pivots", f"<p>expanded {ps.get('expanded', 0)}, not expanded "
                          f"{ps.get('not_expanded', 0)}</p><ul>" + "".join(
                              f"<li>{escape(r)} ×{n}</li>" for r, n in ps.get("skip_reasons", []))
                + "</ul>")
    rem = d.get("remediation", [])
    section("Remediation", "<ul>" + "".join(
        f"<li><b>[{escape(r.get('severity', '').upper())}] {escape(r['title'])}</b><br>"
        f"{escape(r['action'])} {_link(r.get('url')) if r.get('url') else ''}"
        + "".join(" · " + _link(l["url"], l["name"]) for l in r.get("links", []))
        + "</li>" for r in rem) + "</ul>" if rem else "")
    risk = "; ".join(escape(r) for r in d.get("risk_flags", [])) or "none flagged"
    c = d.get("counts", {})
    return f"""<!doctype html><meta charset="utf-8"><title>UNISINT dossier</title>
<style>body{{font-family:monospace;background:#02060a;color:#33ff66;padding:32px;max-width:980px;margin:auto}}
h1{{color:#ffb000}}h2{{color:#27e8ff;border-bottom:1px solid #1c8a3e;margin-top:28px}}a{{color:#27e8ff}}
li{{margin:6px 0}}.b{{font-size:11px;padding:1px 6px;border:1px solid #1c8a3e;margin-left:4px}}
.v-reachable{{color:#27e8ff}}.v-not_found,.v-soft_404{{color:#ff2e4d;text-decoration:line-through}}
.unchecked,.v-blocked,.v-rate_limited,.v-timeout,.v-error,.v-login_wall{{color:#ffb000}}
.v-unsafe,.v-invalid,.con{{color:#ff2e4d}}.lab{{color:#ffb000}}.why{{font-size:12px;color:#1c8a3e}}
.why .sup{{color:#8affb0}}.why .con{{color:#ff7a8a}}.why .unk{{color:#c9a54a}}.nolink{{color:#888}}
td{{padding:2px 10px;border-bottom:1px dashed #0c3a1e}}</style>
<h1>UNISINT DOSSIER</h1>
<p>mode: {escape(d.get('mode', ''))} · generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</p>
<p>accounts: {c.get('accounts', 0)} (strongly linked: {c.get('accounts_strong', 0)}) ·
registrations: {c.get('registrations', 0)} · search results: {c.get('search_results', 0)}</p>
<p>Risk: {risk}</p>
<p><small>Labels describe the evidence, not certainty. A handle or name match is not
proof of identity; "reachable" means a page loaded, not that it belongs to anyone.</small></p>
{''.join(sec)}
<hr><p><small>Public-source OSINT for self-audit / authorised assessment.</small></p>"""
