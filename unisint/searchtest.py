"""`unisint search-test` — run one real search end to end and check the pipeline.

    unisint search-test --type domain example.com
    unisint search-test --type username --mode self yourhandle

Stages checked, each against the previous one:
  1. provider call(s)  — status, raw result count (titles/snippets/URLs printed)
  2. normalise/dedupe  — malformed URLs dropped, duplicates merged w/ provenance
  3. engine + web_search module — URL entities created (basis=candidate)
  4. dossier (server builder used by the UI) — search_results section
  5. HTML + CSV report renderers — every result URL present, escaped
Credentials are never printed: only which provider is configured and whether
its key came from the config file or an environment variable.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import textwrap

import httpx

from . import base, config
from .engine import Engine
from .models import EntityType
from .pivot import Limits
from .report import render_csv, render_html
from .search import configured_providers, run_search
from .synthesis import build_dossier

TYPES = {"domain": EntityType.DOMAIN, "email": EntityType.EMAIL,
         "username": EntityType.USERNAME, "full_name": EntityType.FULL_NAME}


def _short(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


async def run(etype: str, value: str, mode: str) -> int:
    cfg = config.load()
    providers = configured_providers(cfg)
    src = cfg.get("_sources", {})
    print("== providers ==")
    if not providers:
        print("  none configured. Set one of:\n"
              "    UNISINT_BRAVE_API_KEY\n"
              "    UNISINT_GOOGLE_CSE_KEY + UNISINT_GOOGLE_CSE_CX\n"
              "    UNISINT_SEARXNG_URL\n"
              "  (or enter them in SETTINGS). Live search NOT verified.")
        return 2
    for p in providers:
        where = {"brave": src.get("brave"), "google_cse": src.get("google_cse_key"),
                 "searxng": src.get("searxng_url")}.get(p.name)
        print(f"  {p.name}: configured (credential source: {where})")

    # 1-2: provider calls + merge
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        queries, outcomes, results = await run_search(
            etype, value, mode, providers=providers, client=client)
    print(f"\n== 1. provider calls ({len(queries)} queries × {len(providers)} providers) ==")
    raw_total = 0
    for oc in outcomes:
        raw_total += len(oc.results)
        print(f"  [{oc.provider}] {oc.status:12} {len(oc.results):3} results  "
              f"q={_short(oc.query, 60)!r} {('— ' + oc.detail) if oc.detail else ''}")
    ok_calls = [o for o in outcomes if o.status in ("ok", "empty")]
    print(f"\n== 2. normalised + deduplicated: {raw_total} raw -> {len(results)} unique ==")
    for r in results[:15]:
        print(f"  • {_short(r.title, 80)}\n    {r.url}\n    {_short(r.snippet, 140)}"
              f"\n    providers={r.providers} hits={len(r.hits)}")
    if not ok_calls:
        print("\nRESULT: every provider call failed — live search NOT working "
              "(see statuses above).")
        return 1

    # 3: engine + real web_search module
    saved = list(base._REGISTRY)
    base.load_all()
    base._REGISTRY[:] = [m for m in base._REGISTRY if m.name == "web_search"]

    async def emit(_):
        pass

    try:
        eng = Engine(mode=mode, config=cfg, emit=emit, weight_cap=3,
                     limits=Limits(depth=0, time_budget=120))
        eng.add_entity(TYPES[etype], value, source="input")
        await eng.run()
    finally:
        base._REGISTRY[:] = saved
    snap = eng.snapshot()
    ents = [e for e in snap["entities"] if e["meta"].get("kind") == "search_result"]
    print(f"\n== 3. engine: {len(ents)} search_result entities "
          f"(module state: {eng.module_status.get('web_search', {}).get('state')}) ==")

    # 4-5: dossier + reports (same builders the UI/exports use)
    d = build_dossier(snap)
    html, csv_text = render_html(d), render_csv(d)
    urls = [i["url"] for i in d["search_results"]]
    missing_html = [u for u in urls if u.replace("&", "&amp;") not in html]
    missing_csv = [u for u in urls if u not in csv_text]
    entity_urls = {e["value"] for e in ents}
    mismatch = [u for u in urls if u not in entity_urls]
    print(f"== 4. dossier: {len(urls)} search results, labels: "
          f"{sorted({i['assessment']['label'] for i in d['search_results']})} ==")
    print(f"== 5. report: HTML missing {len(missing_html)}, CSV missing {len(missing_csv)}, "
          f"dossier/entity URL mismatches {len(mismatch)} ==")
    out = config.HOME / "search-test-report.html"
    out.write_text(html)
    print(f"   HTML written to {out}")
    healthy = urls and not (missing_html or missing_csv or mismatch)
    print("\nRESULT:", "live search pipeline verified end to end" if healthy else
          "pipeline check FAILED or no results — see above")
    return 0 if healthy else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="unisint search-test",
                                 description=textwrap.dedent(__doc__ or ""),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("value")
    ap.add_argument("--type", choices=sorted(TYPES), default="domain")
    ap.add_argument("--mode", choices=["self", "recon"], default=None)
    a = ap.parse_args(argv)
    mode = a.mode or ("recon" if a.type == "domain" else "self")
    return asyncio.run(run(a.type, a.value, mode))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
