"""Web search module: real retrieval through configured search APIs.

What gets recorded:
* every provider outcome (ok / empty / rate_limited / auth_error / quota /
  error / timeout) as a status finding, so failures are visible;
* each merged result as a URL entity with ``basis='candidate'`` and full
  provenance (providers, queries, ranks, retrieval time);
* for domain queries, emails/hosts under that domain mentioned in results —
  also candidates.
Nothing found here is expanded automatically.
"""
from __future__ import annotations

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType
from ..search import (configured_providers, extract_domain_evidence,
                      run_search, term_in_result)

TYPE_MAP = {EntityType.DOMAIN: "domain", EntityType.EMAIL: "email",
            EntityType.USERNAME: "username", EntityType.FULL_NAME: "full_name"}


@register
class WebSearch(Module):
    name = "web_search"
    label = "Web Search"
    category = "search"
    accepts = set(TYPE_MAP)
    modes = {MODE_SELF, MODE_RECON}
    weight = 2

    async def available(self, engine):
        if not configured_providers(engine.config):
            return False, ("no search provider configured "
                           "(Brave key, Google CSE key+cx, or searxng_url)")
        return True, "ready"

    async def run(self, ctx: Context) -> None:
        etype = TYPE_MAP[ctx.entity.type]
        providers = configured_providers(ctx.config)
        queries, outcomes, results = await run_search(
            etype, ctx.entity.value, ctx.mode, providers=providers,
            client=ctx.http)
        if not queries:
            ctx.log(f"web_search: no query templates for {etype} in {ctx.mode}",
                    level="muted")
            return
        for oc in outcomes:
            if oc.status not in ("ok", "empty"):
                ctx.finding(f"search provider {oc.provider}: {oc.status}",
                            source=self.name, basis="derived",
                            meta={"kind": "provider_status", "provider": oc.provider,
                                  "status": oc.status, "detail": oc.detail,
                                  "query": oc.query})
        n_ok = sum(1 for o in outcomes if o.status in ("ok", "empty"))
        raw = sum(len(o.results) for o in outcomes)
        # Contacted if any provider actually ran; live unless fixture-backed.
        if any(o.status != "unconfigured" for o in outcomes):
            ctx.mark_contacted(live=not any(p.name == "fixture" for p in providers))
        ctx.result_count = raw
        ctx.mark_truncated(len(results), 30)
        # If every provider failed (none ok/empty), surface the worst status.
        if outcomes and n_ok == 0:
            worst = outcomes[0].status
            ctx.status(worst if worst in ("rate_limited", "auth_error", "timeout")
                       else "error", f"all {len(outcomes)} provider call(s) failed")
        ctx.log(f"web_search: {len(queries)} queries × {len(providers)} provider(s) "
                f"→ {n_ok}/{len(outcomes)} succeeded, {len(results)} unique results")

        for sr in results[:30]:
            meta = {"url": sr.url, "title": sr.title, "snippet": sr.snippet,
                    "providers": sr.providers, "hits": sr.hits,
                    "kind": "search_result", "url_origin": "search_api"}
            if etype != "domain":
                meta["term_in_snippet"] = term_in_result(sr, ctx.entity.value)
                meta["caveat"] = ("mentions the search term — not verified to "
                                  "be about you")
            first = sr.hits[0]
            ctx.add_entity(EntityType.URL, sr.url, source=self.name,
                           rel="search_result", basis="candidate",
                           source_url=sr.url, meta=meta)
            if etype == "domain":
                ev = extract_domain_evidence(sr, ctx.entity.value)
                for e in ev["emails"]:
                    ctx.add_entity(EntityType.EMAIL, e, source=self.name,
                                   rel="mentioned_in_result", basis="candidate",
                                   source_url=sr.url,
                                   meta={"result_url": sr.url,
                                         "provider": first["provider"]})
                for h in ev["hosts"]:
                    if h != ctx.entity.value.lower():
                        ctx.add_entity(EntityType.HOST, h, source=self.name,
                                       rel="mentioned_in_result", basis="candidate",
                                       source_url=sr.url,
                                       meta={"result_url": sr.url})
