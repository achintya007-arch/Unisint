"""Search subsystem: queries → providers → parse → normalise → dedupe →
evidence extraction. A *query* is not a *result*, and a result is not
*verified evidence*: results are recorded as candidates with full provenance
(provider, query, rank, retrieval time) and are never auto-expanded.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass, field

import httpx

from ..urls import normalize_url, url_host
from .providers import Provider, ProviderOutcome, RawResult, configured_providers
from .queries import Query, generate_queries

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b", re.I)


@dataclass
class SearchResult:
    url: str                          # normalised
    title: str
    snippet: str
    hits: list[dict] = field(default_factory=list)   # [{provider, query, template_id, rank, retrieved_at}]

    @property
    def providers(self) -> list[str]:
        return sorted({h["provider"] for h in self.hits})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["providers"] = self.providers
        return d


def merge_results(outcomes: list[tuple[Query, ProviderOutcome]]) -> list[SearchResult]:
    """Normalise URLs and merge duplicates across providers/queries.

    Malformed URLs are dropped. Every (provider, query, rank) hit is kept.
    Order: number of independent hits, then best rank.
    """
    by_url: dict[str, SearchResult] = {}
    for q, oc in outcomes:
        for r in oc.results:
            url = normalize_url(r.url)
            if not url:
                continue
            sr = by_url.get(url)
            if sr is None:
                sr = by_url[url] = SearchResult(url=url, title=r.title.strip(),
                                                snippet=r.snippet.strip())
            elif not sr.snippet and r.snippet:
                sr.snippet = r.snippet.strip()
            sr.hits.append({"provider": oc.provider, "query": q.text,
                            "template_id": q.template_id, "rank": r.rank,
                            "retrieved_at": oc.retrieved_at})
    return sorted(by_url.values(),
                  key=lambda s: (-len(s.hits), min(h["rank"] for h in s.hits), s.url))


def extract_domain_evidence(result: SearchResult, domain: str) -> dict:
    """Emails at, and subdomains of, ``domain`` mentioned in a result."""
    d = domain.lower().rstrip(".")
    text = f"{result.title} {result.snippet}"
    emails = sorted({e.lower() for e in EMAIL_RE.findall(text)
                     if e.lower().endswith("@" + d) or e.lower().endswith("." + d)})
    hosts = {h.lower() for h in HOST_RE.findall(text)}
    hosts.add(url_host(result.url))
    hosts = sorted(h for h in hosts if h.endswith("." + d))  # apex = query subject
    return {"emails": emails, "hosts": hosts}


def term_in_result(result: SearchResult, term: str) -> bool:
    t = " ".join(term.lower().split())
    return t in " ".join(f"{result.title} {result.snippet}".lower().split())


async def run_search(entity_type: str, value: str, mode: str, *,
                     providers: list[Provider], client: httpx.AsyncClient,
                     max_queries: int = 4, per_query: int = 10,
                     templates: list[dict] | None = None,
                     ) -> tuple[list[Query], list[ProviderOutcome], list[SearchResult]]:
    queries = generate_queries(entity_type, value, mode, templates=templates,
                               max_queries=max_queries)
    pairs: list[tuple[Query, Provider]] = [(q, p) for q in queries for p in providers]

    async def one(q: Query, p: Provider):
        return q, await p.search(client, q.text, count=per_query)

    done = await asyncio.gather(*(one(q, p) for q, p in pairs))
    outcomes = [oc for _, oc in done]
    return queries, outcomes, merge_results(done)


__all__ = ["SearchResult", "merge_results", "extract_domain_evidence",
           "term_in_result", "run_search", "configured_providers",
           "generate_queries", "Query", "RawResult", "ProviderOutcome"]
