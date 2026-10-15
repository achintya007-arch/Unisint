"""Search subsystem: templates, provider parsing/failures, dedup, evidence."""
import asyncio
import json

import httpx
import pytest

from unisint.search import (extract_domain_evidence, merge_results, run_search,
                            term_in_result)
from unisint.search.providers import (BraveProvider, FixtureProvider,
                                      GoogleCSEProvider, SearXNGProvider,
                                      configured_providers)
from unisint.search.queries import (DEFAULT_TEMPLATES, generate_queries,
                                    load_templates, quote_term,
                                    validate_templates)


# ---- queries ---------------------------------------------------------------

def test_domain_queries_both_modes():
    for mode in ("self", "recon"):
        ids = [q.template_id for q in generate_queries("domain", "corp.com", mode,
                                                       templates=DEFAULT_TEMPLATES)]
        assert ids == ["domain_pages", "domain_docs", "domain_offsite", "domain_emails"]


def test_identifier_queries_self_only():
    assert generate_queries("email", "a@b.com", "recon", templates=DEFAULT_TEMPLATES) == []
    q = generate_queries("full_name", 'Ada "x" Lovelace', "self", templates=DEFAULT_TEMPLATES)
    assert [x.text for x in q] == ['"Ada x Lovelace"']


def test_quote_term_strips_breaking_chars():
    assert quote_term('a"b\nc') == '"a b c"'


def test_template_validation_rejects_unknown_placeholders():
    bad = [{"id": "x", "types": ["domain"], "modes": ["self"], "template": "{secret}"},
           {"id": "", "template": "x"}, "nope"]
    assert validate_templates(bad) == []


def test_user_template_override(tmp_path):
    (tmp_path / "search_queries.json").write_text(json.dumps([
        {"id": "mine", "types": ["domain"], "modes": ["recon"], "template": "site:{value} login"}]))
    t = load_templates(tmp_path)
    assert [q.text for q in generate_queries("domain", "corp.com", "recon", templates=t)] \
        == ["site:corp.com login"]


# ---- provider parsing & failure handling ----------------------------------

def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _search(provider, handler, q="x"):
    async def go():
        async with _client(handler) as c:
            return await provider.search(c, q, backoff=0)
    return asyncio.run(go())


BRAVE_CFG = {"api_keys": {"brave": "k"}}


def test_brave_parse_ok_and_sends_key():
    seen = {}

    def h(r):
        seen["key"] = r.headers.get("X-Subscription-Token")
        return httpx.Response(200, json={"web": {"results": [
            {"title": "T1", "url": "https://corp.com/a", "description": "S1"},
            {"title": "no url"}]}})
    oc = _search(BraveProvider(BRAVE_CFG), h)
    assert oc.status == "ok" and seen["key"] == "k"
    assert [(r.title, r.url, r.rank) for r in oc.results] == [("T1", "https://corp.com/a", 1)]


@pytest.mark.parametrize("code,body,status", [
    (429, "", "rate_limited"), (401, "bad key", "auth_error"),
    (403, "Quota exceeded", "quota"), (404, "", "error")])
def test_brave_failure_statuses(code, body, status):
    oc = _search(BraveProvider(BRAVE_CFG), lambda r: httpx.Response(code, text=body))
    assert oc.status == status and oc.results == []


def test_retry_on_5xx_then_success():
    n = {"c": 0}

    def h(r):
        n["c"] += 1
        return httpx.Response(503) if n["c"] == 1 else \
            httpx.Response(200, json={"web": {"results": []}})
    oc = _search(BraveProvider(BRAVE_CFG), h)
    assert oc.status == "empty" and oc.attempts == 2


def test_timeout_after_retries():
    def h(r):
        raise httpx.ReadTimeout("t", request=r)
    oc = _search(BraveProvider(BRAVE_CFG), h)
    assert oc.status == "timeout" and oc.attempts == 2


def test_unconfigured_is_explicit():
    oc = _search(BraveProvider({}), lambda r: httpx.Response(200))
    assert oc.status == "unconfigured" and "api_keys.brave" in oc.detail
    assert configured_providers({}) == []


def test_google_cse_parse_and_api_error():
    cfg = {"api_keys": {"google_cse_key": "k", "google_cse_cx": "cx"}}
    ok = _search(GoogleCSEProvider(cfg), lambda r: httpx.Response(200, json={
        "items": [{"title": "G", "link": "https://x.org/p", "snippet": "s"}]}))
    assert ok.status == "ok" and ok.results[0].url == "https://x.org/p"
    err = _search(GoogleCSEProvider(cfg), lambda r: httpx.Response(200, json={
        "error": {"code": 400, "message": "Invalid cx"}}))
    assert err.status == "error" and "Invalid cx" in err.detail


def test_searxng_parse_and_malformed_json():
    cfg = {"searxng_url": "http://127.0.0.1:8888"}
    ok = _search(SearXNGProvider(cfg), lambda r: httpx.Response(200, json={
        "results": [{"title": "S", "url": "https://a.org/", "content": "c",
                     "engines": ["ddg"]}]}))
    assert ok.status == "ok"
    bad = _search(SearXNGProvider(cfg), lambda r: httpx.Response(200, text="<html>"))
    assert bad.status == "error"


# ---- merge / dedup / evidence ------------------------------------------------

def _run_fixture(table_a, table_b, etype="domain", value="corp.com", mode="recon"):
    pa = FixtureProvider(table=table_a, name="pa")
    pb = FixtureProvider(table=table_b, name="pb")

    async def go():
        async with _client(lambda r: httpx.Response(500)) as c:
            return await run_search(etype, value, mode, providers=[pa, pb],
                                    client=c, templates=DEFAULT_TEMPLATES)
    return asyncio.run(go())


def test_dedup_across_providers_keeps_provenance():
    a = {"site:corp.com": [
        {"title": "Home", "url": "https://corp.com/?utm_source=x", "snippet": "", "rank": 1},
        {"title": "Bad", "url": "javascript:void(0)", "snippet": "", "rank": 2}]}
    b = {"site:corp.com": [
        {"title": "Home", "url": "https://CORP.com/#top", "snippet": "about", "rank": 3}]}
    qs, outcomes, results = _run_fixture(a, b)
    assert len(results) == 1
    r = results[0]
    assert r.url == "https://corp.com/"
    assert r.providers == ["pa", "pb"]
    assert sorted(h["rank"] for h in r.hits) == [1, 3]
    assert r.snippet == "about"          # filled from the second provider


def test_partial_provider_failure_keeps_other_results():
    a = {"site:corp.com": "rate_limited"}
    b = {"site:corp.com": [{"title": "x", "url": "https://corp.com/x",
                            "snippet": "", "rank": 1}]}
    qs, outcomes, results = _run_fixture(a, b)
    statuses = {(o.provider, o.query): o.status for o in outcomes}
    assert statuses[("pa", "site:corp.com")] == "rate_limited"
    assert [r.url for r in results] == ["https://corp.com/x"]


def test_domain_evidence_extraction_scoped():
    from unisint.search import SearchResult
    sr = SearchResult(url="https://blog.corp.com/post", title="Contact ops@corp.com",
                      snippet="see vpn.corp.com, not evilcorp.com or x@gmail.com")
    ev = extract_domain_evidence(sr, "corp.com")
    assert ev == {"emails": ["ops@corp.com"],
                  "hosts": ["blog.corp.com", "vpn.corp.com"]}


def test_term_in_result_whitespace_insensitive():
    from unisint.search import SearchResult
    sr = SearchResult(url="https://x.org", title="Ada  Lovelace bio", snippet="")
    assert term_in_result(sr, "ada lovelace")
    assert not term_in_result(sr, "grace hopper")


def test_no_results_never_fabricated():
    qs, outcomes, results = _run_fixture({}, {})
    assert results == [] and all(o.status == "empty" for o in outcomes)
