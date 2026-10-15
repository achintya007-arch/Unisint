"""Search credentials/settings and the search-test pipeline.

The success path here uses a FIXTURE provider (no network); only the
real-provider error path was exercised live (see tests/fixtures/README.md).
"""
import asyncio
import json
import pathlib

import httpx
import pytest

from unisint import config as cfgmod
from unisint.search.providers import FixtureProvider, GoogleCSEProvider

FX = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(cfgmod, "HOME", tmp_path)
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cfgmod, "TOOLS_DIR", tmp_path / "tools")
    monkeypatch.setattr(cfgmod, "CASES_DIR", tmp_path / "cases")
    monkeypatch.setattr(cfgmod, "GAPS_PATH", tmp_path / "gaps.md")
    for v in list(cfgmod.ENV_KEYS.values()) + list(cfgmod.ENV_SETTINGS.values()):
        monkeypatch.delenv(v, raising=False)
    return tmp_path


def test_google_invalid_key_fixture_is_auth_error():
    body = json.loads((FX / "google_cse_invalid_key.json").read_text())
    cfg = {"api_keys": {"google_cse_key": "SECRETKEY123", "google_cse_cx": "cx"}}

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(400, json=body))) as c:
            return await GoogleCSEProvider(cfg).search(c, "q", backoff=0)
    oc = asyncio.run(go())
    assert oc.status == "auth_error" and "API_KEY_INVALID" in oc.detail
    assert "SECRETKEY123" not in oc.detail


def test_google_quota_reason():
    body = {"error": {"code": 429, "errors": [{"reason": "rateLimitExceeded"}]}}

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(429, json=body))) as c:
            return await GoogleCSEProvider({"api_keys": {"google_cse_key": "k",
                                                         "google_cse_cx": "c"}}).search(c, "q")
    assert asyncio.run(go()).status == "quota"


def test_env_credentials_override_and_are_never_persisted(home, monkeypatch):
    c = cfgmod.load()
    c["api_keys"]["brave"] = "FILEKEY111"
    cfgmod.save(c)
    monkeypatch.setenv("UNISINT_BRAVE_API_KEY", "ENVKEY222")
    c2 = cfgmod.load()
    assert c2["api_keys"]["brave"] == "ENVKEY222" and c2["_sources"]["brave"] == "env"
    c2["effects"] = False
    cfgmod.save(c2)                                    # must not write the env key
    disk = (home / "config.json").read_text()
    assert "ENVKEY222" not in disk and "FILEKEY111" in disk and "_sources" not in disk


def test_settings_api_set_clear_and_mask(home):
    from fastapi.testclient import TestClient
    from unisint.app import app
    cl = TestClient(app)
    cl.post("/api/config", json={"api_keys": {"brave": "SAVEDKEY333", "bogus": "x"}})
    g = cl.get("/api/config").json()
    assert g["api_keys_set"]["brave"] is True and g["key_sources"]["brave"] == "file"
    assert "SAVEDKEY333" not in json.dumps(g) and "bogus" not in g["api_keys_set"]
    cl.post("/api/config", json={"clear_keys": ["brave"]})
    assert cl.get("/api/config").json()["api_keys_set"]["brave"] is False
    assert "SAVEDKEY333" not in (home / "config.json").read_text()


def test_search_test_pipeline_with_fixture_provider(home, monkeypatch, capsys):
    """Stages 2-5 (merge → engine/web_search → dossier → HTML/CSV) on a
    deterministic provider. Proves plumbing only — NOT live search."""
    from unisint import searchtest
    from unisint.native import web_search
    table = {"site:corp.com": [
        {"title": "Corp & Co", "url": "https://corp.com/?utm_source=x", "snippet": "home", "rank": 1},
        {"title": "Dup", "url": "https://CORP.com/#a", "snippet": "", "rank": 2},
        {"title": "Bad", "url": "javascript:alert(1)", "snippet": "", "rank": 3},
        {"title": "<b>Docs</b>", "url": "https://docs.corp.com/a?b=1&c=2", "snippet": "s", "rank": 4}]}
    fp = lambda cfg: [FixtureProvider(table=table, name="fx")]  # noqa: E731
    monkeypatch.setattr(searchtest, "configured_providers", fp)
    monkeypatch.setattr(web_search, "configured_providers", fp)
    rc = asyncio.run(searchtest.run("domain", "corp.com", "recon"))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "4 raw -> 2 unique" in out
    assert "HTML missing 0, CSV missing 0, dossier/entity URL mismatches 0" in out
    html = (home / "search-test-report.html").read_text()
    assert "https://docs.corp.com/a?b=1&amp;c=2" in html and "javascript:" not in html
