"""Key-gated enrichment modules (Shodan host API, HIBP, Hunter.io, VirusTotal).

No network: a fake HTTP client returns canned vendor responses so we can assert
the parsing, the entities produced, and — crucially — that auth/throttle/empty
statuses map onto the source-run vocabulary (a bad key is auth_error, not a
silent "ok"). Also asserts the modules stay dormant until their key is set.
"""
import asyncio

from unisint import base
from unisint.base import MODE_RECON, MODE_SELF
from unisint.engine import Engine
from unisint.models import EntityType
from unisint.native.enrich import HIBP, Hunter, ShodanHost, VirusTotal
from unisint.pivot import Limits


class FakeResp:
    def __init__(self, status_code=200, data=None, headers=None):
        self.status_code = status_code
        self._data = data
        self.headers = headers or {}

    def json(self):
        if self._data is None:
            raise ValueError("no json body")
        return self._data


class FakeHTTP:
    """get() routes on a substring → FakeResp map (or a single default)."""
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    async def get(self, url, **kw):
        self.calls.append(url)
        if isinstance(self.routes, FakeResp):
            return self.routes
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return FakeResp(404)

    async def aclose(self):
        pass


class _Dummy:
    async def aclose(self):
        pass


async def _noop(_):
    pass


def run_module(mod, etype, value, routes, keys, mode=MODE_SELF):
    with _reg([mod]):
        eng = Engine(mode=mode, config={"api_keys": keys}, emit=_noop,
                     limits=Limits(depth=0, time_budget=30),
                     http=FakeHTTP(routes), safe_http=_Dummy())
        eng.add_entity(etype, value, source="input")
        asyncio.run(eng.run())
    return eng


class _reg:
    def __init__(self, mods):
        self.mods = mods

    def __enter__(self):
        self._saved = list(base._REGISTRY)
        base._REGISTRY[:] = self.mods
        return self

    def __exit__(self, *a):
        base._REGISTRY[:] = self._saved


def _metas(eng):
    return [e for e in eng.entities.values() if e.type == EntityType.METADATA]


# ---- gating ---------------------------------------------------------------

def test_modules_dormant_without_key():
    stub = type("S", (), {"config": {"api_keys": {}}})()
    for mod in (ShodanHost(), HIBP(), Hunter(), VirusTotal()):
        ok, why = asyncio.run(mod.available(stub))
        assert ok is False and mod.requires_key in why


# ---- Shodan host API ------------------------------------------------------

def test_shodan_parses_ports_hosts_and_cves():
    data = {"ip_str": "1.2.3.4", "ports": [22, 443], "hostnames": ["h.example.com"],
            "org": "ExampleOrg", "asn": "AS123",
            "vulns": {"CVE-2021-1234": {"cvss": 9.8}},
            "data": [{"port": 443, "product": "nginx", "version": "1.25",
                      "transport": "tcp"}]}
    eng = run_module(ShodanHost(), EntityType.IP, "1.2.3.4",
                     {"api.shodan.io": FakeResp(200, data)}, {"shodan": "K"})
    st = eng.module_status["shodan"]
    assert st["state"] == "ok" and st["contacted"] is True
    assert ("host", "h.example.com") in eng.entities
    assert ("org", "exampleorg") in eng.entities
    metas = [m.value for m in _metas(eng)]
    assert any("open ports: 22, 443" in v for v in metas)
    assert any("CVE-2021-1234" in v for v in metas)
    assert any("nginx" in v for v in metas)


def test_shodan_404_is_empty():
    eng = run_module(ShodanHost(), EntityType.IP, "1.2.3.4",
                     {"api.shodan.io": FakeResp(404)}, {"shodan": "K"})
    st = eng.module_status["shodan"]
    assert st["state"] == "empty" and st["contacted"] is True


def test_shodan_bad_key_is_auth_error():
    eng = run_module(ShodanHost(), EntityType.IP, "1.2.3.4",
                     {"api.shodan.io": FakeResp(401)}, {"shodan": "BAD"})
    assert eng.module_status["shodan"]["state"] == "auth_error"


# ---- Have I Been Pwned ----------------------------------------------------

def test_hibp_lists_breach_names_only():
    data = [{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04",
             "DataClasses": ["Email addresses", "Password hints"], "PwnCount": 153000000,
             "IsVerified": True},
            {"Name": "LinkedIn", "Title": "LinkedIn", "BreachDate": "2012-05-05",
             "DataClasses": ["Email addresses", "Passwords"]}]
    eng = run_module(HIBP(), EntityType.EMAIL, "a@b.com",
                     {"haveibeenpwned.com": FakeResp(200, data)}, {"hibp": "K"})
    st = eng.module_status["hibp"]
    assert st["state"] == "ok" and st["findings"] == 2
    metas = [m.value for m in _metas(eng)]
    assert any("breach: Adobe (2013-10-04)" in v for v in metas)
    # breach names/metadata only — no password values are ever emitted.
    assert all("hint" not in v.lower() or "Password hints" in v for v in metas)


def test_hibp_404_means_clean():
    eng = run_module(HIBP(), EntityType.EMAIL, "clean@b.com",
                     {"haveibeenpwned.com": FakeResp(404)}, {"hibp": "K"})
    assert eng.module_status["hibp"]["state"] == "empty"


def test_hibp_rate_limited():
    eng = run_module(HIBP(), EntityType.EMAIL, "a@b.com",
                     {"haveibeenpwned.com": FakeResp(429, headers={"retry-after": "3"})},
                     {"hibp": "K"})
    assert eng.module_status["hibp"]["state"] == "rate_limited"


# ---- Hunter.io ------------------------------------------------------------

def test_hunter_emits_candidate_emails():
    data = {"data": {"domain": "acme.com", "organization": "Acme Inc",
                     "pattern": "{first}@acme.com",
                     "emails": [{"value": "jane@acme.com", "confidence": 94,
                                 "type": "personal", "position": "CEO",
                                 "sources": [{"uri": "https://acme.com/team"}]}]}}
    eng = run_module(Hunter(), EntityType.DOMAIN, "acme.com",
                     {"api.hunter.io": FakeResp(200, data)}, {"hunter": "K"}, mode=MODE_RECON)
    assert eng.module_status["hunter"]["state"] == "ok"
    e = eng.entities.get(("email", "jane@acme.com"))
    assert e is not None and e.basis == "candidate"      # discovered, not confirmed
    assert ("org", "acme inc") in eng.entities


def test_hunter_bad_key_is_auth_error():
    eng = run_module(Hunter(), EntityType.DOMAIN, "acme.com",
                     {"api.hunter.io": FakeResp(401, {"errors": [{"code": 401}]})},
                     {"hunter": "BAD"}, mode=MODE_RECON)
    assert eng.module_status["hunter"]["state"] == "auth_error"


# ---- VirusTotal -----------------------------------------------------------

def test_virustotal_domain_reputation_and_passive_dns():
    data = {"data": {"attributes": {
        "last_analysis_stats": {"harmless": 70, "malicious": 2, "suspicious": 1,
                                "undetected": 5},
        "reputation": -4, "categories": {"x": "malware"},
        "last_dns_records": [{"type": "A", "value": "9.9.9.9"},
                             {"type": "MX", "value": "mail.acme.com."}]}}}
    eng = run_module(VirusTotal(), EntityType.DOMAIN, "acme.com",
                     {"virustotal.com": FakeResp(200, data)}, {"virustotal": "K"},
                     mode=MODE_RECON)
    assert eng.module_status["virustotal"]["state"] == "ok"
    assert ("ip", "9.9.9.9") in eng.entities
    assert ("host", "mail.acme.com") in eng.entities
    metas = [m.value for m in _metas(eng)]
    assert any("2 malicious" in v for v in metas)


def test_virustotal_ip_path_and_auth_error():
    eng = run_module(VirusTotal(), EntityType.IP, "9.9.9.9",
                     {"virustotal.com": FakeResp(403)}, {"virustotal": "BAD"},
                     mode=MODE_RECON)
    assert eng.module_status["virustotal"]["state"] == "auth_error"
