"""URL normalisation, SSRF defence and validation-state classification."""
import asyncio

import httpx
import pytest

from unisint import urls
from unisint.urls import (GuardedBackend, UnsafeTarget, check_host,
                          classify_response, normalize_url, validate_url)


# ---- normalisation ---------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("https://GitHub.com/Torvalds", "https://github.com/Torvalds"),
    ("https://example.com:443/a#frag", "https://example.com/a"),
    ("http://example.com:80", "http://example.com/"),
    ("https://example.com/p?utm_source=x&id=7&fbclid=abc", "https://example.com/p?id=7"),
    ("https://bücher.example/x", "https://xn--bcher-kva.example/x"),
    ("https://example.com/a%20b", "https://example.com/a%20b"),
])
def test_normalize_ok(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize("raw", [
    None, "", "github.com/torvalds",          # no scheme: never guessed
    "javascript:alert(1)", "ftp://x.com/a", "file:///etc/passwd",
    "https://user:pw@example.com/",           # credentials refused
    "https://exa mple.com/", "https://-bad-.com/", "https://nodot/",
    "https://example.com:99999/", "Instagram:someone",
])
def test_normalize_rejects(raw):
    assert normalize_url(raw) is None


# ---- SSRF guard ------------------------------------------------------------

def _resolver(mapping):
    async def r(host):
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]
    return r


@pytest.mark.parametrize("host", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1",
    "100.64.0.1", "0.0.0.0", "localhost", "metadata.google.internal",
    "printer.local", "::ffff:127.0.0.1",
])
def test_check_host_blocks_private(host):
    with pytest.raises(UnsafeTarget):
        asyncio.run(check_host(host, _resolver({})))


def test_check_host_blocks_mixed_dns_answer():
    r = _resolver({"evil.example": ["93.184.216.34", "10.0.0.1"]})
    with pytest.raises(UnsafeTarget):
        asyncio.run(check_host("evil.example", r))


def test_check_host_unresolved_is_lookup_error_not_safe():
    with pytest.raises(LookupError):
        asyncio.run(check_host("nope.invalid-tld-xyz", _resolver({})))


def test_guarded_backend_rebinding_defence(monkeypatch):
    calls = []

    class Inner:
        async def connect_tcp(self, host, port, **kw):
            calls.append(host)
            return "stream"

    async def evil(host):  # resolves to loopback at connect time
        return ["127.0.0.1"]

    monkeypatch.setattr(urls, "system_resolve", evil)
    gb = GuardedBackend(Inner(), allowed=[("proxy.local", 8080)])
    with pytest.raises(UnsafeTarget):
        asyncio.run(gb.connect_tcp("rebind.example", 443))
    # configured proxy is still allowed through
    assert asyncio.run(gb.connect_tcp("proxy.local", 8080)) == "stream"
    assert calls == ["proxy.local"]


def test_guarded_backend_dials_checked_ip(monkeypatch):
    calls = []

    class Inner:
        async def connect_tcp(self, host, port, **kw):
            calls.append(host)
            return "ok"

    async def good(host):
        return ["140.82.114.3"]

    monkeypatch.setattr(urls, "system_resolve", good)
    asyncio.run(GuardedBackend(Inner()).connect_tcp("github.com", 443))
    assert calls == ["140.82.114.3"]  # dialled by the IP that was checked


# ---- classification (pure) -------------------------------------------------

def test_classify_states():
    c = classify_response
    assert c("https://a.com/u", "https://a.com/u", 404, "")[0] == "not_found"
    assert c("https://a.com/u", "https://a.com/u", 429, "")[0] == "rate_limited"
    assert c("https://a.com/u", "https://a.com/u", 403, "Just a moment...")[0] == "blocked"
    assert c("https://a.com/u", "https://a.com/u", 200,
             "<title>Page not found</title>")[0] == "soft_404"
    assert c("https://a.com/u", "https://a.com/", 200, "welcome")[0] == "soft_404"
    assert c("https://a.com/u", "https://a.com/login?next=/u", 200, "")[0] == "login_wall"
    assert c("https://a.com/u", "https://a.com/u", 200, "<h1>alice</h1>")[0] == "reachable"
    assert c("https://a.com/u", "https://a.com/u", 502, "")[0] == "error"


# ---- validate_url end-to-end with a mock transport ------------------------

PUBLIC = _resolver({"site.example": ["93.184.216.34"],
                    "other.example": ["93.184.216.35"],
                    "internal.example": ["10.1.2.3"]})


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler),
                             follow_redirects=False)


def _run(url, handler, **kw):
    async def go():
        async with _client(handler) as c:
            return await validate_url(url, c, resolver=PUBLIC, **kw)
    return asyncio.run(go())


def test_validate_reachable_keeps_final_url():
    v = _run("https://site.example/u/alice?utm_source=x",
             lambda r: httpx.Response(200, text="<h1>alice</h1>"))
    assert v.state == "reachable"
    assert v.final_url == "https://site.example/u/alice"


def test_validate_follows_safe_redirect():
    def h(r):
        if r.url.path == "/old":
            return httpx.Response(301, headers={"location": "https://other.example/new"})
        return httpx.Response(200, text="profile")
    v = _run("https://site.example/old", h)
    assert v.state == "reachable" and v.final_url == "https://other.example/new"
    assert v.hops == 1


def test_validate_blocks_redirect_to_private():
    def h(r):
        return httpx.Response(302, headers={"location": "https://internal.example/admin"})
    assert _run("https://site.example/x", h).state == "unsafe"


def test_validate_blocks_redirect_to_metadata_ip():
    def h(r):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})
    assert _run("https://site.example/x", h).state == "unsafe"


def test_validate_redirect_loop():
    def h(r):
        return httpx.Response(302, headers={"location": "https://site.example/loop"})
    v = _run("https://site.example/loop", h)
    assert v.state == "error" and "redirect" in v.detail


def test_validate_soft_404_and_404():
    assert _run("https://site.example/u/ghost",
                lambda r: httpx.Response(200, text="User not found")).state == "soft_404"
    assert _run("https://site.example/u/ghost",
                lambda r: httpx.Response(404)).state == "not_found"


def test_validate_timeout():
    def h(r):
        raise httpx.ReadTimeout("slow", request=r)
    assert _run("https://site.example/x", h).state == "timeout"


def test_validate_connect_error():
    def h(r):
        raise httpx.ConnectError("refused", request=r)
    assert _run("https://site.example/x", h).state == "error"


def test_validate_invalid_and_unresolvable():
    assert _run("not a url", lambda r: httpx.Response(200)).state == "invalid"
    v = _run("https://unknown.example/x", lambda r: httpx.Response(200))
    assert v.state == "error" and "dns_unresolved" in v.detail
