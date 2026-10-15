"""URL normalisation, SSRF-safe fetching and honest link validation.

Three responsibilities, kept separate so each is testable:

* ``normalize_url`` — canonical form for storage/dedup (scheme/host case,
  IDNA, default ports, fragments and tracking parameters removed). Returns
  ``None`` for anything that is not a well-formed public http(s) URL.
* ``check_host`` / ``GuardedBackend`` — refuse destinations that resolve to
  loopback, private, link-local, reserved or metadata addresses. The guard
  runs again at connect time (DNS-rebinding defence) and on every redirect hop.
* ``validate_url`` — classify a URL as reachable / not_found / soft_404 /
  login_wall / blocked / rate_limited / timeout / error / unsafe / invalid.
  "reachable" means a page loaded; it is never treated as proof that an
  account exists.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Awaitable, Callable, Iterable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import httpx

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "igshid",
    "ref_src", "ref_url", "_hsenc", "_hsmi", "yclid", "si", "trk",
}
TRACKING_PREFIXES = ("utm_",)

_BAD_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost",
                  "metadata.google.internal", "metadata"}
_BAD_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                      r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_tracking(key: str) -> bool:
    k = key.lower()
    return k in TRACKING_PARAMS or k.startswith(TRACKING_PREFIXES)


def normalize_url(raw: str | None) -> str | None:
    """Return a canonical http(s) URL, or None if ``raw`` is not usable."""
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or any(c.isspace() for c in s) or len(s) > 2048:
        return None
    if "://" not in s:
        return None  # never guess a scheme for a bare string
    try:
        parts = urlsplit(s)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    if parts.username or parts.password:
        return None  # credentials in URLs are refused outright
    host = (parts.hostname or "").rstrip(".")
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if not _HOST_RE.match(host) or "." not in host:
            return None
    try:
        port = parts.port
    except ValueError:
        return None
    netloc = f"[{host}]" if is_ip and ":" in host else host
    if port and not ((scheme == "http" and port == 80) or
                     (scheme == "https" and port == 443)):
        netloc += f":{port}"
    path = quote(unquote(parts.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                       if not _is_tracking(k)])
    return urlunsplit((scheme, netloc, path, query, ""))


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Destination safety (SSRF)
# ---------------------------------------------------------------------------

class UnsafeTarget(Exception):
    """Raised when a destination is not a public internet address."""


def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return bool(addr.is_global) and not addr.is_multicast


Resolver = Callable[[str], Awaitable[list[str]]]


async def system_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


def _proxy_url() -> str | None:
    for k in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
              "HTTP_PROXY", "http_proxy"):
        if os.environ.get(k):
            return os.environ[k]
    return None


async def check_host(host: str, resolver: Resolver | None = None, *,
                     allow_unresolved: bool = False) -> list[str]:
    """Return the host's public IPs or raise UnsafeTarget.

    Every resolved address must be public; a single private answer fails the
    check (a common DNS-rebinding trick returns one public and one private).
    """
    h = (host or "").strip().rstrip(".").lower()
    if not h or h in _BAD_HOSTNAMES or h.endswith(_BAD_SUFFIXES):
        raise UnsafeTarget(f"refused hostname: {host!r}")
    try:
        ipaddress.ip_address(h)
        if not ip_is_public(h):
            raise UnsafeTarget(f"non-public address: {h}")
        return [h]
    except ValueError:
        pass
    resolver = resolver or system_resolve  # looked up at call time (testable)
    try:
        ips = await resolver(h)
    except (OSError, socket.gaierror) as exc:
        if allow_unresolved:
            return []
        raise LookupError(f"dns_unresolved: {exc}") from exc
    if not ips:
        if allow_unresolved:
            return []
        raise LookupError("dns_unresolved: no addresses")
    bad = [ip for ip in ips if not ip_is_public(ip)]
    if bad:
        raise UnsafeTarget(f"{h} resolves to non-public {bad}")
    return ips


class GuardedBackend:
    """httpcore network backend that validates the IP at connect time.

    Connections to the configured proxy are allowed (the user configured it);
    every other connection is resolved here, checked, and dialled by IP so a
    second, different DNS answer cannot be substituted (rebinding).
    """

    def __init__(self, inner, allowed: Iterable[tuple[str, int]] = (),
                 resolver: Resolver | None = None):
        self._inner = inner
        self._allowed = {(h.lower(), int(p)) for h, p in allowed}
        self._resolver = resolver

    async def connect_tcp(self, host, port, timeout=None, local_address=None,
                          socket_options=None):
        if (host.lower(), int(port)) in self._allowed:
            return await self._inner.connect_tcp(
                host, port, timeout=timeout, local_address=local_address,
                socket_options=socket_options)
        ips = await check_host(host, self._resolver)
        return await self._inner.connect_tcp(
            ips[0], port, timeout=timeout, local_address=local_address,
            socket_options=socket_options)

    async def connect_unix_socket(self, *a, **k):  # pragma: no cover
        raise UnsafeTarget("unix sockets are not allowed")

    async def sleep(self, seconds):
        return await self._inner.sleep(seconds)


def make_safe_client(timeout: float = 12.0) -> httpx.AsyncClient:
    """An httpx client whose every connection passes through GuardedBackend.

    Redirects are NOT followed automatically; callers use ``safe_get`` which
    re-validates each hop.
    """
    verify = httpx.create_ssl_context(trust_env=True)
    proxy = _proxy_url()
    allowed: list[tuple[str, int]] = []
    if proxy:
        p = urlsplit(proxy)
        if p.hostname:
            allowed.append((p.hostname, p.port or (443 if p.scheme == "https" else 80)))
    transport = httpx.AsyncHTTPTransport(verify=verify, proxy=proxy, retries=0)
    pool = transport._pool  # httpcore pool; documented public attr in httpcore
    pool._network_backend = GuardedBackend(pool._network_backend, allowed)
    return httpx.AsyncClient(
        transport=transport, timeout=timeout, follow_redirects=False,
        headers={"User-Agent": "UNISINT-linkcheck/2.0 (+public-source validation)"})


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

STATES = ("unverified", "reachable", "not_found", "soft_404", "login_wall",
          "blocked", "rate_limited", "timeout", "error", "unsafe", "invalid")

SOFT_404_MARKERS = (
    "page not found", "page doesn't exist", "page does not exist",
    "this page isn't available", "this account doesn't exist",
    "user not found", "profile not found", "no such user",
    "sorry, nobody on reddit goes by that name", "account suspended",
    "this account has been suspended", "the specified profile could not be found",
    "<title>404", "error 404", "404 not found",
)
CHALLENGE_MARKERS = ("just a moment...", "attention required! | cloudflare",
                     "cf-browser-verification", "captcha", "are you a robot")
LOGIN_PATH_RE = re.compile(r"/(login|signin|sign-in|sign_in|accounts/login|auth)(/|$|\?)", re.I)


@dataclass
class Validation:
    state: str = "unverified"
    checked_at: float = field(default_factory=time.time)
    http_status: int | None = None
    final_url: str | None = None
    detail: str = ""
    hops: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def classify_response(original: str, final: str, status: int,
                      body: str, headers: dict | None = None) -> tuple[str, str]:
    """Pure classification of a fetched response → (state, detail)."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    text = (body or "")[:65536].lower()
    if status in (404, 410):
        return "not_found", f"HTTP {status}"
    if status == 429:
        return "rate_limited", "HTTP 429"
    if status in (401, 403, 503) and (
            h.get("cf-mitigated") or any(m in text for m in CHALLENGE_MARKERS)):
        return "blocked", "anti-bot challenge"
    if status in (401, 403):
        return "blocked", f"HTTP {status}"
    if status >= 500:
        return "error", f"HTTP {status}"
    if 200 <= status < 300:
        if any(m in text for m in CHALLENGE_MARKERS):
            return "blocked", "anti-bot challenge page"
        o, f = urlsplit(original), urlsplit(final)
        if final != original and LOGIN_PATH_RE.search(f.path or ""):
            return "login_wall", "redirected to a login page"
        if final != original and (o.path not in ("", "/")) and (f.path in ("", "/")):
            return "soft_404", "redirected to site root"
        if any(m in text for m in SOFT_404_MARKERS):
            return "soft_404", "page text indicates not found"
        return "reachable", f"HTTP {status}"
    return "error", f"unexpected HTTP {status}"


async def safe_get(client: httpx.AsyncClient, url: str, *, max_hops: int = 3,
                   resolver: Resolver | None = None,
                   allow_unresolved: bool = False,
                   max_bytes: int = 65536) -> tuple[httpx.Response, str, int, str]:
    """GET with manual, re-validated redirects. Returns (resp, final_url, hops, body)."""
    current = url
    for hop in range(max_hops + 1):
        norm = normalize_url(current)
        if not norm:
            raise ValueError(f"invalid url at hop {hop}: {current!r}")
        await check_host(url_host(norm), resolver, allow_unresolved=allow_unresolved)
        async with client.stream("GET", norm) as resp:
            if resp.is_redirect and "location" in resp.headers:
                current = str(httpx.URL(norm).join(resp.headers["location"]))
                continue
            chunks, size = [], 0
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= max_bytes:
                    break
            body = b"".join(chunks)[:max_bytes].decode("utf-8", "replace")
            return resp, norm, hop, body
    raise RuntimeError("too many redirects")


class HostLimiter:
    """One request at a time per host, with a minimum interval between them."""

    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self._locks: dict[str, asyncio.Lock] = {}
        self._last: dict[str, float] = {}

    async def wait(self, host: str):
        lock = self._locks.setdefault(host, asyncio.Lock())
        await lock.acquire()
        gap = time.monotonic() - self._last.get(host, 0)
        if gap < self.min_interval:
            await asyncio.sleep(self.min_interval - gap)
        return lock

    def done(self, host: str, lock: asyncio.Lock):
        self._last[host] = time.monotonic()
        lock.release()


async def validate_url(url: str, client: httpx.AsyncClient, *,
                       limiter: HostLimiter | None = None,
                       resolver: Resolver | None = None,
                       allow_unresolved: bool = False) -> Validation:
    """Classify ``url``. Never raises; failures become states."""
    norm = normalize_url(url)
    if not norm:
        return Validation(state="invalid", detail="malformed or non-http(s) URL")
    host = url_host(norm)
    lock = await limiter.wait(host) if limiter else None
    try:
        resp, final, hops, body = await safe_get(
            client, norm, resolver=resolver, allow_unresolved=allow_unresolved)
        state, detail = classify_response(norm, final, resp.status_code, body,
                                          dict(resp.headers))
        return Validation(state=state, http_status=resp.status_code,
                          final_url=final, detail=detail, hops=hops)
    except UnsafeTarget as exc:
        return Validation(state="unsafe", detail=str(exc))
    except LookupError as exc:
        return Validation(state="error", detail=str(exc))
    except (httpx.TimeoutException, asyncio.TimeoutError):
        return Validation(state="timeout", detail="request timed out")
    except ValueError as exc:
        return Validation(state="invalid", detail=str(exc))
    except RuntimeError as exc:
        return Validation(state="error", detail=str(exc))
    except httpx.HTTPError as exc:
        return Validation(state="error", detail=f"{type(exc).__name__}: {exc}"[:200])
    finally:
        if limiter and lock:
            limiter.done(host, lock)
