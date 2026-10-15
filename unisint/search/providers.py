"""Search providers. Each wraps one documented API and returns raw results.

No HTML scraping of search engines. A provider is only "available" when its
configuration is present; missing keys, quota exhaustion and failures are
reported as explicit statuses, never as "no results".

Configuration (``~/.unisint/config.json``):
  api_keys.brave            Brave Search API subscription token
  api_keys.google_cse_key   Google Programmable Search JSON API key
  api_keys.google_cse_cx    Programmable Search Engine ID (cx)
  searxng_url               Base URL of your own SearXNG instance with
                            ``search.formats: [json]`` enabled
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class RawResult:
    title: str
    url: str
    snippet: str
    rank: int
    extra: dict = field(default_factory=dict)


@dataclass
class ProviderOutcome:
    provider: str
    query: str
    status: str                 # ok | empty | rate_limited | auth_error | quota | error | timeout | unconfigured
    results: list[RawResult] = field(default_factory=list)
    detail: str = ""
    retrieved_at: float = field(default_factory=time.time)
    attempts: int = 0


class Provider:
    name = "provider"

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    def configured(self) -> tuple[bool, str]:  # pragma: no cover - interface
        raise NotImplementedError

    async def _fetch(self, client: httpx.AsyncClient, query: str,
                     count: int) -> httpx.Response:  # pragma: no cover
        raise NotImplementedError

    def _parse(self, data: dict) -> list[RawResult]:  # pragma: no cover
        raise NotImplementedError

    def _classify(self, r: httpx.Response) -> tuple[str, str] | None:
        """Provider-specific (status, detail) from a structured error body,
        or None to fall back to HTTP-status rules."""
        return None

    def _detail(self, r: httpx.Response) -> str:
        """HTTP status plus the provider's own error message (redacted)."""
        msg = ""
        try:
            body = r.json()
            err = body.get("error") if isinstance(body, dict) else None
            if isinstance(err, dict):
                msg = str(err.get("message") or err.get("detail") or err.get("code") or "")
            elif isinstance(body, dict):
                msg = str(body.get("message") or body.get("detail") or "")
        except Exception:
            pass
        from ..config import redact
        return redact(f"HTTP {r.status_code}" + (f": {msg[:160]}" if msg else ""), self.cfg)

    async def search(self, client: httpx.AsyncClient, query: str, *,
                     count: int = 10, retries: int = 1,
                     backoff: float = 1.5) -> ProviderOutcome:
        ok, why = self.configured()
        if not ok:
            return ProviderOutcome(self.name, query, "unconfigured", detail=why)
        attempt = 0
        while True:
            attempt += 1
            try:
                r = await self._fetch(client, query, count)
            except httpx.TimeoutException:
                if attempt <= retries:
                    await asyncio.sleep(backoff * attempt)
                    continue
                return ProviderOutcome(self.name, query, "timeout",
                                       detail="request timed out", attempts=attempt)
            except httpx.HTTPError as exc:
                if attempt <= retries:
                    await asyncio.sleep(backoff * attempt)
                    continue
                return ProviderOutcome(self.name, query, "error",
                                       detail=f"{type(exc).__name__}", attempts=attempt)
            if r.status_code != 200:
                specific = self._classify(r)
                if specific:
                    return ProviderOutcome(self.name, query, specific[0],
                                           detail=specific[1], attempts=attempt)
            if r.status_code == 429:
                return ProviderOutcome(self.name, query, "rate_limited",
                                       detail=self._detail(r), attempts=attempt)
            if r.status_code in (401, 403):
                status = "quota" if "quota" in r.text.lower() else "auth_error"
                return ProviderOutcome(self.name, query, status,
                                       detail=self._detail(r), attempts=attempt)
            if r.status_code >= 500 and attempt <= retries:
                await asyncio.sleep(backoff * attempt)
                continue
            if r.status_code != 200:
                return ProviderOutcome(self.name, query, "error",
                                       detail=self._detail(r), attempts=attempt)
            try:
                results = self._parse(r.json())
            except (ValueError, KeyError, TypeError) as exc:
                return ProviderOutcome(self.name, query, "error",
                                       detail=f"unparseable response: {exc}",
                                       attempts=attempt)
            return ProviderOutcome(self.name, query, "ok" if results else "empty",
                                   results=results, attempts=attempt)


class BraveProvider(Provider):
    name = "brave"
    URL = "https://api.search.brave.com/res/v1/web/search"

    def configured(self):
        k = (self.cfg.get("api_keys") or {}).get("brave")
        return (True, "") if k else (False, "set api_keys.brave")

    async def _fetch(self, client, query, count):
        return await client.get(
            self.URL, params={"q": query, "count": min(count, 20)},
            headers={"Accept": "application/json",
                     "X-Subscription-Token": self.cfg["api_keys"]["brave"]},
            timeout=15.0)

    def _parse(self, data):
        out = []
        for i, r in enumerate((data.get("web") or {}).get("results") or [], 1):
            if r.get("url"):
                out.append(RawResult(title=r.get("title", ""), url=r["url"],
                                     snippet=r.get("description", ""), rank=i,
                                     extra={"age": r.get("age") or r.get("page_age")}))
        return out


class GoogleCSEProvider(Provider):
    name = "google_cse"
    URL = "https://www.googleapis.com/customsearch/v1"

    def configured(self):
        k = self.cfg.get("api_keys") or {}
        if k.get("google_cse_key") and k.get("google_cse_cx"):
            return True, ""
        return False, "set api_keys.google_cse_key and api_keys.google_cse_cx"

    async def _fetch(self, client, query, count):
        k = self.cfg["api_keys"]
        return await client.get(self.URL, params={
            "key": k["google_cse_key"], "cx": k["google_cse_cx"],
            "q": query, "num": min(count, 10)}, timeout=15.0)

    # Google APIs report errors as {"error": {"code", "status", "errors":
    # [{"reason"}], "details": [{"@type": ...ErrorInfo, "reason"}]}}.
    # Seen live: a bad key -> HTTP 400, ErrorInfo.reason API_KEY_INVALID.
    AUTH_REASONS = {"API_KEY_INVALID", "keyInvalid", "API_KEY_SERVICE_BLOCKED",
                    "SERVICE_DISABLED", "accessNotConfigured", "forbidden",
                    "PERMISSION_DENIED", "unregistered callers"}
    QUOTA_REASONS = {"RATE_LIMIT_EXCEEDED", "rateLimitExceeded", "dailyLimitExceeded",
                     "userRateLimitExceeded", "quotaExceeded", "RESOURCE_EXHAUSTED"}

    def _classify(self, r):
        try:
            err = r.json().get("error") or {}
        except Exception:
            return None
        reasons = {e.get("reason") for e in err.get("errors") or []}
        reasons |= {d.get("reason") for d in err.get("details") or []}
        reasons.add(err.get("status"))
        reasons.discard(None)
        detail = self._detail(r) + (f" [{', '.join(sorted(reasons))}]" if reasons else "")
        if reasons & self.QUOTA_REASONS:
            return "quota", detail
        if reasons & self.AUTH_REASONS or r.status_code in (401, 403):
            return "auth_error", detail
        return None

    def _parse(self, data):
        if "error" in data:
            raise ValueError(data["error"].get("message", "api error"))
        return [RawResult(title=r.get("title", ""), url=r["link"],
                          snippet=r.get("snippet", ""), rank=i,
                          extra={"display": r.get("displayLink")})
                for i, r in enumerate(data.get("items") or [], 1) if r.get("link")]


class SearXNGProvider(Provider):
    """Your own SearXNG instance (a user-configured endpoint, like a proxy)."""
    name = "searxng"

    def configured(self):
        u = (self.cfg.get("searxng_url") or "").strip()
        return (True, "") if u.startswith(("http://", "https://")) else \
            (False, "set searxng_url (instance with JSON format enabled)")

    async def _fetch(self, client, query, count):
        base = self.cfg["searxng_url"].rstrip("/")
        return await client.get(f"{base}/search",
                                params={"q": query, "format": "json"}, timeout=20.0)

    def _parse(self, data):
        return [RawResult(title=r.get("title", ""), url=r["url"],
                          snippet=r.get("content", ""), rank=i,
                          extra={"engines": r.get("engines") or [r.get("engine")]})
                for i, r in enumerate(data.get("results") or [], 1) if r.get("url")]


class FixtureProvider(Provider):
    """Deterministic provider for tests: returns canned outcomes per query."""
    name = "fixture"

    def __init__(self, cfg: dict | None = None, *, table: dict | None = None,
                 name: str = "fixture"):
        super().__init__(cfg or {})
        self.table = table or {}
        self.name = name

    def configured(self):
        return True, ""

    async def search(self, client, query, **kw):
        entry = self.table.get(query, [])
        if isinstance(entry, str):          # simulate a failure status
            return ProviderOutcome(self.name, query, entry, detail="fixture")
        return ProviderOutcome(self.name, query, "ok" if entry else "empty",
                               results=[RawResult(**r) for r in entry], attempts=1)


ALL_PROVIDERS = (BraveProvider, GoogleCSEProvider, SearXNGProvider)


def configured_providers(cfg: dict) -> list[Provider]:
    return [p for p in (cls(cfg) for cls in ALL_PROVIDERS) if p.configured()[0]]
