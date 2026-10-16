"""Central scope policy for active reconnaissance.

One object decides — and records — whether any *active* probe (a request that
touches the target itself, e.g. the HTTP fingerprint, or validating a
user-controlled URL) is permitted. It is consulted in two places so a target
can never slip past:

* at **pivot time** (`classify`, pure/deterministic) the engine refuses to
  expand active modules onto anything outside the authorized assets;
* at **execution time** (`authorize_active`, async) the actual destination is
  re-resolved and re-checked right before the connection, closing the
  time-of-check/time-of-use gap, and the SSRF destination guard
  (`urls.check_host`) runs in the same call so authorization and
  destination-safety are one decision.

Authorization applies to active probing only. Passive collection from
third-party datasets/APIs (DNS, RDAP, crt.sh, subfinder, username/email
lookups, …) is never scope-gated here. The policy fails **closed**: anything it
cannot positively place inside the authorized scope, or cannot safely resolve,
is denied for active use.

A domain resolving to an IP does not authorize probing that IP's other tenants,
and discovering a third-party host via a pivot does not authorize probing it.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from enum import Enum

from .models import Entity, EntityType


class TargetClass(str, Enum):
    SEED = "seed"              # exactly an authorized asset the user entered
    IN_SCOPE = "in_scope"      # subdomain of / IP resolved from a seed
    DISCOVERED = "discovered"  # public, but outside the authorized scope
    UNRESOLVED = "unresolved"  # cannot be placed (no host, or DNS unknown)
    UNSAFE = "unsafe"          # private/loopback/link-local/reserved/metadata

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class ScopeDecision:
    target_class: TargetClass
    allow_active: bool
    reason: str
    target: str = ""

    def to_dict(self) -> dict:
        return {"target": self.target, "class": self.target_class.value,
                "allow_active": self.allow_active, "reason": self.reason}


class ScopeDenied(Exception):
    """An active probe was refused (out of scope, unsafe, or unresolvable)."""

    def __init__(self, decision: ScopeDecision):
        super().__init__(decision.reason)
        self.decision = decision


def _coerce_sneaky_ipv4(host: str) -> str | None:
    """Interpret octal/hex/decimal/integer IPv4 forms the way the C resolver
    (inet_aton) does — e.g. ``0177.0.0.1``, ``0x7f.1``, ``2130706433`` all mean
    127.0.0.1. These look like hostnames but resolve to IPs, so the classifier
    must treat them as the IP, not as an unknown public host.
    """
    s = host.strip()
    if not s or not set(s) <= set("0123456789abcdefABCDEFxX."):
        return None
    parts = s.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if p[:2] in ("0x", "0X"):
                n = int(p, 16)
            elif p[0] == "0" and len(p) > 1:
                n = int(p, 8)
            else:
                n = int(p, 10)
        except ValueError:
            return None
        nums.append(n)
    # inet_aton: the last part fills the remaining low-order bytes.
    try:
        if len(nums) == 1:
            packed = nums[0]
        else:
            if any(n > 0xFF for n in nums[:-1]):
                return None
            rem = 4 - len(nums)
            if nums[-1] > (0xFF << (8 * rem) | (1 << (8 * rem)) - 1):
                return None
            packed = nums[-1]
            for i, n in enumerate(reversed(nums[:-1]), start=1):
                packed |= n << (8 * (rem + i))
        if packed > 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(packed))
    except (ipaddress.AddressValueError, ValueError):
        return None


def _canonical_ip(value: str) -> str | None:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return _coerce_sneaky_ipv4(value)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


@dataclass
class ScopePolicy:
    """Authorized assets for active probing, plus an audit trail.

    Carries the former ``Scope`` surface (``domains``/``ips``/``add_seed``/
    ``contains``) so existing call sites keep working, and adds classification,
    the execution-time authorization gate and an audit log.
    """
    mode: str = "self"
    domains: set[str] = field(default_factory=set)   # authorized apex/host names
    ips: set[str] = field(default_factory=set)       # authorized IPs (canonical)
    audit: list[dict] = field(default_factory=list)

    # ---- building scope from seeds -------------------------------------
    def add_seed(self, ent: Entity) -> None:
        if ent.type in (EntityType.DOMAIN, EntityType.HOST):
            self.domains.add(ent.value.strip().lower().rstrip("."))
        elif ent.type == EntityType.IP:
            ip = _canonical_ip(ent.value)
            if ip:
                self.ips.add(ip)
        elif ent.type == EntityType.URL:
            from .urls import url_host
            h = url_host(ent.value)
            if h:
                self.domains.add(h)

    def authorize_resolved_ip(self, ip: str, parent: Entity) -> None:
        """An IP a *seeded* host resolves to is in scope for active probing.

        Only seeds authorize their resolved IPs: a third-party host discovered
        via a pivot does not drag its address into scope.
        """
        if parent.basis != "seed":
            return
        canon = _canonical_ip(ip)
        if canon:
            self.ips.add(canon)

    # ---- membership (back-compat) --------------------------------------
    def contains_host(self, host: str) -> bool:
        h = (host or "").strip().lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def contains(self, ent: Entity) -> bool:
        c = self.classify(ent).target_class
        return c in (TargetClass.SEED, TargetClass.IN_SCOPE)

    # ---- classification (pure) -----------------------------------------
    def _host_of(self, ent: Entity) -> str | None:
        if ent.type in (EntityType.DOMAIN, EntityType.HOST):
            return ent.value.strip().lower().rstrip(".")
        if ent.type in (EntityType.URL, EntityType.ACCOUNT):
            from .urls import url_host
            return url_host(ent.value) or None
        return None

    def classify(self, target) -> ScopeDecision:
        """Classify an Entity or a host/IP string. Deterministic, no network."""
        if isinstance(target, Entity):
            ent = target
            if ent.type == EntityType.IP:
                return self._classify_ip(ent.value)
            host = self._host_of(ent)
            if host is None:
                return ScopeDecision(TargetClass.UNRESOLVED, False,
                                     f"{ent.type.value} is not an active target",
                                     str(ent.value))
            return self._classify_host(host)
        s = str(target).strip()
        if _canonical_ip(s):
            return self._classify_ip(s)
        return self._classify_host(s.lower().rstrip("."))

    def _classify_host(self, host: str) -> ScopeDecision:
        from .urls import _BAD_HOSTNAMES, _BAD_SUFFIXES
        if not host:
            return ScopeDecision(TargetClass.UNRESOLVED, False, "empty host", host)
        if host in _BAD_HOSTNAMES or host.endswith(_BAD_SUFFIXES):
            return ScopeDecision(TargetClass.UNSAFE, False,
                                 "non-internet hostname", host)
        if host in self.domains:
            return ScopeDecision(TargetClass.SEED, True,
                                 "seed asset entered by user", host)
        if any(host.endswith("." + d) for d in self.domains):
            return ScopeDecision(TargetClass.IN_SCOPE, True,
                                 "subdomain of an authorized seed", host)
        return ScopeDecision(TargetClass.DISCOVERED, False,
                             "public host outside authorized scope "
                             "(recorded, not actively probed)", host)

    def _classify_ip(self, value: str) -> ScopeDecision:
        from .urls import ip_is_public
        canon = _canonical_ip(value)
        if canon is None:
            return ScopeDecision(TargetClass.UNRESOLVED, False,
                                 "unparseable IP", str(value))
        if not ip_is_public(canon):
            return ScopeDecision(TargetClass.UNSAFE, False,
                                 "non-public address", canon)
        if canon in self.ips:
            return ScopeDecision(TargetClass.SEED, True,
                                 "authorized IP (seed or resolved from a seed)",
                                 canon)
        return ScopeDecision(TargetClass.DISCOVERED, False,
                             "public IP outside authorized scope", canon)

    # ---- execution-time gate (async; re-checks + SSRF) -----------------
    def _record(self, decision: ScopeDecision, module: str = "") -> None:
        self.audit.append({"t": time.time(), "module": module, **decision.to_dict()})

    async def authorize_active(self, host: str, resolver=None, *,
                               module: str = "", allow_unresolved: bool = False
                               ) -> list[str]:
        """Gate for an about-to-happen active request. Returns the validated
        public IPs ([] when resolution is delegated to a proxy) or raises
        ScopeDenied. Records every outcome.

        Re-classifies at call time (TOCTOU), then resolves and runs the SSRF
        destination guard so authorization and safety are one decision. Fails
        closed on anything unresolved or ambiguous — except when
        ``allow_unresolved`` (a proxy resolves on our behalf), where the
        authorization check still applies and the connect-time guard remains
        the destination backstop.
        """
        from .urls import UnsafeTarget, check_host
        decision = self.classify(host)
        if not decision.allow_active:
            self._record(decision, module)
            raise ScopeDenied(decision)
        try:
            ips = await check_host(host, resolver, allow_unresolved=allow_unresolved)
        except UnsafeTarget as exc:
            d = ScopeDecision(TargetClass.UNSAFE, False,
                              f"destination refused: {exc}", host)
            self._record(d, module)
            raise ScopeDenied(d) from exc
        except LookupError as exc:
            d = ScopeDecision(TargetClass.UNRESOLVED, False,
                              f"could not resolve safely: {exc}", host)
            self._record(d, module)
            raise ScopeDenied(d) from exc
        self._record(decision, module)
        return ips

    # ---- serialisation --------------------------------------------------
    def to_dict(self) -> dict:
        return {"mode": self.mode, "domains": sorted(self.domains),
                "ips": sorted(self.ips), "audit": self.audit}
