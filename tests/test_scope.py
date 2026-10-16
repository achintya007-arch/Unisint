"""Central scope policy: classification, execution-time gate, audit, SSRF.

Deterministic (no real network): the resolver is injected.
"""
import asyncio

import pytest

from unisint.models import Entity, EntityType
from unisint.scope import ScopeDenied, ScopePolicy, TargetClass


def seed(policy, etype, value):
    policy.add_seed(Entity(type=etype, value=value, basis="seed"))


def mkpolicy(domains=("corp.com",), ips=()):
    p = ScopePolicy(mode="recon")
    for d in domains:
        seed(p, EntityType.DOMAIN, d)
    for i in ips:
        seed(p, EntityType.IP, i)
    return p


# ---- host classification ---------------------------------------------------

@pytest.mark.parametrize("host,cls,active", [
    ("corp.com", TargetClass.SEED, True),
    ("CORP.com.", TargetClass.SEED, True),              # case/trailing dot
    ("api.corp.com", TargetClass.IN_SCOPE, True),
    ("a.b.corp.com", TargetClass.IN_SCOPE, True),
    ("evilcorp.com", TargetClass.DISCOVERED, False),    # suffix trap
    ("corp.com.evil.net", TargetClass.DISCOVERED, False),
    ("third-party.net", TargetClass.DISCOVERED, False),
    ("localhost", TargetClass.UNSAFE, False),
    ("printer.local", TargetClass.UNSAFE, False),
    ("metadata.google.internal", TargetClass.UNSAFE, False),
])
def test_host_classification(host, cls, active):
    d = mkpolicy().classify(host)
    assert d.target_class == cls and d.allow_active is active


# ---- IP classification incl. alternate representations ---------------------

@pytest.mark.parametrize("ip,cls,active", [
    ("93.184.216.34", TargetClass.DISCOVERED, False),   # public, not authorized
    ("10.0.0.5", TargetClass.UNSAFE, False),
    ("127.0.0.1", TargetClass.UNSAFE, False),
    ("169.254.169.254", TargetClass.UNSAFE, False),     # cloud metadata
    ("::1", TargetClass.UNSAFE, False),
    ("::ffff:127.0.0.1", TargetClass.UNSAFE, False),    # v4-mapped loopback
    ("0177.0.0.1", TargetClass.UNSAFE, False),          # octal 127.0.0.1
    ("100.64.0.1", TargetClass.UNSAFE, False),          # CGNAT
])
def test_ip_classification(ip, cls, active):
    d = mkpolicy().classify(ip)
    assert d.target_class == cls and d.allow_active is active


def test_authorized_ip_is_seed():
    p = mkpolicy(ips=("93.184.216.34",))
    assert p.classify("93.184.216.34").target_class == TargetClass.SEED
    assert p.classify("::ffff:93.184.216.34").target_class == TargetClass.SEED


def test_resolved_ip_only_from_seed_parent():
    p = mkpolicy()
    seed_host = Entity(type=EntityType.DOMAIN, value="corp.com", basis="seed")
    discovered = Entity(type=EntityType.HOST, value="x.other.net", basis="observed")
    p.authorize_resolved_ip("93.184.216.34", discovered)   # must NOT authorize
    assert p.classify("93.184.216.34").target_class == TargetClass.DISCOVERED
    p.authorize_resolved_ip("93.184.216.34", seed_host)    # seed does
    assert p.classify("93.184.216.34").target_class == TargetClass.SEED


# ---- entity classification -------------------------------------------------

def test_entity_url_and_account_use_host():
    p = mkpolicy()
    e = Entity(type=EntityType.URL, value="https://api.corp.com/x", basis="observed")
    assert p.classify(e).target_class == TargetClass.IN_SCOPE
    e2 = Entity(type=EntityType.ACCOUNT, value="https://gitlab.com/u", basis="observed")
    assert p.classify(e2).target_class == TargetClass.DISCOVERED


def test_non_targetable_entity_is_unresolved():
    p = mkpolicy()
    e = Entity(type=EntityType.EMAIL, value="a@corp.com", basis="observed")
    d = p.classify(e)
    assert d.target_class == TargetClass.UNRESOLVED and not d.allow_active


# ---- execution-time gate (authorize_active) --------------------------------

def _resolver(mapping):
    async def r(host):
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]
    return r


def test_authorize_active_allows_in_scope_and_records_audit():
    p = mkpolicy()
    ips = asyncio.run(p.authorize_active(
        "api.corp.com", _resolver({"api.corp.com": ["93.184.216.34"]}),
        module="httpfp"))
    assert ips == ["93.184.216.34"]
    assert p.audit[-1]["allow_active"] and p.audit[-1]["module"] == "httpfp"


def test_authorize_active_denies_out_of_scope_before_dns():
    p = mkpolicy()
    with pytest.raises(ScopeDenied) as ei:
        asyncio.run(p.authorize_active("third-party.net", _resolver({})))
    assert ei.value.decision.target_class == TargetClass.DISCOVERED
    assert p.audit[-1]["allow_active"] is False


def test_authorize_active_fails_closed_on_unresolved():
    p = mkpolicy()
    with pytest.raises(ScopeDenied) as ei:
        asyncio.run(p.authorize_active("api.corp.com", _resolver({})))
    assert ei.value.decision.target_class == TargetClass.UNRESOLVED


def test_authorize_active_blocks_rebinding_to_private():
    """In scope by name, but DNS returns a private answer: refuse."""
    p = mkpolicy()
    with pytest.raises(ScopeDenied) as ei:
        asyncio.run(p.authorize_active(
            "api.corp.com", _resolver({"api.corp.com": ["93.184.216.34", "10.0.0.1"]})))
    assert ei.value.decision.target_class == TargetClass.UNSAFE


def test_authorize_active_allow_unresolved_still_checks_authorization():
    p = mkpolicy()
    # proxy resolves: DNS is skipped, but authorization still applies
    assert asyncio.run(p.authorize_active("api.corp.com", _resolver({}),
                                          allow_unresolved=True)) == []
    with pytest.raises(ScopeDenied):
        asyncio.run(p.authorize_active("third-party.net", _resolver({}),
                                       allow_unresolved=True))


def test_scope_serialises_with_audit():
    p = mkpolicy()
    asyncio.run(p.authorize_active("api.corp.com",
                                   _resolver({"api.corp.com": ["93.184.216.34"]})))
    d = p.to_dict()
    assert d["mode"] == "recon" and "corp.com" in d["domains"]
    assert d["audit"] and d["audit"][0]["class"] == "in_scope"
