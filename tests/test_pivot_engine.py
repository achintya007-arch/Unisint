"""Pivot policy, scope guard, engine provenance/dedup and bounded expansion.

Uses fake modules registered into a private registry so no network is touched.
"""
import asyncio

import pytest

from unisint import base
from unisint.base import MODE_RECON, MODE_SELF, Module
from unisint.engine import Engine
from unisint.models import Entity, EntityType
from unisint.pivot import Limits, Scope, decide


class M(Module):
    def __init__(self, name="m", active=False):
        self.name = name
        self.label = name
        self.active = active


def ent(t, v, depth=1, basis="observed", link=None):
    e = Entity(type=t, value=v, depth=depth, basis=basis)
    if link:
        e.meta["identity_link"] = link
    return e


def d(e, m=None, mode=MODE_SELF, scope=None, runs=None, limits=None):
    return decide(e, m or M(), mode=mode, limits=limits or Limits(),
                  scope=scope or Scope(), module_runs=runs or {})


# ---- policy ---------------------------------------------------------------

def test_seed_always_expands():
    ok, why = d(ent(EntityType.USERNAME, "alice", depth=0, basis="seed"))
    assert ok and "seed" in why


def test_candidate_never_expands():
    ok, why = d(ent(EntityType.USERNAME, "a.lovelace", basis="candidate"))
    assert not ok and "candidate" in why


def test_handle_match_does_not_expand():
    ok, why = d(ent(EntityType.EMAIL, "x@y.com", link="handle_profile"))
    assert not ok and "too weak" in why


def test_profile_link_expands():
    ok, _ = d(ent(EntityType.EMAIL, "x@y.com", link="profile"))
    assert ok


@pytest.mark.parametrize("t", [EntityType.FULL_NAME, EntityType.LOCATION,
                               EntityType.ORG, EntityType.ACCOUNT])
def test_attributes_never_expand(t):
    ok, why = d(ent(t, "v", link="profile"))
    assert not ok


def test_recon_records_people_identifiers_only():
    ok, why = d(ent(EntityType.EMAIL, "admin@corp.com", link="profile"),
                mode=MODE_RECON)
    assert not ok and "RECON" in why


def test_depth_limit():
    ok, why = d(ent(EntityType.EMAIL, "x@y.com", depth=3, link="profile"),
                limits=Limits(depth=2))
    assert not ok and "depth" in why


def test_module_run_cap():
    ok, why = d(ent(EntityType.USERNAME, "a", depth=0, basis="seed"),
                m=M("sherlock"), runs={"sherlock": 40}, limits=Limits(per_module_runs=40))
    assert not ok and "cap" in why


def test_scope_infra():
    s = Scope(domains={"corp.com"})
    assert d(ent(EntityType.HOST, "api.corp.com"), scope=s)[0]
    assert not d(ent(EntityType.HOST, "aspmx.l.google.com"), scope=s)[0]
    assert not d(ent(EntityType.HOST, "evilcorp.com"), scope=s)[0]  # suffix trap


def test_active_module_requires_scope_even_for_seed_type_values():
    s = Scope(domains={"corp.com"})
    active = M("httpfp", active=True)
    ok, why = d(ent(EntityType.HOST, "third-party.net"), m=active, scope=s)
    assert not ok and "out of scope" in why
    assert d(ent(EntityType.HOST, "www.corp.com"), m=active, scope=s)[0]


# ---- engine with fake modules ----------------------------------------------

class _Registry:
    def __init__(self, mods):
        self.mods = mods

    def __enter__(self):
        self._saved = list(base._REGISTRY)
        base._REGISTRY[:] = self.mods
        return self

    def __exit__(self, *a):
        base._REGISTRY[:] = self._saved


async def _noop_emit(_):
    pass


def make_engine(mode=MODE_SELF, **lim):
    return Engine(mode=mode, config={"api_keys": {}}, emit=_noop_emit,
                  limits=Limits(**lim), http=_DummyHttp(), safe_http=_DummyHttp())


class _DummyHttp:
    async def aclose(self):
        pass


class Echo(Module):
    """username → ACCOUNT (handle match) + the same username again (loop bait)."""
    name, label, category = "echo", "Echo", "username"
    accepts = {EntityType.USERNAME}
    modes = {MODE_SELF}

    def __init__(self):
        self.calls = []

    async def run(self, ctx):
        self.calls.append(ctx.entity.value)
        ctx.add_entity(EntityType.ACCOUNT, f"https://site.example/{ctx.entity.value}",
                       source=self.name, identity_link="handle_match",
                       meta={"url": f"https://site.example/{ctx.entity.value}"})
        ctx.add_entity(EntityType.USERNAME, ctx.entity.value, source=self.name)
        ctx.add_entity(EntityType.USERNAME, ctx.entity.value + "_alt",
                       source=self.name, identity_link="handle_profile")


def test_engine_no_loops_and_weak_not_expanded():
    echo = Echo()
    with _Registry([echo]):
        e = make_engine()
        e.add_entity(EntityType.USERNAME, "alice", source="input")
        asyncio.run(e.run())
    assert echo.calls == ["alice"]            # alice once; alice_alt not expanded
    alt = e.entities[("username", "alice_alt")]
    assert alt.meta["identity_link"] == "handle_profile"
    skipped = [p for p in e.pivots if p["entity"] == "username:alice_alt"]
    assert skipped and "too weak" in skipped[0]["skipped"][0]["reason"]


def test_engine_provenance_merge_keeps_all_sources():
    with _Registry([]):
        e = make_engine()
        root = e.add_entity(EntityType.DOMAIN, "corp.com", source="input")
        a = e.add_entity(EntityType.HOST, "api.corp.com", source="crtsh", parent=root)
        b = e.add_entity(EntityType.HOST, "API.corp.com.", source="subfinder", parent=root)
    assert a is b                              # normalised dedup
    assert [p["source"] for p in a.provenance] == ["crtsh", "subfinder"]
    assert a.meta["sources"] == ["crtsh", "subfinder"]
    assert all(p["parent_id"] == root.id for p in a.provenance)


def test_engine_candidate_upgraded_by_observation():
    with _Registry([]):
        e = make_engine()
        r = e.add_entity(EntityType.FULL_NAME, "Ada Lovelace", source="input")
        c = e.add_entity(EntityType.USERNAME, "adal", source="name_permute",
                         parent=r, basis="candidate")
        assert c.basis == "candidate"
        e.add_entity(EntityType.USERNAME, "adal", source="github", parent=r)
        assert c.basis == "observed" and len(c.provenance) == 2


def test_engine_entity_cap():
    with _Registry([]):
        e = make_engine(max_entities=3)
        r = e.add_entity(EntityType.DOMAIN, "corp.com", source="input")
        out = [e.add_entity(EntityType.HOST, f"h{i}.corp.com", source="t", parent=r)
               for i in range(5)]
    assert len(e.entities) == 3 and out[-1] is None


def test_engine_scope_includes_ips_of_in_scope_hosts():
    with _Registry([]):
        e = make_engine(mode=MODE_RECON)
        r = e.add_entity(EntityType.DOMAIN, "corp.com", source="input")
        e.add_entity(EntityType.IP, "93.184.216.34", source="dns", parent=r,
                     rel="resolves_to")
        mx = e.add_entity(EntityType.HOST, "aspmx.l.google.com", source="dns",
                          parent=r, rel="mail_server")
        e.add_entity(EntityType.IP, "142.250.1.1", source="dns", parent=mx,
                     rel="resolves_to")
    assert "93.184.216.34" in e.scope.ips
    assert "142.250.1.1" not in e.scope.ips


def test_engine_time_budget_partial():
    class Slow(Module):
        name, label, category = "slow", "Slow", "username"
        accepts = {EntityType.USERNAME}
        modes = {MODE_SELF}

        async def run(self, ctx):
            await asyncio.sleep(5)

    with _Registry([Slow()]):
        e = make_engine(time_budget=0.5)
        e.add_entity(EntityType.USERNAME, "alice", source="input")
        asyncio.run(asyncio.wait_for(e.run(), timeout=10))
    assert any("time budget" in l["msg"] for l in e.logs)


def test_module_status_is_honest():
    """Regression: modules that swallowed network errors were reported 'ok'."""
    class Fails(Module):
        name, label, category = "fails", "Fails", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.error("svc: HTTP 403")

    class Empty(Fails):
        name = "empty"

        async def run(self, ctx):
            pass

    class Finds(Fails):
        name = "finds"

        async def run(self, ctx):
            ctx.add_entity(EntityType.HOST, "a.corp.com", source=self.name)

    class Raises(Fails):
        name = "raises"

        async def run(self, ctx):
            raise RuntimeError("tool exit 2")

    with _Registry([Fails(), Empty(), Finds(), Raises()]):
        e = make_engine(mode=MODE_RECON)
        e.add_entity(EntityType.DOMAIN, "corp.com", source="input")
        asyncio.run(e.run())
    st = {k: v["state"] for k, v in e.module_status.items()}
    assert st == {"fails": "error", "empty": "empty", "finds": "ok", "raises": "error"}
    assert "403" in e.module_status["fails"]["last_error"]


def test_module_status_not_credited_with_concurrent_modules_findings():
    """Regression: 'ok' was inferred from the global entity count, so a module
    that found nothing was credited with a concurrent module's results."""
    class Slowfind(Module):
        name, label, category = "slowfind", "S", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_RECON}

        async def run(self, ctx):
            await asyncio.sleep(0.05)
            ctx.add_entity(EntityType.HOST, "x.corp.com", source=self.name)

    class Nothing(Slowfind):
        name = "nothing"

        async def run(self, ctx):
            await asyncio.sleep(0.2)

    with _Registry([Slowfind(), Nothing()]):
        e = make_engine(mode=MODE_RECON)
        e.add_entity(EntityType.DOMAIN, "corp.com", source="input")
        asyncio.run(e.run())
    assert e.module_status["slowfind"]["state"] == "ok"
    assert e.module_status["nothing"]["state"] == "empty"


def test_engine_corroboration_through_merged_seed():
    """Real path: the profile lists an email that is also a seed, so the
    observation merges into the seed entity. Corroboration must still be found
    via the seed's provenance records."""
    from unisint.synthesis import build_dossier

    class FakeGH(Module):
        name, label, category = "github", "GH", "username"
        accepts = {EntityType.USERNAME}
        modes = {MODE_SELF}

        async def run(self, ctx):
            ctx.add_entity(EntityType.ACCOUNT, "https://github.com/ada", source=self.name,
                           rel="account_of", identity_link="handle_match",
                           meta={"site": "GitHub", "url": "https://github.com/ada"})
            ctx.add_entity(EntityType.EMAIL, "Ada@Corp.com", source=self.name,
                           rel="listed_on_profile", identity_link="handle_profile")

    with _Registry([FakeGH()]):
        e = make_engine()
        e.add_entity(EntityType.USERNAME, "ada", source="input")
        e.add_entity(EntityType.EMAIL, "ada@corp.com", source="input")
        asyncio.run(e.run())
    snap = e.snapshot()
    d = build_dossier(snap)
    acc = d["accounts"][0]
    assert acc["assessment"]["label"] == "corroborated_handle", acc["assessment"]
