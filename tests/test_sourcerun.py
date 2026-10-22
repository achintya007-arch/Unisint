"""Source-run contract: for every module the engine records whether it
actually contacted the source, whether the run was *live* (not fixture-backed),
whether results were truncated, how many findings it produced, and maps a
module's explicit provider/tool status onto the status vocabulary. Also covers
single-source re-run isolation (one module, original seeds, depth 0).

Fake modules only — no network is touched.
"""
import asyncio

from unisint import base
from unisint.base import MODE_RECON, MODE_SELF, Module
from unisint.engine import SOURCE_STATES, Engine, _refine_status
from unisint.models import EntityType
from unisint.pivot import Limits


class _Registry:
    def __init__(self, mods):
        self.mods = mods

    def __enter__(self):
        self._saved = list(base._REGISTRY)
        base._REGISTRY[:] = self.mods
        return self

    def __exit__(self, *a):
        base._REGISTRY[:] = self._saved


class _DummyHttp:
    async def aclose(self):
        pass


async def _noop(_):
    pass


def make_engine(mode=MODE_SELF, only_modules=None, **lim):
    return Engine(mode=mode, config={"api_keys": {}}, emit=_noop,
                  limits=Limits(**lim), http=_DummyHttp(), safe_http=_DummyHttp(),
                  only_modules=only_modules)


def _run_domain(mods, value="corp.com", mode=MODE_RECON, **kw):
    with _Registry(mods):
        e = make_engine(mode=mode, **kw)
        e.add_entity(EntityType.DOMAIN, value, source="input")
        asyncio.run(e.run())
    return e


# ---- the status vocabulary ------------------------------------------------

def test_status_vocabulary_covers_the_contract():
    for s in ("ok", "empty", "partial", "error", "blocked", "rate_limited",
              "auth_error", "unavailable", "not_configured", "timeout", "skipped"):
        assert s in SOURCE_STATES


def test_refine_status_rules():
    # An explicit degraded status wins while the module produced nothing.
    assert _refine_status("empty", "rate_limited", {"ok": 0}) == "rate_limited"
    assert _refine_status("error", "auth_error", {"ok": 0}) == "auth_error"
    # Real findings override the explicit status (the source did work).
    assert _refine_status("ok", "rate_limited", {"ok": 1}) == "ok"
    # A status outside the explicit set never overrides the derived verdict.
    assert _refine_status("empty", "ok", {"ok": 0}) == "empty"
    assert _refine_status("error", None, {"ok": 0}) == "error"


# ---- contacted / live / truncated / findings ------------------------------

def test_contacted_live_truncated_and_findings_recorded():
    class Src(Module):
        name, label, category = "src", "Src", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.mark_contacted(live=False)   # fixture-backed
            ctx.mark_truncated(100, 2)       # 100 available, 2 kept
            ctx.add_entity(EntityType.HOST, "a.corp.com", source=self.name)
            ctx.add_entity(EntityType.HOST, "b.corp.com", source=self.name)

    st = _run_domain([Src()]).module_status["src"]
    assert st["state"] == "ok"
    assert st["contacted"] is True
    assert st["live"] is False
    assert st["truncated"] is True
    assert st["results_retrieved"] == 100
    assert st["findings"] == 2
    assert st["active"] is False
    assert st["target_type"] == "domain"


def test_empty_run_is_contacted_but_live():
    class Quiet(Module):
        name, label, category = "quiet", "Quiet", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.mark_contacted()             # reached the source, found nothing

    st = _run_domain([Quiet()]).module_status["quiet"]
    assert st["state"] == "empty"
    assert st["contacted"] is True and st["live"] is True
    assert st["findings"] == 0 and st["truncated"] is False


# ---- explicit status mapping ---------------------------------------------

def test_explicit_status_maps_onto_vocabulary():
    class Limited(Module):
        name, label, category = "lim", "Limited", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.status("rate_limited", "429 from provider")

    st = _run_domain([Limited()]).module_status["lim"]
    assert st["state"] == "rate_limited"
    assert st["contacted"] is True          # status() implies we reached out


def test_findings_override_an_explicit_degraded_status():
    class Flaky(Module):
        name, label, category = "flaky", "Flaky", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.status("rate_limited")       # one provider throttled, but
            ctx.add_entity(EntityType.HOST, "a.corp.com", source=self.name)

    st = _run_domain([Flaky()]).module_status["flaky"]
    assert st["state"] == "ok"              # it still produced a real result


# ---- unavailable vs not_configured ----------------------------------------

def test_missing_key_is_not_configured_not_contacted():
    class Keyed(Module):
        name, label, category = "keyed", "Keyed", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}
        requires_key = "hunter"

        async def run(self, ctx):          # pragma: no cover - never reached
            ctx.add_entity(EntityType.EMAIL, "x@corp.com", source=self.name)

    st = _run_domain([Keyed()]).module_status["keyed"]
    assert st["state"] == "not_configured"
    assert st["contacted"] is False
    assert st["label"] == "Keyed"


def test_missing_tool_is_unavailable():
    class Tooled(Module):
        name, label, category = "tooled", "Tooled", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}
        requires_tool = "unisint-no-such-binary-xyz"

        async def run(self, ctx):          # pragma: no cover - never reached
            pass

    st = _run_domain([Tooled()]).module_status["tooled"]
    assert st["state"] == "unavailable"
    assert st["contacted"] is False


# ---- single-source re-run isolation ---------------------------------------

def test_only_modules_runs_just_the_target_source():
    class A(Module):
        name, label, category = "a", "A", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.add_entity(EntityType.HOST, "a.corp.com", source=self.name)

    class B(Module):
        name, label, category = "b", "B", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):          # pragma: no cover - must not run
            ctx.add_entity(EntityType.HOST, "b.corp.com", source=self.name)

    e = _run_domain([A(), B()], only_modules={"a"})
    assert "a" in e.module_status and "b" not in e.module_status
    produced = {x.value for x in e.entities.values() if x.source != "input"}
    assert produced == {"a.corp.com"}       # B never contributed
    # The re-run module is credited only with its own findings.
    assert e.module_status["a"]["findings"] == 1


def test_rerun_preserves_provenance_on_produced_entities():
    class Sub(Module):
        name, label, category = "sub", "Sub", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_SELF, MODE_RECON}

        async def run(self, ctx):
            ctx.add_entity(EntityType.HOST, "api.corp.com", source=self.name,
                           rel="subdomain")

    e = _run_domain([Sub()], only_modules={"sub"})
    host = e.entities[("host", "api.corp.com")]
    assert host.provenance and host.provenance[0]["source"] == "sub"
    assert host.provenance[0]["parent_value"] == "corp.com"
    assert host.provenance[0]["rel"] == "subdomain"
