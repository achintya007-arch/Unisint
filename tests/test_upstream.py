"""Silent upstream failures: tools that exit 0 when their sources fail.

Real captured outputs live in tests/fixtures (see README there). Success and
partial variants below are SYNTHETIC, written in the same format.
"""
import asyncio
import json
import pathlib

from unisint.adapters.recon_tools import (parse_harvester_summary,
                                          parse_subfinder_stats, report_upstream,
                                          summarize_sources)
from unisint.base import MODE_RECON, Module
from unisint.models import EntityType

FX = pathlib.Path(__file__).parent / "fixtures"


# ---- real captures --------------------------------------------------------

def test_subfinder_real_capture_all_failed():
    stats = parse_subfinder_stats((FX / "subfinder_v2.17.0_all_sources_failed.stderr").read_text())
    assert stats["crtsh"]["status"] == "failed"
    assert stats["virustotal"]["status"] == "skipped"        # 0 requests
    assert "alienvault" not in stats                         # skipped list is not a row
    status, detail = summarize_sources(stats)
    assert status == "failed" and "crtsh" in detail


def test_harvester_real_capture_failed_and_partial():
    s = parse_harvester_summary((FX / "theharvester_5.0.0_sources_failed.jsonl").read_text())
    assert s["evidence_status"] == "partial"
    assert s["executions"]["crtsh"] == {"status": "failed", "detail": "transport-error",
                                        "results": 0}
    assert s["executions"]["certspotter"]["status"] == "partial"
    status, detail = summarize_sources(s["executions"])
    assert status == "partial"                 # certspotter partial, not all failed
    assert "4 of 5 source(s) failed" in detail


def test_harvester_real_json_is_empty():
    d = json.loads((FX / "theharvester_5.0.0_sources_failed.json").read_text())
    assert d.get("hosts") == [] and "emails" not in d


# ---- synthetic variants (same formats) --------------------------------------

SF_OK = """[INF] Printing source statistics for corp.com
 Source               Duration      Results   Requests     Errors
────────────────────────────────────────────────────────────────────
 crtsh                812ms              12          1          0
 hackertarget         1.2s                3          1          0
 virustotal           0s                  0          0          0
"""
SF_MIXED = SF_OK.replace(" hackertarget         1.2s                3          1          0",
                         " hackertarget         1.2s                0          1          1")


def test_subfinder_synthetic_complete_and_partial():
    assert summarize_sources(parse_subfinder_stats(SF_OK))[0] == "complete"
    assert summarize_sources(parse_subfinder_stats(SF_MIXED))[0] == "partial"


def test_subfinder_missing_or_changed_header_is_unknown_not_success():
    assert parse_subfinder_stats("") is None
    assert parse_subfinder_stats(SF_OK.replace("Requests", "Reqs")) is None


def test_legitimately_empty_when_all_sources_completed():
    execs = {"crtsh": {"status": "completed", "results": 0},
             "otx": {"status": "completed", "results": 0}}
    assert summarize_sources(execs)[0] == "complete"


def test_rate_limited_counts_as_failed_and_all_skipped():
    assert summarize_sources({"a": {"status": "rate-limited"}})[0] == "failed"
    assert summarize_sources({"a": {"status": "skipped"}})[0] == "failed"
    assert summarize_sources({})[0] == "unknown"


def test_harvester_summary_absent_or_garbage():
    assert parse_harvester_summary("") is None
    assert parse_harvester_summary("not json\n{broken") is None


# ---- module status mapping through the real engine -------------------------

def _run_with(execs, n_results):
    from tests.test_pivot_engine import _Registry, make_engine

    class Tool(Module):
        name, label, category = "tool", "Tool", "domain"
        accepts = {EntityType.DOMAIN}
        modes = {MODE_RECON}

        async def run(self, ctx):
            for i in range(n_results):
                ctx.add_entity(EntityType.HOST, f"h{i}.corp.com", source=self.name)
            report_upstream(ctx, "tool", execs, n_results)

    with _Registry([Tool()]):
        e = make_engine(mode=MODE_RECON)
        e.add_entity(EntityType.DOMAIN, "corp.com", source="input")
        asyncio.run(e.run())
    return e.module_status["tool"]


def test_status_mapping():
    failed = {"a": {"status": "failed", "detail": "transport-error"}}
    mixed = {"a": {"status": "failed"}, "b": {"status": "completed"}}
    ok = {"a": {"status": "completed"}}
    assert _run_with(failed, 0)["state"] == "error"          # upstream error
    assert _run_with(mixed, 2)["state"] == "partial"         # partial results
    assert _run_with(mixed, 0)["state"] == "partial"         # empty can't be trusted
    assert _run_with(ok, 0)["state"] == "empty"              # legitimately empty
    assert _run_with(ok, 3)["state"] == "ok"                 # success
    assert _run_with(None, 0)["state"] == "partial"          # status unknown
    assert "transport-error" in _run_with(failed, 0)["last_error"]
