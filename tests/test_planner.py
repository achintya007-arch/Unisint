"""Investigation plan: correct per-input-type module lists and statuses."""
import asyncio

from unisint import base
from unisint.planner import (NEEDS_CREDENTIALS, SKIPPED_PRESET, UNAVAILABLE,
                             WILL_RUN, build_plan)

base.load_all()
NO_KEYS = {"api_keys": {}}


def plan(target, mode, cap=3, config=NO_KEYS):
    return asyncio.run(build_plan([target], mode, weight_cap=cap, config=config))


def _by_name(tp):
    return {m["name"]: m for m in tp["modules"]}


def test_username_plan_lists_username_modules():
    tp = plan("octocat", "self")["targets"][0]
    assert tp["type"] == "username"
    mods = _by_name(tp)
    assert mods["github"]["status"] == WILL_RUN
    assert mods["github"]["passive"] and not mods["github"]["active"]


def test_domain_recon_marks_httpfp_active():
    tp = plan("example.com", "recon")["targets"][0]
    mods = _by_name(tp)
    assert mods["httpfp"]["active"] is True
    # seed is authorized, so the active probe will run on it
    assert mods["httpfp"]["status"] == WILL_RUN


def test_web_search_without_provider_is_needs_credentials():
    tp = plan("Ada Lovelace", "self")["targets"][0]
    assert _by_name(tp)["web_search"]["status"] == NEEDS_CREDENTIALS


def test_preset_weight_cap_skips_heavy_modules():
    tp = plan("octocat", "self", cap=1)["targets"][0]
    # maigret (weight 3) and sherlock (weight 2) are skipped at cap 1
    assert _by_name(tp)["maigret"]["status"] == SKIPPED_PRESET


def test_missing_tool_is_unavailable():
    tp = plan("octocat", "self")["targets"][0]
    # sherlock/socialscan tools aren't installed in the test env
    assert _by_name(tp)["sherlock"]["status"] == UNAVAILABLE
    assert "not installed" in _by_name(tp)["sherlock"]["detail"]


def test_counts_and_authorized_scope():
    p = plan("example.com", "recon")
    assert sum(p["counts"].values()) == len(p["targets"][0]["modules"])
    assert "example.com" in p["authorized"]


def test_email_and_phone_route_to_right_modules():
    em = _by_name(plan("a@b.com", "self")["targets"][0])
    assert "gravatar" in em and "github" not in em
    ph = _by_name(plan("+14155552671", "self")["targets"][0])
    assert "phone_info" in ph and ph["phone_info"]["status"] == WILL_RUN


def test_needs_credentials_detects_configured_brave_key():
    tp = plan("Ada Lovelace", "self", config={"api_keys": {"brave": "k"}})["targets"][0]
    # with a provider key present, web_search becomes runnable
    assert _by_name(tp)["web_search"]["status"] == WILL_RUN
