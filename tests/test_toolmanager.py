"""Tool health states: an executable existing is not proof it works."""
import asyncio
import pathlib

import pytest

from unisint import runner, toolmanager
from unisint.toolmanager import go_requirement, health_check, parse_go_version


def _exe(d, name, body):
    p = d / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)
    return p


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("UNISINT_TOOL_PATHS", str(tmp_path))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(toolmanager, "_HEALTH", {})
    monkeypatch.setattr(runner, "_FAILURES", {})
    monkeypatch.setattr(runner, "_SUCCESSES", {})
    return tmp_path


def test_runnable_misconfigured_unavailable(fake_tools):
    _exe(fake_tools, "sherlock", 'echo "Sherlock v0.16.2"; exit 0')
    _exe(fake_tools, "maigret", 'echo "ModuleNotFoundError: aiohttp" >&2; exit 1')
    r = asyncio.run(health_check("sherlock"))
    assert r["state"] == "runnable" and "0.16.2" in r["detail"]
    m = asyncio.run(health_check("maigret"))
    assert m["state"] == "misconfigured" and "ModuleNotFoundError" in m["detail"]
    assert asyncio.run(health_check("socialscan"))["state"] == "unavailable"


def test_hanging_tool_is_misconfigured(fake_tools):
    _exe(fake_tools, "holehe", "sleep 30")
    r = asyncio.run(health_check("holehe", timeout=1))
    assert r["state"] == "misconfigured" and "hung" in r["detail"]


def test_health_checks_do_not_count_as_runs(fake_tools):
    _exe(fake_tools, "sherlock", "exit 0")
    asyncio.run(health_check("sherlock"))
    assert runner.success_counts() == {}


def test_operational_and_failing_from_real_runs(fake_tools):
    ok = _exe(fake_tools, "sherlock", "exit 0")
    bad = _exe(fake_tools, "maigret", "exit 0")
    asyncio.run(health_check("sherlock"))
    asyncio.run(health_check("maigret"))
    runner.record_success(str(ok))
    runner.record_failure(str(bad))
    runner.record_failure(str(bad))
    states = {t["name"]: t["state"] for t in toolmanager.status()}
    assert states["sherlock"] == "operational"
    assert states["maigret"] == "failing"
    assert states["amass"] == "unavailable"


def test_installed_but_unchecked(fake_tools):
    _exe(fake_tools, "subfinder", "exit 0")
    states = {t["name"]: t["state"] for t in toolmanager.status()}
    assert states["subfinder"] == "installed"


@pytest.mark.parametrize("text,v", [("go version go1.24.7 linux/amd64", (1, 24)),
                                    ("go version go1.18.1 linux/amd64", (1, 18)),
                                    ("nonsense", None)])
def test_parse_go_version(text, v):
    assert parse_go_version(text) == v



@pytest.mark.parametrize("local,tc,need,ok,frag", [
    ((1, 26), "auto", (1, 26), True, "satisfies"),
    ((1, 24), "auto", (1, 26), True, "download go1.26+"),       # verified live here
    ((1, 24), "go1.24.7+auto", (1, 26), True, "download"),
    ((1, 24), "local", (1, 26), False, "GOTOOLCHAIN=local forbids"),  # reproduced live
    ((1, 22), "local", (1, 19), True, "satisfies"),              # amass
    ((1, 18), "auto", (1, 26), False, "predates toolchain switching"),
    ((1, 18), "", (1, 19), False, "predates"),
    (None, "", (1, 26), False, "Go not found"),
])
def test_go_requirement_matrix(local, tc, need, ok, frag):
    got, why = go_requirement(local, tc, need, "subfinder v2.17.0")
    assert got is ok and frag in why


def test_go_tools_are_pinned_with_verified_minimums():
    gotools = {t.name: t for t in toolmanager.CATALOG if t.kind == "go"}
    assert gotools["subfinder"].spec.endswith("@v2.17.0") and gotools["subfinder"].min_go == (1, 26)
    assert gotools["amass"].spec.endswith("@v4.2.0") and gotools["amass"].min_go == (1, 19)
    sh = (pathlib.Path(__file__).resolve().parents[1] / "install_tools.sh").read_text()
    assert gotools["subfinder"].spec in sh and gotools["amass"].spec in sh


def test_go_check_reads_go_env(fake_tools, monkeypatch):
    _exe(fake_tools, "go", 'if [ "$1" = env ]; then echo go1.18.1; echo auto; else echo "go version go1.18.1 linux/amd64"; fi')
    monkeypatch.setenv("PATH", str(fake_tools))
    ok, why = asyncio.run(toolmanager.go_check("subfinder"))
    assert not ok and "predates toolchain switching" in why and "go.dev/dl" in why


def test_harvester_install_explains_uv(monkeypatch):
    import shutil
    real = shutil.which
    monkeypatch.setattr(toolmanager.shutil, "which",
                        lambda n: None if n == "uv" else real(n))
    r = asyncio.run(toolmanager.install("theHarvester"))
    assert not r["ok"] and "3.14" in r["msg"] and "uv" in r["msg"]
