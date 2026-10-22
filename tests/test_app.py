"""Web-layer tests: HTTP endpoints and the /ws scan lifecycle.

These guard the WebSocket envelope contract (entity/link/dossier/done nesting)
whose earlier bug shipped silently, and the key-masking behaviour of the
config endpoint. The scan uses an offline target so no network is required.
"""
import os
import tempfile

# Isolate UNISINT_HOME so tests never touch a real ~/.unisint.
os.environ.setdefault("UNISINT_HOME", tempfile.mkdtemp(prefix="unisint-test-"))

from fastapi.testclient import TestClient  # noqa: E402

from unisint.app import app  # noqa: E402

client = TestClient(app)


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "UNISINT" in r.text


def test_detect_endpoint():
    r = client.post("/api/detect", json={"value": "a@b.com"})
    assert r.json()["type"] == "email"


def test_config_masks_keys():
    client.post("/api/config", json={"api_keys": {"shodan": "SECRET123"}})
    r = client.get("/api/config")
    body = r.json()
    # Only presence is exposed, never the value.
    assert body["api_keys_set"]["shodan"] is True
    assert "SECRET123" not in r.text


def test_arsenal_shape():
    r = client.get("/api/arsenal")
    d = r.json()
    assert "tools" in d and "modules" in d
    assert all("installed" in t and "failures" in t for t in d["tools"])


def test_gap_roundtrip():
    r = client.post("/api/gap", json={"what": "self-audit on email",
                                      "missing": "no instagram check",
                                      "severity": "high"})
    assert r.json()["ok"] is True
    g = client.get("/api/gaps").json()
    assert g["count"] >= 1
    assert "no instagram check" in g["text"]


def test_doctor_offline(monkeypatch):
    import asyncio

    from unisint import doctor

    async def no_net():
        return [(doctor.OK, "stubbed", "skipped")]

    monkeypatch.setattr(doctor, "_check_endpoints", no_net)
    report, tally = asyncio.run(doctor._run())
    assert "UNISINT DOCTOR" in report
    assert "[ MODULES ]" in report and "[ WRAPPED TOOLS ]" in report
    assert tally["ok"] >= 1


def test_ws_requires_authorization():
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"mode": "self", "authorized": False,
                      "targets": ["+14155552671"]})
        msg = ws.receive_json()
        assert msg["type"] == "log" and msg["level"] == "err"


def test_ws_scan_envelope_contract():
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"mode": "self", "preset": "quick", "authorized": True,
                      "targets": ["+14155552671"]})
        kinds = []
        dossier = None
        for _ in range(500):
            m = ws.receive_json()
            kinds.append(m["type"])
            if m["type"] == "entity":
                # entity envelope must NOT collide with the entity's own type
                assert "entity" in m and m["entity"]["type"] != "entity"
            if m["type"] == "dossier":
                dossier = m["dossier"]
                break
        assert "entity" in kinds          # phone metadata produced a finding
        assert dossier is not None
        assert "remediation" in dossier   # self mode attaches remediation


def test_config_file_is_owner_only_and_logs_redacted(tmp_path, monkeypatch):
    import stat as _stat

    from unisint import config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cfgmod, "HOME", tmp_path)
    monkeypatch.setattr(cfgmod, "TOOLS_DIR", tmp_path / "tools")
    monkeypatch.setattr(cfgmod, "CASES_DIR", tmp_path / "cases")
    c = cfgmod.load()
    c["api_keys"]["brave"] = "SUPERSECRETKEY"
    cfgmod.save(c)
    mode = _stat.S_IMODE((tmp_path / "config.json").stat().st_mode)
    assert mode == 0o600
    assert cfgmod.redact("GET ?key=SUPERSECRETKEY failed", c) == "GET ?key=*** failed"


def test_plan_endpoint_shapes_per_input():
    c = TestClient(app)
    r = c.post("/api/plan", json={"targets": ["example.com"], "mode": "recon", "preset": "deep"})
    d = r.json()
    assert d["mode"] == "recon" and d["targets"][0]["type"] == "domain"
    names = {m["name"]: m for m in d["targets"][0]["modules"]}
    assert names["httpfp"]["active"] is True
    assert "example.com" in d["authorized"]
    assert sum(d["counts"].values()) == len(d["targets"][0]["modules"])


def test_rerun_source_unknown_module():
    r = client.post("/api/rerun-source", json={"module": "nope", "targets": ["+14155552671"]})
    assert r.status_code == 400 and "unknown module" in r.json()["error"]


def test_rerun_source_runs_one_offline_module():
    # phone_info is pure-offline: a re-run against the original seed must
    # produce its findings and a well-formed source-run status, nothing else.
    r = client.post("/api/rerun-source",
                    json={"module": "phone_info", "mode": "self",
                          "targets": ["+14155552671"]})
    d = r.json()
    assert d["module"] == "phone_info"
    assert d["status"]["state"] in ("ok", "empty")
    assert d["status"]["findings"] >= 1          # offline parser still finds
    # Only the one module's entities come back; seeds are excluded.
    assert all(e["source"] != "input" for e in d["entities"])
    assert any(e["source"] == "phone_info" for e in d["entities"])
