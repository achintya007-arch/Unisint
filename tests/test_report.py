"""Server-rendered exports: same data as the UI, safely escaped."""
import csv
import io
import os
import tempfile

os.environ.setdefault("UNISINT_HOME", tempfile.mkdtemp(prefix="unisint-test-"))

from fastapi.testclient import TestClient  # noqa: E402

from unisint.app import app  # noqa: E402
from unisint.report import render_csv, render_html  # noqa: E402
from unisint.synthesis import build_dossier  # noqa: E402


def E(id, type, value, source="t", basis="observed", parent=None, **meta):
    return {"id": id, "type": type, "value": value, "source": source, "basis": basis,
            "meta": {"sources": [source], **meta},
            "provenance": [{"parent_id": parent, "parent_value": "seed", "rel": "r"}]}


EVIL = [
    E("s", "username", "ada", "input", "seed", identity_link="seed"),
    E("a1", "account", "https://site.example/ada\"><script>alert(1)</script>", "sherlock",
      parent="s", identity_link="handle_match", site="<img src=x onerror=alert(2)>",
      url="https://site.example/ada\"><script>alert(1)</script>"),
    E("a2", "account", "javascript:alert(3)", "x", parent="s",
      identity_link="handle_match", site="JS", url="javascript:alert(3)"),
    E("r1", "url", "https://ok.example/p", "web_search", "candidate", "s",
      kind="search_result", title="=HYPERLINK(\"http://evil\")",
      snippet="<b>bold</b>", providers=["brave"]),
]


def test_html_escapes_untrusted_and_refuses_js_urls():
    html = render_html(build_dossier({"mode": "self", "entities": EVIL}))
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert 'href="javascript' not in html
    assert "&lt;b&gt;bold&lt;/b&gt;" in html


def test_csv_neutralises_formulas_and_matches_dossier_urls():
    d = build_dossier({"mode": "self", "entities": EVIL})
    rows = list(csv.DictReader(io.StringIO(render_csv(d))))
    titles = [r for r in rows if r["section"] == "search_result"]
    assert titles and titles[0]["url"] == d["search_results"][0]["url"]
    for r in rows:
        for v in r.values():
            assert not (isinstance(v, str) and v and v[0] in "=+@")
    acc_urls = {r["url"] for r in rows if r["section"] == "account"}
    assert acc_urls == {a["url"] for a in d["accounts"]}
    assert all(r["validation_state"] == "unchecked" for r in rows if r["section"] == "account")


def test_export_endpoints_roundtrip():
    c = TestClient(app)
    d = c.post("/api/dossier", json={"mode": "self", "entities": EVIL}).json()
    assert d["counts"]["accounts"] == 2
    h = c.post("/api/export/html", json={"dossier": d})
    assert h.status_code == 200 and "UNISINT DOSSIER" in h.text
    assert "<script>alert(1)" not in h.text
    cs = c.post("/api/export/csv", json={"dossier": d})
    assert cs.status_code == 200 and cs.text.startswith("section,type,value")
    assert c.post("/api/export/pdf", json={"dossier": d}).status_code == 400
