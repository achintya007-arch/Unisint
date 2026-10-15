"""Unit tests: detection, name permutation, phone, synthesis, parsers."""
import asyncio
import csv
import json

import pytest

from unisint import base
from unisint.detect import detect
from unisint.models import Entity, EntityType
from unisint.native.person import permutations
from unisint.synthesis import build_dossier

base.load_all()


def test_detect():
    assert detect("torvalds") == EntityType.USERNAME
    assert detect("a.b@example.com") == EntityType.EMAIL
    assert detect("+1 415 555 2671") == EntityType.PHONE
    assert detect("example.com") == EntityType.DOMAIN
    assert detect("8.8.8.8") == EntityType.IP
    assert detect("2001:4860:4860::8888") == EntityType.IP
    assert detect("Ada Lovelace") == EntityType.FULL_NAME
    assert detect("https://x.com/y") == EntityType.URL


def test_permutations():
    p = permutations("John Michael Doe")
    assert "johndoe" in p
    assert "jdoe" in p
    assert "john.doe" in p
    assert all(len(x) >= 3 for x in p)
    assert permutations("") == []


def test_registry_has_core_modules():
    names = {m.name for m in base.all_modules()}
    for expected in ("sherlock", "maigret", "holehe", "dns", "github",
                     "crtsh", "internetdb", "phone_info", "exif"):
        assert expected in names


def test_modules_for_mode_filtering():
    # name_permute must only run in self-audit mode.
    self_mods = {m.name for m in base.modules_for(EntityType.FULL_NAME, base.MODE_SELF)}
    recon_mods = {m.name for m in base.modules_for(EntityType.FULL_NAME, base.MODE_RECON)}
    assert "name_permute" in self_mods
    assert "name_permute" not in recon_mods


def test_phone_module():
    ent = Entity(type=EntityType.PHONE, value="+14155552671", source="t")
    from unisint.native.phone import PhoneInfo

    captured = {}

    class FakeCtx:
        entity = ent

        def log(self, *a, **k):
            pass

        def finding(self, text, *, source, meta=None, **kw):
            captured["basis"] = kw.get("basis")
            captured["text"] = text
            captured["meta"] = meta

        def add_entity(self, *a, **k):
            pass

    asyncio.run(PhoneInfo().run(FakeCtx()))
    assert captured["meta"]["e164"] == "+14155552671"
    assert captured["meta"]["valid"] is True
    assert captured["basis"] == "derived"  # computed, not observed


def test_sherlock_csv_parsing(tmp_path):
    csv_path = tmp_path / "u.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["username", "name", "url_main", "url_user", "exists",
                    "http_status", "response_time_s"])
        w.writerow(["u", "GitHub", "https://github.com",
                    "https://github.com/u", "true", "200", "0.3"])
        w.writerow(["u", "Nope", "https://nope.com",
                    "https://nope.com/u", "false", "404", "0.2"])
    hits = []
    with csv_path.open() as fh:
        for row in csv.DictReader(fh):
            if str(row["exists"]).lower() in ("true", "claimed"):
                hits.append(row["url_user"])
    assert hits == ["https://github.com/u"]


def test_maigret_json_parsing():
    data = {
        "GitHub": {"status": {"status": "Claimed"},
                   "url_user": "https://github.com/u"},
        "Nope": {"status": {"status": "Available"},
                 "url_user": "https://nope/u"},
    }
    claimed = [v["url_user"] for v in data.values()
               if v["status"]["status"] == "Claimed"]
    assert claimed == ["https://github.com/u"]


def test_synthesis_dossier():
    snap = {
        "mode": "self",
        "entities": [
            {"type": "account", "value": "https://github.com/u", "source": "github",
             "confidence": 0.9, "meta": {"site": "GitHub", "url": "https://github.com/u", "sources": ["github"]}},
            {"type": "email", "value": "u@x.com", "source": "github",
             "confidence": 0.8, "meta": {"note": "exposed in public commits"}},
            {"type": "metadata", "value": "CVE: CVE-2021-1", "source": "internetdb",
             "confidence": 0.7, "meta": {"cve": "CVE-2021-1"}},
        ],
        "links": [],
    }
    d = build_dossier(snap)
    assert d["exposure_count"] == 1
    assert "u@x.com" in d["emails"]
    assert any("commit" in r for r in d["risk_flags"])
    assert any("CVE" in r for r in d["risk_flags"])
