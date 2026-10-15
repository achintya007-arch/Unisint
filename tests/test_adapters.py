"""Adapter parsers against realistic captured output, arg safety, discovery."""
import json
import stat

import pytest

from unisint import runner
from unisint.adapters.contact_tools import parse_holehe_csv, parse_plus_lines
from unisint.adapters.recon_tools import (parse_amass, parse_harvester_json,
                                          parse_subfinder)
from unisint.adapters.username_tools import (parse_maigret_report,
                                             parse_sherlock_csv,
                                             parse_socialscan_json)
from unisint.runner import UnsafeArgument, safe_arg


def test_sherlock_csv_claimed_only_and_url_normalised():
    text = ("username,name,url_main,url_user,exists,http_status,response_time_s\n"
            "u,GitHub,https://github.com,https://github.com/u?utm_source=x,Claimed,200,0.2\n"
            "u,Nope,https://n.com,https://n.com/u,Available,404,0.1\n"
            "u,Broken,https://b.com,not a url,Claimed,200,0.1\n")
    assert parse_sherlock_csv(text) == [{"site": "GitHub", "url": "https://github.com/u"}]


def test_maigret_report_parsing_keeps_ids():
    data = {
        "GitHubGist": {"url_user": "https://gist.github.com/u",
                       "status": {"status": "Claimed", "tags": ["coding"],
                                  "ids": {"fullname": "U Ser", "image": ""}}},
        "X": {"url_user": "https://x.com/u", "status": {"status": "Available"}},
        "weird": "not-a-dict",
    }
    out = parse_maigret_report(data)
    assert len(out) == 1 and out[0]["url"] == "https://gist.github.com/u"
    assert out[0]["ids"] == {"fullname": "U Ser"}


def test_socialscan_never_invents_urls():
    data = {"u": [
        {"platform": "GitHub", "available": "False", "success": "True",
         "link": "https://github.com/u"},
        {"platform": "Instagram", "available": "False", "success": "True"},
        {"platform": "Reddit", "available": "True", "success": "True"},
        {"platform": "Tumblr", "available": "False", "success": "False"},
    ]}
    rows = parse_socialscan_json(data)
    assert [(r["platform"], r["url"]) for r in rows] == [
        ("GitHub", "https://github.com/u"), ("Instagram", None)]


def test_holehe_csv_separates_rate_limited():
    text = ("name,domain,rateLimit,exists,emailrecovery,phoneNumber,others\n"
            "github,github.com,False,True,None,None,None\n"
            "insta,instagram.com,True,False,None,None,None\n"
            "x,twitter.com,False,False,None,None,None\n"
            "bad,not a domain,False,True,None,None,None\n")
    r = parse_holehe_csv(text)
    assert r["used"] == [{"domain": "github.com"}]
    assert r["rate_limited"] == ["instagram.com"]


def test_plus_lines_strip_ansi():
    out = "\x1b[32m[+] spotify.com\x1b[0m\n[-] x.com\n[x] y.com\n[+] amazon.com / FullName A\n"
    assert parse_plus_lines(out) == ["spotify.com", "amazon.com"]


def test_subfinder_json_and_plain_and_filtering():
    text = "\n".join([
        json.dumps({"host": "api.corp.com", "source": "crtsh"}),
        json.dumps({"host": "api.corp.com", "source": "alienvault"}),
        "www.corp.com",
        json.dumps({"host": "evilcorp.com", "source": "x"}),   # not in domain
        "{broken json",
    ])
    assert parse_subfinder(text, "corp.com") == [
        {"host": "api.corp.com", "sources": ["alienvault", "crtsh"]},
        {"host": "www.corp.com", "sources": []}]


def test_amass_v4_graph_lines():
    text = ("www.corp.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)\n"
            "corp.com (FQDN) --> mx_record --> aspmx.l.google.com (FQDN)\n"
            "mail.corp.com (FQDN) --> cname_record --> x.notcorp.com (FQDN)\n"
            "dev.corp.com\n")
    assert parse_amass(text, "corp.com") == [
        "corp.com", "dev.corp.com", "mail.corp.com", "www.corp.com"]


def test_harvester_json_filters():
    data = {"emails": ["Admin@Corp.com", "bad"],
            "hosts": ["www.corp.com:93.184.216.34", "cdn.other.net"], "ips": ["1.2.3.4"]}
    r = parse_harvester_json(data, "corp.com")
    assert r["emails"] == ["admin@corp.com"] and r["hosts"] == ["www.corp.com"]


@pytest.mark.parametrize("v,k", [("-rf", "username"), ("--help", "domain"),
                                 ("a b", "username"), ("x;rm -rf /", "domain"),
                                 ("$(id)", "username"), ("12a", "digits"),
                                 ("", "email"), ("u", "nokind")])
def test_safe_arg_rejects(v, k):
    with pytest.raises(UnsafeArgument):
        safe_arg(v, k)


def test_safe_arg_accepts():
    assert safe_arg("ada.lovelace", "username") == "ada.lovelace"
    assert safe_arg("sub.corp.co.uk", "domain") == "sub.corp.co.uk"
    assert safe_arg("a+b@corp.com", "email") == "a+b@corp.com"


def test_which_finds_theharvester_source_venv(tmp_path, monkeypatch):
    venv_bin = tmp_path / "theHarvester-src" / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    exe = venv_bin / "theHarvester"
    exe.write_text("#!/bin/sh\necho ok\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setitem(runner.SOURCE_VENVS, "theHarvester", venv_bin)
    monkeypatch.setenv("PATH", "/nonexistent")
    assert runner.which("theHarvester") == str(exe)


def test_which_env_override(tmp_path, monkeypatch):
    exe = tmp_path / "subfinder"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("UNISINT_TOOL_PATHS", str(tmp_path))
    assert runner.which("subfinder") == str(exe)
