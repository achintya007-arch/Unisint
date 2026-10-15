"""Adapters for registration checkers: holehe (email) and ignorant (phone).

These tools answer "is this email/phone registered on site X?". They do not
return a profile URL, so the result is recorded as a *registration finding*
for the site's domain — never as an account link (the old ``https://{domain}``
links pointed at home pages, not accounts). Rate-limited checks are reported
as unknown, not as "not registered".
"""
from __future__ import annotations

import csv
import io
import re

from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType
from ..runner import UnsafeArgument, run, safe_arg, tmp_dir, which

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.I)


def parse_holehe_csv(text: str) -> dict:
    used, limited = [], []
    for row in csv.DictReader(io.StringIO(text)):
        dom = (row.get("domain") or "").strip()
        if not _DOMAIN.match(dom):
            continue
        if str(row.get("rateLimit", "")).lower() == "true":
            limited.append(dom)
        elif str(row.get("exists", "")).lower() == "true":
            hints = {k: row[k] for k in ("emailrecovery", "phoneNumber")
                     if row.get(k) not in (None, "", "None")}
            used.append({"domain": dom, **hints})
    return {"used": used, "rate_limited": limited}


def parse_plus_lines(text: str) -> list[str]:
    """`[+] domain ...` lines from holehe/ignorant stdout → domains."""
    out = []
    for line in _ANSI.sub("", text or "").splitlines():
        line = line.strip()
        if line.startswith("[+]"):
            tok = line[3:].strip().split()
            if tok and _DOMAIN.match(tok[0]):
                out.append(tok[0].lower())
    return out


def _record(ctx: Context, source: str, domains: list[dict]) -> None:
    for d in domains:
        meta = {"kind": "registration", "domain": d["domain"]}
        if d.get("emailrecovery"):
            meta["recovery_hint"] = d["emailrecovery"]
        if d.get("phoneNumber"):
            meta["phone_hint"] = d["phoneNumber"]
        ctx.finding(f"registered on {d['domain']}", source=source, meta=meta)


@register
class Holehe(Module):
    name = "holehe"
    label = "holehe"
    category = "email"
    accepts = {EntityType.EMAIL}
    modes = {MODE_SELF}
    requires_tool = "holehe"
    weight = 2

    async def run(self, ctx: Context) -> None:
        try:
            email = safe_arg(ctx.entity.value, "email")
        except UnsafeArgument as exc:
            ctx.log(str(exc), level="warn")
            return
        work = tmp_dir("holehe-run")
        for old in work.glob("holehe_*_results.csv"):
            old.unlink(missing_ok=True)
        # -NP: skip modules that trigger password-recovery flows on sites.
        code, so, se = await run(
            [which("holehe"), "--no-color", "--no-clear", "-NP", "-C", "--", email],
            timeout=240, cwd=str(work))
        files = sorted(work.glob("holehe_*_results.csv"))
        if files:
            res = parse_holehe_csv(files[-1].read_text(errors="replace"))
        else:
            used = parse_plus_lines(so)
            if not used and code != 0:
                raise RuntimeError(f"holehe exit {code}: {(se or so).strip()[-160:]}")
            res = {"used": [{"domain": d} for d in used], "rate_limited": []}
        _record(ctx, self.name, res["used"])
        if res["rate_limited"]:
            ctx.finding(f"{len(res['rate_limited'])} site(s) rate-limited — "
                        "registration unknown", source=self.name, basis="derived",
                        meta={"kind": "unknown", "domains": res["rate_limited"]})
        ctx.log(f"holehe: registered on {len(res['used'])}, "
                f"unknown {len(res['rate_limited'])}")


@register
class Ignorant(Module):
    name = "ignorant"
    label = "ignorant"
    category = "phone"
    accepts = {EntityType.PHONE}
    modes = {MODE_SELF}
    requires_tool = "ignorant"
    weight = 2

    async def run(self, ctx: Context) -> None:
        import phonenumbers

        try:
            num = phonenumbers.parse(ctx.entity.value, None)
        except phonenumbers.NumberParseException:
            ctx.log("ignorant: need a +country-code number", level="warn")
            return
        cc = safe_arg(str(num.country_code), "digits")
        national = safe_arg(str(num.national_number), "digits")
        code, so, se = await run(
            [which("ignorant"), "--no-color", "--no-clear", "--", cc, national],
            timeout=180)
        used = parse_plus_lines(so)
        if not used and code != 0:
            raise RuntimeError(f"ignorant exit {code}: {(se or so).strip()[-160:]}")
        _record(ctx, self.name, [{"domain": d} for d in used])
        ctx.log(f"ignorant: registered on {len(used)}")
