"""Adapters for email/phone registration checkers: holehe, ignorant."""
from __future__ import annotations

import csv

from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType
from ..runner import run, tmp_dir, which


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
        email = ctx.entity.value
        work = tmp_dir(f"holehe-{email}")
        # Clear any stale csv so we glob the fresh one.
        for old in work.glob("holehe_*_results.csv"):
            old.unlink(missing_ok=True)
        bin_ = which("holehe")
        code, so, se = await run(
            [bin_, email, "--only-used", "--no-color", "--no-clear", "-C"],
            timeout=180, cwd=str(work),
        )
        files = sorted(work.glob("holehe_*_results.csv"))
        if not files:
            # holehe prints hits to stdout even without csv; parse the [+] lines
            hits = [l for l in so.splitlines() if l.strip().startswith("[+]")]
            for line in hits:
                dom = line.replace("[+]", "").strip().split()[0]
                ctx.add_entity(EntityType.ACCOUNT, f"https://{dom}",
                               source=self.name, confidence=0.75,
                               rel="registered_on", meta={"site": dom})
            ctx.log(f"holehe: {len(hits)} registrations")
            return
        hits = 0
        with files[-1].open() as fh:
            for row in csv.DictReader(fh):
                if str(row.get("exists", "")).lower() == "true":
                    hits += 1
                    dom = row.get("domain", "")
                    meta = {"site": dom}
                    if row.get("emailrecovery"):
                        meta["recovery_hint"] = row["emailrecovery"]
                    if row.get("phoneNumber"):
                        meta["phone_hint"] = row["phoneNumber"]
                    ctx.add_entity(EntityType.ACCOUNT, f"https://{dom}",
                                   source=self.name, confidence=0.8,
                                   rel="registered_on", meta=meta)
        ctx.log(f"holehe: {hits} registrations")


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

        raw = ctx.entity.value
        try:
            num = phonenumbers.parse(raw, None)
        except phonenumbers.NumberParseException:
            ctx.log("ignorant: need +country-code number", level="warn")
            return
        cc = str(num.country_code)
        national = str(num.national_number)
        bin_ = which("ignorant")
        code, so, se = await run(
            [bin_, cc, national, "--no-color", "--no-clear"],
            timeout=150,
        )
        hits = [l for l in so.splitlines() if l.strip().startswith("[+]")]
        for line in hits:
            dom = line.replace("[+]", "").strip().split()[0]
            ctx.add_entity(EntityType.ACCOUNT, f"https://{dom}",
                           source=self.name, confidence=0.7,
                           rel="registered_on", meta={"site": dom})
        ctx.log(f"ignorant: {len(hits)} registrations")
