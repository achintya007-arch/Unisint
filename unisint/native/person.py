"""Person-level helpers: name -> candidate usernames, and search dorks."""
from __future__ import annotations

import urllib.parse

from ..base import MODE_RECON, MODE_SELF, Context, Module, register
from ..models import EntityType


def permutations(full_name: str) -> list[str]:
    parts = [p for p in full_name.lower().split() if p.isalpha()]
    if not parts:
        return []
    first, last = parts[0], parts[-1]
    cands = {
        first + last, f"{first}.{last}", f"{first}_{last}", f"{first}-{last}",
        first[0] + last, f"{first[0]}.{last}", last + first,
        first + last[0], f"{last}.{first}", first, last,
    }
    if len(parts) >= 3:
        mid = parts[1]
        cands.update({first + mid + last, f"{first}.{mid}.{last}",
                      first[0] + mid[0] + last})
    return sorted(c for c in cands if len(c) >= 3)


@register
class NamePermute(Module):
    name = "name_permute"
    label = "Name->Username"
    category = "person"
    accepts = {EntityType.FULL_NAME}
    modes = {MODE_SELF}            # only pivot a person in self-audit mode
    weight = 1

    async def run(self, ctx: Context) -> None:
        cands = permutations(ctx.entity.value)[:12]
        ctx.log(f"generated {len(cands)} candidate usernames")
        for c in cands:
            ctx.add_entity(EntityType.USERNAME, c, source=self.name,
                           confidence=0.35, rel="possible_username")


DORKS = {
    EntityType.EMAIL: [
        ('Google', 'https://www.google.com/search?q="{q}"'),
        ('DuckDuckGo', 'https://duckduckgo.com/?q=%22{q}%22'),
        ('Pastebin', 'https://www.google.com/search?q=site:pastebin.com+"{q}"'),
    ],
    EntityType.USERNAME: [
        ('Google', 'https://www.google.com/search?q="{q}"'),
        ('Docs', 'https://www.google.com/search?q="{q}"+filetype:pdf'),
    ],
    EntityType.FULL_NAME: [
        ('Google', 'https://www.google.com/search?q="{q}"'),
        ('LinkedIn', 'https://www.google.com/search?q=site:linkedin.com+"{q}"'),
        ('CV', 'https://www.google.com/search?q="{q}"+(resume+OR+cv)+filetype:pdf'),
    ],
    EntityType.DOMAIN: [
        ('Google site', 'https://www.google.com/search?q=site:{q}'),
        ('Files', 'https://www.google.com/search?q=site:{q}+(filetype:pdf+OR+filetype:xlsx)'),
    ],
}


@register
class Dorks(Module):
    name = "dorks"
    label = "Search Dorks"
    category = "person"
    accepts = {EntityType.EMAIL, EntityType.USERNAME,
               EntityType.FULL_NAME, EntityType.DOMAIN}
    modes = {MODE_SELF, MODE_RECON}
    weight = 1

    async def run(self, ctx: Context) -> None:
        tmpl = DORKS.get(ctx.entity.type, [])
        q = urllib.parse.quote(ctx.entity.value)
        links = [{"name": n, "url": u.format(q=q)} for n, u in tmpl]
        if links:
            ctx.finding(f"{len(links)} search dork links",
                        source=self.name, meta={"links": links},
                        confidence=0.4)
