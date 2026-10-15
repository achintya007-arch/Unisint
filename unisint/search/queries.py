"""Query generation from configurable templates.

A query is *not* a result. Templates are data, so they can be reviewed,
tested and overridden without code changes: drop a JSON list with the same
shape into ``~/.unisint/search_queries.json`` to replace the defaults.

Scope: infrastructure/organisation queries for a domain (RECON and
SELF-AUDIT) and exact-match exposure queries for identifiers the user
entered about themselves (SELF-AUDIT only). Results of identifier queries are
mentions of the term — never treated as evidence about a specific person.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TEMPLATES: list[dict] = [
    # --- domain / organisation (both modes) ---
    {"id": "domain_pages", "types": ["domain"], "modes": ["self", "recon"],
     "template": "site:{value}", "purpose": "pages indexed on the domain"},
    {"id": "domain_docs", "types": ["domain"], "modes": ["self", "recon"],
     "template": "site:{value} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)",
     "purpose": "documents published on the domain (metadata exposure)"},
    {"id": "domain_offsite", "types": ["domain"], "modes": ["self", "recon"],
     "template": "{q_value} -site:{value}", "purpose": "third-party pages mentioning the domain"},
    {"id": "domain_emails", "types": ["domain"], "modes": ["self", "recon"],
     "template": "\"@{value}\"", "purpose": "addresses at the domain published online"},
    # --- self-audit exposure (identifiers you entered about yourself) ---
    {"id": "email_exact", "types": ["email"], "modes": ["self"],
     "template": "{q_value}", "purpose": "where your address is published"},
    {"id": "email_paste", "types": ["email"], "modes": ["self"],
     "template": "{q_value} (site:pastebin.com OR site:ghostbin.com OR site:gist.github.com)",
     "purpose": "your address in public pastes"},
    {"id": "username_exact", "types": ["username"], "modes": ["self"],
     "template": "{q_value}", "purpose": "pages mentioning your handle"},
    {"id": "name_exact", "types": ["full_name"], "modes": ["self"],
     "template": "{q_value}", "purpose": "pages mentioning the name (often other people)"},
]

USER_FILE = "search_queries.json"
_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_ALLOWED_FIELDS = {"value", "q_value"}


@dataclass(frozen=True)
class Query:
    template_id: str
    text: str
    purpose: str
    entity_type: str
    value: str


def quote_term(value: str) -> str:
    """Exact-phrase quote, stripping characters that would break the phrase."""
    v = re.sub(r"[\"\r\n\t]", " ", value).strip()
    return f"\"{' '.join(v.split())}\""


def validate_templates(templates: list[dict]) -> list[dict]:
    good = []
    for t in templates:
        if not isinstance(t, dict) or not t.get("id") or not t.get("template"):
            continue
        fields = set(_PLACEHOLDER.findall(t["template"]))
        if not fields <= _ALLOWED_FIELDS:
            continue  # unknown placeholder: refuse rather than mis-format
        if not isinstance(t.get("types"), list) or not isinstance(t.get("modes"), list):
            continue
        good.append(t)
    return good


def load_templates(home: Path | None = None) -> list[dict]:
    if home is None:
        from ..config import HOME as home  # noqa: N811
    p = Path(home) / USER_FILE
    if p.exists():
        try:
            user = validate_templates(json.loads(p.read_text()))
            if user:
                return user
        except (json.JSONDecodeError, OSError):
            pass
    return validate_templates(DEFAULT_TEMPLATES)


def generate_queries(entity_type: str, value: str, mode: str,
                     templates: list[dict] | None = None,
                     max_queries: int = 4) -> list[Query]:
    value = (value or "").strip()
    if not value:
        return []
    out = []
    for t in templates if templates is not None else load_templates():
        if entity_type in t["types"] and mode in t["modes"]:
            text = t["template"].format(value=value.replace('"', ""),
                                        q_value=quote_term(value))
            out.append(Query(t["id"], text, t.get("purpose", ""), entity_type, value))
        if len(out) >= max_queries:
            break
    return out
