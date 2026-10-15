"""Auto-detect the type of a raw input string so the user never has to pick."""
from __future__ import annotations

import ipaddress
import re

from .models import EntityType

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().\-]{6,}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_URL_RE = re.compile(r"^https?://", re.I)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")


def detect(raw: str) -> EntityType:
    """Best-effort classification of a single free-form input."""
    s = raw.strip()
    if not s:
        return EntityType.USERNAME

    if _URL_RE.match(s):
        return EntityType.URL
    if _EMAIL_RE.match(s):
        return EntityType.EMAIL

    # IP (v4/v6)
    try:
        ipaddress.ip_address(s)
        return EntityType.IP
    except ValueError:
        pass

    # Phone: mostly digits with phone punctuation, and enough digits
    digits = re.sub(r"\D", "", s)
    if _PHONE_RE.match(s) and 7 <= len(digits) <= 15:
        return EntityType.PHONE

    if _DOMAIN_RE.match(s):
        return EntityType.DOMAIN

    # A name has a space and alphabetic words
    if " " in s and all(p.isalpha() for p in s.split()):
        return EntityType.FULL_NAME

    if _USERNAME_RE.match(s):
        return EntityType.USERNAME

    return EntityType.USERNAME
