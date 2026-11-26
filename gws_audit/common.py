"""Helpers shared by the area modules."""
from __future__ import annotations

import datetime as dt

from .api import ApiError
from .models import WARN, ERROR, make


def guarded(check_id, perspective, area, title, fn, log=lambda m: None, need=""):
    """Run fn() -> list[Result]; turn API/permission failures into a clear finding instead of crashing the scan."""
    try:
        return fn()
    except ApiError as e:
        log(f"[{perspective}/{area}] {title}: {e}")
        if e.denied:
            hint = " The API may not be enabled in your Google Cloud project, or the account is not an administrator." \
                if "not been used" in e.message or "disabled" in e.message.lower() or e.reason in ("accessNotConfigured", "SERVICE_DISABLED") else ""
            return [make(check_id, perspective, area, title, WARN, "access denied for this account", "readable",
                         f"Not checked: access denied" + (f" ({need})" if need else "") + "." + hint + " Grant the scope / admin role or use another account.")]
        return [make(check_id, perspective, area, title, ERROR, f"{e.status} {e.reason}", "", e.message[:160])]
    except Exception as e:
        log(f"[{perspective}/{area}] {title}: {type(e).__name__}: {e}")
        return [make(check_id, perspective, area, title, ERROR, f"{type(e).__name__}: {str(e)[:120]}", "")]


def parse_time(s):
    """RFC 3339 -> aware datetime (None when missing or the Unix-epoch 'never' sentinel)."""
    if not s:
        return None
    try:
        t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return None if t.year <= 1970 else t


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
