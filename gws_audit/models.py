"""Shared result model."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

PASS, FAIL, WARN, MANUAL, ERROR, INFO = "PASS", "FAIL", "WARN", "MANUAL", "ERROR", "INFO"
STATUSES = (FAIL, WARN, ERROR, MANUAL, INFO, PASS)
ADMIN, USER = "Admin", "User"
AREAS = ("Identity", "Gmail", "Drive", "Groups", "Devices", "Domains", "Logs")


@dataclass
class Result:
    check_id: str
    perspective: str      # "Admin" (Admin console / Admin SDK) or "User" (a normal employee's own account)
    area: str
    title: str
    status: str
    actual: Any = ""
    expected: Any = ""
    remediation: str = ""
    target: str = ""
    reference: str = ""   # benchmark theme / setting name

    def to_dict(self):
        d = asdict(self)
        d["actual"], d["expected"] = str(d["actual"]), str(d["expected"])
        return d


def make(check_id, perspective, area, title, status, actual="", expected="", remediation="", target="", reference=""):
    return Result(check_id, perspective, area, title, status, actual, expected, "" if status == PASS else remediation, target, reference)


def short(items, limit=10):
    items = [str(i) for i in items]
    if len(items) <= limit:
        return "; ".join(items)
    return "; ".join(items[:limit]) + f" ... (+{len(items) - limit} more, total {len(items)})"
