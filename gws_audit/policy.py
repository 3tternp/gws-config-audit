"""Admin-console settings via the Cloud Identity Policy API, evaluated against an editable, data-driven baseline."""
from __future__ import annotations

import json
from pathlib import Path

from .api import ApiError
from .common import guarded
from .models import PASS, FAIL, MANUAL, ADMIN, make

POLICIES = "https://cloudidentity.googleapis.com/v1/policies"
SPEC_FILE = Path(__file__).resolve().parent / "data" / "policies.json"


def load_specs(path=SPEC_FILE):
    return json.loads(Path(path).read_text(encoding="utf-8")).get("specs", [])


def fetch_policies(api):
    try:
        return api.get_all(POLICIES, "policies", {"pageSize": 100}, 5000)
    except ApiError as e:
        if e.status != 400:
            raise
        return api.get_all(POLICIES, "policies", {"pageSize": 100, "filter": 'customer == "customers/my_customer"'}, 5000)


def index_policies(policies):
    """setting type -> list of value dicts (system defaults and admin overrides alike)."""
    idx = {}
    for p in policies:
        s = p.get("setting") or {}
        if s.get("type"):
            idx.setdefault(s["type"], []).append(s.get("value") or {})
    return idx


def _dig(value, path):
    cur = value
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True


def _seconds(v):
    try:
        return float(str(v).rstrip("s"))
    except ValueError:
        return None


def _ok(op, actual, expected):
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "ge":
        return isinstance(actual, (int, float)) and actual >= expected
    if op == "le":
        return isinstance(actual, (int, float)) and actual <= expected
    if op == "duration_le":
        s = _seconds(actual)
        return s is not None and s <= expected
    raise ValueError(op)


def evaluate_policies(policies, specs, areas=None):
    idx = index_policies(policies)
    out = []
    for sp in specs:
        if areas and sp["area"] not in areas:
            continue
        values = idx.get(sp["type"])
        if not values:
            out.append(make(sp["id"], ADMIN, sp["area"], sp["title"], MANUAL, "setting not returned by the Policy API", "reviewed", sp["fix"], reference=sp.get("ref", "")))
            continue
        found = [_dig(v, sp["path"]) for v in values]
        known = [a for a, ok in found if ok]
        if not known:
            out.append(make(sp["id"], ADMIN, sp["area"], sp["title"], MANUAL, f"field '{sp['path']}' not found; raw: {json.dumps(values[0])[:140]}", "reviewed",
                            sp["fix"], reference=sp.get("ref", "")))
            continue
        bad = [a for a in known if not _ok(sp["op"], a, sp["value"])]
        note = f" ({len(known)} policy values, incl. OU overrides)" if len(known) > 1 else ""
        out.append(make(sp["id"], ADMIN, sp["area"], sp["title"], FAIL if bad else PASS, f"{bad[0] if bad else known[0]}{note}", f"{sp['op']} {sp['value']}",
                        sp["fix"], reference=sp.get("ref", "")))
    return out


def policy_checks(api, log=lambda m: None, areas=None, specs=None):
    return guarded("GWS-G00", ADMIN, "Identity", "Admin-console settings (Policy API)",
                   lambda: evaluate_policies(fetch_policies(api), specs or load_specs(), areas), log, "cloud-identity.policies.readonly + Cloud Identity API enabled")
