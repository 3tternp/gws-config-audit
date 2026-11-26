"""Scan orchestration: administrator and/or employee perspective across the selected areas."""
from __future__ import annotations

from dataclasses import dataclass

from . import identity, groups_devices, domains_logs, policy, user_checks
from .models import AREAS, ADMIN, USER


@dataclass
class ScanOptions:
    areas: tuple = AREAS
    include_tokens: bool = False     # third-party app grants (needs the admin.directory.user.security scope)
    max_users: int = 5000
    token_sample: int = 100
    max_groups: int = 200


def scan_admin(api, opts, log, lookup=None):
    areas, out = set(opts.areas), []
    if "Identity" in areas:
        log("[Admin] Users, administrators, 2-step verification")
        out += identity.admin_checks(api, log, opts.include_tokens, opts.max_users, opts.token_sample)
    if areas & {"Identity", "Gmail", "Drive"}:
        log("[Admin] Admin-console settings (Policy API)")
        out += policy.policy_checks(api, log, areas)
    if "Groups" in areas:
        log("[Admin] Groups")
        out += groups_devices.groups_checks(api, log, opts.max_groups)
    if "Devices" in areas:
        log("[Admin] Mobile devices")
        out += groups_devices.devices_checks(api, log)
    if "Domains" in areas:
        log("[Admin] Email authentication (SPF / DKIM / DMARC)")
        out += domains_logs.domain_checks(api, log, lookup)
    if "Logs" in areas:
        log("[Admin] Sign-in events")
        out += domains_logs.log_checks(api, log)
    return out


def run_scan(admin_api=None, user_api=None, opts=None, log=lambda m: None, meta=None, user_domain="", lookup=None):
    opts = opts or ScanOptions()
    if admin_api is None and user_api is None:
        raise ValueError("Sign in as an administrator, an employee, or both before scanning.")
    results = []
    if admin_api is not None:
        results += scan_admin(admin_api, opts, log, lookup)
    if user_api is not None:
        log("[User] Gmail and Drive")
        results += user_checks.user_checks(user_api, user_domain, set(opts.areas), log)
    meta = dict(meta or {})
    meta["perspectives"] = ", ".join(p for p, a in ((ADMIN, admin_api), (USER, user_api)) if a is not None)
    log(f"Scan complete: {len(results)} checks ({meta['perspectives']})")
    return results, meta
