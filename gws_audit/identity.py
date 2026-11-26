"""Identity and access (Admin console > Directory): admins, 2-step verification, dormant accounts, third-party app grants."""
from __future__ import annotations

import datetime as dt

from .api import ApiError
from .common import guarded, parse_time
from .models import PASS, FAIL, WARN, INFO, ADMIN, make, short

AREA = "Identity"
USERS = "https://admin.googleapis.com/admin/directory/v1/users"
A = "https://www.googleapis.com/auth/"
RISKY_SCOPES = {"https://mail.google.com/": "full Gmail access", A + "gmail.modify": "read/modify Gmail", A + "drive": "full Drive access",
                A + "admin.directory.user": "manage users", A + "admin.directory.group": "manage groups", A + "cloud-platform": "Google Cloud"}


def fetch_users(api, limit=5000):
    return api.get_all(USERS, "users", {"customer": "my_customer", "maxResults": 500, "projection": "basic"}, limit)


def evaluate_users(users, now=None, inactive_days=90):
    now = now or dt.datetime.now(dt.timezone.utc)
    active = [u for u in users if not u.get("suspended") and not u.get("archived")]
    admins = [u for u in active if u.get("isAdmin")]
    out = []
    n = len(admins)
    out.append(make("GWS-A01", ADMIN, AREA, "Two to four super administrators", PASS if 2 <= n <= 4 else (FAIL if n > 5 else WARN),
                    f"{n} super admins: " + short([a["primaryEmail"] for a in admins]), "2 to 4",
                    "Keep at least two (one is a single point of failure) and no more than four super admins; use delegated admin roles for everything else.",
                    reference="CIS: super administrator accounts"))
    no2sv = [a["primaryEmail"] for a in admins if not a.get("isEnrolledIn2Sv")]
    out.append(make("GWS-A02", ADMIN, AREA, "Every super admin is enrolled in 2-step verification", FAIL if no2sv else PASS,
                    short(no2sv) if no2sv else "all enrolled", "all enrolled", "Enrol these admins in 2SV (security keys preferred) immediately.",
                    reference="CIS: 2SV for admins"))
    noenf = [a["primaryEmail"] for a in admins if not a.get("isEnforcedIn2Sv")]
    out.append(make("GWS-A03", ADMIN, AREA, "2-step verification is enforced for super admins", FAIL if noenf else PASS,
                    short(noenf) if noenf else "enforced", "enforced", "Admin console > Security > Authentication > 2-step verification: enforce for the admin OU.",
                    reference="CIS: enforce 2SV"))
    total = len(active)
    enrolled = sum(1 for u in active if u.get("isEnrolledIn2Sv"))
    enforced = sum(1 for u in active if u.get("isEnforcedIn2Sv"))
    pct = round(100 * enrolled / total) if total else 100
    out.append(make("GWS-A04", ADMIN, AREA, "All active users are enrolled in 2-step verification", PASS if pct == 100 else (WARN if pct >= 90 else FAIL),
                    f"{enrolled} of {total} enrolled ({pct}%)", "100%", "Enrol the remaining users and enforce 2SV for the whole organisation.",
                    reference="CIS: 2SV for all users"))
    out.append(make("GWS-A05", ADMIN, AREA, "2-step verification is enforced organisation-wide", PASS if total and enforced == total else WARN,
                    f"{enforced} of {total} enforced", "all users", "Admin console > Security > 2-step verification: turn on Enforcement for all organisational units.",
                    reference="CIS: enforce 2SV"))
    cutoff = now - dt.timedelta(days=inactive_days)
    dormant = []
    for u in active:
        last, created = parse_time(u.get("lastLoginTime")), parse_time(u.get("creationTime"))
        if (last is None and created is not None and created < cutoff) or (last is not None and last < cutoff):
            dormant.append(u["primaryEmail"])
    out.append(make("GWS-A06", ADMIN, AREA, f"No accounts inactive for more than {inactive_days} days", WARN if dormant else PASS,
                    f"{len(dormant)}: " + short(dormant) if dormant else "none", "0", "Suspend or delete unused accounts (and reclaim licences).",
                    reference="Best practice: dormant accounts"))
    return out


def fetch_tokens(api, users, cap=100, log=lambda m: None):
    grants = {}
    for u in [x for x in users if not x.get("suspended")][:cap]:
        try:
            grants[u["primaryEmail"]] = api.get_all(f"{USERS}/{u['primaryEmail']}/tokens", "items")
        except ApiError as e:
            if e.denied:
                raise
            log(f"tokens for {u['primaryEmail']}: {e}")
    return grants


def evaluate_tokens(grants):
    apps = {}
    for email, toks in grants.items():
        for t in toks:
            a = apps.setdefault(t.get("clientId"), {"name": t.get("displayText") or t.get("clientId"), "users": set(), "risky": set()})
            a["users"].add(email)
            a["risky"] |= {RISKY_SCOPES[s] for s in (t.get("scopes") or []) if s in RISKY_SCOPES}
    risky = [f"{a['name']} ({', '.join(sorted(a['risky']))}; {len(a['users'])} users)" for a in apps.values() if a["risky"]]
    return [make("GWS-A10", ADMIN, AREA, "Third-party apps with broad access reviewed", WARN if risky else PASS,
                 short(risky) if risky else "none with broad scopes", "only trusted apps",
                 "Admin console > Security > API controls: restrict or block high-risk scopes and review each app's access.",
                 reference="CIS: API controls / third-party apps"),
            make("GWS-A11", ADMIN, AREA, "Third-party app inventory", INFO, f"{len(apps)} apps across {len(grants)} sampled users", "",
                 "", reference="Best practice: app inventory")]


def admin_checks(api, log=lambda m: None, include_tokens=False, max_users=5000, token_sample=100):
    users = []

    def users_part():
        users.extend(fetch_users(api, max_users))
        return evaluate_users(users)
    out = guarded("GWS-A01", ADMIN, AREA, "Users and administrators", users_part, log, "admin.directory.user.readonly")
    if include_tokens and users:
        out += guarded("GWS-A10", ADMIN, AREA, "Third-party app grants", lambda: evaluate_tokens(fetch_tokens(api, users, token_sample, log)), log,
                       "admin.directory.user.security")
    return out
