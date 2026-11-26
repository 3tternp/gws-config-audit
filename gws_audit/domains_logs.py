"""Email authentication DNS (SPF / DKIM / DMARC) per domain, and sign-in security events from the Reports API."""
from __future__ import annotations

import datetime as dt
import re

from .common import guarded
from .models import PASS, FAIL, WARN, INFO, ADMIN, make, short

DOMAINS = "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains"
REPORTS = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}"
DKIM_SELECTOR = "google"          # Workspace default; change if you generated a different selector


def default_lookup(name, rtype="TXT"):
    import dns.resolver
    return ["".join(s.decode() for s in r.strings) for r in dns.resolver.resolve(name, rtype, lifetime=6)]


def evaluate_domain(domain, lookup=default_lookup, selector=DKIM_SELECTOR):
    area = "Domains"

    def txt(name):
        try:
            return lookup(name, "TXT")
        except Exception:
            return []
    out = []
    spf = next((r for r in txt(domain) if r.lower().startswith("v=spf1")), None)
    if not spf:
        out.append(make("GWS-A30", ADMIN, area, "SPF record published", FAIL, "no SPF record", "v=spf1 include:_spf.google.com -all",
                        f"Publish 'v=spf1 include:_spf.google.com ~all' (then -all) for {domain}.", domain, "CIS: SPF"))
    else:
        m = re.search(r"([-~?+])all\b", spf)
        mech = m.group(1) if m else ""
        google = "_spf.google.com" in spf
        status = FAIL if mech in ("?", "+", "") else (PASS if mech == "-" and google else WARN)
        out.append(make("GWS-A30", ADMIN, area, "SPF ends in -all and includes Google", status, spf[:120], "include:_spf.google.com -all",
                        f"Tighten the SPF record for {domain}: include _spf.google.com and end with -all (or ~all with DMARC enforcement).", domain, "CIS: SPF"))
    dkim = [r for r in txt(f"{selector}._domainkey.{domain}") if "v=dkim1" in r.lower() or "p=" in r.lower()]
    out.append(make("GWS-A31", ADMIN, area, "DKIM signing key published", PASS if dkim else FAIL, f"{selector}._domainkey found" if dkim else f"no TXT at {selector}._domainkey",
                    "published and enabled", "Admin console > Apps > Gmail > Authenticate email: generate the DKIM key, publish the TXT record, then Start authentication.", domain, "CIS: DKIM"))
    dmarc = next((r for r in txt("_dmarc." + domain) if r.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        out.append(make("GWS-A32", ADMIN, area, "DMARC record published", FAIL, "no DMARC record", "p=quarantine or p=reject",
                        f"Publish a _dmarc.{domain} TXT record; start with p=none and move to quarantine/reject.", domain, "CIS: DMARC"))
    else:
        p = re.search(r"\bp=(\w+)", dmarc, re.I)
        pol = p.group(1).lower() if p else "none"
        out.append(make("GWS-A32", ADMIN, area, "DMARC policy enforces (quarantine/reject)", PASS if pol in ("quarantine", "reject") else WARN, dmarc[:120],
                        "p=quarantine or p=reject", f"Move the DMARC policy for {domain} from p=none to quarantine/reject after monitoring.", domain, "CIS: DMARC"))
    mta = any(r.lower().startswith("v=stsv1") for r in txt("_mta-sts." + domain))
    out.append(make("GWS-A33", ADMIN, area, "MTA-STS published", PASS if mta else INFO, "present" if mta else "not found", "present",
                    "Publish an MTA-STS policy to force TLS for inbound mail.", domain, "Best practice: MTA-STS"))
    return out


def domain_checks(api, log=lambda m: None, lookup=None):
    lookup = lookup or default_lookup

    def run():
        out = []
        for d in api.get(DOMAINS).get("domains", []):
            if d.get("verified", True):
                out += evaluate_domain(d["domainName"], lookup)
        return out
    return guarded("GWS-A30", ADMIN, "Domains", "Domain email authentication", run, log, "admin.directory.domain.readonly")


# -------------------------------------------------------------------------------- logs
SUSPICIOUS = ("suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login")


def evaluate_events(counts, days=7):
    total = sum(counts.values())
    detail = ", ".join(f"{k}={v}" for k, v in counts.items() if v) or "none"
    return [make("GWS-A50", ADMIN, "Logs", f"No suspicious sign-ins in the last {days} days", WARN if total else PASS, detail, "0",
                 "Investigate in Admin console > Reporting > Audit and investigation > Login; reset passwords and review 2SV on affected users.",
                 reference="Best practice: monitor sign-in events")]


def log_checks(api, log=lambda m: None, days=7, now=None):
    def run():
        start = ((now or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        counts = {}
        for ev in SUSPICIOUS:
            counts[ev] = len(api.get_all(REPORTS.format(app="login"), "items", {"eventName": ev, "startTime": start, "maxResults": 100}, 500))
        return evaluate_events(counts, days)
    return guarded("GWS-A50", ADMIN, "Logs", "Sign-in events", run, log, "admin.reports.audit.readonly")
