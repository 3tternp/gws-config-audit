"""Headless runner:  python gws_audit_cli.py --client-secrets client_secret.json --admin --user"""
import argparse
import sys

from gws_audit import report
from gws_audit.api import Api
from gws_audit.auth import SignIn
from gws_audit.models import AREAS
from gws_audit.scanner import ScanOptions, run_scan


def main():
    ap = argparse.ArgumentParser(description="Read-only Google Workspace configuration audit (CIS and best practice)")
    ap.add_argument("--client-secrets", required=True, help="OAuth client JSON (Desktop app) from your own Google Cloud project")
    ap.add_argument("--admin", action="store_true", help="sign in as a Workspace administrator")
    ap.add_argument("--user", action="store_true", help="sign in as a normal employee")
    ap.add_argument("--areas", default=",".join(AREAS), help="comma separated: " + ",".join(AREAS))
    ap.add_argument("--tokens", action="store_true", help="also list third-party app grants (admin.directory.user.security scope)")
    ap.add_argument("--out", default="gws_audit")
    a = ap.parse_args()
    if not (a.admin or a.user):
        ap.error("choose --admin and/or --user")
    areas = tuple(x.strip() for x in a.areas.split(",") if x.strip() in AREAS)
    sessions = {}
    for flag, persp in ((a.admin, "Admin"), (a.user, "User")):
        if flag:
            print(f"\n== Sign in as {persp.upper()} (a browser window will open) ==")
            s = SignIn(persp, a.client_secrets)
            s.login(areas, include_tokens=a.tokens and persp == "Admin")
            print("Signed in:", s.email)
            sessions[persp] = s
    admin, user = sessions.get("Admin"), sessions.get("User")
    res, meta = run_scan(Api(admin.session) if admin else None, Api(user.session) if user else None, ScanOptions(areas, a.tokens), log=print,
                         meta={"domain": (admin or user).domain}, user_domain=user.domain if user else "")
    report.to_html(res, meta, a.out + ".html")
    report.to_csv(res, a.out + ".csv")
    report.to_json(res, meta, a.out + ".json")
    c, score = report.summarize(res)
    print(dict(c), f"score={score}%", "-> reports written to", a.out + ".*")
    return 0


if __name__ == "__main__":
    sys.exit(main())
