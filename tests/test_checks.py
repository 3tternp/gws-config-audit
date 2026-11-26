"""Offline tests: every check runs against canned Google API data (no account, network or credentials).

Run:  python tests/test_checks.py
"""
import datetime as dt
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from gws_audit import identity, groups_devices, domains_logs, policy, user_checks, scanner, report, gui_model, auth  # noqa: E402
from gws_audit.api import Api, ApiError  # noqa: E402
from gws_audit.models import AREAS  # noqa: E402

NOW = dt.datetime(2026, 11, 26, tzinfo=dt.timezone.utc)


class FakeApi:
    def __init__(self, routes):
        self.routes = routes

    def _r(self, url):
        if url in self.routes:
            v = self.routes[url]
            if isinstance(v, Exception):
                raise v
            return v
        raise ApiError(404, "notFound", url)

    def get(self, url, params=None):
        return self._r(url)

    def get_all(self, url, key, params=None, limit=2000):
        v = self._r(url)
        return (v.get(key, []) if isinstance(v, dict) else v)[:limit]


def by_id(res):
    return {r.check_id: r for r in res}


def user(email, admin=False, enrolled=True, enforced=True, last="2026-11-20T00:00:00.000Z", created="2020-01-01T00:00:00.000Z", suspended=False):
    return {"primaryEmail": email, "isAdmin": admin, "isEnrolledIn2Sv": enrolled, "isEnforcedIn2Sv": enforced, "lastLoginTime": last,
            "creationTime": created, "suspended": suspended}


# ------------------------------------------------------------------ identity
def test_identity_users():
    users = [user("root@x.com", admin=True), user("a2@x.com", admin=True, enrolled=False, enforced=False), user("u1@x.com"),
             user("old@x.com", last="2025-01-01T00:00:00.000Z"), user("never@x.com", last="1970-01-01T00:00:00.000Z"),
             user("gone@x.com", suspended=True, last="2020-01-01T00:00:00.000Z")]
    r = by_id(identity.evaluate_users(users, NOW))
    assert r["GWS-A01"].status == "PASS" and "root@x.com" in r["GWS-A01"].actual
    assert r["GWS-A02"].status == "FAIL" and "a2@x.com" in r["GWS-A02"].actual
    assert r["GWS-A03"].status == "FAIL"
    assert r["GWS-A04"].status == "FAIL" and "4 of 5" in r["GWS-A04"].actual          # suspended user excluded from the base
    assert r["GWS-A05"].status == "WARN"
    assert r["GWS-A06"].status == "WARN" and "old@x.com" in r["GWS-A06"].actual and "never@x.com" in r["GWS-A06"].actual
    assert "gone@x.com" not in r["GWS-A06"].actual
    lone = by_id(identity.evaluate_users([user("only@x.com", admin=True)], NOW))
    assert lone["GWS-A01"].status == "WARN"
    many = by_id(identity.evaluate_users([user(f"a{i}@x.com", admin=True) for i in range(7)], NOW))
    assert many["GWS-A01"].status == "FAIL"


def test_identity_tokens():
    grants = {"a@x.com": [{"clientId": "1", "displayText": "BigApp", "scopes": ["https://mail.google.com/", "openid"]}],
              "b@x.com": [{"clientId": "1", "displayText": "BigApp", "scopes": ["https://mail.google.com/"]},
                          {"clientId": "2", "displayText": "Calendar sync", "scopes": ["https://www.googleapis.com/auth/calendar.readonly"]}]}
    r = by_id(identity.evaluate_tokens(grants))
    assert r["GWS-A10"].status == "WARN" and "BigApp" in r["GWS-A10"].actual and "2 users" in r["GWS-A10"].actual
    assert "Calendar sync" not in r["GWS-A10"].actual and "2 apps" in r["GWS-A11"].actual
    assert by_id(identity.evaluate_tokens({}))["GWS-A10"].status == "PASS"


def test_identity_denied_is_reported():
    r = identity.admin_checks(FakeApi({identity.USERS: ApiError(403, "PERMISSION_DENIED", "Not Authorized to access this resource/api")}))
    assert r[0].status == "WARN" and "denied" in r[0].actual


# -------------------------------------------------------------- groups, devices
def test_groups():
    rows = [{"email": "open@x.com", "settings": {"whoCanJoin": "ANYONE_CAN_JOIN", "whoCanViewGroup": "ANYONE_CAN_VIEW", "whoCanPostMessage": "ANYONE_CAN_POST",
                                                 "allowExternalMembers": "true"}},
            {"email": "team@x.com", "settings": {"whoCanJoin": "INVITED_CAN_JOIN", "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW", "allowExternalMembers": "false"}}]
    r = by_id(groups_devices.evaluate_groups(rows))
    assert r["GWS-A20"].status == "FAIL" and "open@x.com" in r["GWS-A20"].actual and "team@x.com" not in r["GWS-A20"].actual
    assert r["GWS-A21"].status == "WARN" and r["GWS-A22"].status == "WARN" and r["GWS-A23"].status == "INFO"
    clean = by_id(groups_devices.evaluate_groups(rows[1:]))
    assert all(clean[k].status == "PASS" for k in ("GWS-A20", "GWS-A21", "GWS-A22", "GWS-A23"))
    routes = {groups_devices.GROUPS: {"groups": [{"email": "open@x.com"}]}, groups_devices.GROUP_SETTINGS + "open@x.com": rows[0]["settings"]}
    assert by_id(groups_devices.groups_checks(FakeApi(routes)))["GWS-A20"].status == "FAIL"


def test_devices():
    devs = [{"email": ["a@x.com"], "model": "Pixel", "deviceCompromisedStatus": "Compromised", "devicePasswordStatus": "Off", "encryptionStatus": "Not encrypted",
             "lastSync": "2025-01-01T00:00:00.000Z"},
            {"email": ["b@x.com"], "model": "iPhone", "deviceCompromisedStatus": "No compromise detected", "devicePasswordStatus": "On",
             "encryptionStatus": "Encrypted", "lastSync": "2026-11-25T00:00:00.000Z"}]
    r = by_id(groups_devices.evaluate_devices(devs, NOW))
    assert r["GWS-A40"].status == "FAIL" and "Pixel" in r["GWS-A40"].actual and "iPhone" not in r["GWS-A40"].actual
    assert r["GWS-A41"].status == "WARN" and r["GWS-A42"].status == "WARN" and r["GWS-A43"].status == "INFO"
    ok = by_id(groups_devices.evaluate_devices(devs[1:], NOW))
    assert all(ok[k].status == "PASS" for k in ("GWS-A40", "GWS-A41", "GWS-A42", "GWS-A43"))


# ------------------------------------------------------------ domains and logs
def lookup_factory(records):
    def lookup(name, rtype="TXT"):
        if name in records:
            return records[name]
        raise LookupError(name)
    return lookup


def test_domain_dns():
    good = lookup_factory({"a.com": ["v=spf1 include:_spf.google.com -all"], "google._domainkey.a.com": ["v=DKIM1; k=rsa; p=ABC"],
                           "_dmarc.a.com": ["v=DMARC1; p=reject"], "_mta-sts.a.com": ["v=STSv1; id=1"]})
    r = by_id(domains_logs.evaluate_domain("a.com", good))
    assert [r[k].status for k in ("GWS-A30", "GWS-A31", "GWS-A32", "GWS-A33")] == ["PASS"] * 4
    weak = lookup_factory({"b.com": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.b.com": ["v=DMARC1; p=none"]})
    r = by_id(domains_logs.evaluate_domain("b.com", weak))
    assert r["GWS-A30"].status == "WARN" and r["GWS-A31"].status == "FAIL" and r["GWS-A32"].status == "WARN" and r["GWS-A33"].status == "INFO"
    r = by_id(domains_logs.evaluate_domain("c.com", lookup_factory({})))
    assert r["GWS-A30"].status == "FAIL" and r["GWS-A32"].status == "FAIL"
    assert by_id(domains_logs.evaluate_domain("d.com", lookup_factory({"d.com": ["v=spf1 +all"]})))["GWS-A30"].status == "FAIL"
    api = FakeApi({domains_logs.DOMAINS: {"domains": [{"domainName": "a.com", "verified": True}, {"domainName": "pending.com", "verified": False}]}})
    res = domains_logs.domain_checks(api, lookup=good)
    assert {x.target for x in res} == {"a.com"}


def test_logs():
    assert domains_logs.evaluate_events({"suspicious_login": 2, "suspicious_login_less_secure_app": 0})[0].status == "WARN"
    assert domains_logs.evaluate_events({"suspicious_login": 0})[0].status == "PASS"
    url = domains_logs.REPORTS.format(app="login")
    assert domains_logs.log_checks(FakeApi({url: {"items": [{}, {}]}}), now=NOW)[0].status == "WARN"


# ----------------------------------------------------------------------- policy
def test_policy_specs_are_valid():
    specs = policy.load_specs()
    assert len(specs) >= 8
    ids = [s["id"] for s in specs]
    assert len(ids) == len(set(ids))
    for s in specs:
        assert {"id", "area", "title", "type", "path", "op", "value", "fix"} <= set(s), s
        assert s["area"] in AREAS and s["op"] in ("eq", "ne", "ge", "le", "duration_le") and s["type"].startswith("settings/")


def test_policy_evaluation():
    pol = [{"setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": True}}},
           {"setting": {"type": "settings/gmail.pop_access", "value": {"enablePopAccess": False}}},
           {"setting": {"type": "settings/gmail.imap_access", "value": {"unexpectedField": 1}}},
           {"setting": {"type": "settings/drive_and_docs.external_sharing", "value": {"externalSharingMode": "ALLOWLISTED_DOMAINS", "warnForExternalSharing": True,
                                                                                    "allowPublishingFiles": True}}},
           {"setting": {"type": "settings/security.password", "value": {"minimumLength": 8, "enforceRequirementsAtLogin": True}}},
           {"setting": {"type": "settings/security.password", "value": {"minimumLength": 16}}},          # OU override: worst case wins
           {"setting": {"type": "settings/security.session_controls", "value": {"webSessionDuration": "86400s"}}}]
    r = by_id(policy.evaluate_policies(pol, policy.load_specs()))
    assert r["GWS-G01"].status == "FAIL" and r["GWS-G02"].status == "PASS"
    assert r["GWS-G03"].status == "MANUAL" and "unexpectedField" in r["GWS-G03"].actual         # unknown field: never a pass
    assert r["GWS-G04"].status == "PASS" and r["GWS-G05"].status == "PASS" and r["GWS-G06"].status == "FAIL"
    assert r["GWS-G07"].status == "FAIL" and "2 policy values" in r["GWS-G07"].actual and r["GWS-G08"].status == "PASS"
    assert r["GWS-G09"].status == "FAIL"
    only_gmail = policy.evaluate_policies(pol, policy.load_specs(), areas={"Gmail"})
    assert {x.area for x in only_gmail} == {"Gmail"}
    assert by_id(policy.evaluate_policies([], policy.load_specs()))["GWS-G01"].status == "MANUAL"     # nothing returned: manual, not pass
    assert policy.fetch_policies(FakeApi({policy.POLICIES: {"policies": pol}})) == pol


# ---------------------------------------------------------------------- employee
GM = user_checks.GMAIL


def test_gmail_user():
    routes = {GM + "autoForwarding": {"enabled": True, "emailAddress": "me@gmail.com"},
              GM + "forwardingAddresses": {"forwardingAddresses": [{"forwardingEmail": "me@gmail.com"}, {"forwardingEmail": "boss@x.com"}]},
              GM + "filters": {"filter": [{"criteria": {"from": "bank@evil.com"}, "action": {"forward": "x@evil.com"}},
                                          {"criteria": {"subject": "invoice"}, "action": {"addLabelIds": ["TRASH"]}}]},
              GM + "pop": {"accessWindow": "allMail"}, GM + "imap": {"enabled": False},
              GM + "delegates": {"delegates": [{"delegateEmail": "pa@x.com"}]},
              GM + "vacation": {"enableAutoReply": True, "restrictToContacts": False, "restrictToDomain": False}}
    r = by_id(user_checks.gmail_checks(FakeApi(routes), "x.com"))
    assert r["GWS-U01"].status == "FAIL" and "gmail.com" in r["GWS-U01"].actual
    assert r["GWS-U02"].status == "WARN" and "boss@x.com" not in r["GWS-U02"].actual
    assert r["GWS-U03"].status == "FAIL" and r["GWS-U04"].status == "WARN"
    assert r["GWS-U05"].status == "WARN" and r["GWS-U06"].status == "WARN" and r["GWS-U07"].status == "WARN"
    clean = {GM + "autoForwarding": {"enabled": False}, GM + "forwardingAddresses": {}, GM + "filters": {}, GM + "pop": {"accessWindow": "disabled"},
             GM + "imap": {"enabled": False}, GM + "delegates": {}, GM + "vacation": {"enableAutoReply": True, "restrictToDomain": True}}
    r = by_id(user_checks.gmail_checks(FakeApi(clean), "x.com"))
    assert all(r[k].status == "PASS" for k in ("GWS-U01", "GWS-U02", "GWS-U03", "GWS-U04", "GWS-U05", "GWS-U06", "GWS-U07"))
    denied = user_checks.gmail_checks(FakeApi({GM + "autoForwarding": ApiError(403, "PERMISSION_DENIED", "scope")}), "x.com")
    assert denied[0].status == "WARN"


def test_drive_user():
    calls = []

    class Api2(FakeApi):
        def get_all(self, url, key, params=None, limit=2000):
            calls.append(params["q"])
            return [{"id": "1", "name": "secret.docx"}] if "anyoneCanFind" in params["q"] else [{"id": "2", "name": "plan.xlsx"}, {"id": "3", "name": "a.pdf"}]
    r = by_id(user_checks.drive_checks(Api2({})))
    assert r["GWS-U10"].status == "FAIL" and "secret.docx" in r["GWS-U10"].actual and r["GWS-U11"].status == "WARN" and "2:" in r["GWS-U11"].actual
    assert all("'me' in owners" in q and "trashed = false" in q for q in calls)         # only my own files, no contents requested


# -------------------------------------------------------- client, auth, scanner
class FakeResp:
    def __init__(self, status, body, headers=None):
        self.status_code, self._b, self.headers, self.content, self.text = status, body, headers or {}, b"x", json.dumps(body)

    def json(self):
        return self._b


class FakeSession:
    def __init__(self, responses):
        self.responses, self.calls, self.methods = list(responses), [], set()

    def get(self, url, params=None, timeout=None):
        self.methods.add("GET")
        self.calls.append((url, dict(params or {})))
        return self.responses.pop(0)


def test_api_client():
    s = FakeSession([FakeResp(429, {}, {"Retry-After": "1"}), FakeResp(200, {"users": [1, 2], "nextPageToken": "t2"}), FakeResp(200, {"users": [3]})])
    api = Api(s, sleep=lambda x: None)
    assert api.get_all("https://x/users", "users", {"maxResults": 2}) == [1, 2, 3]
    assert s.calls[2][1]["pageToken"] == "t2" and s.methods == {"GET"}
    api = Api(FakeSession([FakeResp(403, {"error": {"code": 403, "message": "API not enabled", "status": "PERMISSION_DENIED"}})]))
    try:
        api.get("https://x")
        assert False
    except ApiError as e:
        assert e.denied and e.reason == "PERMISSION_DENIED"
    assert not hasattr(Api, "post") and not hasattr(Api, "put") and not hasattr(Api, "delete")      # read-only by construction


def test_scopes_are_minimal():
    admin = auth.scopes_for("Admin", ["Identity"])
    assert any(s.endswith("admin.directory.user.readonly") for s in admin)
    assert not any("gmail" in s or "drive" in s or "user.security" in s for s in admin)
    assert any(s.endswith("user.security") for s in auth.scopes_for("Admin", ["Identity"], include_tokens=True))
    user = auth.scopes_for("User", ["Drive"])
    assert any(s.endswith("drive.metadata.readonly") for s in user) and not any("gmail" in s or "admin." in s for s in user)
    assert not any(s.endswith("/auth/drive") or s.endswith("/auth/gmail.modify") or s.endswith("mail.google.com/") for s in auth.scopes_for("User", AREAS))


def test_scanner_end_to_end():
    routes = {identity.USERS: {"users": [user("root@x.com", admin=True), user("u@x.com")]},
              policy.POLICIES: {"policies": [{"setting": {"type": "settings/gmail.pop_access", "value": {"enablePopAccess": True}}}]},
              groups_devices.GROUPS: {"groups": []}, groups_devices.DEVICES: {"mobiledevices": []},
              domains_logs.DOMAINS: {"domains": [{"domainName": "x.com", "verified": True}]},
              domains_logs.REPORTS.format(app="login"): {"items": []}}
    uroutes = {GM + "autoForwarding": {"enabled": False}, GM + "forwardingAddresses": {}, GM + "filters": {}, GM + "pop": {"accessWindow": "disabled"},
               GM + "imap": {}, GM + "delegates": {}, GM + "vacation": {}}

    class UApi(FakeApi):
        def get_all(self, url, key, params=None, limit=2000):
            return []
    res, meta = scanner.run_scan(FakeApi(routes), UApi(uroutes), scanner.ScanOptions(), meta={"domain": "x.com"}, user_domain="x.com",
                                 lookup=lookup_factory({"x.com": ["v=spf1 include:_spf.google.com -all"]}))
    assert meta["perspectives"] == "Admin, User"
    assert {r.perspective for r in res} == {"Admin", "User"}
    ids = {r.check_id for r in res}
    assert {"GWS-A01", "GWS-G02", "GWS-A30", "GWS-A50", "GWS-U01", "GWS-U10"} <= ids, ids
    assert not any(r.status == "ERROR" for r in res), [r for r in res if r.status == "ERROR"]
    assert {r.perspective for r in scanner.run_scan(FakeApi(routes), None, scanner.ScanOptions(areas=("Identity",)))[0]} == {"Admin"}
    try:
        scanner.run_scan(None, None)
        assert False
    except ValueError:
        pass
    res[0].actual = "<script>alert(1)</script>"
    d = tempfile.mkdtemp()
    report.to_html(res, meta, os.path.join(d, "r.html"))
    report.to_csv(res, os.path.join(d, "r.csv"))
    report.to_json(res, meta, os.path.join(d, "r.json"))
    with open(os.path.join(d, "r.html"), encoding="utf-8") as fh:
        page = fh.read()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page and "Google Workspace" in page
    assert gui_model.filter_results(res, perspective="User", area="Gmail")
    assert {(x["area"], x["perspective"]) for x in gui_model.by_area(res)} >= {("Identity", "Admin"), ("Gmail", "User")}
    c, score = gui_model.summary(res)
    assert 0 <= score <= 100 and sum(c.values()) == len(res)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("OK - all offline tests passed")
