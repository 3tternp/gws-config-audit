"""Render the GUI with DEMO data (canned fake domain, not a real environment) -> docs/screenshot*.png.
Requires Pillow and a desktop session."""
import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

from PIL import ImageGrab  # noqa: E402
import test_checks as t  # noqa: E402
from gws_audit import identity, groups_devices, domains_logs, policy, scanner, user_checks  # noqa: E402
from gws_audit.gui import App  # noqa: E402

GM = user_checks.GMAIL
routes = {
    identity.USERS: {"users": [t.user("admin@example.org", admin=True), t.user("ops@example.org", admin=True, enrolled=False, enforced=False),
                               t.user("alex@example.org"), t.user("sam@example.org", enrolled=False, enforced=False),
                               t.user("old@example.org", last="2025-02-01T00:00:00.000Z")]},
    policy.POLICIES: {"policies": [
        {"setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": True}}},
        {"setting": {"type": "settings/gmail.pop_access", "value": {"enablePopAccess": False}}},
        {"setting": {"type": "settings/drive_and_docs.external_sharing", "value": {"externalSharingMode": "ALLOWED", "warnForExternalSharing": True, "allowPublishingFiles": True}}},
        {"setting": {"type": "settings/security.password", "value": {"minimumLength": 8, "enforceRequirementsAtLogin": False}}}]},
    groups_devices.GROUPS: {"groups": [{"email": "all-staff@example.org"}, {"email": "support@example.org"}]},
    groups_devices.GROUP_SETTINGS + "all-staff@example.org": {"whoCanJoin": "ANYONE_CAN_JOIN", "whoCanViewGroup": "ANYONE_CAN_VIEW", "whoCanPostMessage": "ANYONE_CAN_POST", "allowExternalMembers": "true"},
    groups_devices.GROUP_SETTINGS + "support@example.org": {"whoCanJoin": "INVITED_CAN_JOIN", "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW", "allowExternalMembers": "false"},
    groups_devices.DEVICES: {"mobiledevices": [{"email": ["sam@example.org"], "model": "Pixel 7", "deviceCompromisedStatus": "No compromise detected",
                                                "devicePasswordStatus": "Off", "encryptionStatus": "Encrypted", "lastSync": "2026-11-20T00:00:00.000Z"}]},
    domains_logs.DOMAINS: {"domains": [{"domainName": "example.org", "verified": True}]},
    domains_logs.REPORTS.format(app="login"): {"items": [{}]},
}
uroutes = {GM + "autoForwarding": {"enabled": True, "emailAddress": "me@gmail.com"}, GM + "forwardingAddresses": {"forwardingAddresses": [{"forwardingEmail": "me@gmail.com"}]},
           GM + "filters": {"filter": [{"criteria": {"subject": "invoice"}, "action": {"addLabelIds": ["TRASH"]}}]}, GM + "pop": {"accessWindow": "disabled"},
           GM + "imap": {"enabled": True}, GM + "delegates": {}, GM + "vacation": {"enableAutoReply": True}}


class UApi(t.FakeApi):
    def get_all(self, url, key, params=None, limit=2000):
        return [{"id": "1", "name": "Q4 salaries.xlsx"}] if "anyoneCanFind" in params["q"] else [{"id": "2", "name": "roadmap.pdf"}, {"id": "3", "name": "logo.png"}]


res, meta = scanner.run_scan(t.FakeApi(routes), UApi(uroutes), scanner.ScanOptions(), meta={"domain": "example.org (demo data)"}, user_domain="example.org",
                             lookup=t.lookup_factory({"example.org": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.example.org": ["v=DMARC1; p=none"]}))
app = App()
app.geometry("1400x760+30+20")
app.secrets.insert(0, "client_secret.json")
app.chip["Admin"].configure(text="admin@example.org", text_color="#30a46c")
app.chip["User"].configure(text="alex@example.org", text_color="#30a46c")
app.load_results(res, meta)
app.tree.selection_set(app.tree.get_children()[0])
app._detail()
app.update()
app.after(900, app.quit)
app.mainloop()
x, y, w, h = app.winfo_rootx(), app.winfo_rooty(), app.winfo_width(), app.winfo_height()
out = ROOT / "docs"
out.mkdir(exist_ok=True)
ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out / "screenshot_dark.png")
app.f_persp.set("User")
app._refresh()
app.mode_menu.set("Light")
app._set_mode("Light")
app.update()
app.after(900, app.quit)
app.mainloop()
ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out / "screenshot_light.png")
print("saved", sorted(p.name for p in out.glob("screenshot*")), len(res), "findings")
