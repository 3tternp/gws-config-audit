"""Groups (external exposure) and mobile devices."""
from __future__ import annotations

import datetime as dt

from .common import guarded, parse_time
from .models import PASS, FAIL, WARN, INFO, ADMIN, make, short

GROUPS = "https://admin.googleapis.com/admin/directory/v1/groups"
GROUP_SETTINGS = "https://www.googleapis.com/groups/v1/groups/"
DEVICES = "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/mobile"


# ----------------------------------------------------------------------------- groups
def evaluate_groups(rows):
    """rows: list of {email, settings:{whoCanJoin, whoCanViewGroup, whoCanPostMessage, allowExternalMembers}}."""
    area = "Groups"
    join = [r["email"] for r in rows if r["settings"].get("whoCanJoin") == "ANYONE_CAN_JOIN"]
    view = [r["email"] for r in rows if r["settings"].get("whoCanViewGroup") == "ANYONE_CAN_VIEW"]
    post = [r["email"] for r in rows if r["settings"].get("whoCanPostMessage") == "ANYONE_CAN_POST"]
    ext = [r["email"] for r in rows if str(r["settings"].get("allowExternalMembers")).lower() == "true"]
    n = len(rows)
    return [
        make("GWS-A20", ADMIN, area, "Nobody on the internet can join groups freely", FAIL if join else PASS, f"{len(join)} of {n}: " + short(join) if join else f"{n} groups checked",
             "0", "Group settings > Access: set 'Who can join group' to 'Only invited users' or 'Anyone in the organization can ask'.", reference="CIS: group access"),
        make("GWS-A21", ADMIN, area, "Group conversations are not public", WARN if view else PASS, f"{len(view)} of {n}: " + short(view) if view else "none public",
             "0", "Group settings > Access: set 'Who can view conversations' to group members or the organisation.", reference="CIS: group access"),
        make("GWS-A22", ADMIN, area, "Only members/organisation can post to groups", WARN if post else PASS, f"{len(post)} of {n}: " + short(post) if post else "none open",
             "0", "Group settings > Access: restrict 'Who can post' (open groups become spam and phishing relays).", reference="Best practice: group posting"),
        make("GWS-A23", ADMIN, area, "Groups allowing external members reviewed", INFO if ext else PASS, f"{len(ext)} of {n}: " + short(ext) if ext else "none",
             "only where needed", "Turn off 'Allow members outside your organization' unless the group needs it.", reference="CIS: external members"),
    ]


def fetch_groups(api, cap=200, log=lambda m: None):
    from .api import ApiError
    groups = api.get_all(GROUPS, "groups", {"customer": "my_customer", "maxResults": 200}, cap)
    rows = []
    for g in groups:
        try:
            rows.append({"email": g["email"], "settings": api.get(GROUP_SETTINGS + g["email"], {"alt": "json"})})
        except ApiError as e:
            if e.denied:
                raise
            log(f"group settings for {g['email']}: {e}")
    return rows


def groups_checks(api, log=lambda m: None, cap=200):
    return guarded("GWS-A20", ADMIN, "Groups", "Group settings", lambda: evaluate_groups(fetch_groups(api, cap, log)), log,
                   "admin.directory.group.readonly + apps.groups.settings")


# ---------------------------------------------------------------------------- devices
def evaluate_devices(devices, now=None, stale_days=90):
    now = now or dt.datetime.now(dt.timezone.utc)
    area = "Devices"
    n = len(devices)
    name = lambda d: (d.get("email") or ["?"])[0] + "/" + str(d.get("model") or d.get("name") or d.get("resourceId", "?"))
    compromised = [name(d) for d in devices if "compromis" in str(d.get("deviceCompromisedStatus", "")).lower() and "no compromis" not in str(d.get("deviceCompromisedStatus", "")).lower()]
    nopass = [name(d) for d in devices if str(d.get("devicePasswordStatus", "")).lower() in ("off", "disabled", "password not set")]
    noenc = [name(d) for d in devices if "not" in str(d.get("encryptionStatus", "")).lower() and "encrypt" in str(d.get("encryptionStatus", "")).lower()]
    stale = []
    for d in devices:
        t = parse_time(d.get("lastSync"))
        if t is not None and (now - t).days > stale_days:
            stale.append(name(d))
    return [
        make("GWS-A40", ADMIN, area, "No compromised (rooted/jailbroken) devices", FAIL if compromised else PASS, short(compromised) if compromised else f"{n} devices checked",
             "0", "Block the device and wipe the account: Admin console > Devices > Mobile & endpoints.", reference="CIS: mobile management"),
        make("GWS-A41", ADMIN, area, "Devices have a screen lock", WARN if nopass else PASS, f"{len(nopass)}: " + short(nopass) if nopass else "all locked",
             "0", "Require a screen lock in Devices > Settings > Universal settings > Password management.", reference="CIS: mobile management"),
        make("GWS-A42", ADMIN, area, "Devices are encrypted", WARN if noenc else PASS, f"{len(noenc)}: " + short(noenc) if noenc else "all encrypted",
             "0", "Require device encryption in the mobile management settings.", reference="CIS: mobile management"),
        make("GWS-A43", ADMIN, area, f"Devices synced within {stale_days} days", INFO if stale else PASS, f"{len(stale)} stale: " + short(stale) if stale else "none stale",
             "0", "Remove devices of former staff to stop them keeping access.", reference="Best practice: device hygiene"),
    ]


def devices_checks(api, log=lambda m: None):
    return guarded("GWS-A40", ADMIN, "Devices", "Mobile devices", lambda: evaluate_devices(api.get_all(DEVICES, "mobiledevices", {"maxResults": 100}, 5000)), log,
                   "admin.directory.device.mobile.readonly")
