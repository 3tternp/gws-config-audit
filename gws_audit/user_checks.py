"""Employee view: what a normal account has configured in Gmail and how its Drive files are shared.

Only settings and file *metadata* endpoints are called. Message bodies, attachments and file contents are never requested.
"""
from __future__ import annotations

from .common import guarded, domain_of
from .models import PASS, FAIL, WARN, INFO, USER, make, short

GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me/settings/"
DRIVE = "https://www.googleapis.com/drive/v3/files"


# ------------------------------------------------------------------------------ Gmail
def evaluate_forwarding(auto, addresses, internal):
    out = []
    enabled = bool((auto or {}).get("enabled"))
    target = (auto or {}).get("emailAddress", "")
    external = enabled and domain_of(target) != internal.lower()
    out.append(make("GWS-U01", USER, "Gmail", "My mail is not automatically forwarded outside the company",
                    FAIL if external else (INFO if enabled else PASS),
                    f"forwarding to {target}" if enabled else "off", "off", "Gmail > Settings > Forwarding and POP/IMAP: turn forwarding off, then change your password and report it: "
                    "unexpected external forwarding is a common sign of a hijacked mailbox.", reference="CIS: Gmail auto-forwarding"))
    ext_addr = [a.get("forwardingEmail") for a in (addresses or []) if domain_of(a.get("forwardingEmail", "")) != internal.lower()]
    out.append(make("GWS-U02", USER, "Gmail", "No outside forwarding addresses are registered", WARN if ext_addr else PASS,
                    short(ext_addr) if ext_addr else "none", "none", "Remove forwarding addresses you do not recognise (Settings > Forwarding and POP/IMAP).",
                    reference="CIS: Gmail auto-forwarding"))
    return out


def evaluate_filters(filters, internal):
    fwd, hide = [], []
    for f in filters or []:
        a = f.get("action") or {}
        crit = f.get("criteria") or {}
        label = (crit.get("from") or crit.get("subject") or crit.get("query") or "filter")[:40]
        if a.get("forward") and domain_of(a["forward"]) != internal.lower():
            fwd.append(f"{label} -> {a['forward']}")
        if "TRASH" in (a.get("addLabelIds") or []):
            hide.append(label)
    return [make("GWS-U03", USER, "Gmail", "No filter forwards my mail outside the company", FAIL if fwd else PASS, short(fwd) if fwd else f"{len(filters or [])} filters checked", "none",
                 "Delete the filter (Settings > Filters and blocked addresses) and secure the account.", reference="CIS: Gmail filters"),
            make("GWS-U04", USER, "Gmail", "No filter silently deletes incoming mail", WARN if hide else PASS, short(hide) if hide else "none", "none",
                 "Review these filters; attackers use delete filters to hide replies and security alerts.", reference="Best practice: BEC indicators")]


def evaluate_access(pop, imap, delegates, vacation):
    out = []
    pop_on = (pop or {}).get("accessWindow", "disabled") != "disabled"
    imap_on = bool((imap or {}).get("enabled"))
    out.append(make("GWS-U05", USER, "Gmail", "POP and IMAP access are off (or deliberate)", WARN if (pop_on or imap_on) else PASS,
                    f"POP={'on' if pop_on else 'off'}, IMAP={'on' if imap_on else 'off'}", "off unless required",
                    "Settings > Forwarding and POP/IMAP: disable what you do not use; legacy clients bypass some protections.", reference="CIS: Gmail POP/IMAP"))
    dels = [d.get("delegateEmail") for d in (delegates or [])]
    out.append(make("GWS-U06", USER, "Gmail", "Mailbox delegates reviewed", WARN if dels else PASS, short(dels) if dels else "none", "only people you trust",
                    "Settings > Accounts > Grant access to your account: remove delegates you no longer need.", reference="Best practice: delegation"))
    v = vacation or {}
    leaky = bool(v.get("enableAutoReply")) and not v.get("restrictToContacts") and not v.get("restrictToDomain")
    out.append(make("GWS-U07", USER, "Gmail", "Out-of-office reply is limited to contacts or my organisation", WARN if leaky else PASS,
                    "auto-reply on, sent to everyone" if leaky else "off or restricted", "restricted",
                    "Vacation responder: tick 'Only send a response to people in my Contacts / my organization' (otherwise it confirms valid addresses and travel dates to strangers).",
                    reference="Best practice: auto-reply leakage"))
    return out


def gmail_checks(api, internal, log=lambda m: None):
    def run():
        g = lambda name, key=None: (lambda d: d.get(key, []) if key else d)(api.get(GMAIL + name))
        return (evaluate_forwarding(g("autoForwarding"), g("forwardingAddresses", "forwardingAddresses"), internal)
                + evaluate_filters(g("filters", "filter"), internal)
                + evaluate_access(g("pop"), g("imap"), g("delegates", "delegates"), g("vacation")))
    return guarded("GWS-U01", USER, "Gmail", "My Gmail settings", run, log, "gmail.readonly")


# ------------------------------------------------------------------------------ Drive
def evaluate_drive(public, link):
    names = lambda files: [f.get("name", f.get("id", "?")) for f in files]
    return [make("GWS-U10", USER, "Drive", "None of my files are public on the internet", FAIL if public else PASS, short(names(public)) if public else "none", "none",
                 "Open the file > Share > General access: change 'Anyone on the internet' to Restricted.", reference="CIS: Drive public sharing"),
            make("GWS-U11", USER, "Drive", "Files shared with 'anyone with the link' reviewed", WARN if link else PASS, f"{len(link)}: " + short(names(link)) if link else "none",
                 "few, deliberate", "Replace link sharing with named people, or set an expiry, for anything sensitive.", reference="CIS: Drive link sharing")]


def drive_checks(api, log=lambda m: None, limit=300):
    def files(vis):
        return api.get_all(DRIVE, "files", {"q": f"'me' in owners and visibility = '{vis}' and trashed = false", "fields": "files(id,name),nextPageToken",
                                            "pageSize": 100}, limit)
    return guarded("GWS-U10", USER, "Drive", "My Drive sharing", lambda: evaluate_drive(files("anyoneCanFind"), files("anyoneWithLink")), log, "drive.metadata.readonly")


def user_checks(api, internal, areas, log=lambda m: None):
    out = []
    if "Gmail" in areas:
        out += gmail_checks(api, internal, log)
    if "Drive" in areas:
        out += drive_checks(api, log)
    return out
