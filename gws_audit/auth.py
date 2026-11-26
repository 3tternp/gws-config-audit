"""Google sign-in (OAuth installed-app flow). Tokens stay in memory; nothing is written to disk.

Two independent sessions: a Workspace administrator and a normal employee. Only read-oriented scopes are requested,
and scopes are limited to the areas/options you select. Note: a few Google scopes that are *needed to read* certain
data (Groups Settings, user tokens) are defined by Google as read/write scopes; this tool only issues GET requests.
"""
from __future__ import annotations

A = "https://www.googleapis.com/auth/"
ADMIN_SCOPES = {
    "Identity": [A + "admin.directory.user.readonly", A + "cloud-identity.policies.readonly"],
    "Gmail": [A + "cloud-identity.policies.readonly"],
    "Drive": [A + "cloud-identity.policies.readonly"],
    "Groups": [A + "admin.directory.group.readonly", A + "apps.groups.settings"],
    "Devices": [A + "admin.directory.device.mobile.readonly"],
    "Domains": [A + "admin.directory.domain.readonly"],
    "Logs": [A + "admin.reports.audit.readonly"],
}
TOKEN_SCOPE = A + "admin.directory.user.security"        # opt-in: third-party app grants (tokens.list)
USER_SCOPES = {
    "Gmail": [A + "gmail.readonly"],                       # used for settings endpoints only; message bodies are never requested
    "Drive": [A + "drive.metadata.readonly"],              # file names and sharing state only
}
BASE_USER = ["openid", A + "userinfo.email"]


def scopes_for(perspective, areas, include_tokens=False):
    table = ADMIN_SCOPES if perspective == "Admin" else USER_SCOPES
    s = {x for a in areas for x in table.get(a, [])}
    if perspective == "Admin" and include_tokens:
        s.add(TOKEN_SCOPE)
    return sorted(s) + BASE_USER


class SignIn:
    def __init__(self, perspective, client_secrets_path):
        self.perspective, self.path = perspective, client_secrets_path
        self.session, self.email, self.domain, self.scopes = None, "", "", []

    def login(self, areas, include_tokens=False):
        try:
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import AuthorizedSession
        except ImportError as e:
            raise RuntimeError("google-auth-oauthlib is required: pip install -r requirements.txt") from e
        self.scopes = scopes_for(self.perspective, areas, include_tokens)
        flow = InstalledAppFlow.from_client_secrets_file(self.path, self.scopes)
        creds = flow.run_local_server(port=0, prompt="select_account", authorization_prompt_message="",
                                      success_message="Signed in. You can close this tab and return to the auditor.")
        self.session = AuthorizedSession(creds)
        info = self.session.get("https://openidconnect.googleapis.com/v1/userinfo", timeout=30).json()
        self.email = info.get("email", "")
        self.domain = info.get("hd") or (self.email.split("@")[-1] if "@" in self.email else "")
        return self.email
