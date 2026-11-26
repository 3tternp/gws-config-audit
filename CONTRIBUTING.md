# Contributing

Thanks for helping improve the Google Workspace Config Auditor. Bug reports, results from real Workspaces, new checks and documentation fixes are all welcome.

## The most useful contribution right now

The tool has only been tested with canned API data. If you can run it against a **test Google Workspace** (not production), please:

1. Run an audit as an administrator and/or an employee and compare the findings with the Admin console.
2. Look especially at ⚪ `MANUAL` rows from the Policy API: they show the raw setting JSON the API returned, which tells us the real setting and field names.
3. Open an issue describing what differed (wrong status, missing data, API errors). **Remove domain names, user addresses, file names and any tokens first.**

## Development setup

Requires Python 3.10+ (the GUI also needs Tkinter).

```powershell
git clone https://github.com/3tternp/gws-config-audit.git
cd gws-config-audit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the tests (no Google account, credentials or network needed):

```powershell
python tests/test_checks.py
```

CI runs the same test plus a syntax check on Python 3.10, 3.12 and 3.13 on Ubuntu and Windows. Please make sure it passes before opening a pull request.

## Project layout

| Path | Purpose |
|---|---|
| `gws_audit/api.py` | Read-only REST client (GET, paging, retry) |
| `gws_audit/auth.py` | OAuth sign-in and the per-area scope tables |
| `gws_audit/identity.py` | Users, admins, 2SV, dormant accounts, third-party apps |
| `gws_audit/policy.py`, `data/policies.json` | Admin-console settings via the Cloud Identity Policy API (data-driven baseline) |
| `gws_audit/groups_devices.py` | Groups and mobile devices |
| `gws_audit/domains_logs.py` | SPF / DKIM / DMARC / MTA-STS and sign-in events |
| `gws_audit/user_checks.py` | Employee view: Gmail settings and Drive sharing |
| `gws_audit/scanner.py` | Orchestrates the admin and user scans |
| `gws_audit/gui.py`, `gui_model.py` | CustomTkinter GUI and its headless logic |
| `gws_audit/report.py` | HTML / CSV / JSON export |
| `tests/test_checks.py` | Offline tests |

## Ground rules

### Keep it read-only
Only HTTP `GET` requests. The client in `api.py` deliberately has no write methods and a test checks for that; do not add any. Never add code that changes a Workspace setting.

### Request the least access
Scopes live in `auth.py` and are requested only for the areas the person selects. Do not add a broader scope than an endpoint needs, do not request message bodies or file contents, and keep anything that needs an unusually broad scope **opt-in** with a note in the README and `SECURITY.md`. A test verifies that employee sign-ins never request admin or broad Gmail/Drive scopes.

### Never handle secrets
Use Google's sign-in page; do not add fields that take passwords. Keep tokens in memory only, never log them, and never commit OAuth client files (`client_secret*.json`) or token files: `.gitignore` excludes them, so please do not work around it.

### Be honest about uncertainty
If a value cannot be determined (API denied, setting not returned, unknown field), report ⚪ `MANUAL` or 🟠 `WARN` with the reason and the fix, never a pass. A check must only say PASS when it actually measured a compliant value.

## Adding or changing a check

1. Put the check in the right module (admin checks return `Result` objects tagged `ADMIN`, employee checks `USER`). Keep **evaluation** in a pure function that takes plain data (like `evaluate_users`) and keep the API calls in a thin wrapper, so it can be tested with canned data.
2. Wrap the API part with `guarded(...)` so a denied or failed call becomes a clear finding instead of crashing the scan.
3. Use a stable ID (`GWS-A..` admin, `GWS-U..` employee, `GWS-G..` policy settings), a plain title, actual and expected values, and a **remediation** that says where to click or what to set. Fill `reference` with the benchmark theme or best practice it relates to; do not claim CIS section numbers.
4. Add tests in `tests/test_checks.py` for the compliant and non-compliant cases, and for the denied-access case if relevant.
5. Update the checks reference in `README.md` and add a line under **Unreleased** in `CHANGELOG.md`.

## Updating the admin-console baseline

Settings read through the Policy API are defined in `gws_audit/data/policies.json`. Each entry names the setting `type`, the `path` of the field inside its value, an `op` (`eq`, `ne`, `ge`, `le`, `duration_le`), the expected `value`, a `fix` text and a `ref`. To add one, append an entry; a test validates the file's structure and that IDs are unique. If you know the real setting or field name differs from what is in the file, please open a pull request with a **sanitised** sample of the API response.

## GUI changes

Put filtering, sorting and aggregation in `gui_model.py` so it can be unit tested without a display. After visible changes, regenerate the demo screenshots (they use made-up data, never a real Workspace):

```powershell
pip install pillow
python tools/make_screenshot.py
```

`tools/make_icon.py` regenerates the app icons.

## Pull requests

- Keep each pull request focused on one change.
- Describe what changed and how you tested it, and say clearly if it has not run against a real Workspace.
- Update `README.md` and `CHANGELOG.md` when behaviour changes.
- Follow the existing style: type hints where practical, short docstrings explaining *why*, no unused code.

## Reporting security issues

Please do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md) for how to report it privately.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
