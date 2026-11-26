# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

No version has been released yet; everything below is in the initial commit and listed under **Unreleased**.

## [Unreleased]

### Added
- **Two perspectives:** separate Workspace-administrator and normal-employee sign-ins (OAuth installed-app flow, your own Desktop OAuth client). Every finding is tagged *Admin* or *User*; each sign-in requests only the read scopes for the selected areas, and tokens are kept in memory only.
- **Identity:** super administrator count, 2-step verification enrolment and enforcement (admins and everyone), dormant accounts, and an opt-in inventory of third-party app grants with broad scopes.
- **Admin-console settings** through the Cloud Identity Policy API against an editable, data-driven baseline (`gws_audit/data/policies.json`): Gmail auto-forwarding, POP and IMAP; Drive external sharing, sharing warnings and web publishing; password length and enforcement; web session length. Unrecognised settings or fields are reported as `MANUAL` with the raw value, never as a pass.
- **Groups:** groups anyone can join, view or post to, and groups with external members. **Devices:** compromised, unlocked, unencrypted and stale mobile devices. **Domains:** SPF, DKIM, DMARC and MTA-STS per verified domain. **Logs:** suspicious sign-in events in the last 7 days.
- **Employee view:** Gmail forwarding, forwarding addresses, filters that forward or delete, POP/IMAP, delegates and out-of-office leakage; Drive files that are public or shared with anyone who has the link (metadata only).
- **Desktop GUI** (CustomTkinter) with dark, light and system themes, summary cards, filters by view, area and status, search, a by-area roll-up, a fix-instruction panel and a log; plus a **CLI** (`gws_audit_cli.py`).
- **HTML, CSV and JSON reports** (data is HTML-escaped).
- Offline test suite (canned API data, REST client paging and retry, scope minimisation, read-only client, policy baseline, report escaping, GUI logic) running in CI on Ubuntu and Windows with Python 3.10, 3.12 and 3.13.
- README with logo, badges, setup steps, permission tables, collapsible check reference, FAQ and roadmap; `SECURITY.md`; MIT license.

### Known limitations
- Not yet validated against a live Google Workspace; tests use canned data only.
- Policy API setting and field names are best-effort; per-organisational-unit precedence is not resolved (the worst value is reported).
- Some Google scopes needed to read certain data are defined by Google as read/write (Groups Settings, user tokens) or broad (Gmail); the tool only issues `GET` requests to settings and metadata endpoints.
- A focused set of checks inspired by the CIS Google Workspace Foundations Benchmark, not a full or certified benchmark.

[Unreleased]: https://github.com/3tternp/gws-config-audit/commits/main
