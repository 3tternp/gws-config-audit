# Security Policy

## Supported versions

This is an early-stage project with no tagged release yet. Security fixes are made on the `main` branch, and once releases exist only the latest release will be supported.

## Reporting a vulnerability

Please **do not** open a public issue with details of a vulnerability.

1. **Preferred:** open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting), if that button is available.
2. **Otherwise:** open a public issue titled "Security contact request" that contains **no technical details**, and the maintainer will arrange a private channel.

When you report privately, include the affected version or commit, what you observed, steps to reproduce, and the impact you expect. Remove domain names, user addresses, tokens, OAuth client secrets and any real Workspace data from logs and screenshots.

This is a volunteer-maintained project, so there is no guaranteed response time, but reports are taken seriously and will be acknowledged as soon as possible. Please allow time for a fix before disclosing publicly.

## What is in scope

Issues in this tool's own code, for example:

- anything that could **expose, log or store tokens, OAuth client secrets or Workspace data** unexpectedly (logs, reports, the GUI, files written to disk);
- **injection** of Workspace data into reports (including HTML/script injection into exported reports);
- the tool performing a **write or state-changing request** (it is meant to issue only `GET` requests);
- sign-in handling that requests broader scopes than the selected areas and options need.

Out of scope: vulnerabilities in Google Workspace, Google APIs or the Google auth libraries (report those to Google), configuration weaknesses the tool *reports* about your own Workspace, and incomplete or inaccurate check results (open a normal issue for those).

## Design principles that protect you

- **Read-only.** The REST client has only a `GET` method, and a test fails if a write method is added.
- **No passwords handled.** Sign-in happens on Google's own page; the tool never sees a password. Tokens are kept in memory only and no token file is written.
- **Least privilege.** Each sign-in requests only the scopes for the areas you select; the third-party-app scope is opt-in; a test checks that employee sign-ins never request admin or broad Drive/Gmail scopes.
- **Scopes you should know about.** Google defines `apps.groups.settings` and `admin.directory.user.security` as read/write scopes and `gmail.readonly` as mail access, because no narrower scope exists for those endpoints. The tool only calls settings and metadata endpoints and never requests message bodies or file contents.
- **Secrets stay out of git.** `.gitignore` excludes OAuth client files (`client_secret*.json`) and token files. Never commit them.
- **Reports are sensitive.** Exported HTML, CSV and JSON files list users, groups, files and configuration weaknesses. Store and share them as confidential.

## Using it safely

- Try it first in a **test Workspace**: the tool has not yet been validated against a live one.
- Create the OAuth client in your own Google Cloud project with an **Internal** consent screen, so only your organisation's accounts can sign in. Delete the client when you no longer need it.
- Prefer a **dedicated administrator account with read-focused roles** over a day-to-day super admin for the admin view.
- The employee view reads that employee's Gmail settings (forwarding, filters, delegates) and Drive sharing metadata; run it only with the account owner's knowledge and consent.
