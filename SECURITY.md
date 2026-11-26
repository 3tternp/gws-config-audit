# 🔐 Security Policy

This tool reads sensitive configuration from your Google Workspace, so security reports are taken seriously. This page explains how to report a problem, what is in scope, how the tool protects you, and what to do if something goes wrong.

## 📌 Supported versions

This is an early-stage project with no tagged release yet. Security fixes are made on the `main` branch. Once releases exist, only the latest release will be supported.

| Version | Supported |
|---|---|
| `main` (latest commit) | ✅ |
| Older commits | ❌ |

## 📨 Reporting a vulnerability

Please **do not** open a public issue with details of a vulnerability.

1. **Preferred:** open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting), if that button is available.
2. **Otherwise:** open a public issue titled **"Security contact request"** that contains **no technical details**, and the maintainer will arrange a private channel.

Please include:

- the affected commit or version and your operating system / Python version;
- what you observed and the impact you expect;
- steps to reproduce, ideally with **made-up** data.

**Remove** domain names, user and group addresses, file names, tokens and OAuth client secrets from everything you send.

This is a volunteer-maintained project, so there is no guaranteed response time. Reports are taken seriously and acknowledged as soon as possible. Please allow reasonable time for a fix before disclosing publicly, and I will credit you in the changelog if you wish.

## 🎯 What is in scope

Issues in this tool's own code, for example:

- anything that could **expose, log or store tokens, OAuth client secrets or Workspace data** unexpectedly (logs, reports, the GUI, files written to disk, error messages);
- **injection** of Workspace data into exported reports (HTML or script injection, CSV formula injection);
- the tool sending a **write or state-changing request** (it is meant to issue only `GET` requests);
- sign-in handling that requests **broader scopes** than the selected areas and options need;
- unsafe handling of the OAuth client file or of data returned by Google's APIs.

**Out of scope:** vulnerabilities in Google Workspace, Google APIs or Google's auth libraries (report those to Google); configuration weaknesses the tool *reports* about your own Workspace; and incomplete or inaccurate check results (open a normal issue for those).

## 🛡️ How the tool protects you

| Protection | How it works |
|---|---|
| 🔒 **Read-only** | The REST client has only a `GET` method, and a test fails if a write method is added. |
| 🔑 **No passwords handled** | Sign-in happens on Google's own page, including 2-step verification. The tool never sees a password. |
| 🧠 **Tokens in memory only** | No token or cache file is written to disk. Closing the app discards them. |
| 📏 **Least privilege** | Scopes are requested per selected area; the third-party-app scope is opt-in; a test checks that employee sign-ins never request admin scopes or broad Gmail/Drive access. |
| 🗂️ **Metadata only** | The employee view reads Gmail *settings* and Drive file *names and sharing state*. Message bodies and file contents are never requested. |
| 🙈 **Secrets stay out of git** | `.gitignore` excludes `client_secret*.json`, `credentials*.json` and `token*.json`. |
| 🧼 **Escaped reports** | Workspace data is HTML-escaped in the HTML report. |

### Scopes you should know about

Google defines some scopes more broadly than the calls this tool makes, because no narrower scope exists for those endpoints:

| Scope | Why it is broad | What the tool does with it |
|---|---|---|
| `apps.groups.settings` | Google offers only a read/write scope | Reads group settings with `GET` |
| `admin.directory.user.security` (opt-in) | Read/write scope for user tokens | Lists third-party app grants with `GET` |
| `gmail.readonly` | Grants access to mail | Calls only the `settings/*` endpoints |

If you are not comfortable with a scope, leave that area or option unselected.

## ✅ Using it safely

- Try it first in a **test Workspace**: the tool has not yet been validated against a live one.
- Create the OAuth client in **your own** Google Cloud project with an **Internal** consent screen, so only your organisation's accounts can sign in.
- Prefer a **dedicated administrator account with read-focused roles** over a day-to-day super admin for the admin view.
- Run the employee view only with the account owner's **knowledge and consent**: it reads that person's Gmail settings and Drive sharing metadata.
- Treat exported **HTML / CSV / JSON reports as confidential**: they list users, groups, files and weaknesses.
- Download the tool only from this repository and review the code you run.

## 🚨 If something goes wrong

- **You committed an OAuth client file or token:** delete the client in the Google Cloud console (**APIs & Services > Credentials**) and create a new one, remove the file from git history, and review the sign-in activity of the accounts involved.
- **You think a token was exposed:** revoke the app's access at <https://myaccount.google.com/permissions> for the affected account (an administrator can also review and revoke app access in **Admin console > Security > API controls**), then change the account's password.
- **You shared a report by mistake:** assume the configuration details are known to the recipient and prioritise fixing the 🔴 FAIL findings.

## 📄 License

The project is licensed under the [MIT License](LICENSE).
