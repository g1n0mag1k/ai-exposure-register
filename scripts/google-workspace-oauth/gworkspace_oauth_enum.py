#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gworkspace_oauth_enum.py
=========================

AI Data Exposure Register — Google Workspace OAuth Enumeration Script
Sui-Generis LLC

Enumerates every third-party OAuth application that any user in a Google
Workspace domain has granted access to (the "Sign in with Google" / "Connect
to Google" consent screen), using the Admin SDK Directory API's per-user
Tokens endpoint. This is the authoritative source for "what AI tools can
actually reach this org's Google data" — it finds shadow IT that a staff
survey alone will miss, because it reflects what was actually authorized,
not what people remember installing.

Output
------
Two CSVs, written to --output-dir:

  1. oauth_grants_<domain>_<date>.csv
     One row per (user, app) grant — the raw evidence.

  2. oauth_apps_summary_<domain>_<date>.csv
     One row per unique app — rolled up across all users, with a risk
     score, the union of scopes requested, and a user count. This is the
     file to hand-merge into the AI Data Exposure Register's tool inventory
     and BAA/DPA matrix.

If --allowlist is supplied (a CSV with a `client_id` or `domain` column —
e.g. exported from the ai-tool-compliance-db reference database), each app
in the summary is additionally flagged approved / unapproved.

=============================================================================
SETUP (one-time, per client engagement)
=============================================================================

This script requires a Google Cloud service account with Workspace
domain-wide delegation, authorized by the client's own Workspace Super
Admin. You cannot do this unilaterally — it requires the client's admin
to grant access in their own Admin Console. Walk the client through this
(or have their IT/MSP do it); do not ask them to hand you their own admin
credentials.

1. In a Google Cloud project (the client's own project, or a project you
   control specifically for this engagement — confirm which with the
   client):
     a. Enable the "Admin SDK API".
     b. Create a Service Account (IAM & Admin > Service Accounts).
     c. Create a JSON key for that service account and download it.
        Treat this file as a credential: never commit it to a repo, never
        put it in a public bucket, store it only in the client's own
        secrets manager or your encrypted local vault for the duration of
        the engagement, and delete it when the engagement ends.
     d. Note the service account's numeric "Client ID" (not its email) —
        found on the service account's "Details" tab under "Unique ID" /
        in the JSON key file's `client_id` field.

2. In the client's Google Workspace Admin Console
   (admin.google.com > Security > API Controls > Domain-wide Delegation),
   the client's Super Admin adds a new API client:
     - Client ID: the numeric ID from step 1d.
     - OAuth Scopes (comma-separated, request read-only scopes only):
         https://www.googleapis.com/auth/admin.directory.user.security
         https://www.googleapis.com/auth/admin.directory.user.readonly

3. The client's Super Admin also tells you which of their own admin
   accounts this service account should impersonate when calling the API
   (Directory API calls must be made "as" a human admin via domain-wide
   delegation — this is the --admin-email argument below). This account
   needs Admin Console privileges sufficient to read user security info
   (typically a Super Admin or a custom role with the
   "Security > API Controls" and "Users" read privileges).

4. Install dependencies:
     pip install -r requirements.txt

5. Run:
     python3 gworkspace_oauth_enum.py \\
         --credentials /path/to/service-account-key.json \\
         --admin-email admin@clientdomain.com \\
         --domain clientdomain.com \\
         --output-dir ./output

   Optional:
     --allowlist ai_tool_compliance_db_export.csv   (flag approved/unapproved)
     --include-suspended                             (include suspended users)
     --min-risk MEDIUM                                (filter summary output)

=============================================================================
DATA HANDLING
=============================================================================
This script only reads metadata about which apps were authorized and which
OAuth scopes were granted — it never reads the content of email, files, or
other Workspace data. Even so, the output (which employees use which AI
tools, and how broadly) is itself sensitive operational data about the
client. Per engagement guardrails: this output stays in the client's own
environment or your encrypted working directory, never in a public repo,
and is deleted from your local machine at engagement close unless the
client asks you to retain it as part of the delivered register.
"""

import argparse
import csv
import datetime
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    sys.exit(
        "Missing dependencies. Run:\n"
        "    pip install -r requirements.txt\n"
        "(google-api-python-client, google-auth, google-auth-httplib2)"
    )

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]

# ---------------------------------------------------------------------------
# OAuth scope risk classification
# ---------------------------------------------------------------------------
# Maps a scope substring (matched with `in`) to a (risk_level, plain_english)
# tuple. Checked in order; first match wins, so put more specific/severe
# patterns first within a tier. Anything not matched falls through to a
# conservative default of MEDIUM ("unclassified scope — review manually").

RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

SCOPE_RISK_MAP = [
    # --- Full-access / admin-equivalent scopes ---
    ("https://mail.google.com/", (RISK_HIGH, "Full Gmail access (read/send/delete all mail)")),
    ("auth/gmail.readonly", (RISK_HIGH, "Read-only access to all Gmail content")),
    ("auth/gmail.modify", (RISK_HIGH, "Read/modify Gmail content")),
    ("auth/drive\"", (RISK_HIGH, "Full Google Drive access (all files)")),
    ("auth/drive.readonly", (RISK_HIGH, "Read-only access to all Drive files")),
    ("auth/drive.file", (RISK_MEDIUM, "Access limited to files the app created/opened via picker")),
    ("auth/drive.metadata", (RISK_MEDIUM, "Access to Drive file metadata (not content)")),
    ("auth/admin.directory", (RISK_HIGH, "Google Workspace Admin / directory access")),
    ("auth/cloud-platform", (RISK_HIGH, "Full Google Cloud Platform access")),
    ("auth/contacts", (RISK_MEDIUM, "Access to Contacts")),
    ("auth/calendar", (RISK_MEDIUM, "Access to Calendar (events, availability)")),
    ("auth/spreadsheets", (RISK_MEDIUM, "Access to Google Sheets content")),
    ("auth/documents", (RISK_MEDIUM, "Access to Google Docs content")),
    ("auth/presentations", (RISK_MEDIUM, "Access to Google Slides content")),
    ("auth/meetings", (RISK_MEDIUM, "Access to Google Meet data")),
    ("auth/chat", (RISK_MEDIUM, "Access to Google Chat messages")),
    ("auth/forms", (RISK_MEDIUM, "Access to Google Forms content/responses")),
    ("auth/tasks", (RISK_LOW, "Access to Google Tasks")),
    ("auth/userinfo.email", (RISK_INFO, "Sign-in: read account email address only")),
    ("auth/userinfo.profile", (RISK_INFO, "Sign-in: read basic profile info only")),
    ("openid", (RISK_INFO, "Sign-in (OpenID Connect) only")),
]


def classify_scope(scope_url: str):
    for pattern, result in SCOPE_RISK_MAP:
        if pattern in scope_url:
            return result
    return (RISK_MEDIUM, "Unclassified scope — review manually: " + scope_url)


def app_risk_from_scopes(scopes):
    """An app's overall risk is the highest risk among its granted scopes."""
    order = {RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1, RISK_INFO: 0}
    best = RISK_INFO
    for s in scopes:
        level, _ = classify_scope(s)
        if order[level] > order[best]:
            best = level
    return best


# ---------------------------------------------------------------------------
# Google API plumbing
# ---------------------------------------------------------------------------

def build_directory_service(credentials_path: str, admin_email: str):
    creds = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=SCOPES
    )
    delegated = creds.with_subject(admin_email)
    return build("admin", "directory_v1", credentials=delegated, cache_discovery=False)


def call_with_backoff(request, max_retries=5):
    """Execute a googleapiclient request with exponential backoff on 429/5xx."""
    delay = 1.0
    for attempt in range(max_retries):
        try:
            return request.execute()
        except HttpError as e:
            status = getattr(e.resp, "status", None)
            if status in (403, 429, 500, 503) and attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError("Exceeded max retries")


def list_users(service, domain: str, include_suspended: bool):
    """Paginate through all users in the domain via Directory API."""
    users = []
    page_token = None
    while True:
        req = service.users().list(
            domain=domain,
            maxResults=500,
            pageToken=page_token,
            orderBy="email",
        )
        resp = call_with_backoff(req)
        for u in resp.get("users", []):
            if u.get("suspended") and not include_suspended:
                continue
            if u.get("archived"):
                continue
            users.append(u)
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return users


def list_tokens_for_user(service, user_email: str):
    """
    Returns the list of OAuth token grants (third-party app authorizations)
    for a single user. A 404 means the user has no tokens on record, which
    is normal and not an error.
    """
    try:
        req = service.tokens().list(userKey=user_email)
        resp = call_with_backoff(req)
        return resp.get("items", [])
    except HttpError as e:
        if getattr(e.resp, "status", None) == 404:
            return []
        print(f"  [warn] could not fetch tokens for {user_email}: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Allowlist (optional cross-reference against the AI tool compliance DB)
# ---------------------------------------------------------------------------

def load_allowlist(path: str):
    """
    Loads an allowlist CSV for cross-referencing. Accepts either a
    `client_id` column, a `domain` column (matched against the app's
    displayText / redirect domains when available), or both. Returns a
    dict: {"client_ids": set(...), "domains": set(...)}.
    """
    client_ids, domains = set(), set()
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("client_id"):
                client_ids.add(row["client_id"].strip())
            if row.get("domain"):
                domains.add(row["domain"].strip().lower())
    return {"client_ids": client_ids, "domains": domains}


def is_allowlisted(token_item, allowlist):
    if not allowlist:
        return None  # no allowlist supplied -> unknown, not flagged either way
    client_id = token_item.get("clientId", "")
    if client_id in allowlist["client_ids"]:
        return True
    display = (token_item.get("displayText") or "").lower()
    for d in allowlist["domains"]:
        if d in display:
            return True
    return False


# ---------------------------------------------------------------------------
# Main enumeration
# ---------------------------------------------------------------------------

def enumerate_oauth_grants(service, domain, include_suspended, allowlist=None):
    """
    Returns:
      grants: list of dicts, one per (user, app) grant
      summary: dict keyed by client_id -> aggregated app info
    """
    print(f"Listing users in {domain} ...")
    users = list_users(service, domain, include_suspended)
    print(f"  {len(users)} user(s) found.")

    grants = []
    summary = defaultdict(lambda: {
        "app_name": None,
        "client_id": None,
        "native_app": None,
        "anonymous": None,
        "scopes": set(),
        "users": set(),
        "allowlisted": None,
    })

    for i, u in enumerate(users, 1):
        email = u["primaryEmail"]
        print(f"  [{i}/{len(users)}] {email} ...", end=" ", flush=True)
        tokens = list_tokens_for_user(service, email)
        print(f"{len(tokens)} grant(s)")

        for t in tokens:
            client_id = t.get("clientId", "unknown")
            display_name = t.get("displayText") or "(no display name provided)"
            scopes = t.get("scopes", [])
            native_app = t.get("nativeApp", False)
            anonymous = t.get("anonymous", False)
            risk = app_risk_from_scopes(scopes)
            allow_flag = is_allowlisted(t, allowlist)

            grants.append({
                "user_email": email,
                "app_name": display_name,
                "client_id": client_id,
                "native_app": native_app,
                "anonymous_client": anonymous,
                "scope_count": len(scopes),
                "scopes": "; ".join(scopes),
                "risk_level": risk,
                "allowlisted": "" if allow_flag is None else ("Y" if allow_flag else "N"),
            })

            s = summary[client_id]
            s["app_name"] = display_name
            s["client_id"] = client_id
            s["native_app"] = native_app
            s["anonymous"] = anonymous
            s["scopes"].update(scopes)
            s["users"].add(email)
            if allow_flag is not None:
                s["allowlisted"] = allow_flag

    return grants, summary


def write_grants_csv(grants, path: Path):
    fields = ["user_email", "app_name", "client_id", "native_app", "anonymous_client",
              "scope_count", "scopes", "risk_level", "allowlisted"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for g in sorted(grants, key=lambda r: (r["risk_level"] != "HIGH", r["app_name"], r["user_email"])):
            w.writerow(g)
    print(f"Wrote {path} ({len(grants)} rows)")


def write_summary_csv(summary, path: Path, min_risk=None):
    order = {RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1, RISK_INFO: 0}
    fields = ["app_name", "client_id", "user_count", "users", "overall_risk",
              "scope_count", "scopes", "native_app", "anonymous_client", "allowlisted"]
    rows = []
    for client_id, s in summary.items():
        overall_risk = app_risk_from_scopes(s["scopes"])
        if min_risk and order[overall_risk] < order[min_risk]:
            continue
        allow = s["allowlisted"]
        rows.append({
            "app_name": s["app_name"],
            "client_id": client_id,
            "user_count": len(s["users"]),
            "users": "; ".join(sorted(s["users"])),
            "overall_risk": overall_risk,
            "scope_count": len(s["scopes"]),
            "scopes": "; ".join(sorted(s["scopes"])),
            "native_app": s["native_app"],
            "anonymous_client": s["anonymous"],
            "allowlisted": "" if allow is None else ("Y" if allow else "N"),
        })
    rows.sort(key=lambda r: (order.get(r["overall_risk"], 0) * -1, -r["user_count"], r["app_name"] or ""))

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"Wrote {path} ({len(rows)} unique app(s))")
    return rows


def print_console_summary(rows):
    by_risk = defaultdict(int)
    for r in rows:
        by_risk[r["overall_risk"]] += 1
    print("\n=== Summary ===")
    print(f"Unique third-party apps found : {len(rows)}")
    for level in (RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO):
        print(f"  {level:<6}: {by_risk.get(level, 0)}")
    unapproved = [r for r in rows if r["allowlisted"] == "N"]
    if unapproved:
        print(f"\nFlagged NOT on allowlist: {len(unapproved)}")
        for r in unapproved[:15]:
            print(f"  - {r['app_name']} ({r['overall_risk']}) — {r['user_count']} user(s)")
        if len(unapproved) > 15:
            print(f"  ... and {len(unapproved) - 15} more (see CSV)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate third-party OAuth app grants across a Google Workspace domain "
                    "for the AI Data Exposure Register.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--credentials", required=True,
                         help="Path to the service account JSON key file.")
    parser.add_argument("--admin-email", required=True,
                         help="Workspace admin account to impersonate via domain-wide delegation.")
    parser.add_argument("--domain", required=True,
                         help="Workspace domain to enumerate, e.g. riversidefamilypractice.com")
    parser.add_argument("--output-dir", default="./output",
                         help="Directory to write the output CSVs into. Created if missing.")
    parser.add_argument("--allowlist", default=None,
                         help="Optional CSV (with client_id and/or domain columns) to flag "
                              "approved vs. unapproved apps, e.g. exported from the "
                              "ai-tool-compliance-db reference database.")
    parser.add_argument("--include-suspended", action="store_true",
                         help="Include suspended user accounts in the scan.")
    parser.add_argument("--min-risk", choices=[RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO],
                         default=None,
                         help="Only include apps at or above this risk level in the summary CSV. "
                              "(The per-grant CSV always contains everything.)")
    args = parser.parse_args()

    creds_path = Path(args.credentials)
    if not creds_path.exists():
        sys.exit(f"Credentials file not found: {creds_path}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    allowlist = load_allowlist(args.allowlist) if args.allowlist else None
    if allowlist:
        print(f"Loaded allowlist: {len(allowlist['client_ids'])} client ID(s), "
              f"{len(allowlist['domains'])} domain pattern(s).")

    print(f"Authenticating as {args.admin_email} via domain-wide delegation ...")
    try:
        service = build_directory_service(str(creds_path), args.admin_email)
    except Exception as e:
        sys.exit(
            f"Failed to authenticate: {e}\n\n"
            "Common causes:\n"
            "  - Domain-wide delegation not yet configured for this service account\n"
            "    (Admin Console > Security > API Controls > Domain-wide Delegation).\n"
            "  - The --admin-email account lacks sufficient Admin Console privileges.\n"
            "  - The Admin SDK API is not enabled on the Cloud project.\n"
            "See the setup instructions at the top of this script."
        )

    try:
        grants, summary = enumerate_oauth_grants(
            service, args.domain, args.include_suspended, allowlist
        )
    except HttpError as e:
        sys.exit(f"Google API error during enumeration: {e}")

    date_str = datetime.date.today().isoformat()
    grants_path = out_dir / f"oauth_grants_{args.domain}_{date_str}.csv"
    summary_path = out_dir / f"oauth_apps_summary_{args.domain}_{date_str}.csv"

    write_grants_csv(grants, grants_path)
    summary_rows = write_summary_csv(summary, summary_path, min_risk=args.min_risk)
    print_console_summary(summary_rows)

    print(f"Done. Next step: merge {summary_path.name} into the AI Data Exposure Register's "
          f"Tool Inventory and BAA/DPA Matrix sections.")


if __name__ == "__main__":
    main()
