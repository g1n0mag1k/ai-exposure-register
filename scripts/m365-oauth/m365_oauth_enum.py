#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
m365_oauth_enum.py
===================

AI Data Exposure Register — Microsoft 365 / Entra ID OAuth Enumeration Script
Sui-Generis LLC

M365 counterpart to gworkspace_oauth_enum.py. Enumerates every third-party
application that has been granted OAuth access into a Microsoft 365 tenant
(the "Accept"/"Consent" screen employees click when they sign in to a tool
"with Microsoft", plus any application-level consent an admin has granted),
using Microsoft Graph. This finds shadow IT that a staff survey alone will
miss, because it reflects what was actually authorized, not what people
remember installing.

Unlike Google Workspace (per-user token listing), Entra ID records grants
at the tenant level: every third-party app that's been consented into the
tenant shows up as a servicePrincipal ("Enterprise Application"), and the
actual consent grants hang off two endpoints:

  - oauth2PermissionGrants  -> delegated permissions (a specific user
    consented, or an admin consented "for all users") — the closest
    analog to Google's per-user token grants.
  - appRoleAssignments      -> application permissions (tenant-wide,
    not tied to any one user — e.g. an app with Mail.Read as an
    *application* permission can read every mailbox in the tenant
    regardless of who's signed in).

Output
------
Two CSVs, written to --output-dir:

  1. m365_oauth_grants_<tenant>_<date>.csv
     One row per (principal, app, resource, scope-set) grant — the raw
     evidence. "principal" is a user email for a delegated grant tied to
     one person, or "(tenant-wide — admin consent)" / "(tenant-wide —
     application permission)" for grants that aren't tied to a single
     user.

  2. m365_oauth_apps_summary_<tenant>_<date>.csv
     One row per unique third-party app — rolled up across all grants,
     with a risk score, the union of scopes, and a user count. This is
     the file to hand-merge into the AI Data Exposure Register's tool
     inventory and BAA/DPA matrix, same as the Google Workspace script's
     summary CSV.

If --allowlist is supplied (a CSV with a `client_id` and/or `domain`
column — e.g. exported from the ai-tool-compliance-db reference database),
each app in the summary is additionally flagged approved / unapproved.
Uses the app's Entra `appId`, so the same allowlist export can carry both
a Google `client_id` and an M365 `appId` in the same `client_id` column.

=============================================================================
SETUP (one-time, per client engagement)
=============================================================================

This script requires an Entra ID (Azure AD) app registration with
*application* (not delegated) Microsoft Graph permissions, consented by
the client's own Global Administrator or Privileged Role Administrator.
You cannot do this unilaterally — it requires the client's admin to grant
consent in their own tenant. Walk the client through this (or have their
IT/MSP do it); do not ask them to hand you their own admin credentials.

1. In the client's Azure Portal (portal.azure.com), the client's admin, or
   you under their direction, registers a new app:
   Entra ID > App registrations > New registration.
     a. Note the "Application (client) ID" and "Directory (tenant) ID"
        from the registration's Overview page.
     b. Certificates & secrets > New client secret. Copy the secret VALUE
        immediately (it is not shown again). Treat this like a password:
        never commit it to a repo, store it only in the client's own
        secrets manager or your encrypted local vault for the duration
        of the engagement, and delete/rotate it when the engagement ends.

2. API permissions > Add a permission > Microsoft Graph > Application
   permissions (NOT delegated) — add all of:
     - Application.Read.All   (read Enterprise Applications / service
                                principals — this is the app inventory)
     - Directory.Read.All     (resolve which user a delegated grant
                                belongs to)
   Then click "Grant admin consent for <tenant>" — only a Global
   Administrator or Privileged Role Administrator can do this step.

3. Install dependencies:
     pip install -r requirements.txt

4. Run:
     python3 m365_oauth_enum.py \\
         --tenant-id <directory-tenant-id> \\
         --client-id <app-registration-client-id> \\
         --client-secret <app-registration-secret> \\
         --output-dir ./output

   Optional:
     --allowlist ai_tool_compliance_db_export.csv   (flag approved/unapproved)
     --include-first-party                           (include Microsoft's
                                                        own first-party apps
                                                        — noisy, off by default)
     --min-risk MEDIUM                                (filter summary output)

=============================================================================
DATA HANDLING
=============================================================================
This script only reads metadata about which apps were authorized and which
Graph permission scopes were granted — it never reads the content of mail,
files, or other M365 data. Even so, the output (which employees use which
AI tools, and how broadly) is itself sensitive operational data about the
client. Per engagement guardrails: this output stays in the client's own
environment or your encrypted working directory, never in a public repo,
and is deleted from your local machine at engagement close unless the
client asks you to retain it as part of the delivered register.
"""

import argparse
import csv
import datetime
import sys
import time
from collections import defaultdict
from pathlib import Path

try:
    import requests
    from msal import ConfidentialClientApplication
except ImportError:
    sys.exit(
        "Missing dependencies. Run:\n"
        "    pip install -r requirements.txt\n"
        "(msal, requests)"
    )

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

# Microsoft's own first-party service principals are almost all owned by
# this well-known Microsoft Services tenant. Excluded by default (mirrors
# the Google script auto-excluding workspace.google.com) — pass
# --include-first-party to see them too.
MS_FIRST_PARTY_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# ---------------------------------------------------------------------------
# Graph permission (scope) risk classification
# ---------------------------------------------------------------------------
# Maps a scope-name substring (matched with `in`, case-insensitive) to a
# (risk_level, plain_english) tuple. Checked in order; first match wins, so
# more specific/severe patterns are listed first within a tier. Anything
# not matched falls through to a conservative default of MEDIUM
# ("unclassified scope — review manually"). Covers the delegated and
# application permission names that show up for mainstream AI/SaaS tools
# consenting into Microsoft Graph and Exchange Online.

RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

SCOPE_RISK_MAP = [
    # --- Full-mailbox / full-tenant access ---
    ("full_access_as_app", (RISK_HIGH, "Application-level full access to every mailbox (EWS full_access_as_app)")),
    ("mail.readwrite.all", (RISK_HIGH, "Read/write access to every mailbox in the tenant")),
    ("mail.read.all", (RISK_HIGH, "Read access to every mailbox in the tenant")),
    ("mail.send.all", (RISK_HIGH, "Can send mail as any user in the tenant")),
    ("mail.readwrite", (RISK_HIGH, "Read/write access to the signed-in user's mailbox")),
    ("mail.read", (RISK_HIGH, "Read access to the signed-in user's mailbox")),
    ("mail.send", (RISK_HIGH, "Can send mail as the signed-in user")),
    ("files.readwrite.all", (RISK_HIGH, "Read/write access to all OneDrive/SharePoint files in the tenant")),
    ("files.read.all", (RISK_HIGH, "Read access to all OneDrive/SharePoint files in the tenant")),
    ("sites.readwrite.all", (RISK_HIGH, "Read/write access to all SharePoint site collections")),
    ("sites.read.all", (RISK_HIGH, "Read access to all SharePoint site collections")),
    ("sites.fullcontrol.all", (RISK_HIGH, "Full control of all SharePoint site collections")),
    ("files.readwrite", (RISK_MEDIUM, "Access to the signed-in user's own files")),
    ("directory.readwrite.all", (RISK_HIGH, "Read/write access to the full Entra ID directory")),
    ("directory.read.all", (RISK_HIGH, "Read access to the full Entra ID directory (all users/groups)")),
    ("user.readwrite.all", (RISK_HIGH, "Read/write access to every user profile in the tenant")),
    ("user.export.all", (RISK_HIGH, "Can export user data (GDPR export API) tenant-wide")),
    ("roleManagement", (RISK_HIGH, "Can read or manage Entra ID role assignments")),
    ("policy.readwrite", (RISK_HIGH, "Can read/write tenant security or conditional access policy")),
    ("application.readwrite.all", (RISK_HIGH, "Can create/modify app registrations tenant-wide (privilege-escalation risk)")),
    ("teamsactivity", (RISK_MEDIUM, "Access to Teams user activity feed")),
    ("chatmessage.read.all", (RISK_MEDIUM, "Read access to all Teams chat messages")),
    ("chat.read", (RISK_MEDIUM, "Read access to the signed-in user's Teams chats")),
    ("channelmessage.read.all", (RISK_MEDIUM, "Read access to all Teams channel messages")),
    ("contacts.readwrite", (RISK_MEDIUM, "Read/write access to Outlook contacts")),
    ("contacts.read", (RISK_MEDIUM, "Read access to Outlook contacts")),
    ("calendars.readwrite", (RISK_MEDIUM, "Read/write access to calendar events")),
    ("calendars.read", (RISK_MEDIUM, "Read access to calendar events")),
    ("notes.readwrite", (RISK_MEDIUM, "Read/write access to OneNote content")),
    ("notes.read", (RISK_MEDIUM, "Read access to OneNote content")),
    ("people.read", (RISK_MEDIUM, "Access to relevance-ranked contacts/people data")),
    ("presence.read", (RISK_LOW, "Access to the signed-in user's Teams presence/availability status")),
    ("tasks.readwrite", (RISK_LOW, "Read/write access to To Do / Planner tasks")),
    ("tasks.read", (RISK_LOW, "Read access to To Do / Planner tasks")),
    ("mailboxsettings", (RISK_LOW, "Access to mailbox settings (rules, automatic replies)")),
    ("user.read.all", (RISK_MEDIUM, "Read access to all user profiles in the tenant")),
    ("user.readbasic.all", (RISK_LOW, "Read-only access to basic profile info for all users")),
    ("user.read", (RISK_INFO, "Sign-in: read the signed-in user's own profile only")),
    ("email", (RISK_INFO, "Sign-in: read account email address only")),
    ("profile", (RISK_INFO, "Sign-in: read basic profile info only")),
    ("offline_access", (RISK_INFO, "Keep the app signed in / issue refresh tokens")),
    ("openid", (RISK_INFO, "Sign-in (OpenID Connect) only")),
]


def classify_scope(scope_name: str):
    s = scope_name.lower()
    for pattern, result in SCOPE_RISK_MAP:
        if pattern in s:
            return result
    return (RISK_MEDIUM, "Unclassified scope — review manually: " + scope_name)


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
# Microsoft Graph plumbing
# ---------------------------------------------------------------------------

def get_app_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = ConfidentialClientApplication(
        client_id, authority=authority, client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in result:
        raise RuntimeError(
            "Failed to acquire a Graph token: "
            f"{result.get('error')}: {result.get('error_description')}"
        )
    return result["access_token"]


def graph_get_with_backoff(url: str, token: str, params=None, max_retries=5):
    headers = {"Authorization": f"Bearer {token}"}
    delay = 1.0
    for attempt in range(max_retries):
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (429, 500, 503) and attempt < max_retries - 1:
            retry_after = float(resp.headers.get("Retry-After", delay))
            time.sleep(retry_after)
            delay *= 2
            continue
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
    raise RuntimeError(f"Exceeded max retries calling {url}")


def graph_paginate(url: str, token: str, params=None):
    """Yields items across all pages, following @odata.nextLink."""
    next_url, next_params = url, params
    while next_url:
        page = graph_get_with_backoff(next_url, token, params=next_params)
        if page is None:
            return
        for item in page.get("value", []):
            yield item
        next_url = page.get("@odata.nextLink")
        next_params = None  # nextLink already carries the full query string


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def list_service_principals(token: str, include_first_party: bool):
    """
    Enterprise Applications in the tenant. Each represents an app that has
    been registered or consented into the tenant — this is the app
    inventory, analogous to the distinct `clientId`s seen in Google's
    per-user token listing.
    """
    sps = []
    for sp in graph_paginate(
        f"{GRAPH_BASE}/servicePrincipals",
        token,
        params={
            "$select": "id,appId,displayName,appOwnerOrganizationId,"
                       "verifiedPublisher,publisherName,servicePrincipalType,"
                       "signInAudience",
            "$top": 999,
        },
    ):
        if sp.get("servicePrincipalType") != "Application":
            continue  # skip managed identities, legacy, etc.
        if not include_first_party and sp.get("appOwnerOrganizationId") == MS_FIRST_PARTY_TENANT_ID:
            continue
        sps.append(sp)
    return sps


def list_delegated_grants_for_sp(token: str, sp_id: str):
    """oauth2PermissionGrants where this SP is the client (the app that was
    granted access), i.e. the app's delegated-permission consent records."""
    return list(
        graph_paginate(
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}/oauth2PermissionGrants",
            token,
        )
    )


def list_app_role_assignments_for_sp(token: str, sp_id: str):
    """Application permissions this SP has been granted on resource APIs
    (e.g. Mail.Read as an *application* permission, tenant-wide, not tied
    to any signed-in user)."""
    return list(
        graph_paginate(
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignments",
            token,
        )
    )


def resolve_resource_sp_name(token: str, resource_sp_cache: dict, resource_sp_id: str):
    if resource_sp_id in resource_sp_cache:
        return resource_sp_cache[resource_sp_id]
    sp = graph_get_with_backoff(
        f"{GRAPH_BASE}/servicePrincipals/{resource_sp_id}",
        token,
        params={"$select": "displayName"},
    )
    name = sp["displayName"] if sp else resource_sp_id
    resource_sp_cache[resource_sp_id] = name
    return name


def resolve_user_email(token: str, user_cache: dict, user_id: str):
    if user_id in user_cache:
        return user_cache[user_id]
    user = graph_get_with_backoff(
        f"{GRAPH_BASE}/users/{user_id}",
        token,
        params={"$select": "mail,userPrincipalName"},
    )
    email = (user.get("mail") or user.get("userPrincipalName")) if user else None
    email = email or f"(unresolved user {user_id})"
    user_cache[user_id] = email
    return email


def resolve_app_role_names(token: str, resource_sp_id: str, resource_name_cache: dict,
                            app_role_name_cache: dict, role_ids):
    """Application permissions are referenced by GUID (appRoleId) on the
    grant; resolve each to its human-readable value (e.g. 'Mail.Read') by
    looking up the resource SP's declared appRoles, once per resource SP."""
    cache_key = resource_sp_id
    if cache_key not in app_role_name_cache:
        sp = graph_get_with_backoff(
            f"{GRAPH_BASE}/servicePrincipals/{resource_sp_id}",
            token,
            params={"$select": "appRoles"},
        )
        roles = {r["id"]: r["value"] for r in (sp or {}).get("appRoles", [])}
        app_role_name_cache[cache_key] = roles
    roles = app_role_name_cache[cache_key]
    return [roles.get(rid, rid) for rid in role_ids]


# ---------------------------------------------------------------------------
# Allowlist (optional cross-reference against the AI tool compliance DB)
# ---------------------------------------------------------------------------

def load_allowlist(path: str):
    """
    Same shape as gworkspace_oauth_enum.py's allowlist loader — accepts a
    `client_id` column (here, an Entra `appId`), a `domain` column (matched
    against the app's display name when available), or both.
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


def is_allowlisted(app_id: str, display_name: str, allowlist):
    if not allowlist:
        return None  # no allowlist supplied -> unknown, not flagged either way
    if app_id in allowlist["client_ids"]:
        return True
    name = (display_name or "").lower()
    for d in allowlist["domains"]:
        if d in name:
            return True
    return False


# ---------------------------------------------------------------------------
# Main enumeration
# ---------------------------------------------------------------------------

def enumerate_oauth_grants(token, include_first_party=False, allowlist=None, _progress=True):
    """
    Returns:
      grants: list of dicts, one per (principal, app, resource, scope-set) grant
      summary: dict keyed by appId -> aggregated app info
    """
    def log(msg, **kw):
        if _progress:
            print(msg, file=sys.stderr, **kw)

    log("Listing Enterprise Applications (service principals) ...")
    sps = list_service_principals(token, include_first_party)
    log(f"  {len(sps)} app(s) found.")

    user_cache, resource_name_cache, app_role_name_cache = {}, {}, {}
    grants = []
    summary = defaultdict(lambda: {
        "app_name": None,
        "client_id": None,
        "verified_publisher": None,
        "external_tenant": None,
        "scopes": set(),
        "users": set(),
        "allowlisted": None,
    })

    for i, sp in enumerate(sps, 1):
        app_id = sp.get("appId", "unknown")
        display_name = sp.get("displayName") or "(no display name)"
        verified = bool(sp.get("verifiedPublisher", {}).get("verifiedPublisherId"))
        external = sp.get("appOwnerOrganizationId") not in (None, MS_FIRST_PARTY_TENANT_ID)
        log(f"  [{i}/{len(sps)}] {display_name} ...", end=" ")

        row_count = 0

        # --- Delegated permission grants (user or admin consent) ---
        for g in list_delegated_grants_for_sp(token, sp["id"]):
            scopes = [s for s in (g.get("scope") or "").split(" ") if s]
            if not scopes:
                continue
            consent_type = g.get("consentType", "Principal")
            if consent_type == "AllPrincipals":
                principal = "(tenant-wide — admin consent)"
            else:
                principal_id = g.get("principalId")
                principal = resolve_user_email(token, user_cache, principal_id) if principal_id else "(unknown principal)"
            resource_name = resolve_resource_sp_name(token, resource_name_cache, g["resourceId"])
            allow_flag = is_allowlisted(app_id, display_name, allowlist)

            grants.append({
                "principal": principal,
                "app_name": display_name,
                "client_id": app_id,
                "resource": resource_name,
                "grant_type": "delegated",
                "consent_type": consent_type,
                "scope_count": len(scopes),
                "scopes": "; ".join(scopes),
                "risk_level": app_risk_from_scopes(scopes),
                "verified_publisher": "Y" if verified else "N",
                "allowlisted": "" if allow_flag is None else ("Y" if allow_flag else "N"),
            })
            s = summary[app_id]
            s["app_name"], s["client_id"] = display_name, app_id
            s["verified_publisher"], s["external_tenant"] = verified, external
            s["scopes"].update(scopes)
            if consent_type == "AllPrincipals":
                s["users"].add("(tenant-wide — admin consent)")
            else:
                s["users"].add(principal)
            if allow_flag is not None:
                s["allowlisted"] = allow_flag
            row_count += 1

        # --- Application permission grants (tenant-wide, no signed-in user) ---
        role_assignments = list_app_role_assignments_for_sp(token, sp["id"])
        if role_assignments:
            by_resource = defaultdict(list)
            for ra in role_assignments:
                by_resource[ra["resourceId"]].append(ra["appRoleId"])
            for resource_id, role_ids in by_resource.items():
                scopes = resolve_app_role_names(token, resource_id, resource_name_cache, app_role_name_cache, role_ids)
                resource_name = resolve_resource_sp_name(token, resource_name_cache, resource_id)
                allow_flag = is_allowlisted(app_id, display_name, allowlist)

                grants.append({
                    "principal": "(tenant-wide — application permission)",
                    "app_name": display_name,
                    "client_id": app_id,
                    "resource": resource_name,
                    "grant_type": "application",
                    "consent_type": "AllPrincipals",
                    "scope_count": len(scopes),
                    "scopes": "; ".join(scopes),
                    "risk_level": app_risk_from_scopes(scopes),
                    "verified_publisher": "Y" if verified else "N",
                    "allowlisted": "" if allow_flag is None else ("Y" if allow_flag else "N"),
                })
                s = summary[app_id]
                s["app_name"], s["client_id"] = display_name, app_id
                s["verified_publisher"], s["external_tenant"] = verified, external
                s["scopes"].update(scopes)
                s["users"].add("(tenant-wide — application permission)")
                if allow_flag is not None:
                    s["allowlisted"] = allow_flag
                row_count += 1

        log(f"{row_count} grant(s)")

    return grants, summary


def write_grants_csv(grants, path: Path):
    fields = ["principal", "app_name", "client_id", "resource", "grant_type", "consent_type",
              "scope_count", "scopes", "risk_level", "verified_publisher", "allowlisted"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for g in sorted(grants, key=lambda r: (r["risk_level"] != "HIGH", r["app_name"], r["principal"])):
            w.writerow(g)
    print(f"Wrote {path} ({len(grants)} rows)")


def write_summary_csv(summary, path: Path, min_risk=None):
    order = {RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1, RISK_INFO: 0}
    fields = ["app_name", "client_id", "user_count", "users", "overall_risk",
              "scope_count", "scopes", "verified_publisher", "external_tenant", "allowlisted"]
    rows = []
    for app_id, s in summary.items():
        overall_risk = app_risk_from_scopes(s["scopes"])
        if min_risk and order[overall_risk] < order[min_risk]:
            continue
        allow = s["allowlisted"]
        rows.append({
            "app_name": s["app_name"],
            "client_id": app_id,
            "user_count": len(s["users"]),
            "users": "; ".join(sorted(s["users"])),
            "overall_risk": overall_risk,
            "scope_count": len(s["scopes"]),
            "scopes": "; ".join(sorted(s["scopes"])),
            "verified_publisher": "Y" if s["verified_publisher"] else "N",
            "external_tenant": "Y" if s["external_tenant"] else "N",
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
        description="Enumerate third-party OAuth app grants across a Microsoft 365 / Entra ID "
                    "tenant for the AI Data Exposure Register.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--tenant-id", required=True,
                         help="Entra ID directory (tenant) ID.")
    parser.add_argument("--client-id", required=True,
                         help="App registration's Application (client) ID.")
    parser.add_argument("--client-secret", required=True,
                         help="App registration's client secret value.")
    parser.add_argument("--output-dir", default="./output",
                         help="Directory to write the output CSVs into. Created if missing.")
    parser.add_argument("--allowlist", default=None,
                         help="Optional CSV (with client_id and/or domain columns) to flag "
                              "approved vs. unapproved apps, e.g. exported from the "
                              "ai-tool-compliance-db reference database.")
    parser.add_argument("--include-first-party", action="store_true",
                         help="Include Microsoft's own first-party service principals "
                              "(noisy — hundreds of internal Microsoft 365 apps). Off by default.")
    parser.add_argument("--min-risk", choices=[RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO],
                         default=None,
                         help="Only include apps at or above this risk level in the summary CSV. "
                              "(The per-grant CSV always contains everything.)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    allowlist = load_allowlist(args.allowlist) if args.allowlist else None
    if allowlist:
        print(f"Loaded allowlist: {len(allowlist['client_ids'])} client ID(s), "
              f"{len(allowlist['domains'])} domain pattern(s).")

    print(f"Authenticating to tenant {args.tenant_id} via client credentials ...")
    try:
        token = get_app_token(args.tenant_id, args.client_id, args.client_secret)
    except Exception as e:
        sys.exit(
            f"Failed to authenticate: {e}\n\n"
            "Common causes:\n"
            "  - Application.Read.All / Directory.Read.All permissions not granted admin\n"
            "    consent yet (Entra ID > App registrations > API permissions).\n"
            "  - Wrong tenant ID, client ID, or an expired/mistyped client secret.\n"
            "See the setup instructions at the top of this script."
        )

    try:
        grants, summary = enumerate_oauth_grants(
            token, include_first_party=args.include_first_party, allowlist=allowlist
        )
    except requests.exceptions.HTTPError as e:
        sys.exit(f"Microsoft Graph API error during enumeration: {e}")

    date_str = datetime.date.today().isoformat()
    grants_path = out_dir / f"m365_oauth_grants_{args.tenant_id}_{date_str}.csv"
    summary_path = out_dir / f"m365_oauth_apps_summary_{args.tenant_id}_{date_str}.csv"

    write_grants_csv(grants, grants_path)
    summary_rows = write_summary_csv(summary, summary_path, min_risk=args.min_risk)
    print_console_summary(summary_rows)

    print(f"Done. Next step: merge {summary_path.name} into the AI Data Exposure Register's "
          f"Tool Inventory and BAA/DPA Matrix sections (cross-reference against the Google "
          f"Workspace summary too, if the client uses both).")


if __name__ == "__main__":
    main()
