#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smoke test for m365_oauth_enum.py.

This does NOT call Microsoft Graph. It mocks `requests.get` responses
(shaped per Microsoft's documented Graph v1.0 schemas for servicePrincipals,
oauth2PermissionGrants, appRoleAssignments and users) and exercises the real
enumeration, risk-classification, and CSV-writing logic end to end, so the
script's logic can be verified without live tenant credentials.

Run: python3 test_m365_oauth_enum.py
"""

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import m365_oauth_enum as mod

GRAPH_SP_RESOURCE_ID = "resource-graph-sp-id"
CHATGPT_SP_ID = "sp-chatgpt"
OTTER_SP_ID = "sp-otter"
MS_FIRST_PARTY_SP_ID = "sp-ms-teams"


def fake_response(json_body, status=200, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.json.return_value = json_body
    resp.raise_for_status.side_effect = (
        None if status == 200 else Exception(f"HTTP {status}")
    )
    return resp


class FakeGraph:
    """
    Routes `requests.get(url, ...)` calls to canned responses keyed by the
    URL's path shape, standing in for Microsoft Graph. Good enough for the
    narrow set of endpoints m365_oauth_enum.py actually calls.
    """

    def __init__(self):
        self.service_principals = {
            CHATGPT_SP_ID: {
                "id": CHATGPT_SP_ID,
                "appId": "11111-chatgpt-app-id",
                "displayName": "ChatGPT Enterprise",
                "appOwnerOrganizationId": "external-org-id",
                "verifiedPublisher": {"verifiedPublisherId": "vp-1"},
                "servicePrincipalType": "Application",
                "appRoles": [],
            },
            OTTER_SP_ID: {
                "id": OTTER_SP_ID,
                "appId": "22222-otter-app-id",
                "displayName": "Otter.ai",
                "appOwnerOrganizationId": "external-org-id-2",
                "verifiedPublisher": {},
                "servicePrincipalType": "Application",
                "appRoles": [],
            },
            MS_FIRST_PARTY_SP_ID: {
                "id": MS_FIRST_PARTY_SP_ID,
                "appId": "33333-teams-app-id",
                "displayName": "Microsoft Teams Services",
                "appOwnerOrganizationId": mod.MS_FIRST_PARTY_TENANT_ID,
                "verifiedPublisher": {"verifiedPublisherId": "ms"},
                "servicePrincipalType": "Application",
                "appRoles": [],
            },
            GRAPH_SP_RESOURCE_ID: {
                "id": GRAPH_SP_RESOURCE_ID,
                "displayName": "Microsoft Graph",
                "appRoles": [
                    {"id": "role-mail-read", "value": "Mail.Read"},
                ],
            },
        }

        self.delegated_grants = {
            CHATGPT_SP_ID: [
                {
                    "clientId": CHATGPT_SP_ID,
                    "resourceId": GRAPH_SP_RESOURCE_ID,
                    "consentType": "Principal",
                    "principalId": "user-alice-id",
                    "scope": "Mail.Read User.Read",
                },
            ],
            OTTER_SP_ID: [
                {
                    "clientId": OTTER_SP_ID,
                    "resourceId": GRAPH_SP_RESOURCE_ID,
                    "consentType": "AllPrincipals",
                    "principalId": None,
                    "scope": "User.Read",
                },
            ],
            MS_FIRST_PARTY_SP_ID: [
                {
                    "clientId": MS_FIRST_PARTY_SP_ID,
                    "resourceId": GRAPH_SP_RESOURCE_ID,
                    "consentType": "AllPrincipals",
                    "principalId": None,
                    "scope": "User.Read",
                },
            ],
        }

        self.app_role_assignments = {
            CHATGPT_SP_ID: [],
            OTTER_SP_ID: [
                {"resourceId": GRAPH_SP_RESOURCE_ID, "appRoleId": "role-mail-read"},
            ],
            MS_FIRST_PARTY_SP_ID: [],
        }

        self.users = {
            "user-alice-id": {"mail": "alice@contoso.example", "userPrincipalName": "alice@contoso.onmicrosoft.com"},
        }

    def get(self, url, headers=None, params=None, timeout=None):
        if url.endswith("/servicePrincipals") and params and "$select" in params:
            sps = [s for s in self.service_principals.values() if "servicePrincipalType" in s]
            return fake_response({"value": sps})

        for sp_id in self.service_principals:
            if url.endswith(f"/servicePrincipals/{sp_id}/oauth2PermissionGrants"):
                return fake_response({"value": self.delegated_grants.get(sp_id, [])})
            if url.endswith(f"/servicePrincipals/{sp_id}/appRoleAssignments"):
                return fake_response({"value": self.app_role_assignments.get(sp_id, [])})
            if url.endswith(f"/servicePrincipals/{sp_id}") and params == {"$select": "displayName"}:
                return fake_response({"displayName": self.service_principals[sp_id]["displayName"]})
            if url.endswith(f"/servicePrincipals/{sp_id}") and params == {"$select": "appRoles"}:
                return fake_response({"appRoles": self.service_principals[sp_id].get("appRoles", [])})

        for user_id, user in self.users.items():
            if url.endswith(f"/users/{user_id}"):
                return fake_response(user)

        return fake_response({"value": []})


class TestScopeClassification(unittest.TestCase):
    def test_high_risk_mail_read_all(self):
        level, _ = mod.classify_scope("Mail.Read.All")
        self.assertEqual(level, mod.RISK_HIGH)

    def test_high_risk_mail_read_delegated(self):
        level, _ = mod.classify_scope("Mail.Read")
        self.assertEqual(level, mod.RISK_HIGH)

    def test_medium_risk_calendars(self):
        level, _ = mod.classify_scope("Calendars.ReadWrite")
        self.assertEqual(level, mod.RISK_MEDIUM)

    def test_info_sign_in_only(self):
        level, _ = mod.classify_scope("User.Read")
        self.assertEqual(level, mod.RISK_INFO)

    def test_unknown_scope_defaults_medium(self):
        level, desc = mod.classify_scope("Some.New.Scope")
        self.assertEqual(level, mod.RISK_MEDIUM)
        self.assertIn("Unclassified", desc)

    def test_app_risk_is_max_of_scopes(self):
        scopes = ["User.Read", "Mail.Read.All"]
        self.assertEqual(mod.app_risk_from_scopes(scopes), mod.RISK_HIGH)

    def test_case_insensitive(self):
        level, _ = mod.classify_scope("mail.readwrite.all")
        self.assertEqual(level, mod.RISK_HIGH)


class TestEnumerationEndToEnd(unittest.TestCase):
    def setUp(self):
        self.graph = FakeGraph()
        patcher = patch("m365_oauth_enum.requests.get", side_effect=self.graph.get)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_first_party_excluded_by_default(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        app_ids = {g["client_id"] for g in grants}
        self.assertNotIn("33333-teams-app-id", app_ids)

    def test_delegated_grant_resolves_user(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        chatgpt_grant = next(g for g in grants if g["app_name"] == "ChatGPT Enterprise")
        self.assertEqual(chatgpt_grant["principal"], "alice@contoso.example")
        self.assertEqual(chatgpt_grant["grant_type"], "delegated")
        self.assertEqual(chatgpt_grant["risk_level"], mod.RISK_HIGH)  # Mail.Read

    def test_admin_consent_grant_marked_tenant_wide(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        otter_delegated = next(
            g for g in grants if g["app_name"] == "Otter.ai" and g["grant_type"] == "delegated"
        )
        self.assertEqual(otter_delegated["principal"], "(tenant-wide — admin consent)")

    def test_application_permission_grant_present(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        otter_app_perm = next(
            g for g in grants if g["app_name"] == "Otter.ai" and g["grant_type"] == "application"
        )
        self.assertIn("Mail.Read", otter_app_perm["scopes"])
        self.assertEqual(otter_app_perm["risk_level"], mod.RISK_HIGH)
        self.assertEqual(otter_app_perm["principal"], "(tenant-wide — application permission)")

    def test_apps_rolled_up_by_app_id(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        self.assertIn("22222-otter-app-id", summary)
        # Otter: admin-consent delegated grant + app-permission grant -> 2 distinct "user" entries
        self.assertEqual(len(summary["22222-otter-app-id"]["users"]), 2)

    def test_verified_publisher_flag(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        self.assertTrue(summary["11111-chatgpt-app-id"]["verified_publisher"])
        self.assertFalse(summary["22222-otter-app-id"]["verified_publisher"])

    def test_allowlist_flagging(self):
        allowlist = {"client_ids": {"11111-chatgpt-app-id"}, "domains": set()}
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, allowlist=allowlist, _progress=False
        )
        chatgpt_grant = next(g for g in grants if g["app_name"] == "ChatGPT Enterprise")
        otter_grant = next(g for g in grants if g["app_name"] == "Otter.ai")
        self.assertEqual(chatgpt_grant["allowlisted"], "Y")
        self.assertEqual(otter_grant["allowlisted"], "N")

    def test_include_first_party_flag(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=True, _progress=False
        )
        self.assertIn("33333-teams-app-id", summary)

    def test_csv_outputs_are_well_formed(self):
        grants, summary = mod.enumerate_oauth_grants(
            token="fake-token", include_first_party=False, _progress=False
        )
        with tempfile.TemporaryDirectory() as tmp:
            grants_path = Path(tmp) / "grants.csv"
            summary_path = Path(tmp) / "summary.csv"
            mod.write_grants_csv(grants, grants_path)
            rows = mod.write_summary_csv(summary, summary_path)

            with open(grants_path, newline="", encoding="utf-8") as f:
                r = list(csv.DictReader(f))
            self.assertEqual(len(r), 3)  # chatgpt delegated + otter delegated + otter app-perm

            with open(summary_path, newline="", encoding="utf-8") as f:
                r2 = list(csv.DictReader(f))
            self.assertEqual(len(r2), 2)  # chatgpt, otter
            self.assertEqual(r2[0]["overall_risk"], "HIGH")


class TestAllowlistLoading(unittest.TestCase):
    def test_load_allowlist_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "allowlist.csv"
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["client_id", "domain"])
                w.writerow(["abc123-app-id", ""])
                w.writerow(["", "zoom.us"])
            allowlist = mod.load_allowlist(str(p))
            self.assertIn("abc123-app-id", allowlist["client_ids"])
            self.assertIn("zoom.us", allowlist["domains"])


class TestTokenAcquisition(unittest.TestCase):
    def test_raises_on_missing_access_token(self):
        with patch("m365_oauth_enum.ConfidentialClientApplication") as MockApp:
            instance = MockApp.return_value
            instance.acquire_token_for_client.return_value = {
                "error": "invalid_client",
                "error_description": "bad secret",
            }
            with self.assertRaises(RuntimeError):
                mod.get_app_token("tenant", "client", "secret")

    def test_returns_token_on_success(self):
        with patch("m365_oauth_enum.ConfidentialClientApplication") as MockApp:
            instance = MockApp.return_value
            instance.acquire_token_for_client.return_value = {"access_token": "fake-jwt"}
            token = mod.get_app_token("tenant", "client", "secret")
            self.assertEqual(token, "fake-jwt")


if __name__ == "__main__":
    unittest.main(verbosity=2)
