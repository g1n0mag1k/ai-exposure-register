#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smoke test for gworkspace_oauth_enum.py.

This does NOT call Google's API. It mocks the Directory API client's
response shapes (taken from Google's documented Admin SDK schemas) and
exercises the real enumeration, risk-classification, and CSV-writing
logic end to end, so the script's logic can be verified without live
Workspace credentials.

Run: python3 test_gworkspace_oauth_enum.py
"""

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import gworkspace_oauth_enum as mod


def make_fake_service(users_pages, tokens_by_user):
    """
    Builds a MagicMock standing in for the Directory API `service` object,
    wired so that:
      service.users().list(...).execute() walks through `users_pages`
      service.tokens().list(userKey=...).execute() returns tokens_by_user[userKey]
    """
    service = MagicMock()

    # --- users().list().execute() with pagination ---
    pages = list(users_pages)  # list of response dicts, in order

    def users_list(**kwargs):
        req = MagicMock()
        req.execute.return_value = pages.pop(0)
        return req

    service.users.return_value.list.side_effect = users_list

    # --- tokens().list(userKey=...).execute() ---
    def tokens_list(userKey, **kwargs):
        req = MagicMock()
        items = tokens_by_user.get(userKey, [])
        if items is None:
            # simulate a 404 (no tokens) by raising HttpError
            from googleapiclient.errors import HttpError
            resp = MagicMock()
            resp.status = 404
            raise HttpError(resp, b"not found")
        req.execute.return_value = {"items": items}
        return req

    service.tokens.return_value.list.side_effect = tokens_list

    return service


class TestScopeClassification(unittest.TestCase):
    def test_high_risk_gmail(self):
        level, desc = mod.classify_scope("https://mail.google.com/")
        self.assertEqual(level, mod.RISK_HIGH)

    def test_high_risk_drive_full(self):
        level, _ = mod.classify_scope("https://www.googleapis.com/auth/drive\"")
        self.assertEqual(level, mod.RISK_HIGH)

    def test_medium_risk_drive_file(self):
        level, _ = mod.classify_scope("https://www.googleapis.com/auth/drive.file")
        self.assertEqual(level, mod.RISK_MEDIUM)

    def test_info_sign_in_only(self):
        level, _ = mod.classify_scope("https://www.googleapis.com/auth/userinfo.email")
        self.assertEqual(level, mod.RISK_INFO)

    def test_unknown_scope_defaults_medium(self):
        level, desc = mod.classify_scope("https://www.googleapis.com/auth/some.new.scope")
        self.assertEqual(level, mod.RISK_MEDIUM)
        self.assertIn("Unclassified", desc)

    def test_app_risk_is_max_of_scopes(self):
        scopes = [
            "https://www.googleapis.com/auth/userinfo.email",
            "https://mail.google.com/",
        ]
        self.assertEqual(mod.app_risk_from_scopes(scopes), mod.RISK_HIGH)


class TestEnumerationEndToEnd(unittest.TestCase):
    def setUp(self):
        self.users_page = {
            "users": [
                {"primaryEmail": "alice@riverside.example", "suspended": False, "archived": False},
                {"primaryEmail": "bob@riverside.example", "suspended": False, "archived": False},
                {"primaryEmail": "carol@riverside.example", "suspended": True, "archived": False},
            ]
            # no nextPageToken -> single page
        }

        self.tokens_by_user = {
            # Alice has ChatGPT (high-risk Gmail scope) and a sign-in-only app
            "alice@riverside.example": [
                {
                    "clientId": "12345-chatgpt.apps.googleusercontent.com",
                    "displayText": "ChatGPT",
                    "scopes": ["https://mail.google.com/", "https://www.googleapis.com/auth/userinfo.email"],
                    "nativeApp": False,
                    "anonymous": False,
                },
                {
                    "clientId": "99999-zoom.apps.googleusercontent.com",
                    "displayText": "Zoom",
                    "scopes": ["https://www.googleapis.com/auth/userinfo.email", "openid"],
                    "nativeApp": False,
                    "anonymous": False,
                },
            ],
            # Bob also uses ChatGPT (same client_id -> should roll up together) plus Otter
            "bob@riverside.example": [
                {
                    "clientId": "12345-chatgpt.apps.googleusercontent.com",
                    "displayText": "ChatGPT",
                    "scopes": ["https://mail.google.com/"],
                    "nativeApp": False,
                    "anonymous": False,
                },
                {
                    "clientId": "55555-otter.apps.googleusercontent.com",
                    "displayText": "Otter.ai",
                    "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
                    "nativeApp": False,
                    "anonymous": False,
                },
            ],
        }

        self.service = make_fake_service([self.users_page], self.tokens_by_user)

    def test_suspended_user_excluded_by_default(self):
        grants, summary = mod.enumerate_oauth_grants(
            self.service, "riverside.example", include_suspended=False
        )
        emails = {g["user_email"] for g in grants}
        self.assertNotIn("carol@riverside.example", emails)

    def test_grants_count(self):
        grants, summary = mod.enumerate_oauth_grants(
            self.service, "riverside.example", include_suspended=False
        )
        # Alice: 2 grants, Bob: 2 grants = 4 total
        self.assertEqual(len(grants), 4)

    def test_apps_rolled_up_by_client_id(self):
        grants, summary = mod.enumerate_oauth_grants(
            self.service, "riverside.example", include_suspended=False
        )
        chatgpt_id = "12345-chatgpt.apps.googleusercontent.com"
        self.assertIn(chatgpt_id, summary)
        self.assertEqual(len(summary[chatgpt_id]["users"]), 2)  # alice + bob

    def test_overall_risk_high_for_chatgpt(self):
        grants, summary = mod.enumerate_oauth_grants(
            self.service, "riverside.example", include_suspended=False
        )
        chatgpt_id = "12345-chatgpt.apps.googleusercontent.com"
        risk = mod.app_risk_from_scopes(summary[chatgpt_id]["scopes"])
        self.assertEqual(risk, mod.RISK_HIGH)

    def test_allowlist_flagging(self):
        allowlist = {"client_ids": {"99999-zoom.apps.googleusercontent.com"}, "domains": set()}
        grants, summary = mod.enumerate_oauth_grants(
            self.service, "riverside.example", include_suspended=False, allowlist=allowlist
        )
        zoom_grant = next(g for g in grants if g["app_name"] == "Zoom")
        chatgpt_grant = next(g for g in grants if g["app_name"] == "ChatGPT")
        self.assertEqual(zoom_grant["allowlisted"], "Y")
        self.assertEqual(chatgpt_grant["allowlisted"], "N")

    def test_csv_outputs_are_well_formed(self):
        grants, summary = mod.enumerate_oauth_grants(
            self.service, "riverside.example", include_suspended=False
        )
        with tempfile.TemporaryDirectory() as tmp:
            grants_path = Path(tmp) / "grants.csv"
            summary_path = Path(tmp) / "summary.csv"
            mod.write_grants_csv(grants, grants_path)
            rows = mod.write_summary_csv(summary, summary_path)

            with open(grants_path, newline="", encoding="utf-8") as f:
                r = list(csv.DictReader(f))
            self.assertEqual(len(r), 4)

            with open(summary_path, newline="", encoding="utf-8") as f:
                r2 = list(csv.DictReader(f))
            # 3 unique apps: chatgpt, zoom, otter
            self.assertEqual(len(r2), 3)
            # highest risk (ChatGPT, HIGH, 2 users) should sort first
            self.assertEqual(r2[0]["app_name"], "ChatGPT")
            self.assertEqual(r2[0]["overall_risk"], "HIGH")
            self.assertEqual(r2[0]["user_count"], "2")

    def test_404_treated_as_no_tokens_not_error(self):
        tokens_by_user = dict(self.tokens_by_user)
        tokens_by_user["bob@riverside.example"] = None  # simulate 404
        service = make_fake_service([self.users_page], tokens_by_user)
        grants, summary = mod.enumerate_oauth_grants(
            service, "riverside.example", include_suspended=False
        )
        bob_grants = [g for g in grants if g["user_email"] == "bob@riverside.example"]
        self.assertEqual(bob_grants, [])


class TestAllowlistLoading(unittest.TestCase):
    def test_load_allowlist_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "allowlist.csv"
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["client_id", "domain"])
                w.writerow(["abc123.apps.googleusercontent.com", ""])
                w.writerow(["", "zoom.us"])
            allowlist = mod.load_allowlist(str(p))
            self.assertIn("abc123.apps.googleusercontent.com", allowlist["client_ids"])
            self.assertIn("zoom.us", allowlist["domains"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
