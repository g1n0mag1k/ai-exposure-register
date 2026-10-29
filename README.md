# ai-exposure-register

AI Data Exposure Register for HIPAA-covered entities and professional firms — tool inventory, BAA/DPA matrix, acceptable-use policy template, and 90-day remediation plan.

Productized by Sui-Generis LLC. See [`ai-tool-compliance-db`](https://github.com/g1n0mag1k/ai-tool-compliance-db) for the public reference database this toolchain cross-references against.

## Layout

- **`samples/riverside-family-practice/`** — a complete fictional sample deliverable (12-physician Tennessee practice) used as a sales asset: 14-tool AI inventory, BAA/DPA matrix, acceptable-use policy template, and 90-day remediation plan, as a print-ready HTML file (`riverside-ai-exposure-register.html`), plus the generator script (`build_riverside.py`).
- **`scripts/google-workspace-oauth/`** — enumerates every third-party OAuth app grant across a client's Google Workspace domain (via the Admin SDK Directory API), classifies each by risk, and optionally flags approved/unapproved against an allowlist (e.g. an export of `ai-tool-compliance-db`). See the script's own `--help` for full setup instructions and a usage walkthrough.
- **`scripts/m365-oauth/`** — the Microsoft 365 / Entra ID counterpart: enumerates every third-party Enterprise Application consented into a client's tenant (via Microsoft Graph — `servicePrincipals`, `oauth2PermissionGrants` for delegated/user consent, and `appRoleAssignments` for tenant-wide application permissions), classifies each by risk, and optionally flags approved/unapproved against the same allowlist format. See the script's own `--help` for full setup instructions and a usage walkthrough.

## Pipeline (current state)

1. Run the Google Workspace and/or M365 OAuth enumeration script(s) against a client's tenant(s) → `oauth_apps_summary_<domain>_<date>.csv` / `m365_oauth_apps_summary_<tenant>_<date>.csv`.
2. Cross-reference that summary against [`ai-tool-compliance-db`](https://github.com/g1n0mag1k/ai-tool-compliance-db)'s `cross_reference.py` → a BAA/DPA matrix CSV.
3. Merge the matrix into the register template (currently hand-assembled per the `samples/` example; a standalone Jinja-style template is a planned follow-up).

Still open: a standalone reusable HTML template for the register (currently the sample's generator script is the de facto template).

Client intake form (covers both the AI Data Exposure Register and Deal Unlocker) lives in its own repo: [`sui-generis-intake`](https://github.com/g1n0mag1k/sui-generis-intake).
