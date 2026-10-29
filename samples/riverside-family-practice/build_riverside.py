#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generates the Riverside Family Practice AI Data Exposure Register as print-ready HTML."""

import datetime

TODAY = datetime.date(2026, 10, 28)

def dplus(days):
    return (TODAY + datetime.timedelta(days=days)).strftime("%B %-d, %Y")

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ---------------------------------------------------------------------------
# Tool inventory / BAA-DPA matrix
# ---------------------------------------------------------------------------
# status: "approved" | "restricted" | "pending" | "unapproved"
TOOLS = [
    dict(name="ChatGPT (Free / Plus)", vendor="OpenAI", tier="Consumer (Free/Plus)",
         trains="Y", baa="N", dpa="N", approved="N", status="unapproved",
         users="6 of 12 providers", use="Drafting patient instructions, visit summaries, and appeal letters",
         risk="High — consumer tier trains on input by default and offers no BAA; PHI has been entered in session prompts."),
    dict(name="ChatGPT Team", vendor="OpenAI", tier="Team",
         trains="N", baa="N", dpa="N", approved="N", status="unapproved",
         users="Office manager", use="Drafting billing correspondence referencing patient accounts",
         risk="High — training is off by default on Team, but OpenAI does not offer a signable BAA on this tier; no DPA executed."),
    dict(name="Microsoft 365 Copilot", vendor="Microsoft", tier="Microsoft 365 Business Premium (tenant-wide)",
         trains="N", baa="Y", dpa="Y", approved="Y", status="approved",
         users="All front-office staff (5)", use="Drafting scheduling correspondence and internal memos within M365 apps",
         risk="Low — covered under the practice's executed Microsoft BAA and Online Services Terms; data stays within tenant boundary."),
    dict(name="Google Gemini (Workspace)", vendor="Google", tier="Google Workspace Business Standard (tenant-wide)",
         trains="N", baa="Y", dpa="Y", approved="Y", status="approved",
         users="3 administrative staff", use="Drafting patient-facing emails and internal documentation",
         risk="Low — Workspace core service; BAA and DPA executed with Google; content excluded from model training per Workspace terms."),
    dict(name="Google Gemini (personal app)", vendor="Google", tier="Consumer (personal Google account)",
         trains="Y", baa="N", dpa="N", approved="N", status="unapproved",
         users="2 providers (personal phones)", use="Ad hoc clinical question look-ups, occasionally pasting case details",
         risk="High — personal consumer account, outside tenant BAA coverage; used on personal devices outside MDM."),
    dict(name="Otter.ai", vendor="Otter.ai, Inc.", tier="Free / Basic",
         trains="Y", baa="N", dpa="N", approved="N", status="unapproved",
         users="2 providers", use="Transcribing patient phone calls and in-office consultations",
         risk="High — live transcription of patient conversations with no BAA; free tier retains and may use audio/text for training."),
    dict(name="Grammarly", vendor="Grammarly, Inc.", tier="Business",
         trains="N", baa="N", dpa="Y", approved="N", status="restricted",
         users="4 administrative staff", use="Grammar/tone checking on general correspondence",
         risk="Medium — Business tier excludes content from training and offers a DPA, but Grammarly does not offer a BAA; must remain PHI-free."),
    dict(name="Claude.ai (Free)", vendor="Anthropic", tier="Consumer (Free)",
         trains="Y", baa="N", dpa="N", approved="N", status="unapproved",
         users="Billing coordinator", use="Drafting insurance appeal letters referencing patient diagnoses",
         risk="High — free consumer tier, no BAA; PHI-containing appeal drafts have been entered in prompts."),
    dict(name="Perplexity", vendor="Perplexity AI, Inc.", tier="Free",
         trains="Y", baa="N", dpa="N", approved="N", status="unapproved",
         users="1 provider", use="General medical reference look-ups",
         risk="Medium — no PHI confirmed entered to date, but tool is unapproved and unmonitored; free tier trains on input."),
    dict(name="DeepL", vendor="DeepL SE", tier="Free",
         trains="Y", baa="N", dpa="N", approved="N", status="pending",
         users="Front desk (2 staff)", use="Translating patient instructions and intake forms into Spanish",
         risk="Medium-High — free tier retains/trains on submitted text, which includes patient names and clinical instructions; a Pro/API tier with a DPA is available and has not been adopted."),
    dict(name="Fireflies.ai", vendor="Fireflies.ai, Inc.", tier="Free",
         trains="Y", baa="N", dpa="N", approved="N", status="unapproved",
         users="3 providers (clinical staff meetings)", use="Transcribing weekly provider huddles that include patient case discussion",
         risk="High — automatic meeting transcription and storage of clinical case discussions with no BAA."),
    dict(name="Dragon Medical One", vendor="Nuance / Microsoft", tier="Enterprise (cloud, healthcare-specific)",
         trains="N", baa="Y", dpa="Y", approved="Y", status="approved",
         users="All 12 physicians", use="Clinical dictation directly into the EHR",
         risk="Low — purpose-built healthcare dictation platform; BAA executed with Nuance/Microsoft; long-standing approved tool."),
    dict(name="Canva", vendor="Canva Pty Ltd", tier="Free",
         trains="N", baa="N", dpa="N", approved="Restricted", status="restricted",
         users="Office manager", use="Designing patient education handouts and waiting-room signage",
         risk="Low, conditional — approved for non-PHI design work only; no BAA exists, so no patient identifiers may ever be entered."),
    dict(name="Zoom AI Companion", vendor="Zoom Communications, Inc.", tier="Zoom Business (AI Companion enabled tenant-wide)",
         trains="N", baa="Y*", dpa="Y", approved="N", status="pending",
         users="6 providers (telehealth visits)", use="Auto-generating visit summaries and transcripts during telehealth appointments",
         risk="High — Zoom offers a BAA covering AI Companion for qualifying healthcare accounts, but the practice has not executed the healthcare BAA addendum; feature is actively summarizing PHI-containing visits today."),
]
assert len(TOOLS) == 14

status_counts = {}
for t in TOOLS:
    status_counts[t["status"]] = status_counts.get(t["status"], 0) + 1

STATUS_LABEL = {"approved": "Approved", "restricted": "Approved — Non-PHI Only",
                "pending": "Pending / Wrong Tier", "unapproved": "Unapproved — Shadow IT"}
STATUS_CLASS = {"approved": "st-approved", "restricted": "st-restricted",
                "pending": "st-pending", "unapproved": "st-unapproved"}

def yn_pill(v):
    if v.startswith("Y"):
        cls = "yn-yes"
    elif v == "N":
        cls = "yn-no"
    else:
        cls = "yn-partial"
    return f'<span class="yn-pill {cls}">{esc(v)}</span>'

inventory_rows = []
for t in TOOLS:
    inventory_rows.append(f"""
        <tr>
          <td class="tool-name">{esc(t['name'])}<div class="tool-vendor">{esc(t['vendor'])}</div></td>
          <td>{esc(t['tier'])}</td>
          <td class="center">{esc(t['users'])}</td>
          <td>{esc(t['use'])}</td>
          <td><span class="status-pill {STATUS_CLASS[t['status']]}">{STATUS_LABEL[t['status']]}</span></td>
        </tr>""")
inventory_html = "\n".join(inventory_rows)

matrix_rows = []
for t in TOOLS:
    matrix_rows.append(f"""
        <tr>
          <td class="tool-name">{esc(t['name'])}</td>
          <td>{esc(t['tier'])}</td>
          <td class="center">{yn_pill(t['trains'])}</td>
          <td class="center">{yn_pill(t['baa'])}</td>
          <td class="center">{yn_pill(t['dpa'])}</td>
          <td class="center">{yn_pill(t['approved'])}</td>
          <td class="risk-note">{esc(t['risk'])}</td>
        </tr>""")
matrix_html = "\n".join(matrix_rows)

# ---------------------------------------------------------------------------
# 90-day remediation plan
# ---------------------------------------------------------------------------
PHASES = [
    dict(title="Phase 1 — Immediate Containment", window=f"{TODAY.strftime('%b %-d')} – {dplus(14)}",
         deadline=dplus(14), items=[
             ("Block", "ChatGPT (Free/Plus)", "Block at network/DNS level for office devices; issue written notice to the 6 identified users; no PHI is to be entered into any consumer AI tool effective immediately."),
             ("Block", "Claude.ai (Free)", "Block access on office devices; billing coordinator redirected to use only Microsoft 365 Copilot for correspondence drafting."),
             ("Block", "Otter.ai", "Discontinue use for any patient call or visit recording effective immediately; existing recordings/transcripts inventoried for retention review."),
             ("Block", "Fireflies.ai", "Disable Fireflies bot from provider meeting calendar invites; existing meeting transcripts exported and then deleted from Fireflies per data deletion request."),
             ("Block", "Google Gemini (personal app)", "Issue written notice to the 2 providers; personal-account AI use for any work purpose prohibited under interim policy pending MDM review."),
             ("Issue", "Interim Acceptable Use Notice", "Distribute the interim AI Acceptable Use Policy (see template below) to all staff for signature within 5 business days."),
         ]),
    dict(title="Phase 2 — Tier Correction & Vendor Agreements", window=f"{dplus(15)} – {dplus(30)}",
         deadline=dplus(30), items=[
             ("Decide & Execute", "Zoom AI Companion", "Practice manager to execute Zoom's healthcare BAA addendum covering AI Companion, or disable AI Companion tenant-wide if the addendum is not completed by the deadline."),
             ("Decommission / Upgrade", "ChatGPT Team", "Either decommission in favor of Microsoft 365 Copilot (already approved and BAA-covered), or evaluate ChatGPT Enterprise with a signed data processing agreement — decision owned by practice manager."),
             ("Restrict", "Canva", "Publish written restriction: design work only, no patient names, photos, or identifiers of any kind; office manager to confirm no historical PHI exists in existing designs."),
             ("Restrict", "Grammarly", "Confirm Business-tier training-exclusion setting is active for all 4 seats; publish written restriction prohibiting PHI in any text checked through Grammarly."),
         ]),
    dict(title="Phase 3 — Upgrade & Replace", window=f"{dplus(31)} – {dplus(60)}",
         deadline=dplus(60), items=[
             ("Upgrade", "DeepL", "Upgrade front desk to DeepL Pro (API/CAT tier) with a signed DPA and training opt-out confirmed; free-tier access removed from office devices."),
             ("Replace", "Perplexity", "Discontinue informal use; if clinical reference lookup is a recurring need, evaluate a vetted, BAA-eligible clinical reference tool through the practice's EHR vendor."),
             ("Train", "All staff", "Conduct a mandatory 45-minute AI tool training session covering the approved tool list, the Acceptable Use Policy, and how to request evaluation of a new tool."),
             ("Finalize", "Acceptable Use Policy", "Collect signed acknowledgment from all 12 physicians and all administrative staff; file signed copies in HR records."),
         ]),
    dict(title="Phase 4 — Verification & Cadence", window=f"{dplus(61)} – {dplus(90)}",
         deadline=dplus(90), items=[
             ("Audit", "Google Workspace / M365 admin consoles", "Re-pull OAuth-connected third-party app list from both admin consoles and reconcile against this register to confirm no new unapproved tools have appeared."),
             ("Re-survey", "All staff", "Issue a short follow-up survey confirming discontinued use of blocked tools and capturing any newly adopted tools."),
             ("Sign off", "Practice manager", "Practice manager reviews and signs off on remediation completion for each item in this plan; exceptions documented with a revised target date."),
             ("Schedule", "Annual re-inventory", f"Calendar the next full AI Data Exposure Register re-inventory for {(TODAY + datetime.timedelta(days=365)).strftime('%B %-d, %Y')} (annual cadence)."),
         ]),
]

phase_blocks = []
for ph in PHASES:
    rows = "".join(f"""
            <tr>
              <td class="act-pill">{esc(a)}</td>
              <td class="tool-name">{esc(tool)}</td>
              <td>{esc(desc)}</td>
            </tr>""" for a, tool, desc in ph["items"])
    phase_blocks.append(f"""
    <div class="phase-card">
      <div class="phase-head">
        <h3>{esc(ph['title'])}</h3>
        <div class="phase-window">{esc(ph['window'])} &middot; due <b>{esc(ph['deadline'])}</b></div>
      </div>
      <table class="phase-table">
        <thead><tr><th style="width:14%">Action</th><th style="width:24%">Tool / Item</th><th>Detail</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>""")
remediation_html = "\n".join(phase_blocks)

# ---------------------------------------------------------------------------
# HTML assembly
# ---------------------------------------------------------------------------

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Riverside Family Practice — AI Data Exposure Register</title>
<style>
  :root {{
    --teal: #0e5c56; --teal-light: #13786f; --accent: #0e5c56; --accent-light: #e5f3f1;
    --ink: #1c242e; --muted: #5b6672; --border: #d9e0e2; --bg-soft: #f5f9f8;
    --yes: #1b7a43; --yes-bg: #e5f5ea; --no: #b23b2e; --no-bg: #fbeae7;
    --partial-bg: #fbf1de; --partial: #a4700a;
    --approved: #1b7a43; --approved-bg: #e5f5ea;
    --restricted: #a4700a; --restricted-bg: #fbf1de;
    --pending: #b2650e; --pending-bg: #fdebd8;
    --unapproved: #b23b2e; --unapproved-bg: #fbeae7;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Arial, sans-serif; color: var(--ink); margin: 0; background: #fff; font-size: 13.5px; line-height: 1.5; }}
  .page {{ max-width: 1000px; margin: 0 auto; padding: 40px 48px 64px; }}

  .masthead {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid var(--teal); padding-bottom: 18px; margin-bottom: 28px; }}
  .masthead h1 {{ font-size: 22px; margin: 0 0 4px; color: var(--teal); letter-spacing: -0.2px; }}
  .masthead .sub {{ color: var(--muted); font-size: 13px; }}
  .masthead .meta {{ text-align: right; font-size: 12px; color: var(--muted); line-height: 1.7; }}
  .masthead .meta strong {{ color: var(--ink); }}
  .doc-tag {{ display: inline-block; background: var(--teal); color: #fff; font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; padding: 3px 9px; border-radius: 3px; text-transform: uppercase; margin-bottom: 8px; }}

  .summary {{ background: var(--bg-soft); border: 1px solid var(--border); border-left: 5px solid var(--teal); border-radius: 6px; padding: 20px 26px; margin-bottom: 30px; page-break-inside: avoid; }}
  .summary h2 {{ margin: 0 0 12px; font-size: 16px; color: var(--teal); }}
  .summary p {{ margin: 6px 0; font-size: 12.8px; }}
  .stat-row {{ display: flex; gap: 14px; margin: 14px 0 10px; flex-wrap: wrap; }}
  .stat-box {{ background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 10px 16px; min-width: 112px; text-align: center; }}
  .stat-box .num {{ font-size: 22px; font-weight: 700; color: var(--teal); line-height: 1.1; }}
  .stat-box.alert .num {{ color: var(--unapproved); }}
  .stat-box .lbl {{ font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }}

  h2.section-title {{ font-size: 16px; color: var(--teal); border-bottom: 2px solid var(--border); padding-bottom: 6px; margin: 40px 0 16px; }}
  p.lead {{ color: var(--muted); font-size: 12.5px; margin-bottom: 16px; }}

  table.inv-table, table.matrix-table, table.phase-table {{ width: 100%; border-collapse: collapse; font-size: 11.8px; }}
  table.inv-table th, table.matrix-table th {{ text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; color: #fff; background: var(--teal); padding: 8px; }}
  table.inv-table td, table.matrix-table td {{ padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  table.inv-table tr:nth-child(even) td, table.matrix-table tr:nth-child(even) td {{ background: #fafcfb; }}
  .tool-name {{ font-weight: 600; }}
  .tool-vendor {{ font-weight: 400; color: var(--muted); font-size: 10.5px; }}
  .center {{ text-align: center; }}
  .risk-note {{ color: var(--muted); font-size: 11.3px; width: 30%; }}

  .status-pill {{ display: inline-block; font-size: 10px; font-weight: 700; padding: 3px 9px; border-radius: 10px; white-space: nowrap; }}
  .st-approved {{ background: var(--approved-bg); color: var(--approved); }}
  .st-restricted {{ background: var(--restricted-bg); color: var(--restricted); }}
  .st-pending {{ background: var(--pending-bg); color: var(--pending); }}
  .st-unapproved {{ background: var(--unapproved-bg); color: var(--unapproved); }}

  .yn-pill {{ display: inline-block; font-size: 10.5px; font-weight: 700; padding: 2px 8px; border-radius: 9px; min-width: 20px; }}
  .yn-yes {{ background: var(--yes-bg); color: var(--yes); }}
  .yn-no {{ background: var(--no-bg); color: var(--no); }}
  .yn-partial {{ background: var(--partial-bg); color: var(--partial); }}

  .legend {{ display: flex; gap: 18px; flex-wrap: wrap; margin: 10px 0 18px; font-size: 11px; color: var(--muted); }}
  .legend span.dot {{ display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 5px; vertical-align: middle; }}

  /* AUP */
  .aup {{ background: var(--bg-soft); border: 1px solid var(--border); border-radius: 6px; padding: 24px 30px; font-size: 12.5px; }}
  .aup h3 {{ color: var(--teal); font-size: 14px; margin: 20px 0 8px; }}
  .aup h3:first-child {{ margin-top: 0; }}
  .aup p {{ margin: 6px 0; }}
  .aup ul {{ margin: 6px 0; padding-left: 20px; }}
  .aup li {{ margin-bottom: 4px; }}
  .ph {{ background: #fff3cd; color: #7a5c00; padding: 0 4px; border-radius: 3px; font-weight: 600; font-size: 11.5px; }}
  .sig-block {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 24px; }}
  .sig-line {{ border-top: 1px solid var(--ink); margin-top: 32px; padding-top: 4px; font-size: 11px; color: var(--muted); }}

  /* Remediation phases */
  .phase-card {{ border: 1px solid var(--border); border-radius: 6px; margin-bottom: 18px; overflow: hidden; page-break-inside: avoid; }}
  .phase-head {{ background: var(--accent-light); padding: 10px 16px; display: flex; justify-content: space-between; align-items: center; }}
  .phase-head h3 {{ margin: 0; font-size: 13.5px; color: var(--teal); }}
  .phase-window {{ font-size: 11px; color: var(--muted); }}
  table.phase-table th {{ text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); padding: 6px 12px; border-bottom: 1px solid var(--border); }}
  table.phase-table td {{ padding: 7px 12px; border-bottom: 1px solid #eef2f1; vertical-align: top; }}
  .act-pill {{ font-weight: 700; color: var(--teal); white-space: nowrap; }}

  .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 10.5px; color: var(--muted); display: flex; justify-content: space-between; }}
  .sample-watermark {{ position: fixed; top: 46%; left: 50%; transform: translate(-50%,-50%) rotate(-28deg); font-size: 86px; font-weight: 800; color: rgba(14,92,86,0.06); z-index: -1; letter-spacing: 0.05em; pointer-events: none; white-space: nowrap; }}

  @media print {{
    .page {{ padding: 0.3in 0.5in; }}
    .phase-card {{ break-inside: avoid; }}
    a {{ color: inherit; text-decoration: none; }}
  }}
  @page {{ margin: 0.5in; size: letter; }}
</style>
</head>
<body>
<div class="sample-watermark">SAMPLE — FICTIONAL DATA</div>
<div class="page">

  <div class="masthead">
    <div>
      <div class="doc-tag">AI Data Exposure Register</div>
      <h1>Riverside Family Practice</h1>
      <div class="sub">AI Tool Inventory, BAA/DPA Matrix, Acceptable Use Policy &amp; 90-Day Remediation Plan</div>
    </div>
    <div class="meta">
      <div><strong>Practice profile:</strong> 12-physician family medicine group, Tennessee</div>
      <div><strong>Prepared:</strong> {TODAY.strftime('%B %-d, %Y')}</div>
      <div><strong>Method:</strong> Staff survey (17 respondents) + Google Workspace &amp; M365 admin console OAuth review</div>
      <div><strong>Document support:</strong> Sui-Generis &mdash; AI Data Exposure Register</div>
    </div>
  </div>

  <div class="summary">
    <h2>Executive Summary</h2>
    <p>A survey of Riverside's 12 physicians and 5 administrative staff, cross-referenced against OAuth-connected
    third-party applications in the practice's Google Workspace and Microsoft 365 admin consoles, identified
    <b>14 distinct AI tools</b> in active use. Three are approved, tenant-governed tools with executed BAAs and DPAs.
    Two are in use under a restriction (no PHI permitted). The remaining nine are either unapproved consumer-tier
    tools in active use by clinical or administrative staff, or approved vendors being used at the wrong tier
    without the required agreements in place.</p>
    <p>Two tools &mdash; <b>Otter.ai</b> and <b>Fireflies.ai</b> &mdash; are currently being used to record and transcribe
    live patient conversations and clinical case discussions without a Business Associate Agreement. <b>Zoom AI
    Companion</b> is auto-generating telehealth visit summaries under the same condition. These three represent the
    highest-priority items in the remediation plan below.</p>
    <div class="stat-row">
      <div class="stat-box"><div class="num">14</div><div class="lbl">AI tools identified</div></div>
      <div class="stat-box"><div class="num">{status_counts.get('approved',0)}</div><div class="lbl">Approved</div></div>
      <div class="stat-box"><div class="num">{status_counts.get('restricted',0)}</div><div class="lbl">Restricted (non-PHI)</div></div>
      <div class="stat-box alert"><div class="num">{status_counts.get('pending',0)}</div><div class="lbl">Pending / wrong tier</div></div>
      <div class="stat-box alert"><div class="num">{status_counts.get('unapproved',0)}</div><div class="lbl">Unapproved</div></div>
    </div>
    <p style="color:var(--muted); font-size:11.5px;">This register documents current-state AI tool usage and associated data-handling terms as disclosed by vendor documentation and staff reporting as of the date above. It is a technical work product; it does not constitute a legal determination of HIPAA compliance or a legal opinion, and should be reviewed by the practice's legal counsel before reliance.</p>
  </div>

  <h2 class="section-title">1. AI Tool Inventory</h2>
  <p class="lead">Identified via staff survey (17 respondents, administered {dplus(-3) if False else TODAY.strftime('%B %-d, %Y')}) and OAuth-connected app review in Google Workspace and Microsoft 365 admin consoles.</p>
  <table class="inv-table">
    <thead><tr><th style="width:18%">Tool</th><th style="width:20%">Tier in Use</th><th style="width:12%">Users</th><th style="width:32%">Primary Use at Riverside</th><th style="width:18%">Status</th></tr></thead>
    <tbody>{inventory_html}</tbody>
  </table>

  <h2 class="section-title">2. BAA / DPA Matrix</h2>
  <p class="lead">Per-tool data-handling terms. "Trains on Input" reflects the vendor's policy for the tier actually in use at Riverside, which may differ from the vendor's enterprise-tier policy.</p>
  <div class="legend">
    <span><span class="dot" style="background:var(--yes)"></span>Yes</span>
    <span><span class="dot" style="background:var(--no)"></span>No</span>
    <span><span class="dot" style="background:var(--partial)"></span>Partial / conditional</span>
    <span>* Zoom offers a BAA addendum covering AI Companion for qualifying healthcare accounts; Riverside has not yet executed it.</span>
  </div>
  <table class="matrix-table">
    <thead><tr><th style="width:17%">Tool</th><th style="width:22%">Vendor Tier</th><th style="width:9%">Trains on Input</th><th style="width:9%">BAA Available</th><th style="width:9%">DPA in Place</th><th style="width:9%">Approved for PHI</th><th>Risk Note</th></tr></thead>
    <tbody>{matrix_html}</tbody>
  </table>

  <h2 class="section-title">3. Acceptable Use Policy — Template</h2>
  <p class="lead">Drafted for adoption by Riverside leadership; placeholders in <span class="ph">highlight</span> require practice-specific input before distribution. Final policy should be reviewed by the practice's legal counsel.</p>
  <div class="aup">
    <h3>Artificial Intelligence Acceptable Use Policy</h3>
    <p><b>Practice:</b> <span class="ph">[PRACTICE LEGAL NAME]</span> &nbsp; <b>Effective date:</b> <span class="ph">[EFFECTIVE DATE]</span> &nbsp; <b>Policy owner:</b> <span class="ph">[NAME / TITLE, e.g., Practice Manager]</span> &nbsp; <b>Review cycle:</b> <span class="ph">[ANNUALLY / SEMI-ANNUALLY]</span>, next review <span class="ph">[REVIEW DATE]</span></p>

    <h3>1. Purpose</h3>
    <p>This policy governs the use of artificial intelligence (AI) tools, including generative AI chatbots, transcription services, and AI-enabled features within approved software, by all employees, contractors, and affiliated providers of <span class="ph">[PRACTICE NAME]</span>. Its purpose is to prevent unauthorized disclosure of protected health information (PHI) and to establish a clear, auditable process for evaluating and approving new AI tools.</p>

    <h3>2. Approved Tools</h3>
    <p>Only tools listed on the current Approved AI Tool List may be used for any task involving patient information. As of <span class="ph">[EFFECTIVE DATE]</span>, the Approved AI Tool List consists of:</p>
    <ul>
      <li><span class="ph">[Microsoft 365 Copilot — tenant license, scheduling and internal correspondence]</span></li>
      <li><span class="ph">[Google Gemini (Workspace) — tenant license, patient-facing email drafting]</span></li>
      <li><span class="ph">[Dragon Medical One — clinical dictation into the EHR]</span></li>
    </ul>
    <p>Tools marked "Restricted" may be used only for the specific non-PHI purpose documented in the current AI Data Exposure Register (e.g., <span class="ph">[Canva for patient-education design work, with no patient identifiers entered]</span>). No other AI tool may be used for any work purpose unless formally approved under Section 4.</p>

    <h3>3. Prohibited Conduct</h3>
    <ul>
      <li>Entering any patient name, date of birth, medical record number, diagnosis, treatment detail, photograph, or other PHI into any AI tool not on the Approved AI Tool List.</li>
      <li>Using a personal (non-practice-issued) account to access any AI tool for a work purpose.</li>
      <li>Recording or transcribing any patient conversation, visit, or clinical discussion using a tool without an executed BAA.</li>
      <li>Installing or enabling browser extensions, add-ins, or AI features in approved software without prior written approval.</li>
    </ul>

    <h3>4. Requesting a New Tool</h3>
    <p>Employees who wish to use an AI tool not on the Approved AI Tool List must submit a request to <span class="ph">[POLICY OWNER]</span> describing the intended use, the data involved, and the vendor. No tool may be used for PHI-related work until it has a reviewed BAA (where PHI is involved), a signed DPA, and has been added to the Approved AI Tool List in writing.</p>

    <h3>5. Training &amp; Acknowledgment</h3>
    <p>All employees and providers must complete AI acceptable use training within 30 days of hire and upon any material policy update, and must sign the acknowledgment below.</p>

    <h3>6. Enforcement</h3>
    <p>Violations of this policy will be addressed under <span class="ph">[PRACTICE NAME]</span>'s standard HR disciplinary process and, where applicable, reported under the practice's HIPAA breach notification procedure.</p>

    <div class="sig-block">
      <div><div class="sig-line">Employee signature &nbsp;&nbsp; Date: <span class="ph">[DATE]</span></div></div>
      <div><div class="sig-line">Print name</div></div>
    </div>
  </div>

  <h2 class="section-title">4. 90-Day Remediation Plan</h2>
  <p class="lead">Four two-to-four-week phases from {TODAY.strftime('%B %-d, %Y')} to {dplus(90)}, ordered by risk. Each item names a specific action (block, restrict, upgrade, replace, or decommission) and an owner-ready deadline.</p>
  {remediation_html}

  <div class="footer">
    <div>Riverside Family Practice &mdash; AI Data Exposure Register &mdash; Fictional sample for demonstration purposes only.</div>
    <div>Prepared by Sui-Generis &mdash; Knoxville, TN</div>
  </div>

</div>
</body>
</html>
"""

with open("/tmp/deliverables/riverside-ai-exposure-register.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Wrote riverside-ai-exposure-register.html")
print("Status counts:", status_counts)
