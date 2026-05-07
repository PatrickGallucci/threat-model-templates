
# Microsoft Template - Microsoft Security Threat Model Stencil #
https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling


![](https://i.imgur.com/M6o7wJT.png)

## Release Notes 
**Release 12 (2026-05-06)**
## What this update adds
- [Microsoft Template Threat Catalog](ThreatCatalog.md)
- Added sample PowerShell script to create model from Azure Subscription [New-AzureThreatModel.ps1](/Scripts/New-AzureThreatModel.ps1)

## STRIDE+A distribution

| Category | Count | Threats |
|---|---|---|
| S — Spoofing | 1 | TH381 |
| T — Tampering | 5 | TH364, TH366, TH368, TH370, TH375 |
| R — Repudiation | 1 | TH379 |
| I — Information Disclosure | 17 | TH356, TH357, TH358, TH360, TH361, TH362, TH363, TH365, TH367, TH369, TH371, TH373, TH374, TH376, TH377, TH378, TH380 |
| D — Denial of Service | 1 | TH382 |
| E — Elevation of Privilege | 2 | TH359, TH372 |
| A — Abuse | 0 | (no SaaS-distinct abuse pattern beyond LLM/AI abuse already in TH219, TH242) |

The I-heavy distribution accurately reflects the SaaS threat surface: most platform-level risk concentrates in oversharing, federation gaps, and content exposure through legitimate sharing features used incorrectly.

## Stencil coverage after this round

Every SaaS stencil now has at least 2 dedicated threats from this round:

| Stencil | New threats targeting it (this round) |
|---|---|
| GE.CS (parent) | TH356, TH379, TH380 |
| Adobe | TH356, TH357, TH358, TH359, TH374, TH375, TH379, TH380, TH382 |
| ADP | TH356, TH358, TH359, TH367, TH379, TH380, TH382 |
| Aero | TH356, TH358, TH359, TH360, TH361, TH362, TH379, TH380, TH381 |
| Box Storage | TH356, TH357, TH358, TH359, TH361, TH362, TH376, TH379, TH380, TH382 |
| Dynamics CRM | TH358, TH359, TH372, TH379, TH380, TH382 |
| Dynamics CRM Portal | TH372, TH373 |
| Expensify | TH356, TH358, TH359, TH367, TH368, TH379, TH380, TH382 |
| Jira | TH356, TH357, TH358, TH359, TH360, TH361, TH362, TH379, TH380, TH381, TH382 |
| Microsoft 365 | TH356, TH357, TH358, TH359, TH361, TH362, TH379, TH380, TH381, TH382 |
| Monday | TH356, TH357, TH358, TH359, TH360, TH361, TH362, TH379, TH380, TH381, TH382 |
| Notion | TH356, TH357, TH358, TH359, TH360, TH361, TH362, TH379, TH380, TH381, TH382 |
| Postmark | TH356, TH358, TH359, TH369, TH370, TH379, TH380, TH382 |
| Power Automate | TH356, TH358, TH359, TH378, TH379, TH380, TH382 |
| Power BI Platform | TH356, TH358, TH359, TH377, TH379, TH380 |
| Salesforce | TH356, TH357, TH358, TH359, TH371, TH372, TH379, TH380, TH381, TH382 |
| Trello | TH356, TH357, TH358, TH359, TH360, TH361, TH362, TH379, TH380, TH381, TH382 |
| Slack | TH356, TH357, TH358, TH359, TH361, TH363, TH364, TH379, TH380, TH381, TH382 |
| Zoom | TH356, TH357, TH358, TH359, TH361, TH365, TH366, TH379, TH380, TH381, TH382 |
| Workday | TH356, TH358, TH359, TH367, TH379, TH380, TH382 |

## Threats grouped by theme

### Cross-cutting SaaS Governance

**TH356 — SaaS not federated to corporate IdP** *(I / High)*
Local accounts persist after IdP deactivation; SCIM provisioning is the right answer.

**TH357 — SaaS marketplace third-party integrations** *(I / High)*
End-user OAuth grants survive offboarding and accumulate as standing access for vendors of unknown trust.

**TH358 — SaaS audit logs not exported to central SIEM** *(I / Medium)*
Each SaaS retains logs locally with limited retention; cross-SaaS investigation requires central correlation.

**TH359 — SaaS admin role concentration** *(E / High)*
Static admin roles without PIM/JIT controls concentrate tenant-wide privilege.

**TH379 — Vendor audit retention windows** *(R / Medium)*
Retention may not survive the timeline of an investigation; export to tenant-controlled archive is the answer.

**TH380 — SaaS data residency and subprocessor lists** *(I / High)*
Vendor region selection and subprocessor changes can move data across regulatory boundaries the tenant did not authorize.

### Work Management / Productivity (Jira, Monday, Trello, Notion, Aero)

**TH360 — Public-link sharing** *(I / High)*
'Publish to web' / 'anyone with link' features enable end-user oversharing of boards, pages, tickets.

**TH361 — Secrets pasted into tickets/cards/pages** *(I / Medium)*
Credentials, tokens, customer PII pasted for collaboration persist in revision history and search index.

**TH362 — External guest workspace visibility** *(I / Medium)*
Guests typically see more than the inviter intended; cross-references and search surface unrelated workspace content.

### Team Communication (Slack, Zoom)

**TH363 — Slack indefinite message retention** *(I / Medium)*
Default retention preserves years of channels and DMs; a workspace breach exfiltrates accumulated content.

**TH364 — Slack webhook URL leakage** *(T / High)*
Webhook URLs are bearer credentials; leakage enables internal phishing via authentic-looking automation messages.

**TH365 — Zoom cloud recording exposure** *(I / High)*
Default share settings + transcripts + chat logs make sensitive meetings reachable beyond original participants.

**TH366 — Zoom meeting hijack via leaked IDs** *(T / Medium)*
Meetings without passcodes/waiting rooms enable Zoombombing and eavesdropping on confidential discussions.

### HR / Finance / Payroll (Workday, ADP, Expensify)

**TH367 — HR/payroll PII data classification** *(I / High)*
Compensation, tax IDs, banking, dependent info, medical — uniformly highest sensitivity, warrants stricter baseline controls.

**TH368 — Expense fraud through receipt manipulation** *(T / Medium)*
OCR-edited amounts, synthetic receipts, category gaming — design-time controls on validation rules and approvals.

### Mail / Transactional API (Postmark)

**TH369 — Transactional-email API token leakage** *(I / High)*
Leaked tokens enable SPF/DKIM/DMARC-passing phishing from verified organization domains.

**TH370 — Email template tampering** *(T / High)*
Server-side templates modified to convert legitimate transactional flows (password reset, invoice) into phishing/malware delivery.

### CRM (Salesforce, Dynamics CRM)

**TH371 — Salesforce sharing model complexity** *(I / High)*
OWD + role hierarchy + sharing rules + manual sharing + Apex sharing → effective access drift over time.

**TH372 — CRM integration users with broad permissions** *(E / High)*
Shared System Administrator-equivalent service accounts spread across many integrations.

**TH373 — Dynamics CRM Portal Entity Permissions** *(I / High)*
Portal permissions are a separate model from internal CRM security; Global-scope grants can expose all rows of a table.

### Creative / Document (Adobe)

**TH374 — Creative Cloud Library oversharing** *(I / Medium)*
Organization-scoped libraries expose unreleased designs and embedded customer data with retained metadata.

**TH375 — Adobe Sign workflow tampering** *(T / High)*
Workflow-design rights enable swapping signers, changing document versions, or redirecting completion.

### File Storage (Box)

**TH376 — Box anonymous link sharing** *(I / High)*
'Anyone with link' default makes folders globally readable to anyone obtaining the URL.

### Power BI / Power Automate

**TH377 — Power BI Publish to Web** *(I / High)*
Public URL + queryable underlying dataset = unauthenticated read of report content and dataset.

**TH378 — Power Automate connector DLP gaps** *(I / High)*
Without DLP policies, flows bridge business and consumer connectors and become exfil channels.

### Cross-SaaS Identity and Reliability

**TH381 — Display-name impersonation** *(S / Medium)*
User-controllable display names enable internal social-engineering: 'CEO Name', 'IT Help Desk'.

**TH382 — Tenant API rate-limit exhaustion** *(D / Medium)*
One runaway integration starves all other consumers of the same tenant.

