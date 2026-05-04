
# Microsoft Template - Microsoft Security Threat Model Stencil #
https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling

![](https://i.imgur.com/M6o7wJT.png)

## Release Notes 
**Release 10 (2026-05-04)**
## What this update adds

## STRIDE+A distribution

| Category | Count | Threats |
|---|---|---|
| S — Spoofing | 2 | TH293, TH329 |
| T — Tampering | 8 | TH291, TH297, TH301, TH302, TH303, TH312, TH316, TH318 |
| R — Repudiation | 1 | TH326 |
| I — Information Disclosure | 20 | TH290, TH295, TH296, TH298, TH300, TH304, TH305, TH306, TH307, TH309, TH310, TH311, TH313, TH314, TH315, TH319, TH321, TH322, TH323, TH325 |
| D — Denial of Service | 2 | TH327, TH328 |
| E — Elevation of Privilege | 7 | TH292, TH294, TH299, TH308, TH317, TH320, TH324 |
| A — Abuse | 0 | (no Azure-platform-specific abuse pattern distinct from generic LLM/AI abuse already in TH219, TH242) |

The I-heavy distribution accurately reflects the dominant Azure threat surface: most platform-level risk concentrates in misconfigured access controls, over-broad RBAC scopes, and key/secret exposure — categories that map to Information Disclosure.

## Threats grouped by theme

### Identity, Secrets, Key Management

**TH290 — Over-broad Key Vault access policies / RBAC** *(I / High)*
A single principal granted Key Vault Administrator or broad Get/List can read every secret. Co-locating multi-application secrets concentrates blast radius.

**TH291 — Key Vault irreversible destruction** *(T / High)*
Without soft-delete and purge protection, secrets and keys can be permanently destroyed; encrypted data becomes unrecoverable.

**TH292 — User-assigned managed identity sprawl** *(E / High)*
A user-assigned MI attached to many resources concentrates privilege; compromise of any one resource yields the identity's full role set.

**TH293 — Legacy authentication bypasses MFA / Conditional Access** *(S / High)*
Basic auth, IMAP/POP/SMTP AUTH, older MAPI bypass modern auth controls — stolen-password access works without MFA challenge.

### Compute Platforms

**TH294 — AKS cluster-wide RBAC bindings** *(E / High)*
ClusterRoleBindings to cluster-admin/edit/admin grant exec-into-pod, secret-read, and ServiceAccount impersonation across namespaces.

**TH295 — AKS image pulls from untrusted registries / mutable tags** *(I / High)*
Without admission control or registry allowlisting, AKS pulls any image; moving tags swap behavior silently.

**TH296 — App Service settings / connection strings exposed via SCM** *(I / High)*
Configuration values and connection strings are readable to any site Contributor and exposed through Kudu environment.

**TH297 — Functions HTTP trigger with anonymous auth or weak keys** *(T / High)*
Anonymous HTTP triggers are publicly invokable; function/host keys are long-lived shared secrets.

**TH298 — Service Fabric shared admin certificate** *(I / Medium)*
A shared admin certificate masks per-user attribution and creates a single point of compromise.

**TH299 — Batch pool job submission as code execution** *(E / High)*
Anyone with submit rights runs arbitrary code with the pool's identity and network reach.

### Integration / API / Messaging

**TH300 — APIM subscription keys as shared secrets** *(I / High)*
Long-lived keys, no per-caller attribution; if embedded in client code or leaked, anyone with the key calls the APIs.

**TH301 — APIM policy tampering with tenant-wide effect** *(T / High)*
Policy edits affect every consumer of the APIs, including back-end credential injection and rate-limit removal.

**TH302 — Logic App workflow tampering / trigger URL replay** *(T / High)*
HTTP-triggered Logic Apps expose callback URLs containing SAS-style signatures; leakage = invocation rights.

**TH303 — Event Grid subscription endpoint hijacking** *(T / Medium)*
Subscription destination updates may not re-validate webhook ownership, allowing redirection to attacker-controlled URLs.

**TH304 — Service Bus broad SAS / namespace-scoped access** *(I / High)*
Namespace-level SAS with Manage rights grants access to every queue and topic in the namespace.

**TH305 — Stream Analytics output fan-out across trust domains** *(I / High)*
Adding an output sink begins continuous data export with no per-record consent.

### Data Services

**TH306 — Cosmos DB master key exposure** *(I / High)*
Master keys grant full account access; embedding them in clients exposes every database.

**TH307 — Storage anonymous container access** *(I / High)*
Public-blob containers + public network access expose blobs to internet enumeration.

**TH308 — SQL Managed Instance dual auth plane** *(E / High)*
SQL-level admins are separate from Azure RBAC; lifecycle deprovisioning may not remove SQL access.

**TH309 — Azure AI Search admin/query key exposure** *(I / High)*
Admin keys = full management; query keys allow document enumeration without security trimming.

**TH310 — Redis cache as derivative data store** *(I / Medium)*
Cached values inherit only Redis-level auth, not source-system row/column filters.

**TH311 — ADLS Gen2 RBAC + POSIX ACL interaction** *(I / High)*
Removing RBAC does not remove ACLs; access can persist after intended deprovisioning.

**TH312 — Data Factory SHIR credential concentration** *(T / High)*
Self-hosted integration runtime hosts cache credentials for every linked service it brokers.

**TH313 — Synapse / Databricks notebook results persistence** *(I / Medium)*
Query results, history, and cluster logs persist outside source-system access controls.

**TH314 — Azure Backup restore as indirect read path** *(I / High)*
Restore-to-alternative-location bypasses source-resource access controls.

### Operations / Observability

**TH315 — Log Analytics / Sentinel central data exposure** *(I / High)*
Workspace reader rights expose tenant-wide telemetry, identity activity, and application data.

**TH316 — Automation runbook as privileged code execution** *(T / High)*
Runbooks execute under Run As / managed identity, often with broad scope.

### DevOps

**TH317 — Azure DevOps YAML pipeline supply chain** *(E / High)*
Pipeline editors and PR submitters can run code under agent identity with attached secrets.

**TH318 — Azure DevOps branch policy bypass** *(T / High)*
Project administrators and bypass-granted service accounts can push directly to protected branches.

### Network Boundaries

**TH319 — NSG over-permissive rules** *(I / Medium)*
Any-any rules created in troubleshooting persist as lateral movement paths.

**TH320 — Inherited RBAC at MG/Subscription scope** *(E / High)*
Owner/Contributor at high scope concentrates privilege across every current and future resource.

**TH321 — VNet peering / VPN / service endpoint reachability sprawl** *(I / High)*
Network topology changes silently extend resource reachability across trust domains.

**TH322 — Geo-replication residency violation** *(I / High)*
Paired-region replication may breach residency requirements (GDPR, sectoral, sovereignty).

### SaaS Integration

**TH323 — Microsoft 365 oversharing through link defaults** *(I / High)*
Anyone-with-link sharing can be enabled by users with no per-document approval.

**TH324 — Power Automate citizen-developer flows** *(E / Medium)*
End-user flows execute on company systems under user identities, bypassing IT change control.

**TH325 — OAuth consent persistence beyond user lifecycle** *(I / High)*
SaaS app consents persist after user offboarding unless explicitly revoked.

### Cross-cutting

**TH326 — Diagnostic settings disabled or fragmented** *(R / Medium)*
Without enforced diagnostic settings to a central workspace, audit trails are incomplete.

**TH327 — DDoS exposure without DDoS Protection Standard** *(D / Medium)*
Public IPs with only basic protection are vulnerable to targeted volumetric and L7 attacks.

**TH328 — Cost-based denial of service through metered consumption** *(D / High)*
Functions, Logic Apps, Cosmos serverless, Cognitive Services billed per use; attacker load → budget exhaustion → outage.

**TH329 — Power BI Embedded master user impersonation** *(S / Medium)*
Master-user pattern collapses per-end-user attribution into a shared service identity.

## Stencil coverage

After this round, **every Azure stencil in the template has at least one dedicated threat** — Azure Services (47), Azure Data Services (35), Azure Boundaries (10), and Cloud SaaS (7).

| Group | Stencils with ≥1 threat (before → after) |
|---|---|
| Azure Services | 12/47 → 47/47 |
| Azure Data Services | 10/35 → 35/35 |
| Azure Boundaries | 2/10 → 10/10 |
| Cloud SaaS | 2/7 → 7/7 |

