
# Microsoft Template - Microsoft Security Threat Model Stencil #
https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling

![](https://i.imgur.com/M6o7wJT.png)

## Release Notes 
**Release 9 (2026-04-29)**
## What this update adds

The uploaded template already contained 30 Fabric threats from the previous round (TH245–TH274). Reviewing them against the user's Fabric skill files surfaced specific gaps that round did not address. This update adds **15 new threats (TH275–TH289)** focused on those gaps.

| | Before | After |
|---|---|---|
| Total ThreatTypes | 211 | 226 |
| Total Fabric-stencil threats | 30 | 45 |
| Manifest, ThreatMetaData, ThreatCategories, GenericElements, StandardElements | unchanged | byte-identical |
| Existing 211 threats (TH1–TH274) | unchanged | byte-identical |

## What gaps the previous round missed

| Gap | New threat(s) |
|---|---|
| **No Spoofing threats for Fabric** (S=0 in the previous round) | TH275, TH276, TH277 |
| Fabric Compute parent stencil had zero direct references | TH286, TH287, TH289 |
| Fabric Data parent stencil had zero direct references | TH286, TH287, TH289 |
| Fabric Boundary parent stencil had zero direct references | TH279, TH287, TH288 |
| Power BI embed-token compromise (distinct from semantic-model RLS in TH262) | TH275 |
| Data Agent SPN-vs-user-identity confusion (per skill: SPN not supported) | TH276 |
| Scheduled-run identity vs interactive-edit identity divergence | TH277 |
| OneLake Security 250/500/500 role limits forcing role widening | TH278 |
| OneLake Security exclusivity with private link / Purview Data Share | TH279 |
| Direct Lake silent fallback to DirectQuery (security context shift) | TH280 |
| Mirroring source-system credential exposure | TH281 |
| Spark library / JAR supply chain in Data Engineering | TH282 |
| Activator outbound webhook as exfiltration channel | TH283 |
| KQL ingestion silent column drop / type coercion on schema drift | TH284 |
| Lakehouse Files area reachable via ABFS bypassing Tables review | TH285 |
| Copilot / generative AI in Fabric crossing data boundary | TH286 |
| Compute-vs-data identity attribution at the trust boundary | TH287 |
| Contributor-role peer/self elevation through item-ownership grants | TH288 |
| Domain endorsement / Promoted-Certified surface widening discoverability | TH289 |

## STRIDE+A distribution

| Category | Round 1 (TH245–TH274) | Round 2 (TH275–TH289) | Combined |
|---|---|---|---|
| S — Spoofing | 0 | **3** | 3 |
| T — Tampering | 5 | 2 | 7 |
| R — Repudiation | 2 | 1 | 3 |
| I — Information Disclosure | 17 | 8 | 25 |
| D — Denial of Service | 2 | 0 | 2 |
| E — Elevation of Privilege | 4 | 1 | 5 |
| A — Abuse | 0 | 0 | 0 |

The combined catalog now covers six of the seven categories. Spoofing — the previous gap — now has dedicated coverage. Abuse remains at zero for Fabric specifically because the relevant Abuse pattern (LLM misuse) is already covered generically in TH219/TH242 and there is no Fabric-specific abuse pattern distinct from that.

## Stencil coverage after this round

Every Fabric Compute and Data stencil — and every parent — now has at least one dedicated threat:

| Stencil | Threats  |
|---|---|
| **Parents** | |
| Fabric Root | 4 |
| Fabric Compute | 3 |
| Fabric Data | 3 |
| Fabric Tenant | 4 |
| Fabric Workspace | 8 |
| Fabric Boundary | 3 |
| **Compute** | |
| Data Agent | 4 |
| Data Engineering | 4 |
| Data Factory | 4 |
| Fabric IQ | 2 |
| Mirroring | 2 |
| Power BI | 4 |
| Realtime Hub | 3 |
| Activator | 4 |
| **Data** | |
| KQL Database | 5 |
| Cosmos DB | 1 |
| Eventhouse | 6 |
| Lakehouse | 12 |
| OneLake | 12 |
| Fabric SQL DB | 3 |
| Warehouse | 8 |
| Direct Lake | 4 |

## New threats by theme

### Spoofing — newly covered

**TH275 — Power BI embed token impersonation** *(S / High)*
Embed tokens issued for Fabric Power BI artifacts represent the embedding application's broader scope; leakage through client-side script, browser storage, or logs lets an adversary impersonate that scope.

**TH276 — Data Agent SPN vs user identity** *(S / High)*
Fabric Data Agents do not support service principal authentication. Designs that assume SPN can be used may fall back to cached or shared user identities, breaking attribution and potentially executing under a higher-privilege user.

**TH277 — Scheduled-run vs interactive-edit identity divergence** *(S / High)*
Pipelines, notebooks, and refreshes execute under a configured run identity, not the editing user's identity. Edit-rights compromise is therefore a path to invoking work under a broader run identity.

### OneLake Security limits and incompatibility

**TH278 — Role-count and membership limits force role widening** *(I / Medium)*
Hard caps of 250 roles per lakehouse, 500 members per role, and 500 permissions per role can drive consolidation that silently regresses least-privilege.

**TH279 — Mutually exclusive controls** *(I / High)*
OneLake Security cannot coexist with private link or Purview Data Share. Designs requiring all three must partition workspaces or accept reduced control on at least one axis.

### Engine-specific behaviors

**TH280 — Direct Lake silent fallback to DirectQuery** *(I / High)*
Unsupported features cause Direct Lake reports to fall back to DirectQuery, which evaluates security through the SQL endpoint layer rather than OneLake Security, potentially producing different effective access.

### Credential and supply chain

**TH281 — Mirroring source credentials become workspace-resident** *(I / High)*
Source-system credentials stored to enable mirroring grant access to the source database, not just the mirror.

**TH282 — Spark library / environment supply chain** *(T / High)*
Custom JARs, wheel packages, and environments attached to a workspace run in every notebook and Spark job.

### Activator and event paths

**TH283 — Activator webhook as exfiltration channel** *(I / High)*
Outbound webhook calls from Activator rules can become covert exfil paths from privileged event sources.

**TH284 — KQL silent schema-drift handling** *(T / Medium)*
Default ingestion mappings drop unmapped fields and coerce type mismatches silently, hiding malicious or anomalous payloads from detection rules expecting specific fields.

### Direct OneLake access path

**TH285 — Files area reachable via ABFS bypasses Tables review** *(I / High)*
The OneLake ABFS path exposes the Files area at item-level read; sensitive data placed there has no row, column, or schema-level controls.

### Tenant / cross-cutting governance

**TH286 — Copilot / generative AI features cross the workspace boundary** *(I / High)*
Workspace data and metadata sent to model endpoints (potentially in a different geography) is a disclosure event regardless of contractual terms.

**TH287 — Compute-vs-data identity attribution at the trust boundary** *(R / Medium)*
Shared run identities across compute and data layers obscure which compute artifact drove a given data access.

**TH288 — Contributor role enables peer/self elevation through item ownership** *(E / Medium)*
Contributors who create items become item owners with the ability to grant ReadAll and Reshare independently of workspace-admin oversight.

**TH289 — Domain / Promoted-Certified endorsement widens discoverability beyond intended audience** *(I / Medium)*
Endorsement surfaces items in catalog and recommendation experiences across the tenant; if applied before access controls match the wider audience, users discover items they were not intended to see.



