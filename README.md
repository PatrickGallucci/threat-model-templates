
# Microsoft Template - Microsoft Security Threat Model Stencil #
https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling

![](https://i.imgur.com/M6o7wJT.png)

## Release Notes 
**Release 8 (2026-04-29)**
This version includes the following stencil additions:

**Frontier Model Platforms (LLM Providers)**

- Claude (Anthropic) — Frontier AI assistant currently led by Claude Opus 4.7, known for long-horizon agentic work, coding, and powering tools like Cursor, Windsurf, and Claude Code.
- ChatGPT (OpenAI) — The market-leading AI assistant powered by GPT-5.4, offering chat, reasoning, image generation (DALL-E), and the Assistants/Agents SDK.
- Gemini (Google) — Google's flagship multimodal AI featuring Gemini 3.1 Pro with a 1M token context window and the tightest Google Workspace integration on the market.
- Grok (xAI) — Elon Musk's AI assistant integrated into X, focused on real-time search, advanced reasoning ("Think" and "Big Brain" modes), and coding via Grok Studio.
- DeepSeek — Open-source frontier model from China offering competitive performance at significantly lower cost, popular for self-hosted enterprise deployments.
- Perplexity — Verification-first AI search platform with real-time citations, now wrapped in the Comet browser with multi-agent workflow capabilities.

**Enterprise / Cloud AI Platforms**

- AWS Bedrock — Amazon's managed service providing API access to multiple foundation models (Claude, Llama, Titan, etc.) with enterprise-grade governance.
- Google Vertex AI — Google Cloud's end-to-end ML and generative AI platform for training, tuning, and deploying models including Gemini.
- Databricks (Mosaic AI) — Data intelligence platform unifying data lakes, warehouses, and AI workloads with Lakehouse architecture for enterprise ML and GenAI.
- IBM watsonx — IBM's enterprise AI and data platform focused on governance, foundation model customization, and regulated-industry deployments.
- DataRobot — Enterprise AI lifecycle platform for predictive ML, generative AI, and MLOps with strong governance tooling.

**Microsoft Copilot Ecosystem (relevant to your stack)**

- Microsoft 365 Copilot — AI assistant embedded across Word, Excel, PowerPoint, Outlook, and Teams, with the Wave 3 "E7 Frontier Suite" for enterprise productivity.
- GitHub Copilot — AI pair programmer for code completion, chat, and agent-mode coding tasks across IDEs and the GitHub platform.
- Copilot Studio — Low-code platform for building custom AI agents and copilots that integrate with Dynamics 365, Power Platform, and Microsoft 365.
- Microsoft Fabric Data Agents — Native Fabric capability enabling natural language Q&A over lakehouses, warehouses, semantic models, and KQL databases.

**AI Agent & Orchestration Platforms**

- LangChain / LangGraph — Open-source framework for building stateful, multi-actor LLM applications and agent workflows with strong developer adoption.
- CrewAI — Multi-agent orchestration framework for coordinating role-based AI agents to complete complex collaborative tasks.
- AutoGen (Microsoft) — Microsoft Research's open-source framework for building conversational multi-agent systems.
- n8n — Self-hostable workflow automation platform with a powerful AI Agent node, ideal for data-sovereignty-sensitive integrations.
- Lindy — No-code AI agent platform for business automation, lead routing, and CRM workflows.

**Developer & Coding Platforms**

- Cursor — AI-native code editor rebuilt around parallel agents, powered primarily by Claude and other frontier models.
- Claude Code — Anthropic's terminal-native and IDE-integrated agentic coding tool for delegating complex development tasks.
- Windsurf — AI coding IDE (formerly Codeium) focused on agentic flows and multi-file refactoring.
- Google Antigravity — Google's Gemini 3 Pro-powered agentic development platform competing with Cursor.

**Specialized Platforms**

- Hugging Face — The leading open-source hub for hosting, sharing, and deploying ML models, datasets, and Spaces.
- Synthesia — AI video generation platform creating realistic human avatar videos from text scripts.
- Midjourney — Premium AI image generation platform known for high-quality artistic and photorealistic imagery.
- ElevenLabs — Leading AI voice synthesis and text-to-speech platform with realistic voice cloning.

## Release Notes ##
**Release 7 (2025-08-04)**
This is the first version of the new Microsoft Template (MicrosoftTemplate.v1.tb7). This includes the last Azure template version 7 (AzureTemplate.v7.tb7) with the following stencil additions:

**Microsoft Entra**
- Microsoft Entra ID
- Microsoft Entra ID Governance

**Microsoft Security Boundary**
- Microsoft Entra Boundary
- Microsoft Fabric Boundary

**Microsoft Fabric**
- Microsoft Fabric Tenant
- Microsoft Fabric Workspace

**Microsoft Fabric Compute**
- Microsoft Fabric Data Agent
- Microsoft Fabric Data Factory
- Microsoft Fabric Mirroring
- Microsoft Fabric Power BI
- Microsoft Fabric Realtime Hub

**Microsoft Fabric Data**
- KQL Database
- Microsoft Fabric Cosmos DB
- Microsoft Fabric Eventhouse
- Microsoft Fabric Lakehouse
- Microsoft Fabric OneLake
- Microsoft Fabric SQL Database
- Microsoft Fabric Warehouse
- Power BI Direct Lake

**Legacy Azure templates have been moved to the Archive folder**

**Release 6 (2025-08-01)**

Added the following Stencils

**Azure Asset**
- Microsoft Entra ID

**Azure Service**
- Microsoft Sentinel

**AWS Data**
- AWS Aurora
- AWS DocumentDB
- AWS DynamoDB
- AWS Neptune
- AWS RDS
- AWS Redshift
- AWS Timestream
- MariaDB in AWS
- MySQL in AWS
- Oracle in AWS
- PostgreSQL in AWS
- Snowflake in AWS
- SQL Server in AWS
- SQL Server VM in AWS

**AWS Boundary**
- Amazon Cloud Boundary
- AWS Region
- AWS Security Group
- AWS VPC

**Interactor**
- Administrator
- Attacker
- External Service
- System Process
- User

**Cloud SaaS Services**
- Box
- Dropbox
- Google Drive
- Microsoft 365
- OneDrive
- Power BI Platform
- Power Automate
- SharePoint
- X Twitter

**Sample Release (2022-07-17)**

**Added Sample** - [Azure Data & Analytics Platform](https://github.com/AzureArchitecture/threat-model-templates/tree/master/Samples) 

**Pre-Release 5 (2022-03-30)**

**New Stencils**
- Anomaly detectors
- Azure Purview accounts
- Bot Services
- Cognitive search
- Cognitive Services
- Computer vision
- Content moderators
- Custom vision
- Face APIs
- Firewall Policies
- Form recognizers
- Front Door and CDN profiles
- Immersive readers
- Language understanding
- Language
- Metrics advisors
- Network interfaces
- Personalizers
- Public IP Prefixes
- QnA makers
- Speech services
- Splunk
- Translators
- Video Analyzers
- Web Application Firewall policies

**New Threat Properties**
1. FINRA - Does this comply with FINRA, a standard set for not-for-profit organizations authorized by Congress that regulates and enforces the enhancement of investor safeguards and market integrity?
1. FISMA -  Does this comply with FISMA, the US legislation that defines a comprehensive framework to protect government information, operations and assets within federal agencies, against threats?
1. GAAP - Does this comply with GAAP, a collection of commonly-followed accounting rules and standards for financial reporting?
1. HIPPA - Does this comply with HIPAA, the US legislation that sets standards for protecting the confidentiality and security of individually identifiable health information?
1. ISAE 3402 - Does this comply with ISAE 3402, the global standard providing assurance that a service organization has appropriate controls in place?
1. ISO 27001 - Is this ISO 27001 certified, a certificate given to companies upholding internationally recognized guidelines and general principles for initiating, implementing, maintaining, and improving information security management within an organization?
1. ITAR - Does this comply with ITAR, regulations controlling the export and import of defense-related articles and services found on the US Munitions List?
1. SOC 1 - Does this comply with SOC 1, reporting on controls at a service organization which are relevant to user entities' internal control over financial reporting?
1. SOC 2 - Does this comply with SOC 2, reporting on non-financial processing based on one or more of the Trust service criteria on security, privacy, availability, confidentiality, and processing integrity?
1. SOC 3 -  Does this comply with SOC 3, reporting based on the Trust service criteria, that may be distributed freely and only contain management's assertion that they have met the requirements of the chosen criteria?
1. SOX - Does this comply with SOX, US legislation aimed at protecting shareholders and the general public from accounting errors and frauds, as well as improving the accuracy of corporate disclosures?
1. SP 800-53 -  Does this comply with SP80053, recommended security controls for federal information systems and organizations?
1. SSAE 16 - Does this comply with the SSAE 16 standard for auditing a service organization's internal compliance controls and reporting processes?
1. PCI DSS version - The version of the PCI-DSS protocol supported by this app.
1. ISO 27018 - Does this comply with ISO 27018, which establishes commonly accepted controls and guidelines for processing and protecting Personally Identifiable Information (PII) in a public cloud computing environment?
1. GLBA - Does this app comply with the Gramm-Leach-Bliley Act (GLBA), which requires financial institutions to establish standards for protecting the security and confidentiality of customers' personal information?
1. FedRAMP level - The level of the FedRAMP-compliant solution provided.
1. CSA STAR level - The level of CSA STAR program at which this is certified.
1. Privacy Shield - Does this comply with the EU-US Privacy Shield Framework, which imposes stronger obligations on US companies to protect Europeans' personal data?
1. ISO 27017 - Does this comply with ISO 27017, which establishes commonly accepted controls and guidelines for processing and protecting user information in a public cloud-computing environment?
1. COBIT - Does this comply with COBIT, which sets best practices for the governance and control of information systems and technology, and aligns IT with business principles?
1. COPPA - Does this comply with COPPA, which defines requirements on website and online services operators that provide content to children under 13 years of age?
1. FERPA - Does this comply with FERPA, a federal law that protects the privacy of student education records?
1. GAPP -  Does this comply with GAPP, a collection of commonly-followed rules that address privacy risks in an organization?
1. HITRUST CSF - Does this comply with HITRUST CSF, a set of controls that harmonizes the requirements of information security regulations and standards?
1. Jericho Forum Commandments - Does this follow Jericho Forum Commandments, a set if principles to be observed when architecting systems for secure operation in de-perimeterized environments?
1. ISO 27002 -  Does this app comply with ISO 27002, which establishes common guidelines for organizational information security standards and information security management practices?
1. FFIEC - Does this comply with the Federal Financial Institutions Examination Council’s guidance on the risk management controls necessary to authenticate services in an Internet banking environment?
1. Data ownership -  Does this app fully preserve the user's ownership of uploaded data?
1. DMCA - Does this app comply with the Digital Millennium Copyright Act (DMCA), which criminalizes any attempt to unlawfully access copyrighted material?
1. Data Retention Policy - What is the app’s policy for user data retention after account termination?
1. GDPR - What is the app’s policy for user data retention after account termination?



**Release 4 (2019-12-28)**

**New Stencils**
- Azure Storage Explorer
- Azure Open Datasets
- Azure SQL Managed Instance
- Azure Synapse
- Azure SQL Database Edge
- Azure Data Share
- Azure Cloud Shell
- Azure Alerts
- Azure Firewall Manager
- Azure DevOps Pipelines
- Azure DevOps Boards
- Azure DevOps Artifacts
- Azure DevOps Repos
- Azure Sentinal

**New Threat Types**

**Threat Properties**
