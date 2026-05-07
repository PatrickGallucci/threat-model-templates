# Microsoft Threat Modeling Tool — STRIDE+A+LLM Threat Catalog

> A structured reference for the **365 design-time threats** defined in `MicrosoftTemplate_v2_3.tb7`, organised by STRIDE+A+LLM and rendered with their full mitigations and operational steps.

**Source template:** `MicrosoftTemplate_v2_3.tb7`  
**Threat count:** 365  (TH1 – TH428 with intentional gaps; 3 legacy GUID IDs preserved)  
**Categories covered:** Spoofing • Tampering • Repudiation • Information Disclosure • Denial of Service • Elevation of Privilege • Abuse • LLM-specific extensions  
**Primary technology focus:** Microsoft Fabric, Azure, Microsoft Entra, AI/LLM platforms (provider, agent, orchestration, developer-tool, specialised), AWS data services, SaaS, IoT.

## How to read this document

Each threat entry gives you the seven things you actually need at design time:

1. **STRIDE+A category** — the single attack family it belongs to.
1. **Affected stencils** — which DFD shapes the threat fires against.
1. **Severity / SDL phase / effort** — TMT-supplied risk-and-cost shorthand.
1. **Why it matters at design time** — the threat description.
1. **Possible mitigations** — the architectural controls that neutralise it.
1. **Steps** — concrete verification or implementation work the modeller should plan for.
1. **Documentation** — the canonical reference link, when one exists.

LLM-specific threats are flagged with an **🤖 LLM** badge in the category section headings and in the appendix. They are integrated into the standard STRIDE+A categories rather than living in a separate taxonomy — this matches Microsoft's STRIDE-LM extension and OWASP's LLM Top 10 framing, where LLM threats are concrete instances of classical security primitives (tampering = prompt injection, elevation = excessive agency, etc.).

## Table of contents

- [How to read this document](#how-to-read-this-document)
- [Threat distribution at a glance](#threat-distribution-at-a-glance)
- [STRIDE+A+LLM mapping](#strideallm-mapping)
- Catalog by category:
  - [`S` — Spoofing (50)](#s--spoofing-50)
  - [`T` — Tampering (61)](#t--tampering-61)
  - [`R` — Repudiation (28)](#r--repudiation-28)
  - [`I` — Information Disclosure (135)](#i--information-disclosure-135)
  - [`D` — Denial of Service (23)](#d--denial-of-service-23)
  - [`E` — Elevation of Privilege (61)](#e--elevation-of-privilege-61)
  - [`A` — Abuse (7)](#a--abuse-7)
- LLM-specific catalog highlights:
  - [🤖 LLM threats — quick index](#-llm-threats--quick-index)
- [Appendix A — Master threat index](#appendix-a--master-threat-index)

## Threat distribution at a glance

| STRIDE+A | Category | Threats | LLM-tagged | % of total |
| :---: | --- | ---: | ---: | ---: |
| `S` | Spoofing | 50 | 8 | 13.7% |
| `T` | Tampering | 61 | 15 | 16.7% |
| `R` | Repudiation | 28 | 9 | 7.7% |
| `I` | Information Disclosure | 135 | 17 | 37.0% |
| `D` | Denial of Service | 23 | 5 | 6.3% |
| `E` | Elevation of Privilege | 61 | 10 | 16.7% |
| `A` | Abuse | 7 | 5 | 1.9% |
| — | **Totals** | **365** | **69** | **100.0%** |

### By technology family

A single threat may target stencils in more than one family; the counts below are de-duplicated within each row.

| Family | S | T | R | I | D | E | A | Total | LLM-tagged |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Microsoft Fabric | 8 | 10 | 11 | 32 | 8 | 9 | 1 | **79** | 7 |
| AI / LLM | 5 | 13 | 6 | 14 | 4 | 9 | 4 | **55** | 55 |
| Microsoft Entra | 3 | 0 | 0 | 0 | 1 | 0 | 0 | **4** | 0 |
| Azure | 24 | 20 | 6 | 42 | 4 | 26 | 1 | **123** | 0 |
| AWS | 1 | 1 | 0 | 16 | 2 | 1 | 0 | **21** | 0 |
| SaaS | 1 | 5 | 2 | 23 | 1 | 7 | 0 | **39** | 0 |
| IoT | 6 | 6 | 2 | 2 | 0 | 5 | 0 | **21** | 0 |
| Interactor | 1 | 2 | 1 | 3 | 1 | 2 | 1 | **11** | 7 |
| Generic | 1 | 4 | 0 | 3 | 2 | 2 | 0 | **12** | 0 |

## STRIDE+A+LLM mapping

The catalog uses **STRIDE+A** (Microsoft's STRIDE extended with *Abuse* for actions that are within policy but harmful at scale). LLM-specific risks are mapped onto this same taxonomy rather than treated as a separate category, in line with **STRIDE-LM** ([csf.tools/reference/stride-lm](https://csf.tools/reference/stride-lm/)) and the **OWASP LLM Top 10**. The mapping below is the lens used throughout this catalog.

| STRIDE+A | LLM-specific instance(s) | Example threat IDs |
| :---: | --- | --- |
| `S` | Tool / endpoint impersonation, model substitution, fabricated authoritative output (hallucinated citations, fake APIs), voice/avatar synthesis impersonation, unverified agent identity | TH200, TH201, TH220, TH229, TH240, TH383 |
| `T` | Direct prompt injection, indirect (RAG/tool-output) prompt injection, training-data / fine-tune / RLHF poisoning, vector-store or embedding-index poisoning, model-artifact tampering, orchestration-chain tampering, repo-hidden instruction injection | TH202–TH206, TH223, TH227, TH232, TH236, TH238, TH239, TH384, TH411 |
| `R` | Missing prompt/completion logging, missing tool-invocation audit, NL→SQL/DAX/KQL non-paired logging, missing media provenance, unattributable agent actions, multi-agent decision-trail loss, ontology version not preserved | TH207, TH208, TH243, TH256, TH347, TH385, TH414, TH426 |
| `I` | Sensitive-data extraction via completions, training-data memorisation leak, cross-tenant/session context bleed, third-party provider data egress, embedding-vector inversion, MLOps metadata disclosure, IDE codebase indexing, agentic-tool source/secret transmission, ontology-driven implicit joins | TH209–TH213, TH221, TH222, TH224, TH225, TH228, TH234, TH237, TH254, TH260, TH386, TH413 |
| `D` | Cost/quota exhaustion via expensive completions, context-window saturation, public inference endpoint DoS, agent tool-call loops, rate-limit/quota/model-deprecation cascade | TH214, TH215, TH244, TH387, TH412 |
| `E` | Excessive agency / over-broad tool permissions, insecure plugin or function-calling, unsanitised LLM output → downstream code exec, destructive agent actions, MCP / extension supply chain, multi-agent privilege injection, IAM-role-broad inference, workflow-AI-node secret leakage, Bedrock action-group Lambda role | TH216–TH218, TH226, TH230, TH231, TH235, TH345, TH388 |
| `A` | Disallowed content generation, brand-damaging media generation, provider data-retention beyond policy, missing Bedrock Guardrails, agent-driven scaled misuse | TH219, TH242, TH348, TH389, TH410 |

## `S` — Spoofing (50)

> A process or entity is something other than its claimed identity.

🤖 **8 of these threats are LLM-tagged.**

### `3f96bbf2-1d6e-4b20-9bca-8a413008595f` — Ensure that multi-factor authentication is enabled for all privileged users

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Asset, Azure Data Service, Azure Service • Source: Human User

#### Description

Enable multi-factor authentication for all user credentials who have write access to Azure resources.

#### Possible mitigations

Enable multi-factor authentication for all Privileged user credentials Refer:
<https://tinyurl.com/astm-identity>

#### Steps

Enable remember Multi-Factor Authentication Sign in to the Azure portal. On the left, select Azure Active Directory > Users and groups > All users. Select Multi-Factor Authentication. Under Multi-Factor Authentication, select service settings. On the Service Settings page, manage remember multi-factor authentication, select the Allow users to remember multi-factor authentication on devices they trust option. Set the number of days to allow trusted devices to bypass two-step verification. The default is 14 days. Select Save.

**Documentation:** <https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates>

---

### `9f6d0f70-aa99-4ecf-90a5-a6c750f450e7` — Ensure that multi-factor authentication is enabled for all non-privileged users

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Asset, Azure Data Service, Azure Service • Source: Human User

#### Description

Enable multi-factor authentication for all non-privileged users.

#### Possible mitigations

Enable multi-factor authentication for all Privileged user credentials Refer:
<https://tinyurl.com/astm-identity>

#### Steps

Enable remember Multi-Factor Authentication Sign in to the Azure portal. On the left, select Azure Active Directory > Users and groups > All users. Select Multi-Factor Authentication. Under Multi-Factor Authentication, select service settings. On the Service Settings page, manage remember multi-factor authentication, select the Allow users to remember multi-factor authentication on devices they trust option. Set the number of days to allow trusted devices to bypass two-step verification. The default is 14 days. Select Save.

**Documentation:** <https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates>

---

### `TH7` — An adversary can steal sensitive data like user credentials

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Description

Attackers can exploit weaknesses in system to steal user credentials. Downstream and upstream components are often accessed by using credentials stored in configuration stores. Attackers may steal the upstream or downstream component credentials. Attackers may steal credentials if, Credentials are stored and sent in clear text, Weak input validation coupled with dynamic sql queries, Password retrieval mechanism are poor,

#### Possible mitigations

Explicitly disable the autocomplete HTML attribute in sensitive forms and inputs. Refer:
<https://aka.ms/tmtdata#autocomplete-input> Perform input validation and filtering on all string type Model properties. Refer:
<https://aka.ms/tmtinputval#typemodel> Validate all redirects within the application are closed or done safely. Refer:
<https://aka.ms/tmtinputval#redirect-safe> Enable step up or adaptive authentication. Refer:
<https://aka.ms/tmtauthn#step-up-adaptive-authn> Implement forgot password functionalities securely. Refer:
<https://aka.ms/tmtauthn#forgot-pword-fxn> Ensure that password and account policy are implemented. Refer:
<https://aka.ms/tmtauthn#pword-account-policy> Implement input validation on all string type parameters accepted by Controller methods. Refer:
<https://aka.ms/tmtinputval#string-method>

#### Steps

The autocomplete attribute specifies whether a form should have autocomplete on or off. When autocomplete is on, the browser automatically complete values based on values that the user has entered before. For example, when a new name and password is entered in a form and the form is submitted, the browser asks if the password should be saved.Thereafter when the form is displayed, the name and password are filled in automatically or are completed as the name is entered. An attacker with local access could obtain the clear text password from the browser cache. By default autocomplete is enabled, and it must explicitly be disabled.

**Documentation:** <https://msdn.microsoft.com/library/ms533032.aspx>

---

### `TH8` — Attacker can steal user session cookies due to insecure cookie attrbutes

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: API App, WCF, Web API, Web Application • Source: Browser

#### Description

The session cookies is the identifier by which the server knows the identity of current user for each incoming request. If the attacker is able to steal the user token he would be able to access all user data and perform all actions on behalf of user.

#### Possible mitigations

Applications available over HTTPS must use secure cookies. Refer: <https://aka.ms/tmtsmgmt#https-secure-cookies> All http based application should specify http only for cookie definition. Refer:
<https://aka.ms/tmtsmgmt#cookie-definition>

#### Steps

To mitigate the risk of information disclosure with a cross-site scripting (XSS) attack, a new attribute - httpOnly - was introduced to cookies and is supported by all major browsers. The attribute specifies that a cookie is not accessible through script. By using HttpOnly cookies, a web application reduces the possibility that sensitive information contained in the cookie can be stolen via script and sent to an attacker's website.

**Documentation:** <https://www.owasp.org/index.php/HTTPOnly>

---

### `TH11` — An adversary can bypass authentication due to non-standard Azure AD authentication schemes

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Active Directory, Microsoft Entra ID

#### Possible mitigations

Use standard authentication scenarios supported by Azure Active Directory. Refer:
<https://aka.ms/tmtauthn#authn-aad>

#### Steps

Azure Active Directory (Azure AD) simplifies authentication for developers by providing identity as a service, with support for industry-standard protocols such as OAuth 2.0 and OpenID Connect. Below are the five primary application scenarios supported by Azure AD: Web Browser to Web Application: A user needs to sign in to a web application that is secured by Azure AD Single Page Application (SPA): A user needs to sign in to a single page application that is secured by Azure AD Native Application to Web API: A native application that runs on a phone, tablet, or PC needs to authenticate a user to get resources from a web API that is secured by Azure AD Web Application to Web API: A web application needs to get resources from a web API secured by Azure AD Daemon or Server Application to Web API: A daemon application or a server application with no web user interface needs to get resources from a web API secured by Azure AD

**Documentation:** <https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-scenarios>

---

### `TH12` — An adversary can get access to a user's session by replaying authentication tokens

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Active Directory, Microsoft Entra ID • Source: Azure Asset, Azure Data Service, Azure Service, Generic External Interactor, Generic Process

#### Possible mitigations

Ensure that TokenReplayCache is used to prevent the replay of ADAL authentication tokens. Refer:
<https://aka.ms/tmtauthn#tokenreplaycache-adal>

#### Steps

The TokenReplayCache property allows developers to define a token replay cache, a store that can be used for saving tokens for the purpose of verifying that no token can be used more than once. This is a measure against a common attack, the aptly called token replay attack: an attacker intercepting the token sent at sign-in might try to send it to the app again (“replay” it) for establishing a new session. E.g., In OIDC code-grant flow, after successful user authentication, a request to "/signin-oidc" endpoint of the relying party is made with "id_token", "code" and "state" parameters. The relying party validates this request and establishes a new session. If an adversary captures this request and replays it, he/she can establish a successful session and spoof the user. The presence of the nonce in OpenID Connect can limit but not fully eliminate the circumstances in which the attack can be successfully enacted. To protect their applications, developers can provide an implementation of ITokenReplayCache and assign an instance to TokenReplayCache.

**Documentation:** <https://blogs.msdn.microsoft.com/microsoft_press/2016/01/04/new-book-modern-authentication-with-azure-active-directory-for-web-applications/>

---

### `TH13` — An adversary can gain unauthorized access to API end points due to unrestricted cross domain requests

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Operate • **Effort:** Medium

**Applies to:** Targets: Web API • Source: Browser

#### Description

An adversary can gain gain unauthorized access to API end points due to weak CORS configuration

#### Possible mitigations

Ensure that only trusted origins are allowed if CORS is enabled on ASP.NET Web API. Refer:
<https://aka.ms/tmtconfigmgmt#cors-api> Mitigate against Cross-Site Request Forgery (CSRF) attacks on ASP.NET Web APIs. Refer:
<https://aka.ms/tmtsmgmt#csrf-api>

#### Steps

Cross-site request forgery (CSRF or XSRF) is a type of attack in which an attacker can carry out actions in the security context of a different user's established session on a web site. The goal is to modify or delete content, if the targeted web site relies exclusively on session cookies to authenticate received request. An attacker could exploit this vulnerability by getting a different user's browser to load a URL with a command from a vulnerable site on which the user is already logged in. There are many ways for an attacker to do that, such as by hosting a different web site that loads a resource from the vulnerable server, or getting the user to click a link. The attack can be prevented if the server sends an additional token to the client, requires the client to include that token in all future requests, and verifies that all future requests include a token that pertains to the current session, such as by using the ASP.NET AntiForgeryToken or ViewState.

**Documentation:** <http://www.asp.net/web-api/overview/security/preventing-cross-site-request-forgery-csrf-attacks>

---

### `TH21` — An adversary can gain unauthorized access to {target.Name} due to weak CORS configuration

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Storage, CosmosDB

#### Description

An adversary can gain gain unauthorized access to {target.Name} due to weak CORS configuration

#### Possible mitigations

Ensure that only trusted origins are allowed if CORS is enabled on Azure storage. Refer:
<https://aka.ms/tmtconfigmgmt#cors-storage>

#### Steps

Azure Storage allows you to enable CORS – Cross Origin Resource Sharing. For each storage account, you can specify domains that can access the resources in that storage account. By default, CORS is disabled on all services. You can enable CORS by using the REST API or the storage client library to call one of the methods to set the service policies.

**Documentation:** <https://docs.microsoft.com/en-us/rest/api/storageservices/Cross-Origin-Resource-Sharing--CORS--Support-for-the-Azure-Storage-Services?redirectedfrom=MSDN>

---

### `TH22` — An adversary can get access to a user's session due to improper logout and timeout

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API, Web Application • Source: Browser

#### Description

The session cookies is the identifier by which the server knows the identity of current user for each incoming request. If the attacker is able to steal the user token he would be able to access all user data and perform all actions on behalf of user.

#### Possible mitigations

Set up session for inactivity lifetime. Refer: <https://aka.ms/tmtsmgmt#inactivity-lifetime> Implement proper logout from the application. Refer:
<https://aka.ms/tmtsmgmt#proper-app-logout>

#### Steps

Perform proper Sign Out from the application, when user presses log out button. Upon logout, application should destroy user's session, and also reset and nullify session cookie value, along with resetting and nullifying authentication cookie value. Also, when multiple sessions are tied to a single user identity, they must be collectively terminated on the server side at timeout or logout. Lastly, ensure that Logout functionality is available on every page.

---

### `TH23` — An adversary can get access to a user's session due to insecure coding practices

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API, Web Application • Source: Browser

#### Description

The session cookies is the identifier by which the server knows the identity of current user for each incoming request. If the attacker is able to steal the user token he would be able to access all user data and perform all actions on behalf of user.

#### Possible mitigations

Enable ValidateRequest attribute on ASP.NET Pages. Refer: <https://aka.ms/tmtconfigmgmt#validate-aspnet> Encode untrusted web output prior to rendering. Refer:
<https://aka.ms/tmtinputval#rendering> Avoid using Html.Raw in Razor views. Refer:
<https://aka.ms/tmtinputval#html-razor> Sanitization should be applied on form fields that accept all characters e.g, rich text editor . Refer:
<https://aka.ms/tmtinputval#richtext> Do not assign DOM elements to sinks that do not have inbuilt encoding . Refer:
<https://aka.ms/tmtinputval#inbuilt-encode>

#### Steps

Request validation, a feature of ASP.NET since version 1.1, prevents the server from accepting content containing un-encoded HTML. This feature is designed to help prevent some script-injection attacks whereby client script code or HTML can be unknowingly submitted to a server, stored, and then presented to other users. We still strongly recommend that you validate all input data and HTML encode it when appropriate. Request validation is performed by comparing all input data to a list of potentially dangerous values. If a match occurs, ASP.NET raises an HttpRequestValidationException. By default, Request Validation feature is enabled.

**Documentation:** <https://docs.microsoft.com/en-us/aspnet/whitepapers/request-validation>

---

### `TH32` — An adversary can spoof the target web application due to insecure TLS certificate configuration

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Description

Ensure that TLS certificate parameters are configured with correct values

#### Possible mitigations

Verify X.509 certificates used to authenticate SSL, TLS, and DTLS connections. Refer:
<https://aka.ms/tmtcommsec#x509-ssltls>

#### Steps

Applications that use SSL, TLS, or DTLS must fully verify the X.509 certificates of the entities they connect to. This includes verification of the certificates for: Domain name Validity dates (both beginning and expiration dates) Revocation status Usage (for example, Server Authentication for servers, Client Authentication for clients) Trust chain. Certificates must chain to a root certification authority (CA) that is trusted by the platform or explicitly configured by the administrator Key length of certificate's public key must be >2048 bits Hashing algorithm must be SHA256 and above

**Documentation:** <https://blogs.msdn.microsoft.com/kaushal/2015/05/27/client-certificate-authentication-part-1/>

---

### `TH35` — An adversary may spoof {source.Name} with a fake one

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: IoT Cloud Gateway, IoT Field Gateway • Source: IoT Device, IoT Field Gateway

#### Description

An adversary may replacing the {source.Name} or part of the {source.Name} with some other {source.Name}.

#### Possible mitigations

Ensure that devices connecting to Field or Cloud gateway are authenticated. Refer:
<https://aka.ms/tmtauthn#authn-devices-cloud>

#### Steps

Generic: Authenticate the device using Transport Layer Security (TLS) or IPSec. Infrastructure should support using pre-shared key (PSK) on those devices that cannot handle full asymmetric cryptography. Leverage Azure AD, Oauth. C#: When creating a DeviceClient instance, by default, the Create method creates a DeviceClient instance that uses the AMQP protocol to communicate with IoT Hub. To use the HTTPS protocol, use the override of the Create method that enables you to specify the protocol. If you use the HTTPS protocol, you should also add the Microsoft.AspNet.WebApi.Client NuGet package to your project to include the System.Net.Http.Formatting namespace.

**Documentation:** <https://azure.microsoft.com/documentation/articles/iot-hub-csharp-csharp-getstarted/>

---

### `TH36` — An adversary may reuse the authentication tokens of {source.Name} in another

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway, IoT Field Gateway • Source: IoT Device, IoT Field Gateway

#### Description

An attacker may extract cryptographic key material from {source.Name}, either at the software or hardware level, and subsequently access the system with a different physical or virtual {source.Name} under the identity of the {source.Name} the key material has been taken from. A good illustration is remote controls that can turn any TV and that are popular prankster tools.

#### Possible mitigations

Use per-device authentication credentials. Refer: <https://aka.ms/tmtauthn#authn-cred>

#### Steps

Use per device authentication credentials using SaS tokens based on Device key or Client Certificate, instead of IoT Hub-level shared access policies. This prevents the reuse of authentication tokens of one device or field gateway by another

**Documentation:** <https://azure.microsoft.com/documentation/articles/iot-hub-sas-tokens/>

---

### `TH40` — An adversary may auto-generate valid authentication tokens for IoT Hub

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway • Source: IoT Device, IoT Field Gateway

#### Description

An adversary may predict and generate valid security tokens to authenticate to IoT Hub, by leveraging weak encryption keys

#### Possible mitigations

Generate a random symmetric key of sufficient length for authentication to IoT Hub. Refer:
<https://aka.ms/tmtcrypto#random-hub>

#### Steps

IoT Hub contains a device Identity Registry and while provisioning a device, automatically generates a random Symmetric key. It is recommended to use this feature of the Azure IoT Hub Identity Registry to generate the key used for authentication. IoT Hub also allows for a key to be specified while creating the device. If a key is generated outside of IoT Hub during device provisioning, it is recommended to create a random symmetric key or at least 256 bits.

---

### `TH44` — An adversary may replay stolen long-lived SaS tokens of IoT Hub

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway • Source: IoT Device, IoT Field Gateway

#### Description

An adversary may get access to SaS tokens used to authenticate to IoT Hub. If the lifetime of these tokens is not finite, the adversary may replay the stolen tokens indefinitely

#### Possible mitigations

Use finite lifetimes for generated SaS tokens. Refer: <https://aka.ms/tmtsmgmt#finite-tokens>

#### Steps

SaS tokens generated for authenticating to Azure IoT Hub should have a finite expiry period. Keep the SaS token lifetimes to a minimum to limit the amount of time they can be replayed in case the tokens are compromised.

**Documentation:** <https://stackoverflow.com/search?q=IoT+SaS+tokens>

---

### `TH50` — An adversary may spoof a device and connect to field gateway

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: IoT Field Gateway • Source: IoT Device

#### Description

An adversary may spoof a device and connect to field gateway. This may be achieved even when the device is registered in Cloud gateway since the field gateway may not be in sync with the device identites in cloud gateway

#### Possible mitigations

Authenticate devices connecting to the Field Gateway. Refer: <https://aka.ms/tmtauthn#authn-devices-field>

#### Steps

Ensure that each device is authenticated by the Field Gateway before accepting data from them and before facilitating upstream communications with the Cloud Gateway. Also, ensure that devices connect with a per device credential so that individual devices can be uniquely identified.

**Documentation:** <https://stackoverflow.com/questions/27749149/azure-event-hub-what-is-a-field-gateway>

---

### `TH55` — An adversary may replay stolen long-lived Resource tokens of CosmosDB

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: CosmosDB

#### Description

An adversary may get access to Resouce tokens used to authenticate to DocumentDB. If the lifetime of these tokens is not finite, the adversary may replay the stolen tokens for a long time.

#### Possible mitigations

Use minimum token lifetimes for generated Resource tokens. Refer: <https://aka.ms/tmtsmgmt#resource-tokens>

#### Steps

Reduce the timespan of resource token to a minimum value required. Resource tokens have a default valid timespan of 1 hour

**Documentation:** <https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes>

---

### `TH58` — An adversary may spoof a device by reusing the authentication tokens of one device in another

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Azure Event Hub

#### Description

If multiple devices use the same SaS token, then an adversary can spoof any device using a token that he or she has access to

#### Possible mitigations

Use per device authentication credentials using SaS tokens. Refer: <https://aka.ms/tmtauthn#authn-sas-tokens>

#### Steps

The Event Hubs security model is based on a combination of Shared Access Signature (SAS) tokens and event publishers. The publisher name represents the DeviceID that receives the token. This would help associate the tokens generated with the respective devices. All messages are tagged with originator on service side allowing detection of in-payload origin spoofing attempts. When authenticating devices, generate a per device SaS token scoped to a unique publisher.

**Documentation:** <https://azure.microsoft.com/documentation/articles/event-hubs-authentication-and-security-model-overview/>

---

### `TH68` — An adversary may gain unauthorized access to resources in Service Fabric

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Crosses: Service Fabric Trust Boundary

#### Description

If a service fabric cluster is not secured, it allow any anonymous user to connect to it if it exposes management endpoints to the public Internet.

#### Possible mitigations

Restrict anonymous access to Service Fabric Cluster. Refer: <https://aka.ms/tmtauthn#anon-access-cluster>

#### Steps

Clusters should always be secured to prevent unauthorized users from connecting to your cluster, especially when it has production workloads running on it. While creating a service fabric cluster, ensure that the security mode is set to "secure" and configure the required X.509 server certificate. Creating an "insecure" cluster will allow any anonymous user to connect to it if it exposes management endpoints to the public Internet.

**Documentation:** <https://azure.microsoft.com/documentation/articles/service-fabric-cluster-security>

---

### `TH69` — An adversary can spoof a node and access Service Fabric cluster

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Crosses: Service Fabric Trust Boundary

#### Description

If the same certificate that is used for node-to-node security is used for client-to-node security, it will be easy for an adversary to spoof and join a new node, in case the client-to-node certificate (which is often stored locally) is compromised

#### Possible mitigations

Ensure that Service Fabric client-to-node certificate is different from node-to-node certificate. Refer:
<https://aka.ms/tmtauthn#fabric-cn-nn>

#### Steps

Client-to-node certificate security is configured while creating the cluster either through the Azure portal, Resource Manager templates or a standalone JSON template by specifying an admin client certificate and/or a user client certificate. The admin client and user client certificates you specify should be different than the primary and secondary certificates you specify for Node-to-node security.

**Documentation:** <https://azure.microsoft.com/documentation/articles/service-fabric-cluster-security/#_client-to-node-certificate-security>

---

### `TH70` — An adversary can potentially spoof a client if weaker client authentication channels are used

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Crosses: Service Fabric Trust Boundary

#### Description

Azure AD authentication provides better control on identity management and hence it is a better alternative to authenticate clients to Service Fabric

#### Possible mitigations

Use AAD to authenticate clients to service fabric clusters. Refer: <https://aka.ms/tmtauthn#aad-client-fabric>

#### Steps

Clusters running on Azure can also secure access to the management endpoints using Azure Active Directory (AAD), apart from client certificates. For Azure clusters, it is recommended that you use AAD security to authenticate clients and certificates for node-to-node security.

**Documentation:** <https://azure.microsoft.com/documentation/articles/service-fabric-cluster-security/#security-recommendations>

---

### `TH72` — An adversary can spoof a node in Service Fabric cluster by using stolen certificates

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Build • **Effort:** Medium

**Applies to:** Crosses: Service Fabric Trust Boundary

#### Description

If self-signed or test certificates are stolen, it would be difficult to revoke them. An adversary can use stolen certificates and continue to get access to Service Fabric cluster.

#### Possible mitigations

Ensure that service fabric certificates are obtained from an approved Certificate Authority (CA). Refer:
<https://aka.ms/tmtauthn#fabric-cert-ca>

#### Steps

Service Fabric uses X.509 server certificates for authenticating nodes and clients. Some important things to consider while using certificates in service fabrics: Certificates used in clusters running production workloads should be created by using a correctly configured Windows Server certificate service or obtained from an approved Certificate Authority (CA). The CA can be an approved external CA or a properly managed internal Public Key Infrastructure (PKI) Never use any temporary or test certificates in production that are created with tools such as MakeCert.exe You can use a self-signed certificate, but should only do so for test clusters and not in production

---

### `TH74` — An adversary obtains refresh or access tokens from {source.Name} and uses them to obtain access to the {target.Name} API

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API • Source: Mobile Client

#### Description

On a public client (e.g. a mobile device), refresh tokens may be stolen and used by an attacker to obtain access to the API. Depending on the client type, there are different ways that tokens may be revealed to an attacker and therefore different ways to protect them, some involving how the software using the tokens requests, stores and refreshes them.

#### Possible mitigations

Use ADAL libraries to manage token requests from OAuth2 clients to AAD (or on-premises AD). Refer:
<https://aka.ms/tmtauthn#adal-oauth2>

#### Steps

The Azure AD authentication Library (ADAL) enables client application developers to easily authenticate users to cloud or on-premises Active Directory (AD), and then obtain access tokens for securing API calls. ADAL has many features that make authentication easier for developers, such as asynchronous support, a configurable token cache that stores access tokens and refresh tokens, automatic token refresh when an access token expires and a refresh token is available, and more. By handling most of the complexity, ADAL can help a developer focus on business logic in their application and easily secure resources without being an expert on security. Separate libraries are available for .NET, JavaScript (client and Node.js), iOS, Android and Java.

**Documentation:** <https://azure.microsoft.com/documentation/articles/active-directory-authentication-libraries/>

---

### `TH75` — An adversary can get access to a user's session due to improper logout from Azure AD

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Microsoft Entra ID • Source: API App, WCF, Web API, Web Application

#### Description

The session cookies is the identifier by which the server knows the identity of current user for each incoming request. If the attacker is able to steal the user token he would be able to access all user data and perform all actions on behalf of user.

#### Possible mitigations

Implement proper logout using ADAL methods when using Azure AD. Refer: <https://aka.ms/tmtsmgmt#logout-adal>

#### Steps

If the application relies on access token issued by Azure AD, the logout event handler should call

**Documentation:** <https://stackoverflow.com/questions/40241841/adal-azure-ad-authentication-users-login-cached-from-different-azure-ad-session>

---

### `TH76` — An adversary can get access to a user's session due to improper logout from ADFS

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: ADFS • Source: API App, WCF, Web API, Web Application

#### Description

The session cookies is the identifier by which the server knows the identity of current user for each incoming request. If the attacker is able to steal the user token he would be able to access all user data and perform all actions on behalf of user.

#### Possible mitigations

Implement proper logout using WsFederation methods when using ADFS. Refer: <https://aka.ms/tmtsmgmt#wsfederation-logout>

#### Steps

If the application relies on STS token issued by ADFS, the logout event handler should call WSFederationAuthenticationModule.FederatedSignOut method to log out the user. Also the current session should be destroyed, and the session token value should be reset and nullified.

**Documentation:** <https://stackoverflow.com/questions/44290083/proper-logoutrequest-for-single-logout-with-adfs-idp>

---

### `TH81` — An adversary can create a fake website and launch phishing attacks

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Description

Phishing is attempted to obtain sensitive information such as usernames, passwords, and credit card details (and sometimes, indirectly, money), often for malicious reasons, by masquerading as a Web Server which is a trustworthy entity in electronic communication

#### Possible mitigations

Verify X.509 certificates used to authenticate SSL, TLS, and DTLS connections. Refer:
<https://aka.ms/tmtcommsec#x509-ssltls> Ensure that authenticated ASP.NET pages incorporate UI Redressing or clickjacking defenses. Refer:
<https://aka.ms/tmtconfigmgmt#ui-defenses> Validate all redirects within the application are closed or done safely. Refer:
<https://aka.ms/tmtinputval#redirect-safe>

#### Steps

Applications that use SSL, TLS, or DTLS must fully verify the X.509 certificates of the entities they connect to. This includes verification of the certificates for: Domain name Validity dates (both beginning and expiration dates) Revocation status Usage (for example, Server Authentication for servers, Client Authentication for clients) Trust chain. Certificates must chain to a root certification authority (CA) that is trusted by the platform or explicitly configured by the administrator Key length of certificate's public key must be >2048 bits Hashing algorithm must be SHA256 and above

**Documentation:** <https://blogs.msdn.microsoft.com/ieinternals/2010/03/30/combating-clickjacking-with-x-frame-options/>

---

### `TH85` — An adversary can access Azure storage blobs and containers anonymously

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Azure Storage

#### Description

An adversary can gain access to Azure storage containers and blobs if anonymous access is provided to potentially sensitive data accidentally.

#### Possible mitigations

Ensure that only the required containers and blobs are given anonymous read access. Refer:
<https://aka.ms/tmtauthn#req-containers-anon>

#### Steps

By default, a container and any blobs within it may be accessed only by the owner of the storage account. To give anonymous users read permissions to a container and its blobs, one can set the container permissions to allow public access. Anonymous users can read blobs within a publicly accessible container without authenticating the request. Containers provide the following options for managing container access: Full public read access: Container and blob data can be read via anonymous request. Clients can enumerate blobs within the container via anonymous request, but cannot enumerate containers within the storage account. Public read access for blobs only: Blob data within this container can be read via anonymous request, but container data is not available. Clients cannot enumerate blobs within the container via anonymous request No public read access: Container and blob data can be read by the account owner only Anonymous access is best for scenarios where certain blobs should always be available for anonymous read access. For finer-grained control, one can create a shared access signature, which enables to delegate restricted access using different permissions and over a specified time interval. Ensure that containers and blobs, which may potentially contain sensitive data, are not given anonymous access accidentally

**Documentation:** <https://aka.ms/tmtauthn#req-containers-anon>

---

### `TH86` — An adversary may spoof {source.Name} and gain access to Web Application

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Description

If proper authentication is not in place, an adversary can spoof a source process or external entity and gain unauthorized access to the Web Application

#### Possible mitigations

Consider using a standard authentication mechanism to authenticate to Web Application. Refer:
<https://aka.ms/tmtauthn#standard-authn-web-app>

#### Steps

Authentication is the process where an entity proves its identity, typically through credentials, such as a user name and password. There are multiple authentication protocols available which may be considered. Some of them are listed below: Client certificates Windows based Forms based Federation - ADFS Federation - Azure AD Federation - Identity Server Consider using a standard authentication mechanism to identify the source process

**Documentation:** <https://www.owasp.org/index.php/Authentication_Cheat_Sheet>

---

### `TH87` — An adversary may spoof {source.Name} and gain access to Web API

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Description

If proper authentication is not in place, an adversary can spoof a source process or external entity and gain unauthorized access to the Web Application

#### Possible mitigations

Ensure that standard authentication techniques are used to secure Web APIs. Refer:
<https://aka.ms/tmtauthn#authn-secure-api>

#### Steps

Authentication is the process where an entity proves its identity, typically through credentials, such as a user name and password. There are multiple authentication protocols available which may be considered. Some of them are listed below: Client certificates Windows based Forms based Federation - ADFS Federation - Azure AD Federation - Identity Server Links in the references section provide low-level details on how each of the authentication schemes can be implemented to secure a Web API.

**Documentation:** <http://www.asp.net/web-api/overview/security/authentication-and-authorization-in-aspnet-web-api>

---

### `TH117` — An adversary may spoof an Azure administrator and gain access to Azure subscription portal

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Portal • Crosses: Azure Internet Boundary

#### Description

An adversary may spoof an Azure administrator and gain access to Azure subscription portal if the administrator's credentials are compromised.

#### Possible mitigations

Enable fine-grained access management to Azure Subscription using RBAC. Refer:
<https://aka.ms/tmtauthz#grained-rbac> Enable Azure Multi-Factor Authentication for Azure Administrators. Refer:
<https://aka.ms/tmtauthn#multi-factor-azure-admin>

#### Steps

Azure Role-Based Access Control (RBAC) enables fine-grained access management for Azure. Using RBAC, you can grant only the amount of access that users need to perform their jobs. Multi-factor authentication (MFA) is a method of authentication that requires more than one verification method and adds a critical second layer of security to user sign-ins and transactions. It works by requiring any two or more of the following verification methods: Something you know (typically a password) Something you have (a trusted device that is not easily duplicated, like a phone) Something you are (biometrics)

**Documentation:** <https://azure.microsoft.com/documentation/articles/role-based-access-control-configure/>

---

### `TH129` — An adversary may gain access to the field gateway by leveraging default login credentials

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway

#### Description

An adversary may gain access to the field gateway by leveraging default login credentials.

#### Possible mitigations

Ensure that the default login credentials of the field gateway are changed during installation. Refer:
<https://aka.ms/tmtconfigmgmt#default-change>

#### Steps

Ensure that the default login credentials of the field gateway are changed during installation

---

### `TH133` — An adversary may guess the client id and secrets of registered applications and impersonate them

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Identity Server

#### Possible mitigations

Ensure that cryptographically strong client id, client secret are used in Identity Server. Refer:
<https://aka.ms/tmtcrypto#client-server>

#### Steps

Ensure that cryptographically strong client ID, client secret are used in Identity Server. The following guidelines should be used while generating a client ID and secret: Generate a random GUID as the client ID Generate a cryptographically random 256-bit key as the secret

---

### `TH200` — An adversary may impersonate a tool or downstream service in an LLM agent's tool-calling chain 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, Claude Code, Lanchain

#### Description

When an LLM agent or orchestration component (e.g., AI Agent and Orchestration Platform / Lanchain) invokes external tools, plugins, or downstream services without strong, verifiable identity for each callee, an adversary can register, reroute, or substitute a malicious tool that the agent will trust and invoke. This enables impersonation of legitimate plugins, retrieval sources, MCP servers, or internal APIs and allows attacker-controlled responses to enter the agent's reasoning loop.

#### Possible mitigations

Require mutual authentication (mTLS, signed JWTs, or workload identities) for every tool, plugin, and MCP server the agent calls. Maintain a signed allowlist of approved tool endpoints and validate tool manifests/signatures before loading. Use managed identities or workload identity federation rather than long-lived shared secrets. Refer: OWASP LLM Top 10 - LLM07 / LLM08 (<https://owasp.org/www-project-top-10-for-large-language-model-applications/>)

#### Steps

Enumerate every tool, plugin, retrieval source, and MCP server the agent can invoke. For each, define how its identity is established at design time, how that identity is verified at runtime, and how revocation is handled. Avoid trusting tool identity solely from tool-supplied metadata.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH201` — An adversary may impersonate the LLM provider endpoint and return crafted completions 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AI LLM Providers, AI Platform

#### Description

If the application calls an external LLM provider (AI LLM Providers / AI Platform such as AWS Bedrock, Anthropic, Azure OpenAI) without strict endpoint verification — pinned hostname, certificate validation, and bearer-token/managed-identity authentication — an adversary positioned on the network or via DNS manipulation can impersonate the provider and return attacker-controlled completions, embeddings, or tool-call instructions that the application will treat as authoritative model output.

#### Possible mitigations

Pin LLM provider endpoints to specific FQDNs and validate TLS certificates against the provider's CA chain. Authenticate to the provider using short-lived credentials (managed identity, workload identity federation, or rotated API keys stored in a secrets manager). Reject any provider response that is not served over a verified TLS channel.

#### Steps

Document each external LLM endpoint, its hostname, authentication mechanism, and credential storage location. Confirm that provider SDKs are configured to fail closed on certificate validation errors and that no custom trust stores or 'insecure' flags are present.

**Documentation:** <https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-authentication>

---

### `TH220` — An LLM may produce fabricated outputs that spoof authoritative sources or identities 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

LLMs can produce confident, well-formed text that fabricates citations, attributes statements to real people or organizations, generates plausible-looking case law, invents API signatures, or imitates the writing style of a specific author. When such output is presented to end users without provenance markers or grounding, it can be mistaken for an authoritative source — a spoofing threat against the apparent author or source rather than the system itself.

#### Possible mitigations

Where factual accuracy or attribution matters, ground completions in verified retrieval sources and cite those sources in the output. Mark generative content as AI-generated in the user interface. For high-stakes domains (legal, medical, financial), require human review before content is presented as authoritative. Avoid impersonation of named real people in generated content unless explicitly licensed and disclosed.

#### Steps

Identify every surface where model output is presented to end users. For each, document whether output is grounded, how sources are cited, and how AI-generated content is labeled. Identify domains where human review is required.

**Documentation:** <https://genai.owasp.org/llmrisk/llm09-misinformation/>

---

### `TH229` — A managed AI platform may route inference to an attacker-substituted custom model deployment 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Bedrock, DataRobot, Databricks, Vertex

#### Description

Platforms that allow customer-imported or fine-tuned model deployments alongside foundation models (Bedrock custom models, Vertex Model Garden, Databricks Mosaic AI deployments) introduce a model-selection step where the deployment ID, ARN, or endpoint URI determines which model actually serves the request. If callers identify the model only by a mutable name (alias, tag, or human-readable label) without verifying the underlying immutable identifier, an actor with deploy permission can substitute a different model behind the same alias and serve crafted outputs to all callers.

#### Possible mitigations

Pin model invocation to immutable identifiers (specific model version IDs, ARNs, or endpoint URIs) rather than mutable aliases. Restrict the right to create or modify model aliases to a small set of release-management identities, separate from those who can call the model. Log and review every alias change.

#### Steps

For each model invocation in the design, document whether the caller pins to an immutable model version or to a mutable alias. Identify who can change the alias. Confirm the change control is appropriate for the trust placed in the model.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0010>

---

### `TH240` — Voice or avatar synthesis platforms may be used to impersonate real people in attacks against the organization or its customers 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ElevenLabs, Synthesia

#### Description

Voice synthesis (ElevenLabs) and avatar video synthesis (Synthesia) can produce convincing impersonations of named individuals - including the organization's executives, customers, or support staff. When the design integrates these capabilities, the organization assumes risk of misuse: voice-cloned executive impersonation in vishing attacks, fake video communications to customers, or unauthorized cloning of customer voices captured by the application. The design-time concern is what voices/likenesses can be cloned and under what consent regime.

#### Possible mitigations

Restrict voice and likeness cloning to an enrolled set of consenting subjects with verified-consent records. Disable or gate any feature that allows cloning from short user-supplied samples. Watermark synthesized output where the platform supports it. Apply out-of-band verification for sensitive communications that would otherwise rely on voice or video alone.

#### Steps

Document who can submit voice or face samples to the platform, what consent verification is applied, and how synthesized output is labeled. Identify business processes that authenticate by voice or video and add an out-of-band verification step.

**Documentation:** <https://genai.owasp.org/llmrisk/llm09-misinformation/>

---

### `TH275` — An adversary may obtain a Power BI embed token and impersonate the embedding application's authorized scope in Fabric

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Power BI

#### Description

Power BI / Fabric reports embedded into custom applications use embed tokens that authorize the embedded session to access specific reports, dashboards, or semantic models. The embed token represents the application's chosen scope - typically broader than any single end user. If the token is leaked through client-side script exposure, browser storage, log files, referer headers, or careless logging in the embedding host, an adversary can impersonate the embedding application's authorization and access the embedded artifacts directly, bypassing the application's own access checks.

#### Possible mitigations

Generate embed tokens server-side only and pass them to the client over an authenticated, scope-limited session. Use the shortest viable token lifetime and never persist embed tokens in browser storage or logs. Where supported, use embed-for-your-customers with row-level security enforced inside the semantic model, so a leaked token still produces only the intended user's data. Treat embed-token issuance as a server-side audited operation.

#### Steps

Identify every flow that issues or carries embed tokens. For each, document where the token is generated, how it reaches the client, its lifetime, and whether the underlying semantic model enforces RLS that limits the leaked-token blast radius.

**Documentation:** <https://learn.microsoft.com/en-us/power-bi/developer/embedded/embed-tokens>

---

### `TH276` — A Fabric Data Agent invocation that supplies a service principal token will not authenticate as that principal and may execute under an unintended identity 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Data Agent

#### Description

Fabric Data Agents do not support service principal authentication; they require user identity, and integration via Azure AI Foundry uses Identity Passthrough (OBO) to forward the calling user's identity. Designs that assume an SPN can be used to invoke a Data Agent on behalf of a workload may inadvertently fall back to a user identity cached in the calling process, or fail in ways that are bridged by hard-coded or shared user credentials. Either outcome breaks identity attribution and can cause queries to execute under a higher-privilege user's permissions than the workload should hold.

#### Possible mitigations

Confirm at design time that every Data Agent invocation path uses a user identity propagated through OBO. Reject SPN tokens at the calling layer rather than allowing them to be transparently substituted. For unattended workloads that need agent-style data access, use a different mechanism (direct query against the data source under a managed identity scoped to the data) rather than the Data Agent.

#### Steps

Map every caller of each Data Agent. For each caller, document the identity flow (interactive user, OBO from a downstream service, attempted SPN). Identify any path that would silently substitute a different identity, and either remove the path or design an alternative.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-science/concept-data-agent>

---

### `TH277` — Scheduled Fabric pipelines, notebooks, and refreshes may execute under a different identity than the user who authored them, creating attribution gaps

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Engineering, Microsoft Fabric Data Factory, Microsoft Fabric Power BI

#### Description

Fabric pipelines, scheduled notebook runs, and dataset refreshes typically execute under a configured run identity (the item owner, a service principal, or a configured connection identity), not the identity of the user who last edited the artifact. Users editing the definition during the day and seeing it work interactively under their own permissions may not realize the scheduled run uses a different and possibly broader identity. An attacker who compromises the editing surface can have changes applied with the run identity's privilege.

#### Possible mitigations

Make the scheduled-run identity explicit in the design and document it for each pipeline, notebook, or refresh. Scope that identity to the minimum required for the production workload, separately from the identities used during interactive development. Restrict edit rights on production items to a small set of identities trusted with the run-identity's privilege. Log every scheduled run with both the configured run identity and the identity that last edited the artifact.

#### Steps

List each scheduled item, the identity it runs under, and the identities that can edit its definition. Confirm the editor set is consistent with delegating that run-identity's access.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-factory/pipeline-runs>

---

### `TH293` — Legacy authentication protocols (basic auth, IMAP/POP/SMTP AUTH, older MAPI) bypass Microsoft Entra MFA and Conditional Access

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Multi Factor Authentication

#### Description

Microsoft Entra Conditional Access policies that enforce MFA apply only to authentication flows that support modern authentication. Legacy authentication protocols - basic auth, IMAP/POP/SMTP AUTH, older MAPI clients, ActiveSync v14- - typically bypass MFA enforcement and any Conditional Access controls that depend on user/device context. An attacker holding a stolen password but blocked by MFA can authenticate through a legacy protocol to the same account and gain access without challenge.

#### Possible mitigations

Disable legacy authentication tenant-wide via Conditional Access 'Block legacy authentication' policy. Where legacy auth must remain enabled for specific accounts, scope the exception narrowly and monitor those accounts for anomalous sign-in patterns. Audit sign-in logs for legacy auth attempts and treat them as security signals.

#### Steps

Identify all accounts and applications that use legacy authentication protocols. Define a deprecation plan and a Conditional Access policy that blocks legacy auth, with exceptions documented and monitored.

**Documentation:** <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication>

---

### `TH329` — Power BI Embedded scenarios using the master user (service account) pattern impersonate that account for every embedded session, masking per-user attribution

**STRIDE:** `S` (Spoofing) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Power BI Embedded

#### Description

Power BI Embedded supports two embedding scenarios: 'embed for your customers' (using a master user or service principal whose identity is shared across all embedded sessions) and 'embed for your organization' (each user signs in with their own Microsoft Entra identity). The master user pattern is operationally simpler but means every embedded session appears in Power BI audit logs as the master user, with no per-end-user attribution. RLS in the embedded report must be enforced via embed-token claims rather than the calling user's actual permissions.

#### Possible mitigations

Use 'embed for your organization' where end users have Microsoft Entra identities and per-user attribution is needed. Where the master user pattern is required for B2C scenarios, enforce RLS via embed-token effective identity claims and log the end-user identity at the embedding application layer with correlation IDs that match Power BI audit records. Restrict the master user account's permissions to the minimum embedded content requires.

#### Steps

For each Power BI Embedded integration, document the embedding scenario (master user vs Entra), the RLS strategy, and the audit correlation between embedding application logs and Power BI audit.

**Documentation:** <https://learn.microsoft.com/en-us/power-bi/developer/embedded/embed-tokens>

---

### `TH355` — AWS IAM Roles Anywhere or SAML/OIDC federation may grant role assumption based on weakly-validated external identity claims

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Data

#### Description

AWS supports federated role assumption through IAM Identity Center (formerly SSO), SAML 2.0 federation, OIDC federation (e.g., for GitHub Actions, EKS workloads), and IAM Roles Anywhere (using X.509 certificates from a trusted CA). Each federation path defines a trust relationship in the role's trust policy that maps external claims to role assumption. Weak trust conditions — accepting any subject from the OIDC issuer, accepting any certificate from a broad CA, or omitting the audience claim check — let attackers who control any account in the federated realm assume the role. The AWS principal in audit logs is the role; the underlying federated identity may be unverifiable.

#### Possible mitigations

In role trust policies for federated identity, require specific subject (sub), audience (aud), and issuer (iss) claims that uniquely identify the intended workload. For GitHub Actions OIDC, scope sub to a specific repo and ref pattern. For IAM Roles Anywhere, scope to specific certificate subjects and require trust anchor of an internal CA, not a public root. Audit federated role assumption events with the underlying federated identity attribute, not just the AWS role.

#### Steps

List roles with federated trust policies. Document the federated identity provider, the trust conditions on subject/audience/issuer, and the audit destination for assumption events with full federated identity context.

**Documentation:** <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>

---

### `TH381` — SaaS platforms that allow user-controlled display names enable internal impersonation by setting a display name matching another employee or executive

**STRIDE:** `S` (Spoofing) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Aero, Jira, Microsoft 365, Monday, Notion, Salesforce, Slack, Trello, Zoom

#### Description

Slack, Zoom, Notion, and many work-management platforms let users edit their own display name freely. An attacker (insider, or external attacker who has compromised any account) can set their display name to match a colleague or executive — 'CEO Name', 'IT Help Desk' — and then post messages, join calls, or send DMs that appear to come from the impersonated party. The underlying user ID is different but rarely visible in chat threads or call rosters, and recipients trust the display name. This is a foothold for social-engineering attacks against other internal users.

#### Possible mitigations

Restrict display-name changes through the IdP rather than allowing in-SaaS editing where the platform supports it (e.g., SCIM-managed display names). Disable name changes in tenant policy. For the SaaS that don't support locking, train users to verify identity via the user profile / @mention rather than display name for sensitive requests, and to confirm out-of-band before acting on financial or credential requests.

#### Steps

Document the display-name change policy per SaaS in scope. Where the SaaS allows free-form name editing, document compensating controls (verification training, MFA on sensitive actions, dual-approval workflows).

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/iam/iam-01/>

---

### `TH383` — An AI Agent acting on behalf of a user may present unverified identity claims to downstream services 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent

#### Description

An AI Agent that calls downstream APIs, tools, or data services on a user's behalf may forward bearer tokens, session cookies, or self-asserted user identifiers without those downstream services being able to distinguish a request originated by the human principal from one originated autonomously by the agent. Without delegated identity that carries actor (agent) and subject (user) claims separately, downstream systems cannot enforce policies that depend on knowing whether a human approved the action.

#### Possible mitigations

Use a delegation protocol that carries both actor and subject claims (such as OAuth 2.0 Token Exchange or On-Behalf-Of). Issue agent-specific identities and require downstream services to evaluate both the agent identity and the impersonated user. Do not rely on a single bearer token to convey both. Refuse to forward credentials whose audience does not match the called service.

#### Steps

Inventory each downstream service the agent calls. For each, document whether the service can distinguish agent-originated traffic from human-originated traffic. Where it cannot, introduce a delegation token format that carries the actor identity.

**Documentation:** <https://www.rfc-editor.org/rfc/rfc8693>

---

### `TH390` — An Apache Airflow DAG may execute under a service identity that obscures the human owner and approver of the workflow

**STRIDE:** `S` (Spoofing) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Apache Airflow

#### Description

Airflow DAGs run on a worker under a single service identity regardless of which human authored, scheduled, or modified the DAG. Downstream systems see only the worker identity and cannot distinguish a DAG written by an authorized engineer from one introduced by another author with DAG repository write access. Identity for downstream attribution does not match identity for code authorship.

#### Possible mitigations

Bind each DAG's effective service identity to a code-owner record validated at deploy time. Require signed commits or merge approval for DAG changes and propagate the approver identity into the DAG run metadata. Where downstream systems support it, use OBO or token exchange so the approver identity is visible to the called service.

#### Steps

Map each DAG to its code-owner. Confirm a review/approval gate exists for DAG changes. Verify that DAG run metadata records the approver, not just the worker identity.

**Documentation:** <https://airflow.apache.org/docs/apache-airflow/stable/security/index.html>

---

### `TH405` — Fabric Eventstream custom endpoints accept events from any caller holding the connection key, which is shared and rarely rotated

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Fabric Eventstream

#### Description

A custom-endpoint source on an eventstream issues a connection key that any producer can use to send events. The key is typically copied into producer configuration, distributed across teams, and seldom rotated. The eventstream cannot distinguish a legitimate producer from an actor who obtained the key, and downstream consumers see all events as equally authentic.

#### Possible mitigations

Prefer source types that support per-producer identity (Event Hubs with managed identity, IoT Hub per-device tokens) over shared-key custom endpoints. Where a custom endpoint is required, rotate keys on a defined schedule and on every producer-side change. Enrich events with verifiable producer identity downstream.

#### Steps

List custom-endpoint sources. Document the key custodians per producer and the rotation cadence.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/event-streams/add-source-custom-app>

---

### `TH408` — Cross-boundary calls to or from Fabric workloads may rely on shared keys or connection strings whose authentication is unattributable

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Crosses: Microsoft Fabric Boundary

#### Description

Connections between Fabric and external systems (storage accounts, on-premises databases via gateway, REST APIs) may be configured with connection strings, account keys, or basic auth credentials shared by every workload using that connection. The far side cannot tell which Fabric item or principal made a given call. Compromise of one workload's credential exposes the connection to all.

#### Possible mitigations

Prefer managed identity, OAuth, or service principal authentication where the external system supports it. Bind a separate credential per workload that needs the connection. Rotate and audit any remaining shared-key connections.

#### Steps

List connections crossing the Fabric boundary. For each, document the credential type and which workloads share it.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/security/security-managed-identities-overview>

---

### `TH423` — Fabric Data Activator triggers may fire from event content the producer did not authenticate, causing actions on adversary-shaped events

**STRIDE:** `S` (Spoofing) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Activator

#### Description

Activator rules evaluate event content (from eventstreams or Power BI metrics) and invoke actions when conditions match. If the upstream event source accepts unauthenticated or weakly-authenticated input, an attacker who can write to that source can shape events to match an Activator rule and cause it to fire. The downstream action (email, webhook, Teams message, Power Automate) executes under workspace identity, not the event author's.

#### Possible mitigations

Authenticate event producers (managed identity, per-producer keys) and reject unsigned events. Validate event payload against an expected schema before evaluation. Ensure the Activator action's identity and permissions reflect the lowest trust level among producers feeding the rule.

#### Steps

For each Activator rule, trace the event source(s) feeding it and confirm producer authentication. Verify schema validation precedes rule evaluation.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-activator/data-activator-introduction>

---

### `TH425` — Fabric IQ ontology callers may rely on cached resolution that lags behind ontology revisions, producing answers grounded in stale relationships 🤖

**STRIDE:** `S` (Spoofing) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric IQ

#### Description

Ontology resolution in Fabric IQ involves entity bindings, relationship definitions, and cached query plans. When a steward updates the ontology to reflect a corrected relationship or a removed binding, in-flight callers, cached plans, and downstream Data Agents may continue to resolve the prior version for some interval. During that interval, identical queries from different callers can produce different answers, and the answer presented may not match the current authoritative ontology.

#### Possible mitigations

Document the ontology update propagation interval. For changes intended as access-control or correctness fixes, communicate the propagation window to callers. Where strict consistency matters, route through a path that bypasses cache. Surface the ontology version evaluated alongside each answer.

#### Steps

Test the propagation interval by updating an ontology and timing when callers see the change. Document the result.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/iq/overview>

---

## `T` — Tampering (61)

> Altering bits in a process, on the wire, or between processes.

🤖 **15 of these threats are LLM-tagged.**

### `TH24` — An adversary can deface the target web application by injecting malicious code or uploading dangerous files

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API, Web Application • Source: Browser

#### Description

Website defacement is an attack on a website where the attacker changes the visual appearance of the site or a webpage.

#### Possible mitigations

Implement Content Security Policy (CSP), and disable inline javascript. Refer:
<https://aka.ms/tmtconfigmgmt#csp-js> Enable browser's XSS filter. Refer:
<https://aka.ms/tmtconfigmgmt#xss-filter> Access third party javascripts from trusted sources only. Refer:
<https://aka.ms/tmtconfigmgmt#js-trusted> Enable ValidateRequest attribute on ASP.NET Pages. Refer:
<https://aka.ms/tmtconfigmgmt#validate-aspnet> Ensure that each page that could contain user controllable content opts out of automatic MIME sniffing . Refer:
<https://aka.ms/tmtinputval#out-sniffing> Use locally-hosted latest versions of JavaScript libraries . Refer:
<https://aka.ms/tmtconfigmgmt#local-js> Ensure appropriate controls are in place when accepting files from users. Refer:
<https://aka.ms/tmtinputval#controls-users> Disable automatic MIME sniffing. Refer:
<https://aka.ms/tmtconfigmgmt#mime-sniff> Encode untrusted web output prior to rendering. Refer:
<https://aka.ms/tmtinputval#rendering> Perform input validation and filtering on all string type Model properties. Refer:
<https://aka.ms/tmtinputval#typemodel> Ensure that the system has inbuilt defenses against misuse. Refer:
<https://aka.ms/tmtauditlog#inbuilt-defenses> Enable HTTP Strict Transport Security (HSTS). Refer:
<https://aka.ms/tmtcommsec#http-hsts> Implement input validation on all string type parameters accepted by Controller methods. Refer:
<https://aka.ms/tmtinputval#string-method> Avoid using Html.Raw in Razor views. Refer:
<https://aka.ms/tmtinputval#html-razor> Sanitization should be applied on form fields that accept all characters e.g, rich text editor . Refer:
<https://aka.ms/tmtinputval#richtext> Do not assign DOM elements to sinks that do not have inbuilt encoding . Refer:
<https://aka.ms/tmtinputval#inbuilt-encode>

**Documentation:** <http://content-security-policy.com/>

---

### `TH33` — An attacker steals messages off the network and replays them in order to steal a user's session

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: API App, WCF, Web API, Web Application • Source: Browser

#### Possible mitigations

Reduce session timeouts. Avoid storing sensitive data in session stores. Secure the channel to the session store. Authenticate and authorize access to the session store.

**Documentation:** <https://docs.microsoft.com/en-us/azure/app-service/app-service-authentication-how-to>

---

### `TH39` — An adversary may exploit known vulnerabilities in unpatched devices

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Source: IoT Device, IoT Field Gateway

#### Description

An adversary may leverage known vulnerabilities and exploit a device if the firmware of the device is not updated

#### Possible mitigations

Ensure that the Cloud Gateway implements a process to keep the connected devices firmware up to date. Refer:
<https://aka.ms/tmtconfigmgmt#cloud-firmware>

#### Steps

LWM2M is a protocol from the Open Mobile Alliance for IoT Device Management. Azure IoT device management allows to interact with physical devices using device jobs. Ensure that the Cloud Gateway implements a process to routinely keep the device and other configuration data up to date using Azure IoT Hub Device Management.

**Documentation:** <https://azure.microsoft.com/documentation/articles/iot-hub-device-management-overview/>

---

### `TH43` — An adversary may tamper {source.Name} and extract cryptographic key material from it

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Source: IoT Device, IoT Field Gateway

#### Description

An adversary may partially or wholly replace the software running on {target.Name}, potentially allowing the replaced software to leverage the genuine identity of the device if the key material or the cryptographic facilities holding key materials were available to the illicit program. For example an attacker may leverage extracted key material to intercept and suppress data from the device on the communication path and replace it with false data that is authenticated with the stolen key material.

#### Possible mitigations

Store Cryptographic Keys securely on IoT Device. Refer: <https://aka.ms/tmtcrypto#keys-iot>

#### Steps

Symmetric or Certificate Private keys securely in a hardware protected storage like TPM or Smart Card chips. Windows 10 IoT Core supports the user of a TPM and there are several compatible TPMs that can be used: <https://docs.microsoft.com/windows/iot-core/secure-your-device/tpm#discrete-tpm-dtpm>. It is recommended to use a Firmware or Discrete TPM. A Software TPM should only be used for development and testing purposes. Once a TPM is available and the keys are provisioned in it, the code that generates the token should be written without hard coding any sensitive information in it.

**Documentation:** <https://developer.microsoft.com/windows/iot/docs/tpm>

---

### `TH45` — An adversary may attempt to intercept encrypted traffic sent to {target.Name}

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: IoT Device, IoT Field Gateway • Source: IoT Cloud Gateway, IoT Field Gateway

#### Description

An adversary may perform a Man-In-The-Middle attack on the encrypted traffic sent to {target.Name}

#### Possible mitigations

Verify X.509 certificates used to authenticate SSL, TLS, and DTLS connections. Refer:
<https://aka.ms/tmtcommsec#x509-ssltls>

#### Steps

Applications that use SSL, TLS, or DTLS must fully verify the X.509 certificates of the entities they connect to. This includes verification of the certificates for: Domain name Validity dates (both beginning and expiration dates) Revocation status Usage (for example, Server Authentication for servers, Client Authentication for clients) Trust chain. Certificates must chain to a root certification authority (CA) that is trusted by the platform or explicitly configured by the administrator Key length of certificate's public key must be >2048 bits Hashing algorithm must be SHA256 and above

**Documentation:** <https://blogs.msdn.microsoft.com/kaushal/2015/05/27/client-certificate-authentication-part-1/>

---

### `TH46` — An adversary may execute unknown code on {target.Name}

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: IoT Device, IoT Field Gateway

#### Description

An adversary may launch malicious code into {target.Name} and execute it

#### Possible mitigations

Ensure that unknown code cannot execute on devices. Refer: <https://aka.ms/tmtconfigmgmt#unknown-exe>

#### Steps

UEFI Secure Boot restricts the system to only allow execution of binaries signed by a specified authority. This feature prevents unknown code from being executed on the platform and potentially weakening the security posture of it. Enable UEFI Secure Boot and restrict the list of certificate authorities that are trusted for signing code. Sign all code that is deployed on the device using one of the trusted authorities.

**Documentation:** <https://docs.microsoft.com/windows/iot-core/secure-your-device/securebootandbitlocker>

---

### `TH47` — An adversary may tamper the OS of a device and launch offline attacks

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Source: IoT Device

#### Description

An adversary may launch offline attacks attacks made by disabling or circumventing the installed operating system, or made by physically separating the storage media from the device in order to attack the data separately.

#### Possible mitigations

Encrypt OS and additional partitions of IoT Device with Bitlocker. Refer: <https://aka.ms/tmtconfigmgmt#partition-iot>

#### Steps

Windows 10 IoT Core implements a lightweight version of bit-locker Device Encryption, which has a strong dependency on the presence of a TPM on the platform, including the necessary preOS protocol in UEFI that conducts the necessary measurements. These preOS measurements ensure that the OS later has a definitive record of how the OS was launched.Encrypt OS partitions using bit-locker and any additional partitions also in case they store any sensitive data.

---

### `TH61` — An adversary may eavesdrop the communication between the a client and Event Hub, IoT Hub, Service Bus or Event Grid

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Event Hub, Event Grid, IoT Hub, Service Bus

#### Description

An adversary may eavesdrop and interfere with the communication between a client and Event Hub and possibly tamper the data that is transmitted

#### Possible mitigations

Secure communication to Event Hub using SSL/TLS. Refer: <https://aka.ms/tmtcommsec#comm-ssltls>

#### Steps

Secure AMQP or HTTP connections to Event Hub using SSL/TLS

**Documentation:** <https://azure.microsoft.com/documentation/articles/event-hubs-authentication-and-security-model-overview/>

---

### `TH66` — An adversary can tamper the data uploaded to {target.Name} when HTTPS cannot be enabled

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Storage

#### Description

An adversary can tamper the data uploaded to {target.Name} storage when HTTPS cannot be enabled.

#### Possible mitigations

Validate MD5 hash after downloading blob if HTTPS cannot be enabled. Refer: <https://aka.ms/tmtcommsec#md5-https>

#### Steps

<https://blogs.msdn.microsoft.com/windowsazurestorage/2011/02/17/windows-azure-blob-md5-overview/>

**Documentation:** <https://blogs.msdn.microsoft.com/windowsazurestorage/2011/02/17/windows-azure-blob-md5-overview/>

---

### `TH88` — An adversary can tamper with Data Factory and can cause undesirable consequences

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Data Factory, Azure Data Service • Source: Azure Data Factory, Azure Data Service

#### Description

The source of an integration package or app is the individual or organization that created the package. Running an integration package or app from an unknown or untrusted source might be risky.

#### Possible mitigations

ADF Jobs credentials should be encrypted.

#### Steps

Create a JSON file named SqlServerLinkedService.json in any folder with the following content: Replace servername, databasename, username, and password with values for your SQL Server before saving the file. And, replace integration runtime name with the name of your integration runtime.

**Documentation:** <https://docs.microsoft.com/en-us/azure/data-factory/encrypt-credentials-self-hosted-integration-runtime>

---

### `TH89` — An adversary may leverage the lack of monitoring systems and trigger anamolous traffic to database

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, Database, SQL Data Warehouse

#### Description

An adversary may leverage the lack of intrusion detection and prevention of anomalous database activities and trigger anamolous traffic to database

#### Possible mitigations

Enable Threat detection on Azure SQL database. Refer: <https://aka.ms/tmtauditlog#threat-detection>

#### Steps

Threat Detection detects anomalous database activities indicating potential security threats to the database. It provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users can explore the suspicious events using Azure SQL Database Auditing to determine if they result from an attempt to access, breach or exploit data in the database. Threat Detection makes it simple to address potential threats to the database without the need to be a security expert or manage advanced security monitoring systems

**Documentation:** <https://azure.microsoft.com/documentation/articles/sql-database-threat-detection-get-started/>

---

### `TH92` — An adversary may gain unauthorized access to IoT Field Gateway and tamper its OS

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Source: IoT Field Gateway

#### Description

An adversary may gain unauthorized access to {source.Name}, tamper its OS and get access to confidential information in the field gateway

#### Possible mitigations

Encrypt OS and additional partitions of IoT Field Gateway with Bitlocker. Refer:
<https://aka.ms/tmtconfigmgmt#field-bitlocker>

#### Steps

Windows 10 IoT Core implements a lightweight version of bit-locker Device Encryption, which has a strong dependency on the presence of a TPM on the platform, including the necessary preOS protocol in UEFI that conducts the necessary measurements. These preOS measurements ensure that the OS later has a definitive record of how the OS was launched.Encrypt OS partitions using bit-locker and any additional partitions also in case they store any sensitive data.

---

### `TH95` — An adversary can reverse engineer and tamper binaries

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Source: Mobile Client

#### Description

An adversary can use various tools, reverse engineer binaries and abuse them by tampering

#### Possible mitigations

Obfuscate generated binaries before distributing to end users. Refer: <https://aka.ms/tmtdata#binaries-end>

#### Steps

Generated binaries (assemblies within apk) should be obfuscated to stop reverse engineering of assemblies.Tools like CryptoObfuscator may be used for this purpose.

**Documentation:** <http://www.ssware.com/cryptoobfuscator/obfuscator-net.htm>

---

### `TH96` — An adversary can gain access to sensitive data by performing SQL injection through Web App

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** —

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Description

SQL injection is an attack in which malicious code is inserted into strings that are later passed to an instance of SQL Server for parsing and execution. The primary form of SQL injection consists of direct insertion of code into user-input variables that are concatenated with SQL commands and executed. A less direct attack injects malicious code into strings that are destined for storage in a table or as metadata. When the stored strings are subsequently concatenated into a dynamic SQL command, the malicious code is executed.

#### Possible mitigations

Ensure that type-safe parameters are used in Web Application for data access. Refer:
<https://aka.ms/tmtinputval#typesafe>

#### Steps

If you use the Parameters collection, SQL treats the input is as a literal value rather then as executable code. The Parameters collection can be used to enforce type and length constraints on input data. Values outside of the range trigger an exception. If type-safe SQL parameters are not used, attackers might be able to execute injection attacks that are embedded in the unfiltered input. Use type safe parameters when constructing SQL queries to avoid possible SQL injection attacks that can occur with unfiltered input. You can use type safe parameters with stored procedures and with dynamic SQL statements. Parameters are treated as literal values by the database and not as executable code. Parameters are also checked for type and length.

**Documentation:** <https://weblogs.asp.net/jhallal/building-secure-asp-net-mvc-web-applications>

---

### `TH97` — An adversary can gain access to sensitive data by performing SQL injection through Web API

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Web API

#### Description

SQL injection is an attack in which malicious code is inserted into strings that are later passed to an instance of SQL Server for parsing and execution. The primary form of SQL injection consists of direct insertion of code into user-input variables that are concatenated with SQL commands and executed. A less direct attack injects malicious code into strings that are destined for storage in a table or as metadata. When the stored strings are subsequently concatenated into a dynamic SQL command, the malicious code is executed.

#### Possible mitigations

Ensure that type-safe parameters are used in Web API for data access. Refer:
<https://aka.ms/tmtinputval#typesafe-api>

#### Steps

If you use the Parameters collection, SQL treats the input is as a literal value rather then as executable code. The Parameters collection can be used to enforce type and length constraints on input data. Values outside of the range trigger an exception. If type-safe SQL parameters are not used, attackers might be able to execute injection attacks that are embedded in the unfiltered input. Use type safe parameters when constructing SQL queries to avoid possible SQL injection attacks that can occur with unfiltered input. You can use type safe parameters with stored procedures and with dynamic SQL statements. Parameters are treated as literal values by the database and not as executable code. Parameters are also checked for type and length.

**Documentation:** <https://weblogs.asp.net/jhallal/building-secure-asp-net-mvc-web-applications>

---

### `TH98` — An adversary can gain access to sensitive data stored in Web App's config files

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Web Application

#### Description

An adversary can gain access to the config files. and if sensitive data is stored in it, it would be compromised.

#### Possible mitigations

Encrypt sections of Web App's configuration files that contain sensitive data. Refer:
<https://aka.ms/tmtdata#encrypt-data>

#### Steps

Configuration files such as the Web.config, appsettings.json are often used to hold sensitive information, including user names, passwords, database connection strings, and encryption keys. If you do not protect this information, your application is vulnerable to attackers or malicious users obtaining sensitive information such as account user names and passwords, database names and server names. Based on the deployment type (azure/on-prem), encrypt the sensitive sections of config files using DPAPI or services like Azure Key Vault.

**Documentation:** <https://msdn.microsoft.com/library/ff647398.aspx>

---

### `TH100` — An adversary can execute remote code on the server through XSLT scripting

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application

#### Possible mitigations

Disable XSLT scripting for all transforms using untrusted style sheets. Refer:
<https://aka.ms/tmtinputval#disable-xslt>

#### Steps

XSLT supports scripting inside style sheets using the msxml:script element. This allows custom functions to be used in an XSLT transformation. The script is executed under the context of the process performing the transform. XSLT script must be disabled when in an untrusted environment to prevent execution of untrusted code. If using .NET: XSLT scripting is disabled by default; however, you must ensure that it has not been explicitly enabled through the XsltSettings.EnableScript property.

**Documentation:** <https://msdn.microsoft.com/library/ms763800(v=vs.85).aspx>

---

### `TH105` — An adversary can tamper critical database securables and deny the action

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, Database, SQL Data Warehouse

#### Possible mitigations

Add digital signature to critical database securables. Refer: <https://aka.ms/tmtcrypto#securables-db>

#### Steps

In cases where the integrity of a critical database securable has to be verified, digital signatures should be used. Database securables such as a stored procedure, function, assembly, or trigger can be digitally signed. Below is an example of when this can be useful: Let us say an ISV (Independent Software Vendor) has provided support to a software delivered to one of their customers. Before providing support, the ISV would want to ensure that a database securable in the software was not tampered either by mistake or by a malicious attempt. If the securable is digitally signed, the ISV can verify its digital signature and validate its integrity.

**Documentation:** <https://msdn.microsoft.com/library/ms181700>

---

### `TH108` — An adversary may inject malicious inputs into an API and affect downstream processes

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Possible mitigations

Ensure that model validation is done on Web API methods. Refer: <https://aka.ms/tmtinputval#validation-api> Implement input validation on all string type parameters accepted by Web API methods. Refer:
<https://aka.ms/tmtinputval#string-api>

#### Steps

When a client sends data to a web API, it is mandatory to validate the data before doing any processing. For ASP.NET Web APIs which accept models as input, use data annotations on models to set validation rules on the properties of the model.

**Documentation:** <http://www.asp.net/web-api/overview/formats-and-model-binding/model-validation-in-aspnet-web-api>

---

### `TH132` — An Adversary can view the message and may tamper the message

**STRIDE:** `T` (Tampering) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: WCF

#### Possible mitigations

WCF: Set Message security Protection level to EncryptAndSign. Refer: <https://aka.ms/tmtcommsec#message-protection>

#### Steps

EXPLANATION: When Protection level is set to "none" it will disable message protection. Confidentiality and integrity is achieved with appropriate level of setting. RECOMMENDATIONS: when Mode=None - Disables message protection when Mode=Sign - Signs but does not encrypt the message; should be used when data integrity is important when Mode=EncryptAndSign - Signs and encrypts the message Consider turning off encryption and only signing your message when you just need to validate the integrity of the information without concerns of confidentiality. This may be useful for operations or service contracts in which you need to validate the original sender but no sensitive data is transmitted. When reducing the protection level, be careful that the message does not contain any personally identifiable information (PII).

**Documentation:** <https://msdn.microsoft.com/library/ff650862.aspx>

---

### `TH134` — An adversary may spread malware, steal or tamper data due to lack of endpoint protection on devices

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Crosses: Machine Trust Boundary

#### Description

An adversary may spread malware, steal or tamper data due to lack of endpoint protection on devices. Scenarios such as stealing a user's laptop and extracting data from hard disk, luring users to install malware, exploit unpatched OS etc.

#### Possible mitigations

Ensure that devices have end point security controls configured as per organizational policies. Refer:
<https://aka.ms/tmtconfigmgmt#controls-policies>

#### Steps

Ensure that devices have end-point security controls such as bit-locker for disk-level encryption, anti-virus with updated signatures, host based firewall, OS upgrades, group policies etc. are configured as per organizational security policies.

---

### `TH137` — An adversary may reverse engineer deployed binaries

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Crosses: Machine Trust Boundary

#### Possible mitigations

Ensure that binaries are obfuscated if they contain sensitive information. Refer:
<https://aka.ms/tmtdata#binaries-info>

#### Steps

Ensure that binaries are obfuscated if they contain sensitive information such as trade secrets, sensitive business logic that should not reversed. This is to stop reverse engineering of assemblies. Tools like CryptoObfuscator may be used for this purpose.

**Documentation:** <https://www.owasp.org/index.php/.NET_Obfuscation>

---

### `TH138` — An adversary may tamper deployed binaries

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Crosses: Machine Trust Boundary

#### Possible mitigations

Ensure that deployed application's binaries are digitally signed. Refer: <https://aka.ms/tmtauthn#binaries-signed>

#### Steps

Ensure that deployed application's binaries are digitally signed so that the integrity of the binaries can be verified

**Documentation:** <https://docs.microsoft.com/en-us/dotnet/framework/tools/signtool-exe>

---

### `TH202` — An adversary may alter LLM behavior through direct prompt injection in user input 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain • Source: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

An attacker who controls any portion of the prompt sent to the model — through a chat field, API parameter, uploaded file, or form input — can inject instructions that override system prompts, exfiltrate context, or coerce the model into ignoring guardrails. This is a design-time concern wherever untrusted text is concatenated into a model prompt without isolation.

#### Possible mitigations

Treat all user-supplied content as untrusted data, never as trusted instructions. Separate system instructions from user content using provider-supported role boundaries (system / user / tool roles) rather than string concatenation. Apply input validation, content filtering, and output validation. Constrain model authority by reducing tool/plugin permissions (least privilege). Refer: OWASP LLM01: Prompt Injection (<https://owasp.org/www-project-top-10-for-large-language-model-applications/>)

#### Steps

Identify every flow that feeds untrusted text into a model prompt. For each, specify how the input is delimited from system instructions, what content filtering is applied, and what the blast radius is if the model follows the injected instruction.

**Documentation:** <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>

---

### `TH203` — An adversary may inject instructions via untrusted retrieved content (indirect prompt injection) 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain • Source: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

When an LLM application retrieves content from external or user-controlled sources — web pages, documents, emails, vector store results, third-party APIs — and includes that content in the model prompt, an attacker who can write to those sources can embed hidden instructions that the model will execute. The threat applies to any RAG pipeline, agent that browses the web, or assistant that summarizes user-supplied documents.

#### Possible mitigations

Treat all retrieved content as untrusted data. Render retrieved content inside clearly delimited, non-instructional context blocks. Strip or quarantine known instruction patterns and active content (scripts, hidden text, metadata) before indexing or retrieval. Limit the model's tool authority when operating on retrieved content. Maintain provenance metadata for every retrieved chunk so that downstream actions can be gated by source trust level.

#### Steps

Map every retrieval source feeding model context. Classify each by trust level (first-party / tenant-controlled / fully untrusted). Define how content from each tier is sanitized, delimited, and what tool actions are permitted while the model is reasoning over content from that tier.

**Documentation:** <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>

---

### `TH204` — An adversary may poison training, fine-tuning, or RLHF data to alter model behavior 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: AI Developer Platform, AI Platform, AI Specialized Platform, Hugging Face

#### Description

Models that are fine-tuned, continually trained, or subjected to reinforcement learning from feedback are subject to data poisoning if the training corpus, feedback channel, or annotation pipeline accepts contributions from untrusted parties. Poisoned samples can introduce backdoors, biased outputs, or instructions that activate on attacker-chosen triggers. This is a design-time concern any time the design ingests external data into a learning loop.

#### Possible mitigations

Establish a curated, version-controlled training data pipeline with provenance for every sample. Require dual review for fine-tuning data sourced from end-users or external providers. Apply anomaly detection on training contributions and hold-out evaluation against trigger probes. Sign and version model artifacts so a compromised training run can be identified and rolled back.

#### Steps

List every dataset that flows into a fine-tuning, RLHF, or continual-learning step. For each, document who can contribute data, how contributions are authenticated, what review they undergo, and how poisoned samples would be detected before deployment.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0020>

---

### `TH205` — An adversary may poison a vector store or embedding index used for retrieval 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

Vector databases and embedding indexes used by RAG and agentic systems are trust-sensitive data stores. An adversary who can write to the index — through an ingestion pipeline, a user-upload feature, or a shared multi-tenant store — can insert documents whose embeddings are crafted to rank high for targeted queries and whose content carries injected instructions or misinformation. The model then surfaces attacker-controlled content as if it were authoritative.

#### Possible mitigations

Authenticate and authorize all writes to the vector store; do not permit anonymous or low-privilege ingestion. Tag every chunk with source provenance and trust level, and filter retrievals by trust at query time. Isolate tenants into separate indexes or partitions. Periodically audit the index for anomalous embeddings and content drift.

#### Steps

For each vector store, document who can write, what authentication is required, how provenance metadata is preserved end-to-end, and whether retrievals can mix content across trust tiers within a single prompt.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH206` — An adversary may tamper with model artifacts pulled from a model registry or hub 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Platform, AI Specialized Platform, Hugging Face

#### Description

Applications that load model weights, tokenizers, adapters, or pipelines from external sources (e.g., AI Specialized Platform such as Hugging Face, internal model registries) without integrity verification are exposed to supply-chain tampering. A modified artifact can contain backdoored weights, malicious deserialization payloads (pickle, custom code), or altered tokenizer behavior that subtly changes model output.

#### Possible mitigations

Pin model artifacts to specific revisions and verify cryptographic checksums or signatures before loading. Avoid loading formats that allow arbitrary code execution at load time (prefer safetensors over pickle). Mirror approved artifacts into an internal, write-controlled registry. Restrict the set of accounts permitted to publish or update artifacts.

#### Steps

Inventory every model, adapter, and tokenizer the application loads. Confirm each is pinned to a specific revision, checksum-verified at load time, and pulled from a registry whose write access is governed.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0010>

---

### `TH223` — Real-time social-media-grounded providers may ingest attacker-authored posts as model context 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Grok xAI, Perplexity

#### Description

Providers that ground completions on real-time social media content (Grok with X integration, or any platform-grounded retrieval) automatically include posts authored by anyone on the platform — including coordinated adversaries — into model context. An attacker can publish a post timed or keyworded to influence completions for a target query, achieving indirect prompt injection or coordinated misinformation at platform scale. This is more severe than generic indirect injection (TH203) because the ingestion source is open-publication.

#### Possible mitigations

For workflows where output integrity matters, disable real-time social grounding or restrict it to authoritative source allowlists. Treat any output produced with social-grounding enabled as low-trust and surface that provenance to end users. Apply human review before acting on social-grounded output in high-stakes contexts.

#### Steps

Identify whether the integration uses real-time social-platform grounding. Document the trust level of the platform's content and whether downstream consumers are aware that the output may be steered by adversarial public posts.

**Documentation:** <https://genai.owasp.org/llmrisk/llm09-misinformation/>

---

### `TH227` — A unified data + ML platform may allow poisoning of training data through the data-engineering surface 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: DataRobot, Databricks, Vertex, Watson IBM

#### Description

Platforms that unify data engineering, feature stores, and ML training (Databricks, Vertex, DataRobot) reduce the trust boundary between the team that writes ETL jobs and the team that deploys models. An engineer or compromised account with write access to a feature table or a raw landing zone can introduce poisoned features that propagate into the next training run, with no separate review at the model-training boundary.

#### Possible mitigations

Establish a formal review boundary between data ingestion/feature engineering and model training. Version and sign feature tables consumed by training jobs. Require dual approval and lineage-verified inputs for promotion of features into the production training pipeline. Detect distribution drift in features at training time as a poisoning indicator.

#### Steps

Diagram the path from raw data ingestion, through feature engineering, to the training job. Identify every principal with write access to any stage, and confirm a review/approval gate exists before features are consumed by training.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0020>

---

### `TH232` — An orchestration framework may load attacker-supplied chains, tools, or templates that execute on import 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: CrewAI, Lanchain

#### Description

Agent and orchestration frameworks (Lanchain, CrewAI) commonly load chains, prompt templates, tools, and integrations from local files, marketplaces, or third-party packages. Many such artifacts execute Python on import or contain prompt templates that are themselves trusted system instructions to the model. Loading an unreviewed community chain or a marketplace-installed tool tampers with the agent's behavior and may execute attacker code in the host process.

#### Possible mitigations

Pin all framework dependencies, chain definitions, and tool packages to specific reviewed versions in a private package index. Forbid runtime download of chains or tools from unverified sources. Treat prompt templates from third parties as code requiring review. Use a lockfile and verify hashes for every dependency.

#### Steps

Inventory every chain, prompt template, tool integration, and package the framework loads. Confirm provenance, version pinning, and review for each.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0010>

---

### `TH236` — An agentic coding tool may follow injected instructions hidden in repository content or third-party dependencies 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Antigravity, Claude Code, Cursor, Windsurf

#### Description

Coding agents read every file in scope - source, READMEs, docstrings, comments, dependency package manifests, vendored code, web pages opened during research. Any of these can contain instructions targeting the agent (e.g., a comment in a dependency telling the agent to exfiltrate environment variables, or a README instructing the agent to add a backdoor). Because the developer trusts the agent, malicious code edits or commands flowing from injected instructions are likely to be applied or run.

#### Possible mitigations

Pin and review dependencies; do not run an agent inside a freshly-pulled untrusted codebase without sandboxing. Treat third-party content (dependencies, web pages, issue trackers) as untrusted input to the agent, distinct from the developer's instructions. Surface diff previews for every file change before applying. Do not let the agent consume web content into its context without an explicit per-fetch confirmation in sensitive workflows.

#### Steps

List the content sources the agent reads (project files, dependencies, web). Confirm there is a review step between agent-generated edits and persistent application, and that web fetch is constrained or reviewed.

**Documentation:** <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>

---

### `TH238` — An installable AI tool extension or MCP server may compromise the developer environment at install or runtime 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Antigravity, Claude Code, Cursor, Windsurf

#### Description

Coding-agent ecosystems load extensions, plugins, and MCP servers - many distributed through open marketplaces with low publishing barriers. An installed extension runs with the agent's (and often the developer's) privileges, can read every prompt, modify outputs, and interpose on tool calls. A malicious or compromised extension is a high-impact supply-chain entry that may also be silently auto-updated.

#### Possible mitigations

Maintain an internal allowlist of approved extensions and MCP servers, vetted before approval. Pin versions and disable automatic updates for security-sensitive tooling. Prefer extensions with reproducible builds and signed releases. Periodically audit installed extensions across the developer fleet.

#### Steps

List the extensions and MCP servers permitted in the developer environment, the publisher verification applied, and the update policy. Confirm no auto-update path bypasses review.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0010>

---

### `TH239` — A Hugging Face Space, dataset loader, or model card may execute attacker code when consumed 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Hugging Face

#### Description

The Hugging Face hub hosts not only model weights but also dataset loader scripts, custom model code, and Spaces (hosted demo applications). Loading a dataset with a custom loader script, instantiating a model with custom code (trust_remote_code), or running a Space executes arbitrary code authored by the contributor. Without explicit pinning and review, the consumer is running untrusted code from a community contributor.

#### Possible mitigations

Refuse trust_remote_code for production loads; vendor the model code in-house instead. Pin every model and dataset to a specific commit hash, not a tag or revision. Avoid loading datasets that require executing the contributor's loader script; convert to safetensors or Parquet locally. Mirror approved artifacts into a private hub.

#### Steps

List each Hugging Face artifact loaded by the system. For each, confirm pinning to a commit hash and that no custom-code loader executes at consume time.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0010>

---

### `TH255` — A Fabric Data Agent may be steered by injected instructions in agent metadata, ontology bindings, or queried data 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Data Agent, Microsoft Fabric IQ

#### Description

Fabric Data Agent behavior is shaped by agent-level instructions (up to ~15,000 characters), per-data-source instructions, and example queries. Each of these is an authoring surface that becomes part of the agent's effective prompt. Where any of those authoring surfaces or the underlying data the agent reads can be modified by less-trusted contributors, the agent can be directed to issue unintended queries, expose excluded columns, or produce misleading natural-language answers. The threat is amplified when an ontology serves as the grounding layer, since a single ontology change influences every agent bound to it.

#### Possible mitigations

Treat agent instructions, example queries, and ontology bindings as code: subject changes to review and version control. Restrict edit rights on these artifacts to a small named set of owners. Use OneLake Security and SQL endpoint controls on the underlying data so that an agent that follows an injected instruction is still bounded by the calling identity's row/column permissions. Sanitize free-text data the agent surfaces back to users.

#### Steps

Identify the authors who can edit each agent's instructions, examples, bound ontology, and underlying tables. Confirm change-control coverage for each surface and that data-layer permissions backstop the agent's effective authority.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-science/data-agent-config>

---

### `TH258` — A Fabric Data Factory pipeline definition or its parameters may be tampered with to redirect data movement

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Data Factory

#### Description

Data Factory pipelines orchestrate copy, transform, and notebook activities across many sources and sinks. The pipeline definition (source/sink references, expressions, parameters) and any trigger that supplies runtime parameters together control where data flows. A user who can edit the pipeline definition, modify a trigger payload, or write to a parameter file can redirect production data flows: change the destination of a copy activity, alter a transformation expression, or substitute a sink connection - causing exfiltration or corruption with no change to the underlying data sources.

#### Possible mitigations

Govern pipeline definitions under source control with mandatory review. Restrict pipeline-edit permissions to a small set distinct from pipeline-execute. Validate trigger payloads and pipeline parameters against an allowlist (sink names, file paths, table names) before activity execution. Log every pipeline run with the resolved source, sink, and parameter values for audit.

#### Steps

For each pipeline, document who can edit the definition, who can trigger it, what parameters are runtime-supplied, and how those parameters are validated. Confirm the run record captures resolved source/sink so post-hoc review is possible.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-factory/data-factory-overview>

---

### `TH263` — An eventstream feeding the Fabric Realtime Hub may accept attacker-supplied events that influence downstream Activator alerts and analytics

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Activator, Microsoft Fabric Eventhouse, Microsoft Fabric Realtime Hub

#### Description

The Fabric Realtime Hub aggregates streams from many sources - Azure Event Hub, IoT Hub, custom apps, sample data. If any contributing source authenticates weakly or accepts events from unauthenticated publishers, an attacker can inject crafted events that propagate through the stream into KQL databases, Eventhouses, and Activator triggers. Because Activator can automatically initiate actions on event patterns, an injected event may cause the system to send notifications, kick off pipelines, or change downstream state.

#### Possible mitigations

Authenticate each event source with a per-source identity (managed identity, SAS, or OAuth client). Validate event schema and known fields before forwarding. Apply allowlists for publisher identities at the eventstream ingestion stage. Treat Activator triggers that produce external side effects as high-trust paths requiring authenticated and validated input.

#### Steps

List each eventstream source, its authentication mechanism, the schema validation applied, and the downstream Activator triggers or KQL queries that consume it.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-hub/overview>

---

### `TH266` — Direct OneLake writes to a Lakehouse table's underlying Parquet/Delta files may corrupt table state and bypass table-level controls

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake

#### Description

Fabric Lakehouse tables are Delta tables backed by Parquet files in OneLake. A user or service with OneLake write access to the underlying directory can write Parquet files directly, bypassing the Delta transaction log and any table-level access control evaluated by the compute engine. The result can be silent table corruption, unsynchronized state across engines (Spark vs SQL endpoint vs Direct Lake), or insertion of rows that the table-level layer would have refused.

#### Possible mitigations

Restrict OneLake write access to lakehouse Tables directories to the engines and service identities that perform table writes through the Delta log. Do not grant interactive users OneLake write to Tables paths; route them through the SQL endpoint or notebook write APIs. Audit OneLake write events to the Tables prefix.

#### Steps

For each lakehouse, list the identities with OneLake write access to the Tables directory. Confirm that interactive users go through engine-mediated APIs and that direct write is reserved for the engine and trusted ETL identities.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/onelake-overview>

---

### `TH272` — KQL update policies and stored functions execute under the ingestion identity and may be modified to alter or drop ingested data

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: KQL Database, Microsoft Fabric Eventhouse

#### Description

KQL Database update policies, ingestion mappings, and stored functions transform data on the way in or wrap query logic for callers. They execute with the privilege of the ingestion or calling identity. A user with permission to alter these objects can modify ingested rows, drop fields before they are persisted, or shadow expected query results - tampering with the data observed by every downstream consumer with no signal at the source.

#### Possible mitigations

Restrict alter-rights on update policies, ingestion mappings, and stored functions to a small set of named owners distinct from those who write queries against the database. Version the definitions in source control and require change review. Audit changes to these objects.

#### Steps

List the update policies, ingestion mappings, and stored functions in each KQL database. Document the alter-rights holders and confirm change control for each.

**Documentation:** <https://learn.microsoft.com/en-us/azure/data-explorer/kusto/management/update-policy>

---

### `TH282` — Custom Spark libraries, JARs, or environment definitions attached to a Fabric workspace may carry malicious code that runs in every notebook and Spark job

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Engineering, Microsoft Fabric Workspace

#### Description

Fabric Data Engineering allows workspace admins and members to attach custom libraries, JARs, wheel packages, and environment definitions that are loaded into the Spark runtime for every notebook and Spark job in the workspace. A library uploaded by a contributor - sourced from a public package index, a personal repository, or a build pipeline with weak controls - executes in the workspace's runtime under the run identity. A compromised or malicious library becomes a workspace-wide foothold that runs against every dataset reachable from any job.

#### Possible mitigations

Curate an internal allowlist of approved libraries; do not allow ad-hoc upload from individual contributors in production workspaces. Pin versions and verify hashes for every library admitted. Build environment definitions in source control and review them as code. Separate development workspaces (where contributors can experiment with libraries) from production workspaces with locked environments.

#### Steps

List the libraries, JARs, and environments attached to each workspace. Confirm the source, version pinning, and review process for each. Identify production workspaces where library upload should be restricted.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/library-management>

---

### `TH284` — An eventstream feeding KQL Database or Eventhouse may silently drop or coerce fields on schema drift, masking malicious or anomalous payloads

**STRIDE:** `T` (Tampering) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: KQL Database, Microsoft Fabric Eventhouse, Microsoft Fabric Realtime Hub

#### Description

KQL ingestion mappings define how event fields are placed into target columns. When events arrive with new fields, missing fields, or values that do not match the column's data type, the default behavior is to silently drop unmapped fields and substitute defaults or null for type mismatches. An attacker who can influence the source of the eventstream can push events containing additional fields or carefully-typed values that look ordinary in the ingested table but carry information visible only at the source - or make malicious patterns invisible to detection rules that expect specific fields to be present.

#### Possible mitigations

Define ingestion mappings that explicitly enumerate accepted fields and reject events with unexpected schemas to a quarantine path rather than dropping them silently. Use update policies to capture raw payloads alongside the typed ingest, so post-hoc analysis can recover what was discarded. Monitor ingestion failure and drop counters as security signals rather than performance metrics.

#### Steps

For each KQL ingestion path, document the mapping behavior on unknown fields and on type mismatches. Confirm a quarantine destination exists for non-conforming events and that drop counters are monitored.

**Documentation:** <https://learn.microsoft.com/en-us/azure/data-explorer/kusto/management/data-ingestion/>

---

### `TH291` — Key Vault contents may be irreversibly destroyed if soft-delete and purge protection are not enabled, or if purge permissions are over-granted

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Key Vault

#### Description

By default, deletion of Key Vault objects (secrets, keys, certificates) and the vault itself may be recoverable through soft-delete, but only if the feature is enabled at vault creation. Even with soft-delete enabled, a principal with purge permission can permanently destroy objects within the retention window. An attacker - or a careless operator - can therefore render encrypted data permanently unrecoverable by purging the encryption keys, even where the Key Vault itself remains intact.

#### Possible mitigations

Enable soft-delete and purge protection on every Key Vault holding production secrets or keys used to encrypt persistent data. Restrict the purge permission to a small set of identities that cannot perform any other Key Vault administration. Use long retention periods (90 days is the maximum) for high-value vaults. Treat purge events as security-critical alerts.

#### Steps

For each Key Vault, document soft-delete state, purge protection state, retention period, and the identities holding purge permission. Ensure production vaults have purge protection and minimal purge-rights holders.

**Documentation:** <https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview>

---

### `TH297` — An HTTP-triggered Azure Function published with anonymous auth level, or with a long-lived function/host key, exposes the function logic to public invocation

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Functions

#### Description

Azure Functions support multiple authorization levels for HTTP triggers: anonymous, function (function-scoped key), admin (host-scoped key). Anonymous functions are reachable without any credential. Function and host keys are long-lived shared secrets that, if leaked through CI logs, public repositories, or browser network traces, grant the same access as the original publisher. Attackers can invoke the function repeatedly, modify downstream state through it, or use it as a pivot into systems the function reaches.

#### Possible mitigations

Avoid anonymous auth for any function that has side effects or accesses sensitive data. Prefer Microsoft Entra authentication via App Service Authentication ('Easy Auth') or function-level token validation rather than function/host keys. Where keys are used, treat them as secrets, store in Key Vault, rotate regularly, and never log them. Place HTTP functions behind APIM or Front Door with WAF for additional inspection.

#### Steps

For each HTTP-triggered function, document the auth level, key storage location and rotation policy, and any upstream gateway. Confirm anonymous and key-based access are justified for the function's risk class.

**Documentation:** <https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts>

---

### `TH301` — APIM policies executed at the gateway may be modified by API publishers in ways that affect every consumer, bypassing back-end controls

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: API Management

#### Description

API Management policies (XML-based, executed in inbound, backend, outbound, on-error pipes) transform requests, attach credentials to upstream calls, perform authorization checks, and set caching. A user with API contributor or APIM contributor rights can modify policies on any API published in the instance, including policies that rewrite back-end credentials, disable rate limits, or change CORS. Because all consumers traverse the same policy pipeline, the change has tenant-wide effect with no per-consumer signal.

#### Possible mitigations

Govern APIM policy changes under source control with mandatory review (DevOps for APIM patterns, Bicep/ARM templates). Restrict APIM contributor rights to a small named set distinct from the API publishers. Use named values stored in Key Vault for back-end credentials referenced by policies, so policy review and credential review are separable. Audit policy revisions.

#### Steps

Inventory APIM instances, the principals with policy-edit rights, and the change-management process for policies. Confirm policy changes go through review and that back-end credentials are externalized to Key Vault.

**Documentation:** <https://learn.microsoft.com/en-us/azure/api-management/api-management-policies>

---

### `TH302` — An Azure Logic App's workflow definition or trigger URL may be modified to redirect data flow or replayed to invoke unintended actions

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: LogicApp

#### Description

Logic Apps execute workflows whose definitions are stored as JSON and reachable to anyone with workflow Contributor on the resource. HTTP-triggered Logic Apps expose a callback URL containing a SAS-style signature; a leaked URL is sufficient to invoke the workflow. A compromised editor identity can rewrite actions to send data to attacker-controlled destinations, swap connections, or alter parallel branches. Each invocation runs under the Logic App's connections and managed identity, with the privilege those grant.

#### Possible mitigations

Govern Logic App definitions in source control with mandatory review. Restrict Contributor rights on production Logic Apps to a small named set. For HTTP-triggered workflows, treat the callback URL as a secret, store it in Key Vault, and rotate by regenerating the access key. Use Microsoft Entra authentication on triggers where supported. Log every workflow run with the resolved actions and connections used.

#### Steps

List each Logic App, the trigger type, the editor set, the connections referenced, and the managed identity attached. Confirm change control on workflow edits and protection of HTTP trigger URLs.

**Documentation:** <https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app>

---

### `TH303` — An Event Grid subscription endpoint may be redirected to an attacker-controlled webhook if subscription-edit permissions and webhook validation are inadequate

**STRIDE:** `T` (Tampering) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Event Grid

#### Description

Event Grid delivers events to subscriber-defined webhook endpoints, queue/event-hub destinations, or Functions. A user with permission to modify a subscription can change the destination URL. Because Event Grid validates webhook ownership only at subscription-create time (or with manual handshake), a destination already accepted into a subscription can be replaced with an attacker-controlled URL through subscription update if the subject does not re-validate ownership of the new destination.

#### Possible mitigations

Restrict subscription-edit permissions on Event Grid topics to a small named set. Use managed-identity-authenticated delivery (e.g., to Service Bus, Event Hubs, Functions) rather than arbitrary webhook URLs where possible. For webhook destinations, require endpoint validation on every URL change, not only at subscription create. Audit subscription destination changes as security events.

#### Steps

For each Event Grid topic, list the subscriptions and their destinations. Document the principals with subscription-edit rights and the destination validation policy.

**Documentation:** <https://learn.microsoft.com/en-us/azure/event-grid/security-authorization>

---

### `TH312` — Azure Data Factory self-hosted integration runtime credentials concentrate access to every linked service it brokers, becoming a single high-value target

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Data Factory, Azure Integration Runtime

#### Description

Azure Data Factory's self-hosted integration runtime (SHIR) is installed on customer-managed VMs to bridge cloud pipelines to on-premises or restricted-network sources. The SHIR host caches credentials for every linked service it brokers, and a compromised SHIR host exposes those credentials. SHIR registration also requires a node key whose leakage allows an attacker to register a rogue node into the integration runtime, intercepting connection definitions and data in flight.

#### Possible mitigations

Run the SHIR on hardened, dedicated hosts with minimal external exposure and strict admin access. Rotate the SHIR node key on a defined cadence and on personnel changes. Use credential storage that is encrypted with a Key Vault-managed key. Place the SHIR host on a network segment from which the smallest set of source systems is reachable.

#### Steps

List each SHIR, the host configuration, the linked services it brokers, and the credentials cached. Confirm host hardening and key-rotation cadence.

**Documentation:** <https://learn.microsoft.com/en-us/azure/data-factory/create-self-hosted-integration-runtime>

---

### `TH316` — Azure Automation runbooks may execute under high-privilege Run As accounts or managed identities, becoming a privileged code-execution surface that bypasses normal change control

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Automation

#### Description

Azure Automation runbooks are PowerShell or Python scripts that execute under an Automation account's identity (Run As account, system-assigned or user-assigned managed identity). These identities frequently hold Subscription Contributor or broader role assignments to perform the operations the runbooks automate. A user with permission to publish or modify runbooks can therefore execute arbitrary code under that high-privilege identity - a lateral path into every resource the identity can reach, often without traversing the same change-control gates as direct admin operations.

#### Possible mitigations

Govern runbook publication under source control with mandatory review. Restrict the principals who can edit and publish runbooks in production Automation accounts to a small named set. Scope the Automation identity's permissions to the minimum the runbooks require. Use separate Automation accounts for separate trust domains. Audit runbook publish/edit events and runbook execution logs.

#### Steps

List Automation accounts, their identities and role assignments, and the principals who can edit runbooks. Confirm the editor set is consistent with the identity's privilege.

**Documentation:** <https://learn.microsoft.com/en-us/azure/automation/automation-security-overview>

---

### `TH318` — Azure DevOps Repos branch policies may be bypassed by repository administrators or by service accounts not subject to the policy, undermining the integrity of protected branches

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure DevOps, Azure DevOps Repos

#### Description

Branch policies (require reviewers, require build pass, require linked work items) protect the main and release branches in Azure DevOps Repos. Project administrators and certain service accounts can bypass policy when configured. A compromise of an administrator identity, or of a service principal granted bypass for CI scenarios, allows direct push to protected branches and bypass of the review gate. Pipelines triggered from such pushes execute with the same downstream privilege as policy-compliant changes.

#### Possible mitigations

Require all changes to protected branches go through pull request, including for administrators ('Bypass policies when pushing' and 'Bypass policies when completing pull requests' set to no). Audit bypass events. Use separate identities for break-glass scenarios with monitored use. Restrict the set of identities granted bypass to the minimum.

#### Steps

For each protected branch in production-impacting repos, document the policy, the principals with bypass rights, and the audit on bypass events.

**Documentation:** <https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies>

---

### `TH336` — AWS S3 buckets without versioning or Object Lock allow silent overwrite or permanent deletion of objects, including by ransomware or compromised principals

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Storage

#### Description

By default, S3 PUT operations overwrite the existing object at the same key with no history retained, and DELETE removes objects immediately. A compromised IAM principal, a ransomware payload running with bucket-write rights, or accidental tooling can therefore destroy or corrupt objects irrecoverably. Versioning preserves prior object versions but still allows version deletion. Object Lock (governance or compliance mode) provides immutability for a defined retention period.

#### Possible mitigations

Enable Versioning on every bucket containing valuable data. For data with retention or compliance requirements, enable Object Lock in compliance mode with appropriate retention. Apply MFA Delete on critical buckets. Replicate to a separate account / region for cross-account restore in case the primary account is compromised. Monitor for bulk-delete operations as security alerts.

#### Steps

List buckets in scope, their versioning state, Object Lock configuration, and cross-account replication. Confirm critical buckets cannot be silently emptied by a single principal compromise.

**Documentation:** <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html>

---

### `TH346` — AWS Bedrock Knowledge Bases ingest documents from S3 sources that may be writable by less-trusted contributors, creating indirect prompt injection paths 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Bedrock

#### Description

Bedrock Knowledge Bases connect to S3 source buckets (and other vector store inputs), ingesting documents and chunking them into embeddings for retrieval-augmented generation. If the source S3 bucket accepts content from a wider set of writers than the agent's callers — for example, customer-uploaded documents, partner-supplied PDFs, or content synced from external systems — those writers can embed instructions in their content that the model executes when retrieving and summarizing them. This is indirect prompt injection at retrieval time.

#### Possible mitigations

Restrict write access to Knowledge Base source buckets to a small set of trusted ingestion identities. Sanitize or quarantine content from less-trusted sources before indexing. Tag retrieved chunks with provenance and trust level so downstream prompts can reflect source trust. Combine with Bedrock Guardrails to filter both inputs and outputs.

#### Steps

For each Knowledge Base, document the source buckets, the identities with write access, the content sanitization step, and the consumer authorization model. Confirm trust level of the source matches the agent's effective authority.

**Documentation:** <https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base.html>

---

### `TH364` — Slack incoming webhook URLs are bearer credentials; if leaked through code repositories or logs, anyone holding the URL can inject messages into the channel

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Slack

#### Description

Slack incoming webhooks expose a per-webhook URL that, when POSTed to, posts the supplied payload as a message in a configured channel — with no further authentication. The URL is the credential. Webhook URLs leaked in public source code repositories, application logs, or browser network traces are routinely exploited: attackers post phishing messages appearing to come from internal automation, social-engineering recipients into clicking links or sharing credentials. Because the message appears to come from the configured Slack app, recipients trust it.

#### Possible mitigations

Treat incoming webhook URLs as secrets; store in a secrets manager and reference at runtime. Never commit webhook URLs to source control. For automated posting from CI/CD or production services, prefer Slack apps with bot tokens and channel-scoped OAuth scopes over incoming webhooks. Rotate webhooks on personnel changes and after any suspected leak. Monitor channels for unexpected automation messages.

#### Steps

List Slack incoming webhooks in use, where the URLs are stored, and the rotation policy. Confirm none are in source control and that rotation occurs on schedule.

**Documentation:** <https://api.slack.com/messaging/webhooks>

---

### `TH366` — Zoom meetings without passcodes, waiting rooms, or authentication requirements may be hijacked by uninvited participants who guess or scrape meeting IDs

**STRIDE:** `T` (Tampering) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Zoom

#### Description

Zoom meetings can be configured to allow joining with only a meeting ID — no passcode, no waiting room, no authenticated-user requirement. Meeting IDs that are predictable (Personal Meeting IDs reused across all meetings) or leaked (calendar invites forwarded externally, screenshots in social media) become entry points for uninvited participants — including the disruption attacks colloquially called 'Zoombombing' and more deliberate attempts to eavesdrop on confidential discussions.

#### Possible mitigations

Configure tenant defaults to require passcodes on all meetings, enable waiting rooms, and require authenticated users (corporate IdP) for internal meetings. Disable Personal Meeting ID for recurring sensitive meetings; use one-time meeting IDs. Restrict 'Join before host.' Train hosts on lock-meeting and remove-participant controls.

#### Steps

Document the tenant defaults for passcode, waiting room, and authentication requirements. Confirm sensitive meeting workflows use one-time IDs.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/iam/iam-02/>

---

### `TH368` — Expense management systems may allow submitters to manipulate receipt images, amounts, or expense categories without sufficient validation, enabling expense fraud

**STRIDE:** `T` (Tampering) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Expensify

#### Description

Expense management SaaS (Expensify and similar) ingest user-uploaded receipts, OCR them, and let users edit the extracted fields before submission. Without robust review, submitters can manipulate receipt images, alter OCR-extracted amounts, change expense categories to bypass policy, or submit synthetic receipts. The downstream consequence is financial fraud whose detection depends on per-line review by reviewers who cannot compare against the original physical artifact.

#### Possible mitigations

Configure receipt-validation rules: require original receipt image attached, flag edited-amount cases for review, apply policy thresholds per category. Enable AI/ML-based receipt validation features where the platform supports them. Sample audit of approved expenses with comparison to original receipts. For high-amount expenses, require dual approval and out-of-band verification.

#### Steps

Document the receipt validation rules, the approval workflow, and the audit cadence. Identify expense categories with elevated fraud risk.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-03/>

---

### `TH370` — Email templates stored in Postmark or similar transactional services may be modified to alter content sent to customers, including phishing payloads

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Postmark

#### Description

Postmark and equivalent platforms support server-side templates that the application invokes by template ID with merge variables. A user with template-edit rights on the Postmark account can modify the template body, links, sender display name, or layout — and every subsequent send using that template carries the modified content. Compromise of an account with template-edit rights, or insider modification, can convert legitimate transactional flows (password reset, invoice, receipt) into phishing or malware delivery without changing application code.

#### Possible mitigations

Restrict template-edit rights to a small named set distinct from those who use the tokens. Govern template content in source control with mandatory review; deploy through the API rather than allowing in-portal editing in production. Audit template revisions as security events. Use template versioning where supported and pin to a specific version per send.

#### Steps

List the templates used, the principals with edit rights, and the change-control process. Confirm production templates are versioned and that revisions are audited.

**Documentation:** <https://postmarkapp.com/developer/templates>

---

### `TH375` — Adobe Sign / Acrobat Sign workflows may be modified to alter signing parties, document content, or completion routing, undermining the integrity of executed agreements

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Adobe

#### Description

Adobe Sign supports complex multi-party signing workflows: ordered signers, parallel signing, conditional fields, automated routing on completion. A user with workflow-design rights can modify a workflow to swap signing parties, change the document version sent for signature, or redirect completion notifications. Combined with weak per-document approval, an insider can route an executed agreement to an unintended counterparty, change which fields are required, or substitute a different document version into a previously-approved workflow.

#### Possible mitigations

Restrict Sign workflow design rights to a small named set, separate from general Sign users. Govern workflows in version control where the platform supports it; audit workflow modifications. Pin documents in workflows to specific revisions. Require out-of-band verification for high-value agreements (e.g., signed over a defined threshold).

#### Steps

List Sign workflows in production, the principals with workflow-design rights, and the audit trail on workflow changes.

**Documentation:** <https://helpx.adobe.com/sign/using/security-overview-acrobat-sign.html>

---

### `TH384` — An AI Agent's tool definitions, system prompt, or memory store may be tampered with to alter its behavior between invocations 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent

#### Description

An AI Agent persists a system prompt, a list of tool definitions, and often a long-term memory store that influence subsequent invocations. A party with write access to any of these (workspace storage, prompt registry, vector index, configuration database) can change agent behavior for all future calls without changing the agent's code or the calling application. The change persists silently and affects every user the agent serves.

#### Possible mitigations

Treat the agent's system prompt, tool registrations, and persistent memory as code, not data: version-control them, require review for changes, sign or hash them, and verify the hash at agent load time. Restrict write access to a small named set of agent maintainers separate from operators and users.

#### Steps

Inventory every artifact the agent loads at start or between turns: system prompt, tool list, memory backend, configuration. For each, identify who can write to it and what review gate exists.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH391` — Apache Airflow DAG files loaded from a writable repository allow arbitrary Python execution on the scheduler and workers

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Apache Airflow

#### Description

Airflow's scheduler imports DAG files as Python modules to discover tasks. Any code at module top-level executes on the scheduler at parse time, and task code executes on workers at run time. A party with write access to the DAG folder, the connected Git repository, or the artifact storage backing it can introduce code that runs in the Airflow process with all its connection credentials and worker privileges, without invoking any DAG.

#### Possible mitigations

Treat the DAG repository as a privileged code path: require pull-request review, branch protection, and signed commits. Avoid granting DAG-folder write access to non-engineering identities. Run the scheduler and workers with least-privilege OS accounts and segregate connection credentials per DAG so a single compromise does not yield all secrets.

#### Steps

Document who can write to the DAG folder or the repository feeding it. Confirm review and signing requirements. Inventory connection credentials available to each worker and confirm scoping.

**Documentation:** <https://airflow.apache.org/docs/apache-airflow/stable/security/index.html>

---

### `TH395` — A Fabric Notebook executed interactively and on schedule may resolve cell code or referenced libraries from sources that change between runs

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Notebook

#### Description

Fabric Notebooks load code from notebook cells, attached environments, and library references resolved at run time (PyPI, Maven, custom artifacts). Between an interactive run reviewed by an engineer and a scheduled run executing the same notebook, the resolved package versions, environment definition, or referenced notebook cells may have changed. The reviewed code is not necessarily the executed code.

#### Possible mitigations

Pin all library versions explicitly. Reference a frozen environment artifact rather than a mutable one. Sign or hash the notebook content and verify before scheduled execution. Restrict write access to attached environments and shared notebooks to a small named set.

#### Steps

Confirm every notebook scheduled in production uses pinned library versions and a frozen environment. Document who can modify the environment between runs.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/library-management>

---

### `TH400` — Fabric Dataflow Gen2 M-language definitions may include dynamic data sources or eval-style transforms that change behavior at refresh time

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Dataflow

#### Description

Power Query M can construct data-source URIs from parameters, query parameter tables for connection strings, and use Expression.Evaluate to interpret strings as code at refresh time. A maintainer who edits a parameter table or a referenced lookup in OneLake can change what the dataflow reads or how it transforms data, without changing the dataflow definition under review.

#### Possible mitigations

Disallow dynamic data-source construction in production dataflows. Forbid Expression.Evaluate. Lock parameter tables behind separate change control from the dataflow itself. Treat the dataflow definition and any referenced parameter source as a single change-controlled unit.

#### Steps

Review dataflow M code for dynamic source construction or Expression.Evaluate. Identify parameter sources and confirm their change-control regime matches the dataflow's.

**Documentation:** <https://learn.microsoft.com/en-us/power-query/dataflows/overview-dataflows-across-power-platform-dynamics-365>

---

### `TH411` — An agent orchestration framework may allow tool outputs to influence subsequent tool selection, enabling data-driven hijack of the agent's plan 🤖

**STRIDE:** `T` (Tampering) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, CrewAI, Lanchain

#### Description

Frameworks that let an LLM choose the next tool based on prior tool output let attacker-influenced data steer that choice. A document fetched by one tool can contain instructions that the model reads as guidance, causing the agent to call a different tool, with different arguments, than the user's prompt requested. The user observes the original prompt and the final answer; the redirected tool calls happen in between and may have side effects the user never sees.

#### Possible mitigations

Treat tool outputs as untrusted input. Strip or sandbox instruction-like content before re-feeding to the model. Constrain tool selection via deterministic rules where the trust level of intermediate data is low. Log every tool call with its inputs and outputs and surface the chain to the user.

#### Steps

Trace a sample agent run. Confirm whether tool outputs flow back into model input that drives further tool selection. Document the sanitization or constraint at that boundary.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

## `R` — Repudiation (28)

> An adversary denies that something happened.

🤖 **9 of these threats are LLM-tagged.**

### `TH3` — An adversary can deny actions on database due to lack of auditing

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, Database, SQL Data Warehouse

#### Description

Proper logging of all security events and user actions builds traceability in a system and denies any possible repudiation issues. In the absence of proper auditing and logging controls, it would become impossible to implement any accountability in a system.

#### Possible mitigations

Ensure that login auditing is enabled on SQL Server. Refer: <https://aka.ms/tmtauditlog#identify-sensitive-entities>

#### Steps

Database Server login auditing must be enabled to detect/confirm password guessing attacks. It is important to capture failed login attempts. Capturing both successful and failed login attempts provides additional benefit during forensic investigations

**Documentation:** <https://msdn.microsoft.com/library/ms175850.aspx>

---

### `TH20` — An adversary can deny actions on {target.Name} due to lack of auditing

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Storage

#### Description

Proper logging of all security events and user actions builds traceability in a system and denies any possible repudiation issues. In the absence of proper auditing and logging controls, it would become impossible to implement any accountability in a system.

#### Possible mitigations

Use Azure Storage Analytics to audit access of Azure Storage. Refer: <https://aka.ms/tmtauditlog#analytics>

#### Steps

For each storage account, one can enable Azure Storage Analytics to perform logging and store metrics data. The storage analytics logs provide important information such as authentication method used by someone when they access storage. This can be really helpful if you are tightly guarding access to storage. For example, in Blob Storage you can set all of the containers to private and implement the use of an SAS service throughout your applications. Then you can check the logs regularly to see if your blobs are accessed using the storage account keys, which may indicate a breach of security, or if the blobs are public but they shouldn’t be.

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-security-guide/#storage-analytics>

---

### `TH30` — Attacker can deny the malicious act and remove the attack foot prints leading to repudiation issues

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application

#### Description

Proper logging of all security events and user actions builds traceability in a system and denies any possible repudiation issues. In the absence of proper auditing and logging controls, it would become impossible to implement any accountability in a system

#### Possible mitigations

Ensure that auditing and logging is enforced on the application. Refer: <https://aka.ms/tmtauditlog#auditing> Ensure that log rotation and separation are in place. Refer:
<https://aka.ms/tmtauditlog#log-rotation> Ensure that Audit and Log Files have Restricted Access. Refer:
<https://aka.ms/tmtauditlog#log-restricted-access> Ensure that User Management Events are Logged. Refer:
<https://aka.ms/tmtauditlog#user-management>

#### Steps

Enable auditing and logging on all components. Audit logs should capture user context. Identify all important events and log those events. Implement centralized logging

**Documentation:** <https://docs.microsoft.com/en-us/azure/security/azure-log-audit>

---

### `TH34` — An adversary can deny actions on Cloud Gateway due to lack of auditing

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway

#### Description

An adversary may perform actions such as spoofing attempts, unauthorized access etc. on Cloud gateway. It is important to monitor these attempts so that adversary cannot deny these actions

#### Possible mitigations

Ensure that appropriate auditing and logging is enforced on Cloud Gateway. Refer:
<https://aka.ms/tmtauditlog#logging-cloud-gateway>

#### Steps

Design for collecting and storing audit data gathered through IoT Hub Operations Monitoring. Enable the following monitoring categories: Device identity operations Device-to-cloud communications Cloud-to-device communications Connections File uploads

**Documentation:** <https://azure.microsoft.com/documentation/articles/iot-hub-operations-monitoring/>

---

### `TH49` — An adversary can deny actions on Field Gateway due to lack of auditing

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: IoT Field Gateway

#### Description

An adversary may perform actions such as spoofing attempts, unauthorized access etc. on Field gateway. It is important to monitor these attempts so that adversary cannot deny these actions

#### Possible mitigations

Ensure that appropriate auditing and logging is enforced on Field Gateway. Refer:
<https://aka.ms/tmtauditlog#logging-field-gateway>

#### Steps

When multiple devices connect to a Field Gateway, ensure that connection attempts and authentication status (success or failure) for individual devices are logged and maintained on the Field Gateway. Also, in cases where Field Gateway is maintaining the IoT Hub credentials for individual devices, ensure that auditing is performed when these credentials are retrieved.Develop a process to periodically upload the logs to Azure IoT Hub/storage for long term retention.

---

### `TH77` — An adversary can deny actions on Azure App Service due to lack of auditing

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application • Source: Generic External Interactor

#### Description

Proper logging of all security events and user actions builds traceability in a system and denies any possible repudiation issues. In the absence of proper auditing and logging controls, it would become impossible to implement any accountability in a system.

#### Possible mitigations

Enable diagnostics logging for web apps in Azure App Service. Refer: <https://aka.ms/tmtauditlog#diagnostics-logging>

#### Steps

Azure provides built-in diagnostics to assist with debugging an App Service web app. It also applies to API apps and mobile apps. App Service web apps provide diagnostic functionality for logging information from both the web server and the web application. These are logically separated into web server diagnostics and application diagnostics

---

### `TH109` — Attacker can deny a malicious act on an API leading to repudiation issues

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: API App, WCF, Web API, Web Application

#### Possible mitigations

Ensure that auditing and logging is enforced on Web API. Refer: <https://aka.ms/tmtauditlog#logging-web-api>

#### Steps

Enable auditing and logging on Web APIs. Audit logs should capture user context. Identify all important events and log those events. Implement centralized logging

**Documentation:** <https://docs.microsoft.com/en-us/azure/security/azure-log-audit>

---

### `TH118` — A malicious user can deny they made a change to {target.Name}

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM

#### Description

This is due to the Last Modified By field being overwritten on each save

#### Possible mitigations

Identify sensitive entities in your solution and implement change auditing. Refer:
<https://aka.ms/tmtauditlog#sensitive-entities>

#### Steps

Identify entities in your solution containing sensitive data and implement change auditing on those entities and fields

**Documentation:** <https://docs.microsoft.com/en-us/dynamics365/customer-engagement/admin/audit-data-user-activity>

---

### `TH207` — A user or service may repudiate LLM interactions due to insufficient prompt and completion logging 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

If the design does not durably log each prompt, completion, model identity, version, and invoking principal — with tamper-evident storage and a defined retention policy — users, operators, or automated agents can credibly deny having issued a particular request or having received a particular response. This blocks incident investigation, abuse review, and regulatory reporting for AI-assisted decisions.

#### Possible mitigations

Log every prompt and completion with the invoking principal, model name and version, request ID, and timestamp. Send logs to an append-only, access-controlled store with a defined retention policy. Apply privacy controls (redaction or tokenization) before logging when prompts may contain sensitive personal data. Ensure logging cannot be disabled by the calling code path alone.

#### Steps

Identify every entry point that can call the model. For each, confirm that the principal identity, full request/response payload (or redacted equivalent), and model version are captured and shipped to durable storage outside the calling process's control.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH208` — An LLM agent may repudiate actions due to missing tool-invocation audit trail 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, Claude Code, Lanchain

#### Description

When an autonomous or semi-autonomous agent invokes tools — write APIs, code execution, file modification, ticket creation, payments — without recording the chain of reasoning, tool name, arguments, principal on whose behalf the call was made, and the resulting output, there is no reliable record of which entity caused which side effect. This makes after-the-fact attribution, rollback, and dispute resolution impossible.

#### Possible mitigations

Log every tool call with: invoking user/session, agent identity, tool name and version, full argument set, tool result, and the model turn that produced the call. Persist logs to an append-only store. Where actions are high-impact (financial, destructive, irreversible), require a human-in-the-loop confirmation that is itself logged.

#### Steps

List every tool and write-capable function exposed to the agent. For each, define the audit record schema and storage location. Confirm that audit writes are not conditional on agent success and cannot be suppressed by the agent itself.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH233` — No-code AI agent platforms may allow business users to deploy agents that act on company systems without change control 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Lindy

#### Description

No-code AI agent platforms (Lindy and similar) are positioned for business users to build agents that perform real actions: send emails, update CRMs, route leads, contact customers. These agents typically run under the building user's identity or under a shared platform identity, with no SDLC review, no audit pipeline integrated with engineering systems, and no mandatory tagging for compliance. Actions taken by the agent are difficult to attribute after the fact.

#### Possible mitigations

Govern no-code agent platforms under the same change-management regime as IT-deployed automation: require approval for production agents, enforce tagging that ties agent actions back to a business owner, and forward platform audit logs to the central SIEM. Restrict the set of downstream systems agents can touch.

#### Steps

Identify the no-code agent platforms in scope. Document who can build and deploy production agents, what downstream systems they reach, and how their actions are audited and attributed.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH243` — Generated media released without provenance metadata may be repudiated or, conversely, mistaken for authentic 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ElevenLabs, Midjourney, Synthesia

#### Description

Generated images, videos, and audio without embedded provenance (C2PA, signed manifests, perceptual watermarks) cannot later be reliably distinguished from authentic media. This creates two complementary repudiation problems: a creator can deny producing AI-generated media that was in fact theirs, and a real recording can be disputed as 'probably AI'. For organizations publishing generated media or relying on media for evidence, the absence of provenance is a design-time gap.

#### Possible mitigations

Adopt provenance standards (C2PA / Content Credentials) for all generated media at the point of generation, embedding signed manifests that record creator, model, and timestamp. For organization-internal media used as evidence (security camera footage, recorded calls), apply the same provenance signing. Preserve provenance metadata through the publication pipeline.

#### Steps

Identify each surface where generated media is produced or accepted as evidence. For each, confirm whether provenance metadata is embedded at generation and preserved end-to-end.

**Documentation:** <https://c2pa.org/specifications/>

---

### `TH250` — Permission changes in Fabric do not take effect immediately, creating an audit window where attribution is unreliable

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: KQL Database, Microsoft Fabric Eventhouse, Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric SQL Database, Microsoft Fabric Warehouse, Microsoft Fabric Workspace

#### Description

OneLake Security role definition changes propagate in roughly 5 minutes; group membership changes can take an hour or more, plus additional engine-side caching. During that window, a user whose access was apparently revoked may continue to read data, and a user whose access was apparently granted may not yet be able to. Investigations that rely on 'this user could have done X at time T' must account for this lag, or risk false attribution and false exoneration.

#### Possible mitigations

Document the propagation behavior in operational runbooks. For revocations of sensitive access, follow up with token/session invalidation at the identity provider and a defined wait period before treating the revocation as complete. Log and retain Fabric activity events independently of the role state at query time, so that historical reconstruction does not depend on a snapshot of current permissions.

#### Steps

Identify high-impact actions where access revocation must be effective immediately. For those actions, define the workflow that supplements the Fabric permission change with identity-side session invalidation and a quiet period before declaring the change complete.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/best-practices-secure-data-in-onelake>

---

### `TH256` — Lack of paired logging of natural-language input and translated SQL/DAX/KQL leaves Fabric Data Agent activity unattributable 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Data Agent

#### Description

A Fabric Data Agent accepts natural-language questions and emits SQL, DAX, or KQL that is executed under the calling identity. If only the executed query is logged at the data layer (SQL endpoint, lakehouse, KQL database) and only the natural-language exchange is logged at the agent layer, neither log alone shows what the user asked and what was returned. Disputes over what an agent surfaced cannot be reliably resolved.

#### Possible mitigations

Log natural-language prompts, the generated query, the executing identity, the bound data source, and the result row count together as a correlated record per agent invocation. Persist to an append-only audit store with a retention policy aligned to the data sensitivity. Do not rely on engine-side query logs alone to attribute agent behavior.

#### Steps

For each Data Agent, document the audit destination for prompts, generated queries, and results. Confirm the records are correlated and persisted independently of the agent runtime.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-science/data-agent-config>

---

### `TH287` — The Fabric trust boundary may not adequately distinguish compute identity from data identity, complicating attribution of data access to a compute caller

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Compute, Microsoft Fabric Data

#### Description

In Fabric, compute workloads (notebooks, pipelines, Power BI refreshes, Activator actions) access data items (lakehouses, warehouses, KQL databases, OneLake) through a mix of run identities, configured connections, and end-user identity passthrough. When the compute layer and the data layer share a workspace and a small set of identities, the data-side audit log shows access by that identity without clearly attributing which compute artifact (which notebook, which pipeline run) drove the read. Disputes over what executed against the data cannot be reliably resolved from the data-side log alone.

#### Possible mitigations

At the Fabric trust boundary, ensure each compute artifact's run identity is distinct enough to attribute data access back to a specific item - not a single shared service principal across the workspace. Correlate data-side audit (lakehouse query log, KQL ingestion log) with compute-side run records (Monitoring Hub job ID, pipeline run ID) so that 'who read this data' resolves to a specific compute invocation. Persist the correlation independently of the engine logs.

#### Steps

Identify the run identities in use across compute artifacts. Confirm distinctness or, where shared identities are unavoidable, that compute-side run IDs are correlated to data-side events.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/admin/track-user-activities>

---

### `TH326` — Azure resources may have diagnostic settings disabled, partially configured, or routed to per-resource destinations rather than a central audit workspace, breaking attribution

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Log Analytics, Microsoft Sentinel, Monitor

#### Description

Most Azure resources do not emit activity, audit, or diagnostic logs to any destination by default; diagnostic settings must be configured explicitly. A resource without diagnostic settings emits only the platform-level activity log, which captures control-plane changes but not data-plane access. Diagnostic settings configured to per-resource storage rather than a central Log Analytics workspace fragment the audit trail and may be deleted or lifecycled by the resource owner. Investigations cannot reliably reconstruct who accessed what and when.

#### Possible mitigations

Apply Azure Policy (DeployIfNotExists) to enforce diagnostic settings on every resource kind, with destinations including a central Log Analytics workspace. Standardize the category/log groups enabled per resource type. Restrict who can modify or delete diagnostic settings. Audit policy compliance and treat resources without diagnostics as exceptions requiring review.

#### Steps

Inventory the Azure resource types in scope and the diagnostic settings policy applied. Confirm a central destination is configured and that resource owners cannot suppress logging unilaterally.

**Documentation:** <https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings>

---

### `TH347` — AWS Bedrock model invocation logging is disabled by default; without it, prompts and completions are not retained for security investigation or compliance review 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Bedrock

#### Description

Bedrock supports model invocation logging that captures the full prompt, completion, and request metadata to CloudWatch Logs or S3, but the feature is opt-in and disabled by default. Without invocation logging, only the CloudTrail record of the InvokeModel call is captured — operation name, timestamp, IAM principal — but not the content of the interaction. Disputes over what an agent or application surfaced cannot be reliably resolved, and content-policy violations cannot be reviewed retroactively.

#### Possible mitigations

Enable Bedrock model invocation logging at the account level or per-model. Route logs to a destination with retention aligned to compliance and incident-investigation needs, with access controls that restrict read to authorized investigators. Where prompts or completions may contain personal data, apply field-level filtering or redaction before storage.

#### Steps

For each Bedrock account or model in scope, document whether invocation logging is enabled, the log destination and retention, and access controls on the logs.

**Documentation:** <https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html>

---

### `TH379` — Vendor-managed audit-log retention limits in SaaS may not match the timeline of investigations, leaving actions unattributable after the retention window expires

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: ADP, Adobe, Aero, Box Storage, Cloud SaaS Services, Expensify, Jira, Microsoft 365, Monday, Notion, Postmark, Power Automate, Power BI Platform, Salesforce, Slack, Trello, Workday, Zoom

#### Description

SaaS vendors retain audit logs for vendor-defined periods that vary by product and tier (commonly 30, 90, 180, or 365 days; some only on enterprise tiers). When an investigation or compliance request looks at activity older than the retention window, the audit data is gone — the vendor will not produce it, and reconstruction may be impossible. Designs that rely on 'we can always look back at the audit log' to attribute actions discover the limitation only when needed.

#### Possible mitigations

Export SaaS audit logs to a tenant-controlled SIEM or log-archive at the maximum cadence the platform supports, so retention is governed by the org rather than the vendor. Document the longest applicable compliance retention requirement and confirm the SIEM retention meets it. Where the SaaS does not support export, document the gap and treat as an accepted risk or a procurement requirement on renewal.

#### Steps

List the SaaS in scope, the vendor-side audit retention, the export mechanism, and the retention at the org-controlled archive. Confirm coverage meets compliance.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/lng/lng-01/>

---

### `TH385` — Actions taken by an AI Agent may be unattributable to either the agent or the user that triggered them 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent

#### Description

An AI Agent that takes actions through tools (writing to a database, sending email, calling an API, modifying a ticket) may produce log entries on the downstream system that record only the agent's service identity, with no link back to the originating user prompt, conversation, or human approval step. After-the-fact investigation cannot answer whether the user requested the action, whether the agent inferred it, or which prompt produced it.

#### Possible mitigations

Generate a correlation ID per user turn and propagate it through every tool call the agent makes. Persist the prompt, the model output, the chosen tool calls, and the tool results bound to that ID. Ensure downstream services log the correlation ID alongside the agent's service identity so actions can be traced to a user turn.

#### Steps

For each tool the agent can call, confirm that downstream logs capture both the agent identity and a correlation token tying the action to the originating prompt. Verify that prompt, model response, tool inputs, and tool outputs are stored together.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH398` — Fabric Notebook execution history may not durably bind the executed cell content to the run identity for after-the-fact attribution

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Notebook

#### Description

Notebooks are mutable artifacts: cells can be edited between runs. A scheduled or interactive run records which notebook ran and which user ran it, but unless the cell content at the moment of execution is captured, an investigator cannot later determine what code actually ran. A user can edit a notebook, run it, then revert, leaving only the unrelated reverted version in storage.

#### Possible mitigations

Snapshot the notebook content (or a content hash) into the run record at execution time. Retain run snapshots according to investigative-retention policy. Log who edited the notebook between runs and surface the change to scheduled-run reviewers.

#### Steps

Inspect a recent notebook run record. Confirm whether the cell content executed is recoverable. If only the current notebook version is available, attribution is incomplete.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/notebook-source-control-deployment>

---

### `TH403` — Fabric Dataflow ownership transfer or scheduled-refresh identity changes may detach refresh activity from the human accountable for it

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Fabric Dataflow

#### Description

A dataflow runs scheduled refreshes under an owner credential or service principal. When ownership transfers (a person leaves, a connection is rebound), historic refresh records still attribute past runs to the original identity, but ongoing runs use the new one. The audit trail no longer answers who is currently accountable for the refresh that is now happening.

#### Possible mitigations

Bind dataflow ownership to a role or service identity rather than an individual where possible. Require explicit approval for ownership transfer. Ensure refresh history records the owning identity at the time of each run, not only the current owner.

#### Steps

List dataflows whose refresh is owned by a personal identity. Confirm a process exists to reassign ownership cleanly when the person leaves.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-factory/dataflows-gen2-overview>

---

### `TH414` — Multi-agent orchestrations may distribute decision-making across agents in a way that no single log captures the chain of reasoning 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, CrewAI, Lanchain

#### Description

When one agent delegates to another, which delegates to a third, each agent's logs typically capture only its own inputs and outputs. The decision chain that led from the user's prompt to a downstream action is reconstructable only by joining logs across agents, which often run on different services with different log schemas and retention policies. Effective non-repudiation requires the full chain.

#### Possible mitigations

Issue a single trace ID at the outer agent and propagate it to every delegated agent and tool call. Standardize log schemas across agents. Centralize logs and retain for the longer of any individual agent's policy and the investigative-retention requirement.

#### Steps

Trace a multi-agent invocation. Confirm a single ID links every agent's record of the run. Verify centralized log retention covers the full chain.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH415` — Fabric tenant and workspace administrative actions may not produce uniformly attributable audit events for cross-workspace operations

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric Tenant, Microsoft Fabric Workspace

#### Description

Tenant settings, capacity assignments, workspace role grants, and item ownership transfers are administrative actions that can affect data access broadly. Audit coverage of these actions exists but is split across the Fabric admin portal, Microsoft Purview audit logs, and per-workload event streams; some operations are recorded only on the source workspace, not the target. After-the-fact reconstruction of a permission grant or capacity reassignment may be incomplete.

#### Possible mitigations

Enable unified audit log ingestion for all Fabric admin events. Cross-correlate with Microsoft Entra audit logs for the responsible identities. Define a small named set of administrators and require ticket-of-record for each tenant or workspace administrative action. Confirm both source and target are captured for cross-workspace operations.

#### Steps

Sample a recent admin action (role grant, capacity reassignment, ownership transfer). Confirm it is recorded with sufficient detail for attribution and that both source and target are visible.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/admin/track-user-activities>

---

### `TH417` — Fabric Mirroring activity logs may not record per-row changes ingested from the source, limiting after-the-fact reconciliation

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Mirroring

#### Description

Mirroring continuously replicates source-system changes into OneLake using change feeds or CDC. Operational logs typically record bulk metrics (rows replicated, lag, errors) rather than per-row provenance. If a downstream investigation asks 'when did this row arrive and from which source transaction', the answer may not be available, and reconciliation against the source is the only recourse.

#### Possible mitigations

Where investigative reconciliation matters, retain change-data-capture metadata (source transaction ID, commit timestamp) on the mirrored rows. Match mirroring monitoring to source-system audit retention. Test a row-level reconciliation procedure end-to-end.

#### Steps

Sample a mirrored table and confirm whether source transaction ID or commit timestamp is preserved. Test a reconciliation query against the source.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/database/mirrored-database/overview>

---

### `TH419` — Fabric Eventhouse and KQL Database update policies may transform or drop events without preserving the original payload for after-the-fact verification

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric Eventhouse

#### Description

Update policies on KQL tables run a transformation function on each ingested batch and write to a target table. The original raw payload may be discarded, replaced with the transformed view, or retained only briefly. If an event is later disputed (was the user's action this, or that?), the only record may be the post-transform projection.

#### Possible mitigations

Retain the raw ingest table for the longer of operational need and investigative retention. Document the update policy version applied to each batch. Make raw retention explicit in the data classification.

#### Steps

List Eventhouse tables with update policies. Confirm raw ingest retention covers investigative needs.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/event-streams/destination-eventhouse>

---

### `TH421` — Power BI report exports and subscriptions may distribute data outside the platform without auditable record of the recipient list

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Power BI

#### Description

A user with Read access to a report can export to PDF, Excel, PowerPoint, or PNG, and create subscriptions that email the export to arbitrary addresses on a schedule. The exported artifact leaves Power BI's tenancy and lands in mailboxes outside the report's audience controls. Audit logs record the export action but the subsequent forwarding chain is invisible.

#### Possible mitigations

Apply sensitivity labels with encryption to exported artifacts so the protection travels with the file. Restrict export and subscription rights for reports bound to classified data. Limit subscription recipients to addresses within the tenant. Audit subscription creation events.

#### Steps

Identify reports on classified data with export and subscription permitted. Confirm sensitivity labels travel with exports and that subscription recipient policy is enforced.

**Documentation:** <https://learn.microsoft.com/en-us/power-bi/enterprise/service-security-sensitivity-label-overview>

---

### `TH424` — Fabric Data Activator action invocations may not record the originating event with sufficient detail to reproduce the firing condition

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Fabric Data Activator

#### Description

When an Activator rule fires, the action invocation is logged, but the exact event payload that satisfied the condition may not be retained, especially in high-volume streams where event bodies are sampled or summarized. Investigators asked to determine whether the rule fired correctly cannot replay the input, only inspect the output.

#### Possible mitigations

Persist the satisfying event payload alongside each action invocation for the investigative-retention period. Index by rule and timestamp so an action can be traced back to the event that caused it.

#### Steps

For a recent Activator action invocation, confirm the originating event payload is recoverable and tied to the action.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-activator/data-activator-introduction>

---

### `TH426` — Fabric IQ query history may not preserve the ontology version, source bindings, and resolved query at the time of execution 🤖

**STRIDE:** `R` (Repudiation) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric IQ

#### Description

An IQ query traverses ontology relationships that translate at evaluation time into source-system queries (SQL, KQL, DAX). If only the natural-language input or final answer is logged, an investigator cannot determine which ontology version, which bindings, or which generated query produced the result. Reconstruction is impossible after the ontology changes.

#### Possible mitigations

Snapshot the ontology version and the resolved underlying query into the query record. Retain for the longer of operational need and investigative retention. Make the snapshot inspectable to reviewers.

#### Steps

For a recent IQ query, confirm the ontology version and resolved underlying query are recoverable from the query record.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/iq/overview>

---

## `I` — Information Disclosure (135)

> Information can be read by an unauthorized party.

🤖 **17 of these threats are LLM-tagged.**

### `TH5` — An adversary can gain access to sensitive data by sniffing traffic to database

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, Database, SQL Data Warehouse • Source: Web Application

#### Description

An adversary can eaves drop on communication between application server and {target.Name} server, due to clear text communication protocol usage.

#### Possible mitigations

Ensure SQL server connection encryption and certificate validation. Refer: <https://aka.ms/tmtcommsec#sqlserver-validation> Force Encrypted communication to SQL server. Refer:
<https://aka.ms/tmtcommsec#encrypted-sqlserver>

#### Steps

All communications between SQL Database and a client application are encrypted using Secure Sockets Layer (SSL) at all times. SQL Database doesn’t support unencrypted connections. To validate certificates with application code or tools, explicitly request an encrypted connection and do not trust the server certificates. If your application code or tools do not request an encrypted connection, they will still receive encrypted connections However, they may not validate the server certificates and thus will be susceptible to "man in the middle" attacks. To validate certificates with ADO.NET application code, set Encrypt=True and TrustServerCertificate=False in the database connection string. To validate certificates via SQL Server Management Studio, open the Connect to Server dialog box. Click Encrypt connection on the Connection Properties tab

**Documentation:** <https://social.technet.microsoft.com/wiki/contents/articles/2951.windows-azure-sql-database-connection-security.aspx#best>

---

### `TH6` — An adversary can gain access to sensitive PII or HBI data in {target.Name}

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, Azure Storage, CosmosDB, Database, SQL Data Warehouse

#### Description

Additional controls like Transparent Data Encryption, Column Level Encryption, EKM etc. provide additional protection mechanism to high value PII or HBI data.

#### Possible mitigations

Use strong encryption algorithms to encrypt data in the database. Refer: <https://aka.ms/tmtcrypto#strong-db> Ensure that sensitive data in database columns is encrypted. Refer:
<https://aka.ms/tmtdata#db-encrypted> Ensure that database-level encryption (TDE) is enabled. Refer:
<https://aka.ms/tmtdata#tde-enabled> Ensure that database backups are encrypted. Refer:
<https://aka.ms/tmtdata#backup> Use SQL server EKM to protect encryption keys. Refer:
<https://aka.ms/tmtcrypto#ekm-keys> Use AlwaysEncrypted feature if encryption keys should not be revealed to Database engine. Refer:
<https://aka.ms/tmtcrypto#keys-engine>

#### Steps

Encryption algorithms define data transformations that cannot be easily reversed by unauthorized users. SQL Server allows administrators and developers to choose from among several algorithms, including DES, Triple DES, TRIPLE_DES_3KEY, RC2, RC4, 128-bit RC4, DESX, 128-bit AES, 192-bit AES, and 256-bit AES

**Documentation:** <https://technet.microsoft.com/library/ms345262(v=sql.130).aspx>

---

### `TH9` — An adversary can gain access to sensitive data by sniffing traffic to Web Application

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application • Source: Browser

#### Description

An adversary may conduct man in the middle attack and downgrade TLS connection to clear text protocol, or forcing browser communication to pass through a proxy server that he controls. This may happen because the application may use mixed content or HTTP Strict Transport Security policy is not ensured.

#### Possible mitigations

Applications available over HTTPS must use secure cookies. Refer: <https://aka.ms/tmtsmgmt#https-secure-cookies> Enable HTTP Strict Transport Security (HSTS). Refer:
<https://aka.ms/tmtcommsec#http-hsts>

#### Steps

Cookies are normally only accessible to the domain for which they were scoped. Unfortunately, the definition of "domain" does not include the protocol so cookies that are created over HTTPS are accessible over HTTP. The "secure" attribute indicates to the browser that the cookie should only be made available over HTTPS. Ensure that all cookies set over HTTPS use the secure attribute. The requirement can be enforced in the web.config file by setting the requireSSL attribute to true. It is the preferred approach because it will enforce the secure attribute for all current and future cookies without the need to make any additional code changes.

**Documentation:** <https://msdn.microsoft.com/library/ms228262(v=vs.100).aspx>

---

### `TH14` — An adversary can gain access to sensitive data by sniffing traffic to Azure Redis Cache

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Redis Cache

#### Possible mitigations

Ensure that communication to Azure Redis Cache is over SSL . Refer: <https://aka.ms/tmtcommsec#redis-ssl>

#### Steps

Redis server does not support SSL out of the box, but Azure Cache for Redis does. If you are connecting to Azure Cache for Redis and your client supports SSL, like StackExchange.Redis, then you should use SSL. By default non-SSL port is disabled for new Azure Cache for Redis instances. Ensure that the secure defaults are not changed unless there is a dependency on SSL support for redis clients. Please note that Redis is designed to be accessed by trusted clients inside trusted environments. This means that usually it is not a good idea to expose the Redis instance directly to the internet or, in general, to an environment where untrusted clients can directly access the Redis TCP port or UNIX socket.

**Documentation:** <https://azure.microsoft.com/documentation/articles/cache-faq/#when-should-i-enable-the-non-ssl-port-for-connecting-to-redis>

---

### `TH15` — An adversary can gain access to sensitive data by sniffing traffic from Mobile client

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Source: Mobile Client

#### Possible mitigations

Implement Certificate Pinning. Refer: <https://aka.ms/tmtcommsec#cert-pinning>

#### Steps

Certificate pinning defends against Man-In-The-Middle (MITM) attacks. Pinning is the process of associating a host with their expected X509 certificate or public key. Once a certificate or public key is known or seen for a host, the certificate or public key is associated or 'pinned' to the host. Thus, when an adversary attempts to do SSL MITM attack, during SSL handshake the key from attacker's server will be different from the pinned certificate's key, and the request will be discarded, thus preventing MITM Certificate pinning can be achieved by implementing ServicePointManager's ServerCertificateValidationCallback delegate.

**Documentation:** <https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#.Net>

---

### `TH16` — An adversary can gain access to sensitive data by sniffing traffic to Web API

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web API

#### Possible mitigations

Force all traffic to Web APIs over HTTPS connection. Refer: <https://aka.ms/tmtcommsec#webapi-https>

#### Steps

If an application has both an HTTPS and an HTTP binding, clients can still use HTTP to access the site. To prevent this, use an action filter to ensure that requests to protected APIs are always over HTTPS.

**Documentation:** <http://www.asp.net/web-api/overview/security/working-with-ssl-in-web-api>

---

### `TH18` — An adversary can gain access to unencrypted sensitive data stored in {target.Name}

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** —

**Applies to:** Targets: Azure Storage

#### Description

An adversary can gain access to unencrypted sensitive data in {target.Name}

#### Possible mitigations

Use Azure Storage Service Encryption (SSE) for Data at Rest (Preview). Refer: <https://aka.ms/tmtdata#sse-preview> Use Client-Side Encryption to store sensitive data in Azure Storage. Refer: <https://aka.ms/tmtdata#client-storage>

---

### `TH19` — An adversary can gain access to sensitive data by sniffing unencrypted SMB traffic to {target.Name}

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Storage

#### Description

An adversary can gain access to sensitive data by sniffing traffic to {target.Name}

#### Possible mitigations

Use SMB 3.0 compatible client to ensure in-transit data encryption to Azure File Shares. Refer:
<https://aka.ms/tmtcommsec#smb-shares>

#### Steps

Azure File Storage supports HTTPS when using the REST API, but is more commonly used as an SMB file share attached to a VM. SMB 2.1 does not support encryption, so connections are only allowed within the same region in Azure. However, SMB 3.0 supports encryption, and can be used with Windows Server 2012 R2, Windows 8, Windows 8.1, and Windows 10, allowing cross-region access and even access on the desktop.

**Documentation:** <https://azure.microsoft.com/blog/azure-file-storage-now-generally-available/#comment-2529238931>

---

### `TH31` — An adversary can gain sensitive data from mobile device

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Source: Mobile Client

#### Description

If application saves sensitive PII or HBI data on phone SD card or local storage, then it ay get stolen.

#### Possible mitigations

Encrypt sensitive or PII data written to phones local storage. Refer: <https://aka.ms/tmtdata#pii-phones>

#### Steps

If the application writes sensitive information like user's PII (email, phone number, first name, last name, preferences etc.)- on mobile's file system, then it should be encrypted before writing to the local file system. If the application is an enterprise application, then explore the possibility of publishing application using Windows Intune.

**Documentation:** <https://docs.microsoft.com/intune/deploy-use/manage-settings-and-features-on-your-devices-with-microsoft-intune-policies>

---

### `TH38` — An adversary may eavesdrop the traffic to cloud gateway

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway • Source: IoT Device, IoT Field Gateway

#### Description

An adversary may eavesdrop and interfere with the communication between {source.Name} and {target.Name} and possibly tamper the data that is transmitted.

#### Possible mitigations

Secure Device to Cloud Gateway communication using SSL/TLS. Refer: <https://aka.ms/tmtcommsec#device-cloud>

#### Steps

Secure HTTP/AMQP or MQTT protocols using SSL/TLS.

**Documentation:** <https://azure.microsoft.com/documentation/articles/iot-hub-devguide/#messaging>

---

### `TH52` — An adversary may eavesdrop the communication between the device and the field gateway

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: IoT Field Gateway • Source: IoT Device

#### Description

An adversary may eavesdrop and interfere with the communication between the device and the field gateway and possibly tamper the data that is transmitted

#### Possible mitigations

Secure Device to Field Gateway communication. Refer: <https://aka.ms/tmtcommsec#device-field>

#### Steps

For IP based devices, the communication protocol could typically be encapsulated in a SSL/TLS channel to protect data in transit. For other protocols that do not support SSL/TLS investigate if there are secure versions of the protocol that provide security at transport or message layer.

---

### `TH53` — An adversary may gain access to sensitive clear-text data in CosmosDB

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: CosmosDB

#### Description

An adversary may gain access to sensitive clear-text data in DocumentDB storage

#### Possible mitigations

Encrypt sensitive data stored in DocumentDB. Refer: <https://aka.ms/tmtdata#encrypt-docdb>

#### Steps

Encrypt sensitive data at application level before storing in document DB or store any sensitive data in other storage solutions like Azure Storage or Azure SQL

---

### `TH63` — An adversary can abuse poorly managed {target.Name}'s access keys

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Azure Storage, CosmosDB

#### Description

An adversary can abuse poorly managed {target.Name}'s access keys and gain unauthorized access to storage.

#### Possible mitigations

Ensure secure management of Azure storage access keys. Refer: <https://aka.ms/tmtconfigmgmt#secure-keys>

#### Steps

Key Storage: It is recommended to store the Azure Storage access keys in Azure Key Vault as a secret and have the applications retrieve the key from key vault. This is recommended due to the following reasons: The application will never have the storage key hardcoded in a configuration file, which removes that avenue of somebody getting access to the keys without specific permission Access to the keys can be controlled using Azure Active Directory. This means an account owner can grant access to the handful of applications that need to retrieve the keys from Azure Key Vault. Other applications will not be able to access the keys without granting them permission specifically Key Regeneration: It is recommended to have a process in place to regenerate Azure storage access keys for security reasons. Details on why and how to plan for key regeneration are documented in the Azure Storage Security Guide reference article

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-security-guide/#_managing-your-storage-account-keys>

---

### `TH65` — An adversary can gain access to sensitive data by sniffing traffic between {source.Name} and {target.Name}

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Storage

#### Description

An adversary can gain access to sensitive data by sniffing traffic between {source.Name} and {target.Name} if unencrypted channels are used.

#### Possible mitigations

Ensure that communication to Azure Storage is over HTTPS. Refer: <https://aka.ms/tmtcommsec#comm-storage> Use Client-Side Encryption to store sensitive data in Azure Storage. Refer:
<https://aka.ms/tmtdata#client-storage>

#### Steps

To ensure the security of Azure Storage data in-transit, always use the HTTPS protocol when calling the REST APIs or accessing objects in storage. Also, Shared Access Signatures, which can be used to delegate access to Azure Storage objects, include an option to specify that only the HTTPS protocol can be used when using Shared Access Signatures, ensuring that anybody sending out links with SAS tokens will use the proper protocol.

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-security-guide/#_encryption-in-transit>

---

### `TH73` — An adversary can gain access to unencrypted secrets in Service Fabric applicatinos

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Crosses: Service Fabric Trust Boundary

#### Description

Secrets can be any sensitive information, such as storage connection strings, passwords, or other values that should not be handled in plain text. If secrets are not encrypted, an adversary who can gain access to them can abusethem.

#### Possible mitigations

Encrypt secrets in Service Fabric applications. Refer: <https://aka.ms/tmtdata#fabric-apps>

#### Steps

Secrets can be any sensitive information, such as storage connection strings, passwords, or other values that should not be handled in plain text. Use Azure Key Vault to manage keys and secrets in service fabric applications.

**Documentation:** <https://azure.microsoft.com/documentation/articles/service-fabric-application-secret-management/>

---

### `TH78` — An adversary can gain access to sensitive data by sniffing traffic to Azure Web App

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application • Source: Generic External Interactor

#### Description

An adversary may conduct man in the middle attack and downgrade TLS connection to clear text protocol, or forcing browser communication to pass through a proxy server that he controls. This may happen because the application may use mixed content or HTTP Strict Transport Security policy is not ensured.

#### Possible mitigations

Configure SSL certificate for custom domain in Azure App Service. Refer: <https://aka.ms/tmtcommsec#ssl-appservice> Force all traffic to Azure App Service over HTTPS connection . Refer:
<https://aka.ms/tmtcommsec#appservice-https>

#### Steps

By default, Azure already enables HTTPS for every app with a wildcard certificate for the *.azurewebsites.net domain. However, like all wildcard domains, it is not as secure as using a custom domain with own certificate Refer. It is recommended to enable SSL for the custom domain which the deployed app will be accessed through

**Documentation:** <https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-ssl>

---

### `TH79` — An adversary can fingerprint an Azure web application by leveraging server header information

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟨 Low • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application • Source: Generic External Interactor

#### Description

An adversary can fingerprint web application by leveraging server header information

#### Possible mitigations

Remove standard server headers on Windows Azure Web Sites to avoid fingerprinting. Refer:
<https://aka.ms/tmtconfigmgmt#standard-finger>

#### Steps

Headers such as Server, X-Powered-By, X-AspNet-Version reveal information about the server and the underlying technologies. It is recommended to suppress these headers thereby preventing fingerprinting the application

**Documentation:** <https://azure.microsoft.com/blog/removing-standard-server-headers-on-windows-azure-web-sites/>

---

### `TH80` — An adversary can gain access to certain pages or the site as a whole

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application • Source: Browser

#### Description

Robots.txt is often found in your site's root directory and exists to regulate the bots that crawl your site. This is where you can grant or deny permission to all or some specific search engine robots to access certain pages or your site as a whole. The standard for this file was developed in 1994 and is known as the Robots Exclusion Standard or Robots Exclusion Protocol. Detailed info about the robots.txt protocol can be found at robotstxt.org.

#### Possible mitigations

Ensure that administrative interfaces are appropriately locked down. Refer: <https://aka.ms/tmtauthn#admin-interface-lockdown>

#### Steps

The first solution is to grant access only from a certain source IP range to the administrative interface. If that solution would not be possible than it is always recommended to enforce a step-up or adaptive authentication for logging in into the administrative interface

---

### `TH82` — An adversary can gain access to sensitive data by performing SQL injection

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, CosmosDB, Database, SQL Data Warehouse

#### Description

SQL injection is an attack in which malicious code is inserted into strings that are later passed to an instance of SQL Server for parsing and execution. The primary form of SQL injection consists of direct insertion of code into user-input variables that are concatenated with SQL commands and executed. A less direct attack injects malicious code into strings that are destined for storage in a table or as metadata. When the stored strings are subsequently concatenated into a dynamic SQL command, the malicious code is executed.

#### Possible mitigations

Ensure that login auditing is enabled on SQL Server. Refer: <https://aka.ms/tmtauditlog#identify-sensitive-entities> Ensure that least-privileged accounts are used to connect to Database server. Refer:
<https://aka.ms/tmtauthz#privileged-server> Enable Threat detection on Azure SQL database. Refer:
<https://aka.ms/tmtauditlog#threat-detection> Do not use dynamic queries in stored procedures. Refer:
<https://aka.ms/tmtinputval#stored-proc>

#### Steps

A SQL injection attack exploits vulnerabilities in input validation to run arbitrary commands in the database. It can occur when your application uses input to construct dynamic SQL statements to access the database. It can also occur if your code uses stored procedures that are passed strings that contain raw user input. Using the SQL injection attack, the attacker can execute arbitrary commands in the database. All SQL statements (including the SQL statements in stored procedures) must be parameterized. Parameterized SQL statements will accept characters that have special meaning to SQL (like single quote) without problems because they are strongly typed.

**Documentation:** <https://stackoverflow.com/questions/25558875/how-to-protect-against-asp-net-sql-injections-in-sql-azure>

---

### `TH83` — An adversary can gain access to sensitive data stored in Web API's config files

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web API

#### Description

An adversary can gain access to the config files. and if sensitive data is stored in it, it would be compromised.

#### Possible mitigations

Encrypt sections of Web API's configuration files that contain sensitive data. Refer:
<https://aka.ms/tmtconfigmgmt#config-sensitive>

#### Steps

Configuration files such as the Web.config, appsettings.json are often used to hold sensitive information, including user names, passwords, database connection strings, and encryption keys. If you do not protect this information, your application is vulnerable to attackers or malicious users obtaining sensitive information such as account user names and passwords, database names and server names. Based on the deployment type (azure/on-prem), encrypt the sensitive sections of config files using DPAPI or services like Azure Key Vault.

**Documentation:** <https://msdn.microsoft.com/library/ff647398.aspx>

---

### `TH93` — An adversary may gain access to sensitive data stored in Azure Virtual Machines

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Crosses: Azure IaaS VM Trust Boundary

#### Description

If an adversary can gain access to Azure VMs, sensitive data in the VM can be disclosed if the OS in the VM is not encrypted

#### Possible mitigations

Use Azure Disk Encryption to encrypt disks used by Virtual Machines. Refer: <https://aka.ms/tmtdata#disk-vm>

#### Steps

Azure Disk Encryption is a new feature that is currently in preview. This feature allows you to encrypt the OS disks and Data disks used by an IaaS Virtual Machine. For Windows, the drives are encrypted using industry-standard BitLocker encryption technology. For Linux, the disks are encrypted using the DM-Crypt technology. This is integrated with Azure Key Vault to allow you to control and manage the disk encryption keys. The Azure Disk Encryption solution supports the following three customer encryption scenarios: Enable encryption on new IaaS VMs created from customer-encrypted VHD files and customer-provided encryption keys, which are stored in Azure Key Vault. Enable encryption on new IaaS VMs created from the Azure Marketplace. Enable encryption on existing IaaS VMs already running in Azure.

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-security-guide/#_using-azure-disk-encryption-to-encrypt-disks-used-by-your-virtual-machines>

---

### `TH94` — An adversary can gain access to sensitive information through error messages

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Web Application

#### Description

An adversary can gain access to sensitive data such as the following, through verbose error messages - Server names - Connection strings - Usernames - Passwords - SQL procedures - Details of dynamic SQL failures - Stack trace and lines of code - Variables stored in memory - Drive and folder locations - Application install points - Host configuration settings - Other internal application details

#### Possible mitigations

Do not expose security details in error messages. Refer: <https://aka.ms/tmtxmgmt#messages> Implement Default error handling page. Refer:
<https://aka.ms/tmtxmgmt#default> Set Deployment Method to Retail in IIS. Refer:
<https://aka.ms/tmtxmgmt#deployment> Exceptions should fail safely. Refer:
<https://aka.ms/tmtxmgmt#fail> ASP.NET applications must disable tracing and debugging prior to deployment. Refer:
<https://aka.ms/tmtconfigmgmt#trace-deploy> Implement controls to prevent username enumeration. Refer:
<https://aka.ms/tmtauthn#controls-username-enum>

#### Steps

Generic error messages are provided directly to the user without including sensitive application data. Examples of sensitive data include: Server names Connection strings Usernames Passwords SQL procedures Details of dynamic SQL failures Stack trace and lines of code Variables stored in memory Drive and folder locations Application install points Host configuration settings Other internal application details Trapping all errors within an application and providing generic error messages, as well as enabling custom errors within IIS will help prevent information disclosure. SQL Server database and .NET Exception handling, among other error handling architectures, are especially verbose and extremely useful to a malicious user profiling your application. Do not directly display the contents of a class derived from the .NET Exception class, and ensure that you have proper exception handling so that an unexpected exception isn't inadvertently raised directly to the user. Provide generic error messages directly to the user that abstract away specific details found directly in the exception/error message Do not display the contents of a .NET exception class directly to the user Trap all error messages and if appropriate inform the user via a generic error message sent to the application client Do not expose the contents of the Exception class directly to the user, especially the return value from .ToString, or the values of the Message or StackTrace properties. Securely log this information and display a more innocuous message to the user

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH99` — An adversary may gain access to sensitive data from uncleared browser cache

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Web Application • Source: Browser

#### Possible mitigations

Ensure that sensitive content is not cached on the browser. Refer: <https://aka.ms/tmtdata#cache-browser>

#### Steps

Browsers can store information for purposes of caching and history. These cached files are stored in a folder, like the Temporary Internet Files folder in the case of Internet Explorer. When these pages are referred again, the browser displays them from its cache. If sensitive information is displayed to the user (such as their address, credit card details, Social Security Number, or username), then this information could be stored in browser’s cache, and therefore retrievable through examining the browser's cache or by simply pressing the browser's "Back" button. Set cache-control response header value to “no-store” for all pages.

---

### `TH101` — An adversary can reverse weakly encrypted or hashed content

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application

#### Possible mitigations

Do not expose security details in error messages. Refer: <https://aka.ms/tmtxmgmt#messages> Implement Default error handling page. Refer:
<https://aka.ms/tmtxmgmt#default> Set Deployment Method to Retail in IIS. Refer:
<https://aka.ms/tmtxmgmt#deployment> Use only approved symmetric block ciphers and key lengths. Refer:
<https://aka.ms/tmtcrypto#cipher-length> Use approved block cipher modes and initialization vectors for symmetric ciphers. Refer:
<https://aka.ms/tmtcrypto#vector-ciphers> Use approved asymmetric algorithms, key lengths, and padding. Refer:
<https://aka.ms/tmtcrypto#padding> Use approved random number generators. Refer:
<https://aka.ms/tmtcrypto#numgen> Do not use symmetric stream ciphers. Refer:
<https://aka.ms/tmtcrypto#stream-ciphers> Use approved MAC/HMAC/keyed hash algorithms. Refer:
<https://aka.ms/tmtcrypto#mac-hash> Use only approved cryptographic hash functions. Refer:
<https://aka.ms/tmtcrypto#hash-functions> Verify X.509 certificates used to authenticate SSL, TLS, and DTLS connections. Refer:
<https://aka.ms/tmtcommsec#x509-ssltls>

#### Steps

Generic error messages are provided directly to the user without including sensitive application data. Examples of sensitive data include: Server names Connection strings Usernames Passwords SQL procedures Details of dynamic SQL failures Stack trace and lines of code Variables stored in memory Drive and folder locations Application install points Host configuration settings Other internal application details Trapping all errors within an application and providing generic error messages, as well as enabling custom errors within IIS will help prevent information disclosure. SQL Server database and .NET Exception handling, among other error handling architectures, are especially verbose and extremely useful to a malicious user profiling your application. Do not directly display the contents of a class derived from the .NET Exception class, and ensure that you have proper exception handling so that an unexpected exception isn't inadvertently raised directly to the user. Provide generic error messages directly to the user that abstract away specific details found directly in the exception/error message Do not display the contents of a .NET exception class directly to the user Trap all error messages and if appropriate inform the user via a generic error message sent to the application client Do not expose the contents of the Exception class directly to the user, especially the return value from .ToString, or the values of the Message or StackTrace properties. Securely log this information and display a more innocuous message to the user

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH102` — An adversary may gain access to sensitive data from log files

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** —

**Applies to:** Targets: Web Application

#### Possible mitigations

Ensure that the application does not log sensitive user data. Refer: <https://aka.ms/tmtauditlog#log-sensitive-data> Ensure that Audit and Log Files have Restricted Access. Refer:
<https://aka.ms/tmtauditlog#log-restricted-access>

#### Steps

Check that you do not log any sensitive data that a user submits to your site. Check for intentional logging as well as side effects caused by design issues. Examples of sensitive data include: User Credentials Social Security number or other identifying information Credit card numbers or other financial information Health information Private keys or other data that could be used to decrypt encrypted information System or application information that can be used to more effectively attack the application

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH103` — An adversary may gain access to unmasked sensitive data such as credit card numbers

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** —

**Applies to:** Targets: Web Application • Source: Browser

#### Possible mitigations

Ensure that sensitive data displayed on the user screen is masked. Refer: <https://aka.ms/tmtdata#data-mask>

---

### `TH106` — An adversary can gain access to sensitive information from an API through error messages

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web API

#### Description

An adversary can gain access to sensitive data such as the following, through verbose error messages - Server names - Connection strings - Usernames - Passwords - SQL procedures - Details of dynamic SQL failures - Stack trace and lines of code - Variables stored in memory - Drive and folder locations - Application install points - Host configuration settings - Other internal application details

#### Possible mitigations

Ensure that proper exception handling is done in ASP.NET Web API. Refer: <https://aka.ms/tmtxmgmt#exception>

#### Steps

By default, most uncaught exceptions in ASP.NET Web API are translated into an HTTP response with status code 500, Internal Server Error

**Documentation:** <http://www.asp.net/web-api/overview/error-handling/exception-handling>

---

### `TH107` — An adversary may retrieve sensitive data (e.g, auth tokens) persisted in browser storage

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web API • Source: Browser

#### Possible mitigations

Ensure that sensitive data relevant to Web API is not stored in browser's storage. Refer:
<https://aka.ms/tmtdata#api-browser>

#### Steps

In certain implementations, sensitive artifacts relevant to Web API's authentication are stored in browser's local storage. E.g., Azure AD authentication artifacts like adal.idtoken, adal.nonce.idtoken, adal.access.token.key, adal.token.keys, adal.state.login, adal.session.state, adal.expiration.key etc. All these artifacts are available even after sign out or browser is closed. If an adversary gets access to these artifacts, he/she can reuse them to access the protected resources (APIs). Ensure that all sensitive artifacts related to Web API is not stored in browser's storage. In cases where client-side storage is unavoidable (e.g., Single Page Applications (SPA) that leverage Implicit OpenIdConnect/OAuth flows need to store access tokens locally), use storage choices with do not have persistence. e.g., prefer SessionStorage to LocalStorage.

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH115` — An adversary may sniff the data sent from Identity Server

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Identity Server

#### Description

An adversary may sniff the data sent from Identity Server. This can lead to a compromise of the tokens issued by the Identity Server

#### Possible mitigations

Ensure that all traffic to Identity Server is over HTTPS connection. Refer: <https://aka.ms/tmtcommsec#identity-https>

#### Steps

By default, IdentityServer requires all incoming connections to come over HTTPS. It is absolutely mandatory that communication with IdentityServer is done over secured transports only. There are certain deployment scenarios like SSL offloading where this requirement can be relaxed. See the Identity Server deployment page in the references for more information.

**Documentation:** <https://identityserver.github.io/Documentation/docsv2/configuration/crypto.html>

---

### `TH119` — Sensitive attributes or fields on an Entity can be inadvertantly disclosed

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM

#### Possible mitigations

Perform security modelling and use Field Level Security where required. Refer:
<https://aka.ms/tmtauthz#modeling-field> Perform security modelling and use Business Units/Teams where required. Refer:
<https://aka.ms/tmtdata#modeling-teams>

#### Steps

Perform security modeling and use Field Level Security where required

**Documentation:** <https://docs.microsoft.com/en-us/azure/security/azure-security-threat-modeling-tool>

---

### `TH121` — Sensitive Entity records (containing PII, HBI information) can be inadvertantly disclosed to users who should not have access

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM

#### Possible mitigations

Perform security modelling and use Field Level Security where required. Refer:
<https://aka.ms/tmtauthz#modeling-field> Perform security modelling and use Business Units/Teams where required. Refer:
<https://aka.ms/tmtdata#modeling-teams>

#### Steps

Perform security modeling and use Field Level Security where required

**Documentation:** <https://docs.microsoft.com/en-us/azure/security/azure-security-threat-modeling-tool>

---

### `TH126` — Secure system configuration information exposed via JScript

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Dynamics CRM

#### Possible mitigations

Include a development standards rule proscribing showing config details in exception management outside development. Refer:
<https://aka.ms/tmtdata#exception-mgmt>

#### Steps

Include a development standards rule proscribing showing config details in exception management outside development. Test for this as part of code reviews or periodic inspection.

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH127` — Secure system configuration information exposed when a DotNET exception is thrown

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Dynamics CRM

#### Description

Secure system configuration information exposed when exception is thrown.

#### Possible mitigations

Include a development standards rule proscribing showing config details in exception management outside development. Refer:
<https://aka.ms/tmtdata#exception-mgmt>

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH131` — An Adversary can sniff communication channel and steal the secrets

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: WCF

#### Description

An Adversary can sniff communication channel and steal the secrets.

#### Possible mitigations

Enable HTTPS - Secure Transport channel. Refer: <https://aka.ms/tmtcommsec#https-transport>

**Documentation:** <https://msdn.microsoft.com/library/ff648500.aspx>

---

### `TH139` — An adversary may gain access to sensitive data stored on host machines

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Crosses: Machine Trust Boundary

#### Possible mitigations

Consider using Encrypted File System (EFS) is used to protect confidential user-specific data. Refer:
<https://aka.ms/tmtdata#efs-user> Ensure that sensitive data stored by the application on the file system is encrypted. Refer:
<https://aka.ms/tmtdata#filesystem>

#### Steps

Consider using Encrypted File System (EFS) is used to protect confidential user-specific data from adversaries with physical access to the computer.

**Documentation:** <https://docs.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/create-and-verify-an-efs-dra-certificate>

---

### `TH209` — An adversary may extract sensitive data through model completions 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

An LLM that has access — through retrieval context, tool outputs, system prompt, fine-tuning data, or session memory — to confidential information may surface that information in completions to a user not authorized to see it. The user need not exploit any infrastructure flaw; carefully crafted questions can elicit data the model has been exposed to. This applies to multi-tenant assistants, RAG pipelines that pull from broadly-permissioned stores, and any model whose context blends data of differing sensitivity.

#### Possible mitigations

Apply authorization checks before adding any document, record, or tool result to model context — do not rely on the model to honor 'do not reveal' instructions. Filter retrievals by the calling user's permissions ('security trimming'). Apply output filters to detect sensitive patterns (PII, secrets) before returning completions. Avoid placing high-sensitivity data in system prompts.

#### Steps

For each data source feeding model context, document the authorization model and confirm that permission checks happen before retrieval, not via prompt instructions to the model. Verify that outputs are scanned for sensitive patterns before being returned to the user.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH210` — An adversary may extract memorized training or fine-tuning data from the model 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: AI Developer Platform, AI Platform, AI Specialized Platform, Hugging Face

#### Description

Models trained or fine-tuned on data that includes secrets, personal information, or proprietary content may memorize specific samples and reproduce them when prompted. An adversary using extraction prompts, divergence attacks, or membership inference can recover training samples. This is a design-time concern whenever sensitive data is included in any training, fine-tuning, or embedding generation step.

#### Possible mitigations

Exclude secrets, credentials, and high-sensitivity personal data from all training and fine-tuning corpora. Apply de-identification, redaction, and deduplication before training. Where memorization risk is unavoidable, use techniques that reduce memorization (e.g., differential privacy training) and evaluate the deployed model against extraction probes prior to release.

#### Steps

Identify every training and fine-tuning dataset. Document its sensitivity classification and the redaction and deduplication steps applied. Define an evaluation step that probes the resulting model for memorization of canary samples before deployment.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0024>

---

### `TH211` — An adversary may receive context belonging to another tenant or session due to shared model state 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

Designs that share model context across users or tenants — through reused conversation buffers, global caches, shared system prompts assembled from per-tenant data, or improperly scoped session memory — risk leaking content from one user or tenant into another's completions. The threat is particularly acute for multi-tenant SaaS assistants and shared agent platforms.

#### Possible mitigations

Scope every conversation, memory store, embedding index, and cache by tenant and user identity. Use distinct keys, partitions, or namespaces; do not rely on the model or the calling code to filter by tenant after retrieval. Validate cross-tenant isolation through authorization tests on every retrieval and memory read path.

#### Steps

Diagram tenant boundaries through every component that holds model state — conversation history, vector indexes, caches, fine-tuned adapters. Confirm that each is keyed by tenant and that no shared key path exists.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH212` — Sensitive data may be disclosed to a third-party LLM provider beyond the data's authorized boundary 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI LLM Providers, AI Platform, AI Specialized Platform, Claude Anthropic, Hugging Face

#### Description

When an application sends prompts containing customer data, regulated information, or internal secrets to an external LLM provider, that data crosses an organizational and often jurisdictional trust boundary. If the provider's data-handling terms, regional residency, retention, or training use are not aligned with the data's classification, the act of calling the model itself is a disclosure event.

#### Possible mitigations

Classify data before it is sent to any external LLM provider. For regulated or high-sensitivity data, use providers covered by an appropriate data processing agreement, data residency commitment, and a 'no training on customer data' contractual term. Apply pre-prompt redaction or tokenization for fields not strictly required. Where contractual controls are insufficient, route the workload to a self-hosted or in-tenant model.

#### Steps

Enumerate the data classes that may appear in prompts to each external provider. For each (provider, data class) pair, confirm contractual coverage, retention behavior, and whether redaction is applied before transmission.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH213` — An adversary with access to embedding vectors may reconstruct sensitive source content 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

Embedding vectors are not one-way. An adversary with read access to an embedding store, plus access to the same embedding model, can use embedding inversion techniques to approximately reconstruct the original text — including PII, confidential prose, or source code that was embedded for retrieval. Treating embeddings as 'just numbers' under-protects them.

#### Possible mitigations

Treat embedding stores at the same sensitivity classification as the underlying source text. Apply the same access controls, encryption, and audit logging as for the source data. Avoid embedding fields that are not required for retrieval. Where feasible, use private embedding models so the inversion attacker also needs to obtain the model.

#### Steps

For every embedding store, classify the source data and confirm that the store inherits the same access controls. Verify that embeddings are encrypted at rest and that read access is audited.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH221` — Sensitive business data may be sent to a consumer-tier LLM provider lacking enterprise data controls 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: ChatGPT OpenAI, DeepSeek, Gemini Google, Grok xAI, Perplexity

#### Description

Consumer-grade LLM endpoints (ChatGPT, Gemini, Grok, Perplexity, DeepSeek) historically default to using submitted prompts for model training, retain conversation history indefinitely, and lack the data-processing-agreement coverage available on their enterprise tiers. If the design routes any internal, regulated, or customer data to a consumer-tier endpoint, that data crosses an organizational boundary into a corpus and retention regime the organization does not control.

#### Possible mitigations

Route business data exclusively through enterprise/team tiers that contractually commit to no-training-on-customer-data, defined retention, and a data processing agreement. Block consumer endpoint hostnames at the egress proxy for systems handling regulated data. Maintain an explicit allowlist of approved provider endpoints per data classification.

#### Steps

List every flow that sends prompt data to ChatGPT, Gemini, Grok, DeepSeek, or Perplexity. For each, document the contracted tier (consumer vs enterprise/team), the data classes involved, and confirm the tier matches the classification.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH222` — Search-augmented LLM providers may expose query terms or context to third-party search infrastructure 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Grok xAI, Perplexity

#### Description

Search-augmented assistants (Perplexity, Grok with X integration) issue user query terms and, in some configurations, conversation context to upstream web search backends and to publishers via outbound HTTP fetches. Sensitive terms in a prompt can therefore appear in third-party search logs, referer headers, or publisher analytics, even when the LLM provider itself is contractually compliant. This is distinct from the LLM provider's own data handling.

#### Possible mitigations

For sensitive workloads, disable the search-grounding feature or pre-filter queries to remove identifiers, secrets, and customer terms before submission. Where grounding is required, prefer providers that expose a private retrieval grounding option using a tenant-controlled index. Document the upstream search provider chain as part of the data-flow inventory.

#### Steps

Identify each call to a search-augmented LLM. Determine whether the provider's web-grounding step is enabled and document the upstream search backend and publisher fetch behavior in the data flow diagram.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH224` — Self-hosted open-weights deployments may expose model weights or inference logs through misconfigured infrastructure 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: DeepSeek

#### Description

Open-weights models (DeepSeek and similar) are commonly self-hosted to retain data sovereignty, but the inference servers, weight files, prompt logs, and tokenizer artifacts then become assets the operator must protect. Misconfigured object storage, exposed inference APIs without authentication, and verbose request logging are common deployment-time disclosures. The threat exists at design time wherever the architecture self-hosts open-weights models without an explicit hosting hardening plan.

#### Possible mitigations

Place self-hosted inference endpoints behind authenticated, network-restricted ingress. Treat model weights, adapters, and prompt logs as sensitive data with encryption at rest and audited read access. Use private networks for tenant-to-inference traffic; do not expose inference APIs to the public internet without explicit authentication and rate limiting.

#### Steps

If the design self-hosts an open-weights model, document the hosting environment, ingress controls, network exposure, weight-storage location, log destinations, and credential model. Confirm that prompt logs are scoped, retention-bound, and access-controlled.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0044>

---

### `TH225` — Sending prompts to a provider headquartered in a high-risk jurisdiction may expose data to legal compulsion 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ChatGPT OpenAI, Claude Anthropic, DeepSeek, Gemini Google, Grok xAI, Perplexity

#### Description

Different LLM providers operate under different legal regimes for government access, lawful intercept, and data localization. Sending prompts to a provider whose primary jurisdiction differs from the data's regulatory home (e.g., GDPR-protected data routed outside the EEA, controlled technical data routed to a sanctioned or restricted jurisdiction) may breach data protection or export-control obligations regardless of the provider's commercial terms.

#### Possible mitigations

Maintain a mapping of approved providers per data classification and per regulatory regime. For data subject to residency rules (GDPR, sectoral, sovereignty), route only to providers with documented in-region deployment and a corresponding processing agreement. Engage legal and trade-compliance review for any provider in a jurisdiction with potential export-control or compulsion exposure.

#### Steps

For each provider data flow, record the provider's primary jurisdiction, available regional deployments, and the regulatory regime governing the prompt data. Confirm alignment before approving the integration.

**Documentation:** <https://learn.microsoft.com/en-us/compliance/regulatory/gdpr>

---

### `TH228` — MLOps experiment-tracking metadata may disclose proprietary model design and training data details 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Bedrock, DataRobot, Databricks, Vertex, Watson IBM

#### Description

AI platforms' built-in experiment tracking (notebooks, runs, metrics, model registries) often store hyperparameters, training data sample paths, evaluation outputs, and prompt templates. When workspace permissions default to broad workspace-wide read, this metadata becomes a discovery surface that reveals proprietary model architecture, training corpus composition, and prompt design to anyone with workspace access — including former team members not yet deprovisioned.

#### Possible mitigations

Apply workspace and project-scoped permissions to experiment tracking, model registry, and notebook artifacts on the same basis as source code repositories. Audit reads and removals. Avoid placing real production data samples in tracked experiment outputs; use redacted or synthetic samples for shared workspaces.

#### Steps

Inventory experiment tracking workspaces, model registries, and notebook stores. Document the default permission model and confirm sensitive runs and data samples are placed in appropriately-scoped workspaces.

**Documentation:** <https://atlas.mitre.org/techniques/AML.T0024>

---

### `TH234` — An agentic coding tool may transmit proprietary source code, secrets, or customer data to its model backend 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Antigravity, Claude Code, Cursor, Windsurf

#### Description

Agentic coding tools (Claude Code, Cursor, Windsurf, Antigravity) read repository content, open files, terminal output, and environment context, then send the relevant slices to a remote model. Without scope restrictions, the tool can transmit code from outside the active project, files in the developer's home directory, .env files, cloud credentials cached on disk, and the contents of clipboard or terminal scrollback. The transmitted content crosses the organization boundary into the model provider.

#### Possible mitigations

Configure the coding tool to operate only within an explicit project root. Maintain a deny-list for filenames and patterns commonly containing secrets (.env, .pem, credentials, kube/config). Use enterprise-tier model accounts with no-training and defined retention. For repositories containing regulated or customer data, route the tool to a tenant-controlled model deployment instead of the consumer cloud endpoint.

#### Steps

Document the scope of files and context the tool may access, the model endpoint it sends data to, the contracted tier, and the secret-detection or filename deny-list applied before transmission.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH237` — IDE-integrated AI tools may build and transmit an index of the entire workspace, including out-of-scope projects 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Antigravity, Claude Code, Cursor, Windsurf

#### Description

IDE-native AI assistants frequently index the entire workspace folder for retrieval, including subdirectories the developer did not intend the tool to use - other clients' code, archived projects, scratch experiments containing real data. The index, embeddings, or chunked content is then transmitted to the provider for retrieval-augmented completions, expanding the data exposure beyond what the developer believes they shared.

#### Possible mitigations

Configure indexing scope explicitly per project rather than per workspace root. Use ignore files (.aiignore or equivalent) to exclude archives, secrets, and unrelated client folders. Confirm whether the indexed content is processed in-tenant or transmitted to the provider, and align with the data classification of indexed material.

#### Steps

Document the indexing scope for each developer setup. Confirm an ignore policy excludes out-of-scope folders, and identify whether index content leaves the workstation.

**Documentation:** <https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/>

---

### `TH241` — Generative media outputs may inadvertently reproduce protected training samples or customer-supplied source media 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ElevenLabs, Midjourney, Synthesia

#### Description

Image and audio generation models can reproduce identifiable training samples (specific artworks, copyrighted characters, recognizable voices) when prompted in ways that target memorized content. For platforms that fine-tune on customer-supplied media (custom voices, brand image styles), there is a parallel risk that one customer's outputs surface another customer's training material if tenant isolation in the fine-tuning pipeline is incomplete.

#### Possible mitigations

Use providers that contractually commit to training-data isolation per tenant for custom-trained voices or styles. Apply provider-supplied content filters and watermarking on generated output. Clear license and attribution before deploying generated media in customer-facing products. Avoid prompting strategies that target named third-party works.

#### Steps

For each generative media flow, document whether tenant-specific fine-tuning is in use, the isolation guarantee, and the content/IP-filter applied to generated output before downstream use.

**Documentation:** <https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/>

---

### `TH245` — An over-permissioned DefaultReader role may bypass custom OneLake security data access roles

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric Warehouse, Power BI Direct Lake

#### Description

Microsoft Fabric OneLake Security ships with a DefaultReader role that grants the ReadAll permission. If the DefaultReader role is left in place when custom data access roles are introduced, users assigned to DefaultReader continue to see all data regardless of the narrower roles that were intended to scope their access. The presence of DefaultReader silently negates table, folder, row, and column-level restrictions defined elsewhere.

#### Possible mitigations

When introducing OneLake Security data access roles, edit or delete the DefaultReader role to remove the ReadAll grant before relying on custom roles for access decisions. Treat DefaultReader as an explicit allow-all and design the role model with that in mind. After changes, validate effective permissions for representative users (admin, contributor, viewer, external guest) before publishing.

#### Steps

Inventory each lakehouse where OneLake Security is enabled. Confirm whether DefaultReader still exists and what permissions it carries. For any lakehouse using custom data access roles, remove or scope DefaultReader before treating the custom roles as authoritative.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-security>

---

### `TH246` — A workspace Admin, Member, or Contributor role grants OneLake read/write access to all items in the workspace

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: KQL Database, Microsoft Fabric Eventhouse, Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric SQL Database, Microsoft Fabric Warehouse, Microsoft Fabric Workspace

#### Description

Fabric workspace roles operate at a coarser granularity than item-level or OneLake Security permissions. Admin, Member, and Contributor workspace roles all grant OneLake read and write across every item in the workspace, before any item permission or OneLake Security role is evaluated. A user added to a workspace as Contributor to collaborate on one Power BI report thereby gains read/write to every lakehouse, warehouse, and KQL database in that workspace.

#### Possible mitigations

Scope workspaces to a single business domain or sensitivity tier so that workspace-level access is meaningful. Do not co-locate items of differing classification in one workspace. Use the Viewer role for users who need only see items, and rely on item permissions or OneLake Security for any narrower access. Audit workspace role assignments on a defined cadence.

#### Steps

Diagram each workspace and the items it contains. Classify items by sensitivity and confirm the workspace boundary aligns with the highest-sensitivity item it holds. Document the role assignments and confirm Contributor/Member is granted only to identities that should have full OneLake access to every item in the workspace.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/fundamentals/roles-workspaces>

---

### `TH247` — Data restricted by OneLake Security may still be readable through the SQL analytics endpoint

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric Warehouse

#### Description

OneLake Security and the SQL analytics endpoint security model are separate layers; restrictions configured in one layer do not automatically apply in the other. A row-level or column-level restriction defined in OneLake Security data access roles does not constrain queries that come in through the SQL endpoint, and vice versa. A user denied access via the lakehouse's data access role can still read the same data by issuing T-SQL against the SQL analytics endpoint if they hold endpoint permissions.

#### Possible mitigations

Apply matching restrictions in both layers, or restrict callers to a single access path. Where access must be narrow, prefer disabling the SQL analytics endpoint, or applying T-SQL GRANT/DENY/REVOKE plus RLS/CLS that mirrors the OneLake Security policy. Document the access matrix per persona showing which engines they use and which layer enforces their restriction.

#### Steps

For each lakehouse and warehouse, list the engines that can reach it (Spark, SQL endpoint, Direct Lake, KQL). For each engine, document which security layer is enforcing the restriction and confirm there is no engine path that bypasses it.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-warehouse/sql-granular-permissions>

---

### `TH249` — A cross-region OneLake shortcut combined with OneLake Security may break access or expose unintended data through fallback paths

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake

#### Description

OneLake Security does not support cross-region shortcuts; queries through such shortcuts return 404 errors. Designs that route around the failure by adding parallel un-secured copies, or by expanding role membership to include the shortcut path, may inadvertently widen data exposure. The security model also creates a hidden coupling between Fabric region selection and the ability to apply granular permissions.

#### Possible mitigations

When OneLake Security is required, host the source and consuming workspaces in the same region. If a cross-region shortcut is necessary, replicate the data into a same-region item and apply OneLake Security there rather than introducing parallel un-secured access paths.

#### Steps

Diagram each shortcut, including source and target regions. For shortcuts that cross regions, confirm the OneLake Security posture and that no parallel un-secured copy has been created to work around the limitation.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-security>

---

### `TH252` — Tenant-level Fabric settings may permit data egress (cross-geo AI processing, external sharing, exports) inconsistent with data classification

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric, Microsoft Fabric Tenant

#### Description

Several Fabric capabilities are gated by tenant-level switches: Cross-geo processing for AI, Cross-geo storing for AI, Power BI semantic models via XMLA endpoints, external user sharing, Copilot/Azure OpenAI integration, and dataset export. When a tenant administrator enables one of these for a single workload's convenience, the change applies tenant-wide and may cause regulated data in unrelated workspaces to leave its intended region or be shared externally without the data owner's knowledge.

#### Possible mitigations

Govern Fabric tenant settings as a security-impacting change requiring documented approval from the data protection function. Use security groups in tenant settings to scope risky capabilities to specific workspaces rather than enabling tenant-wide. Maintain an inventory of tenant settings and their last reviewed state.

#### Steps

List the tenant settings currently enabled. For each, identify which workloads rely on it, which workspaces it actually applies to, and whether the data classes in those workspaces are consistent with the egress or sharing the setting permits.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/admin/about-tenant-settings>

---

### `TH254` — A Fabric Data Agent grounding multiple data sources may surface data from one source through queries targeting another 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Data Agent

#### Description

Fabric Data Agents accept up to five data sources (lakehouses, warehouses, semantic models, KQL databases, ontologies) and translate natural-language questions into SQL, DAX, or KQL across them. When sources of differing sensitivity are bound to a single agent, a natural-language question targeting a low-sensitivity source can produce a query plan or a joined result that surfaces information from a higher-sensitivity source. The agent does not enforce per-source authorization beyond the calling identity's underlying permissions.

#### Possible mitigations

Configure each Data Agent with sources of a single sensitivity tier; do not blend regulated and general-purpose data in one agent. Validate that the calling identity has the strictest applicable permission on every bound source. Use table selection within each source to expose only the columns the agent is intended to reason over. Apply OneLake Security or SQL endpoint permissions on the underlying sources rather than relying on agent instructions to constrain behavior.

#### Steps

List each Data Agent and its bound sources, the data classification of each source, and the user populations that can call the agent. Confirm the agent's effective access matches the least-privileged source.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-science/how-to-create-data-agent>

---

### `TH259` — Connections held by a Fabric Data Factory pipeline may grant broader source/sink access than any single pipeline requires

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Data Factory

#### Description

Data Factory connections (linked services) authenticate to source and destination systems and are typically reused across many pipelines. A connection often grants more than the minimum any individual pipeline needs - for example, account-level access to a storage account when only a single container is required, or admin-equivalent database credentials reused across many copy activities. Any pipeline (or pipeline author) on the workspace inherits this broader scope.

#### Possible mitigations

Define connections at the narrowest scope each pipeline requires (specific container, schema, or table) rather than a single shared admin connection. Prefer managed identities or workload identity federation to long-lived shared secrets. Audit connections for unused permission scopes and rotate credentials on a defined cadence.

#### Steps

List the connections in each Data Factory workspace, the scope of access each grants, and the pipelines that reference them. Confirm scope matches the minimum required across consumers.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-factory/connector-overview>

---

### `TH260` — A Fabric IQ ontology may make implicit joins across source systems queryable by callers who hold no relationship to the underlying data model 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric IQ

#### Description

Fabric IQ ontologies model business entities and relationships across multiple OneLake sources, exposing entity types, properties, and traversable relationships through a unified graph. Once an ontology is bound to data, a caller authorized to query the ontology can pose questions that traverse relationships the source-system access controls would not have permitted to be joined directly - for example, linking employee records to compensation, or customer records to support tickets. The ontology becomes a join surface that aggregates exposure beyond any one source.

#### Possible mitigations

Treat the ontology as a security-relevant artifact: review the entity types, properties, and relationship types before publication. Bind only sources whose joined view is intended to be queryable. Ensure callers' permissions on each underlying source are still evaluated; do not rely on the ontology to be a sufficient access boundary. Restrict ontology authoring to a small named set of stewards.

#### Steps

Inventory each ontology and the data sources it binds. Document the relationships defined and confirm that callers authorized to traverse them have the corresponding source-level access.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/iq/overview>

---

### `TH261` — Mirroring data from an external source into Fabric strips the source's native access controls and replaces them with the Fabric workspace model

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Mirroring

#### Description

Fabric Mirroring continuously replicates data from external sources (Azure SQL, Cosmos DB, Snowflake, etc.) into OneLake. The replicated data is then governed by Fabric's workspace, item, and OneLake Security model - not by the source system's row-level security, dynamic data masking, or column-level grants. Designs that depend on source-system controls for compliance can find that the mirrored copy is reachable by a wider population, with no equivalent restriction.

#### Possible mitigations

Before enabling Mirroring, inventory the source system's row, column, and masking policies and design equivalent OneLake Security or SQL endpoint controls in the Fabric workspace. Place the mirror in a workspace whose role assignments match the intended audience. Where source controls cannot be reproduced, do not mirror the affected tables.

#### Steps

List each Mirroring source, the source-system access controls in effect, and the Fabric-side controls planned for the mirror. Confirm equivalence before enabling replication.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/database/mirrored-database/overview>

---

### `TH262` — A Power BI semantic model published without row-level security may expose data across role boundaries when the report is shared

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Power BI

#### Description

Power BI semantic models within Fabric govern report access through role-level security (RLS) defined in the model. When a model is published without RLS, or with overly broad role definitions, a report shared with a wider audience exposes data the recipients should not see based on their organizational role. The risk is exacerbated by 'Build' permission, which lets recipients author new reports against the same model and discover data the original report did not surface.

#### Possible mitigations

Define RLS at the semantic model level for any model that exposes data partitioned by role, tenant, or business unit. Test the RLS rules with representative role memberships before publishing. Be explicit about Build vs Read sharing - granting Build effectively grants the user the model's full data scope. Re-evaluate RLS after schema changes that add new tables or columns.

#### Steps

For each semantic model, document the RLS rules, the tested role memberships, and the sharing policy (Read vs Build). Re-validate after model changes.

**Documentation:** <https://learn.microsoft.com/en-us/power-bi/enterprise/service-admin-rls>

---

### `TH265` — A Fabric Lakehouse may expose raw landing-zone data through Files or Tables paths before redaction or schema enforcement

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse

#### Description

A Fabric Lakehouse contains both an unmanaged Files area and a Delta-managed Tables area. Raw data ingested into Files - source extracts, change-data-capture dumps, third-party drops - is reachable by anyone with read access to the lakehouse before any column-level redaction, tokenization, or schema enforcement is applied. OneLake Security column-level controls operate on the Tables side; the Files side is governed by item-level read.

#### Possible mitigations

Land sensitive raw data in a workspace whose role assignments are limited to ingestion service identities, then promote redacted/curated outputs to a separate workspace where consumers have access. Do not co-locate the raw landing zone with consumer-facing curated tables. Apply column-level OneLake Security on the Tables side and treat Files as not-yet-protected.

#### Steps

Diagram the data path from ingestion through landing zone to curated tables. Confirm the landing zone is in a workspace whose access matches the highest-sensitivity raw data it receives.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/lakehouse-overview>

---

### `TH267` — A OneLake shortcut to external storage transfers control over data residency and access to whoever administers the shortcut target

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric OneLake

#### Description

OneLake shortcuts virtualize external storage (ADLS Gen2, Amazon S3, Google Cloud Storage, Dataverse) to appear as a native OneLake folder. The shortcut definition holds the connection and credential reference. Once a shortcut exists, callers authorized on the OneLake side can read data living outside Fabric's region and outside the workspace administrator's direct control. Conversely, a contributor who can create shortcuts can introduce data of unknown provenance into a workspace.

#### Possible mitigations

Restrict shortcut creation to a named set of stewards. Document the target storage, region, and ownership for every shortcut. For sensitive workspaces, enforce a review process before shortcut creation. Use private endpoints and managed identities for shortcut connections rather than shared keys.

#### Steps

List each shortcut in scope, its target storage location, the credential mechanism, and the data classification on each side. Confirm shortcut creation is governed and that targets comply with the workspace's residency requirements.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/onelake-shortcuts>

---

### `TH268` — Fabric Warehouse dynamic data masking is a presentation control, not a security boundary, and may be bypassed by direct queries with sufficient privilege

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric Warehouse

#### Description

Fabric Warehouse supports dynamic data masking, which obfuscates column values for designated callers in result sets. Dynamic data masking is intended as a defense-in-depth presentation control: it does not encrypt the underlying data, and a user with UNMASK permission, appropriate role, or the ability to issue queries that infer the value (sub-strings, range queries, casts) can recover the masked data. Treating dynamic data masking as the primary control for sensitive data leaves the data exposed to determined queriers.

#### Possible mitigations

Use dynamic data masking only as a defense-in-depth measure. For sensitive columns, combine it with column-level GRANT/DENY, RLS, or storage-side encryption with a separate access boundary for the decryption key. Do not assume masked output protects against an authenticated caller with read on the column.

#### Steps

For each masked column, identify the callers with read access and confirm whether they could recover the value through allowed queries. Add column-level revocation or RLS where the masked value must be unrecoverable.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-warehouse/dynamic-data-masking>

---

### `TH269` — Power BI Direct Lake reports may surface schema or data changes from the underlying Lakehouse before the semantic model's RLS or OLS is re-evaluated

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Power BI Direct Lake

#### Description

Power BI Direct Lake mode reads Delta tables directly from OneLake without an import step, so underlying schema changes (new columns, restored deleted columns, reorganized partitions) are visible to the semantic model on the next refresh of metadata. If the semantic model's row-level or object-level security was authored against the prior schema, a newly-introduced sensitive column may pass through into report visuals before security rules covering it are added. There is a window where the model exposes more than the data steward intended.

#### Possible mitigations

Treat schema changes to lakehouses backing Direct Lake models as security-impacting events. Notify the model owner before applying additive schema changes and re-validate RLS/OLS coverage afterward. Use deny-by-default rules where supported so that unrecognized columns are hidden until explicitly granted.

#### Steps

Identify each Direct Lake semantic model and the lakehouses it reads. Define the change-control process linking schema changes in the lakehouse to RLS/OLS review in the model.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-warehouse/direct-lake-overview>

---

### `TH271` — Telemetry stored in a KQL Database or Eventhouse may retain identifying or sensitive data beyond its intended lifecycle

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: KQL Database, Microsoft Fabric Eventhouse

#### Description

KQL Databases and Eventhouses are commonly used as the analytic store for telemetry, audit, and observability data. The default retention and caching policies frequently outlive the lifecycle of the personal or sensitive identifiers contained in the events. Without an explicit retention policy aligned to data classification, identifiers (user IDs, IP addresses, device IDs, request bodies) accumulate in queryable form long after they are needed.

#### Possible mitigations

Define explicit retention and caching policies on each KQL table according to the sensitivity of the fields it stores. Apply update policies or materialized views to drop or hash sensitive fields at ingestion time when only aggregate analysis is required. Document retention decisions per table and align with data protection obligations.

#### Steps

List each KQL table and its sensitive fields. Confirm the retention and caching policy matches the field-level classification, and that downstream queries cannot read fields past their intended retention.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/event-house-overview>

---

### `TH273` — Cosmos DB in Fabric may expose multi-tenant operational data through its OneLake mirror to consumers without the application-tier tenancy controls

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Cosmos DB

#### Description

Cosmos DB in Fabric exposes operational containers as OneLake-readable mirrored tables. Where the operational application enforces tenancy through partition-key filtering at the application layer, the mirror surfaces all tenants' data to any caller with read on the OneLake item. Analytics consumers that bypass the application tier therefore lose the tenancy boundary without any explicit configuration change.

#### Possible mitigations

Treat the Cosmos-in-Fabric mirror as a separate trust boundary from the operational store. Apply OneLake Security row-level filtering on the partition-key column to reproduce the tenancy boundary, or restrict workspace access to identities that are authorized to see all tenants' data. Do not assume application-tier tenancy carries through to the mirror.

#### Steps

For each Cosmos DB in Fabric mirror, document the application-tier tenancy model, the OneLake Security policy applied to the mirror, and the consumer audience.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/database/cosmos-db/overview>

---

### `TH274` — External (B2B guest) users may receive broader OneLake access than intended depending on Entra External ID collaboration settings

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric Workspace

#### Description

Fabric inherits guest user behavior from Microsoft Entra External ID. The 'Guest user access' setting determines whether guests get the same access as members or are restricted. When set to 'same access as members,' guests added to a workspace inherit the full member-level access to OneLake content; when set more restrictively, OneLake Security data access role assignments for guest users may not work as intended. The behavior is configured at the tenant level and is not visible from the Fabric workspace UI.

#### Possible mitigations

Document the Entra External Collaboration setting that governs guest behavior in this tenant. When inviting guests to workspaces containing sensitive data, confirm the setting matches the intended access model. Where guest access is required for OneLake Security roles to function, set 'Guest user access' to 'same access as members' explicitly. Audit guest workspace memberships periodically.

#### Steps

Identify the workspaces that contain external guest members. Document the tenant External Collaboration setting, confirm guest access matches the intended scope on each item, and audit guest assignments on a defined cadence.

**Documentation:** <https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure>

---

### `TH278` — OneLake Security role and membership limits may force designs to widen role scope, regressing least-privilege at scale

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric Warehouse

#### Description

OneLake Security supports a maximum of 250 roles per lakehouse, 500 members per role, and 500 permissions per role. Designs intended to encode fine-grained access by role-per-team or role-per-data-category can hit these limits as the organization scales, after which the common workaround is to consolidate roles - merging populations of differing need-to-know into broader roles - which silently regresses the least-privilege model the original design established.

#### Possible mitigations

Design the role model with the limits in mind: prefer role assignments based on group membership (one role, many groups) rather than direct user assignment, so the 500-member limit applies to groups, not individuals. Where business segmentation exceeds the role budget, split the data across multiple lakehouses on the corresponding workspace boundary rather than consolidating roles. Track role count toward the limit and treat reaching 80%+ as a design review trigger.

#### Steps

Project the steady-state role count, member count per role, and permission count per role for each lakehouse. Confirm the design fits within the limits without resorting to role consolidation that would broaden access.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-security>

---

### `TH279` — Enabling OneLake Security forces an exclusive choice with private link protection and Purview Data Share, potentially weakening the chosen control

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric Warehouse, Microsoft Fabric Workspace

#### Description

OneLake Security does not work with private link tenant configurations or with Azure/Purview Data Share. A workspace requiring all three protections cannot have them simultaneously; the design must pick one. A workspace owner who enables OneLake Security to gain row/column filtering may inadvertently disable a private-link-only network posture, exposing data over public endpoints. Conversely, retaining private link may force fall back to coarser workspace-level access without granular OneLake roles.

#### Possible mitigations

At design time, decide the primary control posture per workspace: granular access via OneLake Security, network isolation via private link, or external sharing via Purview Data Share. Document the choice and the residual exposure of the controls not adopted. For workloads needing both granular access and network isolation, partition the data across workspaces with different postures (one private-link-protected with workspace-role access, one OneLake-Security-enabled for the consumer surface).

#### Steps

List each workspace's required protections and confirm the chosen control set is achievable in combination. For mutually exclusive requirements, document the partitioning strategy.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/best-practices-secure-data-in-onelake>

---

### `TH280` — Direct Lake's silent fallback to DirectQuery shifts the engine evaluating the query and may apply a different security context than the design assumed

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Power BI Direct Lake

#### Description

Power BI Direct Lake mode falls back to DirectQuery against the SQL analytics endpoint when encountering features Direct Lake does not support (calculated columns, certain DAX functions, model-size or row-count thresholds). The fallback is silent at the report level. Direct Lake and DirectQuery can apply security through different layers - OneLake Security for Direct Lake reads, SQL endpoint permissions for DirectQuery - and the controls may not be equivalent. A design that protects sensitive data only at one layer can find that fallback surfaces the data through the other.

#### Possible mitigations

Apply matching security restrictions to the data through both Direct Lake and DirectQuery paths so that fallback does not change the effective access. Monitor query plans or capacity metrics for unexpected DirectQuery activity on Direct Lake models. Where features are known to trigger fallback, evaluate them at design time and either avoid them or accept the DirectQuery security model.

#### Steps

List the Direct Lake semantic models in scope and the model features they use. Identify fallback triggers and confirm both engines are restricted equivalently.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-warehouse/direct-lake-overview>

---

### `TH281` — Source-system credentials stored to enable Fabric Mirroring become a workspace-resident asset that compromises the source if leaked

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Mirroring

#### Description

Fabric Mirroring continuously replicates data from source systems (Azure SQL, Cosmos DB, Snowflake, etc.). Establishing the mirror requires storing source-system credentials - a connection string, a SQL login, a service principal secret, or an API key - inside the Fabric workspace's connection store. That credential typically grants more than the mirroring function strictly needs (e.g., read across an entire database rather than just the mirrored schema). A workspace administrator who can read connection metadata, or any compromise that exposes the workspace credential store, gives the attacker access to the upstream source system - not merely the mirror.

#### Possible mitigations

Use the most narrowly-scoped source-system principal that supports mirroring (e.g., a dedicated SQL login with read on only the mirrored schema). Prefer managed identity or workload identity federation over shared keys where the source supports it. Restrict who can view connection metadata in the workspace. Rotate mirroring credentials on a defined cadence. Treat the workspace as having effective read on every system it mirrors from.

#### Steps

List each Mirroring connection, the credential type, the source-system permissions it grants, and the workspace identities that can view or use the connection. Confirm scope minimization.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/database/mirrored-database/overview>

---

### `TH283` — A Fabric Data Activator rule that calls an outbound webhook may become a data exfiltration channel disguised as an automation

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Activator

#### Description

Activator rules can call arbitrary external webhooks as actions. A user authorized to create rules can author a rule that, on detecting a benign condition, sends event data - including the values that triggered it - to a URL the user controls. Because Activator's outbound calls may be permitted by default network policies (the Fabric service is the originating host), this can become a covert exfiltration path that surfaces fields from the underlying eventstream or KQL data without traversing the user's own network.

#### Possible mitigations

Restrict Activator outbound destinations using an allowlist of approved webhook URLs at the workspace or capacity level. Where allowlisting is not available, place high-sensitivity Activator items in a workspace whose rule authoring is limited to a small set of trusted operators. Audit the destination URL of every Activator action and treat changes as security-impacting events. Avoid exposing high-sensitivity fields in event payloads that are available to rule authors.

#### Steps

List every Activator rule with an outbound webhook action. Document the destination, the fields included in the call, and the authoring identity. Confirm the destinations are approved and that rule authoring is appropriately scoped.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/data-activator/data-activator-introduction>

---

### `TH285` — The Lakehouse Files area is reachable through ABFS / OneLake paths that bypass the Tables-only review surface and any Delta-table-level access decisions

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake

#### Description

Each Fabric Lakehouse exposes its Files area through the OneLake ABFS path (abfss://@onelake.dfs.fabric.microsoft.com/.Lakehouse/Files). Tools and scripts using OneLake-aware clients can read and write directly to that path with the calling identity's OneLake permissions, without touching the Tables surface that is the focus of most data-modeling review. Sensitive data placed in Files - lookup CSVs, scratch outputs, model artifacts - inherits only item-level read, with no row, column, or schema-level controls.

#### Possible mitigations

Treat the Files area as having only coarse access control; do not place data there that requires row, column, or schema-level restriction. Audit OneLake ABFS read events on the Files prefix. Where teams use Files for intermediate artifacts, segregate sensitive ones into separate lakehouses or workspaces with appropriately narrow membership rather than relying on in-Files filtering.

#### Steps

List the data classes placed in each Lakehouse Files area and the identities with OneLake read on the lakehouse. Confirm the data classification matches item-level access; relocate sensitive content to a lakehouse with narrower access if needed.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/onelake-access-api>

---

### `TH286` — Copilot and generative AI features in Fabric send workspace data and metadata to model providers, crossing trust boundaries that the workspace owner may not have authorized

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric, Microsoft Fabric Compute, Microsoft Fabric Data, Microsoft Fabric Tenant

#### Description

Fabric integrates Copilot and other generative AI features that operate against workspace content - column names, sample data, query results, semantic model metadata - and may invoke Azure OpenAI or other model endpoints, potentially in a different geography than the data's primary region. The data and metadata sent in support of these features cross the workspace trust boundary. Where the data is regulated or where data residency matters, the act of using Copilot (often enabled by default at the tenant level) is itself a disclosure event.

#### Possible mitigations

Govern Copilot and generative AI feature enablement as security-impacting changes. Disable at tenant level for workspaces handling regulated data, or scope the feature to specific security groups. Confirm geography and processing terms for the Copilot endpoint match the data's residency and regulatory requirements. Document Copilot-derived outputs as having been exposed to the model provider.

#### Steps

Document Copilot enablement state at tenant and workspace level. For each workspace where Copilot is enabled, confirm the data classes are consistent with the model endpoint's processing region and terms.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/fundamentals/copilot-faq>

---

### `TH289` — Fabric domains and tenant-wide endorsement features may distribute items across the organization beyond their original workspace audience

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric, Microsoft Fabric Compute, Microsoft Fabric Data, Microsoft Fabric Tenant

#### Description

Fabric domains (subdivisions of a tenant) and item endorsement (Promoted, Certified) make items more discoverable across workspaces. An item endorsed at domain or tenant level is surfaced in OneLake Catalog and recommendation experiences for users who would not have otherwise found it. If endorsement is granted before access controls on the item match the wider audience, users discover the item in catalog views and may request or be auto-granted access in ways the original owner did not anticipate.

#### Possible mitigations

Treat endorsement (Promoted, Certified) as a publication step that requires confirming the underlying item's permissions match the endorsed audience. Restrict who can apply endorsement, particularly Certified. Define a domain/tenant publication review checklist that includes the item's row/column/role permissions, classification, and shareability before endorsement.

#### Steps

List endorsed items at domain and tenant level. For each, confirm the item's effective permission boundary matches the endorsed audience and that the endorsement did not implicitly widen access.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/governance/domains>

---

### `TH290` — An over-broad Key Vault access policy or RBAC role grants identities the ability to read every secret, key, and certificate in the vault

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Key Vault

#### Description

Azure Key Vault uses access policies or RBAC roles (Key Vault Secrets User, Key Vault Administrator, Key Vault Crypto Officer) to control access. A single principal granted Key Vault Administrator or a broad Get/List policy can read every secret, including those that belong to unrelated workloads sharing the same vault. Co-locating secrets for many applications in one vault therefore concentrates blast radius: any compromised consumer becomes a compromise of every secret in the vault.

#### Possible mitigations

Scope each principal to the minimum operations and minimum object scope required (Key Vault RBAC supports per-secret scoping with secret URIs). Partition secrets across multiple vaults by application or sensitivity tier rather than concentrating them. Prefer Key Vault RBAC over legacy access policies for granular permission scoping. Audit role assignments and access policies on a defined cadence.

#### Steps

Inventory each Key Vault and the principals with read access. Document the application or workload boundary the vault is intended to serve and confirm the principal set matches.

**Documentation:** <https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide>

---

### `TH295` — Pods deployed to Azure Kubernetes Service may pull container images from untrusted registries or with mutable tags, introducing unverified code into the cluster

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Kubernetes Service

#### Description

Without admission control or registry restriction, AKS will pull any image referenced in a pod spec - including from public registries, personal accounts, or tagged but unsigned images. A pod referencing :latest or a moving tag receives whatever the publisher pushed most recently. A compromised dependency, a typosquatted image name, or a mutable tag swap introduces attacker-controlled code into the cluster, executing under the pod's ServiceAccount and reaching every cluster resource the ServiceAccount can address.

#### Possible mitigations

Restrict image pulls to a curated set of approved registries (Azure Container Registry with private endpoints, internal mirror). Pin images by digest (sha256), not tag. Enforce image provenance with admission controllers (Azure Policy for Kubernetes, Gatekeeper, or signed-image policies via Notation/Cosign). Scan images for vulnerabilities before deployment and block on policy violations.

#### Steps

Document the registries permitted in the cluster, the admission policies enforcing image provenance, and the image-signing/scanning workflow. Identify any deployment paths that bypass these controls.

**Documentation:** <https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-container-image-management>

---

### `TH296` — Azure App Service application settings and connection strings are readable by anyone with site Contributor and may be exposed through deployment slots and Kudu

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: App Service

#### Description

App Service stores application settings, connection strings, and slot-specific configuration as plain text accessible to any principal with site Contributor or above on the App Service resource. The Kudu (SCM) site exposes these values in the environment of the running process, in build logs, and to anyone with access to the SCM endpoint. Cloning a production deployment slot or copying configuration to a non-production environment can propagate production secrets into less-protected scopes.

#### Possible mitigations

Reference secrets from Azure Key Vault using Key Vault references rather than storing them directly in App Service configuration. Restrict site Contributor membership to identities trusted with the secrets the app holds. Scope SCM/Kudu access separately and disable basic auth on SCM. Be explicit about which configuration values are slot-sticky vs slot-swapped.

#### Steps

List each App Service and the configuration values it holds. Confirm sensitive values use Key Vault references and that site Contributor membership matches the trust required.

**Documentation:** <https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references>

---

### `TH298` — Service Fabric cluster certificates used for administrator access may be shared across operators, eliminating per-user attribution

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Service Fabric

#### Description

Service Fabric clusters authenticate management clients with X.509 certificates that map to either administrator or user roles. When a single admin certificate is exported and shared with every operator, the cluster's audit log shows only 'admin certificate' as the actor, not the human who acted. Compromise of any operator's machine compromises the shared certificate, with no signal of which copy was leaked.

#### Possible mitigations

Issue per-operator client certificates rather than sharing a single admin certificate. Where Microsoft Entra-based authentication for the cluster is supported, prefer it over client certificates so that named-user attribution and Conditional Access apply. Rotate the node-to-node and admin certificates on a defined schedule.

#### Steps

For each Service Fabric cluster, document the admin authentication method (shared cert, per-user cert, Entra). Confirm per-user attribution is achievable and that certificate rotation is planned.

**Documentation:** <https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-security-update-certs-azure>

---

### `TH300` — API Management subscription keys are long-lived shared secrets that grant the subscription's API access to anyone holding the key

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: API Management

#### Description

Azure API Management subscriptions issue primary and secondary subscription keys that callers present in headers (Ocp-Apim-Subscription-Key) to identify themselves and authorize API access. The key is a long-lived shared secret. If embedded in client-side code, leaked in browser network traces, committed to a repository, or shared across clients, anyone with the key can call the subscribed APIs at the subscription's quota, with no per-caller attribution. Subscription keys do not authenticate the caller; they identify a subscription.

#### Possible mitigations

For client-facing or untrusted-environment APIs, prefer OAuth 2.0 / Microsoft Entra-issued tokens with per-user identity rather than subscription keys. When subscription keys are used, scope them to a single back-end caller and rotate regularly. Do not embed subscription keys in client-side code; route untrusted callers through a server-side proxy that adds the key. Monitor subscription usage anomalies.

#### Steps

Document each APIM subscription, its consumer, and the storage location of its keys. Confirm keys are not exposed to untrusted environments and that rotation is in place.

**Documentation:** <https://learn.microsoft.com/en-us/azure/api-management/api-management-subscriptions>

---

### `TH304` — Service Bus shared access signatures with broad rights or namespace-level scope grant blanket access to every queue and topic in the namespace

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Event Hub, Service Bus

#### Description

Azure Service Bus authentication via SAS supports two scope levels: namespace-level and entity-level (queue or topic). A namespace-level SAS with Manage rights grants access to every queue and topic in the namespace, including ones the consumer should not see. Embedding a namespace-level SAS in client code or sharing it across applications concentrates access far beyond what each application needs.

#### Possible mitigations

Use entity-scoped SAS with the minimum rights needed (Send, Listen) per consumer rather than namespace-scoped SAS with Manage. Prefer Microsoft Entra-based authentication and Azure RBAC for Service Bus over SAS where possible. Rotate SAS keys regularly and store them in Key Vault. Audit SAS rule definitions on each namespace.

#### Steps

List the SAS rules on each Service Bus namespace and entity. Document the consumers, the rights granted, and the storage location of each key. Confirm scope is appropriate.

**Documentation:** <https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization>

---

### `TH305` — An Azure Stream Analytics job output configuration may fan out sensitive event data to multiple sinks at differing trust levels

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Stream Analytics

#### Description

Stream Analytics jobs read from inputs (Event Hubs, IoT Hub, Blob), apply transformations, and write to one or more outputs (Storage, SQL, Cosmos, Event Hub, Power BI). A job edited to add an output sink immediately begins streaming live data there. If the new sink is in a different trust domain than the inputs - a different storage account, a different team's Power BI workspace - the addition is a continuous data export with no per-record consent.

#### Possible mitigations

Govern Stream Analytics job edits under change control; restrict job-edit rights on production jobs to a small named set. Document each input/output pair as a data flow with trust classification on both ends. Require approval for adding new outputs to a job that consumes sensitive inputs. Apply transformations that filter or redact sensitive fields before writing to lower-trust sinks.

#### Steps

For each Stream Analytics job, document inputs, outputs, and the trust classification of each. Identify edits that would cross trust boundaries and require approval.

**Documentation:** <https://learn.microsoft.com/en-us/azure/stream-analytics/stream-analytics-introduction>

---

### `TH306` — Azure Cosmos DB master keys grant full account access; embedding them in clients or sharing them across services exposes every database in the account

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: CosmosDB

#### Description

Cosmos DB exposes primary and secondary master keys that grant full read/write/manage across every database and container in the account. Read-only keys grant read across the entire account. Resource tokens (per-user, per-permission) and Microsoft Entra RBAC are available but require explicit configuration. Designs that embed master keys in client applications, share them across services, or check them into source control expose every container in the account.

#### Possible mitigations

Use Microsoft Entra RBAC for Cosmos DB control-plane access and resource tokens (or Entra data-plane RBAC where available) for client applications. Reserve master keys for back-end services that cannot be trusted to handle other key types, store them in Key Vault, and rotate regularly. Disable local (key-based) auth where Entra alone suffices.

#### Steps

For each Cosmos DB account, list consumers and the auth method each uses. Confirm master keys are reserved for trusted back-ends and clients use scoped credentials.

**Documentation:** <https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control>

---

### `TH307` — Azure Storage containers configured with anonymous read access, or storage accounts allowing public network access, expose blobs to the internet

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Storage, Data Lake Store, Files

#### Description

Azure Storage containers can be set to Blob (anonymous read for blobs) or Container (anonymous read+list) public access levels. Combined with a storage account that allows public network access (the default), the contents are reachable from the internet without authentication. Misconfiguration through ARM templates, casual portal use, or programmatic deployment can expose containers holding logs, backups, or customer data. Discovery is trivial via account-name enumeration.

#### Possible mitigations

Disable anonymous container access at the storage account level (allowBlobPublicAccess=false). Restrict the storage account to private endpoints or selected networks. Audit existing containers' public access level. Use Azure Policy to enforce no-public-access at scale and alert on storage accounts that allow public access.

#### Steps

List storage accounts and their network and public-access configuration. Identify any anonymous containers and confirm they intentionally hold public content. Apply Azure Policy to prevent regression.

**Documentation:** <https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent>

---

### `TH309` — Azure AI Search admin keys grant full index management; query keys leaked to clients allow enumeration of indexed content beyond the application's intended access

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Search

#### Description

Azure AI Search uses admin keys (full management) and query keys (read-only on indexes). Admin key exposure permits index modification, scoring profile changes, and synonym map tampering. Query key exposure allows enumeration of every searchable document in the index via wildcard queries, scrolling, or aggregations - not just the documents the embedding application intended each user to see. Document-level security must be enforced inside the query (security trimming) since Azure Search does not natively filter by caller identity.

#### Possible mitigations

Treat Azure Search admin keys as high-value secrets stored in Key Vault, accessed by trusted back-ends only. Issue scoped query keys per consumer. For multi-tenant or per-user data, implement security trimming (filter by user/tenant claim in every query) at the back-end before invoking search; do not expose the query API directly to untrusted clients. Prefer Microsoft Entra-based authentication where supported.

#### Steps

For each Search service, document index contents, query-key consumers, and the security trimming approach for multi-tenant data.

**Documentation:** <https://learn.microsoft.com/en-us/azure/search/search-security-overview>

---

### `TH310` — Azure Cache for Redis may persist sensitive data with weaker access controls than the source system, and may be reachable over non-TLS ports if defaults are changed

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Redis Cache

#### Description

Azure Cache for Redis is commonly used to cache session data, API responses, and database query results. Cached values inherit only Redis-level authentication (access key or Entra RBAC) - not the source system's row, column, or tenant filters. RDB/AOF persistence (if enabled) writes the cache to managed storage that has its own access boundary. The non-TLS port is disabled by default but can be re-enabled for client compatibility, after which credentials and cached values traverse the network in clear text.

#### Possible mitigations

Apply the source data's classification to the cache: do not cache fields the source restricts unless the cache enforces equivalent controls. Keep the non-TLS port disabled. Use Microsoft Entra authentication for Redis where supported. If persistence is enabled, audit the persistence storage account's access. Scope each Redis instance to a single tenant or trust domain.

#### Steps

For each Redis instance, document what is cached, the source data classification, the auth method, the TLS configuration, and persistence settings.

**Documentation:** <https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-best-practices-development>

---

### `TH311` — ADLS Gen2 access decisions combine Azure RBAC and POSIX-style ACLs in non-obvious ways, allowing access to persist after the intended deprovisioning

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: Data Lake Store

#### Description

Azure Data Lake Storage Gen2 evaluates access using a combination of Azure RBAC (Storage Blob Data Reader/Contributor/Owner) and POSIX-style ACLs on filesystem entries. Access granted via either layer is sufficient. Removing a user from a Storage RBAC role does not remove ACL entries, and vice versa - ACL entries can persist on individual files and directories after the user's RBAC is revoked. Designs that rely on RBAC removal for deprovisioning may leave granular ACL grants intact.

#### Possible mitigations

Define the access model up-front: prefer RBAC for service-level and broad access and ACLs for fine-grained data-set access. Document the combined model and ensure deprovisioning workflows remove both. Audit ACL entries on directories and files for principals no longer in the tenant. Avoid scattering ACLs across many files; group at directory level where possible.

#### Steps

For each ADLS Gen2 account, document the access model (RBAC, ACLs, or combined). Audit ACL entries against current tenant principals and confirm the deprovisioning workflow removes both.

**Documentation:** <https://learn.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-access-control-model>

---

### `TH313` — Notebook results, query history, and cluster logs in Synapse and Databricks may persist sensitive data outside the original data store's access controls

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Databricks, Azure Notebooks, Azure Synapse SQL OnDemand, Azure Synapse SQL Pool, Azure Synapse Spark Pools, Azure Synapse Workspace

#### Description

Synapse and Databricks notebooks render query results into the notebook artifact and may cache results to workspace-level storage, query history, or driver logs. Sensitive rows that the notebook author was authorized to see are then accessible to anyone with read on the notebook or workspace - including future workspace members - regardless of whether those people have permission on the underlying source. Cluster init scripts and event logs can also retain credentials passed at runtime.

#### Possible mitigations

Treat notebook artifacts and workspace storage at the same sensitivity classification as the source data. Do not co-locate notebooks with broadly-shared workspace permissions and queries against high-sensitivity sources. Avoid printing sensitive values to notebook output. Audit notebook sharing, query history retention, and cluster log destinations.

#### Steps

For each workspace, identify notebooks containing sensitive query output and confirm workspace permissions match the data classification.

**Documentation:** <https://learn.microsoft.com/en-us/azure/databricks/security/>

---

### `TH314` — Azure Backup vaults grant restore operations the ability to write data to alternative locations, providing an indirect read path for backed-up content

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Backup

#### Description

Azure Backup stores recovery points in Recovery Services or Backup Vaults. A user with Backup Operator or higher on the vault can typically restore items - to alternative locations or original locations - and thereby read the contents of the backed-up resource without holding direct read on the source. Restore to alternative storage accounts or VMs is a common pattern for disaster recovery testing, but it can also be a route around the source's access controls.

#### Possible mitigations

Restrict vault Restore operations to a small named set distinct from the source resource's operators. Where required, separate Backup Reader, Backup Operator, and Backup Contributor roles per vault. Audit restore events and treat restore-to-alternative as a security signal. Apply immutability and soft-delete on vaults to defend against destructive restoration as well.

#### Steps

For each Backup vault, document the principals with restore rights and confirm separation from source-resource operators. Audit restore events.

**Documentation:** <https://learn.microsoft.com/en-us/azure/backup/backup-rbac-rs-vault>

---

### `TH315` — Microsoft Sentinel and Log Analytics workspaces aggregate telemetry from across the tenant; broad workspace reader rights expose security events, identity activity, and application data centrally

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Log Analytics, Microsoft Sentinel, Monitor

#### Description

A Sentinel or Log Analytics workspace is the central destination for sign-in logs, audit logs, application telemetry, and resource diagnostics from across the tenant. Granting Log Analytics Reader on the workspace allows the principal to query every table in the workspace, including SigninLogs (PII, sign-in IP and device), AuditLogs (privilege grants, config changes), and any custom application logs. The workspace becomes a centralized discovery surface that may exceed the access any consumer holds at the source.

#### Possible mitigations

Apply table-level RBAC (resource-context or table-context) so that consumers see only the subset of tables required for their role. Separate workspaces by sensitivity or business function rather than concentrating everything in one. Consider Customer-Managed Keys for the workspace storage. Audit workspace reader grants and treat additions as security-impacting changes.

#### Steps

For each Log Analytics / Sentinel workspace, document the data sources ingested, the table set, and the principals with read access. Confirm scope is appropriate.

**Documentation:** <https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access>

---

### `TH319` — Azure Network Security Group rules with overly broad source/destination/port specifications create lateral movement paths between workloads that should be isolated

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Virtual Network

#### Description

NSG rules using Any source, Any destination, or wide port ranges are simple to author and common in 'just make it work' troubleshooting. Once in place, they typically remain - creating permanent open paths between subnets, resources, or to the internet that the design did not intend. An attacker who reaches one resource on a subnet protected by an any-any NSG can scan and reach every other resource on that subnet, regardless of host-level controls.

#### Possible mitigations

Author NSG rules with explicit source service tags or address prefixes, explicit destination prefixes or service tags, and minimum port ranges. Use Application Security Groups to express intent (group of web servers, group of app servers) rather than IP prefixes. Periodically audit NSG rules for any-any patterns and remove troubleshooting rules. Apply Azure Policy to flag or deny over-broad rules at deployment.

#### Steps

Audit each NSG for any-any or wide-range rules. Document the justification for each broad rule and convert to scoped rules where possible.

**Documentation:** <https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works>

---

### `TH321` — VNet peering, VPN, ExpressRoute, or service endpoints may extend network reachability across trust boundaries, exposing services to a wider population than intended

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: Virtual Network

#### Description

Azure VNet peerings, hub-and-spoke topologies, VPN gateways, and ExpressRoute create transitive network reachability between VNets and on-premises networks. Service endpoints and Private Endpoints further widen the set of clients that can reach a PaaS resource. A newly-added peering, a misconfigured route table, or a service endpoint added to an unrelated subnet can silently expose a database, storage account, or Key Vault to workloads in a different trust domain - particularly in environments where one team manages networking and another manages workloads.

#### Possible mitigations

Govern peering, VPN, and ExpressRoute changes through change control involving the owners of the resources reachable through the network. Document the intended reach of each PaaS resource (which subnets and service endpoints are permitted) and use Azure Policy to prevent additions outside that set. Audit peering topologies for transitive reachability across trust domains.

#### Steps

Diagram VNet topology including peerings, VPN/ER, and service/private endpoints. For each PaaS resource with selected-network firewall rules, confirm the reachable client set is intended.

**Documentation:** <https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview>

---

### `TH322` — Geo-replication features (Azure SQL geo-replicas, RA-GRS storage, Cosmos multi-region writes) may replicate data into a paired region inconsistent with residency requirements

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure SQL Database Managed Instance, Azure Storage, CosmosDB

#### Description

Several Azure data services replicate data to a paired region for redundancy: read-access geo-redundant storage (RA-GRS) replicates blobs, Azure SQL Database geo-replication replicates database state, Cosmos DB multi-region writes propagate to additional regions. A workspace owner who enables these features may not realize the paired region's geographic location, which may differ from the data's regulatory home (e.g., GDPR-protected data residing in West Europe with paired North Europe is acceptable, but enabling cross-geo replication or selecting a non-EEA region as a secondary breaches residency).

#### Possible mitigations

Document data residency requirements per data class and per resource. Choose primary and paired regions that satisfy residency at design time. Disable geo-redundant features for workloads where the paired region is not compliant. Apply Azure Policy to constrain permitted regions per management group or subscription.

#### Steps

List data resources with geo-replication enabled, the primary and paired regions, and the data's residency requirement. Confirm each pair is compliant.

**Documentation:** <https://learn.microsoft.com/en-us/azure/availability-zones/cross-region-replication-azure>

---

### `TH323` — Microsoft 365 (SharePoint, OneDrive, Teams) sharing defaults may permit anyone-with-link or external user access without explicit per-document review

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft 365

#### Description

Microsoft 365 sharing settings determine the default link type when users share documents and the audience permitted (only people in your organization, specific people, anyone with the link). When tenant or site defaults allow 'anyone with link' and external sharing, users can share documents to any audience with no per-document approval. Documents containing customer data, internal proposals, or unreleased plans can be shared outside the organization with one click, leaving an audit trail that is rarely reviewed in real time.

#### Possible mitigations

Set default link types to 'specific people' at tenant and site level. Restrict 'anyone with link' to specific sites where it is required. For sites containing sensitive content, enable Sensitivity Labels with auto-labeling and conditional sharing restrictions. Audit external sharing events through Microsoft Purview audit. Train content owners on the implications of each link type.

#### Steps

Document tenant and site sharing defaults. Identify sites containing sensitive content and confirm sharing settings reflect the data classification. Define the audit/review process for external sharing events.

**Documentation:** <https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview>

---

### `TH325` — OAuth consent grants from Microsoft Entra users to SaaS applications (Salesforce, Box, third-party connectors) persist beyond user offboarding and may not be reviewed

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Box Storage, Microsoft 365, Power Automate, Power BI Platform, Salesforce

#### Description

When a user grants OAuth consent to a SaaS application or third-party connector to access their Microsoft Entra-protected data, the grant typically persists until explicitly revoked. Standard offboarding (disable user, remove licenses) does not necessarily invalidate the OAuth tokens already issued or the standing grant. A SaaS application that polled the user's mail, calendar, or files continues to do so until the application itself is reviewed or the tenant revokes consent.

#### Possible mitigations

Govern third-party application consent at tenant level: restrict user consent to verified publishers and low-risk permissions, requiring admin consent for higher-risk scopes. Maintain an inventory of consented applications and their permissions. Include OAuth consent revocation in the offboarding workflow. Periodically review tenant-wide application grants and disable unused or unrecognized applications.

#### Steps

List the third-party applications with tenant or user consent and the permissions held. Define the consent governance policy and the offboarding step that revokes user grants.

**Documentation:** <https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent>

---

### `TH332` — Workloads in an AWS VPC that allow IMDSv1 metadata access expose EC2 instance role credentials to SSRF attacks

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Data

#### Description

EC2 instances expose credentials for their attached IAM role through the Instance Metadata Service (IMDS) on the link-local address 169.254.169.254. IMDSv1 responds to any HTTP GET from the instance, making it trivially reachable through an SSRF vulnerability in any application running on the instance: a single SSRF can exfiltrate the instance role's credentials. IMDSv2 mitigates this by requiring a session token obtained via PUT, which most SSRF vectors cannot perform.

#### Possible mitigations

Configure all EC2 instances and Auto Scaling groups to require IMDSv2 (HttpTokens=required) and to enforce a hop limit of 1 (HttpPutResponseHopLimit=1) so containers cannot reach IMDS through the host. Apply this at AMI/launch-template level. Use Service Control Policies or AWS Config rules to deny instances that allow IMDSv1. Combine with least-privilege instance roles so that even compromised credentials have minimum reach.

#### Steps

Audit launch templates and existing instances for IMDSv2 enforcement. Confirm hop limit is 1 for hosts running containers. Apply Config rules to detect and remediate IMDSv1 hosts.

**Documentation:** <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>

---

### `TH333` — AWS AMIs, EBS snapshots, RDS snapshots, and DocumentDB cluster snapshots may be shared publicly through a single misconfigured permission setting

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Aurora, AWS DocumentDB, AWS RDS, AWS Storage

#### Description

AMIs, EBS snapshots, RDS snapshots, and DocumentDB snapshots all expose a 'public' sharing option that makes the artifact accessible to every AWS account globally. A snapshot of a production database made public — through a misclick, a CLI flag in the wrong place, or a misapplied policy — exposes the entire dataset to anyone who can enumerate snapshots in that region. Discovery is straightforward; the AWS Marketplace and snapshot-search tools regularly index public snapshots.

#### Possible mitigations

Apply AWS Config rules and Service Control Policies to prevent public sharing of snapshots and AMIs (e.g., ec2:ModifySnapshotAttribute restricted to internal scope, rds:ModifyDBSnapshotAttribute restricted from setting public). Enable the EBS, RDS, and DocumentDB block-public-sharing settings at account level. Audit existing snapshots and AMIs for public sharing on a defined cadence.

#### Steps

List shareable artifacts (AMIs, EBS snapshots, RDS snapshots, DocumentDB snapshots) and the account-level block-public settings. Confirm SCPs prevent public-sharing actions on production accounts.

**Documentation:** <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html>

---

### `TH334` — An AWS S3 bucket without S3 Block Public Access enabled may be made publicly readable through bucket policy, ACL, or website configuration

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Storage

#### Description

S3 bucket access is governed by bucket policies, bucket ACLs, object ACLs, and Block Public Access settings — any of which can independently grant public read or write. Without Block Public Access enabled at the account or bucket level, a single misconfigured bucket policy ('Principal: *') or a legacy ACL set to public-read makes objects globally readable or even writable. Public S3 buckets are routinely enumerated by attackers using wordlist-based bucket-name guessing.

#### Possible mitigations

Enable S3 Block Public Access at the AWS account level so it overrides per-bucket configuration. Where a bucket genuinely requires public access (static website hosting), scope the public access narrowly and serve through CloudFront with Origin Access Control rather than direct S3 public read. Enable bucket policies that deny non-TLS access. Audit buckets via S3 Access Analyzer.

#### Steps

List buckets in scope, their Block Public Access state, and any policy/ACL grants to AllUsers or AuthenticatedUsers. Confirm account-level Block Public Access is enabled and exceptions are explicitly justified.

**Documentation:** <https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html>

---

### `TH335` — AWS S3 presigned URLs grant time-bounded but unauthenticated access to the underlying object, and may persist beyond the recipient's intended use

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Storage

#### Description

Presigned S3 URLs encode the IAM credentials of the signer, the object key, the operation (GET, PUT), and an expiration time into a URL that anyone holding it can use without further authentication. Long-expiry presigned URLs (hours or days) leaked via referrer headers, browser history, email forwarding, or screenshot become standing object access for any holder. A presigned PUT URL allows uploading arbitrary content under the bucket, potentially overwriting existing objects.

#### Possible mitigations

Use the shortest viable expiration on presigned URLs (minutes, not hours) and re-issue on demand rather than reusing. Generate presigned URLs from a back-end service that authenticates the requester each time. Sign with credentials of a least-privilege role scoped to the specific object. For browser-direct upload scenarios, use S3 PostObject form-based uploads with conditions on key, size, and Content-Type.

#### Steps

Document each surface that issues presigned URLs, the expiration policy, the signing role, and the operations allowed. Confirm expiry is minimal and that signing roles are scoped to the specific object pattern.

**Documentation:** <https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html>

---

### `TH337` — AWS S3 server-side encryption choice determines the access boundary for decryption; SSE-S3 alone does not protect against an attacker with bucket read

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Storage

#### Description

S3 supports SSE-S3 (S3-managed keys), SSE-KMS (KMS customer-managed keys), and SSE-C (customer-supplied keys). With SSE-S3, S3 transparently decrypts on read for any caller with s3:GetObject — encryption protects against physical disk theft but not against IAM compromise. SSE-KMS adds a separate KMS key policy that the caller must satisfy in addition to the S3 policy, providing a true second access boundary. Designs that use SSE-S3 for sensitive data assume protection that the encryption mode does not provide.

#### Possible mitigations

For sensitive data, use SSE-KMS with a customer-managed KMS key whose key policy is scoped to the specific principals and contexts that should decrypt. Use S3 Bucket Keys to reduce KMS request cost. Apply 'aws:SourceVpc' or 'kms:ViaService' conditions on the KMS key policy to prevent decryption from unexpected contexts. Document the encryption choice per bucket against the data classification.

#### Steps

For each bucket, document the encryption mode, the KMS key (if applicable), and the key policy. Confirm sensitive data uses SSE-KMS with a scoped key policy.

**Documentation:** <https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html>

---

### `TH338` — AWS RDS and Aurora master user credentials grant superuser access to the database engine and may be reused or stored insecurely across applications

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Aurora, AWS RDS

#### Description

AWS RDS and Aurora are provisioned with a master user that holds engine-level superuser privileges (rds_superuser on PostgreSQL, the master user with ALL on MySQL). The credential is set at instance creation and is commonly stored in application configuration, Secrets Manager, or operations playbooks. Shared use across applications, infrequent rotation, or storage in CloudFormation parameters/templates expose this credential and give the holder full database control including the ability to grant access to others, alter audit settings, or extract the entire dataset.

#### Possible mitigations

Use IAM database authentication for application access where the engine supports it, so credentials are short-lived tokens issued per-call. Reserve the master credential for break-glass admin and store it in Secrets Manager with automatic rotation. Create least-privileged engine-level users for each application. Audit master credential access events.

#### Steps

For each RDS / Aurora instance, document who can read the master credential, where it is stored, the rotation policy, and whether IAM database auth is used for application access.

**Documentation:** <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html>

---

### `TH340` — Aurora cluster snapshots may be shared with other AWS accounts or made public, transferring ownership of the entire dataset

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Aurora, AWS RDS

#### Description

Aurora cluster snapshots can be shared with specific AWS accounts (for cross-account restore) or made public. A shared snapshot can be restored in the target account with no further coordination, after which the recipient account holds a complete copy of the data and the database admin permissions on the restored cluster. Accidentally setting 'public', or sharing with an over-broad set of accounts during DR testing, exposes the data permanently.

#### Possible mitigations

Restrict the principals authorized to share snapshots; require approval for cross-account snapshot sharing. Apply SCPs that deny rds:ModifyDBClusterSnapshotAttribute with a value of 'all' (public). Maintain a mapping of approved cross-account snapshot recipients per cluster. Audit snapshot sharing changes as security events.

#### Steps

List Aurora clusters and their snapshot sharing configuration. Document approved cross-account recipients and confirm SCP coverage prevents public sharing.

**Documentation:** <https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_ShareSnapshot.html>

---

### `TH341` — AWS DynamoDB tables without fine-grained IAM conditions grant access to every item; per-tenant or per-user isolation requires explicit condition keys

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS DynamoDB

#### Description

DynamoDB IAM permits operations like GetItem, Query, and Scan at table granularity by default. Designs that store multi-tenant data in a single table — using a tenant-id partition key — but grant a role 'dynamodb:Query on TableArn' allow that role to query any tenant's data. Per-tenant isolation requires the dynamodb:LeadingKeys condition (restricting access to specific partition-key values) and dynamodb:Attributes condition (restricting which attributes can be read or projected).

#### Possible mitigations

Use IAM condition keys to enforce per-tenant or per-user data isolation: dynamodb:LeadingKeys for partition-key scoping, dynamodb:Attributes for attribute-level scoping, dynamodb:Select for query result limits. Combine with attribute-based access control where the principal's tag matches the partition key. Audit IAM policies on DynamoDB tables for missing condition keys on multi-tenant tables.

#### Steps

For each multi-tenant DynamoDB table, document the partition-key tenancy model and confirm IAM policies use LeadingKeys / Attributes conditions to enforce it.

**Documentation:** <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html>

---

### `TH342` — DynamoDB Streams expose item-level change history to consumers, potentially with broader access than the source table grants

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS DynamoDB

#### Description

DynamoDB Streams capture every item-level change (NEW_IMAGE, OLD_IMAGE, KEYS_ONLY, NEW_AND_OLD_IMAGES) and make them available to downstream consumers (Lambda, Kinesis Firehose, etc.). Stream consumers authorize against the stream ARN, which is separate from the table ARN — a Lambda function with stream read access can read every item change including data the function would not be permitted to read directly. Stream data may also fan out to less-protected destinations through the consumer.

#### Possible mitigations

Configure stream view types to expose only the data downstream consumers actually need (KEYS_ONLY rather than NEW_AND_OLD_IMAGES where full payload is not required). Apply least-privilege on stream-read IAM, equivalent in scope to table-read. Govern downstream destinations of stream data as data-flow events with classification matching the source table. Disable streams on tables where the data is not consumed downstream.

#### Steps

For each DynamoDB table with streams enabled, document the view type, the stream consumers, the consumer's downstream destinations, and the classification of the data. Confirm exposure does not exceed source table access.

**Documentation:** <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html>

---

### `TH343` — AWS DocumentDB authentication is collection-coarse; multi-tenant data co-located in shared collections relies on application-tier filtering

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS DocumentDB

#### Description

DocumentDB grants permissions at database and collection scope through engine-level roles. Unlike some MongoDB-compatible offerings, it does not natively support per-document or row-level security — designs that store multi-tenant data in a shared collection rely on application-tier filters (e.g., always include in the query) to enforce isolation. Application bugs, misuse of admin connections, or a compromised database credential bypass the entire tenancy model.

#### Possible mitigations

Where strong tenant isolation is required, use one collection per tenant or one cluster per tenant rather than co-locating multi-tenant data. For application-tier filtering designs, treat the database credential as having effective access to all tenants and scope its use accordingly. Audit application code for the presence of the tenant filter on every query path. Use IAM authentication where available to scope per-application access.

#### Steps

For each DocumentDB cluster, document the tenancy model (collection per tenant vs shared) and the access controls. Confirm application-tier filtering covers every query path or tenancy is enforced at storage level.

**Documentation:** <https://docs.aws.amazon.com/documentdb/latest/developerguide/security.html>

---

### `TH344` — AWS Neptune graph queries can traverse relationships to reach data the calling identity has no direct authorization to read

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Neptune

#### Description

Neptune permissions are granted at graph (database) granularity rather than per-vertex or per-edge. A caller authorized to query the graph can issue Gremlin, openCypher, or SPARQL traversals that follow relationships across business domains — for example, traversing from a customer record to associated employee records, transactions, or audit events that would not be readable through more targeted query interfaces. The graph becomes a join surface aggregating exposure across the underlying relationships.

#### Possible mitigations

Where multiple sensitivity tiers must coexist in graph form, use separate Neptune instances per tier rather than one combined graph. For a shared graph, restrict the callers permitted to issue ad-hoc queries; expose only specific stored queries through a facade service that filters the result. Apply IAM authentication and audit query patterns for unusual traversals.

#### Steps

For each Neptune graph, document the data domains it joins, the principals authorized to query, and the query interface (direct vs facade). Confirm the join surface matches the consumer authorization model.

**Documentation:** <https://docs.aws.amazon.com/neptune/latest/userguide/security.html>

---

### `TH349` — Snowflake on AWS uses a separate role and authentication system from AWS IAM, with the ACCOUNTADMIN role granting unrestricted account-wide privilege

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Snowflake in AWS

#### Description

Snowflake authenticates and authorizes users through its own role hierarchy (ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, custom roles) — separate from AWS IAM. The ACCOUNTADMIN role grants full control over the Snowflake account: every database, warehouse, share, and security policy. Lifecycle management at the AWS level (deprovisioning the IAM user, removing the federated identity) does not automatically remove Snowflake-level access if the user authenticates with a Snowflake-native password or holds a separate key-pair authentication.

#### Possible mitigations

Restrict ACCOUNTADMIN to a small named set with break-glass procedures, not standing membership. Federate Snowflake authentication to the corporate identity provider so that lifecycle changes propagate. Use SCIM provisioning where supported. Audit Snowflake account-level role grants on the same cadence as AWS IAM. Disable Snowflake-native passwords for human users where federation is in place.

#### Steps

For the Snowflake account, document the ACCOUNTADMIN holders, the authentication methods enabled, the federation configuration, and the deprovisioning workflow. Confirm Snowflake access is removed in step with AWS IAM.

**Documentation:** <https://docs.snowflake.com/en/user-guide/security-access-control-considerations>

---

### `TH350` — Snowflake on AWS data sharing features can share databases or tables with external Snowflake accounts, creating data flows that bypass AWS-side network and IAM controls

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Snowflake in AWS

#### Description

Snowflake supports Secure Data Sharing, which makes databases or tables in one Snowflake account readable by named consumer accounts without copying the data. The shared data is read by the consumer's Snowflake compute, with no AWS-side network egress visible from the producer account's CloudTrail or VPC flow logs. A producer-side admin can therefore share data outside the organization through Snowflake without traversing any AWS-tier control point, and the share remains active until explicitly revoked.

#### Possible mitigations

Restrict the right to create or modify shares to a small named set distinct from ACCOUNTADMIN. Maintain an inventory of active shares with their consumer accounts and approval records. Apply Snowflake network policies to constrain consumer connections where supported. Audit share creation and modification events as security-impacting changes.

#### Steps

List active shares from the Snowflake account, the consumer accounts, the data shared, and the approval records. Confirm consumer accounts and data scope are appropriate.

**Documentation:** <https://docs.snowflake.com/en/user-guide/data-sharing-intro>

---

### `TH351` — AWS VPC security groups with 0.0.0.0/0 ingress on management or database ports expose those services to the entire internet

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Data

#### Description

Security groups are stateful firewalls attached to ENIs that permit inbound and outbound traffic by source/destination CIDR or security-group reference. Rules with source 0.0.0.0/0 (or ::/0) on management ports (22 SSH, 3389 RDP, 5985 WinRM) or database ports (5432 Postgres, 3306 MySQL, 1433 MSSQL, 27017 MongoDB) expose those services to the internet. Internet scans regularly enumerate such exposures and attempt credential stuffing or known-CVE exploitation.

#### Possible mitigations

Restrict inbound rules to specific source CIDRs (corporate ranges, VPN, Bastion subnet) or to security-group references. Use Systems Manager Session Manager for instance access instead of SSH/RDP through internet-exposed ports. Apply AWS Config managed rules (restricted-ssh, restricted-common-ports) and SCPs that deny rule changes opening these ports. Audit existing security groups on a defined cadence.

#### Steps

List security groups in scope and any rules with 0.0.0.0/0 or ::/0 source on management or database ports. Confirm exceptions are explicit and time-bounded.

**Documentation:** <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html>

---

### `TH352` — AWS VPC endpoints without endpoint policies allow workloads in the VPC to reach AWS services in any account, including attacker-controlled accounts

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS DynamoDB, AWS Storage

#### Description

VPC endpoints (Gateway endpoints for S3/DynamoDB, Interface endpoints for other services) enable VPC-private access to AWS services. By default, endpoints have no resource policy constraining which AWS resources can be reached through them. A workload in the VPC can therefore use the endpoint to put objects to an attacker's S3 bucket, write to an attacker's DynamoDB table, or invoke services in a foreign account — appearing to internal monitoring as legitimate AWS API traffic over a VPC-private path.

#### Possible mitigations

Apply VPC endpoint policies that restrict accessible resources to specific AWS account IDs or specific resource ARNs (e.g., 'aws:ResourceAccount' = your-account-id condition). Combine with SCPs that constrain the accounts and resources principals can interact with. Use VPC flow logs and CloudTrail data events on key buckets to surface unexpected external destinations.

#### Steps

List VPC endpoints in scope, their endpoint policies (if any), and the cross-account destinations reachable. Apply endpoint policies and SCPs that restrict to in-scope accounts.

**Documentation:** <https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html>

---

### `TH353` — AWS VPC peering and Transit Gateway routing extend network reachability in ways that may bypass intended trust boundaries between VPCs and accounts

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: AWS Data

#### Description

VPC peering connections are non-transitive but pairwise routable; Transit Gateway hubs centralize routing across many VPCs and on-premises connections. Adding a new peering or TGW attachment, or modifying a route table to advertise wider CIDRs, can silently extend reachability between VPCs that were intended to be isolated. Cross-account peerings or TGW shares broaden the change-control surface to multiple account owners.

#### Possible mitigations

Govern VPC peering and TGW route changes through change control involving the owners of the affected VPCs. Use Resource Access Manager (RAM) sharing audit to track cross-account TGW shares. Apply Network ACLs and security groups as defense in depth at the subnet boundary even within a TGW. Audit TGW route tables and peering connections on a defined cadence.

#### Steps

Diagram VPC peering and TGW topology including cross-account attachments. For each transit path, confirm both endpoints' owners agree the path is intended.

**Documentation:** <https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html>

---

### `TH356` — A SaaS application not federated to the corporate identity provider may retain local user accounts that survive workforce offboarding

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ADP, Adobe, Aero, Box Storage, Cloud SaaS Services, Expensify, Jira, Microsoft 365, Monday, Notion, Postmark, Power Automate, Power BI Platform, Salesforce, Slack, Trello, Workday, Zoom

#### Description

SaaS applications support local username/password accounts in addition to (or instead of) SAML/OIDC federation with the corporate identity provider. When users authenticate locally rather than through SSO, deactivating their corporate Microsoft Entra (or other IdP) account does not remove their SaaS access. Long after offboarding, the local SaaS account remains active with whatever data and permissions it accumulated. Designs that assume IdP deactivation propagates to SaaS access do not account for this.

#### Possible mitigations

Federate every SaaS application to the corporate IdP via SAML 2.0 or OIDC. Disable local account creation where the SaaS supports it, or restrict local accounts to a small named break-glass set. Enable SCIM provisioning so user lifecycle (create, update, deactivate) flows from the IdP into the SaaS. Audit the SaaS user list against the IdP on a defined cadence to surface orphan accounts.

#### Steps

List each SaaS application in scope. Document whether SSO/SCIM are enabled, whether local accounts are permitted, and the offboarding workflow that removes SaaS access.

**Documentation:** <https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/plan-sso-deployment>

---

### `TH357` — SaaS application marketplaces enable end-user installation of third-party integrations that obtain OAuth grants to read or modify data with little oversight

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Adobe, Box Storage, Jira, Microsoft 365, Monday, Notion, Salesforce, Slack, Trello, Zoom

#### Description

Most SaaS platforms (Slack, Salesforce, Jira, Microsoft 365, Notion, Box, Zoom) offer integration marketplaces where end users install third-party apps that, on installation, obtain OAuth tokens granting them programmatic access to the user's or workspace's content. Without admin governance, end users can install apps from unknown publishers granting read of channels, files, tickets, contacts, calendar, or messages. The third party then holds ongoing programmatic access to that data, surviving the user's offboarding unless the grant is explicitly revoked.

#### Possible mitigations

Restrict third-party app installation to admin-approved apps in each SaaS. Maintain a vetted allowlist of approved publishers and integrations. Require admin consent for OAuth scopes that access organization-wide data. Periodically audit installed apps and revoke unused or unverified ones. Include OAuth grant revocation in user offboarding workflows.

#### Steps

List the SaaS marketplaces in scope and the admin policy for third-party app installation. Inventory active integrations, their scopes, and the publisher review.

**Documentation:** <https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent>

---

### `TH358` — SaaS audit logs may remain in each vendor's portal with limited retention and no central correlation, making cross-SaaS investigation impossible

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ADP, Adobe, Aero, Box Storage, Dynamics CRM, Expensify, Jira, Microsoft 365, Monday, Notion, Postmark, Power Automate, Power BI Platform, Salesforce, Slack, Trello, Workday, Zoom

#### Description

Each SaaS application maintains its own audit log of user activity, sharing events, permission changes, and admin actions. Defaults vary widely: some retain logs for 30-90 days only on lower tiers; many provide no programmatic export without enterprise tier; log fields are inconsistent across vendors. Without central export to a SIEM, investigations of cross-SaaS attacks (a compromised account that pivots between Slack, Salesforce, and Box) cannot correlate events, and retrospective analysis is bounded by the shortest vendor retention.

#### Possible mitigations

Configure each SaaS to forward audit logs to the central SIEM via API export, log streaming connector, or Microsoft Sentinel data connectors where available. Verify retention in the SIEM meets the longest applicable compliance requirement. Define cross-SaaS detection rules for indicators that span vendors (e.g., new third-party app install + bulk file download + new sharing rule).

#### Steps

Inventory the SaaS applications in scope and the audit log destinations. Document retention policy at the SaaS and at the SIEM. Confirm cross-SaaS correlation queries are in place.

**Documentation:** <https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference>

---

### `TH360` — Work management and productivity SaaS often allow end users to publish boards, pages, or tickets via public link without authentication

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Aero, Jira, Monday, Notion, Trello

#### Description

Productivity and work-management platforms (Jira, Monday, Trello, Notion, Aero) commonly expose 'share publicly via link' or 'publish to web' features that make a board, page, or ticket readable by anyone holding the URL — no authentication required, and often discoverable via search engine indexing. End users enable these features for legitimate external collaboration, but the same control becomes an exfiltration channel for sensitive content (customer names, internal project plans, credentials in ticket descriptions, secrets pasted into comments).

#### Possible mitigations

Restrict public-link sharing at the workspace or tenant level, with an explicit allowlist of items permitted to be made public. Block search-engine indexing on any public links that remain. Audit existing public links periodically and ask owners to confirm or revoke. For tenants handling regulated content, disable public sharing entirely and use email-restricted external sharing instead.

#### Steps

Document the public-link-sharing policy per platform in scope. Identify existing public items and confirm content classification matches the public audience.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-04/>

---

### `TH361` — End users may paste credentials, tokens, or sensitive customer data into work management items, persisting secrets in the SaaS audit history

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Aero, Jira, Microsoft 365, Monday, Notion, Slack, Trello, Zoom

#### Description

Tickets, cards, comments, and wiki pages in work-management and productivity SaaS are a frequent destination for ad-hoc collaboration content: credentials shared between teammates to debug an outage, API keys pasted into a ticket reproducer, customer PII included in a support escalation. Once pasted, the content persists in the item's revision history, in full-text search, in attachment thumbnails, and in audit log exports — often surviving edits or deletions that the user assumes have removed it. The blast radius extends to every current and future workspace member with read on the item.

#### Possible mitigations

Configure DLP scanning for known secret patterns (API keys, JWTs, connection strings) on tickets, comments, and attachments where the SaaS supports it. Train users to use the approved secrets manager rather than paste credentials. For platforms supporting it, configure secret-scanning hooks that quarantine items containing detected secrets. Periodically purge revision history on items known to have contained secrets.

#### Steps

Identify the SaaS items most likely to receive secrets (incident tickets, support escalations, runbook pages). Configure DLP scanning and document the response process for detected secrets.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-02/>

---

### `TH362` — Adding external guests to SaaS work management workspaces may grant broader visibility than the inviting user expected

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Aero, Box Storage, Jira, Microsoft 365, Monday, Notion, Slack, Trello

#### Description

Inviting an external guest to a Jira project, Monday board, Notion workspace, or Trello board frequently grants the guest visibility to more than the specific item they were invited to: cross-references, linked tickets, mentions in unrelated discussions, and search results often surface other workspace content to a guest who has 'access to one thing.' The inviter's mental model of 'I shared one ticket with this contractor' may not match what the guest can actually see.

#### Possible mitigations

Use guest-restricted workspaces or projects for external collaboration rather than inviting guests into mixed-content workspaces. Where the SaaS supports per-item guest permissions, scope strictly. Audit guest membership and review on a defined cadence; automatically deprovision guests after a period of inactivity. Train inviters on the guest visibility model of each platform.

#### Steps

List the SaaS workspaces with external guest members. Document the guest visibility model and confirm workspaces with guests do not contain unrelated sensitive content.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/iam/iam-09/>

---

### `TH363` — Slack message retention defaults retain channel and DM history indefinitely, accumulating sensitive content discussed years prior

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Slack

#### Description

Slack workspace defaults retain messages and files forever unless a message-retention policy is configured. Years of channel discussions accumulate: incident postmortems containing internal IPs and credentials, sensitive customer issues, off-record HR conversations, OAuth tokens posted in DMs to debug integrations. A workspace breach or a compromised admin account exfiltrates all of it; legal discovery may be required to produce it. The retention is a liability asset that grows by default.

#### Possible mitigations

Define a message and file retention policy aligned to legal-hold and business needs (e.g., 90-day rolling for general channels, 1 year for compliance-relevant). Apply per-channel policies for channels with regulatory or HR content. Use Slack Enterprise Grid retention controls where the tenant supports it. Train users that DMs and channels are auditable and retained, and offer the secrets manager as the right place for credential exchange.

#### Steps

Document the current retention policy. Identify channels containing regulated content and apply per-channel retention as needed. Communicate the policy to users.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-01/>

---

### `TH365` — Zoom cloud recordings, transcripts, and chat logs may be stored with weak access controls and shared via link, exposing meeting content beyond the original participants

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Zoom

#### Description

Zoom cloud recordings include video, audio, transcript, and in-meeting chat. Recording share settings default in many tenants to 'anyone with the link' or 'organization-wide,' and shared links rarely expire. Sensitive meetings — board discussions, customer-data deep dives, HR conversations, terminations — can therefore be reachable by the entire tenant or the public internet long after the meeting. Transcripts include the raw spoken content, which may be discoverable via SIEM/eDiscovery in ways the participants did not anticipate.

#### Possible mitigations

Set tenant-default recording sharing to 'specific people' with expiration. Require passwords on shared recording links. Define a retention policy aligned to legal/business needs and apply automated deletion. Disable cloud recording for meeting types where the discussion is not appropriate to retain. Restrict who can record by default; require explicit consent display in the meeting UI.

#### Steps

Document the cloud-recording defaults, retention policy, and sharing controls. Identify meeting types subject to higher restriction and apply per-account or per-template settings.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-04/>

---

### `TH367` — HR and payroll SaaS hold compensation, tax identifiers, banking, and medical data that warrant stricter controls than general-purpose SaaS

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ADP, Expensify, Workday

#### Description

Workday, ADP, and similar HR/payroll platforms store compensation, social security / tax identifiers, banking details for direct deposit, dependents' personal data, and in some cases medical or disability data. The data classification is uniformly high — typically the most sensitive PII in the organization. Designs that treat HR SaaS with the same controls as work-management or productivity tools (broad admin pools, casual integration approval, lax password policies on local accounts) under-protect the highest-risk data the organization holds.

#### Possible mitigations

Apply stricter controls to HR/payroll SaaS than to general-purpose SaaS: smaller admin set, mandatory MFA on all access (no exceptions), restricted IP ranges, no public-link or external-share features, mandatory SSO with no local accounts, narrowest possible third-party integration allowlist. Audit access logs daily for unusual export, bulk read, or admin actions. Treat any policy exception as security-impacting.

#### Steps

Document the access controls applied to each HR/payroll SaaS. Confirm they are stricter than the general SaaS baseline and align with the data sensitivity.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-02/>

---

### `TH369` — Postmark and similar transactional-email API tokens, if leaked, allow an attacker to send authenticated email from the organization's verified sending domains

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Postmark

#### Description

Transactional-email services (Postmark) issue per-server API tokens that authorize sending email from the configured verified domains. Unlike SMTP credentials, these tokens are frequently embedded in application configuration and CI/CD pipelines. A leaked token (committed to public repository, present in error logs, harvested from a compromised dev machine) lets the attacker send messages that pass SPF, DKIM, and DMARC checks — they appear to recipients as fully legitimate organization mail. This enables high-quality phishing of customers, partners, and employees.

#### Possible mitigations

Store transactional-email API tokens in a secrets manager and rotate on a defined cadence. Use server-scoped tokens (one server / token per application) so a leak's blast radius is bounded to one sending stream. Configure inbound IP restrictions where the platform supports it. Monitor sending volume and recipient anomalies; alert on unexpected destinations. Verify SPF/DKIM/DMARC are tightened to make off-platform sends fail.

#### Steps

List transactional-email tokens in use, where they are stored, the rotation cadence, the scope (server/account), and the monitoring on send anomalies.

**Documentation:** <https://postmarkapp.com/manual>

---

### `TH371` — Salesforce's combination of org-wide defaults, role hierarchy, sharing rules, and manual sharing creates a complex permission model where oversharing is common

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Targets: Salesforce

#### Description

Salesforce sharing is computed from multiple layers: org-wide defaults (OWD), role hierarchy (managers see subordinates' records by default), sharing rules (criteria-based or owner-based), manual sharing, account teams, and Apex sharing. The effective permission for a record is the union. Designs that depend on OWD=Private without auditing the other layers regularly find that role-hierarchy rollup, broad sharing rules, or unintended public groups grant access far beyond the OWD. The complexity makes ongoing governance hard.

#### Possible mitigations

Document the org-wide defaults per object alongside the active sharing rules, role hierarchy, public groups, and Apex sharing. Use the Salesforce Sharing Settings, Permission Set Group analyzer, and Field-Level Security analyzer to identify effective access. Audit sharing rule changes as security-impacting events. Train admins on the layered sharing model and require dual review of changes to OWD or sharing rules on sensitive objects.

#### Steps

For each Salesforce org, document the OWD per sensitive object and audit sharing rules, public groups, and role-hierarchy rollup. Confirm effective access matches intent.

**Documentation:** <https://help.salesforce.com/s/articleView?id=sf.security_sharing_overview.htm>

---

### `TH373` — Dynamics CRM Portal entity permissions are configured separately from internal CRM security, and may expose data to anonymous or low-trust portal users

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM Portal

#### Description

Dynamics CRM Portal (now Power Pages) exposes selected CRM entities to external users via a customer-facing web portal. Entity permissions for the portal are defined in a separate permission model — Entity Permissions, Web Roles, table permissions — distinct from the internal CRM's Business Units / Security Roles. Portals can grant 'global scope' read on entities, exposing all rows of a table to authenticated portal users (or even anonymous), regardless of the CRM-internal sharing model.

#### Possible mitigations

Treat the portal's permission model as a separate access boundary; review every Entity Permission and Web Role for scope (Global, Contact-scoped, Account-scoped, etc.). Default to Contact or Account scope rather than Global. Limit anonymous-user access to truly public information. Audit Web Role membership and Entity Permission changes as security-impacting events.

#### Steps

Document the Entity Permissions and Web Roles for each Power Pages site. Confirm scope is the minimum required and that anonymous-accessible content is genuinely public.

**Documentation:** <https://learn.microsoft.com/en-us/power-pages/security/assign-entity-permissions>

---

### `TH374` — Adobe Creative Cloud Libraries shared at organization scope expose design assets, brand materials, and embedded customer data to all CC users in the tenant

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Adobe

#### Description

Adobe Creative Cloud Libraries enable shared storage of design assets — colors, character styles, components, images, video clips. Libraries can be scoped to private, team, or organization-wide. Designers commonly share libraries broadly to enable collaboration; this exposes works-in-progress, unreleased product imagery, customer photography, and embedded layered files to every CC user in the tenant. PSDs and AI files frequently retain metadata (location, author, hidden layers) that surface customer or campaign details.

#### Possible mitigations

Default to team-scoped (project-team) libraries rather than organization-wide. For unreleased products or customer assets, use private libraries with explicit shares. Audit library scope on a defined cadence. Scrub metadata on assets before placing them in broader-scoped libraries. Restrict CC tenant membership to identities that should see the broadest scope.

#### Steps

List Creative Cloud Libraries shared at organization scope. Confirm content classification matches the audience.

**Documentation:** <https://helpx.adobe.com/enterprise/admin-guide.html>

---

### `TH376` — Box folders shared via 'anyone with link' setting expose contents to anyone holding the URL, with discovery via web crawl or shared screenshots

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Box Storage

#### Description

Box file-sharing supports several link types: 'people in your company,' 'people in this folder,' and 'anyone with link.' The last grants unauthenticated read to anyone who obtains the URL — through forwarded email, screenshots, browser history, search engine indexing, or referrer headers. Default link type is configurable at tenant or folder level; tenants that default to 'anyone with link' (or do not enforce a tighter default) make oversharing routine.

#### Possible mitigations

Set tenant default link type to 'people in your company.' For folders containing regulated content, restrict to 'people in this folder' or disable link sharing entirely. Configure shared link expiration and password requirements. Disable shared-link discoverability by search engines. Audit existing 'anyone with link' shares periodically.

#### Steps

Document the tenant link-sharing defaults and the per-folder overrides. Confirm regulated content is not in folders with 'anyone with link' enabled.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-04/>

---

### `TH377` — Power BI Publish to Web makes a report or dashboard accessible to anyone on the internet without authentication; the underlying dataset is queryable

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Power BI Platform

#### Description

Power BI's 'Publish to web' feature generates a public URL for embedding a report on a public website. The URL grants unauthenticated read of the report and, indirectly, the underlying dataset content (visuals can be queried by anyone who finds the URL). Reports intended for an internal audience may be inadvertently published by a content creator and indexed by search engines. The published content reflects the dataset at the time of publish, including any sensitive measures or columns the report shows.

#### Possible mitigations

Disable Publish to Web at tenant level for the entire organization, or scope it to a named security group with explicit business justification. Use Power BI Embedded with row-level security for legitimate external embedding scenarios. Audit existing Publish-to-web URLs and revoke any unjustified ones. Train report authors on the implications of the feature.

#### Steps

Document the tenant Publish-to-web setting and any active public URLs. Confirm each is justified and the underlying dataset contains only public-suitable content.

**Documentation:** <https://learn.microsoft.com/en-us/power-bi/admin/service-admin-portal-export-sharing>

---

### `TH378` — A Power Automate flow combining business and consumer connectors can bridge data classifications; without DLP policies, sensitive data flows out of the trust boundary

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Power Automate

#### Description

Power Automate flows combine connectors to multiple SaaS endpoints. Without tenant-level Data Loss Prevention (DLP) policies that classify connectors (business, non-business, blocked) and prevent flows from spanning the classification boundary, end users can build flows that read regulated data from a business connector (Microsoft 365 mail, SharePoint, Dynamics) and write to a consumer connector (personal Twitter, generic SMTP, personal Gmail). The flow becomes a sanctioned data-exfiltration channel.

#### Possible mitigations

Configure tenant-level DLP policies that classify connectors and block flows from spanning classifications. Define the business connector list narrowly and treat all others as non-business by default. Audit existing flows for connector combinations that violate DLP. Restrict premium connector access. Treat new connector approvals as security-impacting changes.

#### Steps

Document the DLP policies in place. Audit existing flows for cross-classification connector combinations. Confirm new connector approvals require security review.

**Documentation:** <https://learn.microsoft.com/en-us/power-platform/admin/wp-data-loss-prevention>

---

### `TH380` — SaaS data residency and sub-processor lists may move tenant data across geographic and regulatory boundaries that the tenant did not authorize

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ADP, Adobe, Aero, Box Storage, Cloud SaaS Services, Dynamics CRM, Expensify, Jira, Microsoft 365, Monday, Notion, Postmark, Power Automate, Power BI Platform, Salesforce, Slack, Trello, Workday, Zoom

#### Description

SaaS vendors commonly process tenant data across multiple regions and engage subprocessors (infrastructure providers, support contractors, analytics vendors) that may operate in different jurisdictions. Vendor terms typically grant the vendor the right to move data across regions for performance, redundancy, or support. For tenants subject to data residency obligations (GDPR EU/EEA, sectoral, sovereign-cloud requirements), the SaaS default may breach those obligations, and the breach is invisible without active review of the vendor's region selection and DPA terms.

#### Possible mitigations

Review each SaaS vendor's region options and select an in-region tier where available. Confirm Data Processing Agreement coverage including subprocessor restrictions. Document the data classes sent to each vendor and the residency requirement of each. Re-review on contract renewal and on vendor subprocessor list changes (most DPAs require the vendor to notify of subprocessor changes).

#### Steps

For each SaaS in scope, document the configured region, the subprocessor list, and the data classes sent. Confirm alignment with residency requirements.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/dsi/dsi-06/>

---

### `TH386` — An AI Agent's context window may aggregate data from multiple authorization scopes and disclose it across user turns 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent

#### Description

An AI Agent that retrieves grounding data from several sources (documents, databases, prior conversation, tool results) loads all of it into a single context window before producing output. The model has no enforcement boundary between the data it has read and the response it generates: information retrieved under one authorization scope can be paraphrased or surfaced verbatim in answers to a different question, including in answers shown to a different user if conversation state is reused or summarized.

#### Possible mitigations

Resolve every retrieval against the calling user's authorization at the time the data is fetched, not against the agent's broader service identity. Do not share long-lived context across users. When summarizing conversation history, re-evaluate whether the summarized data is still authorized for the current caller.

#### Steps

Trace the agent's retrieval paths. For each, confirm that authorization is evaluated under the calling user's identity, not the agent's. Confirm conversation memory is scoped per user and not pooled.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH392` — Apache Airflow Connections and Variables centralize credentials and secrets in a way that broadens blast radius on compromise

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Apache Airflow

#### Description

Airflow stores connection strings, API keys, and other Variables in a central metadata database, with optional encryption keyed to a single Fernet key. Operators that read these (BashOperator with templating, PythonOperator) can interpolate Variables into commands and logs. A compromise of the metadata DB, the Fernet key, or a verbose operator exposes the union of every credential the deployment holds.

#### Possible mitigations

Use an external secrets backend (cloud KMS, Key Vault) so Airflow holds references rather than secret values. Scope each connection to the DAG that needs it. Mask sensitive Variables and forbid templating them into command strings or task logs. Rotate the Fernet key on schedule and on compromise of any metadata DB credential.

#### Steps

Confirm an external secrets backend is configured and that Variables containing secrets are not templated into logged commands. Verify Fernet key custody and rotation policy.

**Documentation:** <https://airflow.apache.org/docs/apache-airflow/stable/security/secrets/secrets-backend/index.html>

---

### `TH396` — Fabric Notebook outputs and saved cell results may persist data the executing user was authorized to read but other workspace users were not

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Fabric Notebook

#### Description

When a notebook cell runs, its result is rendered inline and saved with the notebook artifact in OneLake. A user who runs a query against a sensitive table, then saves and shares the notebook, persists the query result inside an artifact governed by workspace permissions, not by the source table's permissions. Other workspace members can read the cached result without ever holding access to the underlying data.

#### Possible mitigations

Clear cell outputs before saving notebooks that touch sensitive sources. Restrict workspace membership for notebooks holding cached sensitive results. Consider a policy that scrubs outputs on save for notebooks bound to classified sources. Treat the saved notebook as a derivative data store and apply equivalent access controls.

#### Steps

Sample notebooks in production workspaces and check whether saved cell outputs contain rows from sensitive tables. Verify policy on output retention.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/how-to-use-notebook>

---

### `TH401` — Fabric Dataflow staged data and refresh history may persist sensitive intermediate values outside the controls applied to the final destination

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Dataflow

#### Description

Dataflow Gen2 stages data in OneLake-backed enhanced compute storage during transformation and writes incremental and refresh history. Intermediate columns dropped before the final write may still exist in staging, and refresh history may quote sample row values in error messages. The downstream destination's column-level controls do not protect data that never reaches it.

#### Possible mitigations

Audit the staging location and apply equivalent access controls to those on the final destination. Mask sensitive columns in source-side queries rather than dropping them later. Restrict who can view dataflow refresh history and error details when failures are likely to surface row data.

#### Steps

Identify staging locations for production dataflows handling sensitive columns. Confirm access matches that of the destination. Review whether refresh-history error rendering exposes row values.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-factory/dataflows-gen2-overview>

---

### `TH404` — Fabric Eventstream destinations may broadcast events to multiple sinks whose individual access controls collectively widen the data audience

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Eventstream

#### Description

An eventstream can fan out a single source to multiple destinations: KQL Database, Lakehouse, custom endpoint, Activator. Each destination has its own access-control model. The set of principals authorized to read at least one destination is the union of all destinations' reader sets, which is typically larger than any one source intended. Adding a destination expands the data audience without changing the source.

#### Possible mitigations

Treat the addition of a destination as a data-sharing event subject to the same review as exporting from the source. Evaluate the union of reader sets across destinations against the source's intended audience. Avoid replicating sensitive event streams into broadly-readable destinations.

#### Steps

For each eventstream carrying sensitive events, list every destination and the readers of each. Compare the union to the source's intended audience.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/event-streams/overview>

---

### `TH407` — Data crossing the Microsoft Fabric tenant boundary via shortcut, mirroring, or cross-tenant share may exit governance controls applied inside the tenant

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Crosses: Microsoft Fabric Boundary

#### Description

Fabric supports several mechanisms (OneLake shortcuts to external accounts, Mirroring to/from external sources, cross-tenant sharing) that move data references or copies across the tenant boundary. Sensitivity labels, OneLake security roles, and tenant-level DLP that govern the data inside the tenant may not propagate to or be enforced on the other side of the boundary, leaving data effectively unlabeled and unprotected outside.

#### Possible mitigations

Inventory every cross-boundary data path. Confirm that sensitivity labels and access controls apply on the receiving side, not just the sending side. Restrict who may create cross-tenant shortcuts or shares. Where the receiving environment cannot honor the controls, refuse the share.

#### Steps

Enumerate shortcuts targeting external accounts, Mirroring sources/destinations, and cross-tenant shares. Document the governance on each remote endpoint.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/onelake-shortcuts>

---

### `TH413` — LLM completions may regurgitate memorized training data or fine-tuning corpus content, disclosing material the prompt did not request 🤖

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI LLM Providers, AI Platform, AWS Bedrock, ChatGPT OpenAI, Grok xAI

#### Description

Models may memorize and reproduce verbatim sequences from their training data, especially for content that appears in the corpus repeatedly or in distinctive form. A prompt designed to elicit memorized output (long completions, prompts containing the start of a known sequence, specific extraction techniques) can surface training-corpus material the requester was not authorized to see. Fine-tuned models present the same risk against the fine-tuning corpus, often containing customer data.

#### Possible mitigations

Avoid fine-tuning on data that should not be reproducible to every model caller. For models trained on customer data, apply per-tenant model isolation. Filter completions for verbatim corpus matches when the corpus is sensitive. Prefer retrieval-augmented generation over fine-tuning when grounding-data confidentiality matters.

#### Steps

Identify any fine-tunes and the corpus they used. Confirm callers of the fine-tuned model are authorized to see all data in the corpus.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH420` — Power BI semantic models exposed through Direct Lake or DirectQuery may surface row-level data through measures and visuals that bypass source column-level controls

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Power BI

#### Description

A semantic model built on a Lakehouse, Warehouse, or external source defines its own DAX measures, calculated columns, and relationships. Authors can construct measures that aggregate or filter in ways that effectively expose rows the source's column-level or row-level security would have hidden. RLS in the model is enforced; aggregation and projection are evaluation-time and depend on author intent.

#### Possible mitigations

Apply row-level and object-level security in the semantic model regardless of source-side controls. Review measure definitions for potential disclosure (filter measures, granular slices). Restrict who can author measures on classified models. Evaluate Direct Lake's silent fallback to DirectQuery and the resulting credential context.

#### Steps

Identify semantic models bound to classified sources. Confirm RLS/OLS is configured in the model and that measure-author access is appropriately restricted.

**Documentation:** <https://learn.microsoft.com/en-us/power-bi/enterprise/service-admin-rls>

---

### `TH422` — Spark job logs and the Spark UI in Fabric Data Engineering may render row data, query plans, and credentials in user-readable form

**STRIDE:** `I` (Information Disclosure) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Fabric Data Engineering

#### Description

Spark drivers print partition counts, sample rows, plan trees, and broadcast values to driver and executor logs. The Spark UI surfaces stage details that include join keys and small-broadcast values. A user with workspace access to the job's diagnostic logs or Spark UI sees content that would have been protected at rest in OneLake. Verbose logging libraries amplify the exposure.

#### Possible mitigations

Set log levels to suppress row-level rendering by default. Disable Spark UI access for jobs handling classified data, or restrict who can view diagnostic logs. Forbid logging credentials, secrets, and sample row data through code review.

#### Steps

Sample logs from production Spark jobs touching sensitive data. Confirm row data and credentials do not appear. Check Spark UI access controls.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/spark-monitor-overview>

---

## `D` — Denial of Service (23)

> A process or datastore cannot service requests or perform up to spec.

🤖 **5 of these threats are LLM-tagged.**

### `b2596654-b80e-41c3-ae5e-51859d1107b3` — An adversary may block access to the application or API hosted on {target.Name} through a denial of service attack

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Functions, Mobile App, Web API, Web Application

#### Possible mitigations

Network level denial of service mitigations are automatically enabled as part of the Azure platform (Basic Azure DDoS Protection). Refer:
&lt;a href=&quot;<https://aka.ms/tmt-th165a&quot;&gt;https://aka.ms/tmt-th165a&lt;/a&gt>;. Implement application level throttling (e.g. per-user, per-session, per-API) to maintain service availability and protect against DoS attacks. Leverage Azure API Management for managing and protecting APIs. Refer: &lt;a href=&quot;<https://aka.ms/tmt-th165b&quot;&gt;https://aka.ms/tmt-th165b&lt;/a&gt>;. General throttling guidance, refer:
&lt;a href=&quot;<https://aka.ms/tmt-th165c&quot;&gt;https://aka.ms/tmt-th165c&lt;/a&gt>;

#### Steps

Information and guidance provided at <https://aka.ms/tmt-th165c>

**Documentation:** <https://aka.ms/tmt-th165c>

---

### `TH26` — An adversary can perform action on behalf of other user due to lack of controls against cross domain requests

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web Application • Source: Browser

#### Description

Failure to restrict requests originating from third party domains may result in unauthorized actions or access of data

#### Possible mitigations

Ensure that authenticated ASP.NET pages incorporate UI Redressing or clickjacking defenses. Refer:
<https://aka.ms/tmtconfigmgmt#ui-defenses> Ensure that only trusted origins are allowed if CORS is enabled on ASP.NET Web Applications. Refer:
<https://aka.ms/tmtconfigmgmt#cors-aspnet> Mitigate against Cross-Site Request Forgery (CSRF) attacks on ASP.NET web pages. Refer:
<https://aka.ms/tmtsmgmt#csrf-asp>

#### Steps

click-jacking, also known as a "UI redress attack", is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button or link on another page when they were intending to click on the top-level page. This layering is achieved by crafting a malicious page with an iframe, which loads the victim's page. Thus, the attacker is "hijacking" clicks meant for their page and routing them to another page, most likely owned by another application, domain, or both. To prevent click-jacking attacks, set the proper X-Frame-Options HTTP response headers that instruct the browser to not allow framing from other domains

**Documentation:** <https://blogs.msdn.microsoft.com/ieinternals/2010/03/30/combating-clickjacking-with-x-frame-options/>

---

### `TH91` — An adversary can leverage the weak scalability of token cache and cause DoS

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Microsoft Entra ID

#### Description

The default cache that ADAL (Active Directory Authentication Library) uses is an in-memory cache that relies on a static store, available process-wide. While this works for native applications, it does not scale for mid tier and backend applications. This can cause availability issues and result in denial of service either by the influence of an adversary or by the large scale of application's users.

#### Possible mitigations

Override the default ADAL token cache with a scalable alternative. Refer: <https://aka.ms/tmtauthn#adal-scalable>

#### Steps

The default cache that ADAL (Active Directory Authentication Library) uses is an in-memory cache that relies on a static store, available process-wide. While this works for native applications, it does not scale for mid tier and backend applications for the following reasons: These applications are accessed by many users at once. Saving all access tokens in the same store creates isolation issues and presents challenges when operating at scale: many users, each with as many tokens as the resources the app accesses on their behalf, can mean huge numbers and very expensive lookup operations These applications are typically deployed on distributed topologies, where multiple nodes must have access to the same cache Cached tokens must survive process recycles and deactivations For all the above reasons, while implementing web apps, it is recommended to override the default ADAL token cache with a scalable alternative such as Azure Cache for Redis.

**Documentation:** <https://blogs.msdn.microsoft.com/microsoft_press/2016/01/04/new-book-modern-authentication-with-azure-active-directory-for-web-applications/>

---

### `TH112` — An adversary can leverage the weak scalability of Identity Server's token cache and cause DoS

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Identity Server

#### Description

The default cache that Identity Server uses is an in-memory cache that relies on a static store, available process-wide. While this works for native applications, it does not scale for mid tier and backend applications. This can cause availability issues and result in denial of service either by the influence of an adversary or by the large scale of application's users.

#### Possible mitigations

Override the default Identity Server token cache with a scalable alternative. Refer:
<https://aka.ms/tmtauthn#override-token>

#### Steps

IdentityServer has a simple built-in in-memory cache. While this is good for small scale native apps, it does not scale for mid tier and backend applications for the following reasons: These applications are accessed by many users at once. Saving all access tokens in the same store creates isolation issues and presents challenges when operating at scale: many users, each with as many tokens as the resources the app accesses on their behalf, can mean huge numbers and very expensive lookup operations These applications are typically deployed on distributed topologies, where multiple nodes must have access to the same cache Cached tokens must survive process recycles and deactivations For all the above reasons, while implementing web apps, it is recommended to override the default Identity Server's token cache with a scalable alternative such as Azure Cache for Redis

**Documentation:** <https://identityserver.github.io/Documentation/docsv2/advanced/deployment.html>

---

### `TH130` — An Adversary can launch DoS attack on WCF if Throttling in not enabled

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟨 Low • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: WCF

#### Possible mitigations

Enable WCF's service throttling feature. Refer: <https://aka.ms/tmtconfigmgmt#throttling>

#### Steps

Not placing a limit on the use of system resources could result in resource exhaustion and ultimately a denial of service. EXPLANATION: Windows Communication Foundation (WCF) offers the ability to throttle service requests. Allowing too many client requests can flood a system and exhaust its resources. On the other hand, allowing only a small number of requests to a service can prevent legitimate users from using the service. Each service should be individually tuned to and configured to allow the appropriate amount of resources. RECOMMENDATIONS Enable WCF's service throttling feature and set limits appropriate for your application.

**Documentation:** <https://msdn.microsoft.com/library/ff648500.aspx>

---

### `TH214` — An adversary may exhaust budget or quota by triggering high-cost LLM calls (denial of wallet) 🤖

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

LLM inference and embedding APIs are usage-priced. An adversary who can trigger requests — through an unauthenticated endpoint, an expensive feature exposed to anonymous users, or by inflating input/output tokens — can drive up provider costs, exhaust per-tenant quotas, or trigger account throttling that affects legitimate users. This is a design concern wherever model invocation is reachable without proportional rate and cost controls.

#### Possible mitigations

Place authenticated, per-principal rate limits and token-budget caps on every model-invoking endpoint. Cap maximum input length and maximum output tokens per request. Track spend per tenant and per user against a configurable budget with automated cutoffs. For high-cost operations, require an authenticated, rate-limited entry point and disable anonymous invocation.

#### Steps

List every code path that issues a paid model call. For each, document the authentication requirement, per-principal rate limit, max-tokens cap, and the budget alert/cutoff that protects the tenant and the platform.

**Documentation:** <https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/>

---

### `TH215` — An adversary may saturate the model context window with crafted inputs to deny service 🤖

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain • Source: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

If user-supplied content (uploaded documents, retrieved web pages, chat history) can grow without bound before being placed in the model prompt, an adversary can submit very long content that consumes the entire context window. Legitimate retrieved context is then truncated, reasoning quality degrades, and per-call latency and cost spike. Repeated submissions can stall the agent loop entirely.

#### Possible mitigations

Cap the size of every individual input field, retrieved document chunk, and aggregated prompt. Apply summarization or chunking with hard upper bounds before prompt assembly. Reject inputs that exceed a defined per-request token budget at the API boundary, before they reach the model.

#### Steps

For every user-controllable field that can enter a prompt, document the maximum accepted size. Confirm the limit is enforced at the API gateway or earliest server-side handler, and that aggregated prompt length is bounded before invocation.

**Documentation:** <https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/>

---

### `TH244` — A publicly-reachable Hugging Face Space or self-hosted inference endpoint may be enumerated and abused 🤖

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Hugging Face

#### Description

Hugging Face Spaces and inference endpoints are convenient to deploy but, by default, are discoverable. Once exposed, an attacker can enumerate them, fingerprint the underlying model, and submit traffic to consume capacity or budget — the operator continues to pay for the compute regardless of legitimacy. The same applies to self-hosted inference servers that are exposed to the internet without authentication.

#### Possible mitigations

Authenticate every inference endpoint and Space that is not intended as a public demo. Apply per-caller rate limits and a hard daily compute budget. For internal use, restrict to private networks. Monitor request volume per principal and alert on anomalies.

#### Steps

List each Space or inference endpoint exposed by the design. For each, document its authentication, rate limits, network exposure, and budget cap.

**Documentation:** <https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/>

---

### `TH248` — Mixed queries spanning OneLake-Security-enabled and non-enabled data sources will fail, denying availability

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric OneLake, Microsoft Fabric Warehouse, Power BI Direct Lake

#### Description

When OneLake Security is enabled on some lakehouses or warehouses but not others within the same query scope, queries that reference both kinds of items in a single statement (for example, joins, unions, or notebook code reading multiple lakehouses) fail rather than silently masking data. A design that mixes secured and unsecured items across queries creates an availability gap for any workload that depends on a unified view, and the failure typically surfaces only after OneLake Security is enabled on one side.

#### Possible mitigations

Decide OneLake Security enablement at the workload boundary, not per-item: either all data sources in a query scope have OneLake Security enabled, or none do. Plan migrations as coordinated cutovers across the joined items. Test each downstream report, notebook, and pipeline against the proposed configuration before enabling OneLake Security in production.

#### Steps

List every report, pipeline, and notebook that joins or unions multiple lakehouses or warehouses. For each, confirm all referenced sources will have OneLake Security in the same state after enablement.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-security>

---

### `TH251` — A noisy-neighbor workload may exhaust shared Fabric capacity and throttle other workspaces with HTTP 430 TooManyRequestsForCapacity

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Activator, Fabric Data Engineering, Microsoft Fabric Data Factory, Microsoft Fabric Power BI, Microsoft Fabric Realtime Hub, Microsoft Fabric Workspace

#### Description

Fabric capacity (CUs and Spark VCores) is shared across every workspace assigned to that capacity. A single notebook, refresh, or pipeline issuing a heavy Spark or DAX workload can consume the entire capacity, causing other workspaces' jobs to be rejected with HTTP 430 TooManyRequestsForCapacity. Background operations are smoothed over 24 hours, so a burst can create sustained throttling for unrelated tenants of the same capacity.

#### Possible mitigations

Place workloads of differing criticality on separate capacities; do not co-locate development and production on a shared capacity. Set workspace-level admin policies to limit individual Spark job size and concurrency. Enable queueing for pipeline-triggered jobs so they retry rather than fail. Right-size capacity SKU based on observed peak demand and an explicit headroom factor.

#### Steps

Identify each capacity and the workspaces assigned to it. For each capacity, document the highest-criticality workload it hosts and the headroom relative to peak observed demand. Confirm that lower-criticality workloads cannot starve higher-criticality ones.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/enterprise/throttling>

---

### `TH327` — Azure services exposed via public IP addresses without DDoS Protection Standard rely only on basic platform-level protection, which may not absorb targeted volumetric or application-layer attacks

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: API Management, App Service, Traffic Manager

#### Description

Public IP addresses on Azure resources receive basic DDoS protection by default - infrastructure-level absorption of large floods. DDoS Protection Standard adds adaptive tuning, application-layer protection, attack telemetry, and SLA-backed mitigations against targeted attacks. Production services with public IPs and no Standard plan can be subjected to volumetric attacks that exceed basic-tier capacity, or to application-layer attacks (HTTP floods, Slowloris) that basic protection does not address.

#### Possible mitigations

For public-facing production services, enable DDoS Protection Standard on the VNet hosting the public endpoints. Place HTTP-facing applications behind Front Door or Application Gateway with WAF for application-layer protection. Use Private Endpoints to remove the public attack surface where possible. Monitor public-IP exposure via Azure Policy.

#### Steps

List public IPs in the design and the services they expose. For each, document the DDoS protection tier and any upstream WAF or CDN.

**Documentation:** <https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview>

---

### `TH328` — Consumption-billed Azure services (Functions, Logic Apps, Cosmos DB serverless, Cognitive Services) may incur runaway cost from attacker-induced load, causing budget-driven service interruption

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: API Management, Cognitive Services, CosmosDB, Functions, LogicApp, Machine Learning

#### Description

Several Azure services bill on per-invocation or per-RU consumption: Functions on a Consumption Plan, Logic Apps on Consumption SKU, Cosmos DB serverless, Cognitive Services and other AI APIs. An attacker who can trigger requests - through an unauthenticated endpoint, an expensive operation exposed to anonymous users, or amplification - can drive cost up arbitrarily. Budget-driven cutoffs, throttling on hitting service limits, or out-of-credit subscription suspension cause genuine outage for legitimate users.

#### Possible mitigations

Place authenticated rate limits on every consumption-billed endpoint reachable from untrusted callers. Cap maximum request rate per principal and per source IP. Configure Azure budgets with alerts and automated actions (disable resource, scale down) before spend reaches subscription credit limits. Use APIM or Front Door with rate-limit policies in front of consumption APIs.

#### Steps

List consumption-billed services reachable from untrusted callers. For each, document the rate-limit policy, budget alerts, and response actions on threshold breach.

**Documentation:** <https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/cost-management-budget-scenario>

---

### `TH339` — AWS RDS and Aurora instances without deletion protection or final snapshot configuration may be permanently destroyed by a single API call

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Aurora, AWS RDS

#### Description

RDS and Aurora support a 'deletion protection' attribute that, when disabled (the default), allows the cluster or instance to be deleted via a single API call. Without a final snapshot configured, deletion permanently destroys the database and all its data. A compromised IAM principal, a misconfigured Terraform/CloudFormation drift, or accidental operator action can therefore eliminate a production database irreversibly.

#### Possible mitigations

Enable deletion protection on every production RDS / Aurora cluster and instance. Configure final snapshots in stack policies and infrastructure-as-code defaults. Apply Service Control Policies that deny deletion API calls on tagged production resources. Maintain cross-region or cross-account snapshot replication for recovery if the source account is compromised.

#### Steps

List RDS / Aurora resources in scope, deletion protection state, final snapshot configuration, and snapshot replication. Confirm production resources are protected from single-API-call destruction.

**Documentation:** <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteCluster.html>

---

### `TH354` — AWS resources deployed across multiple regions or replicated cross-region may breach data residency obligations or extend the failure blast radius

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Aurora, AWS Data, AWS DocumentDB, AWS DynamoDB, AWS RDS, AWS Storage

#### Description

AWS resources are regional: an S3 bucket lives in one region, a DynamoDB table in one region (unless Global Tables), an RDS instance in one region (unless cross-region replicas). Cross-region replication features (S3 CRR, DynamoDB Global Tables, RDS cross-region read replicas, Aurora Global Database) replicate data into additional regions, potentially across geographic and regulatory boundaries. A single replication configuration enabled for redundancy may thereby breach GDPR or sectoral residency requirements, and a region-wide failure of the primary region may extend impact to consumers in regions assumed to be independent.

#### Possible mitigations

Document data residency requirements per data class. Enable cross-region replication only where the destination region is compliant with the source data's residency rules. Use SCPs or AWS Control Tower guardrails to constrain permitted regions per OU. Audit cross-region replication configurations against the residency matrix.

#### Steps

For each AWS data resource in scope, document the primary region, replication targets, and the residency requirement. Confirm replication targets are compliant.

**Documentation:** <https://aws.amazon.com/compliance/data-residency/>

---

### `TH382` — Heavy or runaway API usage by one integration may exhaust the SaaS tenant's API rate limit, denying service to other integrations and the user-facing app

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ADP, Adobe, Box Storage, Dynamics CRM, Expensify, Jira, Microsoft 365, Monday, Notion, Postmark, Power Automate, Salesforce, Slack, Trello, Workday, Zoom

#### Description

SaaS APIs are rate-limited per tenant (or per app/user). Integrations that misuse the API — bulk syncs without backoff, retry storms, scraping loops, or compromised credentials weaponized for enumeration — can consume the tenant's rate budget. The SaaS then throttles or blocks all callers for that tenant: other integrations fail, scheduled jobs miss SLAs, and in some platforms the user-facing UI degrades because the same tenant rate limit applies. The blast radius is the entire tenant.

#### Possible mitigations

Document the API rate limit per SaaS and per integration. Implement client-side rate limiting and exponential backoff in every integration. Use bulk APIs (Salesforce Bulk API, Box batch endpoints) for large data movements rather than item-by-item calls. Monitor API consumption per integration and alert on outlier usage. Where supported, use per-app rate limit tiers to isolate integrations from each other.

#### Steps

List integrations against each SaaS, the API consumption pattern (sync, bulk, real-time), and the rate-limit posture. Confirm backoff and bulk-API usage where applicable.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/aac/aac-02/>

---

### `TH387` — An AI Agent may enter a tool-call loop or context-expansion loop that exhausts compute, tokens, or downstream API quota 🤖

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AI Agent

#### Description

Agents that decide their own next action can enter loops: repeatedly calling the same tool, invoking themselves recursively, or expanding the context window with growing tool outputs until token limits are hit. These loops consume LLM provider quota, compute capacity, and downstream API quota in proportion to the loop length, denying service to other callers and producing unpredictable cost. Adversarial prompts can deliberately induce such loops.

#### Possible mitigations

Cap each agent invocation by maximum tool-call count, maximum total tokens, maximum wall-clock time, and maximum recursion depth. Detect repeated identical tool calls and abort. Apply per-user and per-agent rate limits to downstream APIs the agent calls. Set hard cost ceilings.

#### Steps

For each agent, document the maximum tool-call count, token budget, and timeout per turn. Confirm downstream APIs the agent calls have their own per-agent rate limits.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH394` — Apache Airflow scheduler and worker capacity may be exhausted by misconfigured schedules, runaway tasks, or DAG parsing failures

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Apache Airflow

#### Description

Airflow's scheduler parses every DAG file on a configurable interval; a DAG with expensive top-level code, an import that calls out to a slow service, or an excessive number of dynamically generated tasks can saturate the scheduler. Worker pools are bounded: a single DAG that floods the queue with tasks, fires too-frequent schedules, or hangs without a task timeout can starve every other DAG of execution slots.

#### Possible mitigations

Set per-DAG concurrency limits, per-task timeouts, and pool-size caps. Forbid expensive top-level code in DAG files; do work inside tasks. Monitor scheduler parse times and alert on regressions. Quarantine DAGs that repeatedly time out or fail to parse.

#### Steps

Inventory DAGs without task timeouts or concurrency limits. Measure scheduler parse time per DAG. Confirm pool assignments isolate critical workflows.

**Documentation:** <https://airflow.apache.org/docs/apache-airflow/stable/best-practices.html>

---

### `TH402` — Fabric Dataflow refreshes may share capacity with interactive workloads and induce throttling that cascades to dependent reports

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Fabric Dataflow

#### Description

Dataflow refreshes run on Fabric capacity and consume CU. A long-running or frequently-scheduled dataflow can drive capacity utilization above smoothing thresholds, producing HTTP 430 throttling that affects every workload on the same capacity, including the Power BI reports the dataflow feeds. Failure of one dataflow can therefore deny service to its downstream consumers.

#### Possible mitigations

Schedule heavy dataflow refreshes off-peak. Place refresh-heavy dataflows on a separate capacity from interactive consumption when CU budget allows. Monitor capacity smoothing and refresh duration trends. Use incremental refresh to bound work per run.

#### Steps

Inventory scheduled refreshes per capacity. Compare aggregate CU consumption to capacity SKU. Confirm critical reports are not co-resident with bursty dataflow workloads.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/enterprise/throttling>

---

### `TH406` — Fabric Eventstream backpressure on a slow destination may delay or drop events for every other destination on the same stream

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Eventstream

#### Description

When one destination of an eventstream becomes slow or unavailable (a Lakehouse paused, a custom endpoint timing out, a KQL Database under throttling), the stream may apply backpressure that delays delivery to other destinations or drops events past a retention window. Failure of one downstream consumer becomes a denial of timely or complete data to all consumers.

#### Possible mitigations

Decouple high-criticality destinations into their own eventstream where possible. Monitor per-destination lag and surface alerts before the retention window is exhausted. Choose retention duration with worst-case downstream outage in mind.

#### Steps

List destinations per eventstream and rank by criticality. Confirm per-destination lag monitoring and retention durations are sized for downstream outage.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/event-streams/overview>

---

### `TH412` — LLM provider rate limits, quota exhaustion, or model deprecation may cause dependent application functionality to fail without warning 🤖

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI LLM Providers, AI Platform, AWS Bedrock, ChatGPT OpenAI, Grok xAI

#### Description

Applications that depend on a single LLM endpoint inherit that endpoint's availability: per-tenant rate limits, regional quota exhaustion, model retirement on a vendor-controlled schedule, or temporary provider outages will halt the application's AI features. Recovery often requires code changes (new model name, new provider SDK) that cannot be deployed during the incident.

#### Possible mitigations

Design for provider failover: maintain a configured alternative provider/model and a tested switchover path. Subscribe to model-deprecation announcements. Monitor quota headroom and projected exhaustion. Cache or downgrade gracefully on rate-limit responses.

#### Steps

Document the application's primary and fallback provider/model. Verify the switchover path is exercised periodically. Confirm quota headroom monitoring exists.

**Documentation:** <https://learn.microsoft.com/en-us/azure/ai-services/openai/quotas-limits>

---

### `TH416` — Fabric query workloads may be denied service when capacity throttling, statistics drift, or runaway queries consume the SQL endpoint or compute pool

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Lakehouse, Microsoft Fabric SQL Database, Microsoft Fabric Warehouse

#### Description

The Lakehouse SQL endpoint, Warehouse, and Fabric SQL Database share workspace and capacity-level resources. A single user running an unbounded query (cross-join, missing predicate, runaway recursive CTE) can consume the resource pool and cause concurrent queries to queue or fail. Stale statistics and schema drift compound the impact by causing previously-fast queries to plan poorly.

#### Possible mitigations

Set per-user and per-workload concurrency and resource limits where the engine supports them. Enforce query timeouts. Maintain statistics. Monitor capacity smoothing and surface long-running queries. Quarantine or require review for queries that repeatedly trigger throttling.

#### Steps

Identify the longest-running queries against each Lakehouse/Warehouse/SQL DB over the last 30 days. Confirm timeouts and resource limits are configured.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-warehouse/workload-management>

---

### `TH418` — Fabric Mirroring may amplify source-side load or lag indefinitely if the change feed backs up, blocking source operations and stalling downstream consumers

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Mirroring

#### Description

Mirroring depends on the source database's change-data feed. If Mirroring stops consuming (paused workspace, capacity throttled, network outage) while the source continues writing, the source's change feed grows. Some sources block transactions or refuse to truncate transaction log when CDC consumers fall behind, transmitting denial of service from a paused Fabric workload back to the source database that other applications depend on.

#### Possible mitigations

Monitor source-side change-feed depth as well as Fabric-side mirroring lag. Define a maximum tolerable lag and a procedure to disable mirroring before the source is blocked. Test the disable-and-resume path on each source type.

#### Steps

For each mirrored source, document how the source behaves when CDC is paused. Confirm monitoring covers source-side depth and that disable procedure is documented and tested.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/database/mirrored-database/overview>

---

### `TH428` — OneLake security role and group-membership propagation latency creates a window in which intended denials are not yet enforced

**STRIDE:** `D` (Denial of Service) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Microsoft Fabric, Microsoft Fabric OneLake

#### Description

Role assignments propagate within roughly five minutes; group-membership-driven access can take an hour or longer. An access removal intended to take effect immediately (terminated employee, scope reduction during incident response) is not actually enforced until propagation completes. During the window, the removed identity continues to have access.

#### Possible mitigations

For incident-driven access removals, also revoke at the identity layer (disable the account, revoke session tokens) rather than relying on role removal alone. Document expected propagation intervals and surface them to administrators making access changes.

#### Steps

Test propagation by removing a role assignment and timing when access actually fails. Confirm incident-response procedures account for the window.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-onelake-security>

---

## `E` — Elevation of Privilege (61)

> A subject gains capability or privilege beyond what is intended.

🤖 **10 of these threats are LLM-tagged.**

### `TH1` — An adversary can gain unauthorized access to database due to lack of network access protection

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, CosmosDB, Database, SQL Data Warehouse

#### Description

If there is no restriction at network or host firewall level, to access the database then anyone can attempt to connect to the database from an unauthorized location

#### Possible mitigations

Configure a Windows Firewall for Database Engine Access. Refer: <https://aka.ms/tmtconfigmgmt#firewall-db>

#### Steps

Firewall systems help prevent unauthorized access to computer resources. To access an instance of the SQL Server Database Engine through a firewall, you must configure the firewall on the computer running SQL Server to allow access

**Documentation:** <https://azure.microsoft.com/documentation/articles/sql-database-firewall-configure/>

---

### `TH2` — An adversary can gain unauthorized access to {target.Name} due to weak account policy

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Database

#### Description

Due to poorly configured account policies, adversary can launch brute force attacks on {target.Name}

#### Possible mitigations

When possible, use Windows Authentication for connecting to SQL Server. Refer:
<https://aka.ms/tmtauthn#win-authn-sql> When SQL authentication mode is used, ensure that account and password policy are enforced on SQL server. Refer:
<https://aka.ms/tmtauthn#authn-account-pword> Do not use SQL Authentication in contained databases. Refer:
<https://aka.ms/tmtauthn#autn-contained-db>

#### Steps

Windows Authentication uses Kerberos security protocol, provides password policy enforcement with regard to complexity validation for strong passwords, provides support for account lockout, and supports password expiration.

**Documentation:** <https://msdn.microsoft.com/library/ms144284.aspx>

---

### `TH4` — An adversary can gain unauthorized access to {target.Name} due to loose authorization rules

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, CosmosDB, Database, SQL Data Warehouse

#### Description

Database access should be configured with roles and privilege based on least privilege and need to know principle.

#### Possible mitigations

Ensure that least-privileged accounts are used to connect to Database server. Refer:
<https://aka.ms/tmtauthz#privileged-server> Implement Row Level Security RLS to prevent tenants from accessing each others data. Refer:
<https://aka.ms/tmtauthz#rls-tenants> Sysadmin role should only have valid necessary users . Refer:
<https://aka.ms/tmtauthz#sysadmin-users>

#### Steps

Least-privileged accounts should be used to connect to the database. Application login should be restricted in the database and should only execute selected stored procedures. Application's login should have no direct table access.

**Documentation:** <https://msdn.microsoft.com/library/ms191465>

---

### `TH10` — An adversary can gain unauthorized access to Azure SQL database due to weak account policy

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Analysis Services, Azure Database for MariaDB, Azure Database for MySQL, Azure Database for PostgreSQL, CosmosDB, Database, SQL Data Warehouse

#### Description

Due to poorly configured account policies, adversary can launch brute force attacks on {target.Name}

#### Possible mitigations

When possible use Azure Active Directory Authentication for Connecting to SQL Database. . Refer:
<https://aka.ms/tmtauthn#win-authn-sql> Ensure that least-privileged accounts are used to connect to Database server. Refer:
<https://aka.ms/tmtauthz#privileged-server>

#### Steps

Windows Authentication uses Kerberos security protocol, provides password policy enforcement with regard to complexity validation for strong passwords, provides support for account lockout, and supports password expiration.

**Documentation:** <https://msdn.microsoft.com/library/ms144284.aspx>

---

### `TH17` — An adversary can gain unauthorized access to {target.Name} due to weak access control restrictions

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Azure Storage

#### Possible mitigations

Grant limited access to objects in Azure storage using SAS or SAP. Refer: <https://aka.ms/tmtauthn#limited-access-sas>

#### Steps

Using a shared access signature (SAS) is a powerful way to grant limited access to objects in a storage account to other clients, without having to expose account access key. The SAS is a URI that encompasses in its query parameters all of the information necessary for authenticated access to a storage resource. To access storage resources with the SAS, the client only needs to pass in the SAS to the appropriate constructor or method. You can use a SAS when you want to provide access to resources in your storage account to a client that can't be trusted with the account key. Your storage account keys include both a primary and secondary key, both of which grant administrative access to your account and all of the resources in it. Exposing either of your account keys opens your account to the possibility of malicious or negligent use. Shared access signatures provide a safe alternative that allows other clients to read, write, and delete data in your storage account according to the permissions you've granted, and without need for the account key. If you have a logical set of parameters that are similar each time, using a Stored Access Policy (SAP) is a better idea. Because using a SAS derived from a Stored Access Policy gives you the ability to revoke that SAS immediately, it is the recommended best practice to always use Stored Access Policies when possible.

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-dotnet-shared-access-signature-part-1/>

---

### `TH27` — An adversary may bypass critical steps or perform actions on behalf of other users (victims) due to improper validation logic

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Web Application • Source: Browser

#### Description

Failure to restrict the privileges and access rights to the application to individuals who require the privileges or access rights may result into unauthorized use of data due to inappropriate rights settings and validation.

#### Possible mitigations

Ensure that administrative interfaces are appropriately locked down. Refer: <https://aka.ms/tmtauthn#admin-interface-lockdown> Enforce sequential step order when processing business logic flows. Refer:
<https://aka.ms/tmtauthz#sequential-logic> Ensure that proper authorization is in place and principle of least privileges is followed. Refer:
<https://aka.ms/tmtauthz#principle-least-privilege> Business logic and resource access authorization decisions should not be based on incoming request parameters. Refer:
<https://aka.ms/tmtauthz#logic-request-parameters> Ensure that content and resources are not enumerable or accessible via forceful browsing. Refer:
<https://aka.ms/tmtauthz#enumerable-browsing>

#### Steps

The first solution is to grant access only from a certain source IP range to the administrative interface. If that solution would not be possible than it is always recommended to enforce a step-up or adaptive authentication for logging in into the administrative interface

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH37` — An adversary may gain elevated privileges on {target.Name}

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: IoT Cloud Gateway • Source: IoT Device, IoT Field Gateway

#### Description

An adversary may gain elevated privileges on the functionality of cloud gateway if SAS tokens with over-privileged permissions are used to connect

#### Possible mitigations

Connect to Cloud Gateway using least-privileged tokens. Refer: <https://aka.ms/tmtauthz#cloud-least-privileged>

#### Steps

Provide least privilege permissions to various components that connect to Cloud Gateway (IoT Hub). Typical example is – Device management/provisioning component uses registryread/write, Event Processor (ASA) uses Service Connect. Individual devices connect using Device credentials

**Documentation:** <https://azure.microsoft.com/documentation/articles/iot-hub-devguide/#Security>

---

### `TH41` — An adversary may gain unauthorized access to privileged features on {source.Name}

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Source: IoT Device, IoT Field Gateway

#### Description

An adversary may get access to admin interface or privileged services like WiFi, SSH, File shares, FTP etc., on a device

#### Possible mitigations

Ensure that all admin interfaces are secured with strong credentials. Refer:
<https://aka.ms/tmtconfigmgmt#admin-strong>

#### Steps

Any administrative interfaces that the device or field gateway exposes should be secured using strong credentials. Also, any other exposed interfaces like WiFi, SSH, File shares, FTP should be secured with strong credentials. Default weak passwords should not be used.

---

### `TH42` — An adversary may trigger unauthorized commands on the {target.Name} Device

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: IoT Device • Source: IoT Cloud Gateway, IoT Field Gateway

#### Description

An adversary may leverage insufficient authorization checks on the device and execute unauthorized and sensitive commands remotely.

#### Possible mitigations

Perform authorization checks in the device if it supports various actions that require different permission levels. Refer:
<https://aka.ms/tmtauthz#device-permission>

#### Steps

The Device should authorize the caller to check if the caller has the required permissions to perform the action requested. For e.g. Lets say the device is a Smart Door Lock that can be monitored from the cloud, plus it provides functionalities like Remotely locking the door. The Smart Door Lock provides unlocking functionality only when someone physically comes near the door with a Card. In this case, the implementation of the remote command and control should be done in such a way that it does not provide any functionality to unlock the door as the cloud gateway is not authorized to send a command to unlock the door.

---

### `TH48` — An adversary may exploit unused services or features in {target.Name}

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Source: IoT Device, IoT Field Gateway

#### Description

An adversary may use unused features or services on {target.Name} such as UI, USB port etc. Unused features increase the attack surface and serve as additional entry points for the adversary

#### Possible mitigations

Ensure that only the minimum services/features are enabled on devices. Refer:
<https://aka.ms/tmtconfigmgmt#min-enable>

#### Steps

Do not enable or turn off any features or services in the OS that is not required for the functioning of the solution. For e.g. if the device does not require a UI to be deployed, install Windows IoT Core in headless mode.

---

### `TH51` — An adversary may trigger unauthorized commands on the {target.Name} gateway

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: IoT Field Gateway • Source: IoT Cloud Gateway, IoT Device

#### Description

An adversary may leverage insufficient authorization checks on the {target.Name} and execute unauthorized and sensitive commands remotely

#### Possible mitigations

Perform authorization checks in the {target.Name} if it supports various actions that require different permission levels. Refer:
<https://aka.ms/tmtauthz#field-permission>

#### Steps

The Field Gateway should authorize the caller to check if the caller has the required permissions to perform the action requested. For e.g. there should be different permissions for an admin user interface/API used to configure a field gateway v/s devices that connect to it.

---

### `TH54` — An adversary may gain elevated privileges on {target.Name} NoSQL Database

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: CosmosDB

#### Description

An adversary may gain elevated privileges on the contents of {target.Name} if over-privileged master or read-only keys are used to connect

#### Possible mitigations

Use resource tokens to connect to {target.Name} whenever possible. Refer: <https://aka.ms/tmtauthz#resource-docdb>

#### Steps

A resource token is associated with an Azure Cosmos DB permission resource and captures the relationship between the user of a database and the permission that user has for a specific Azure Cosmos DB application resource (e.g. collection, document). Always use a resource token to access the Azure Cosmos DB if the client cannot be trusted with handling master or read-only keys - like an end user application like a mobile or desktop client.Use Master key or read-only keys from backend applications which can store these keys securely.

---

### `TH56` — An adversary may read unauthorized content stored in {target.Name}

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: CosmosDB

#### Description

An adversary may gain elevated privileges on the document stored in {target.Name} storage.

#### Possible mitigations

Use parametrized SQL queries for {target.Name}. Refer: <https://aka.ms/tmtinputval#sql-docdb>

#### Steps

Although Azure Cosmos DB only supports read-only queries, SQL injection is still possible if queries are constructed by concatenating with user input. It might be possible for a user to gain access to data they shouldn’t be accessing within the same collection by crafting malicious SQL queries. Use parameterized SQL queries if queries are constructed based on user input.

**Documentation:** <https://azure.microsoft.com/blog/announcing-sql-parameterization-in-documentdb/>

---

### `TH57` — An adversary may directly connect to {target.Name} from anywhere

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: CosmosDB

#### Description

An adversary may directly connect to {target.Name} from anywhere since {target.Name} does not have any Firewall restrictions that can be enforced.

#### Possible mitigations

Use resource tokens to connect to {target.Name} whenever possible. Refer: <https://aka.ms/tmtauthz#resource-docdb>

#### Steps

A resource token is associated with an Azure Cosmos DB permission resource and captures the relationship between the user of a database and the permission that user has for a specific Azure Cosmos DB application resource (e.g. collection, document). Always use a resource token to access the Azure Cosmos DB if the client cannot be trusted with handling master or read-only keys - like an end user application like a mobile or desktop client.Use Master key or read-only keys from backend applications which can store these keys securely.

---

### `TH59` — An adversary may exploit the permissions provisioned to the device token to gain elevated privileges

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Event Hub, Event Grid, IoT Hub, Service Bus

#### Description

An adversary may leverage insufficient authorization checks on the Event Hub (SAS token) and be able to listen (Read) to the Events and manage (change) configurations of the Event Hub

#### Possible mitigations

Use a send-only permissions SAS Key for generating device tokens. Refer: <https://aka.ms/tmtauthz#sendonly-sas>

#### Steps

A SAS key is used to generate individual device tokens. Use a send-only permissions SAS key while generating the device token for a given publisher

**Documentation:** <https://azure.microsoft.com/documentation/articles/event-hubs-authentication-and-security-model-overview/>

---

### `TH60` — An adversary bypass the secure functionalities of the {target.Name} if devices authenticate with tokens that give direct access to {target.Name}

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: Azure Event Hub, Event Grid, IoT Hub, Service Bus

#### Description

If a token that grants direct access to the event hub is given to the device, it would be able to send messages directly to the eventhub without being subjected to throttling. It further exempts such a device from being able to be blacklisted.

#### Possible mitigations

Do not use access tokens that provide direct access to the Event Hub. Refer:
<https://aka.ms/tmtauthz#access-tokens-hub>

#### Steps

A token that grants direct access to the event hub should not be given to the device. Using a least privileged token for the device that gives access only to a publisher would help identify and blacklist it if found to be a rogue or compromised device.

**Documentation:** <https://azure.microsoft.com/documentation/articles/event-hubs-authentication-and-security-model-overview/>

---

### `TH62` — An adversary may gain elevated privileges on {target.Name} (Service Bus Technologies)

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Event Hub, Event Grid, IoT Hub, Service Bus

#### Description

An adversary may gain elevated privileges on the functionality of {target.Name} if SAS keys with over-privileged permissions are used to connect

#### Possible mitigations

Connect to {target.Name} using SAS keys that have the mimimum permissions required. Refer:
<https://aka.ms/tmtauthz#sas-minimum-permissions>

#### Steps

Provide least privilege permissions to various back-end applications that connect to the Event Hub. Generate separate SAS keys for each back-end application and only provide the required permissions - Send, Receive or Manage to them.

**Documentation:** <https://azure.microsoft.com/documentation/articles/event-hubs-authentication-and-security-model-overview/>

---

### `TH64` — An adversary can gain unauthorized access to all entities in {target.Name}'s tables

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟧 Medium • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Storage

#### Description

An adversary can gain unauthorized access to all entities in {target.Name} tables

#### Possible mitigations

Grant fine-grained permission on a range of entities in Azure Table Storage. Refer:
<https://aka.ms/tmtauthz#permission-entities>

#### Steps

In certain business scenarios, Azure Table Storage may be required to store sensitive data that caters to different parties. E.g., sensitive data pertaining to different countries. In such cases, SAS signatures can be constructed by specifying the partition and row key ranges, such that a user can access data specific to a particular country.

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-security-guide/#_data-plane-security>

---

### `TH67` — An adversary may gain unauthorized access to {target.Name} account in a subscription

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Data Service

#### Possible mitigations

Enable Role-Based Access Control (RBAC) to Azure storage account using Azure Resource Manager. Refer:
<https://aka.ms/tmtauthz#rbac-azure-manager>

#### Steps

When you create a new storage account, you select a deployment model of Classic or Azure Resource Manager. The Classic model of creating resources in Azure only allows all-or-nothing access to the subscription, and in turn, the storage account. With the Azure Resource Manager model, you put the storage account in a resource group and control access to the management plane of that specific storage account using Azure Active Directory. For example, you can give specific users the ability to access the storage account keys, while other users can view information about the storage account, but cannot access the storage account keys.

**Documentation:** <https://azure.microsoft.com/documentation/articles/storage-security-guide/#management-plane-security>

---

### `TH71` — An adversary may gain unauthorized access to Service Fabric cluster operations

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Crosses: Service Fabric Trust Boundary

#### Description

If RBAC is not implemented on Service Fabric, clients may have over-privileged access on the fabric's cluster operations

#### Possible mitigations

Restrict client's access to cluster operations using RBAC. Refer: <https://aka.ms/tmtauthz#cluster-rbac>

#### Steps

Azure Service Fabric supports two different access control types for clients that are connected to a Service Fabric cluster: administrator and user. Access control allows the cluster administrator to limit access to certain cluster operations for different groups of users, making the cluster more secure. Administrators have full access to management capabilities (including read/write capabilities). Users, by default, have only read access to management capabilities (for example, query capabilities), and the ability to resolve applications and services. You specify the two client roles (administrator and client) at the time of cluster creation by providing separate certificates for each.

**Documentation:** <https://azure.microsoft.com/documentation/articles/service-fabric-cluster-security-roles/>

---

### `TH90` — An adversary may gain unauthorized access to {target.Name} if connection is insecure

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Source: Azure Data Factory, LogicApp

#### Possible mitigations

Use Data managent gateway while connecting On Prem SQL Server to Azure Data Factory. Refer:
<https://aka.ms/tmtcommsec#sqlserver-factory>

**Documentation:** <https://azure.microsoft.com/documentation/articles/data-factory-move-data-between-onprem-and-cloud/#create-gateway>

---

### `TH104` — An adversary may jail break into a mobile device and gain elevated privileges

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** High

**Applies to:** Source: Mobile Client

#### Possible mitigations

Implement implicit jailbreak or rooting detection. Refer: <https://aka.ms/tmtauthz#rooting-detection>

#### Steps

Application should safeguard its own configuration and user data in case if phone is rooted or jail broken. Rooting/jail breaking implies unauthorized access, which normal users won't do on their own phones. Therefore application should have implicit detection logic on application startup, to detect if the phone has been rooted. The detection logic can be simply accessing files which normally only root user can access, for example: /system/app/Superuser.apk /sbin/su /system/bin/su /system/xbin/su /data/local/xbin/su /data/local/bin/su /system/sd/xbin/su /system/bin/failsafe/su /data/local/su If the application can access any of these files, it denotes that the application is running as root user.

---

### `TH110` — An adversary may gain unauthorized access to {target.Name} due to poor access control checks

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Web API

#### Description

An adversary may gain unauthorized access to Web API due to poor access control checks

#### Possible mitigations

Implement proper authorization mechanism in ASP.NET Web API. Refer: <https://aka.ms/tmtauthz#authz-aspnet>

#### Steps

Role information for the application users can be derived from Azure AD or ADFS claims if the application relies on them as Identity provider or the application itself might provided it. In any of these cases, the custom authorization implementation should validate the user role information. Role information for the application users can be derived from Azure AD or ADFS claims if the application relies on them as Identity provider or the application itself might provided it. In any of these cases, the custom authorization implementation should validate the user role information.

**Documentation:** <http://www.asp.net/web-api/overview/security/authentication-and-authorization-in-aspnet-web-api>

---

### `TH116` — An adversary can can gain unauthorized access to resources in an Azure subscription

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Crosses: Azure Trust Boundary

#### Description

An adversary can can gain unauthorized access to resources in Azure subscription. The adversary can be either a disgruntled internal user, or someone who has stolen the credentials of an Azure subscription.

#### Possible mitigations

Enable fine-grained access management to Azure Subscription using RBAC. Refer:
<https://aka.ms/tmtauthz#grained-rbac>

#### Steps

Azure Role-Based Access Control (RBAC) enables fine-grained access management for Azure. Using RBAC, you can grant only the amount of access that users need to perform their jobs.

**Documentation:** <https://azure.microsoft.com/documentation/articles/role-based-access-control-configure/>

---

### `TH120` — An adversary can bypass built in security through Custom Services or ASP.NET Pages which authenticate as a service account

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Dynamics CRM

#### Possible mitigations

Check service account privileges and check that the custom Services or ASP.NET Pages respect CRM's security. Refer:
<https://aka.ms/tmtcommsec#priv-aspnet>

#### Steps

Check service account privileges and check that the custom Services or ASP.NET Pages respect CRM's security

---

### `TH124` — Misconfiguration of Security Roles, Business Unit or Teams

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM

#### Possible mitigations

Perform security modelling and use Field Level Security where required. Refer:
<https://aka.ms/tmtauthz#modeling-field> Perform security modelling and use Business Units/Teams where required. Refer:
<https://aka.ms/tmtdata#modeling-teams>

#### Steps

Perform security modeling and use Business Units/Teams where required

**Documentation:** <https://docs.microsoft.com/en-us/azure/security/azure-security-threat-modeling-tool>

---

### `TH125` — Misuse of the Share feature

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM

#### Possible mitigations

Minimise access to share feature on critical entities. Refer: <https://aka.ms/tmtdata#entities> Train users on the risks associated with the Dynamics CRM Share feature and good security practices. Refer:
<https://aka.ms/tmtdata#good-practices>

#### Steps

Train users on the risks associated with the Dynamics CRM Share feature and good security practices

---

### `TH128` — Users with CRM Portal access are inadvertantly given access to sensitive records and data

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM Portal

#### Possible mitigations

Perform security modelling of portal accounts keeping in mind that the security model for the portal differs from the rest of CRM. Refer:
<https://aka.ms/tmtauthz#portal-security>

#### Steps

Perform security modeling of portal accounts keeping in mind that the security model for the portal differs from the rest of CRM

---

### `TH135` — An adversary may gain unauthorized access to data on host machines

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Crosses: Machine Trust Boundary

#### Possible mitigations

Ensure that proper ACLs are configured to restrict unauthorized access to data on the device. Refer:
<https://aka.ms/tmtauthz#acl-restricted-access> Ensure that sensitive user-specific application content is stored in user-profile directory. Refer:
<https://aka.ms/tmtauthz#sensitive-directory>

#### Steps

Ensure that proper ACLs are configured to restrict unauthorized access to data on the device

---

### `TH136` — An adversary may gain elevated privileges and execute malicious code on host machines

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Medium

**Applies to:** Crosses: Machine Trust Boundary

#### Description

If an application runs under a high-privileged account, it may provide an opportunity for an adversary to gain elevated privileges and execute malicious code on host machines. E.g., If the developed executable runs under the logged-in user's identity and the user has admin rights on the machine, the executable will be running with administrator privileges. Any unnoticed vulnerability in the application could be used by adversaries to execute malicious code on the host machines that run the application.

#### Possible mitigations

Ensure that the deployed applications are run with least privileges. . Refer:
<https://aka.ms/tmtauthz#deployed-privileges>

#### Steps

Ensure that the deployed application is run with least privileges.

**Documentation:** <https://www.owasp.org/index.php/OWASP_Application_Security_Verification_Standard>

---

### `TH140` — A compromised access key may permit an adversary to have more access than intended to an {target.Name} instance

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: CosmosDB

#### Description

A compromised access key may permit an adversary to have over-privileged access to an {target.Name} instance

#### Possible mitigations

Use resource (SAS like) tokens (derived using master keys) to connect to Cosmos DB instances whenever possible. Scope the resource tokens to permit only the privileges necessary (e.g. read-only). Store secrets in a secret storage solution (e.g. Azure Key Vault). Refer: <https://aka.ms/tmt-th54>

#### Steps

Implementation details provided at <https://aka.ms/tmt-th54>

**Documentation:** <https://docs.microsoft.com/en-us/rest/api/cosmos-db/access-control-on-cosmosdb-resources>

---

### `TH141` — An adversary can gain unauthorized access to Azure Cosmos DB instances due to weak network security configuration

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: CosmosDB

#### Possible mitigations

Restrict access to Azure Cosmos DB instances by configuring account-level firewall rules to only permit connections from selected IP addresses where possible. Refer:
<https://aka.ms/tmt-th57>

#### Steps

Implementation details provided at <https://aka.ms/tmt-th57>

**Documentation:** <https://docs.microsoft.com/en-us/azure/cosmos-db/firewall-support>

---

### `TH216` — An LLM agent may exceed its intended privilege through over-broad tool permissions (excessive agency) 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, Claude Code, Lanchain

#### Description

An autonomous agent that holds credentials with privileges greater than the minimum required for its task — broad write access to data stores, ability to invoke administrative APIs, network egress without restriction — can be steered (through prompt injection, untrusted retrieval, or model error) into taking actions that exceed the requesting user's authority. The model becomes a confused deputy that escalates the user's privilege via the agent's identity.

#### Possible mitigations

Run agents under least-privilege identities scoped to the specific task and the requesting user's permissions. Use on-behalf-of (OBO) or downstream-token-exchange flows so that downstream calls carry the end-user's authorization, not a powerful service identity. Limit the toolset to the minimum required and gate destructive or high-impact tools behind explicit human confirmation.

#### Steps

List every credential and role the agent holds. For each, confirm it is scoped to the minimum permissions required and tied to the requesting user where possible. Identify destructive tools and confirm a confirmation gate is in place.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH217` — An adversary may elevate privilege through insecure plugin or function-calling design 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, Claude Code, Lanchain

#### Description

Plugins, function-calling tools, and MCP servers exposed to an LLM agent often perform privileged actions on behalf of the model. If a plugin trusts model-supplied arguments without server-side authorization (treating the model as a trusted caller), an attacker who can influence the model (via prompt injection, indirect injection, or a malicious user prompt) can cause it to invoke the plugin with arguments that escalate the attacker's effective privilege.

#### Possible mitigations

Each plugin or callable tool must perform its own server-side authorization based on the end-user identity propagated with the call — never on the agent identity alone. Validate and constrain every argument the model can supply (allowlist values, type checks, range checks). Treat the model as an untrusted client of the plugin, not a privileged caller.

#### Steps

For each plugin/tool, document who calls it, whose identity is on the call, what authorization decision it makes, and how each parameter is validated. Confirm the plugin does not assume the agent has pre-validated anything.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH218` — Improper handling of LLM output may enable downstream code execution or injection (insecure output handling) 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain • Source: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

Treating model output as trusted text and passing it directly into downstream interpreters — rendering as HTML in a browser, concatenating into SQL, executing as shell or code, building URLs for outbound requests — converts a prompt-injection or hallucination event into XSS, SQLi, SSRF, or RCE in downstream systems. The threat is design-level whenever model output reaches an interpreter without contextual encoding or validation.

#### Possible mitigations

Treat model output as untrusted user input at every downstream interpreter. Apply contextual output encoding (HTML, SQL parameterization, shell argument arrays) and strict allowlists for URLs, file paths, and command names. Where the model emits structured calls (tool/function calling), validate the call name and arguments against an allowlisted schema before execution.

#### Steps

Trace every consumer of model output: UI renderers, SQL builders, shell invocations, HTTP clients, code executors. For each, confirm that output is encoded or validated for that specific sink and that no path treats model output as trusted code or markup.

**Documentation:** <https://genai.owasp.org/llmrisk/llm05-improper-output-handling/>

---

### `TH226` — A managed AI platform's broad IAM role may grant cross-account or cross-project model access 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Bedrock, DataRobot, Databricks, Vertex, Watson IBM

#### Description

Managed AI platforms (Bedrock, Vertex, Databricks, Watson) execute inference and training under platform service identities. If those identities are granted broadly-scoped roles (e.g., account-wide model invocation, cross-project data read, organization-level admin) to simplify integration, an attacker who compromises any consumer of the platform - or any less-privileged consumer in the same account - can pivot through the platform identity to invoke models or access training data in other projects, accounts, or business units.

#### Possible mitigations

Scope platform service identities and consumer roles to the minimum project, account, model, and dataset required. Use per-workload identities rather than a shared platform admin identity. Apply IAM condition keys to constrain invocation by source VPC, identity tag, and model ARN/URI. Audit IAM policies against an allowlisted set of permitted permissions.

#### Steps

List every IAM role, service principal, or workspace identity granted access to the AI platform. For each, document the scope (project, account, model, dataset), and confirm it matches the consumer's actual need.

**Documentation:** <https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-authorization>

---

### `TH230` — A compromised agent in a multi-agent system may escalate by injecting instructions into peer agents' context 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: CrewAI, Lanchain

#### Description

Multi-agent frameworks (CrewAI and similar role-based agent platforms) coordinate agents by passing messages, shared memory, or task outputs between them. A single agent that becomes compromised — by indirect prompt injection from a tool result, by adversarial user input, or by following a malicious task description — can propagate injected instructions through the shared communication channel into other agents that may hold higher privilege or different tool access. The attacker's effective privilege is the union of the crew.

#### Possible mitigations

Treat inter-agent messages as untrusted input to the receiving agent; apply the same sanitization, delimiting, and instruction-stripping as for end-user prompts. Avoid mixing agents of different privilege levels in the same shared memory. Constrain each agent to the minimum tool set required for its role; do not permit privilege uplift through delegation.

#### Steps

Diagram the message and shared-memory channels between agents in the crew. For each channel, identify the privilege difference between sender and receiver and confirm receiver-side sanitization of inter-agent messages.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH231` — A self-hosted workflow automation platform with AI nodes may expose powerful credentials to anyone who can edit a workflow 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Lindy, n8n

#### Description

Workflow automation platforms (n8n, Lindy and similar) store provider credentials, downstream API keys, and database connection strings as workflow-scoped resources. The user who can edit a workflow can typically wire any stored credential into any node, including AI nodes that can be steered by external content. A user with workflow-edit rights — but no business-systems rights — can therefore exfiltrate or misuse those credentials by constructing a workflow that leaks them or invokes downstream APIs in their name.

#### Possible mitigations

Treat workflow-edit rights as equivalent to direct possession of every credential the workflow platform stores. Scope credentials to the minimum nodes/workflows that need them and segregate production from shared sandboxes. Require code review or change approval on workflow changes in production. Audit credential usage per workflow run.

#### Steps

List the credentials stored in the automation platform and the users who can edit each workflow. Confirm the edit-rights set matches the trust required to hold those credentials.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH235` — An agentic coding tool may take destructive actions on the developer's workstation or repositories without sufficient confirmation 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Antigravity, Claude Code, Cursor, Windsurf

#### Description

Agentic coding tools execute shell commands, write files, and increasingly perform git operations, package installs, deploy commands, and cloud API calls under the developer's credentials. If the tool is configured for low-friction autonomous operation (auto-approve all commands, no allowlist), a prompt injection from a README, dependency, or web page the tool reads can cause it to run destructive commands - rm, force-push, credential rotation, deploy-to-production - under the developer's full local privilege.

#### Possible mitigations

Operate the tool with explicit per-command confirmation for the categories of operations that are destructive or have external side effects (git push, package install, network calls, file delete, deploy). Maintain a short allowlist of auto-approved commands. Run agentic operations in isolated workspaces (containers, ephemeral VMs) without persistent credentials. Keep developer cloud and git credentials short-lived.

#### Steps

Document which command categories the tool can execute without confirmation, the credentials available in the execution environment, and the blast radius of those credentials. Confirm destructive categories require explicit approval.

**Documentation:** <https://genai.owasp.org/llmrisk/llm08-excessive-agency/>

---

### `TH253` — A capacity admin or service principal scoped to a Fabric capacity may exercise privilege across every workspace assigned to that capacity

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric, Microsoft Fabric Tenant, Microsoft Fabric Workspace

#### Description

Fabric capacity admins and service principals granted capacity-level access can manage and, depending on configuration, read items in every workspace assigned to the capacity. Concentrating multiple business-domain workspaces under a single shared capacity therefore concentrates privilege as well: a single compromised capacity-admin identity has the blast radius of every workload on the capacity.

#### Possible mitigations

Limit capacity admin assignments to the smallest possible set of human and service identities. Use Privileged Identity Management or just-in-time elevation for capacity admin where the identity provider supports it. Separate workspaces of materially different sensitivity onto separate capacities so that capacity-admin compromise has a bounded blast radius. Audit capacity admin changes.

#### Steps

List each capacity, the identities holding capacity admin, and the workspaces assigned. Confirm the capacity admin set is appropriately small, and that capacity boundaries follow data-classification boundaries.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/admin/microsoft-fabric-admin>

---

### `TH257` — A Fabric Data Engineering notebook or Spark job may execute arbitrary code under workspace-scoped credentials, escalating any contributor to the workspace's effective privilege

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Engineering

#### Description

Notebooks and Spark Job Definitions in Fabric Data Engineering execute Python, SQL, and Scala code that can read and write any OneLake item the workspace can reach, call external endpoints, and use any connection or library installed in the workspace. A user with Contributor on the workspace - or anyone who can submit a notebook for execution - can construct code that exercises the full union of the workspace's data access and outbound network privileges. This is a confused-deputy escalation through the workspace identity.

#### Possible mitigations

Constrain who can author and run notebooks in production workspaces. Separate development workspaces (where contributors run notebooks) from production workspaces (where automated, reviewed jobs run under managed identities with narrow scope). Restrict library and package installation to a curated set. Use private endpoints and outbound network policies where available to limit egress.

#### Steps

List each workspace where notebooks or Spark jobs run. Document who can author and execute, the credentials available at runtime, the outbound network policy, and the package install policy. Confirm the contributor set is appropriately bounded.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/spark-job-concurrency-and-queueing>

---

### `TH264` — A Fabric Data Activator rule may invoke external actions under a workspace-scoped identity that exceeds the rule author's intended privilege

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Data Activator

#### Description

Fabric Activator translates event patterns into automated actions: send email, trigger Power Automate flows, start a pipeline, call a webhook. The actions execute under the Activator item's identity, not the rule author's. If the identity holds broad permissions - to send mail from a service account, to trigger sensitive pipelines, or to call privileged webhooks - the act of authoring a rule effectively grants the author the ability to invoke those actions. Combined with weak control over the triggering event source, this can yield action invocations the operator did not intend.

#### Possible mitigations

Scope the Activator's outbound action identity to the minimum permissions required. Use separate Activator items with separate identities for actions of different sensitivity. Restrict rule authoring to identities trusted with the action set. Require approval for new rules that invoke external side effects (mail, pipelines, webhooks).

#### Steps

For each Activator item, list the outbound actions configured, the identity used to invoke them, and the rule authors. Confirm separation of duties between the action permission grant and the rule-authoring privilege.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/real-time-intelligence/data-activator/data-activator-introduction>

---

### `TH270` — A Fabric SQL Database may grant server-level administrative privilege to anyone with sufficient workspace role, conflating data-plane and control-plane access

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric SQL Database

#### Description

Fabric SQL Database (based on Azure SQL Database) ties the database admin role to the Fabric workspace role rather than to a separate database-level administrator. A workspace Member or Admin therefore holds privileges equivalent to Azure SQL DB owner: schema modification, user management, and full data access. Co-locating a Fabric SQL Database with other items in a broadly-shared workspace effectively grants every workspace contributor database-admin equivalence.

#### Possible mitigations

Place Fabric SQL Database items in workspaces dedicated to that database, with a tightly scoped role membership. Do not place Fabric SQL Database in a general-purpose workspace whose Contributor list is broad. Use database-level roles and security policies to enforce additional least-privilege within the database for application identities.

#### Steps

List each Fabric SQL Database, the workspace it lives in, and the workspace's role members. Confirm membership matches the trust required to hold database-admin equivalence.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/database/sql/overview>

---

### `TH288` — A workspace Contributor role may be permitted to manage some item permissions, enabling self- or peer-elevation that bypasses workspace role controls

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric Workspace

#### Description

Fabric workspace Contributor role grants edit access to items and the ability to manage item permissions on items the user owns. A contributor who creates a new lakehouse, semantic model, or data agent owns it and can therefore grant ReadAll or Reshare on it to other principals - including service principals or external guests - without involvement of a workspace Admin. The blast radius of compromised Contributor credentials therefore exceeds the workspace's apparent role assignments.

#### Possible mitigations

Restrict Contributor membership to identities trusted with item permission grants. Where create-and-share is not part of the contributor's role, downgrade them to Viewer with explicit item-level Read on what they need. Audit item-permission changes within each workspace and treat unexpected Reshare grants as security events. For high-sensitivity workspaces, consider tenant settings that restrict who can share items externally.

#### Steps

For each workspace, document the Contributor membership and the items each contributor owns. Confirm the resulting share-out potential matches the trust placed in those identities.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/fundamentals/roles-workspaces>

---

### `TH292` — A user-assigned managed identity attached to multiple Azure resources concentrates privilege across all of them, enabling lateral movement after a single compromise

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: App Service, Automation, Azure Kubernetes Service, Batch, Functions, LogicApp

#### Description

User-assigned managed identities can be attached to many Azure resources simultaneously - VMs, App Services, Functions, AKS pods, Logic Apps. The role assignments granted to that identity (e.g., Storage Blob Data Reader on a storage account, Key Vault Secrets User on a vault) apply to every resource that holds the identity. A workload compromise on any one of those resources gives the attacker the full set of permissions, and lateral movement extends to every other resource sharing the identity.

#### Possible mitigations

Use system-assigned managed identities by default, so each resource has a unique principal scoped to only its own role assignments. Where a user-assigned identity is required (e.g., for fixed identity across replacement of the underlying resource), restrict its attachment to a single resource or a small set of resources serving the same function. Audit the resources holding each user-assigned identity and the role assignments granted.

#### Steps

For each user-assigned managed identity, list the resources it is attached to and its role assignments. Confirm the attachments are coherent with the identity's purpose and that the blast radius is acceptable.

**Documentation:** <https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview>

---

### `TH294` — Cluster-wide Kubernetes RBAC bindings (cluster-admin, edit) on Azure Kubernetes Service grant escalation paths through pod exec, secret read, and ServiceAccount token impersonation

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Kubernetes Service

#### Description

AKS uses Kubernetes RBAC for in-cluster authorization. ClusterRoleBindings such as cluster-admin, edit, or admin grant their subjects sweeping permissions: read every Secret (including ServiceAccount tokens), exec into any pod, mount any volume, and create privileged workloads. A user or group bound at cluster scope can therefore escalate from any tenant or namespace into any other, regardless of namespace boundaries the design assumed. Service principals or workload identities used by CI/CD that hold cluster-admin become equivalent to subscription-owner for the cluster's data plane.

#### Possible mitigations

Bind users and service identities at namespace scope (RoleBinding) rather than cluster scope (ClusterRoleBinding) wherever possible. Avoid granting cluster-admin, edit, or admin to any identity except a small set of named cluster operators. Use Azure RBAC for Kubernetes Authorization to integrate with Entra-side governance and Conditional Access. Audit ClusterRoleBindings and ServiceAccount token usage.

#### Steps

List ClusterRoleBindings and the subjects bound to cluster-admin, edit, and admin. Confirm each is justified and monitored. Identify CI/CD or automation identities holding cluster-scope permissions and consider scope reduction.

**Documentation:** <https://learn.microsoft.com/en-us/azure/aks/concepts-identity>

---

### `TH299` — An Azure Batch user with submit permission can execute arbitrary code on every pool node, inheriting the pool's identity and network reach

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Batch

#### Description

Azure Batch pools execute customer-supplied tasks. A user with permission to submit jobs to a pool can run any binary or script as the pool's task user, reaching every resource the pool's managed identity can reach (storage, Key Vault, databases) and any network endpoint the pool's subnet can address. Pool reuse across teams concentrates this submit-anywhere primitive: a developer who can submit to the shared pool effectively has the pool's identity and network position.

#### Possible mitigations

Scope each Batch pool to a single workload class and a small named submitter set. Use separate pools for separate trust domains rather than reusing one pool across teams. Run tasks under the dedicated TaskUser identity, not pool-admin, where supported. Restrict the managed identities and network paths granted to each pool to what the workload requires.

#### Steps

List each Batch pool, the identities permitted to submit, the managed identities attached, and the network reach. Confirm submitter set matches the trust placed in the pool's identity.

**Documentation:** <https://learn.microsoft.com/en-us/azure/batch/security-best-practices>

---

### `TH308` — Azure SQL Managed Instance database admins (sysadmin / dbo) operate on a separate authorization plane from Azure RBAC and may not be governed by tenant identity policies

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure SQL Database Managed Instance

#### Description

Azure SQL Managed Instance has a database-level authorization plane (server admin, sysadmin, dbo, contained users) that is separate from Azure RBAC on the resource. A user removed from the Azure subscription may retain database-level access if their SQL login is not also removed; conversely, granting Contributor on the resource does not grant data access. Conditional Access, Privileged Identity Management, and lifecycle workflows applied at the Entra layer do not automatically remove SQL-level access.

#### Possible mitigations

Use Microsoft Entra-only authentication on SQL Managed Instance where possible and configure an Entra group as the SQL admin so membership changes flow through Entra lifecycle. Maintain a documented mapping of SQL principals to Entra principals and review on the same cadence as Azure RBAC. Treat SQL principals as access-grant artifacts that require deprovisioning at workforce changes.

#### Steps

For each SQL Managed Instance, document the SQL-level admin set, mapping to Entra identities, and the deprovisioning workflow. Confirm Entra and SQL are kept in sync.

**Documentation:** <https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview>

---

### `TH317` — Azure DevOps YAML pipelines that run on self-hosted agents may execute arbitrary code under the agent's service identity, escalating any pipeline editor to that identity's reach

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure DevOps, Azure DevOps Pipelines

#### Description

Azure DevOps Pipelines defined in YAML execute build and deployment steps on agents. Self-hosted agents typically run under a service account with credentials in environment variables, secrets in the agent's keystore, and network access to internal systems. A developer with pipeline edit rights - or anyone who can submit a pull request that triggers a pipeline (PR builds) - can introduce steps that exfiltrate the agent's credentials, steal pipeline variables, or pivot into the agent's network. Microsoft-hosted agents reduce some risk but do not eliminate access to pipeline secrets.

#### Possible mitigations

Require approval for pipeline runs on protected branches (branch policies, environment approvals). Mark sensitive variables as secret and scope them per pipeline rather than shared variable groups. Restrict self-hosted agent pools to specific projects or pipelines. Disable PR builds against protected branches or require human approval before execution. Use workload identity federation for cloud deployments rather than long-lived service connections.

#### Steps

For each pipeline that touches production, document the agent pool, the service identities and secrets accessible, the trigger configuration (branch, PR, schedule), and the approval gates.

**Documentation:** <https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview>

---

### `TH320` — Azure RBAC role assignments at Management Group or Subscription scope inherit to every resource within, concentrating privilege beyond what individual workloads require

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Azure Asset, Azure Service

#### Description

Azure RBAC role assignments are evaluated as the union of assignments at all scopes from Management Group through Resource. An Owner or Contributor assignment at Management Group scope grants that role on every subscription and every resource within - including workloads added later. Subscription-level Contributor likewise applies to every current and future resource group. Designs that grant elevated roles at high scope for convenience expand the blast radius of every assigned identity to the entire scope.

#### Possible mitigations

Assign roles at the lowest scope that satisfies the requirement (resource > resource group > subscription > management group). Use Privileged Identity Management for time-bound elevation rather than standing assignments at high scope. Periodically review high-scope assignments and downscope where possible. Treat Owner and User Access Administrator at Management Group or Subscription scope as security-critical with mandatory PIM and approval.

#### Steps

Inventory role assignments at Management Group and Subscription scope. For each, confirm the assigned principals require the scope's full extent and that PIM/approval gates apply to standing high-scope grants.

**Documentation:** <https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices>

---

### `TH324` — Power Automate flows built by end users execute on company systems under those users' identities, bypassing engineering change control and creating shadow integrations

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Power Automate

#### Description

Power Automate (and Power Apps) is positioned for citizen developers to build flows that connect Microsoft 365, third-party SaaS, and Azure services. Flows execute under the building user's identity (or a configured connection's identity) and can read mail, send messages, post to Teams, modify SharePoint items, and call REST APIs. Built outside the IT change-management process, these flows accumulate as undocumented integrations whose failure or compromise has business-process impact disproportionate to the user who authored them.

#### Possible mitigations

Govern Power Platform under tenant-level Data Loss Prevention policies that classify connectors (business, non-business, blocked) and prevent flows from combining connectors across classes that would bridge trust boundaries. Maintain an inventory of production-impacting flows. Restrict who can install premium connectors. Require review for flows that touch high-impact systems (Finance, HR, customer data).

#### Steps

Document the DLP policies in place. List flows touching production systems, their owners, and the systems they reach. Identify flows that should be migrated to IT-managed automation.

**Documentation:** <https://learn.microsoft.com/en-us/power-platform/admin/wp-data-loss-prevention>

---

### `TH330` — AWS IAM identity or resource policies using wildcard Action or Resource statements grant broader access than the workload requires 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Aurora, AWS Bedrock, AWS DocumentDB, AWS DynamoDB, AWS Neptune, AWS RDS, AWS Storage

#### Description

AWS IAM policy statements use Action and Resource fields that accept wildcards (s3:*, * Resource on a service). Designs that grant Action=* or Resource=* to a role for convenience, or that copy policies from documentation examples without scoping, give that role permission across the entire service or the entire account. A role intended to read one S3 bucket may end up able to delete every bucket; a role intended to publish to one SQS queue may end up able to manage IAM. Compromise of any consumer of the role inherits the over-broad scope.

#### Possible mitigations

Author IAM policies with explicit Resource ARNs (specific bucket, specific table, specific queue) and explicit Action lists (s3:GetObject rather than s3:*). Use IAM Access Analyzer to identify unused permissions and refine policies based on actual access patterns. Apply permission boundaries on roles delegated to less-trusted principals. Audit policy diffs as security-impacting changes.

#### Steps

List the IAM roles attached to each AWS resource in scope. For each role, document the Action and Resource scope of its policies and confirm scope matches the resource's actual needs. Run IAM Access Analyzer to identify unused or over-broad permissions.

**Documentation:** <https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html>

---

### `TH331` — AWS cross-account access via AssumeRole with weak trust policies allows any principal in the trusted account to invoke the role

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AWS Data

#### Description

Cross-account AWS access is granted through IAM roles whose trust policy lists external AWS account principals. A trust policy that lists Principal as 'arn:aws:iam::ACCOUNT:root' permits any IAM principal in ACCOUNT to call AssumeRole. Without an ExternalId condition or other condition keys, the trust is also vulnerable to the confused-deputy problem when the trusted account is a third-party SaaS: any of that vendor's customers could potentially trigger the role to act against your account.

#### Possible mitigations

In trust policies, restrict Principal to specific role/user ARNs in the partner account rather than the account root. For third-party-vendor cross-account access, require an ExternalId condition with a per-tenant value the vendor must supply. Use IAM Access Analyzer cross-account findings to surface unintended trust relationships. Audit the trust relationships of every role granting access to external accounts.

#### Steps

List roles in scope whose trust policy includes external AWS accounts. Document the principal scope and conditions on each. Confirm ExternalId is required for third-party SaaS trusts.

**Documentation:** <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html>

---

### `TH345` — AWS Bedrock Agent action groups invoke Lambda functions whose execution role may grant access beyond what the agent's user is authorized for 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Bedrock

#### Description

Bedrock Agents implement tool calling through action groups that map model-issued function calls to Lambda functions. The Lambda executes under its own execution role, not the calling user's identity. If the execution role holds broad permissions — DynamoDB read across multiple tables, S3 access across many buckets, write to downstream queues — a user who can invoke the agent (potentially through prompt injection or by simply asking) can cause those permissions to be exercised. The agent becomes a confused deputy through which the user's effective privilege exceeds their direct IAM grants.

#### Possible mitigations

Scope each Bedrock Agent's action-group Lambda execution role to the minimum operations required for that specific action. Use separate Lambdas (and separate execution roles) per action rather than a shared 'agent toolbox' Lambda with broad scope. Validate action-group inputs from the model against allowlists before performing privileged operations. Where actions affect external state, require user confirmation in the agent flow.

#### Steps

For each Bedrock Agent, list its action groups, the Lambda execution roles, the IAM scope of each role, and the input validation applied. Confirm role scope matches the minimum action requirement.

**Documentation:** <https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html>

---

### `TH359` — SaaS administrator roles granted to multiple operators concentrate full-tenant privilege without the just-in-time controls available for cloud platforms

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ADP, Adobe, Aero, Box Storage, Dynamics CRM, Expensify, Jira, Microsoft 365, Monday, Notion, Postmark, Power Automate, Power BI Platform, Salesforce, Slack, Trello, Workday, Zoom

#### Description

SaaS applications typically expose a small set of admin roles (Org Admin, Workspace Owner, Super Admin) that hold tenant-wide control: read every channel, modify every user, install any integration, change SSO settings, export all data. Unlike Azure or AWS where Privileged Identity Management or just-in-time elevation is available, most SaaS admin roles are static — once granted, they persist until manually revoked. Rosters of 'just in case' admins accumulate and become a concentrated risk: any one compromise yields the tenant.

#### Possible mitigations

Restrict SaaS admin assignments to a small named set with documented business justification. Require named individuals (not shared accounts) and unique credentials per admin. Where the SaaS supports it, separate admin roles by function (user mgmt, billing, security) rather than blanket org-admin. Review admin membership on a defined cadence (e.g., quarterly) and remove inactive or unjustified admins.

#### Steps

List admin role holders for each SaaS in scope. Document business justification, credential type, and review cadence.

**Documentation:** <https://csf.tools/reference/cloud-controls-matrix/v4-0/iam/iam-12/>

---

### `TH372` — Integration users in Salesforce and Dynamics CRM frequently hold broad permissions for convenience and become high-value targets

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Dynamics CRM, Dynamics CRM Portal, Salesforce

#### Description

Application integrations into Salesforce and Dynamics CRM (CTI integrations, marketing automation, MDM connectors, ETL pipelines) typically authenticate as a dedicated 'API user' or service principal. To avoid integration-time errors, these accounts are commonly granted System Administrator or Modify All Data — far more than any single integration requires. The credentials end up in many integration platforms' configurations, ETL job parameters, and middleware secret stores; compromise of any one yields effective tenant control of the CRM.

#### Possible mitigations

Create a dedicated integration user per integration with permissions scoped to the specific objects, fields, and actions that integration requires. Use OAuth client credentials flow with named OAuth-connected apps where possible, scoped to specific API names. Rotate API user credentials and OAuth client secrets on a defined cadence. Monitor API user activity for unexpected operations.

#### Steps

List integration users / service accounts in each CRM, their permissions, and the integrations that authenticate as them. Confirm scope minimization.

**Documentation:** <https://help.salesforce.com/s/articleView?id=sf.users_creating.htm>

---

### `TH388` — An AI Agent's tool surface may grant the agent privileges that exceed any single user's needs and become an escalation path 🤖

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent

#### Description

Agents are typically registered with a static set of tools whose union covers every scenario the agent might handle. The agent identity therefore holds the union of all those tool permissions, even when serving a user whose own role grants only a subset. An adversary who steers the agent through prompt injection, social engineering, or a compromised tool can cause it to invoke privileges no individual user should have aggregated.

#### Possible mitigations

Scope the tool set per user role, not per agent. Where the platform does not support per-user tool scoping, evaluate the user's authorization at tool-invocation time inside the tool implementation rather than at agent registration time. Avoid registering high-privilege tools on agents serving low-privilege users.

#### Steps

List every tool registered to the agent. For each, determine the permission it grants. Compare against the union of permissions of users the agent serves; flag any tool exceeding that union.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH393` — Apache Airflow Web UI roles may grant DAG-trigger or connection-edit privileges that bypass code-review on automation

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Apache Airflow

#### Description

The Airflow web UI exposes role-based actions including triggering DAG runs with arbitrary configuration JSON, editing Connection and Variable values, and clearing/marking task instances. Users with broad UI roles (Op, Admin) can invoke production automation with crafted payloads, change credentials live, or rewrite task state, without going through the code-review path that governs DAG files.

#### Possible mitigations

Restrict UI roles using Airflow's RBAC: separate DAG authors, operators, and admins. Disable trigger-with-config for production DAGs that should run only on schedule. Scope Connection and Variable edit rights to a small named set. Audit UI actions and feed them to the same review surface that watches code changes.

#### Steps

Enumerate UI roles assigned to each user. Confirm operators cannot edit production Connections or trigger sensitive DAGs with arbitrary config.

**Documentation:** <https://airflow.apache.org/docs/apache-airflow/stable/security/access-control.html>

---

### `TH397` — A Fabric Notebook that calls %run on another notebook executes that notebook's code in the caller's identity context, broadening the trust boundary

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Notebook

#### Description

The %run magic and equivalent notebook-utility calls execute another notebook's cells in the current Spark session, inheriting the caller's identity, mounted credentials, and library state. A maintainer of the called notebook (often a lower-trust user, since shared utility notebooks are often broadly editable) can execute arbitrary code in the caller's context every time the calling notebook runs. The trust boundary collapses to the union of editor sets across the call chain.

#### Possible mitigations

Restrict edit access on shared utility notebooks to the same trust set as the notebooks that call them. Prefer pip-installable libraries with versioned releases over %run for shared logic. Audit which notebooks reference others and treat the union of editors as the effective code-author set.

#### Steps

List notebooks scheduled in production. For each, enumerate %run targets and their editor sets. Confirm callers and callees share the same trust boundary.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/data-engineering/author-execute-notebook>

---

### `TH409` — OneLake shortcuts to external accounts may grant Fabric workloads broader access to the target account than the shortcut's intended path

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Crosses: Microsoft Fabric Boundary

#### Description

A shortcut from a Fabric Lakehouse or workspace to an external account (ADLS, S3, GCS) is created using a credential or assumed role with permissions on the target. Those permissions usually exceed the shortcut path: a shortcut to a single folder is backed by a credential that may grant container-level read or even write. A workload that gains the ability to redirect or extend the shortcut path can reach data the shortcut owner did not intend to expose.

#### Possible mitigations

Scope the credential or role backing each shortcut to the smallest possible target prefix. Restrict shortcut creation and modification to a narrow set of stewards. Re-validate shortcut credentials periodically against the principle of least privilege.

#### Steps

Inspect credentials backing each external shortcut. Confirm the target scope is limited to the shortcut path.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/onelake-shortcuts>

---

### `TH427` — OneLake DefaultReader role grants ReadAll across the lakehouse and may exceed the access intended by data stewards adding users to a workspace

**STRIDE:** `E` (Elevation of Privilege) • **Severity:** 🟥 High • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Microsoft Fabric OneLake

#### Description

When a user is added to a workspace with a role that maps to the OneLake DefaultReader, that user receives ReadAll across every item the role covers. Stewards typically add users to enable a specific report or query, expecting access to be limited to that artifact. The role grant in fact extends to all data the role covers, exposing data the steward did not intend.

#### Possible mitigations

Replace DefaultReader with explicit OneLake security roles scoped to the specific paths or items the user needs. Avoid using workspace-role addition as a fine-grained access mechanism. Document the data accessible to each role and review on grant.

#### Steps

Identify users granted via DefaultReader. Confirm each was intended to have ReadAll on the covered scope.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-onelake-security>

---

## `A` — Abuse (7)

> A legitimate user violates terms of use without breaking a security policy.

🤖 **5 of these threats are LLM-tagged.**

### `TH142` — A user tries to delete a resource from the Azure Subscription

**STRIDE:** `A` (Abuse) • **Severity:** 🟥 High • **Phase:** Implementation • **Effort:** Low

**Applies to:** Targets: Azure Asset, Azure Data Service, Azure Service • Source: Human User

#### Description

User can delete resources in Azure with malicious or non-malicious intent.

#### Possible mitigations

Protect Azure resources with resource manager locks

#### Steps

New-AzResourceLock -LockLevel CanNotDelete -LockName LockSite -ResourceName examplesite -ResourceType Microsoft.Web/sites -ResourceGroupName exampleresourcegroup

**Documentation:** <https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-lock-resources>

---

### `TH219` — A legitimate user may misuse the LLM to generate disallowed or policy-violating content 🤖

**STRIDE:** `A` (Abuse) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent and Orchestration Platform, AI Developer Platform, AI LLM Providers, AI Platform, AI Specialized Platform, AWS Bedrock, Bot Service, Claude Anthropic, Claude Code, Cognitive Services, Hugging Face, Lanchain

#### Description

An authenticated, authorized user can submit prompts that — while not technically bypassing access controls — direct the model to produce content that violates the system's terms of use, the provider's acceptable-use policy, applicable law, or the operator's brand and safety standards (e.g., harassing content, regulated advice, defamation, content targeting minors). The risk is design-relevant for any user-facing generative feature.

#### Possible mitigations

Define an acceptable-use policy specific to the application and surface it to users at sign-up and in-product. Apply input and output content classifiers aligned to that policy. Log policy-violating requests for review and apply graduated responses (refusal, warning, rate-limiting, account action). Where the underlying provider offers safety/moderation features, enable them and align thresholds with the application risk profile.

#### Steps

Document the application's acceptable-use boundaries. Identify the input and output classifiers that enforce them, the categories each covers, and the action taken on a violation. Confirm violations are logged and reviewable.

**Documentation:** <https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter>

---

### `TH242` — Authorized users may generate brand-damaging or non-compliant media that the organization is responsible for 🤖

**STRIDE:** `A` (Abuse) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: ElevenLabs, Midjourney, Synthesia

#### Description

When the design exposes generative image, video, or voice capability to internal users or customers, the organization becomes accountable for media that may be off-brand, discriminatory, regulated (financial advice, health claims), or attached to a real person without consent. Even when each generation is individually within the platform's terms, publication under the organization's name carries reputational and regulatory exposure.

#### Possible mitigations

Define an organization-specific acceptable-use policy for generated media that includes brand, regulatory, and consent boundaries. Apply pre-publication review or automated content classifiers aligned to that policy. Tag generated content with creator and prompt provenance for after-the-fact review. Restrict the named-persons set that generated media may depict.

#### Steps

Define the categories of media the organization will and will not publish. Implement a review or classifier gate before any generated media leaves an internal workspace. Confirm creator and prompt are logged.

**Documentation:** <https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter>

---

### `TH348` — AWS Bedrock model invocations without Guardrails attached rely entirely on the calling application for content safety, allowing harmful or policy-violating output 🤖

**STRIDE:** `A` (Abuse) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AWS Bedrock

#### Description

AWS Bedrock Guardrails provide content filtering, denied topics, sensitive information redaction, and harmful-content classification at the model invocation boundary. When a model is invoked without an attached Guardrail (the default), the application alone is responsible for input filtering, output classification, and policy enforcement. Applications that pass through user prompts and surface model output unchanged become channels for policy-violating content (harassment, PII leakage, off-topic responses) — exposing the operator to brand and regulatory risk.

#### Possible mitigations

Define an AWS Bedrock Guardrail aligned to the application's acceptable-use policy and attach it to every InvokeModel call. Configure denied topics, sensitive information filters (PII patterns to redact), and word filters as appropriate for the workload. Where the application has a stricter policy than the foundation model's defaults, encode that policy in the Guardrail. Audit invocations missing the Guardrail attachment as policy exceptions.

#### Steps

For each Bedrock invocation path, document whether a Guardrail is attached and the policy categories enforced. Confirm coverage matches the application's acceptable-use policy.

**Documentation:** <https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html>

---

### `TH389` — Authorized users may misuse an AI Agent to perform actions at scale or in patterns that violate intended use policies 🤖

**STRIDE:** `A` (Abuse) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: AI Agent

#### Description

An AI Agent that exposes powerful capabilities (mass email, bulk record updates, data export, code execution) lets an authorized user accomplish tasks faster than they could manually. Faster than intended often means at a scale or frequency that the original use policy did not contemplate: scraping internal data, sending bulk outreach, exporting customer records in batches small enough to evade per-call DLP. The actions are individually authorized but collectively abusive.

#### Possible mitigations

Define and enforce per-user usage envelopes (rate, volume, sensitivity-tiered limits) on agent actions independent of per-call authorization. Surface aggregate behavior to the user (and to a reviewer) so a pattern of abuse is visible. Require step-up confirmation for actions that cross volume or sensitivity thresholds.

#### Steps

Classify the agent's actions by sensitivity and volume. For each class, define a per-user envelope. Implement aggregation that detects when a user approaches the envelope.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

### `TH399` — An authorized Fabric Notebook user may exfiltrate data through interactive cell output, downloads, or copy-to-clipboard rendering

**STRIDE:** `A` (Abuse) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Medium

**Applies to:** Targets: Fabric Notebook

#### Description

A user authorized to query a Lakehouse, Warehouse, or other Fabric source through a notebook can render arbitrary query results in cells, copy them to clipboard, download them, or persist them to the user's personal workspace or attached storage. The action is within the user's authorization on the source, but the destination (personal workspace, local download) is outside the controls applied to the source. The agent of exfiltration is a legitimate user.

#### Possible mitigations

Apply DLP and information protection labels to data at the source so labels travel with query results. Restrict notebook download and personal-workspace use for users querying classified sources. Monitor large or unusual notebook output volumes.

#### Steps

Identify users who query sensitive sources from notebooks. Confirm DLP and label-inheritance policy applies to notebook outputs.

**Documentation:** <https://learn.microsoft.com/en-us/fabric/governance/information-protection>

---

### `TH410` — An LLM provider may retain prompts, completions, or fine-tuning data beyond the user's expectation and use them to improve future models 🤖

**STRIDE:** `A` (Abuse) • **Severity:** 🟧 Medium • **Phase:** Design • **Effort:** Low

**Applies to:** Targets: AI LLM Providers, ChatGPT OpenAI, Grok xAI

#### Description

Provider terms vary: some retain prompts and completions for abuse monitoring, model improvement, or training future models, with retention periods that may not match the user's data-handling requirements. A prompt that cleared internal DLP because it was bound for a sanctioned provider may still be retained, copied to training pipelines, or surfaced in human-review samples. Negotiated enterprise terms differ from default consumer terms.

#### Possible mitigations

Choose enterprise tiers with explicit zero-retention or short-retention contracts. Document the negotiated retention term per provider and verify it aligns with data classification policy. Forbid sending classified data to providers without explicit zero-retention guarantees.

#### Steps

Document each LLM provider's contracted retention. Map data classifications to permitted providers under those terms.

**Documentation:** <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

---

## 🤖 LLM threats — quick index

Sixty-eight threats target AI/LLM stencils directly (LLM providers, managed AI platforms, agent / orchestration frameworks, agentic developer tools, specialised media platforms, Fabric Data Agent / IQ, and the AI Agent interactor). They map onto STRIDE+A as follows:

| ID | STRIDE | Severity | Title |
| --- | :---: | :---: | --- |
| `TH200` | `S` | High | An adversary may impersonate a tool or downstream service in an LLM agent's tool-calling chain |
| `TH201` | `S` | High | An adversary may impersonate the LLM provider endpoint and return crafted completions |
| `TH202` | `T` | High | An adversary may alter LLM behavior through direct prompt injection in user input |
| `TH203` | `T` | High | An adversary may inject instructions via untrusted retrieved content (indirect prompt injection) |
| `TH204` | `T` | High | An adversary may poison training, fine-tuning, or RLHF data to alter model behavior |
| `TH205` | `T` | High | An adversary may poison a vector store or embedding index used for retrieval |
| `TH206` | `T` | High | An adversary may tamper with model artifacts pulled from a model registry or hub |
| `TH207` | `R` | Medium | A user or service may repudiate LLM interactions due to insufficient prompt and completion logging |
| `TH208` | `R` | High | An LLM agent may repudiate actions due to missing tool-invocation audit trail |
| `TH209` | `I` | High | An adversary may extract sensitive data through model completions |
| `TH210` | `I` | High | An adversary may extract memorized training or fine-tuning data from the model |
| `TH211` | `I` | High | An adversary may receive context belonging to another tenant or session due to shared model state |
| `TH212` | `I` | High | Sensitive data may be disclosed to a third-party LLM provider beyond the data's authorized boundary |
| `TH213` | `I` | Medium | An adversary with access to embedding vectors may reconstruct sensitive source content |
| `TH214` | `D` | High | An adversary may exhaust budget or quota by triggering high-cost LLM calls (denial of wallet) |
| `TH215` | `D` | Medium | An adversary may saturate the model context window with crafted inputs to deny service |
| `TH216` | `E` | High | An LLM agent may exceed its intended privilege through over-broad tool permissions (excessive agenc… |
| `TH217` | `E` | High | An adversary may elevate privilege through insecure plugin or function-calling design |
| `TH218` | `E` | High | Improper handling of LLM output may enable downstream code execution or injection (insecure output… |
| `TH219` | `A` | Medium | A legitimate user may misuse the LLM to generate disallowed or policy-violating content |
| `TH220` | `S` | Medium | An LLM may produce fabricated outputs that spoof authoritative sources or identities |
| `TH221` | `I` | High | Sensitive business data may be sent to a consumer-tier LLM provider lacking enterprise data controls |
| `TH222` | `I` | Medium | Search-augmented LLM providers may expose query terms or context to third-party search infrastructu… |
| `TH223` | `T` | High | Real-time social-media-grounded providers may ingest attacker-authored posts as model context |
| `TH224` | `I` | High | Self-hosted open-weights deployments may expose model weights or inference logs through misconfigur… |
| `TH225` | `I` | High | Sending prompts to a provider headquartered in a high-risk jurisdiction may expose data to legal co… |
| `TH226` | `E` | High | A managed AI platform's broad IAM role may grant cross-account or cross-project model access |
| `TH227` | `T` | High | A unified data + ML platform may allow poisoning of training data through the data-engineering surf… |
| `TH228` | `I` | Medium | MLOps experiment-tracking metadata may disclose proprietary model design and training data details |
| `TH229` | `S` | High | A managed AI platform may route inference to an attacker-substituted custom model deployment |
| `TH230` | `E` | High | A compromised agent in a multi-agent system may escalate by injecting instructions into peer agents… |
| `TH231` | `E` | High | A self-hosted workflow automation platform with AI nodes may expose powerful credentials to anyone… |
| `TH232` | `T` | High | An orchestration framework may load attacker-supplied chains, tools, or templates that execute on i… |
| `TH233` | `R` | Medium | No-code AI agent platforms may allow business users to deploy agents that act on company systems wi… |
| `TH234` | `I` | High | An agentic coding tool may transmit proprietary source code, secrets, or customer data to its model… |
| `TH235` | `E` | High | An agentic coding tool may take destructive actions on the developer's workstation or repositories… |
| `TH236` | `T` | High | An agentic coding tool may follow injected instructions hidden in repository content or third-party… |
| `TH237` | `I` | Medium | IDE-integrated AI tools may build and transmit an index of the entire workspace, including out-of-s… |
| `TH238` | `T` | High | An installable AI tool extension or MCP server may compromise the developer environment at install… |
| `TH239` | `T` | High | A Hugging Face Space, dataset loader, or model card may execute attacker code when consumed |
| `TH240` | `S` | High | Voice or avatar synthesis platforms may be used to impersonate real people in attacks against the o… |
| `TH241` | `I` | Medium | Generative media outputs may inadvertently reproduce protected training samples or customer-supplie… |
| `TH242` | `A` | Medium | Authorized users may generate brand-damaging or non-compliant media that the organization is respon… |
| `TH243` | `R` | Medium | Generated media released without provenance metadata may be repudiated or, conversely, mistaken for… |
| `TH244` | `D` | Medium | A publicly-reachable Hugging Face Space or self-hosted inference endpoint may be enumerated and abu… |
| `TH254` | `I` | High | A Fabric Data Agent grounding multiple data sources may surface data from one source through querie… |
| `TH255` | `T` | High | A Fabric Data Agent may be steered by injected instructions in agent metadata, ontology bindings, o… |
| `TH256` | `R` | Medium | Lack of paired logging of natural-language input and translated SQL/DAX/KQL leaves Fabric Data Agen… |
| `TH260` | `I` | High | A Fabric IQ ontology may make implicit joins across source systems queryable by callers who hold no… |
| `TH276` | `S` | High | A Fabric Data Agent invocation that supplies a service principal token will not authenticate as tha… |
| `TH330` | `E` | High | AWS IAM identity or resource policies using wildcard Action or Resource statements grant broader ac… |
| `TH345` | `E` | High | AWS Bedrock Agent action groups invoke Lambda functions whose execution role may grant access beyon… |
| `TH346` | `T` | High | AWS Bedrock Knowledge Bases ingest documents from S3 sources that may be writable by less-trusted c… |
| `TH347` | `R` | Medium | AWS Bedrock model invocation logging is disabled by default; without it, prompts and completions ar… |
| `TH348` | `A` | Medium | AWS Bedrock model invocations without Guardrails attached rely entirely on the calling application… |
| `TH383` | `S` | High | An AI Agent acting on behalf of a user may present unverified identity claims to downstream services |
| `TH384` | `T` | High | An AI Agent's tool definitions, system prompt, or memory store may be tampered with to alter its be… |
| `TH385` | `R` | High | Actions taken by an AI Agent may be unattributable to either the agent or the user that triggered t… |
| `TH386` | `I` | High | An AI Agent's context window may aggregate data from multiple authorization scopes and disclose it… |
| `TH387` | `D` | Medium | An AI Agent may enter a tool-call loop or context-expansion loop that exhausts compute, tokens, or… |
| `TH388` | `E` | High | An AI Agent's tool surface may grant the agent privileges that exceed any single user's needs and b… |
| `TH389` | `A` | Medium | Authorized users may misuse an AI Agent to perform actions at scale or in patterns that violate int… |
| `TH410` | `A` | Medium | An LLM provider may retain prompts, completions, or fine-tuning data beyond the user's expectation… |
| `TH411` | `T` | High | An agent orchestration framework may allow tool outputs to influence subsequent tool selection, ena… |
| `TH412` | `D` | Medium | LLM provider rate limits, quota exhaustion, or model deprecation may cause dependent application fu… |
| `TH413` | `I` | Medium | LLM completions may regurgitate memorized training data or fine-tuning corpus content, disclosing m… |
| `TH414` | `R` | Medium | Multi-agent orchestrations may distribute decision-making across agents in a way that no single log… |
| `TH425` | `S` | Medium | Fabric IQ ontology callers may rely on cached resolution that lags behind ontology revisions, produ… |
| `TH426` | `R` | Medium | Fabric IQ query history may not preserve the ontology version, source bindings, and resolved query… |

## Appendix A — Master threat index

All 365 threats sorted by ID, with one-line summaries. 🤖 marks LLM-relevant threats. Severity codes: H = High, M = Medium, L = Low. Phase codes: D = Design, I = Implementation.

| ID | LLM | S | Sv | Ph | Title | Targets |
| --- | :---: | :---: | :---: | :---: | --- | --- |
| `TH1` | · | `E` | H | I | An adversary can gain unauthorized access to database due to lack of network access prote… | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH2` | · | `E` | H | I | An adversary can gain unauthorized access to {target.Name} due to weak account policy | Database |
| `TH3` | · | `R` | M | I | An adversary can deny actions on database due to lack of auditing | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH4` | · | `E` | H | I | An adversary can gain unauthorized access to {target.Name} due to loose authorization rul… | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH5` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing traffic to database | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH6` | · | `I` | H | I | An adversary can gain access to sensitive PII or HBI data in {target.Name} | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH7` | · | `S` | H | I | An adversary can steal sensitive data like user credentials | API App, WCF, Web API, Web Application |
| `TH8` | · | `S` | H | I | Attacker can steal user session cookies due to insecure cookie attrbutes | API App, WCF, Web API, Web Application |
| `TH9` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing traffic to Web Application | Web Application |
| `TH10` | · | `E` | H | I | An adversary can gain unauthorized access to Azure SQL database due to weak account policy | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH11` | · | `S` | H | I | An adversary can bypass authentication due to non-standard Azure AD authentication schemes | Active Directory, Microsoft Entra ID |
| `TH12` | · | `S` | H | I | An adversary can get access to a user's session by replaying authentication tokens | Active Directory, Microsoft Entra ID |
| `TH13` | · | `S` | H | O | An adversary can gain unauthorized access to API end points due to unrestricted cross dom… | Web API |
| `TH14` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing traffic to Azure Redis Cache | Azure Redis Cache |
| `TH15` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing traffic from Mobile client | Mobile Client |
| `TH16` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing traffic to Web API | Web API |
| `TH17` | · | `E` | H | I | An adversary can gain unauthorized access to {target.Name} due to weak access control res… | Azure Storage |
| `TH18` | · | `I` | H | I | An adversary can gain access to unencrypted sensitive data stored in {target.Name} | Azure Storage |
| `TH19` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing unencrypted SMB traffic to {ta… | Azure Storage |
| `TH20` | · | `R` | M | I | An adversary can deny actions on {target.Name} due to lack of auditing | Azure Storage |
| `TH21` | · | `S` | H | I | An adversary can gain unauthorized access to {target.Name} due to weak CORS configuration | Azure Storage, CosmosDB |
| `TH22` | · | `S` | H | I | An adversary can get access to a user's session due to improper logout and timeout | API App, WCF, Web API, Web Application |
| `TH23` | · | `S` | H | I | An adversary can get access to a user's session due to insecure coding practices | API App, WCF, Web API, Web Application |
| `TH24` | · | `T` | H | I | An adversary can deface the target web application by injecting malicious code or uploadi… | API App, WCF, Web API, Web Application |
| `TH26` | · | `D` | H | I | An adversary can perform action on behalf of other user due to lack of controls against c… | Web Application |
| `TH27` | · | `E` | H | I | An adversary may bypass critical steps or perform actions on behalf of other users (victi… | Web Application |
| `TH30` | · | `R` | M | I | Attacker can deny the malicious act and remove the attack foot prints leading to repudiat… | Web Application |
| `TH31` | · | `I` | H | I | An adversary can gain sensitive data from mobile device | Mobile Client |
| `TH32` | · | `S` | H | I | An adversary can spoof the target web application due to insecure TLS certificate configu… | API App, WCF, Web API, Web Application |
| `TH33` | · | `T` | H | I | An attacker steals messages off the network and replays them in order to steal a user's s… | API App, WCF, Web API, Web Application |
| `TH34` | · | `R` | H | D | An adversary can deny actions on Cloud Gateway due to lack of auditing | IoT Cloud Gateway |
| `TH35` | · | `S` | H | D | An adversary may spoof {source.Name} with a fake one | IoT Cloud Gateway, IoT Field Gateway |
| `TH36` | · | `S` | H | D | An adversary may reuse the authentication tokens of {source.Name} in another | IoT Cloud Gateway, IoT Field Gateway |
| `TH37` | · | `E` | H | D | An adversary may gain elevated privileges on {target.Name} | IoT Cloud Gateway |
| `TH38` | · | `I` | H | D | An adversary may eavesdrop the traffic to cloud gateway | IoT Cloud Gateway |
| `TH39` | · | `T` | H | D | An adversary may exploit known vulnerabilities in unpatched devices | IoT Device, IoT Field Gateway |
| `TH40` | · | `S` | H | I | An adversary may auto-generate valid authentication tokens for IoT Hub | IoT Cloud Gateway |
| `TH41` | · | `E` | H | I | An adversary may gain unauthorized access to privileged features on {source.Name} | IoT Device, IoT Field Gateway |
| `TH42` | · | `E` | H | D | An adversary may trigger unauthorized commands on the {target.Name} Device | IoT Device |
| `TH43` | · | `T` | H | D | An adversary may tamper {source.Name}  and extract cryptographic key material from it | IoT Device, IoT Field Gateway |
| `TH44` | · | `S` | H | I | An adversary may replay stolen long-lived SaS tokens of IoT Hub | IoT Cloud Gateway |
| `TH45` | · | `T` | H | I | An adversary may attempt to intercept encrypted traffic sent to {target.Name} | IoT Device, IoT Field Gateway |
| `TH46` | · | `T` | H | D | An adversary may execute unknown code on {target.Name} | IoT Device, IoT Field Gateway |
| `TH47` | · | `T` | H | D | An adversary may tamper the OS of a device and launch offline attacks | IoT Device |
| `TH48` | · | `E` | H | I | An adversary may exploit unused services or features in {target.Name} | IoT Device, IoT Field Gateway |
| `TH49` | · | `R` | H | D | An adversary can deny actions on Field Gateway due to lack of auditing | IoT Field Gateway |
| `TH50` | · | `S` | H | D | An adversary may spoof a device and connect to field gateway | IoT Field Gateway |
| `TH51` | · | `E` | H | D | An adversary may trigger unauthorized commands on the {target.Name} gateway | IoT Field Gateway |
| `TH52` | · | `I` | H | D | An adversary may eavesdrop the communication between the device and the field gateway | IoT Field Gateway |
| `TH53` | · | `I` | H | D | An adversary may gain access to sensitive clear-text data in CosmosDB | CosmosDB |
| `TH54` | · | `E` | H | D | An adversary may gain elevated privileges on {target.Name} NoSQL Database | CosmosDB |
| `TH55` | · | `S` | H | I | An adversary may replay stolen long-lived Resource tokens of CosmosDB | CosmosDB |
| `TH56` | · | `E` | H | I | An adversary may read unauthorized content stored in {target.Name} | CosmosDB |
| `TH57` | · | `E` | H | I | An adversary may directly connect to {target.Name} from anywhere | CosmosDB |
| `TH58` | · | `S` | H | I | An adversary may spoof a device by reusing the authentication tokens of one device in ano… | Azure Event Hub |
| `TH59` | · | `E` | H | D | An adversary may exploit the permissions provisioned to the device token to gain elevated… | Azure Event Hub, Event Grid, IoT Hub, Service Bus |
| `TH60` | · | `E` | H | D | An adversary bypass the secure functionalities of the {target.Name} if devices authentica… | Azure Event Hub, Event Grid, IoT Hub, Service Bus |
| `TH61` | · | `T` | H | D | An adversary may eavesdrop the communication between the a client and Event Hub, IoT Hub,… | Azure Event Hub, Event Grid, IoT Hub, Service Bus |
| `TH62` | · | `E` | H | D | An adversary may gain elevated privileges on {target.Name} (Service Bus Technologies) | Azure Event Hub, Event Grid, IoT Hub, Service Bus |
| `TH63` | · | `I` | M | I | An adversary can abuse poorly managed {target.Name}'s access keys | Azure Storage, CosmosDB |
| `TH64` | · | `E` | M | I | An adversary can gain unauthorized access to all entities in {target.Name}'s tables | Azure Storage |
| `TH65` | · | `I` | M | I | An adversary can gain access to sensitive data by sniffing traffic between {source.Name}… | Azure Storage |
| `TH66` | · | `T` | H | I | An adversary can tamper the data uploaded to {target.Name} when HTTPS cannot be enabled | Azure Storage |
| `TH67` | · | `E` | H | I | An adversary may gain unauthorized access to {target.Name} account in a subscription | Azure Data Service |
| `TH68` | · | `S` | H | I | An adversary may gain unauthorized access to resources in Service Fabric | crosses Service Fabric Trust Boundary |
| `TH69` | · | `S` | H | I | An adversary can spoof a node and access Service Fabric cluster | crosses Service Fabric Trust Boundary |
| `TH70` | · | `S` | H | D | An adversary can potentially spoof a client if weaker client authentication channels are… | crosses Service Fabric Trust Boundary |
| `TH71` | · | `E` | H | I | An adversary may gain unauthorized access to Service Fabric cluster operations | crosses Service Fabric Trust Boundary |
| `TH72` | · | `S` | H | B | An adversary can spoof a node in Service Fabric cluster by using stolen certificates | crosses Service Fabric Trust Boundary |
| `TH73` | · | `I` | H | I | An adversary can gain access to unencrypted secrets in Service Fabric applicatinos | crosses Service Fabric Trust Boundary |
| `TH74` | · | `S` | H | I | An adversary obtains refresh or access tokens from {source.Name} and uses them to obtain… | API App, WCF, Web API |
| `TH75` | · | `S` | H | I | An adversary can get access to a user's session due to improper logout from Azure AD | Microsoft Entra ID |
| `TH76` | · | `S` | H | I | An adversary can get access to a user's session due to improper logout from ADFS | ADFS |
| `TH77` | · | `R` | H | I | An adversary can deny actions on Azure App Service due to lack of auditing | Web Application |
| `TH78` | · | `I` | H | I | An adversary can gain access to sensitive data by sniffing traffic to Azure Web App | Web Application |
| `TH79` | · | `I` | L | I | An adversary can fingerprint an Azure web application by leveraging server header informa… | Web Application |
| `TH80` | · | `I` | M | I | An adversary can gain access to certain pages or the site as a whole. | Web Application |
| `TH81` | · | `S` | H | I | An adversary can create a fake website and launch phishing attacks | API App, WCF, Web API, Web Application |
| `TH82` | · | `I` | H | I | An adversary can gain access to sensitive data by performing SQL injection | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH83` | · | `I` | M | I | An adversary can gain access to sensitive data stored in Web API's config files | Web API |
| `TH85` | · | `S` | H | I | An adversary can access Azure storage blobs and containers anonymously | Azure Storage |
| `TH86` | · | `S` | H | D | An adversary may spoof {source.Name} and gain access to Web Application | API App, WCF, Web API, Web Application |
| `TH87` | · | `S` | H | D | An adversary may spoof {source.Name} and gain access to Web API | API App, WCF, Web API, Web Application |
| `TH88` | · | `T` | H | D | An adversary can tamper with Data Factory and can cause undesirable consequences | Azure Data Factory, Azure Data Service |
| `TH89` | · | `T` | H | D | An adversary may leverage the lack of monitoring systems and trigger anamolous traffic to… | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH90` | · | `E` | H | D | An adversary may gain unauthorized access to {target.Name} if connection is insecure | Azure Data Factory, LogicApp |
| `TH91` | · | `D` | H | I | An adversary can leverage the weak scalability of token cache and cause DoS | Microsoft Entra ID |
| `TH92` | · | `T` | H | D | An adversary may gain unauthorized access to IoT Field Gateway and tamper its OS | IoT Field Gateway |
| `TH93` | · | `I` | H | D | An adversary may gain access to sensitive data stored in Azure Virtual Machines | crosses Azure IaaS VM Trust Boundary |
| `TH94` | · | `I` | H | I | An adversary can gain access to sensitive information through error messages | Web Application |
| `TH95` | · | `T` | H | D | An adversary can reverse engineer and tamper binaries | Mobile Client |
| `TH96` | · | `T` | H | I | An adversary can gain access to sensitive data by performing SQL injection through Web App | API App, WCF, Web API, Web Application |
| `TH97` | · | `T` | H | I | An adversary can gain access to sensitive data by performing SQL injection through Web API | Web API |
| `TH98` | · | `T` | H | I | An adversary can gain access to sensitive data stored in Web App's config files | Web Application |
| `TH99` | · | `I` | H | I | An adversary may gain access to sensitive data from uncleared browser cache | Web Application |
| `TH100` | · | `T` | H | I | An adversary can execute remote code on the server through XSLT scripting | Web Application |
| `TH101` | · | `I` | H | I | An adversary can reverse weakly encrypted or hashed content | Web Application |
| `TH102` | · | `I` | H | I | An adversary may gain access to sensitive data from log files | Web Application |
| `TH103` | · | `I` | H | I | An adversary may gain access to unmasked sensitive data such as credit card numbers | Web Application |
| `TH104` | · | `E` | H | D | An adversary may jail break into a mobile device and gain elevated privileges | Mobile Client |
| `TH105` | · | `T` | H | I | An adversary can tamper critical database securables and deny the action | Analysis Services, Azure Database for MariaDB, Azure D… |
| `TH106` | · | `I` | H | I | An adversary can gain access to sensitive information from an API through error messages | Web API |
| `TH107` | · | `I` | H | I | An adversary may retrieve sensitive data (e.g, auth tokens) persisted in browser storage | Web API |
| `TH108` | · | `T` | H | I | An adversary may inject malicious inputs into an API and affect downstream processes | API App, WCF, Web API, Web Application |
| `TH109` | · | `R` | H | D | Attacker can deny a malicious act on an API leading to repudiation issues | API App, WCF, Web API, Web Application |
| `TH110` | · | `E` | H | I | An adversary may gain unauthorized access to {target.Name} due to poor access control che… | Web API |
| `TH112` | · | `D` | H | D | An adversary can leverage the weak scalability of Identity Server's token cache and cause… | Identity Server |
| `TH115` | · | `I` | H | D | An adversary may sniff the data sent from Identity Server | Identity Server |
| `TH116` | · | `E` | H | D | An adversary can can gain unauthorized access to resources in an Azure subscription | crosses Azure Trust Boundary |
| `TH117` | · | `S` | H | D | An adversary may spoof an Azure administrator and gain access to Azure subscription portal | Azure Portal |
| `TH118` | · | `R` | H | D | A malicious user can deny they made a change to {target.Name} | Dynamics CRM |
| `TH119` | · | `I` | M | D | Sensitive attributes or fields on an Entity can be inadvertantly disclosed | Dynamics CRM |
| `TH120` | · | `E` | H | I | An adversary can bypass built in security through Custom Services or ASP.NET Pages which… | Dynamics CRM |
| `TH121` | · | `I` | H | D | Sensitive Entity records (containing PII, HBI information) can be inadvertantly disclosed… | Dynamics CRM |
| `TH124` | · | `E` | H | D | Misconfiguration of Security Roles, Business Unit or Teams | Dynamics CRM |
| `TH125` | · | `E` | H | I | Misuse of the Share feature | Dynamics CRM |
| `TH126` | · | `I` | M | I | Secure system configuration information exposed via JScript | Dynamics CRM |
| `TH127` | · | `I` | M | I | Secure system configuration information exposed when a DotNET exception is thrown | Dynamics CRM |
| `TH128` | · | `E` | H | D | Users with CRM Portal access are inadvertantly given access to sensitive records and data | Dynamics CRM Portal |
| `TH129` | · | `S` | H | I | An adversary may gain access to the field gateway by leveraging default login credentials. | IoT Cloud Gateway |
| `TH130` | · | `D` | L | I | An Adversary can launch DoS attack on WCF if Throttling in not enabled | WCF |
| `TH131` | · | `I` | M | I | An Adversary can sniff communication channel and steal the secrets | WCF |
| `TH132` | · | `T` | M | I | An Adversary can view the message and may tamper the message | WCF |
| `TH133` | · | `S` | H | I | An adversary may guess the client id and secrets of registered applications and impersona… | Identity Server |
| `TH134` | · | `T` | H | D | An adversary may spread malware, steal or tamper data due to lack of endpoint protection… | crosses Machine Trust Boundary |
| `TH135` | · | `E` | H | I | An adversary may gain unauthorized access to data on host machines | crosses Machine Trust Boundary |
| `TH136` | · | `E` | H | I | An adversary may gain elevated privileges and execute malicious code on host machines | crosses Machine Trust Boundary |
| `TH137` | · | `T` | H | I | An adversary may reverse engineer deployed binaries | crosses Machine Trust Boundary |
| `TH138` | · | `T` | H | D | An adversary may tamper deployed binaries | crosses Machine Trust Boundary |
| `TH139` | · | `I` | H | D | An adversary may gain access to sensitive data stored on host machines | crosses Machine Trust Boundary |
| `TH140` | · | `E` | H | D | A compromised access key may permit an adversary to have more access than intended to an… | CosmosDB |
| `TH141` | · | `E` | H | I | An adversary can gain unauthorized access to Azure Cosmos DB instances due to weak networ… | CosmosDB |
| `TH142` | · | `A` | H | I | A user tries to delete a resource from the Azure Subscription. | Azure Asset, Azure Data Service, Azure Service |
| `TH200` | 🤖 | `S` | H | D | An adversary may impersonate a tool or downstream service in an LLM agent's tool-calling… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH201` | 🤖 | `S` | H | D | An adversary may impersonate the LLM provider endpoint and return crafted completions | AI LLM Providers, AI Platform |
| `TH202` | 🤖 | `T` | H | D | An adversary may alter LLM behavior through direct prompt injection in user input | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH203` | 🤖 | `T` | H | D | An adversary may inject instructions via untrusted retrieved content (indirect prompt inj… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH204` | 🤖 | `T` | H | D | An adversary may poison training, fine-tuning, or RLHF data to alter model behavior | AI Developer Platform, AI Platform, AI Specialized Pla… |
| `TH205` | 🤖 | `T` | H | D | An adversary may poison a vector store or embedding index used for retrieval | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH206` | 🤖 | `T` | H | D | An adversary may tamper with model artifacts pulled from a model registry or hub | AI Platform, AI Specialized Platform, Hugging Face |
| `TH207` | 🤖 | `R` | M | D | A user or service may repudiate LLM interactions due to insufficient prompt and completio… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH208` | 🤖 | `R` | H | D | An LLM agent may repudiate actions due to missing tool-invocation audit trail | AI Agent and Orchestration Platform, Claude Code, Lanc… |
| `TH209` | 🤖 | `I` | H | D | An adversary may extract sensitive data through model completions | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH210` | 🤖 | `I` | H | D | An adversary may extract memorized training or fine-tuning data from the model | AI Developer Platform, AI Platform, AI Specialized Pla… |
| `TH211` | 🤖 | `I` | H | D | An adversary may receive context belonging to another tenant or session due to shared mod… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH212` | 🤖 | `I` | H | D | Sensitive data may be disclosed to a third-party LLM provider beyond the data's authorize… | AI LLM Providers, AI Platform, AI Specialized Platform… |
| `TH213` | 🤖 | `I` | M | D | An adversary with access to embedding vectors may reconstruct sensitive source content | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH214` | 🤖 | `D` | H | D | An adversary may exhaust budget or quota by triggering high-cost LLM calls (denial of wal… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH215` | 🤖 | `D` | M | D | An adversary may saturate the model context window with crafted inputs to deny service | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH216` | 🤖 | `E` | H | D | An LLM agent may exceed its intended privilege through over-broad tool permissions (exces… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH217` | 🤖 | `E` | H | D | An adversary may elevate privilege through insecure plugin or function-calling design | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH218` | 🤖 | `E` | H | D | Improper handling of LLM output may enable downstream code execution or injection (insecu… | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH219` | 🤖 | `A` | M | D | A legitimate user may misuse the LLM to generate disallowed or policy-violating content | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH220` | 🤖 | `S` | M | D | An LLM may produce fabricated outputs that spoof authoritative sources or identities | AI Agent and Orchestration Platform, AI Developer Plat… |
| `TH221` | 🤖 | `I` | H | D | Sensitive business data may be sent to a consumer-tier LLM provider lacking enterprise da… | ChatGPT OpenAI, DeepSeek, Gemini Google, Grok xAI, Per… |
| `TH222` | 🤖 | `I` | M | D | Search-augmented LLM providers may expose query terms or context to third-party search in… | Grok xAI, Perplexity |
| `TH223` | 🤖 | `T` | H | D | Real-time social-media-grounded providers may ingest attacker-authored posts as model con… | Grok xAI, Perplexity |
| `TH224` | 🤖 | `I` | H | D | Self-hosted open-weights deployments may expose model weights or inference logs through m… | DeepSeek |
| `TH225` | 🤖 | `I` | H | D | Sending prompts to a provider headquartered in a high-risk jurisdiction may expose data t… | ChatGPT OpenAI, Claude Anthropic, DeepSeek, Gemini Goo… |
| `TH226` | 🤖 | `E` | H | D | A managed AI platform's broad IAM role may grant cross-account or cross-project model acc… | AWS Bedrock, DataRobot, Databricks, Vertex, Watson IBM |
| `TH227` | 🤖 | `T` | H | D | A unified data + ML platform may allow poisoning of training data through the data-engine… | DataRobot, Databricks, Vertex, Watson IBM |
| `TH228` | 🤖 | `I` | M | D | MLOps experiment-tracking metadata may disclose proprietary model design and training dat… | AWS Bedrock, DataRobot, Databricks, Vertex, Watson IBM |
| `TH229` | 🤖 | `S` | H | D | A managed AI platform may route inference to an attacker-substituted custom model deploym… | AWS Bedrock, DataRobot, Databricks, Vertex |
| `TH230` | 🤖 | `E` | H | D | A compromised agent in a multi-agent system may escalate by injecting instructions into p… | CrewAI, Lanchain |
| `TH231` | 🤖 | `E` | H | D | A self-hosted workflow automation platform with AI nodes may expose powerful credentials… | Lindy , n8n |
| `TH232` | 🤖 | `T` | H | D | An orchestration framework may load attacker-supplied chains, tools, or templates that ex… | CrewAI, Lanchain |
| `TH233` | 🤖 | `R` | M | D | No-code AI agent platforms may allow business users to deploy agents that act on company… | Lindy |
| `TH234` | 🤖 | `I` | H | D | An agentic coding tool may transmit proprietary source code, secrets, or customer data to… | Antigravity, Claude Code, Cursor, Windsurf |
| `TH235` | 🤖 | `E` | H | D | An agentic coding tool may take destructive actions on the developer's workstation or rep… | Antigravity, Claude Code, Cursor, Windsurf |
| `TH236` | 🤖 | `T` | H | D | An agentic coding tool may follow injected instructions hidden in repository content or t… | Antigravity, Claude Code, Cursor, Windsurf |
| `TH237` | 🤖 | `I` | M | D | IDE-integrated AI tools may build and transmit an index of the entire workspace, includin… | Antigravity, Claude Code, Cursor, Windsurf |
| `TH238` | 🤖 | `T` | H | D | An installable AI tool extension or MCP server may compromise the developer environment a… | Antigravity, Claude Code, Cursor, Windsurf |
| `TH239` | 🤖 | `T` | H | D | A Hugging Face Space, dataset loader, or model card may execute attacker code when consum… | Hugging Face |
| `TH240` | 🤖 | `S` | H | D | Voice or avatar synthesis platforms may be used to impersonate real people in attacks aga… | ElevenLabs, Synthesia |
| `TH241` | 🤖 | `I` | M | D | Generative media outputs may inadvertently reproduce protected training samples or custom… | ElevenLabs, Midjourney, Synthesia |
| `TH242` | 🤖 | `A` | M | D | Authorized users may generate brand-damaging or non-compliant media that the organization… | ElevenLabs, Midjourney, Synthesia |
| `TH243` | 🤖 | `R` | M | D | Generated media released without provenance metadata may be repudiated or, conversely, mi… | ElevenLabs, Midjourney, Synthesia |
| `TH244` | 🤖 | `D` | M | D | A publicly-reachable Hugging Face Space or self-hosted inference endpoint may be enumerat… | Hugging Face |
| `TH245` | · | `I` | H | D | An over-permissioned DefaultReader role may bypass custom OneLake security data access ro… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake,… |
| `TH246` | · | `I` | H | D | A workspace Admin, Member, or Contributor role grants OneLake read/write access to all it… | KQL Database, Microsoft Fabric Eventhouse, Microsoft F… |
| `TH247` | · | `I` | H | D | Data restricted by OneLake Security may still be readable through the SQL analytics endpo… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake,… |
| `TH248` | · | `D` | M | D | Mixed queries spanning OneLake-Security-enabled and non-enabled data sources will fail, d… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake,… |
| `TH249` | · | `I` | M | D | A cross-region OneLake shortcut combined with OneLake Security may break access or expose… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake |
| `TH250` | · | `R` | M | D | Permission changes in Fabric do not take effect immediately, creating an audit window whe… | KQL Database, Microsoft Fabric Eventhouse, Microsoft F… |
| `TH251` | · | `D` | M | D | A noisy-neighbor workload may exhaust shared Fabric capacity and throttle other workspace… | Fabric Data Activator, Fabric Data Engineering, Micros… |
| `TH252` | · | `I` | H | D | Tenant-level Fabric settings may permit data egress (cross-geo AI processing, external sh… | Microsoft Fabric, Microsoft Fabric Tenant |
| `TH253` | · | `E` | H | D | A capacity admin or service principal scoped to a Fabric capacity may exercise privilege… | Microsoft Fabric, Microsoft Fabric Tenant, Microsoft F… |
| `TH254` | 🤖 | `I` | H | D | A Fabric Data Agent grounding multiple data sources may surface data from one source thro… | Microsoft Fabric Data Agent |
| `TH255` | 🤖 | `T` | H | D | A Fabric Data Agent may be steered by injected instructions in agent metadata, ontology b… | Microsoft Fabric Data Agent, Microsoft Fabric IQ |
| `TH256` | 🤖 | `R` | M | D | Lack of paired logging of natural-language input and translated SQL/DAX/KQL leaves Fabric… | Microsoft Fabric Data Agent |
| `TH257` | · | `E` | H | D | A Fabric Data Engineering notebook or Spark job may execute arbitrary code under workspac… | Fabric Data Engineering |
| `TH258` | · | `T` | H | D | A Fabric Data Factory pipeline definition or its parameters may be tampered with to redir… | Microsoft Fabric Data Factory |
| `TH259` | · | `I` | M | D | Connections held by a Fabric Data Factory pipeline may grant broader source/sink access t… | Microsoft Fabric Data Factory |
| `TH260` | 🤖 | `I` | H | D | A Fabric IQ ontology may make implicit joins across source systems queryable by callers w… | Microsoft Fabric IQ |
| `TH261` | · | `I` | H | D | Mirroring data from an external source into Fabric strips the source's native access cont… | Microsoft Fabric Mirroring |
| `TH262` | · | `I` | H | D | A Power BI semantic model published without row-level security may expose data across rol… | Microsoft Fabric Power BI |
| `TH263` | · | `T` | H | D | An eventstream feeding the Fabric Realtime Hub may accept attacker-supplied events that i… | Fabric Data Activator, Microsoft Fabric Eventhouse, Mi… |
| `TH264` | · | `E` | H | D | A Fabric Data Activator rule may invoke external actions under a workspace-scoped identit… | Fabric Data Activator |
| `TH265` | · | `I` | H | D | A Fabric Lakehouse may expose raw landing-zone data through Files or Tables paths before… | Microsoft Fabric Lakehouse |
| `TH266` | · | `T` | H | D | Direct OneLake writes to a Lakehouse table's underlying Parquet/Delta files may corrupt t… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake |
| `TH267` | · | `I` | H | D | A OneLake shortcut to external storage transfers control over data residency and access t… | Microsoft Fabric OneLake |
| `TH268` | · | `I` | M | D | Fabric Warehouse dynamic data masking is a presentation control, not a security boundary,… | Microsoft Fabric Warehouse |
| `TH269` | · | `I` | M | D | Power BI Direct Lake reports may surface schema or data changes from the underlying Lakeh… | Power BI Direct Lake |
| `TH270` | · | `E` | H | D | A Fabric SQL Database may grant server-level administrative privilege to anyone with suff… | Microsoft Fabric SQL Database |
| `TH271` | · | `I` | M | D | Telemetry stored in a KQL Database or Eventhouse may retain identifying or sensitive data… | KQL Database, Microsoft Fabric Eventhouse |
| `TH272` | · | `T` | H | D | KQL update policies and stored functions execute under the ingestion identity and may be… | KQL Database, Microsoft Fabric Eventhouse |
| `TH273` | · | `I` | H | D | Cosmos DB in Fabric may expose multi-tenant operational data through its OneLake mirror t… | Microsoft Fabric Cosmos DB |
| `TH274` | · | `I` | M | D | External (B2B guest) users may receive broader OneLake access than intended depending on… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake,… |
| `TH275` | · | `S` | H | D | An adversary may obtain a Power BI embed token and impersonate the embedding application'… | Microsoft Fabric Power BI |
| `TH276` | 🤖 | `S` | H | D | A Fabric Data Agent invocation that supplies a service principal token will not authentic… | Microsoft Fabric Data Agent |
| `TH277` | · | `S` | H | D | Scheduled Fabric pipelines, notebooks, and refreshes may execute under a different identi… | Fabric Data Engineering, Microsoft Fabric Data Factory… |
| `TH278` | · | `I` | M | D | OneLake Security role and membership limits may force designs to widen role scope, regres… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake,… |
| `TH279` | · | `I` | H | D | Enabling OneLake Security forces an exclusive choice with private link protection and Pur… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake,… |
| `TH280` | · | `I` | H | D | Direct Lake's silent fallback to DirectQuery shifts the engine evaluating the query and m… | Power BI Direct Lake |
| `TH281` | · | `I` | H | D | Source-system credentials stored to enable Fabric Mirroring become a workspace-resident a… | Microsoft Fabric Mirroring |
| `TH282` | · | `T` | H | D | Custom Spark libraries, JARs, or environment definitions attached to a Fabric workspace m… | Fabric Data Engineering, Microsoft Fabric Workspace |
| `TH283` | · | `I` | H | D | A Fabric Data Activator rule that calls an outbound webhook may become a data exfiltratio… | Fabric Data Activator |
| `TH284` | · | `T` | M | D | An eventstream feeding KQL Database or Eventhouse may silently drop or coerce fields on s… | KQL Database, Microsoft Fabric Eventhouse, Microsoft F… |
| `TH285` | · | `I` | H | D | The Lakehouse Files area is reachable through ABFS / OneLake paths that bypass the Tables… | Microsoft Fabric Lakehouse, Microsoft Fabric OneLake |
| `TH286` | · | `I` | H | D | Copilot and generative AI features in Fabric send workspace data and metadata to model pr… | Microsoft Fabric, Microsoft Fabric Compute, Microsoft… |
| `TH287` | · | `R` | M | D | The Fabric trust boundary may not adequately distinguish compute identity from data ident… | Microsoft Fabric Compute, Microsoft Fabric Data |
| `TH288` | · | `E` | M | D | A workspace Contributor role may be permitted to manage some item permissions, enabling s… | Microsoft Fabric Workspace |
| `TH289` | · | `I` | M | D | Fabric domains and tenant-wide endorsement features may distribute items across the organ… | Microsoft Fabric, Microsoft Fabric Compute, Microsoft… |
| `TH290` | · | `I` | H | D | An over-broad Key Vault access policy or RBAC role grants identities the ability to read… | Key Vault |
| `TH291` | · | `T` | H | D | Key Vault contents may be irreversibly destroyed if soft-delete and purge protection are… | Key Vault |
| `TH292` | · | `E` | H | D | A user-assigned managed identity attached to multiple Azure resources concentrates privil… | App Service, Automation, Azure Kubernetes Service, Bat… |
| `TH293` | · | `S` | H | D | Legacy authentication protocols (basic auth, IMAP/POP/SMTP AUTH, older MAPI) bypass Micro… | Multi Factor Authentication |
| `TH294` | · | `E` | H | D | Cluster-wide Kubernetes RBAC bindings (cluster-admin, edit) on Azure Kubernetes Service g… | Azure Kubernetes Service |
| `TH295` | · | `I` | H | D | Pods deployed to Azure Kubernetes Service may pull container images from untrusted regist… | Azure Kubernetes Service |
| `TH296` | · | `I` | H | D | Azure App Service application settings and connection strings are readable by anyone with… | App Service |
| `TH297` | · | `T` | H | D | An HTTP-triggered Azure Function published with anonymous auth level, or with a long-live… | Functions |
| `TH298` | · | `I` | M | D | Service Fabric cluster certificates used for administrator access may be shared across op… | Service Fabric |
| `TH299` | · | `E` | H | D | An Azure Batch user with submit permission can execute arbitrary code on every pool node,… | Batch |
| `TH300` | · | `I` | H | D | API Management subscription keys are long-lived shared secrets that grant the subscriptio… | API Management |
| `TH301` | · | `T` | H | D | APIM policies executed at the gateway may be modified by API publishers in ways that affe… | API Management |
| `TH302` | · | `T` | H | D | An Azure Logic App's workflow definition or trigger URL may be modified to redirect data… | LogicApp |
| `TH303` | · | `T` | M | D | An Event Grid subscription endpoint may be redirected to an attacker-controlled webhook i… | Event Grid |
| `TH304` | · | `I` | H | D | Service Bus shared access signatures with broad rights or namespace-level scope grant bla… | Azure Event Hub, Service Bus |
| `TH305` | · | `I` | H | D | An Azure Stream Analytics job output configuration may fan out sensitive event data to mu… | Stream Analytics |
| `TH306` | · | `I` | H | D | Azure Cosmos DB master keys grant full account access; embedding them in clients or shari… | CosmosDB |
| `TH307` | · | `I` | H | D | Azure Storage containers configured with anonymous read access, or storage accounts allow… | Azure Storage, Data Lake Store, Files |
| `TH308` | · | `E` | H | D | Azure SQL Managed Instance database admins (sysadmin / dbo) operate on a separate authori… | Azure SQL Database Managed Instance |
| `TH309` | · | `I` | H | D | Azure AI Search admin keys grant full index management; query keys leaked to clients allo… | Azure Search |
| `TH310` | · | `I` | M | D | Azure Cache for Redis may persist sensitive data with weaker access controls than the sou… | Azure Redis Cache |
| `TH311` | · | `I` | H | D | ADLS Gen2 access decisions combine Azure RBAC and POSIX-style ACLs in non-obvious ways, a… | Data Lake Store |
| `TH312` | · | `T` | H | D | Azure Data Factory self-hosted integration runtime credentials concentrate access to ever… | Azure Data Factory, Azure Integration Runtime |
| `TH313` | · | `I` | M | D | Notebook results, query history, and cluster logs in Synapse and Databricks may persist s… | Azure Databricks, Azure Notebooks, Azure Synapse SQL O… |
| `TH314` | · | `I` | H | D | Azure Backup vaults grant restore operations the ability to write data to alternative loc… | Backup |
| `TH315` | · | `I` | H | D | Microsoft Sentinel and Log Analytics workspaces aggregate telemetry from across the tenan… | Log Analytics, Microsoft Sentinel, Monitor |
| `TH316` | · | `T` | H | D | Azure Automation runbooks may execute under high-privilege Run As accounts or managed ide… | Automation |
| `TH317` | · | `E` | H | D | Azure DevOps YAML pipelines that run on self-hosted agents may execute arbitrary code und… | Azure DevOps, Azure DevOps Pipelines |
| `TH318` | · | `T` | H | D | Azure DevOps Repos branch policies may be bypassed by repository administrators or by ser… | Azure DevOps, Azure DevOps Repos |
| `TH319` | · | `I` | M | D | Azure Network Security Group rules with overly broad source/destination/port specificatio… | Virtual Network |
| `TH320` | · | `E` | H | D | Azure RBAC role assignments at Management Group or Subscription scope inherit to every re… | Azure Asset, Azure Service |
| `TH321` | · | `I` | H | D | VNet peering, VPN, ExpressRoute, or service endpoints may extend network reachability acr… | Virtual Network |
| `TH322` | · | `I` | H | D | Geo-replication features (Azure SQL geo-replicas, RA-GRS storage, Cosmos multi-region wri… | Azure SQL Database Managed Instance, Azure Storage, Co… |
| `TH323` | · | `I` | H | D | Microsoft 365 (SharePoint, OneDrive, Teams) sharing defaults may permit anyone-with-link… | Microsoft 365 |
| `TH324` | · | `E` | M | D | Power Automate flows built by end users execute on company systems under those users' ide… | Power Automate |
| `TH325` | · | `I` | H | D | OAuth consent grants from Microsoft Entra users to SaaS applications (Salesforce, Box, th… | Box Storage, Microsoft 365, Power Automate, Power BI P… |
| `TH326` | · | `R` | M | D | Azure resources may have diagnostic settings disabled, partially configured, or routed to… | Log Analytics, Microsoft Sentinel, Monitor |
| `TH327` | · | `D` | M | D | Azure services exposed via public IP addresses without DDoS Protection Standard rely only… | API Management, App Service, Traffic Manager |
| `TH328` | · | `D` | H | D | Consumption-billed Azure services (Functions, Logic Apps, Cosmos DB serverless, Cognitive… | API Management, Cognitive Services, CosmosDB, Function… |
| `TH329` | · | `S` | M | D | Power BI Embedded scenarios using the master user (service account) pattern impersonate t… | Power BI Embedded |
| `TH330` | 🤖 | `E` | H | D | AWS IAM identity or resource policies using wildcard Action or Resource statements grant… | AWS Aurora, AWS Bedrock, AWS DocumentDB, AWS DynamoDB,… |
| `TH331` | · | `E` | H | D | AWS cross-account access via AssumeRole with weak trust policies allows any principal in… | AWS Data |
| `TH332` | · | `I` | H | D | Workloads in an AWS VPC that allow IMDSv1 metadata access expose EC2 instance role creden… | AWS Data |
| `TH333` | · | `I` | H | D | AWS AMIs, EBS snapshots, RDS snapshots, and DocumentDB cluster snapshots may be shared pu… | AWS Aurora, AWS DocumentDB, AWS RDS, AWS Storage |
| `TH334` | · | `I` | H | D | An AWS S3 bucket without S3 Block Public Access enabled may be made publicly readable thr… | AWS Storage |
| `TH335` | · | `I` | M | D | AWS S3 presigned URLs grant time-bounded but unauthenticated access to the underlying obj… | AWS Storage |
| `TH336` | · | `T` | H | D | AWS S3 buckets without versioning or Object Lock allow silent overwrite or permanent dele… | AWS Storage |
| `TH337` | · | `I` | M | D | AWS S3 server-side encryption choice determines the access boundary for decryption; SSE-S… | AWS Storage |
| `TH338` | · | `I` | H | D | AWS RDS and Aurora master user credentials grant superuser access to the database engine… | AWS Aurora, AWS RDS |
| `TH339` | · | `D` | H | D | AWS RDS and Aurora instances without deletion protection or final snapshot configuration… | AWS Aurora, AWS RDS |
| `TH340` | · | `I` | H | D | Aurora cluster snapshots may be shared with other AWS accounts or made public, transferri… | AWS Aurora, AWS RDS |
| `TH341` | · | `I` | H | D | AWS DynamoDB tables without fine-grained IAM conditions grant access to every item; per-t… | AWS DynamoDB |
| `TH342` | · | `I` | H | D | DynamoDB Streams expose item-level change history to consumers, potentially with broader… | AWS DynamoDB |
| `TH343` | · | `I` | H | D | AWS DocumentDB authentication is collection-coarse; multi-tenant data co-located in share… | AWS DocumentDB |
| `TH344` | · | `I` | H | D | AWS Neptune graph queries can traverse relationships to reach data the calling identity h… | AWS Neptune |
| `TH345` | 🤖 | `E` | H | D | AWS Bedrock Agent action groups invoke Lambda functions whose execution role may grant ac… | AWS Bedrock |
| `TH346` | 🤖 | `T` | H | D | AWS Bedrock Knowledge Bases ingest documents from S3 sources that may be writable by less… | AWS Bedrock |
| `TH347` | 🤖 | `R` | M | D | AWS Bedrock model invocation logging is disabled by default; without it, prompts and comp… | AWS Bedrock |
| `TH348` | 🤖 | `A` | M | D | AWS Bedrock model invocations without Guardrails attached rely entirely on the calling ap… | AWS Bedrock |
| `TH349` | · | `I` | H | D | Snowflake on AWS uses a separate role and authentication system from AWS IAM, with the AC… | Snowflake in AWS |
| `TH350` | · | `I` | H | D | Snowflake on AWS data sharing features can share databases or tables with external Snowfl… | Snowflake in AWS |
| `TH351` | · | `I` | H | D | AWS VPC security groups with 0.0.0.0/0 ingress on management or database ports expose tho… | AWS Data |
| `TH352` | · | `I` | H | D | AWS VPC endpoints without endpoint policies allow workloads in the VPC to reach AWS servi… | AWS DynamoDB, AWS Storage |
| `TH353` | · | `I` | H | D | AWS VPC peering and Transit Gateway routing extend network reachability in ways that may… | AWS Data |
| `TH354` | · | `D` | M | D | AWS resources deployed across multiple regions or replicated cross-region may breach data… | AWS Aurora, AWS Data, AWS DocumentDB, AWS DynamoDB, AW… |
| `TH355` | · | `S` | H | D | AWS IAM Roles Anywhere or SAML/OIDC federation may grant role assumption based on weakly-… | AWS Data |
| `TH356` | · | `I` | H | D | A SaaS application not federated to the corporate identity provider may retain local user… | ADP, Adobe, Aero, Box Storage, Cloud SaaS Services, Ex… |
| `TH357` | · | `I` | H | D | SaaS application marketplaces enable end-user installation of third-party integrations th… | Adobe, Box Storage, Jira, Microsoft 365, Monday, Notio… |
| `TH358` | · | `I` | M | D | SaaS audit logs may remain in each vendor's portal with limited retention and no central… | ADP, Adobe, Aero, Box Storage, Dynamics CRM, Expensify… |
| `TH359` | · | `E` | H | D | SaaS administrator roles granted to multiple operators concentrate full-tenant privilege… | ADP, Adobe, Aero, Box Storage, Dynamics CRM, Expensify… |
| `TH360` | · | `I` | H | D | Work management and productivity SaaS often allow end users to publish boards, pages, or… | Aero, Jira, Monday, Notion, Trello |
| `TH361` | · | `I` | M | D | End users may paste credentials, tokens, or sensitive customer data into work management… | Aero, Jira, Microsoft 365, Monday, Notion, Slack, Trel… |
| `TH362` | · | `I` | M | D | Adding external guests to SaaS work management workspaces may grant broader visibility th… | Aero, Box Storage, Jira, Microsoft 365, Monday, Notion… |
| `TH363` | · | `I` | M | D | Slack message retention defaults retain channel and DM history indefinitely, accumulating… | Slack |
| `TH364` | · | `T` | H | D | Slack incoming webhook URLs are bearer credentials; if leaked through code repositories o… | Slack |
| `TH365` | · | `I` | H | D | Zoom cloud recordings, transcripts, and chat logs may be stored with weak access controls… | Zoom |
| `TH366` | · | `T` | M | D | Zoom meetings without passcodes, waiting rooms, or authentication requirements may be hij… | Zoom |
| `TH367` | · | `I` | H | D | HR and payroll SaaS hold compensation, tax identifiers, banking, and medical data that wa… | ADP, Expensify, Workday |
| `TH368` | · | `T` | M | D | Expense management systems may allow submitters to manipulate receipt images, amounts, or… | Expensify |
| `TH369` | · | `I` | H | D | Postmark and similar transactional-email API tokens, if leaked, allow an attacker to send… | Postmark |
| `TH370` | · | `T` | H | D | Email templates stored in Postmark or similar transactional services may be modified to a… | Postmark |
| `TH371` | · | `I` | H | D | Salesforce's combination of org-wide defaults, role hierarchy, sharing rules, and manual… | Salesforce |
| `TH372` | · | `E` | H | D | Integration users in Salesforce and Dynamics CRM frequently hold broad permissions for co… | Dynamics CRM, Dynamics CRM Portal, Salesforce |
| `TH373` | · | `I` | H | D | Dynamics CRM Portal entity permissions are configured separately from internal CRM securi… | Dynamics CRM Portal |
| `TH374` | · | `I` | M | D | Adobe Creative Cloud Libraries shared at organization scope expose design assets, brand m… | Adobe |
| `TH375` | · | `T` | H | D | Adobe Sign / Acrobat Sign workflows may be modified to alter signing parties, document co… | Adobe |
| `TH376` | · | `I` | H | D | Box folders shared via 'anyone with link' setting expose contents to anyone holding the U… | Box Storage |
| `TH377` | · | `I` | H | D | Power BI Publish to Web makes a report or dashboard accessible to anyone on the internet… | Power BI Platform |
| `TH378` | · | `I` | H | D | A Power Automate flow combining business and consumer connectors can bridge data classifi… | Power Automate |
| `TH379` | · | `R` | M | D | Vendor-managed audit-log retention limits in SaaS may not match the timeline of investiga… | ADP, Adobe, Aero, Box Storage, Cloud SaaS Services, Ex… |
| `TH380` | · | `I` | H | D | SaaS data residency and sub-processor lists may move tenant data across geographic and re… | ADP, Adobe, Aero, Box Storage, Cloud SaaS Services, Dy… |
| `TH381` | · | `S` | M | D | SaaS platforms that allow user-controlled display names enable internal impersonation by… | Aero, Jira, Microsoft 365, Monday, Notion, Salesforce,… |
| `TH382` | · | `D` | M | D | Heavy or runaway API usage by one integration may exhaust the SaaS tenant's API rate limi… | ADP, Adobe, Box Storage, Dynamics CRM, Expensify, Jira… |
| `TH383` | 🤖 | `S` | H | D | An AI Agent acting on behalf of a user may present unverified identity claims to downstre… | AI Agent |
| `TH384` | 🤖 | `T` | H | D | An AI Agent's tool definitions, system prompt, or memory store may be tampered with to al… | AI Agent |
| `TH385` | 🤖 | `R` | H | D | Actions taken by an AI Agent may be unattributable to either the agent or the user that t… | AI Agent |
| `TH386` | 🤖 | `I` | H | D | An AI Agent's context window may aggregate data from multiple authorization scopes and di… | AI Agent |
| `TH387` | 🤖 | `D` | M | D | An AI Agent may enter a tool-call loop or context-expansion loop that exhausts compute, t… | AI Agent |
| `TH388` | 🤖 | `E` | H | D | An AI Agent's tool surface may grant the agent privileges that exceed any single user's n… | AI Agent |
| `TH389` | 🤖 | `A` | M | D | Authorized users may misuse an AI Agent to perform actions at scale or in patterns that v… | AI Agent |
| `TH390` | · | `S` | M | D | An Apache Airflow DAG may execute under a service identity that obscures the human owner… | Apache Airflow |
| `TH391` | · | `T` | H | D | Apache Airflow DAG files loaded from a writable repository allow arbitrary Python executi… | Apache Airflow |
| `TH392` | · | `I` | H | D | Apache Airflow Connections and Variables centralize credentials and secrets in a way that… | Apache Airflow |
| `TH393` | · | `E` | H | D | Apache Airflow Web UI roles may grant DAG-trigger or connection-edit privileges that bypa… | Apache Airflow |
| `TH394` | · | `D` | M | D | Apache Airflow scheduler and worker capacity may be exhausted by misconfigured schedules,… | Apache Airflow |
| `TH395` | · | `T` | H | D | A Fabric Notebook executed interactively and on schedule may resolve cell code or referen… | Fabric Notebook |
| `TH396` | · | `I` | H | D | Fabric Notebook outputs and saved cell results may persist data the executing user was au… | Fabric Notebook |
| `TH397` | · | `E` | H | D | A Fabric Notebook that calls %run on another notebook executes that notebook's code in th… | Fabric Notebook |
| `TH398` | · | `R` | M | D | Fabric Notebook execution history may not durably bind the executed cell content to the r… | Fabric Notebook |
| `TH399` | · | `A` | M | D | An authorized Fabric Notebook user may exfiltrate data through interactive cell output, d… | Fabric Notebook |
| `TH400` | · | `T` | H | D | Fabric Dataflow Gen2 M-language definitions may include dynamic data sources or eval-styl… | Fabric Dataflow |
| `TH401` | · | `I` | M | D | Fabric Dataflow staged data and refresh history may persist sensitive intermediate values… | Fabric Dataflow |
| `TH402` | · | `D` | M | D | Fabric Dataflow refreshes may share capacity with interactive workloads and induce thrott… | Fabric Dataflow |
| `TH403` | · | `R` | M | D | Fabric Dataflow ownership transfer or scheduled-refresh identity changes may detach refre… | Fabric Dataflow |
| `TH404` | · | `I` | H | D | Fabric Eventstream destinations may broadcast events to multiple sinks whose individual a… | Fabric Eventstream |
| `TH405` | · | `S` | H | D | Fabric Eventstream custom endpoints accept events from any caller holding the connection… | Fabric Eventstream |
| `TH406` | · | `D` | M | D | Fabric Eventstream backpressure on a slow destination may delay or drop events for every… | Fabric Eventstream |
| `TH407` | · | `I` | H | D | Data crossing the Microsoft Fabric tenant boundary via shortcut, mirroring, or cross-tena… | crosses Microsoft Fabric Boundary |
| `TH408` | · | `S` | H | D | Cross-boundary calls to or from Fabric workloads may rely on shared keys or connection st… | crosses Microsoft Fabric Boundary |
| `TH409` | · | `E` | H | D | OneLake shortcuts to external accounts may grant Fabric workloads broader access to the t… | crosses Microsoft Fabric Boundary |
| `TH410` | 🤖 | `A` | M | D | An LLM provider may retain prompts, completions, or fine-tuning data beyond the user's ex… | AI LLM Providers, ChatGPT OpenAI, Grok xAI |
| `TH411` | 🤖 | `T` | H | D | An agent orchestration framework may allow tool outputs to influence subsequent tool sele… | AI Agent and Orchestration Platform, CrewAI, Lanchain |
| `TH412` | 🤖 | `D` | M | D | LLM provider rate limits, quota exhaustion, or model deprecation may cause dependent appl… | AI LLM Providers, AI Platform, AWS Bedrock, ChatGPT Op… |
| `TH413` | 🤖 | `I` | M | D | LLM completions may regurgitate memorized training data or fine-tuning corpus content, di… | AI LLM Providers, AI Platform, AWS Bedrock, ChatGPT Op… |
| `TH414` | 🤖 | `R` | M | D | Multi-agent orchestrations may distribute decision-making across agents in a way that no… | AI Agent and Orchestration Platform, CrewAI, Lanchain |
| `TH415` | · | `R` | M | D | Fabric tenant and workspace administrative actions may not produce uniformly attributable… | Microsoft Fabric Tenant, Microsoft Fabric Workspace |
| `TH416` | · | `D` | M | D | Fabric query workloads may be denied service when capacity throttling, statistics drift,… | Microsoft Fabric Lakehouse, Microsoft Fabric SQL Datab… |
| `TH417` | · | `R` | M | D | Fabric Mirroring activity logs may not record per-row changes ingested from the source, l… | Microsoft Fabric Mirroring |
| `TH418` | · | `D` | H | D | Fabric Mirroring may amplify source-side load or lag indefinitely if the change feed back… | Microsoft Fabric Mirroring |
| `TH419` | · | `R` | M | D | Fabric Eventhouse and KQL Database update policies may transform or drop events without p… | Microsoft Fabric Eventhouse |
| `TH420` | · | `I` | H | D | Power BI semantic models exposed through Direct Lake or DirectQuery may surface row-level… | Microsoft Fabric Power BI |
| `TH421` | · | `R` | M | D | Power BI report exports and subscriptions may distribute data outside the platform withou… | Microsoft Fabric Power BI |
| `TH422` | · | `I` | M | D | Spark job logs and the Spark UI in Fabric Data Engineering may render row data, query pla… | Fabric Data Engineering |
| `TH423` | · | `S` | H | D | Fabric Data Activator triggers may fire from event content the producer did not authentic… | Fabric Data Activator |
| `TH424` | · | `R` | M | D | Fabric Data Activator action invocations may not record the originating event with suffic… | Fabric Data Activator |
| `TH425` | 🤖 | `S` | M | D | Fabric IQ ontology callers may rely on cached resolution that lags behind ontology revisi… | Microsoft Fabric IQ |
| `TH426` | 🤖 | `R` | M | D | Fabric IQ query history may not preserve the ontology version, source bindings, and resol… | Microsoft Fabric IQ |
| `TH427` | · | `E` | H | D | OneLake DefaultReader role grants ReadAll across the lakehouse and may exceed the access… | Microsoft Fabric OneLake |
| `TH428` | · | `D` | M | D | OneLake security role and group-membership propagation latency creates a window in which… | Microsoft Fabric, Microsoft Fabric OneLake |
| `3f96bbf2-1d6e-4b20-9bca-8a413008595f` | · | `S` | H | D | Ensure that multi-factor authentication is enabled for all privileged users | Azure Asset, Azure Data Service, Azure Service |
| `9f6d0f70-aa99-4ecf-90a5-a6c750f450e7` | · | `S` | H | D | Ensure that multi-factor authentication is enabled for all non-privileged users | Azure Asset, Azure Data Service, Azure Service |
| `b2596654-b80e-41c3-ae5e-51859d1107b3` | · | `D` | H | I | An adversary may block access to the application or API hosted on {target.Name} through a… | Functions, Mobile App, Web API, Web Application |
