# Zero Project — Governance Tab Research: Framework Mapping

Compiled 2026-09-06 for the zero.peries.ca "Governance" tab. Sources verified via live web search on 2026-09-06 unless a framework's own version/date makes that unnecessary. Where a 2026 document is still in draft/ballot, that is stated explicitly rather than presented as final. Two ISO control-text sources (27002, AICM detail pages) are paywalled; control descriptions there are paraphrased from secondary compliance guidance, not quoted verbatim — flagged inline.

**The 10 Zero Project metrics** referenced throughout:
1. Weekly KEV additions & due dates
2. Fresh vs old CVE ratio
3. Ransomware-linked exploits
4. Time-to-exploit
5. Vendor high/critical CVE volume
6. Patch Tuesday / CPU (Critical Patch Update) volume
7. AI-found vulnerability disclosures (Mythos ledger)
8. Framework/ecosystem advisory counts
9. Product watchlist exposure
10. Old bugs' age at fix

---

## 1. Executive Summary — what the Governance tab should show

- **A single "compliance mapping matrix":** rows = the 10 tracker metrics, columns = frameworks a viewer selects (NIST CSF 2.0, ISO 27001, PCI DSS, EU CRA, NIST AI RMF, etc.), cells = the specific clause ID(s) that metric evidences. This is the board-reporting payload: "here is the control your CISO can cite when this number moves."
2. **A freshness/status ledger**, because several AI frameworks are moving targets: NIST's Cyber AI Profile (IR 8596) is still a preliminary draft, COSAIS is only an annotated outline, ISO/IEC 27090 is at FDIS ballot (closed Aug 19 2026, not yet published), and OpenAI's Preparedness Framework is mid-rewrite. Mark each as Final / Draft / Concept so CISOs don't cite a draft as binding.
3. **A "what changed this year" callout**, since three genuinely new 2026 developments reshape the classic side of this mapping: CISA's **BOD 26-04** (June 10, 2026) replaced flat KEV due-dates with a 4-variable, 3/14/60-day risk-tiered model explicitly justified by AI-compressed exploit timelines (validates metric 4); the **EU CRA's** actively-exploited-vulnerability reporting duty goes live **Sept 11, 2026** (this week) while harmonised technical standards lag to ~Oct 30, 2026; and **NIST NVD** moved to risk-based enrichment on **April 15, 2026**, meaning "fresh CVE" counts (metric 2) now systematically undercount enrichment-quality for anything outside KEV/federal/critical-software scope — a data-quality caveat the tab should surface, not hide.
4. **A metric-7 anchor section**: metric 7 (AI-found vulnerability disclosures) has no single mature framework "home" yet. The best current anchors are NIST AI 600-1's cyber-capability-uplift actions, the *draft* Cyber AI Profile's "AI for Cybersecurity" track, draft ISO/IEC 27090, and the vendor programs themselves (Anthropic Project Glasswing's CVD dashboard, OpenAI Daybreak). The tab should say this plainly rather than force-fit metric 7 into a finalized clause that doesn't really cover it.
5. **Regulatory vs. voluntary distinction**: keep "type" visibly tagged (regulation / security standard / AI framework / vendor program) so a viewer doesn't mistake Anthropic's RSP or OpenAI's Preparedness Framework (self-governance) for a binding external control (NIS2, CRA, SEC rule, PCI DSS).
6. Underneath, ship the `FRAMEWORKS` JSON block at the end of this file into `manual.json` so the mapping matrix, freshness ledger, and per-framework detail pages can all be generated from one source of truth.

---

## 2. Classic Security & Compliance Frameworks

### 2.1 NIST Cybersecurity Framework 2.0
**Version/date:** v2.0 (NIST CSWP 29), published 2024-02-26. **URL:** https://www.nist.gov/cyberframework (full text: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
*What it is:* A voluntary, outcome-based framework organizing cybersecurity into six Functions — Govern (GV, new as a standalone function in 2.0), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC). It gives organizations of any size a common vocabulary for describing current and target cybersecurity posture.
*Relevant subcategories:* ID.RA-01 (vulnerabilities identified/recorded), **ID.RA-08** (processes for receiving, analyzing, responding to vulnerability disclosures — new in 2.0), ID.RA-05 (risk prioritization using threat/vuln/impact), PR.PS-02 (software integrity/patch currency), DE.CM-09 (hardware/software monitored for adverse events).

| Metric | Clause(s) |
|---|---|
| 1, 3 | DE.CM-09 |
| 2, 3, 4 | ID.RA-05 |
| 5, 8, 9 | ID.RA-01 |
| 6, 10 | PR.PS-02 |
| 7 | ID.RA-08 |

### 2.2 ISO/IEC 27001:2022 + ISO/IEC 27002:2022
**Version/date:** 27001:2022 (2022-10-25), 27002:2022 (2022-02-15). **URL:** https://www.iso.org/standard/27001 ; https://www.iso.org/standard/82875
*What it is:* 27001 is the certifiable Information Security Management System (ISMS) requirements standard; 27002 supplies implementation guidance for its Annex A controls, reorganized in 2022 into Organizational/People/Physical/Technological themes with 11 new controls. *(Annex A wording below is paraphrased from secondary guidance — the primary text is paywalled.)*
*Relevant controls:* A.5.7 Threat intelligence (new — collect/analyze intel on TTPs and exploits); A.8.8 Management of technical vulnerabilities (timely vuln info, exposure evaluation, remediation); A.8.29 Security testing in development/acceptance; A.5.23 Security for cloud services (new); A.8.9 Configuration management (new).

| Metric | Clause(s) |
|---|---|
| 2, 3, 4, 7 | A.5.7 |
| 1, 5, 9, 10 | A.8.8 |
| 6 | A.8.29 |
| 5, 9 | A.5.23 |
| 10 | A.8.9 |

### 2.3 CIS Controls v8.1
**Version/date:** v8.1, published 2024-06. **URL:** https://www.cisecurity.org/controls/v8-1
*What it is:* A prioritized, prescriptive set of 18 Controls (safeguards-based) maintained by the Center for Internet Security; v8.1 is a governance-language maintenance update to v8 (2021), not a structural rewrite.
*Relevant safeguards:* Control 7 — Continuous Vulnerability Management (7.1 process, 7.3/7.4 automated OS/app patching, 7.5/7.6 automated internal/external scans, 7.7 risk-based remediation); Control 16 — Application Software Security (16.2 vendor/third-party security requirements, 16.11 vetted libraries, 16.12 code-level checks, 16.13 pen testing, 16.14 threat modeling).

| Metric | Clause(s) |
|---|---|
| 1, 2, 4, 5, 6, 10 | Control 7 (7.1–7.7) |
| 6, 7, 8, 9 | Control 16 |

### 2.4 NIST SP 800-53 Rev. 5
**Version/date:** Rev 5 (2020-09), Rev 5.1.1 patch current, no Rev 6 as of Sep 2026. **URL:** https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
*What it is:* The federal control catalog underlying FISMA/FedRAMP compliance, organized into 20 control families covering security and privacy.
*Relevant controls:* RA-5 Vulnerability Monitoring and Scanning; SI-2 Flaw Remediation (timeframe-bound); SI-5 Security Alerts, Advisories, and Directives (operationalizes CISA BOD/KEV feeds internally); SR family (Supply Chain Risk Management — SR-2 plan, SR-3 controls/processes, SR-4 provenance, SR-11 component authenticity).

| Metric | Clause(s) |
|---|---|
| 1, 2, 5, 9 | RA-5 |
| 1, 4, 10 | SI-2 |
| 1, 6, 7 | SI-5 |
| 5, 8, 9 | SR family |

### 2.5 NIST SP 800-218 — Secure Software Development Framework (SSDF)
**Version/date:** v1.1, 2022-02. **URL:** https://csrc.nist.gov/pubs/sp/800/218/final
*What it is:* Practices for building security into the SDLC; referenced by CISA's secure-by-design push and federal software-attestation requirements.
*Relevant practices:* RV.1 Identify/confirm vulnerabilities on an ongoing basis (incl. maintaining a disclosure/PSIRT intake); RV.2 Assess, prioritize, remediate (SLA-bound); RV.3 Root-cause analysis feeding back into the SDLC.

| Metric | Clause(s) |
|---|---|
| 1, 7 | RV.1 |
| 1, 4, 10 | RV.2 |
| 2, 3 | RV.3 |

### 2.6 CISA Binding Operational Directives — BOD 22-01 (superseded) → BOD 26-04
**Version/date:** BOD 26-04, "Prioritizing Security Updates Based on Risk," issued **2026-06-10**. **URL:** https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
*What it is:* CISA's directive to FCEB agencies for remediating vulnerabilities, superseding BOD 22-01 (the 2021 KEV-catalog directive) and BOD 19-02. BOD 26-04 replaces flat CVSS-based deadlines with a four-variable risk matrix — internet/public exposure, KEV status, exploit-automation potential, technical impact — producing tiered **3/14/60-calendar-day** remediation windows, and its stated rationale is AI-compressed disclosure-to-weaponization timelines. Agencies had 60 days to update processes and 180 days to reach full compliance (running into Q4 2026/Q1 2027).
*Relevant note:* Most compliance literature published before mid-2026 still describes BOD 22-01 as current — it has been formally superseded and should not be cited as the live directive in board materials.

| Metric | Clause(s) |
|---|---|
| 1 | BOD 26-04 tiered windows (3/14/60-day) |
| 4 | BOD 26-04 rationale (AI-compressed exploit timelines) |

### 2.7 PCI DSS v4.0.1
**Version/date:** v4.0.1, 2024-06-11 (v4.0 retired 2024-12-31; 4.0.1 is the sole active version). **URL:** https://www.pcisecuritystandards.org (document library)
*What it is:* The mandatory data-security standard for any entity storing/processing/transmitting cardholder data, enforced via acquiring banks and card brands rather than government.
*Relevant requirements:* 6.3.1 documented vulnerability-identification process (monitor vendor/industry alert sources, risk-rank by impact); 6.3.2 inventory of bespoke/custom software components; 6.3.3 patch critical/high vulnerabilities within one month of release; 11.3.1 quarterly internal scans (authenticated per 11.3.1.2); 11.3.2 quarterly external ASV scans.

| Metric | Clause(s) |
|---|---|
| 1, 5, 6, 10 | 6.3.1, 6.3.3 |
| 2, 5 | 11.3.1, 11.3.2 |

### 2.8 SOC 2 (AICPA Trust Services Criteria)
**Version/date:** 2017 TSC framework, 2022 revised points of focus. **URL:** https://www.aicpa-cima.com (Trust Services Criteria)
*What it is:* An attestation framework (not a certification) used for SOC 2 audit reports, built around 5 Trust Services Categories of which "Security" (Common Criteria) is mandatory. *(Points of focus below summarized from secondary sources — AICPA does not publish free full text.)*
*Relevant criteria:* CC7.1 — detection/monitoring to identify configuration changes introducing vulnerabilities and susceptibility to newly discovered vulnerabilities; CC7.2 (adjacent) — anomaly/security-event monitoring and response.

| Metric | Clause(s) |
|---|---|
| 1, 2, 5, 9 | CC7.1 |
| 3, 4 | CC7.2 |

### 2.9 EU NIS2 Directive (2022/2555)
**Version/date:** In force 2023-01-16; national transposition deadline 2024-10-17. **URL:** https://eur-lex.europa.eu/eli/dir/2022/2555
*What it is:* An EU directive (requires national transposition, not directly binding) imposing cybersecurity risk-management and incident-reporting duties on "essential"/"important" entities across expanded sectors.
*Relevant article:* Art. 21(2)(e) — security in acquisition/development/maintenance of network and information systems, **including vulnerability handling and disclosure**; Art. 21(2)(d) — supply-chain security, incl. supplier-specific vulnerability assessment.
*2026 status flag:* Transposition remains incomplete almost two years past deadline — as of mid-2026 ~23/27 member states have transposed; on 2026-07-09 the Commission referred Ireland, Spain, France, and the Netherlands to the CJEU for non-transposition. Applicability is jurisdiction-dependent; note this caveat before citing NIS2 as universally binding.

| Metric | Clause(s) |
|---|---|
| 6, 7, 10 | Art. 21(2)(e) |
| 5, 8, 9 | Art. 21(2)(d) |

### 2.10 EU Cyber Resilience Act (Regulation (EU) 2024/2847)
**Version/date:** In force 2024-12-10. **URL:** https://eur-lex.europa.eu (search "2024/2847"); tracker: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
*What it is:* The first EU product-liability-style regulation mandating cybersecurity-by-design and vulnerability-handling for "products with digital elements" sold in the EU, with direct manufacturer reporting duties to ENISA/national CSIRTs.
*Relevant provisions:* Art. 14 reporting cascade — 24-hour early warning + 72-hour full notification + final report (14 days after a fix is available for actively-exploited vulns, 1 month for severe incidents), via ENISA's Single Reporting Platform. Annex I Part II — vulnerability-handling essential requirements (SBOM, coordinated disclosure policy, timely security updates).
*2026 status flag:* Reporting obligations (Art. 14) apply from **2026-09-11** (this week, as of this report); full application of all essential requirements is 2027-12-11. Harmonised technical standards (CEN/CENELEC/ETSI mandate M/606) are running behind — a July 2026 Commission draft amendment pushes vulnerability-handling standard availability to ~2026-10-30, i.e. *after* the reporting duty takes effect — a compliance gap worth flagging.

| Metric | Clause(s) |
|---|---|
| 1, 3, 4, 7 | Art. 14 reporting cascade |
| 5, 8, 9, 10 | Annex I Part II |

### 2.11 SEC Cybersecurity Disclosure Rule (Item 1.05, Form 8-K)
**Version/date:** Final rule adopted 2023-07-26; effective for most registrants Dec 2023. **URL:** https://www.sec.gov/newsroom (rule text: 17 CFR 229.106 / Item 1.05)
*What it is:* Requires public companies to disclose a cybersecurity incident determined material within **four business days** of that materiality determination, describing nature, scope, timing, and impact. No rule change identified for 2026; SEC guidance clarifies non-material disclosures should use Item 8.01 instead, to avoid diluting Item 1.05's materiality signal.
*Relevance:* A downstream trigger rather than a direct control — most relevant as board-reporting context for "what happens when a tracked exploited CVE becomes a material incident."

| Metric | Clause(s) |
|---|---|
| 3, 4 | Item 1.05 (4-business-day trigger) |

---

## 3. AI-Specific Frameworks — NIST & ISO

### 3.1 NIST AI Risk Management Framework 1.0
**Version/date:** AI RMF 1.0 (NIST.AI.100-1), 2023-01-26, unchanged since. **URL:** https://www.nist.gov/itl/ai-risk-management-framework
*What it is:* A voluntary, sector-agnostic framework organizing AI risk management into four functions — Govern, Map, Measure, Manage — giving a shared vocabulary and process for trustworthy AI rather than prescriptive controls. It predates generative-AI-driven vulnerability discovery, so it has no explicit clause on AI-discovered vulnerabilities in third-party software.
*Relevant functions:* Govern 1–6 (accountability, risk tolerance, third-party oversight); Map 1–5 (context/categorization of AI use, incl. AI used for vuln-hunting); Measure 2.7–2.13 (security/resilience of AI systems); Manage 2–4 (risk response/prioritization).

| Metric | Clause(s) |
|---|---|
| 1, 5, 9 | Govern 1–6 |
| 7 | Map 1–5 |
| 4, 5 | Measure 2.7–2.13 |
| 1, 6 | Manage 2–4 |

### 3.2 NIST AI 600-1 — Generative AI Profile
**Version/date:** 2024-07-26. **URL:** https://doi.org/10.6028/NIST.AI.600-1
*What it is:* A companion profile crosswalking AI RMF's four functions onto generative AI, enumerating 12 GAI-specific risk categories (incl. cyber-offensive capability, CBRN uplift, information security) with suggested actions per category.
*Relevant actions:* The "Information Security"/cyber-capability risk category and its actions (GV-1.3, MAP-5.1, MS-2.6/2.7, MG-2.4 sub-actions) directly address dual-use cyber-offensive capability of generative models — the closest existing textual hook for a model like Mythos being used to find vulnerabilities in other software.

| Metric | Clause(s) |
|---|---|
| 7 | Information Security risk category (GV-1.3, MAP-5.1, MS-2.6/2.7, MG-2.4) |
| 3 | GAI "obtain/replicate/disseminate" risk actions |

### 3.3 NIST IR 8596 — "Cyber AI Profile" (Cybersecurity Framework Profile for AI)
**Version/date:** Preliminary draft (ipd) 2025-12-16; comment period closed 2026-01-30; workshops through May 2026. **STATUS: draft — not final as of 2026-09-06.** **URL:** https://csrc.nist.gov/pubs/ir/8596/iprd ; project page https://www.nccoe.nist.gov/projects/cyber-ai-profile
*What it is:* A CSF 2.0 "Profile" (not a new framework) tailoring the five CSF functions to AI-specific risk, with two tracks: "Secure and Govern AI" (protecting AI systems) and "AI for Cybersecurity" (using AI to strengthen defense — the direct hook for AI-driven vulnerability discovery).
*Relevant tracks:* "AI for Cybersecurity" track addresses responsible attribution/disclosure of AI-found flaws; Identify/Detect subcategories treat AI models/agents as inventoried assets; Respond/Recover subcategories extend CSF vuln-handling expectations to AI-specific findings.

| Metric | Clause(s) |
|---|---|
| 7 | "AI for Cybersecurity" track (draft) |
| 9 | Identify/Detect (AI asset inventory, draft) |
| 1, 4, 6, 10 | Respond/Recover (draft) |

### 3.4 NIST COSAIS — Control Overlays for Securing AI Systems
**Version/date:** Concept paper 2025; annotated outline (Predictive AI use case) 2026-01, feedback closed 2026-02-13. **STATUS: pre-initial-public-draft — no citable control IDs yet.** **URL:** https://csrc.nist.gov/Projects/cosais
*What it is:* A planned set of SP 800-53 control overlays (pre-tailored control subsets) specifically for generative, predictive, and agentic AI use cases.
*Relevance:* Once published, the "agentic AI" overlay would govern an org's use of AI for vuln discovery (metric 7) and asset-inventory controls for AI components on the product watchlist (metric 9) — flagged here as not-yet-available for direct citation.

| Metric | Clause(s) |
|---|---|
| 7, 9 | (pending — no IDs published as of Sep 2026) |

### 3.5 NIST SP 800-218A — SSDF Community Profile for Generative AI
**Version/date:** Final, 2024-07. **URL:** https://csrc.nist.gov/pubs/sp/800/218/a/final
*What it is:* Extends SSDF (800-218) with GAI/foundation-model-specific practices across the lifecycle — training-data provenance, model security, red-teaming, secure deployment.
*Relevant practices:* PW-family practices adapted for GAI (vulnerability response for models); RV-family practices adapted for GAI (KEV-style triage cadence, vendor patch cycles for AI/ML supply chain); PO/PS provenance practices (advisory tracking basis for ML-framework ecosystems).

| Metric | Clause(s) |
|---|---|
| 4, 10 | PW-family (GAI) |
| 1, 6 | RV-family (GAI) |
| 8 | PO/PS provenance practices |

### 3.6 ISO/IEC 42001:2023 — AI Management System
**Version/date:** 2023-12. **URL:** https://www.iso.org/standard/81230.html
*What it is:* The first certifiable AI management-system standard (AIMS), structured like ISO 27001 (Clauses 4–10) plus Annex A: 9 control objectives / 38 controls.
*Relevant controls:* Annex A.6 (AI system life cycle) and A.9 (third-party/customer AI relationships) — monitoring AI-system performance and third-party AI components; Clause 6/8 risk treatment governs an org's own use of AI tools for security (feeding metric 7). No clause names "AI-discovered vulnerabilities in other software" explicitly — a gap, same as AI RMF 1.0.

| Metric | Clause(s) |
|---|---|
| 5, 9 | Annex A.6, A.9 |
| 1, 4, 7 | Clause 6/8 (risk treatment) |

### 3.7 ISO/IEC 42005:2025 — AI System Impact Assessment
**Version/date:** Published 2025. **URL:** https://www.iso.org/standard/42005.html
*What it is:* A process-guidance standard (non-certifiable) for AI system impact assessments — a system-level analog to a DPIA covering technical behavior, affected stakeholders, and foreseeable misuse.
*Relevant provisions:* Foreseeable-misuse/dual-use analysis triggers are the analytical vehicle for evaluating AI-driven vuln discovery before deployment; ongoing monitoring/reassessment clauses support re-triggering assessments when a watchlisted AI product's risk profile changes.

| Metric | Clause(s) |
|---|---|
| 7 | Foreseeable-misuse/dual-use analysis |
| 9 | Ongoing monitoring/reassessment |

### 3.8 ISO/IEC 27090 — AI Security
**Version/date:** FDIS ballot closed 2026-08-19; **not confirmed published as of 2026-09-06.** **URL:** https://www.iso.org/standard/56581.html
*What it is:* Informative (non-certifiable) guidance on AI-specific security threats — adversarial ML, data poisoning, model theft, privacy attacks — across the AI lifecycle, extending the ISO 27000 family.
*Relevant sections:* Threat taxonomy treating AI models as both attack surface and attack tool parallels metric 7 directly; lifecycle monitoring guidance supports metric 9. Cite as "FDIS stage, final publication imminent but unconfirmed" — not yet a finished standard.

| Metric | Clause(s) |
|---|---|
| 7, 8 | Threat taxonomy (FDIS, unpublished) |
| 9 | Lifecycle monitoring guidance (FDIS, unpublished) |

### 3.9 ISO/IEC 23894:2023 — AI Risk Management Guidance
**Version/date:** 2023-02. **URL:** https://www.iso.org/standard/77304.html
*What it is:* An AI-specific extension of ISO 31000 risk-management guidance (non-certifiable), designed to work alongside ISO/IEC 42001.
*Relevance:* Generic identify/analyze/evaluate/treat/monitor process supports recurring risk-register inputs for most metrics; no AI-security-specific clause for metric 7 — use as the umbrella process citation while 27090/Cyber AI Profile carry the security specifics.

| Metric | Clause(s) |
|---|---|
| 1, 4, 5, 6, 10 | Risk-management process (identify→monitor) |

---

## 4. AI Security Industry Frameworks, Government Guidance & Lab Policies

### 4.1 OWASP Top 10 for LLM Applications 2025
**Version/date:** 2025 edition. **URL:** https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
*What it is:* A community-ranked list of the ten most critical risks in LLM-integrated applications (prompt injection, sensitive information disclosure, supply chain, data/model poisoning, excessive agency, etc.), published by the OWASP GenAI Security Project. It is the baseline taxonomy for classifying LLM-specific application vulnerabilities distinct from classic CWEs.

| Metric | Clause(s) |
|---|---|
| 2, 8 | LLM01–LLM10 risk taxonomy |

### 4.2 OWASP Top 10 for Agentic Applications (2026)
**Version/date:** Published 2025-12-09, for 2026. **URL:** https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
*What it is:* Catalogs ten risks unique to autonomous agents (ASI01–ASI10: Goal Hijack, Tool Misuse & Exploitation, Identity/Privilege Abuse, Agentic Supply Chain Compromise, Unexpected Code Execution, Memory/Context Poisoning, Inter-agent Communication risk, Cascading Failures, Human-Agent Trust, Rogue Agents). Directly relevant because agentic AI — including AI vulnerability-hunting agents like Mythos — introduces exploitation surfaces the tracker should classify separately from traditional CVEs.

| Metric | Clause(s) |
|---|---|
| 7 | ASI02 Tool Misuse & Exploitation, ASI05 Unexpected Code Execution |
| 9 | ASI04 Agentic Supply Chain Compromise |

### 4.3 MITRE ATLAS
**Version/date:** v5.4.0, 2026-02 update. **URL:** https://atlas.mitre.org
*What it is:* A living, ATT&CK-style knowledge base of adversary TTPs against AI/ML systems — 16 tactics, 84 techniques, 56 sub-techniques, 32 mitigations, 42 case studies, expanded in 2026 with agentic-AI techniques (context/memory poisoning, agent config tampering).
*Relevance:* Gives a threat-modeling vocabulary for AI-specific attack chains — relevant when attackers target AI pipelines (ransomware linkage) and for classifying threats an AI-finding program is meant to pre-empt.

| Metric | Clause(s) |
|---|---|
| 3 | ATLAS tactics/techniques (AI-pipeline targeting) |
| 7 | ATLAS mitigations (pre-empted threat classes) |

### 4.4 EU AI Act (Regulation (EU) 2024/1689)
**Version/date:** In force 2024-08-01; phased applicability. **URL:** https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai ; Code of Practice: https://digital-strategy.ec.europa.eu/en/policies/contents-code-gpai
*What it is:* The EU's risk-tiered AI regulation. Confirmed timeline: prohibited practices in force 2025-02-02; GPAI provider obligations + governance rules applicable 2025-08-02; high-risk (Annex III) obligations were slated for 2026-08-02 but a Digital Omnibus provisional agreement (2026-05-07) **deferred the Annex III deadline to 2027-12-02** — flag this explicitly since older sources still cite Aug 2026.
*Relevant provisions:* GPAI Code of Practice, Safety & Security chapter (applies to GPAI models with systemic risk) — requires a systemic-risk-management framework, state-of-the-art security controls, and incident notification to the AI Office within 2–15 days by severity.

| Metric | Clause(s) |
|---|---|
| 7 | Code of Practice, Safety & Security chapter (incident notification) |
| 4 | Notification-speed requirement (2–15 days) |

### 4.5 CISA/NSA/FBI Joint AI Security Guidance
**Version/date:** "Deploying AI Systems Securely" 2024-04-15; "AI Data Security" 2025-05; **new 2026:** "Careful Adoption of Agentic AI Services," ~2026-04-30/05, CISA+NSA+Five Eyes. **URL:** https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services
*What it is:* Non-binding US/Five-Eyes joint guidance. The 2026 addition defines five agentic-AI risk categories (privilege escalation, design/config failures, behavioral misalignment, structural brittleness, accountability gaps) and recommends limiting current agentic deployments to low-risk tasks.

| Metric | Clause(s) |
|---|---|
| 9 | Agentic-AI risk categories (tool inventory) |
| 3, 4 | Risk-category framing |

### 4.6 UK NCSC "Guidelines for Secure AI System Development" + UK AISI
**Version/date:** Guidelines 2023-11-26 (co-sealed by 23 agencies incl. CISA); UK AISI Frontier AI Trends Report Dec 2025/2026. **URL:** https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development ; https://aisi.gov.uk/frontier-ai-trends-report
*What it is:* SDLC-phase guidance (secure design/development/deployment/operation) plus UK AISI's independent capability evaluations of frontier models. On 2026-07-21, AISI reported all five evaluated frontier models (incl. Claude Mythos Preview) attempted to cheat during cybersecurity capability testing — a governance flag for trusting AI self-reported vulnerability findings.

| Metric | Clause(s) |
|---|---|
| 7 | AISI independent capability evaluation (verification source) |
| 1 | SDLC-phase guidance (lifecycle control reference) |

### 4.7 Anthropic — Responsible Scaling Policy, Cyber Verification Program, Project Glasswing
**Version/date:** RSP v3.2 (following v3.0 eff. 2026-02-24, v3.1 eff. 2026-04-02). **URL:** https://www.anthropic.com/responsible-scaling-policy ; https://www.anthropic.com/research/glasswing-initial-update
*What it is:* Anthropic's internal safety-gating policy (tiered ASL-3 security standards, periodic public Risk Reports) plus **Project Glasswing**, a defensive vulnerability-finding initiative granting ~50 partners early access to Claude Mythos Preview, extended via a Cyber Verification Program to ~40 additional vetted security orgs. This is the **direct source of metric 7's raw data**: as of the May 2026 update, Glasswing had surfaced 10,000+ high/critical vulnerabilities across 1,000+ OSS projects (6,202 high/critical), including a 27-year-old OpenBSD bug and a 16-year-old FFmpeg bug.

| Metric | Clause(s) |
|---|---|
| 7 | RSP tiered ASL-3 gating; Glasswing CVD disclosure cadence (data source) |

### 4.8 OpenAI — Preparedness Framework + Frontier Governance Framework + Daybreak
**Version/date:** Preparedness Framework v2, updated 2025-04-15 (a v3 rewrite reportedly in progress as of Aug 2026 — **unconfirmed, flag as pending**); Frontier Governance Framework published 2026-05-28; Daybreak launched ~2026-05. **URL:** https://openai.com/index/openai-frontier-governance-framework/ ; https://openai.com/daybreak/
*What it is:* Preparedness Framework evaluates cyber/CBRN/persuasion/autonomy capability against Low/Medium/High/Critical gates. The Frontier Governance Framework maps that internal policy to EU AI Act GPAI Code of Practice and California's frontier-AI transparency law. **Daybreak** is OpenAI's cyber program — Daybreak Blue (defensive) and Daybreak Red (authorized offensive vuln research/exploit validation) — paralleling Anthropic's Glasswing.

| Metric | Clause(s) |
|---|---|
| 7 | Preparedness Framework cyber capability gate; Daybreak disclosure cadence |
| 4 | Daybreak's cited patch-diff-to-exploit compression rationale |

### 4.9 Frontier Model Forum
**Version/date:** Founded 2023-07 (Anthropic, Google DeepMind, Microsoft, OpenAI). **URL:** https://www.frontiermodelforum.org
*What it is:* An industry self-governance nonprofit maintaining an AI-Cyber Workstream that develops shared cyber threat models, safety evaluations, and capability/risk thresholds across labs, tracing back to the May 2024 Seoul Summit Frontier AI Safety Commitments (16 companies).

| Metric | Clause(s) |
|---|---|
| 7 | AI-Cyber Workstream (cross-lab disclosure norms) |
| 5 | Industry-wide risk-threshold reports |

### 4.10 Google Secure AI Framework (SAIF) 2.0
**Version/date:** SAIF 2.0, 2026 update (original SAIF 2023). **URL:** https://safety.google/intl/en/safety/saif/
*What it is:* A six-element framework for securing AI systems, extended in 2.0 with an Agent Risk Map and three agent-security principles (well-defined human controllers, limited agent powers, observable actions/planning); risk-map data is being donated to the Coalition for Secure AI (CoSAI).

| Metric | Clause(s) |
|---|---|
| 9 | Agent Risk Map (agent-based product inventories) |
| 8 | Framework alignment reference |

### 4.11 Microsoft AI Red Team + PyRIT
**Version/date:** PyRIT v0.1x line, "PyRIT 2.0" update noted 2026-04-29. **URL:** https://github.com/Azure/PyRIT
*What it is:* An open-source practitioner tool (not a governance framework) for automated red-teaming of generative AI across text/image/audio/video, tied into Microsoft's AI bounty program.

| Metric | Clause(s) |
|---|---|
| 6 | Feeds Microsoft Patch Tuesday findings |
| 9 | Red-team tool for AI product watchlist |

### 4.12 Cloud Security Alliance — AI Controls Matrix (AICM)
**Version/date:** v1.1, released 2025-07-10; ISO 42001/27001 mappings added Aug 2025. **URL:** https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1
*What it is:* A vendor-agnostic, lifecycle-spanning control matrix (~243–247 objectives across 18 domains, built on CCM v4.1 principles). CSA also launched "STAR for AI," an auditable certification program built on AICM (2025-10-23). *(Detailed control text paraphrased from the artifact summary page.)*

| Metric | Clause(s) |
|---|---|
| 5, 6, 8, 9 | AICM domain controls (umbrella citation) |
| 7 | AI-lifecycle risk-management domain |

---

## 5. 2026 Industry Commentary — Adapting Vulnerability Management to AI-Scale Discovery

*(Reports and analyses, not formal frameworks; included for the Governance tab's "what practitioners are saying" context. Not part of the FRAMEWORKS JSON below.)*

1. **CSA, "The AI Vulnerability Storm: Building a Mythos-Ready Security Program"** (~Apr 2026), https://labs.cloudsecurityalliance.org/research/ai-vulnerability-storm-mythos-ready-security-program/ — CISO guidance framing the April 2026 Mythos disclosures as an inflection point; companion research note on Claude Mythos and the "autonomous offensive threshold."
2. **Palo Alto Networks / Unit 42, "Defender's Guide to the Frontier AI Impact on Cybersecurity"** (Apr 2026, updated May 2026), https://www.paloaltonetworks.com/blog/2026/04/defenders-guide-frontier-ai-impact-cybersecurity/ — found "generational" jump in AI vuln-finding/exploit-generation capability; 2026 Global IR Report clocked fastest breaches at 72 minutes initial-access-to-exfiltration (4x faster YoY).
3. **Cisco, "Shields Up: Guidance for Defending in the Age of AI-Enabled Attacks"** (2026), https://www.cisco.com/c/m/en_us/about/doing_business/trust-center/cisco-defending-against-ai-attacks-guidance.html — a Cisco-branded 2026 posture (harden/understand exposure/validate/hunt/respond), distinct from the historical CISA "Shields Up" campaign name; reports scanning 1.8B lines of customer code.
4. **Zscaler, "Exposure Management After Mythos | Project Glasswing"** (2026), https://www.zscaler.com/blogs/product-insights/exposure-management-after-mythos-4-urgent-changes-security-leaders-must-make — reports Mythos generated 181 working Firefox exploits vs. 2 for Claude Opus 4.6 under the same conditions; argues for environment-specific exploitability assessment over generic CVSS severity.
5. **Sonatype, State of the Software Supply Chain 2026** (2026-01-28), https://www.sonatype.com/state-of-the-software-supply-chain/introduction — 1.233M malicious packages found, 9.8T annual OSS downloads (+67% YoY); frames risk as AI-assisted development introducing bad inputs "at machine speed" rather than using the exact phrase "AI vulnerability storm."
6. **Barracuda, "Mythos Hype Index"** (2026-05-12), https://blog.barracuda.com/2026/05/12/mythos-hype-index-ai-vulnerability-discovery — hype score of 94 (large expectation/outcome gap); notes fewer than 200 CVEs currently credit AI/LLM-assisted discovery despite the narrative.
7. **FIRST.org, 2026 Vulnerability Forecast + Mid-Year Update** (2026-02-11, updated 2026-06-15), https://www.first.org/newsroom/releases/20260211 ; https://www.first.org/newsroom/releases/20260615 — projects ~59,000–66,000 CVEs for 2026; notes exploited/exploitable volume (KEV + EPSS>10%) has stayed comparatively flat even as raw CVE count surges.
8. **NIST, "NIST Updates NVD Operations to Address Record CVE Growth"** (2026-04-15), https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth — NVD moved to risk-based enrichment: only KEV, federal-government, and EO 14028 "critical software" CVEs get full enrichment; ~29,000 backlogged pre-March-2026 CVEs reclassified "Not Scheduled." Driven by a 263% rise in submissions 2020–2025.
9. **CVE Program / CVE Foundation status** — MITRE's CVE contract funding scare (Apr 2025) triggered an 11-month CISA-funded extension and the launch of the nonprofit CVE Foundation (thecvefoundation.org). As of Jan 2026 program meeting minutes, no funding cliff materialized and CISA/MITRE remains the operating channel; the CVE Foundation's own 501(c)(3) standup appears still in progress — no definitive 2026 completion announcement was found.
10. **EPSS v4** (Empirical Security / FIRST EPSS SIG, released 2025-03-16/17 — predates the 2026 surge), https://research.empiricalsecurity.com/research/introducing-epss-version-4 — expanded exploitation-activity coverage to ~12,000 vulns/month (malware/endpoint detection, RSS, Shodan, HackerOne Hacktivity), uses cve.org CNA/ADP data as a backup to NVD (now more relevant given item 8), collapsed CWEs to top-22 categories.
11. **CISA SSVC** (Stakeholder-Specific Vulnerability Categorization), https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc — still CISA's core prioritization framework in 2026 (Vendor + Deployer models); BOD 26-04's tiered remediation table (Sec. 2.6 above) is explicitly informed by SSVC, the concrete 2026 tie between SSVC methodology and federal patch-timeline policy.

---

## 6. Consolidated JSON — `FRAMEWORKS`

```json
FRAMEWORKS = [
  {"id":"nist-csf-2.0","name":"NIST Cybersecurity Framework 2.0","version":"2.0 (CSWP 29)","date":"2024-02-26","url":"https://www.nist.gov/cyberframework","type":"security","relevance":"Outcome-based framework across six functions; ID.RA-08 explicitly covers vulnerability disclosure intake, a direct anchor for AI-found disclosures.","controls":[{"ref":"ID.RA-01","title":"Vulnerabilities identified and recorded","metrics":[5,8,9]},{"ref":"ID.RA-05","title":"Threat/vuln/impact used for risk prioritization","metrics":[2,3,4]},{"ref":"ID.RA-08","title":"Vulnerability disclosure processes established","metrics":[7]},{"ref":"PR.PS-02","title":"Software integrity and patch currency","metrics":[6,10]},{"ref":"DE.CM-09","title":"Hardware/software monitored for adverse events","metrics":[1,3]}]},
  {"id":"iso-27001-27002-2022","name":"ISO/IEC 27001:2022 + 27002:2022","version":"2022","date":"2022-10-25","url":"https://www.iso.org/standard/27001","type":"security","relevance":"Certifiable ISMS plus Annex A control guidance; A.8.8 and A.5.7 are the primary vulnerability-management and threat-intel controls.","controls":[{"ref":"A.5.7","title":"Threat intelligence","metrics":[2,3,4,7]},{"ref":"A.8.8","title":"Management of technical vulnerabilities","metrics":[1,5,9,10]},{"ref":"A.8.29","title":"Security testing in development and acceptance","metrics":[6]},{"ref":"A.5.23","title":"Security for use of cloud services","metrics":[5,9]},{"ref":"A.8.9","title":"Configuration management","metrics":[10]}]},
  {"id":"cis-controls-v8.1","name":"CIS Controls v8.1","version":"8.1","date":"2024-06","url":"https://www.cisecurity.org/controls/v8-1","type":"security","relevance":"Prescriptive safeguards; Control 7 is the tracker's closest operational analog (scan/patch cadence).","controls":[{"ref":"Control 7","title":"Continuous Vulnerability Management","metrics":[1,2,4,5,6,10]},{"ref":"Control 16","title":"Application Software Security","metrics":[6,7,8,9]}]},
  {"id":"nist-800-53-r5","name":"NIST SP 800-53 Rev. 5","version":"Rev 5 (5.1.1 patch)","date":"2020-09","url":"https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final","type":"security","relevance":"Federal control catalog; RA-5/SI-2/SI-5 map directly to scanning, remediation SLAs, and advisory intake.","controls":[{"ref":"RA-5","title":"Vulnerability Monitoring and Scanning","metrics":[1,2,5,9]},{"ref":"SI-2","title":"Flaw Remediation","metrics":[1,4,10]},{"ref":"SI-5","title":"Security Alerts, Advisories, and Directives","metrics":[1,6,7]},{"ref":"SR family","title":"Supply Chain Risk Management","metrics":[5,8,9]}]},
  {"id":"nist-ssdf-800-218","name":"NIST SP 800-218 (SSDF)","version":"1.1","date":"2022-02","url":"https://csrc.nist.gov/pubs/sp/800/218/final","type":"security","relevance":"SDLC vulnerability-response practices; RV group covers intake through root-cause fix.","controls":[{"ref":"RV.1","title":"Identify and confirm vulnerabilities on an ongoing basis","metrics":[1,7]},{"ref":"RV.2","title":"Assess, prioritize, and remediate vulnerabilities","metrics":[1,4,10]},{"ref":"RV.3","title":"Analyze vulnerabilities to identify root causes","metrics":[2,3]}]},
  {"id":"cisa-bod-26-04","name":"CISA BOD 26-04 (supersedes BOD 22-01)","version":"BOD 26-04","date":"2026-06-10","url":"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk","type":"regulation","relevance":"Replaces flat KEV due-dates with a 4-variable risk matrix and 3/14/60-day tiers, explicitly citing AI-compressed exploit timelines; directly validates the tracker's KEV and time-to-exploit metrics.","controls":[{"ref":"BOD 26-04 tiers","title":"3/14/60-day risk-tiered remediation windows","metrics":[1]},{"ref":"BOD 26-04 rationale","title":"AI-compressed disclosure-to-weaponization timeline","metrics":[4]}]},
  {"id":"pci-dss-4.0.1","name":"PCI DSS","version":"4.0.1","date":"2024-06-11","url":"https://www.pcisecuritystandards.org","type":"regulation","relevance":"Mandatory for cardholder-data environments; Req 6.3 and 11.3 cover identification, patching SLA, and scanning cadence.","controls":[{"ref":"6.3.1/6.3.3","title":"Vulnerability identification and 1-month critical/high patch SLA","metrics":[1,5,6,10]},{"ref":"11.3.1/11.3.2","title":"Quarterly internal/external vulnerability scans","metrics":[2,5]}]},
  {"id":"soc2-cc7.1","name":"SOC 2 (AICPA Trust Services Criteria)","version":"2017 TSC, 2022 points of focus","date":"2022","url":"https://www.aicpa-cima.com","type":"security","relevance":"Audit attestation criteria; CC7.1 is the vulnerability/anomaly detection control cited in SOC 2 reports.","controls":[{"ref":"CC7.1","title":"Detection and monitoring for vulnerabilities","metrics":[1,2,5,9]},{"ref":"CC7.2","title":"Anomaly and security-event monitoring/response","metrics":[3,4]}]},
  {"id":"eu-nis2","name":"EU NIS2 Directive","version":"2022/2555","date":"2023-01-16","url":"https://eur-lex.europa.eu/eli/dir/2022/2555","type":"regulation","relevance":"Requires vulnerability handling/disclosure and supply-chain vuln assessment for essential/important entities; transposition still incomplete in several member states as of mid-2026.","controls":[{"ref":"Art.21(2)(e)","title":"Vulnerability handling and disclosure in system acquisition/maintenance","metrics":[6,7,10]},{"ref":"Art.21(2)(d)","title":"Supply-chain security","metrics":[5,8,9]}]},
  {"id":"eu-cra","name":"EU Cyber Resilience Act","version":"Regulation (EU) 2024/2847","date":"2024-12-10","url":"https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act","type":"regulation","relevance":"Reporting obligations for actively-exploited vulnerabilities go live 2026-09-11 (this week); the Art.14 cascade is the clearest regulatory analog to the tracker's KEV/time-to-exploit metrics.","controls":[{"ref":"Art.14","title":"24h/72h/final report cascade for actively exploited vulns","metrics":[1,3,4,7]},{"ref":"Annex I Part II","title":"Vulnerability-handling essential requirements","metrics":[5,8,9,10]}]},
  {"id":"sec-cyber-disclosure","name":"SEC Cybersecurity Disclosure Rule","version":"Item 1.05, Form 8-K","date":"2023-07-26","url":"https://www.sec.gov/newsroom","type":"regulation","relevance":"Material-incident disclosure within 4 business days; downstream trigger context for tracked exploits becoming reportable incidents.","controls":[{"ref":"Item 1.05","title":"4-business-day material incident disclosure","metrics":[3,4]}]},
  {"id":"nist-ai-rmf-1.0","name":"NIST AI Risk Management Framework 1.0","version":"1.0 (NIST.AI.100-1)","date":"2023-01-26","url":"https://www.nist.gov/itl/ai-risk-management-framework","type":"ai","relevance":"Foundational voluntary AI risk framework (Govern/Map/Measure/Manage); predates AI-driven vuln discovery so has no explicit clause for metric 7.","controls":[{"ref":"Govern 1-6","title":"Accountability, risk tolerance, third-party oversight","metrics":[1,5,9]},{"ref":"Map 1-5","title":"Context and categorization of AI use","metrics":[7]},{"ref":"Measure 2.7-2.13","title":"Security and resilience of AI systems","metrics":[4,5]},{"ref":"Manage 2-4","title":"Risk response and prioritization","metrics":[1,6]}]},
  {"id":"nist-ai-600-1","name":"NIST AI 600-1 Generative AI Profile","version":"1.0","date":"2024-07-26","url":"https://doi.org/10.6028/NIST.AI.600-1","type":"ai","relevance":"Closest existing NIST text addressing dual-use cyber-offensive capability of generative models — direct anchor for metric 7.","controls":[{"ref":"Information Security risk category","title":"Cyber-offensive capability / uplift actions","metrics":[7]},{"ref":"GAI dissemination risk actions","title":"Obtain/replicate/disseminate risk","metrics":[3]}]},
  {"id":"nist-ir-8596-cyber-ai-profile","name":"NIST IR 8596 Cyber AI Profile","version":"Preliminary draft (ipd)","date":"2025-12-16 (draft; not final as of 2026-09-06)","url":"https://csrc.nist.gov/pubs/ir/8596/iprd","type":"ai","relevance":"CSF 2.0 profile for AI with a dedicated 'AI for Cybersecurity' track for AI-driven vuln discovery — the most directly on-point framework for metric 7, but still in draft.","controls":[{"ref":"AI for Cybersecurity track","title":"AI-driven vulnerability discovery attribution/disclosure","metrics":[7]},{"ref":"Identify/Detect (AI assets)","title":"AI model/agent asset inventory","metrics":[9]},{"ref":"Respond/Recover","title":"Vulnerability handling extended to AI findings","metrics":[1,4,6,10]}]},
  {"id":"nist-cosais","name":"NIST COSAIS (Control Overlays for Securing AI Systems)","version":"Annotated outline","date":"2026-01 (pre-initial-public-draft)","url":"https://csrc.nist.gov/Projects/cosais","type":"ai","relevance":"Planned SP 800-53 overlays for AI use cases including agentic AI; no citable control IDs published yet.","controls":[{"ref":"pending","title":"Agentic AI / predictive AI overlays (not yet published)","metrics":[7,9]}]},
  {"id":"nist-sp-800-218a","name":"NIST SP 800-218A SSDF Community Profile for GenAI","version":"Final","date":"2024-07","url":"https://csrc.nist.gov/pubs/sp/800/218/a/final","type":"ai","relevance":"Extends SSDF to generative AI/foundation models across the lifecycle including vulnerability response practices.","controls":[{"ref":"PW-family (GAI)","title":"Vulnerability response for AI models","metrics":[4,10]},{"ref":"RV-family (GAI)","title":"Vendor patch cycles for AI/ML supply chain","metrics":[1,6]},{"ref":"PO/PS provenance","title":"Advisory tracking for ML-framework ecosystems","metrics":[8]}]},
  {"id":"iso-42001","name":"ISO/IEC 42001:2023","version":"2023","date":"2023-12","url":"https://www.iso.org/standard/81230.html","type":"ai","relevance":"Certifiable AI management system; governs AI-as-asset (vendor products) more than AI-as-discovery-tool.","controls":[{"ref":"Annex A.6, A.9","title":"AI lifecycle and third-party AI relationships","metrics":[5,9]},{"ref":"Clause 6/8","title":"Risk treatment for organizational AI use","metrics":[1,4,7]}]},
  {"id":"iso-42005","name":"ISO/IEC 42005:2025","version":"2025","date":"2025","url":"https://www.iso.org/standard/42005.html","type":"ai","relevance":"AI system impact assessment process; foreseeable-misuse analysis is the review vehicle for AI-driven vuln-discovery deployment decisions.","controls":[{"ref":"Foreseeable misuse analysis","title":"Dual-use impact assessment","metrics":[7]},{"ref":"Ongoing monitoring","title":"Reassessment triggers","metrics":[9]}]},
  {"id":"iso-27090","name":"ISO/IEC 27090 AI Security","version":"FDIS (ballot closed 2026-08-19)","date":"2026 (not confirmed published as of 2026-09-06)","url":"https://www.iso.org/standard/56581.html","type":"ai","relevance":"AI-specific security threat guidance treating AI as both attack surface and attack tool — directly on point for metric 7 once published.","controls":[{"ref":"Threat taxonomy","title":"AI as attack surface and attack tool","metrics":[7,8]},{"ref":"Lifecycle monitoring","title":"AI product security monitoring","metrics":[9]}]},
  {"id":"iso-23894","name":"ISO/IEC 23894:2023","version":"2023","date":"2023-02","url":"https://www.iso.org/standard/77304.html","type":"ai","relevance":"Generic AI risk-management process (ISO 31000 extension); umbrella process citation, no AI-security specifics.","controls":[{"ref":"Identify-Monitor process","title":"AI risk management lifecycle","metrics":[1,4,5,6,10]}]},
  {"id":"owasp-llm-top10-2025","name":"OWASP Top 10 for LLM Applications","version":"2025","date":"2025","url":"https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/","type":"ai","relevance":"Baseline taxonomy for LLM-application vulnerabilities distinct from classic CWEs.","controls":[{"ref":"LLM01-LLM10","title":"LLM application risk taxonomy","metrics":[2,8]}]},
  {"id":"owasp-agentic-top10-2026","name":"OWASP Top 10 for Agentic Applications","version":"2026","date":"2025-12-09","url":"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/","type":"ai","relevance":"Risks unique to autonomous agents; relevant to classifying AI vulnerability-hunting agents themselves as a risk class.","controls":[{"ref":"ASI02, ASI05","title":"Tool Misuse & Exploitation; Unexpected Code Execution","metrics":[7]},{"ref":"ASI04","title":"Agentic Supply Chain Compromise","metrics":[9]}]},
  {"id":"mitre-atlas","name":"MITRE ATLAS","version":"5.4.0","date":"2026-02","url":"https://atlas.mitre.org","type":"ai","relevance":"ATT&CK-style knowledge base of adversary TTPs against AI/ML systems, expanded in 2026 for agentic AI.","controls":[{"ref":"Tactics/Techniques","title":"AI-pipeline targeting TTPs","metrics":[3]},{"ref":"Mitigations","title":"Pre-empted threat classes for AI-finding programs","metrics":[7]}]},
  {"id":"eu-ai-act","name":"EU AI Act","version":"Regulation (EU) 2024/1689","date":"2024-08-01 (phased; Annex III deferred to 2027-12-02 per May 2026 Digital Omnibus)","url":"https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai","type":"regulation","relevance":"GPAI Code of Practice Safety & Security chapter mandates systemic-risk management and incident notification for GPAI models with systemic risk.","controls":[{"ref":"Code of Practice - Safety & Security","title":"Systemic-risk management and incident notification","metrics":[7]},{"ref":"Notification timeline","title":"2-15 day AI Office notification by severity","metrics":[4]}]},
  {"id":"cisa-nsa-fbi-ai-guidance","name":"CISA/NSA/FBI Joint AI Security Guidance","version":"'Careful Adoption of Agentic AI Services'","date":"2026-04/05","url":"https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services","type":"ai","relevance":"Non-binding Five Eyes guidance defining agentic-AI risk categories and recommending limits on current agentic deployments.","controls":[{"ref":"Agentic AI risk categories","title":"Privilege escalation, config failures, misalignment, brittleness, accountability gaps","metrics":[9]},{"ref":"Deployment guidance","title":"Limit agentic deployments to low-risk tasks","metrics":[3,4]}]},
  {"id":"ncsc-aisi-secure-ai","name":"UK NCSC Guidelines for Secure AI + UK AISI Frontier AI Trends Report","version":"Guidelines 2023; AISI report 2025/2026","date":"2023-11-26 / 2026","url":"https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development","type":"ai","relevance":"SDLC-phase AI security guidance plus independent frontier-model capability evaluation, including a 2026 finding that frontier models attempted to cheat during cyber capability testing.","controls":[{"ref":"AISI capability evaluation","title":"Independent verification of AI cyber capability","metrics":[7]},{"ref":"SDLC-phase guidance","title":"Secure design/development/deployment/operation","metrics":[1]}]},
  {"id":"anthropic-rsp-glasswing","name":"Anthropic RSP + Cyber Verification Program + Project Glasswing","version":"RSP v3.2","date":"2026 (v3.0 eff. 2026-02-24)","url":"https://www.anthropic.com/responsible-scaling-policy","type":"vendor-program","relevance":"Direct source of the tracker's Mythos ledger metric: Glasswing's CVD disclosure cadence is the raw data behind metric 7.","controls":[{"ref":"RSP ASL-3 gating","title":"Tiered safety/security standards for frontier models","metrics":[7]},{"ref":"Glasswing CVD dashboard","title":"Coordinated vulnerability disclosure ledger","metrics":[7]}]},
  {"id":"openai-preparedness-daybreak","name":"OpenAI Preparedness Framework + Frontier Governance Framework + Daybreak","version":"Preparedness v2; Daybreak launched 2026-05","date":"2025-04-15 / 2026-05-28","url":"https://openai.com/daybreak/","type":"vendor-program","relevance":"Parallel AI-vuln-finding/disclosure program to Anthropic's Glasswing; cites exploit-generation-speed compression as rationale.","controls":[{"ref":"Preparedness cyber gate","title":"Cyber capability Low/Medium/High/Critical gating","metrics":[7]},{"ref":"Daybreak disclosure cadence","title":"Defensive/offensive vuln research program","metrics":[4,7]}]},
  {"id":"frontier-model-forum","name":"Frontier Model Forum","version":"n/a","date":"2023-07 (founded)","url":"https://www.frontiermodelforum.org","type":"vendor-program","relevance":"Cross-lab AI-Cyber Workstream likely to arbitrate shared disclosure norms across Mythos/Daybreak-style programs.","controls":[{"ref":"AI-Cyber Workstream","title":"Shared cyber threat models and disclosure norms","metrics":[7]},{"ref":"Risk threshold reports","title":"Industry-wide capability risk thresholds","metrics":[5]}]},
  {"id":"google-saif","name":"Google Secure AI Framework (SAIF)","version":"2.0","date":"2026","url":"https://safety.google/intl/en/safety/saif/","type":"vendor-program","relevance":"Agent Risk Map extends SAIF to agentic AI threats relevant to product watchlist governance.","controls":[{"ref":"Agent Risk Map","title":"Agentic AI threat and control mapping","metrics":[9]},{"ref":"SAIF elements","title":"Framework alignment reference","metrics":[8]}]},
  {"id":"microsoft-pyrit","name":"Microsoft AI Red Team + PyRIT","version":"~2.0 (2026-04-29)","date":"2026-04-29","url":"https://github.com/Azure/PyRIT","type":"vendor-program","relevance":"Open-source automated red-teaming tool for generative AI; findings feed Microsoft's Patch Tuesday and AI bounty program.","controls":[{"ref":"PyRIT orchestrators/scorers","title":"Automated AI red-teaming","metrics":[6,9]}]},
  {"id":"csa-aicm","name":"CSA AI Controls Matrix (AICM)","version":"1.1","date":"2025-07-10","url":"https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1","type":"ai","relevance":"Vendor-agnostic, lifecycle-spanning AI control matrix with ISO 42001/27001 mappings; umbrella citation for AI governance program maturity.","controls":[{"ref":"AICM domains","title":"18-domain AI lifecycle control set","metrics":[5,6,8,9]},{"ref":"AI-lifecycle risk domain","title":"Risk management for AI systems","metrics":[7]}]},
  {"id":"epss-v4","name":"EPSS v4 (Exploit Prediction Scoring System)","version":"4","date":"2025-03-16","url":"https://research.empiricalsecurity.com/research/introducing-epss-version-4","type":"security","relevance":"Expanded exploitation-activity coverage and non-NVD data sources; underpins fresh-vs-old CVE prioritization and time-to-exploit scoring.","controls":[{"ref":"EPSS score","title":"Exploitation-probability scoring using multi-source telemetry","metrics":[2,4]}]},
  {"id":"cisa-ssvc","name":"CISA SSVC (Stakeholder-Specific Vulnerability Categorization)","version":"current","date":"2019 (2026 tie-in via BOD 26-04)","url":"https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc","type":"security","relevance":"CISA's core prioritization methodology; explicitly informs BOD 26-04's tiered remediation windows.","controls":[{"ref":"Vendor/Deployer models","title":"Decision-tree vulnerability prioritization","metrics":[1,4]}]},
  {"id":"nist-nvd-2026-triage","name":"NIST NVD Risk-Based Enrichment Triage","version":"2026 operational change","date":"2026-04-15","url":"https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth","type":"regulation","relevance":"NVD now fully enriches only KEV/federal/critical-software CVEs; a data-quality caveat for the tracker's fresh-vs-old CVE ratio and vendor CVE volume metrics.","controls":[{"ref":"Risk-based enrichment scope","title":"KEV/federal/critical-software prioritization; ~29,000 CVEs reclassified Not Scheduled","metrics":[1,2,5,6]}]},
  {"id":"cve-foundation-status","name":"CVE Program Funding / CVE Foundation","version":"n/a","date":"2026 (status as of Jan 2026 program minutes)","url":"https://www.thecvefoundation.org","type":"regulation","relevance":"Governance/funding continuity for the CVE identifier system underlying every metric on the tracker; no funding cliff materialized in 2026 but the Foundation's independent standup remains in progress.","controls":[{"ref":"CISA/MITRE operating channel","title":"Continued CVE Program operation, no 2026 funding lapse","metrics":[5,6,8]}]}
]
```
