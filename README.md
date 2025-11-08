# 🛰️ CyberSentinels Depi Project — Threat Intelligence & Hunting Pipeline

A structured **Threat Hunting and Threat Intelligence (CTI) Pipeline** that integrates open-source intelligence, adversary profiling, and behavioral analytics to detect and understand advanced persistent threats (APTs) — focusing on **APT41**.

---

## 📑 Table of Contents

* [1. Objective](#1-objective)
* [2. Environment Setup](#2-environment-setup)
* [3. Project Phases](#3-project-phases)

  * [Week 1: Threat Intelligence and IOC Enrichment](#week-1-threat-intelligence-and-ioc-enrichment)
  * [Week 2: Threat Hunting Lab](#week-2-threat-hunting-lab)
  * [Week 3: Tactics, Techniques, and Procedures (TTPs) Mapping](#week-3-tactics-techniques-and-procedures-ttps-mapping)
  * [Week 4: Reporting & Final Presentation](#week-4-reporting--final-presentation)
* [4. Expected Outcomes](#4-expected-outcomes)
* [5. Screenshots](#5-screenshots)
* [6. References](#6-references)

---

## 1. Objective

This project designs and implements a proactive **Threat Hunting and Threat Intelligence Pipeline** integrating **OSINT**, **threat actor profiling**, and **behavioral analytics** for detecting and analyzing **APT41**.

The pipeline uses the **Elastic Stack (Elasticsearch, Logstash, Kibana, Beats)** for data ingestion and visualization, and **MISP** for IOC enrichment and correlation.

---

## 2. Environment Setup

| Component                        | Description                                                               |
| -------------------------------- | ------------------------------------------------------------------------- |
| **Platform**                     | Ubuntu Server (VM)                                                        |
| **SIEM**                         | Elastic Stack (ELK)                                                       |
| **Threat Intelligence Platform** | MISP (Malware Information Sharing Platform)                               |
| **Attack Simulation Tools**      | Metasploit / Atomic Red Team / Nmap                                    |
| **Data Sources**                 | System logs, simulated attack telemetry, network traffic (pcap/Wireshark) |

---

## 3. Project Phases

<details>
<summary>▶️ <b>Week 1: Threat Intelligence and IOC Enrichment</b></summary>

**Goal:** Integrate threat intelligence feeds and classify adversaries using MITRE ATT&CK.

**Key Tasks:**

* Deploy MISP and connect to feeds such as **AlienVault OTX**.
* Collect and normalize IOCs (domains, IPs, hashes, URLs) for **APT41**.
* Map techniques and tactics to the **MITRE ATT&CK** framework.

**Deliverables:**

* IOC Enrichment Documentation (sources, indicators, correlations)
* Threat Actor Profile Report (APT41 overview, TTPs, campaigns, detections)

</details>

---

<details>
<summary>▶️ <b>Week 2: Threat Hunting Lab</b></summary>

**Goal:** Simulate intrusions and perform data-driven hunting operations.

**Key Tasks:**

* Build a lab environment with vulnerable hosts and attacker systems.
* Simulate APT41 TTPs (e.g., credential dumping, web shell deployment).
* Collect and forward logs via **Beats (Winlogbeat)** to **Elasticsearch**.
* Hunt and visualize suspicious activity in **Kibana**.

**Deliverables:**

* Screenshots and log analyses of hunting sessions
* Threat Hunting Hypothesis & Findings Report

</details>

---

<details>
<summary>▶️ <b>Week 3: Tactics, Techniques, and Procedures (TTPs) Mapping</b></summary>

**Goal:** Correlate observed behaviors to MITRE ATT&CK and assess detection coverage.

**Key Tasks:**

* Identify APT41-related behaviors in telemetry data.
* Build ATT&CK Navigator heatmaps for covered/uncovered techniques.
* Analyze visibility and detection gaps.

**Deliverables:**

* MITRE ATT&CK Navigator Heatmap
* Detection Gaps Analysis Report

</details>

---

<details>
<summary>▶️ <b>Week 4: Reporting & Final Presentation</b></summary>

**Goal:** Deliver a complete report and presentation summarizing intelligence, simulation, and detection results.

**Key Tasks:**

* Compile intelligence findings, simulations, and detection results.
* Provide recommendations to close visibility gaps.

**Deliverables:**

* Final CTI & Threat Hunting Report
* End-to-end Presentation on detecting and profiling **APT41**

</details>

---

## 4. Expected Outcomes

* Live integration between **MISP** and **Elastic Stack** for real-time IOC correlation.
* End-to-end **Threat Hunting Workflow** from intelligence to validation.
* Full **APT41 Profile** including mapped TTPs and detection strategies.
* Actionable **Detection Coverage Insights** and improvement roadmap.

---

## 5. Screenshots

> *(Add screenshots here to illustrate dashboards, MISP integrations, or hunting visualizations.)*
> Example placeholders:

* `docs/screenshots/misp_integration.png`
* `docs/screenshots/kibana_dashboard.png`
* `docs/screenshots/attack_simulation.png`

---

## 6. References

* [MITRE ATT&CK Group G0096 – APT41](https://attack.mitre.org/groups/G0096/)
* [ATT&CK® Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0096%2FG0096-enterprise-layer.json)
* [FortiGuard Threat Actor Encyclopedia]([https://www.fortiguard.com/threat-signal-reports](https://www.fortiguard.com/threat-actor/5566/apt41))
* [Apt41: Arisen from Dust](https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust)
* [STIX v2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_1j0vun2r7rgb)
* [CISA STIX Best Practices](https://www.cisa.gov/sites/default/files/2022-12/stix-bp-v1.0.0.pdf)
* Johnson, C., Feldman, L., & Witte, G. (2017). *Cyber Threat Intelligence and Information Sharing*, NIST ITL Bulletin, Gaithersburg, MD.
  [Link](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=923332)
* [ISO 27010:2015 — Information security management](https://www.iso.org/standard/68427.html)
* [ISO/IEC 27032:2012 — Cybersecurity guidelines](https://www.iso.org/standard/78973.html)
* [AlienVault OTX — APT41 Overview](https://otx.alienvault.com/adversary/APT41)
* Example Feeds:
  [Pulse 1](https://otx.alienvault.com/pulse/68abf0f55f8716f665e33ffd) •
  [Pulse 2](https://otx.alienvault.com/pulse/68480e89dbe1f2bc0746a80c) •
  [Pulse 3](https://otx.alienvault.com/pulse/68de2cc8e4c38a8cbc7ffc40)
