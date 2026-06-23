# Wazuh Security Operations & SOAR Integrations

## Overview
This repository serves as a centralized engineering portfolio for custom **Security Orchestration, Automation, and Response (SOAR)** architectures built within the Wazuh XDR platform. 

The primary objective of this monorepo is to demonstrate applied, mid-to-senior level Security Operations Center (SOC) capabilities, including custom detection engineering mapped to the MITRE ATT&CK framework, external Threat Intelligence integration, and the development of automated Python-based remediation pipelines.

## Repository Architecture
This is structured as a monorepo to house multiple independent SIEM/SOAR integrations. Each project directory contains its own detailed technical documentation, scripts, and visual evidence of the architecture in action.

### Current Projects

* **[1. VirusTotal API & Automated Malware Containment](./wazuh-virustotal)**
    * **Focus:** Zero-Day File Drops, API Integration, Active Response.
    * **Description:** A closed-loop SOAR pipeline that intercepts file drops, verifies cryptographic hashes via the VirusTotal API, and autonomously executes a Python-based killswitch to quarantine payloads and strip execution permissions (`chmod 000`). Features custom **MITRE T1036 (Masquerading)** detection rules and automated tactical PDF reporting.

---

## Core Capabilities Demonstrated
* **Detection Engineering:** Authoring and tuning custom XML decoders and rules using PCRE2 regex to detect sophisticated evasion techniques.
* **Automated Remediation (SOAR):** Bypassing strict Python environments to engineer Active Response scripts that execute OS-level lockdowns.
* **Threat Intelligence:** Bridging internal File Integrity Monitoring (FIM) alerts with global, crowdsourced data via REST APIs.
* **Forensic Reporting:** Translating raw JSON OpenSearch telemetry into executive-ready incident reports and dashboards.

---
*Note: Sensitive API keys, environment variables, and specific localized infrastructure data have been sanitized from these configurations prior to publishing.*
