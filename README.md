# Wazuh Security Operations & SOAR Integrations

## Overview
This repository is a growing collection of custom **Security Orchestration, Automation, and Response (SOAR)** integrations built within the Wazuh XDR platform.

The goal is to demonstrate applied Security Operations Center (SOC) and detection-engineering work: custom detection rules mapped to the MITRE ATT&CK framework, external threat-intelligence integration, and automated Python-based response pipelines. Each project is self-contained, with its own documentation, scripts, and evidence.

## Repository Architecture
This is structured as a monorepo so that multiple independent SIEM/SOAR integrations can live alongside each other. Each project directory contains its own technical write-up, scripts, and screenshots of the architecture in action.

### Current Projects
- **[1. VirusTotal API & Automated Malware Containment](./wazuh-virustotal)**
  * **Focus:** Malicious file drops, threat-intelligence API integration, Active Response.
  * **Description:** A closed-loop SOAR pipeline that detects new file drops, checks their hashes against the VirusTotal API, and triggers a Python response script that quarantines the file and strips its permissions (`chmod 000`). Includes a custom detection rule mapped to **MITRE ATT&CK T1036.008 (Masquerade File Type)** and automated PDF incident reporting.

### Roadmap
More integrations are in progress and will be added here, 

## Core Capabilities Demonstrated
- **Detection Engineering:** Writing and tuning custom Wazuh XML decoders and rules with PCRE2 regex to detect evasion techniques.
- **Automated Response (SOAR):** Building Active Response scripts that carry out filesystem-level containment on detection.
- **Threat Intelligence:** Bridging internal File Integrity Monitoring (FIM) alerts with external data via REST APIs.
- **Reporting:** Turning raw OpenSearch JSON telemetry into readable incident reports and dashboards.

---

*Note: API keys, environment variables, and local infrastructure details have been removed from these configurations prior to publishing.*
