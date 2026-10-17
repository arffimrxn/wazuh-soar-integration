# VirusTotal API & Automated Malware Containment (SOAR)

## Project Overview
This project implements a Security Orchestration, Automation, and Response (SOAR) pipeline built within Wazuh XDR. The pipeline detects newly dropped files, checks their hashes against VirusTotal's threat intelligence database, and automatically triggers a Python response script that quarantines the file and generates an incident report — bringing time-to-remediation down to seconds with no human intervention.

## Tools Used
* **Wazuh XDR:** Core SIEM, File Integrity Monitoring (FIM), and Active Response engine.
* **VirusTotal API:** External threat intelligence integration for hash lookups.
* **Python 3:** Active Response scripting, using the `fpdf` library for report generation.
* **OpenSearch / Wazuh Dashboard:** Log aggregation, JSON telemetry parsing, and dashboards.
* **Linux (Debian/Kali):** Endpoint simulation and file-permission handling.

## Project Steps
1. **FIM Configuration:** Configured Wazuh File Integrity Monitoring to watch the `/Downloads` directory in real time for new file creation.
2. **API Integration:** Added a VirusTotal API key to the Wazuh manager (`ossec.conf`) to automatically look up the hashes of newly dropped files.
3. **Detection Engineering:** Authored a custom XML rule mapped to **MITRE ATT&CK T1036.008 (Masquerade File Type)** to flag malicious files disguised with a `.pdf` extension.
4. **Active Response Scripting:** Developed a Python response script (`quarantine-killswitch.py`) that triggers on detection.
5. **Attack Simulation:** Dropped an EICAR test string renamed as a financial document (`Q3_Audit_Report.pdf`) to exercise the full detection-to-remediation pipeline.

> **Note on test payload:** This simulation uses the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) — a standard, harmless string every AV engine detects by design — rather than live malware. The near-total VirusTotal detection rate reflects that EICAR is universally flagged; the point of the test is to validate the *pipeline*, not the sample.

## Analysis
The detection relies on a custom Wazuh rule (Level 15 — Critical). It fires when VirusTotal returns a malicious verdict (parent rule `87105`) **and** the reported filename ends in `.pdf`, using a PCRE2 regular expression:

```xml
<rule id="100002" level="15">
    <if_sid>87105</if_sid>
    <field name="virustotal.source.file" type="pcre2">(?i)\.pdf$</field>
    <description>CRITICAL: MITRE T1036.008 - Malicious payload disguised as a PDF document detected!</description>
    <mitre>
      <id>T1036.008</id>
    </mitre>
</rule>
```

The engine parses the incoming JSON telemetry and triggers only when the flagged payload carries a `.pdf` extension, regardless of capitalization (the `(?i)` flag). The end-of-string anchor (`$`) ensures only files *ending* in `.pdf` match, which avoids false positives on filenames that merely contain the string.

The Python script uses a fallback hash-extraction method, searching the nested JSON for a SHA-256 hash first, then falling back to SHA-1 or MD5, so the VirusTotal analysis link is always generated.

> **Scope note:** This rule alerts on a *known-bad hash that happens to carry a PDF extension*. Detecting the masquerade itself — a file *claiming* to be a PDF whose actual content/magic bytes say otherwise — is a separate check (comparing declared extension against content-derived type). That extension-vs-magic-byte comparison is on the roadmap below.

## Reporting
The architecture produces two layers of reporting:

1. **Technical report (Python):** The Active Response script generates a PDF the moment a file is quarantined, recording the file path, VirusTotal detection rate, and a clickable analysis link.
2. **OpenSearch telemetry (Wazuh):** Dashboards and CSV exports from OpenSearch for reviewing threat trends over time.

## Full Alert Reports
The raw CSV telemetry and the generated PDF for this simulation are in the `reports/` directory:

* [Python Incident Report (PDF)](./reports/Incident_Report_kali_20260622_193424.pdf)
* [Wazuh / OpenSearch Telemetry (CSV)](./reports/Critical%20MITRE%20T1036%20PDF%20Alerts.csv)

## Key Findings
During the simulation the pipeline behaved as designed:
* The disguised payload (`Q3_Audit_Report.pdf`) was detected within seconds of hitting disk.
* The Wazuh manager pulled a 61/65 malicious detection rate from VirusTotal.
* The custom Level 15 rule triggered and invoked the Python response script.
* The script moved the payload to a root-owned quarantine directory (`/var/ossec/quarantine`) and stripped all permissions (`chmod 000`), neutralizing the file without human intervention.

## Screenshots

### 1. Main Dashboard Overview
![Main Dashboard](images/01_dashboard_main.png)
*High-level view of the Wazuh security events dashboard and agent status.*

### 2. Critical Alert Trigger (MITRE T1036.008)
![Critical Alert](images/02_dashboard_cricical_alert.png)
*Custom Level 15 rule triggering on the malicious file drop.*

### 3. Alert Table Logs
![Alert Logs](images/03_alert_table_logs.png)
*Tabular view of the security events log capturing the file drop and initial VirusTotal hits.*

### 4. Raw JSON Telemetry Parse
![Raw JSON](images/04_raw_json_telemetry.png)
*OpenSearch telemetry showing the PCRE2 regex hit and nested API data.*

### 5. Quarantine Directory Validation
![Quarantine Directory](images/05_quarantine_vault.png)
*Verification of the automated response: the payload is isolated in a root-owned directory with all permissions revoked (`000`).*

### 6. Terminal Execution Pipeline
![Terminal Execution](images/06_terminal_execution.png)
*Real-time log monitoring showing the Active Response script firing and executing the containment step.*

### 7. Automated Technical PDF Report
![Technical PDF](images/05_technical_pdf_report.png)
*The PDF generated by the Python response script: file path, VirusTotal detection rate, and clickable analysis link.*

### 8. Wazuh Manager API Integration
![Wazuh Configuration](images/07_wazuh_vt_config.png)
*XML API connector bridging internal FIM alerts with external threat intelligence.*

### 9. VirusTotal Portal Verification
![VirusTotal Portal](images/08_virustotal_portal.png)
*VirusTotal matching the payload hash, confirming the alert.*

## Lessons Learned
* **Environment sandboxing:** Working around PEP-668 Python environment restrictions required installing the `fpdf` library into Wazuh's isolated, embedded framework rather than using global system packages.
* **JSON complexity:** Parsing Wazuh's deeply nested alert JSON required defensive, fault-tolerant Python (using `.get()`) so the script wouldn't crash when an expected key was missing.
* **Regex precision:** Using the end-of-string anchor (`$`) in the PCRE2 pattern was important for preventing false positives and matching only true `.pdf` filenames.

## Next Steps
Planned additions to harden this architecture:

* **Content-vs-extension detection:** Add a check that compares a file's declared extension against its content-derived type (magic bytes), to detect file-type masquerading independently of the VirusTotal verdict — a truer implementation of T1036.008.
* **Shodan integration:** Correlate internal alerts with exposed public-facing services to add external attack-surface context.
* **YARA rules:** Move beyond hash lookups with custom YARA signatures that scan files for specific malware byte patterns and strings at the endpoint.

**Disclaimer:** All malware simulations, API integrations, and Active Response executions in this repository were conducted in an isolated, controlled virtual environment. No production systems or external networks were exposed to any payload during development.
