# 🛡️ Project 4: SIEM Detection Engineering, Alert Triage & SOC Operations

## 📌 Overview
An end-to-end SOC operations and detection engineering lab. This project demonstrates the ingestion of security telemetry into a centralized SIEM, engineering custom detection rules aligned with the **MITRE ATT&CK®** framework, conducting tiered alert triage, and executing incident response workflows for validated threats.

---

## 🏗️ Architecture & Lab Stack
* **SIEM Platform:** Splunk / Elastic SIEM / Microsoft Sentinel *(choose your deployment)*
* **Telemetry & Ingestion:** Sysmon (Windows Event Logs), Linux Auditd, Zeek Network Logs, Suricata IDS
* **Attack Simulation:** Atomic Red Team, Metasploit, PowerShell Empire
* **Ticket & Triage Management:** TheHive / Jira

---

## 🎯 Key Objectives & Deliverables

### 1. Telemetry Pipeline & Data Ingestion
* Configured log shippers (Splunk Forwarder / Elastic Agent) across Windows and Linux endpoints.
* Normalized heterogeneous event streams using standardized data models (CIM / ECS).
* Validated logging coverage across critical telemetry points: Process Creation (Sysmon Event ID 1), Network Connections (Sysmon ID 3), and PowerShell Script Block Logging (Event ID 4104).

### 2. Detection Engineering (MITRE ATT&CK)
Engineered and tested custom correlation searches and detection logic targeting real-world attacker tradecraft:

| Technique ID | Name | Detection Logic | Artifact / Data Source |
| :--- | :--- | :--- | :--- |
| **T1059.001** | PowerShell Encoded Command Execution | CLI arguments matching `-enc` / `-e` with base64 strings | Sysmon EID 1 / Security 4688 |
| **T1003.001** | OS Credential Dumping: LSASS Memory | Suspicious open handle access to `lsass.exe` with mask `0x1010` / `0x1F0FFF` | Sysmon EID 10 |
| **T1053.005** | Scheduled Task Persistence | Anomaly detection on `schtasks.exe /create` spawning non-standard processes | Windows Security 4698 / Sysmon EID 1 |
| **T1071.001** | C2 over Web Protocols | High-frequency beaconing patterns with static jitter | Zeek `http.log` / Proxy Logs |

### 3. Alert Triage & SOC Analysis Workflow
Executed simulated Tier-1 & Tier-2 analyst workflows for every triggered alert:
1. **Initial Assessment:** Scope verification, False Positive vs. True Positive validation.
2. **Context Enrichment:** Correlated IP reputation (VirusTotal, AbuseIPDB), WHOIS data, and endpoint process parentage.
3. **Pivoting & Deep Dive:** Traced parent/child process trees and correlated host artifacts with network connections.
4. **Containment & Response:** Formulated containment playbooks (host isolation via EDR, firewall IOC blocking, token revocation).

---

## 📂 Repository Structure
```text
├── detections/           # Sigma / SPL / KQL detection rules
│   ├── rules/
│   └── tests/            # Attack simulation verification scripts
├── playbooks/            # Standard Operating Procedures (SOPs) & Triage Runbooks
├── samples/              # Sanitized PCAPs, Sysmon logs, and query dumps
└── reports/              # Executive summary and Incident Response case reports
