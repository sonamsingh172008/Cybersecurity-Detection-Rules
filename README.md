# Cybersecurity Detection Rules Using Elastic Security and Sysmon

## Project Overview

This project focuses on developing and configuring custom Security Information and Event Management (SIEM) detection rules using **Elastic Security, Kibana, Windows Event Logs, and Sysmon**.

The objective is to monitor security-related events, identify potentially suspicious activities, and generate alerts that can support security monitoring and investigation.

## Objectives

- Configure custom detection rules in Elastic Security.
- Monitor Windows authentication failures.
- Monitor DNS queries collected through Sysmon.
- Monitor PowerShell Script Block Logging events.
- Understand SIEM alert generation and security event monitoring.

## Technologies Used

- **Elastic Security** – SIEM and detection rule management.
- **Kibana** – Security monitoring and visualization.
- **Sysmon** – Windows system activity monitoring.
- **Windows Event Logs** – Security event collection.
- **Kibana Query Language (KQL)** – Detection query configuration.

## Detection Rules Implemented

### 1. Windows Credential Stuffing Detection

- **Rule type:** Threshold
- **Event ID:** 4625
- **Detection query:** `event.code : "4625" and event.dataset : "system.security"`
- **Threshold:** 2 events grouped by `source.ip`
- **Purpose:** Detects repeated failed Windows login attempts that may indicate credential stuffing or suspicious authentication activity.

### 2. Sysmon DNS Query Monitoring

- **Rule type:** Query
- **Event ID:** 22
- **Detection query:** `event.code: "22" and dns.question.name: *`
- **Purpose:** Monitors DNS queries collected through Sysmon to support investigation of potentially suspicious DNS activity.

### 3. PowerShell Script Block Monitoring

- **Rule type:** Query
- **Event ID:** 4104
- **Detection query:** `event.code: "4104" and event.dataset: "windows.powershell_operational"`
- **Purpose:** Monitors PowerShell Script Block Logging events to support investigation of suspicious PowerShell activity.

## Rule Configuration

The exported configurations show:

- All three detection rules are enabled.
- Execution interval: 5 minutes.
- Rule look-back period: 10 minutes.
- Detection queries configured using KQL.

## Project Screenshots

The repository includes screenshots of the Elastic Security dashboard, detection rules, and rule execution results.

See the screenshots available in the repository for visual evidence of the implementation.

## Project Structure

```text
Cybersecurity-Detection-Rules/
│
├── README.md
├── Project_Report.md
│
├── rules/
│   ├── README.md
│   ├── windows-credential-stuffing.ndjson
│   ├── sysmon-dns-monitoring.ndjson
│   └── powershell-script-block-monitoring.ndjson
│
├── Screenshot (4).png
├── Screenshot (5).png
├── Screenshot (7).png
└── Screenshot (8).png
```

## Learning Outcomes

Through this project, I gained practical exposure to:

- SIEM fundamentals and security monitoring.
- Elastic Security detection rule configuration.
- Windows authentication event monitoring.
- Sysmon DNS event monitoring.
- PowerShell activity monitoring.
- KQL-based detection queries.
- Exporting and documenting SIEM detection rules.

## Important Notes

These rules provide basic monitoring and detection capabilities. Their effectiveness depends on correct event collection, field mappings, and configuration of the Elastic environment.

The presence of a detection rule does not guarantee detection of every attack. Further testing and tuning are required to evaluate detection accuracy and reduce false positives.

## Author

**Cybersecurity Project**

GitHub Repository: [Cybersecurity-Detection-Rules](https://github.com/sonamsingh172008/Cybersecurity-Detection-Rules)
