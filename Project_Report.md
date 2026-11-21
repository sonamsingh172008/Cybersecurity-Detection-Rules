# Custom SIEM Detection Rules Using Elastic Security and Sysmon

## 1. Introduction

This project focuses on developing and configuring custom detection rules using Elastic Security and Kibana. The objective is to monitor security events, identify potentially suspicious activities, and support security investigation.

The project covers three important areas:

- Credential stuffing detection
- DNS activity monitoring
- PowerShell activity monitoring

## 2. Tools and Technologies Used

- **Elastic Security:** Used to create and manage detection rules.
- **Kibana:** Used to configure rules and view execution results.
- **Sysmon:** Used to collect Windows system activity.
- **Windows Event Logs:** Used as a source of security events.
- **KQL:** Used to write detection queries.

## 3. Detection Rules Implemented

### 3.1 Windows Credential Stuffing Detection

**Purpose:** Detect repeated failed Windows login attempts that may indicate credential stuffing or suspicious authentication activity.

- Rule type: Threshold
- Event ID: 4625
- Query: `event.code : "4625" and event.dataset : "system.security"`
- Group by: `source.ip`
- Threshold: 2 events

The rule monitors failed login events and groups them by source IP address.

### 3.2 Sysmon DNS Query Monitoring

**Purpose:** Monitor DNS queries collected through Sysmon to support investigation of potentially suspicious DNS activity.

- Rule type: Custom query
- Event ID: 22
- Query: `event.code: "22" and dns.question.name: *`

This rule monitors DNS query events. It does not independently confirm DNS tunnelling.

### 3.3 Additional Repeated DNS Query Detection

**Purpose:** Identify repeated DNS queries to the same domain that may require further investigation.

- Rule type: Threshold
- Query: `event.category: "network" and dns.question.name: *`
- Group by: `dns.question.name`
- Threshold: 20 events

This additional rule looks for repeated DNS activity. Repeated queries alone do not prove DNS tunnelling.

### 3.4 PowerShell Script Block Monitoring

**Purpose:** Monitor PowerShell Script Block Logging events to support investigation of suspicious script activity.

- Rule type: Custom query
- Event ID: 4104
- Query: `event.code: "4104" and event.dataset: "windows.powershell_operational"`

This rule monitors PowerShell script block events.

### 3.5 Additional PowerShell Process Detection

**Purpose:** Identify PowerShell process execution for further security investigation.

- Rule type: Custom query
- Query: `event.category: "process" and process.name: ("powershell.exe" or "pwsh.exe")`

This additional rule monitors PowerShell process activity. It does not independently establish that exploitation has occurred.

## 4. Rule Scheduling

The original detection rules documented in the repository use:

- Execution interval: 5 minutes
- Look-back period: 10 minutes

The additional rules configured during the later Kibana session use:

- Execution interval: 5 minutes
- Additional look-back time: 5 minutes

## 5. Execution and Testing Results

The following execution results were observed during the additional rule configuration:

| Detection rule | Execution result | Alerts created |
|---|---|---:|
| Windows Credential Stuffing Detection | Succeeded | 0 |
| Repeated DNS Query Detection | Succeeded | 0 |
| PowerShell Process Detection | Succeeded | 0 |

The latest credential stuffing execution succeeded, although earlier execution gaps were reported.

The DNS and PowerShell rules also executed successfully without generating alerts during the observed executions.

A successful execution confirms that the rule ran. It does not prove that the rule detects
