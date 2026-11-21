# Custom SIEM Detection Rules Using Elastic Security and Sysmon

## 1. Introduction

The objective of this project was to create and configure custom security detection rules using Elastic Security and Kibana. These rules were designed to monitor Windows security events, DNS activity, and PowerShell activity.

The rules were configured to help identify potentially suspicious behaviour and generate alerts when matching events were found.

## 2. Tools and Technologies Used

- **Elastic Security:** Used to create and manage detection rules.
- **Kibana:** Used to configure rules and check their execution status.
- **Sysmon:** Used to collect Windows system activity.
- **Windows Event Logs:** Used as a source of security events.
- **KQL:** Used to write detection queries.

## 3. Detection Rules Configured

### 3.1 Windows Credential Stuffing Detection

**Objective:** Monitor repeated failed login attempts that could indicate suspicious authentication activity.

**Configuration:**
- Rule type: Threshold
- Event ID: 4625
- Query: `event.code : "4625" and event.dataset : "system.security"`
- Group by: `source.ip`
- Threshold: 2 events
- Execution interval: 5 minutes

**Implementation and observation:**

The rule was created in Kibana using Windows failed login events. It was configured to group events by source IP address and look for at least two matching events.

The rule's execution history showed successful executions. However, an earlier execution also reported a gap in the event time range. The latest recorded execution succeeded.

No credential-stuffing attack was simulated as part of this configuration.

### 3.2 Sysmon DNS Query Monitoring

**Objective:** Monitor DNS queries recorded by Sysmon for further investigation.

**Configuration:**
- Rule type: Custom query
- Event ID: 22
- Query: `event.code: "22" and dns.question.name: *`
- Execution interval: 5 minutes
- Look-back period: 10 minutes

**Implementation and observation:**

The rule was configured in Kibana to monitor Sysmon DNS Query events. It was enabled to search for events containing DNS query information.

This rule provides visibility into DNS activity and can help an analyst investigate unusual domain requests. It does not independently identify or confirm DNS tunnelling.

### 3.3 Additional Repeated DNS Query Detection

**Objective:** Identify domains receiving repeated DNS queries.

**Configuration:**
- Rule type: Threshold
- Query: `event.category: "network" and dns.question.name: *`
- Group by: `dns.question.name`
- Threshold: 20 events
- Execution interval: 5 minutes
- Look-back period: 5 minutes

**Implementation and observation:**

An additional threshold rule was created in Kibana to monitor repeated DNS queries to the same domain.

The rule was enabled, and its execution status showed that it ran successfully. The recorded execution generated zero alerts.

This confirms that the rule executed, but no matching activity reached the configured threshold during the observed execution. Repeated DNS queries alone are not sufficient to confirm DNS tunnelling.

### 3.4 PowerShell Script Block Monitoring

**Objective:** Monitor PowerShell script activity recorded in Windows event logs.

**Configuration:**
- Rule type: Custom query
- Event ID: 4104
- Query: `event.code: "4104" and event.dataset: "windows.powershell_operational"`
- Execution interval: 5 minutes
- Look-back period: 10 minutes

**Implementation and observation:**

The rule was configured to search for PowerShell Script Block Logging events using Event ID 4104.

These events can provide information about PowerShell commands and scripts executed on a Windows system. The rule supports further investigation of potentially suspicious script activity.

### 3.5 Additional PowerShell Process Detection

**Objective:** Monitor the execution of PowerShell processes.

**Configuration:**
- Rule type: Custom query
- Query: `event.category: "process" and process.name: ("powershell.exe" or "pwsh.exe")`
- Execution interval: 5 minutes
- Look-back period: 5 minutes

**Implementation and observation:**

An additional rule was created in Kibana to search for process events involving `powershell.exe` and `pwsh.exe`.

The rule was enabled, and its execution status showed success. The recorded execution generated zero alerts.

This means no matching events were found during the observed execution. PowerShell process execution by itself does not establish that exploitation has occurred.

## 4. Rule Execution Results

The execution history was checked in Kibana after configuring the additional rules.

| Detection rule | Observed execution status | Alerts generated |
|---|---|---:|
| Windows Credential Stuffing Detection | Succeeded (latest execution) | 0 |
| Repeated DNS Query Detection | Succeeded | 0 |
| PowerShell Process Detection | Succeeded | 0 |

The credential stuffing rule had an earlier execution gap, but its latest recorded execution succeeded.

The repeated DNS query and PowerShell process rules also showed successful execution with zero alerts.

A successful execution means that Kibana ran the rule without an execution error. It does not prove that an attack was detected or that the rule will identify every suspicious activity.

## 5. Observations

During the project, the following activities were completed:

- Created and configured detection rules in Kibana.
- Used Windows Event IDs 4625, 22, and 4104 in detection queries.
- Configured threshold-based detection for repeated failed logins and DNS queries.
- Created an additional rule to monitor PowerShell process execution.
- Enabled the configured rules and reviewed their execution history.
- Checked the execution status and alert count of the additional rules.

The observed executions confirmed that the configured rules could run successfully. However, controlled attack simulations and further testing with known security events would be required to measure their detection accuracy.

## 6. Limitations

- Detection depends on the availability of the required Windows and Sysmon event data.
- Failed login events do not automatically confirm credential stuffing.
- Repeated DNS queries do not automatically indicate DNS tunnelling.
- PowerShell process execution does not automatically indicate malicious activity.
- Zero alerts during an execution do not prove that a rule is ineffective.
- Further testing with controlled events is required to validate the detection rules.

## 7. Conclusion

Custom SIEM detection rules were created and configured using Elastic Security and Kibana to monitor authentication failures, DNS queries, and PowerShell activity.

The rules were enabled, and their execution history was reviewed. The additional repeated DNS query and PowerShell process rules completed their observed executions successfully without generating alerts. The credential stuffing rule's latest execution also succeeded, although an earlier execution gap was reported.

This project provided practical experience in creating SIEM detection rules, writing KQL queries, configuring rule schedules, and reviewing execution results in Kibana. It also demonstrated how custom detection rules can support security monitoring and investigation.
