# Wazuh SOC Detection Lab

A hands-on Security Operations Center (SOC) detection engineering lab built using **Wazuh, Sysmon, and a Windows 11 endpoint**.

The project demonstrates endpoint telemetry collection, custom Wazuh detection engineering, security event analysis, MITRE ATT&CK mapping, and validation of detection rules using controlled laboratory activity.

---

## Project Objective

The objective of this project is to build and validate practical SOC detections using:

* Wazuh SIEM
* Wazuh Agent
* Microsoft Sysmon
* Windows 11
* Custom Wazuh rules
* MITRE ATT&CK
* Controlled security test events

The project focuses on demonstrating the complete detection pipeline from endpoint telemetry generation to a visible Wazuh security alert.

---

## Architecture

```text
                    Windows 11 Target
                           |
                           | Sysmon Telemetry
                           v
                    Wazuh Agent 008
                           |
                           v
                    Wazuh Manager
                           |
                           v
                    Windows EventChannel
                           |
                           v
                    Wazuh Detection Rules
                           |
                           v
                    Custom Detection Rules
                           |
                           v
                     Wazuh Alert
                           |
                           v
                    Wazuh Dashboard
```

---

## Validated Detection Portfolio

| Detection                           | Rule ID | Level | Data Source        | MITRE ATT&CK         | Status                                            |
| ----------------------------------- | ------: | ----: | ------------------ | -------------------- | ------------------------------------------------- |
| PowerShell Encoded Command          |  100001 |    10 | Sysmon Event ID 1  | T1059.001            | VALIDATED                                         |
| PowerShell VSS/SAM Access           |  100002 |    12 | Sysmon Event ID 1  | T1003.002, T1059.001 | VALIDATED                                         |
| PowerShell Executable in Local Temp |  100003 |    15 | Sysmon Event ID 11 | T1105, T1059.001     | IMPLEMENTED / VALIDATION EVIDENCE TO BE COMPLETED |

---

# Detection 1 — PowerShell Encoded Command

**Rule ID:** `100001`

**Severity:** Level 10

**MITRE ATT&CK:** `T1059.001 — PowerShell`

**Data Source:** Sysmon Event ID 1 — Process Create

**Endpoint:** Windows11-Target

**Wazuh Agent:** `008`

### Detection Logic

The custom rule detects PowerShell process creation where the command line contains:

```text
-EncodedCommand
```

Detection flow:

```text
Sysmon Event ID 1
        |
        v
PowerShell Process Creation
        |
        v
-EncodedCommand
        |
        v
Built-in Rule 92057
        |
        v
Custom Rule 100001
        |
        v
Level 10 Alert
        |
        v
Wazuh Dashboard
```

### Validation

A controlled benign encoded PowerShell command was executed to generate Sysmon telemetry.

A real Wazuh alert was observed with:

```text
Rule ID: 100001
Level: 10
Agent: Windows11-Target
Agent ID: 008
MITRE: T1059.001
Decoder: windows_eventchannel
Event ID: 1
```

**Validation Status: PASS**

Detailed documentation:

```text
detections/powershell-encoded-command.md
```

---

# Detection 2 — PowerShell Volume Shadow Copy SAM Access

**Rule ID:** `100002`

**Severity:** Level 12

**Parent Rule:** `92023`

**MITRE ATT&CK:**

* `T1003.002 — Security Account Manager`
* `T1059.001 — PowerShell`

**Data Source:** Sysmon Event ID 1 — Process Create

### Detection Logic

The custom rule is implemented as a child of Wazuh rule `92023`.

```xml
<rule id="100002" level="12">
  <if_sid>92023</if_sid>
  <description>Custom Detection: PowerShell accessed SAM or SECURITY hive through Volume Shadow Copy</description>
  <mitre>
    <id>T1003.002</id>
    <id>T1059.001</id>
  </mitre>
</rule>
```

The detection identifies PowerShell activity involving Volume Shadow Copy paths and sensitive SAM or SECURITY registry hive references.

Detection flow:

```text
Windows 11
    |
    v
PowerShell Process Creation
    |
    v
Sysmon Event ID 1
    |
    v
Wazuh Agent
    |
    v
Wazuh Manager
    |
    v
Rule 92023
    |
    v
Custom Rule 100002
    |
    v
Level 12 Alert
    |
    v
Wazuh Dashboard
```

### Validation

A controlled test generated the required Sysmon process-creation telemetry.

A real Wazuh alert was observed:

```text
Rule ID: 100002
Level: 12
Agent: Windows11-Target
Agent ID: 008
Event ID: 1
```

The detection was validated without performing credential extraction.

**Validation Status: PASS**

Detailed documentation:

```text
detections/sam-vss-access.md
```

---

# Detection 3 — PowerShell Executable Dropped in Local Temp

**Rule ID:** `100003`

**Severity:** Level 15

**Parent Rule:** `92213`

**MITRE ATT&CK:**

* `T1105 — Ingress Tool Transfer`
* `T1059.001 — PowerShell`

**Data Source:** Sysmon Event ID 11 — File Create

### Detection Logic

The custom rule builds on Wazuh rule `92213` and adds a PowerShell-specific condition.

```xml
<rule id="100003" level="15">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <description>Custom Detection: PowerShell dropped executable in Local Temp directory</description>
  <mitre>
    <id>T1105</id>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Detection flow:

```text
PowerShell
    |
    v
Sysmon Event ID 11
    |
    v
Executable created in Local Temp
    |
    v
Wazuh Agent
    |
    v
Wazuh Manager
    |
    v
Rule 92213
    |
    v
Custom Rule 100003
    |
    v
Level 15 Alert
    |
    v
Wazuh Dashboard
```

### Current Status

The custom detection has been implemented and successfully validated in the Wazuh SOC laboratory.

A live **Level 15 Rule 100003** alert was generated from Sysmon Event ID 11 telemetry collected from the Windows 11 endpoint.

The alert confirmed:

```text
Rule ID: 100003
Level: 15
Agent: Windows11-Target
Agent ID: 008
Sysmon Event ID: 11
MITRE ATT&CK: T1105, T1059.001
```

The alert was successfully written to:

```text
/var/ossec/logs/alerts/alerts.json
```

Dashboard evidence was also captured during validation.

**Validation Status: PASS — LIVE ALERT CONFIRMED**

Detailed documentation:

```text
detections/powershell-temp-executable.md
```

---

# Built-in Wazuh Detection Evidence

The project also validated the underlying Wazuh detection rules used by the custom detections.

## Rule 92023

**Severity:** Level 8

Rule `92023` identifies suspicious PowerShell activity involving Volume Shadow Copy paths and SAM/SECURITY hive references.

A Wazuh Dashboard screenshot was captured showing the detection.

---

## Rule 92024

**Severity:** Level 14

Rule `92024` identifies:

```text
Powershell used to copy SAM hive from VSS
```

A live alert was observed in:

```text
/var/ossec/logs/alerts/alerts.json
```

The alert contained:

```text
Rule ID: 92024
Level: 14
Agent ID: 008
Agent: Windows11-Target
Event ID: 1
PowerShell
Volume Shadow Copy
SAM
```

The activity was performed as a controlled laboratory test.

---

# Evidence

Evidence collected during the project includes Wazuh Dashboard screenshots and live alert records.

Validated evidence currently includes:

```text
92023 — Level 8
92024 — Level 14
100001 — Level 10
100002 — Level 12
```

Live Wazuh alerts were also verified through:

```text
/var/ossec/logs/alerts/alerts.json
```

---

# Technologies

* Wazuh
* Wazuh Agent
* Wazuh Manager
* Wazuh Dashboard
* Microsoft Sysmon
* Windows 11
* Ubuntu
* VirtualBox
* MITRE ATT&CK
* PowerShell
* Git
* GitHub

---

# Repository Structure

```text
wazuh-soc-detection-lab/
│
├── architecture/
│
├── detections/
│   ├── powershell-encoded-command.md
│   ├── sam-vss-access.md
│   └── powershell-temp-executable.md
│
├── docs/
│
├── screenshots/
│
├── sysmon/
│
├── test-events/
│   ├── powershell-encoded-command.json
│   └── sam-vss-access.json
│
├── wazuh/
│   └── rules/
│       └── local_rules.xml
│
├── .gitignore
├── README.md
└── ...
```

---

# Detection Engineering Approach

The project follows a layered detection-engineering approach:

```text
Endpoint Telemetry
       |
       v
Sysmon Event
       |
       v
Built-in Wazuh Detection
       |
       v
Custom Detection Rule
       |
       v
MITRE ATT&CK Mapping
       |
       v
Security Alert
       |
       v
SOC Investigation
```

Custom rules are designed to add project-specific detection logic and severity while leveraging existing Wazuh telemetry and detection capabilities.

---

# Security Considerations

All tests are performed in a controlled laboratory environment.

The purpose of the tests is to validate detection telemetry and rule logic rather than perform unauthorized credential access or compromise.

Detection alerts indicate suspicious behavioral patterns and should not automatically be interpreted as proof of successful compromise.

In a production SOC, analysts should correlate alerts with:

* Process relationships
* User identity
* Command-line arguments
* File activity
* Registry activity
* Authentication events
* Network connections
* Endpoint context
* Threat intelligence

---

# Project Status

| Component                       | Status      |
| ------------------------------- | ----------- |
| Windows 11 endpoint             | PASS        |
| Sysmon telemetry                | PASS        |
| Wazuh Agent                     | PASS        |
| Wazuh Manager                   | PASS        |
| Wazuh Dashboard                 | PASS        |
| Custom Rule 100001              | VALIDATED   |
| Custom Rule 100002              | VALIDATED   |
| Rule 92023 evidence             | CAPTURED    |
| Rule 92024 evidence             | CAPTURED    |
| Custom Rule 100003              | VALIDATED   |
| Rule 100003 final live evidence | CAPTURED    |

---

## Overall Project Status

**Wazuh SOC Detection Lab — ACTIVE / FUNCTIONAL**

The project has successfully demonstrated real endpoint telemetry flowing from Windows 11 through Sysmon and the Wazuh Agent to the Wazuh Manager, where custom detection rules generated security alerts visible through the Wazuh Dashboard.

The currently validated custom detections are:

```text
100001 — PowerShell Encoded Command — Level 10
100002 — PowerShell VSS/SAM Access — Level 12
```

Additional detection engineering is in progress for:

```text
100003 — PowerShell Executable in Local Temp — Level 15
```
