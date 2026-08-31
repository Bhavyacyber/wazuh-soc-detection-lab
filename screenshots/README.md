# Wazuh SOC Detection Lab — Evidence Screenshots

This directory contains visual evidence captured during validation of the Wazuh SOC Detection Lab.

The screenshots demonstrate that Sysmon telemetry generated on the Windows 11 endpoint was collected by the Wazuh Agent, processed by the Wazuh Manager, matched by Wazuh detection rules, and displayed as security alerts in the Wazuh Dashboard.

All activities shown were performed in a controlled laboratory environment for detection validation.

---

## Evidence Summary

| Rule ID | Detection                             | Level | Sysmon Event | MITRE ATT&CK                          | Evidence |
| ------- | ------------------------------------- | ----: | -----------: | ------------------------------------- | -------- |
| 100001  | PowerShell Encoded Command            |    10 |   Event ID 1 | T1059.001                             | Captured |
| 100002  | PowerShell VSS/SAM Access             |    12 |   Event ID 1 | T1003.002, T1059.001                  | Captured |
| 100003  | PowerShell File Created in Local Temp |    15 |  Event ID 11 | T1105, T1059.001                      | Captured |
| 92023   | PowerShell VSS/SAM Detection          |     8 |   Event ID 1 | Related to VSS/SAM activity           | Captured |
| 92024   | PowerShell SAM Copy from VSS          |    14 |   Event ID 1 | Related to credential-access activity | Captured |

---

# Detection 1 — PowerShell Encoded Command

## Rule 100001

**Severity:** Level 10
**MITRE ATT&CK:** T1059.001 — PowerShell
**Data Source:** Sysmon Event ID 1 — Process Create
**Endpoint:** Windows11-Target
**Wazuh Agent:** 008

### Screenshot: Alert View

**File:** `100001  view.png`

This screenshot shows the Wazuh Dashboard displaying the custom Rule `100001` alert.

It provides visual evidence that the PowerShell encoded-command detection generated a Wazuh security alert.

### Screenshot: Expanded Alert

**File:** `100001 expanded  view.png`

The expanded view provides additional event details associated with the Rule `100001` alert.

The evidence supports the detection chain:

```text
PowerShell Process Creation
        ↓
Sysmon Event ID 1
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Rule 92057
        ↓
Custom Rule 100001
        ↓
Level 10 Alert
        ↓
Wazuh Dashboard
```

**Validation:** PASS

---

# Detection 2 — PowerShell Volume Shadow Copy SAM Access

## Rule 100002

**Severity:** Level 12
**Parent Rule:** 92023
**MITRE ATT&CK:** T1003.002, T1059.001
**Data Source:** Sysmon Event ID 1 — Process Create
**Endpoint:** Windows11-Target
**Wazuh Agent:** 008

### Screenshot: Alert View

**File:** `100002 view.png`

This screenshot shows the Wazuh Dashboard displaying the custom Rule `100002` alert.

It provides evidence that the custom VSS/SAM detection generated a Level 12 Wazuh alert.

### Screenshot: Expanded Alert

**File:** `100002 expanded view.png`

The expanded alert provides additional telemetry associated with the detection.

The evidence supports the detection chain:

```text
PowerShell Process Creation
        ↓
Sysmon Event ID 1
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Rule 92023
        ↓
Custom Rule 100002
        ↓
Level 12 Alert
        ↓
Wazuh Dashboard
```

The test was designed to validate detection telemetry and did not perform credential extraction.

**Validation:** PASS

---

# Detection 3 — PowerShell File Created in Local Temp

## Rule 100003

**Severity:** Level 15
**Parent Rule:** 92213
**MITRE ATT&CK:** T1105, T1059.001
**Data Source:** Sysmon Event ID 11 — File Create
**Endpoint:** Windows11-Target
**Wazuh Agent:** 008

### Screenshot: Alert View

**File:** `100003  view.png`

This screenshot shows the Wazuh Dashboard displaying the custom Rule `100003` alert at Level 15.

It provides visual evidence that Sysmon Event ID 11 telemetry from the Windows 11 endpoint triggered the custom detection.

### Screenshot: Expanded Alert

**File:** `100003 expanded view.png`

The expanded alert provides additional event details.

The validated telemetry included PowerShell creating a file in the user's Local Temp directory, including a test file similar to:

```text
C:\Users\vboxuser\AppData\Local\Temp\__PSScriptPolicyTest_....ps1
```

The evidence supports the detection chain:

```text
PowerShell
        ↓
Sysmon Event ID 11
        ↓
File Created in Local Temp
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Rule 92213
        ↓
Custom Rule 100003
        ↓
Level 15 Alert
        ↓
Wazuh Dashboard
```

The detection identifies suspicious PowerShell file creation in a commonly monitored temporary directory. The observed test event created a `.ps1` file; therefore, this documentation does not claim that an executable `.exe` was created.

**Validation:** PASS — LIVE ALERT CONFIRMED

---

# Built-in Rule Evidence

The project also captured evidence for the built-in Wazuh rules that support the custom detections.

---

# Rule 92023

**Severity:** Level 8

### Screenshot: Alert View

**File:** `92023 view.png`

This screenshot shows the Wazuh Dashboard displaying the built-in Rule `92023` detection.

The rule identifies suspicious PowerShell activity involving Volume Shadow Copy paths and references to sensitive SAM/SECURITY registry hives.

### Screenshot: Expanded Alert

**File:** `92023 expanded view.png`

The expanded view provides additional telemetry associated with the Rule `92023` detection.

This evidence demonstrates the underlying built-in detection that is used as the parent rule for custom Rule `100002`.

**Validation:** PASS

---

# Rule 92024

**Severity:** Level 14

### Screenshot: Alert View

**File:** `92024 view.png`

This screenshot shows the Wazuh Dashboard displaying the built-in Rule `92024` detection.

The rule identifies PowerShell activity associated with copying the SAM hive from a Volume Shadow Copy path.

### Screenshot: Expanded Alert

**File:** `92024 expanded view.png`

The expanded view provides additional event information associated with Rule `92024`.

The activity was performed as a controlled laboratory detection test.

**Validation:** PASS

---

# Evidence Interpretation

These screenshots demonstrate different stages of the Wazuh detection process.

```text
Windows 11 Endpoint
        ↓
Sysmon Telemetry
        ↓
Wazuh Agent 008
        ↓
Wazuh Manager
        ↓
Built-in Wazuh Rule
        ↓
Custom Wazuh Rule
        ↓
Security Alert
        ↓
Wazuh Dashboard
```

The screenshots therefore provide visual evidence that the detection rules were not only configured but produced observable Wazuh alerts from endpoint telemetry.

---

# Evidence Limitations

Dashboard screenshots demonstrate that alerts were generated and displayed, but a screenshot alone does not prove that an underlying activity was malicious.

The detections were validated using controlled laboratory events.

For production deployment, alerts should be investigated using additional telemetry such as:

* Process relationships
* User identity
* Command-line arguments
* File activity
* Registry activity
* Authentication events
* Network connections
* Endpoint context
* Threat intelligence

The presence of a detection alert should therefore be treated as a security signal requiring investigation rather than automatic proof of compromise.

---

# Validation Status

| Evidence                       | Status   |
| ------------------------------ | -------- |
| Rule 100001 Dashboard evidence | PASS     |
| Rule 100002 Dashboard evidence | PASS     |
| Rule 100003 Dashboard evidence | PASS     |
| Rule 92023 Dashboard evidence  | CAPTURED |
| Rule 92024 Dashboard evidence  | CAPTURED |
| Sysmon Event ID 1 evidence     | CAPTURED |
| Sysmon Event ID 11 evidence    | CAPTURED |
| Wazuh Dashboard evidence       | CAPTURED |

**Overall Evidence Status: COMPLETE**

