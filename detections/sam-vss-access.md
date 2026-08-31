# PowerShell Volume Shadow Copy SAM Access Detection

## Overview

This Wazuh detection identifies suspicious PowerShell activity involving a Windows Volume Shadow Copy path referencing the SAM or SECURITY registry hive.

The detection was implemented and validated in a controlled SOC laboratory environment using:

* Windows 11 target
* Sysmon
* Wazuh Agent
* Wazuh Manager
* Wazuh Dashboard
* PowerShell
* Custom Wazuh detection rule `100002`

The activity is mapped to MITRE ATT&CK techniques **T1003.002 (Security Account Manager)** and **T1059.001 (PowerShell)**.

## Detection Logic

The custom Wazuh rule is implemented as a child rule of the existing Wazuh rule `92023`.

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

The built-in Wazuh rule `92023` identifies the underlying Sysmon Event ID 1 characteristics:

* PowerShell executable
* Volume Shadow Copy path
* SAM or SECURITY hive reference

Rule `100002` raises the custom detection severity to **Level 12** and provides the project's custom MITRE ATT&CK mapping.

## Detection Chain

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
Wazuh Agent 008
    |
    v
Wazuh Manager
    |
    v
Built-in Rule 92023
    |
    v
Custom Rule 100002
    |
    v
Level 12 Wazuh Alert
    |
    v
Wazuh Dashboard
```

## Controlled Test Event

A controlled PowerShell process was generated on the Windows 11 endpoint using:

```powershell
powershell.exe -Command "Write-Output 'C:\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM'"
```

This command was used only to generate a Sysmon Process Creation event containing the detection indicators.

It did **not** dump, copy, or extract the SAM database.

The resulting Sysmon Event ID 1 contained the relevant fields:

```text
OriginalFileName: PowerShell.EXE

CommandLine:
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
-Command
"Write-Output 'C:\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM'"
```

## MITRE ATT&CK Mapping

| Technique | Name                     | Tactic            |
| --------- | ------------------------ | ----------------- |
| T1003.002 | Security Account Manager | Credential Access |
| T1059.001 | PowerShell               | Execution         |

## Rule Information

| Field             | Value                       |
| ----------------- | --------------------------- |
| Custom Wazuh Rule | 100002                      |
| Parent Rule       | 92023                       |
| Severity          | Level 12                    |
| Log Source        | Microsoft Sysmon            |
| Event ID          | 1                           |
| Process           | PowerShell.EXE              |
| Detection Type    | VSS/SAM suspicious activity |

## Validation

The detection was validated using a controlled live event generated on the Windows 11 endpoint.

The telemetry successfully followed the complete detection pipeline:

```text
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

The custom rule `100002` was successfully observed as a live Wazuh alert in the Wazuh Dashboard.

This confirms that the custom detection is operational in the SOC laboratory environment.

## Security Significance

The Windows SAM registry hive contains security-account information. References to sensitive registry hives through Volume Shadow Copy paths can therefore be relevant during credential-access investigations.

PowerShell combined with Volume Shadow Copy references may warrant investigation because similar patterns can occur during credential-access activity.

However, the presence of this pattern alone does not prove that credentials were successfully extracted.

## Detection Limitations

This detection is based on command-line and process-creation telemetry. It identifies suspicious activity patterns rather than proving successful credential extraction.

Potential legitimate administrative or forensic activity involving Volume Shadow Copies may generate similar telemetry.

Additional investigation should therefore consider:

* Parent and child process relationships
* User account
* Process integrity level
* Command-line arguments
* Subsequent file or registry activity
* Authentication events
* Other endpoint telemetry

## Validation Result

**Status: PASS**

The controlled test successfully generated Sysmon Event ID 1 telemetry on Windows 11 and produced the custom Wazuh **Level 12 Rule 100002** alert visible in the Wazuh Dashboard.

This demonstrates successful implementation of a custom Wazuh detection for suspicious PowerShell activity involving Volume Shadow Copy references to the SAM or SECURITY hive.
