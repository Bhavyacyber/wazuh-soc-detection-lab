# PowerShell Executable Dropped in Local Temp

## Detection Overview

This detection identifies PowerShell creating an executable file in a user's `AppData\Local\Temp` directory.

This behavior can be associated with malware delivery, payload staging, or execution activity.

## Data Source

* Endpoint: Windows 11
* Telemetry: Sysmon
* Sysmon Event ID: 11 - File Create
* SIEM: Wazuh
* Wazuh Agent: Windows11-Target
* Agent ID: 008

## Wazuh Rules

### Parent Rule

* Rule ID: 92213
* Level: 15
* Description: Executable file dropped in folder commonly used by malware
* MITRE ATT&CK: T1105 - Ingress Tool Transfer

### Custom Rule

* Rule ID: 100003
* Level: 15
* Parent Rule: 92213

The custom rule additionally requires:

```text
win.eventdata.image = powershell.exe
```

## Custom Rule

```xml
<rule id="100003" level="15">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <description>Custom Detection: PowerShell created file in Local Temp directory</description>
  <mitre>
    <id>T1105</id>
    <id>T1059.001</id>
  </mitre>
</rule>
```

## MITRE ATT&CK Mapping

* T1105 - Ingress Tool Transfer
* T1059.001 - PowerShell

## Validation

A controlled test generated a Sysmon Event ID 11 when PowerShell created:

```text
C:\Users\vboxuser\AppData\Local\Temp\__PSScriptPolicyTest_v1rij0ba.oca.ps1
```

The resulting Wazuh alert was:

```text
Rule ID: 100003
Level: 15
Description: Custom Detection: PowerShell created executable in Local Temp directory
Agent: Windows11-Target
Event ID: 11
```

The alert was successfully written to:

```text
/var/ossec/logs/alerts/alerts.json
```

The rule was also successfully visible in the Wazuh Dashboard.

## Rule Validation

The Wazuh analysis engine configuration test completed without errors related to Rule 100003.

Command used:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -E '100003|local_rules|ERROR' | tail -30
```

Result:

```text
No output related to Rule 100003
```

This confirms that the custom rule was accepted by the Wazuh analysis engine.

## Validation Status

Validation Status

**PASS — Live Wazuh alert confirmed**

Rule 100003 generated a real Level 15 alert from Sysmon Event ID 11 telemetry collected from Windows11-Target (Agent 008).

Dashboard evidence was captured during validation.

The detection was successfully validated through the complete telemetry pipeline:

```text
PowerShell
    ↓
Sysmon Event ID 11
    ↓
Wazuh Agent
    ↓
Wazuh Manager
    ↓
Windows EventChannel Decoder
    ↓
Sysmon Event 11 Detection
    ↓
Rule 92213
    ↓
Custom Rule 100003
    ↓
Level 15 Wazuh Alert
    ↓
Wazuh Dashboard
```

## Evidence Summary

The live validation demonstrated:

* Sysmon generated Event ID 11.
* Wazuh Agent 008 received the event.
* Wazuh Manager processed the event.
* Built-in Rule 92213 matched the Local Temp executable creation.
* Custom Rule 100003 matched the PowerShell process.
* A Level 15 alert was generated.
* The alert was stored in `alerts.json`.
* Rule 100003 was visible in the Wazuh Dashboard.
* MITRE ATT&CK techniques T1105 and T1059.001 were associated with the custom detection.
