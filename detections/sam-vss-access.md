# PowerShell Volume Shadow Copy SAM Access Detection

## Overview

This Wazuh detection identifies suspicious PowerShell activity accessing the Windows SAM or SECURITY registry hive through a Volume Shadow Copy path.

## Detection Logic

The custom Wazuh rule is:

<rule id="100002" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)PowerShell\.EXE</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)HarddiskVolumeShadowCopy[0-9]+.*\\(SAM|SECURITY)</field>
  <description>MITRE T1003.002: PowerShell accessed SAM or SECURITY hive through Volume Shadow Copy</description>
  <mitre>
    <id>T1003.002</id>
    <id>T1059.001</id>
  </mitre>
</rule>

## Test Event

The controlled test event used for Wazuh Logtest was:

{
  "win": {
    "system": {
      "providerName": "Microsoft-Windows-Sysmon",
      "eventID": "1"
    },
    "eventdata": {
      "originalFileName": "PowerShell.EXE",
      "commandLine": "powershell.exe C:\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM"
    }
  }
}

## MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|---|---|---|
| T1003.002 | Security Account Manager | Credential Access |
| T1059.001 | PowerShell | Execution |

## Rule Information

| Field | Value |
|---|---|
| Wazuh Rule | 100002 |
| Severity | Level 12 |
| Log Source | Sysmon |
| Event ID | 1 |
| Process | PowerShell.EXE |

## Validation

The test event was successfully decoded by Wazuh.

The event reached Phase 3 of Wazuh Logtest and matched custom rule 100002 with severity level 12.

This validates the detection logic in the controlled SOC lab environment.

## Security Significance

The Windows SAM database contains credential-related information. Access to sensitive registry hives through Volume Shadow Copies can be relevant to credential-access investigations.
