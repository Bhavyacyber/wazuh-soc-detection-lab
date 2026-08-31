# PowerShell Encoded Command Detection

## Overview

This detection identifies PowerShell processes executing commands through the `-EncodedCommand` parameter.

Encoded PowerShell commands can be used to obscure command content and are commonly associated with malicious PowerShell execution.

## Detection Pipeline

```text
Windows 11 Endpoint
        ↓
Sysmon Event ID 1
        ↓
Wazuh Windows EventChannel
        ↓
Built-in Rule 92057
        ↓
Custom Rule 100001
        ↓
Wazuh Alert
```

## Detection Logic

The Wazuh custom rule uses the existing Wazuh rule `92057` as its parent rule.

```xml
<rule id="100001" level="10">
  <if_sid>92057</if_sid>
  <description>MITRE T1059.001: PowerShell Encoded Command Detected</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

## Parent Rule

Wazuh rule `92057` detects PowerShell spawning another PowerShell process with an encoded command.

The relevant detection conditions include:

```text
ParentImage: powershell.exe
CommandLine: powershell.exe ... -EncodedCommand
```

## MITRE ATT&CK Mapping

| Field          | Value      |
| -------------- | ---------- |
| Tactic         | Execution  |
| Technique      | T1059.001  |
| Technique Name | PowerShell |
| Wazuh Rule     | 100001     |
| Severity       | Level 10   |
| Log Source     | Sysmon     |
| Event ID       | 1          |

## Validation

The detection was tested using a controlled PowerShell encoded-command event on the Windows 11 lab endpoint.

The event was successfully decoded by Wazuh:

```text
name: 'json'
win.eventdata.commandLine:
'powershell.exe -EncodedCommand ...'
```

The resulting Wazuh alert was generated with:

```text
rule.id: 100001
rule.level: 10
description: MITRE T1059.001: PowerShell Encoded Command Detected
agent.name: Windows11-Target
decoder.name: windows_eventchannel
```

## Result

The custom detection successfully identified a PowerShell encoded-command execution and generated a Wazuh alert mapped to MITRE ATT&CK technique `T1059.001`.

This demonstrates a complete SOC detection workflow from endpoint telemetry collection through custom rule creation, alert generation, and MITRE ATT&CK mapping.
