# Detection #2 — PowerShell Encoded Command Detection

## 1. Overview

This detection identifies PowerShell processes launched with the `-EncodedCommand` parameter.

Attackers commonly use PowerShell encoded commands to obfuscate command content and make malicious activity harder to identify during log analysis. The detection uses Sysmon Process Creation telemetry and a custom Wazuh rule to identify this behavior.

**Detection ID:** 100001
**Severity:** Level 10 — High
**MITRE ATT&CK:** T1059.001 — PowerShell
**Data Source:** Sysmon Event ID 1 — Process Create
**Endpoint:** Windows11-Target
**Wazuh Agent ID:** 008
**Status:** Validated

---

## 2. Detection Objective

The objective of this detection is to identify PowerShell execution where the command line contains the `-EncodedCommand` parameter.

The detection demonstrates that:

1. Windows 11 generates Sysmon Process Creation telemetry.
2. The Wazuh Agent collects the Sysmon event.
3. The Wazuh Manager receives and analyzes the event.
4. The custom Wazuh rule identifies the encoded PowerShell execution.
5. Wazuh generates a Level 10 security alert.
6. The alert becomes visible in the Wazuh Dashboard.

---

## 3. Detection Logic

The custom Wazuh rule is:

```xml
<rule id="100001" level="10">
    <if_sid>92057</if_sid>
    <field name="win.eventdata.commandLine">(?i)-EncodedCommand</field>
    <description>MITRE T1059.001: PowerShell Encoded Command Detected</description>
    <mitre>
        <id>T1059.001</id>
    </mitre>
    <group>local,sysmon,</group>
</rule>
```

The rule is based on the upstream Sysmon-related detection rule and adds a condition for the `-EncodedCommand` PowerShell parameter.

### Matching condition

```text
Sysmon Process Creation
        +
PowerShell command line
        +
-EncodedCommand
        ↓
Custom Rule 100001
        ↓
Level 10 Alert
```

---

## 4. MITRE ATT&CK Mapping

| Field         | Value                                     |
| ------------- | ----------------------------------------- |
| Tactic        | Execution                                 |
| Technique     | T1059 — Command and Scripting Interpreter |
| Sub-technique | T1059.001 — PowerShell                    |

PowerShell is frequently used by threat actors for execution, automation, payload delivery, and post-compromise activity. Encoded commands provide an additional layer of command-line obfuscation.

---

## 5. Validated Event

The detection was validated using a controlled PowerShell encoded-command test on the Windows 11 endpoint.

### Wazuh Alert

```text
Timestamp: 2026-08-31 10:42:19 +0530
Rule ID: 100001
Rule Level: 10
Description: MITRE T1059.001: PowerShell Encoded Command Detected
Agent ID: 008
Agent Name: Windows11-Target
Agent IP: 192.168.56.112
Decoder: windows_eventchannel
Location: EventChannel
```

### Sysmon Event

```text
Provider: Microsoft-Windows-Sysmon
Event ID: 1
Event: Process Create
Computer: windows11
Event Record ID: 20304
```

The detected process was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The command line contained:

```text
-EncodedCommand
```

The encoded test value was:

```text
VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFcAQQBaAFUASABfAEUATgBDAE8ARABFAEQAXwBUAEUAUwBUACIA
```

This was a controlled benign test payload used only to validate the detection pipeline.

---

## 6. Process Information

The Sysmon event recorded the following process information:

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Image             | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process ID        | `748`                                                       |
| Parent Process ID | `2988`                                                      |
| Parent Image      | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| User              | `WINDOWS11\vboxuser`                                        |
| Integrity Level   | High                                                        |
| Terminal Session  | 1                                                           |
| Current Directory | `C:\WINDOWS\system32\`                                      |
| File Version      | `10.0.26100.5074`                                           |

The parent process was also PowerShell, which is useful contextual information for investigating the process execution chain.

---

## 7. File Hashes

Sysmon recorded the following hashes for the PowerShell executable:

```text
MD5:
A97E6573B97B44C96122BFA543A82EA1

SHA256:
0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46

IMPHASH:
AFACF6DC9041114B198160AAB4D0AE77
```

These values can be used for additional investigation or threat-intelligence enrichment in a production SOC environment.

---

## 8. Detection Pipeline

The validated telemetry flow is:

```text
Windows 11 Target
       │
       │ PowerShell Process Creation
       ▼
Sysmon Event ID 1
       │
       │ -EncodedCommand detected
       ▼
Wazuh Agent
       │
       ▼
Wazuh Manager
       │
       ▼
Built-in Rule 92057
       │
       ▼
Custom Rule 100001
       │
       │ MITRE T1059.001
       ▼
Level 10 Wazuh Alert
       │
       ▼
Wazuh Dashboard
```

---

## 9. Validation Result

| Validation Item                            | Result |
| ------------------------------------------ | ------ |
| Windows 11 endpoint                        | PASS   |
| Sysmon installed and generating Event ID 1 | PASS   |
| PowerShell Process Create telemetry        | PASS   |
| `-EncodedCommand` present in command line  | PASS   |
| Wazuh Agent collection                     | PASS   |
| Wazuh Manager processing                   | PASS   |
| Built-in Rule 92057 correlation            | PASS   |
| Custom Rule 100001 matching                | PASS   |
| Level 10 alert generated                   | PASS   |
| MITRE T1059.001 mapping                    | PASS   |
| Wazuh Dashboard visibility                 | PASS   |

**Overall Detection Status: VALIDATED**

---

## 10. Security Significance

Encoded PowerShell commands can make command-line activity less immediately readable to analysts and can be used as an obfuscation technique during attacks.

This detection therefore provides an additional behavioral signal for PowerShell execution.

The detection should not automatically be treated as proof of malicious activity. Legitimate administrative scripts and software can also use encoded PowerShell commands.

For this reason, a SOC analyst should investigate:

* The decoded command.
* Parent and child process relationships.
* Executing user.
* Integrity level.
* File and process hashes.
* Network connections associated with the process.
* Subsequent PowerShell activity.
* Whether the execution is expected in the environment.

---

## 11. False Positive Considerations

Potential legitimate sources include:

* Enterprise administration scripts.
* Software deployment systems.
* Configuration-management tools.
* Automated Windows administration.
* Security and monitoring software.
* Legitimate PowerShell automation.

Recommended production tuning would include environment-specific allowlisting and additional contextual conditions rather than suppressing all encoded PowerShell activity.

---

## 12. Evidence

The following evidence was captured during validation:

### Evidence 1 — Wazuh Dashboard

The Wazuh Dashboard displayed:

```text
Rule ID: 100001
Level: 10
MITRE T1059.001: PowerShell Encoded Command Detected
Endpoint: Windows11-Target
```

### Evidence 2 — Wazuh Alert JSON

The live alert was retrieved from:

```text
/var/ossec/logs/alerts/alerts.json
```

The alert contained:

```text
"id":"100001"
"level":10
"mitre":{"id":["T1059.001"]}
"agent":{"id":"008","name":"Windows11-Target"}
```

### Evidence 3 — Sysmon Telemetry

The alert contained Sysmon Event ID 1 data showing:

```text
providerName:
Microsoft-Windows-Sysmon

eventID:
1

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
... -EncodedCommand ...
```

---

## 13. Conclusion

Detection #2 successfully demonstrates end-to-end detection of PowerShell encoded-command execution using Wazuh and Sysmon.

The controlled test generated a real Level 10 Wazuh alert through the complete telemetry pipeline:

```text
Sysmon → Wazuh Agent → Wazuh Manager → Rule 100001 → Wazuh Dashboard
```

The detection is mapped to **MITRE ATT&CK T1059.001 (PowerShell)** and has been successfully validated on the Windows 11 target.

**Detection #2: COMPLETE AND VALIDATED.**
