# Wazuh SOC Detection Lab

A hands-on Security Operations Center (SOC) detection lab built using Wazuh, Sysmon, and a Windows 11 endpoint.

## Project Objective

The project demonstrates endpoint telemetry collection, security event analysis, custom detection engineering, and MITRE ATT&CK mapping using Wazuh.

## Current Detection

### PowerShell Encoded Command

- Wazuh Rule ID: `100001`
- Severity: `10`
- MITRE ATT&CK: `T1059.001`
- Technique: PowerShell
- Data Source: Sysmon Event ID 1
- Endpoint: Windows 11

## Architecture

```text
Windows 11
    |
    | Sysmon Events
    v
Wazuh Agent
    |
    v
Wazuh Manager
    |
    v
Detection Rules
    |
    v
Wazuh Alert
    |
    v
Wazuh Dashboard


Technologies
Wazuh
Wazuh Agent
Sysmon
Windows 11
Ubuntu
MITRE ATT&CK
VirtualBox
