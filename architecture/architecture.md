# Wazuh SOC Detection Lab Architecture

## Overview

This document describes the architecture of the Wazuh SOC Detection Lab.

The laboratory demonstrates endpoint telemetry collection, security event analysis, custom detection engineering, MITRE ATT&CK mapping, and alert validation using a controlled Windows 11 environment.

## Architecture Diagram

```text
                         SOC Detection Laboratory
                                  │
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │     Windows 11 Target   │
                     │                         │
                     │  PowerShell Activity    │
                     │  File Activity          │
                     │  Process Activity       │
                     └────────────┬────────────┘
                                  │
                                  │ Sysmon Telemetry
                                  ▼
                     ┌─────────────────────────┐
                     │       Microsoft Sysmon  │
                     │                         │
                     │ Event ID 1              │
                     │ Process Creation        │
                     │                         │
                     │ Event ID 11             │
                     │ File Creation           │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │      Wazuh Agent        │
                     │       Agent 008         │
                     │                         │
                     │ Collects endpoint       │
                     │ security telemetry      │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │     Wazuh Manager       │
                     │                         │
                     │ Event Processing        │
                     │ Decoders                │
                     │ Detection Rules         │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │   Built-in Wazuh Rules  │
                     │                         │
                     │ 92023                   │
                     │ 92024                   │
                     │ 92213                   │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │   Custom Detection Rules│
                     │                         │
                     │ 100001 — Level 10       │
                     │ 100002 — Level 12       │
                     │ 100003 — Level 15       │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │      Wazuh Alert        │
                     │                         │
                     │ Severity                 │
                     │ MITRE ATT&CK            │
                     │ Agent Context            │
                     │ Event Context            │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │    Wazuh Dashboard      │
                     │                         │
                     │ Alert Investigation     │
                     │ Detection Validation    │
                     │ SOC Monitoring          │
                     └─────────────────────────┘
```

## Components

### 1. Windows 11 Endpoint

The Windows 11 virtual machine acts as the monitored endpoint.

Controlled laboratory activity is performed on this endpoint to generate security telemetry for detection validation.

### 2. Microsoft Sysmon

Microsoft Sysmon provides detailed Windows endpoint telemetry.

The project currently uses:

* **Sysmon Event ID 1 — Process Create**
* **Sysmon Event ID 11 — File Create**

These events provide the telemetry required by the custom detections.

### 3. Wazuh Agent

The Wazuh Agent runs on the Windows 11 endpoint and forwards security telemetry to the Wazuh Manager.

The validated laboratory endpoint uses:

```text
Agent Name: Windows11-Target
Agent ID: 008
```

### 4. Wazuh Manager

The Wazuh Manager receives and processes endpoint telemetry.

The processing pipeline includes:

```text
Telemetry
   ↓
Decoder
   ↓
Built-in Wazuh Rule
   ↓
Custom Detection Rule
   ↓
Security Alert
```

### 5. Built-in Wazuh Detection Rules

The custom detections leverage existing Wazuh detection logic.

Validated supporting rules include:

```text
92023 — PowerShell VSS/SAM activity
92024 — PowerShell SAM hive copy from VSS
92213 — Local Temp file creation
```

### 6. Custom Detection Rules

The project contains three validated custom rules:

| Rule   | Level | Detection                             | Sysmon Event |
| ------ | ----: | ------------------------------------- | ------------ |
| 100001 |    10 | PowerShell Encoded Command            | Event ID 1   |
| 100002 |    12 | PowerShell VSS/SAM Access             | Event ID 1   |
| 100003 |    15 | PowerShell File Created in Local Temp | Event ID 11  |

### 7. MITRE ATT&CK Mapping

The detections are mapped to relevant MITRE ATT&CK techniques:

```text
T1059.001 — PowerShell
T1003.002 — Security Account Manager
T1105     — Ingress Tool Transfer
```

### 8. Wazuh Dashboard

The Wazuh Dashboard provides the analyst-facing interface for reviewing and validating generated security alerts.

Dashboard evidence was captured for the validated detections.

## Detection Pipeline

The complete detection pipeline is:

```text
Windows 11 Activity
        ↓
Sysmon Telemetry
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Event Decoder
        ↓
Built-in Wazuh Rule
        ↓
Custom Detection Rule
        ↓
MITRE ATT&CK Mapping
        ↓
Wazuh Security Alert
        ↓
Wazuh Dashboard
```

## Validation

The project has validated real endpoint telemetry flowing through the detection pipeline.

Validated custom detections:

```text
100001 — PowerShell Encoded Command — Level 10
100002 — PowerShell VSS/SAM Access — Level 12
100003 — PowerShell File Created in Local Temp — Level 15
```

The resulting alerts were verified through the Wazuh alert pipeline and Dashboard.

## Laboratory Scope

All testing is performed in a controlled virtual laboratory environment.

The purpose of the laboratory is defensive detection engineering and SOC investigation practice.

The architecture is designed to be extended with automated threat-enrichment capabilities in a future phase.
