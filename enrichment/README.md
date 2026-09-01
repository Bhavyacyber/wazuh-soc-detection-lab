# Python Threat Enrichment

## Overview

This component provides automated threat-intelligence enrichment for Wazuh security alerts.

The Python utility extracts potential indicators of compromise (IOCs) from Wazuh JSON events and supports enrichment through VirusTotal and AbuseIPDB.

## Architecture

```text
Wazuh Alert
     |
     v
Python Threat Enrichment
     |
     +---- IOC Extraction
     |       |
     |       +---- IPv4 Address
     |       +---- File Hash
     |       +---- Domain
     |
     v
Threat Intelligence
     |
     +---- VirusTotal
     |
     +---- AbuseIPDB
     |
     v
Normalized JSON Result
