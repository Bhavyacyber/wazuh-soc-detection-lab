#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import re
from pathlib import Path

import requests
from dotenv import load_dotenv


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

REQUEST_TIMEOUT = 15


def load_alert(path):
    """Load a JSON alert from disk."""

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def flatten_strings(value):
    """Recursively collect string values from JSON."""

    values = []

    if isinstance(value, dict):
        for item in value.values():
            values.extend(flatten_strings(item))

    elif isinstance(value, list):
        for item in value:
            values.extend(flatten_strings(item))

    elif isinstance(value, str):
        values.append(value)

    return values


def extract_iocs(alert):
    """Extract IPv4 addresses, hashes and domains."""

    strings = flatten_strings(alert)
    text = "\n".join(strings)

    # ---------------------------------------------------------
    # IPv4 addresses
    # ---------------------------------------------------------

    ipv4_candidates = set(
        re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            text
        )
    )

    ipv4 = set()

    for candidate in ipv4_candidates:

        try:
            address = ipaddress.ip_address(candidate)

            if isinstance(address, ipaddress.IPv4Address):
                ipv4.add(candidate)

        except ValueError:
            continue

    # ---------------------------------------------------------
    # File hashes
    # ---------------------------------------------------------

    hashes = set(
        re.findall(
            r"\b[a-fA-F0-9]{32}\b"
            r"|\b[a-fA-F0-9]{40}\b"
            r"|\b[a-fA-F0-9]{64}\b",
            text
        )
    )

    # ---------------------------------------------------------
    # Domains
    # ---------------------------------------------------------

    domain_candidates = set(
        re.findall(
            r"\b(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,63}\b",
            text
        )
    )

    excluded_domains = {
        "powershell.exe",
        "cmd.exe",
        "conhost.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "wmic.exe",
        "svchost.exe",
        "explorer.exe",
        "services.exe",
        "lsass.exe",
        "smss.exe",
        "winlogon.exe",
        "taskhost.exe",
        "taskhostw.exe",
    }

    domains = set()

    for domain in domain_candidates:

        if domain.lower() not in excluded_domains:
            domains.add(domain)

    return {
        "ipv4": sorted(ipv4),
        "hashes": sorted(hashes),
        "domains": sorted(domains),
    }


def hash_type(value):
    """Identify hash algorithm from length."""

    return {
        32: "md5",
        40: "sha1",
        64: "sha256",
    }.get(len(value))


def offline_virustotal(ioc):
    """Simulated VirusTotal response for offline testing."""

    try:
        ipaddress.ip_address(ioc)
        ioc_type = "ip"

    except ValueError:

        if hash_type(ioc):
            ioc_type = hash_type(ioc)
        else:
            ioc_type = "domain"

    return {
        "status": "offline_test",
        "ioc_type": ioc_type,
        "source": "local_test_data",
        "message": "VirusTotal API not queried. Offline demonstration mode.",
    }


def offline_abuseipdb(ip):
    """Simulated AbuseIPDB response for offline testing."""

    return {
        "status": "offline_test",
        "source": "local_test_data",
        "message": "AbuseIPDB API not queried. Offline demonstration mode.",
    }


def query_virustotal(ioc, offline=False):
    """Query VirusTotal or use offline mode."""

    if offline:
        return offline_virustotal(ioc)

    if not VT_API_KEY:

        return {
            "status": "not_configured",
            "message": "VT_API_KEY is not configured.",
        }

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
    }

    try:

        try:
            ipaddress.ip_address(ioc)

            endpoint = f"{VT_URL}/ip/{ioc}"
            ioc_type = "ip"

        except ValueError:

            detected_hash_type = hash_type(ioc)

            if detected_hash_type:

                endpoint = f"{VT_URL}/files/{ioc}"
                ioc_type = detected_hash_type

            else:

                endpoint = f"{VT_URL}/domains/{ioc}"
                ioc_type = "domain"

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 404:

            return {
                "status": "not_found",
                "ioc_type": ioc_type,
            }

        response.raise_for_status()

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "status": "success",
            "ioc_type": ioc_type,
            "reputation": attributes.get("reputation"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "message": str(error),
        }


def query_abuseipdb(ip, offline=False):
    """Query AbuseIPDB or use offline mode."""

    if offline:
        return offline_abuseipdb(ip)

    if not ABUSEIPDB_API_KEY:

        return {
            "status": "not_configured",
            "message": "ABUSEIPDB_API_KEY is not configured.",
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:

        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json().get(
            "data",
            {}
        )

        return {
            "status": "success",
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "total_reports": data.get(
                "totalReports"
            ),
            "country_code": data.get(
                "countryCode"
            ),
            "isp": data.get(
                "isp"
            ),
            "domain": data.get(
                "domain"
            ),
            "is_tor": data.get(
                "isTor"
            ),
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "message": str(error),
        }


def enrich_alert(alert, offline=False):
    """Extract and enrich IOCs."""

    iocs = extract_iocs(alert)

    result = {
        "source": "Wazuh",
        "mode": "offline" if offline else "api",
        "iocs": iocs,
        "enrichment": {
            "virustotal": {},
            "abuseipdb": {},
        },
    }

    # ---------------------------------------------------------
    # IP enrichment
    # ---------------------------------------------------------

    for ip in iocs["ipv4"]:

        result["enrichment"]["virustotal"][ip] = (
            query_virustotal(
                ip,
                offline=offline
            )
        )

        result["enrichment"]["abuseipdb"][ip] = (
            query_abuseipdb(
                ip,
                offline=offline
            )
        )

    # ---------------------------------------------------------
    # Hash enrichment
    # ---------------------------------------------------------

    for file_hash in iocs["hashes"]:

        result["enrichment"]["virustotal"][file_hash] = (
            query_virustotal(
                file_hash,
                offline=offline
            )
        )

    # ---------------------------------------------------------
    # Domain enrichment
    # ---------------------------------------------------------

    for domain in iocs["domains"]:

        result["enrichment"]["virustotal"][domain] = (
            query_virustotal(
                domain,
                offline=offline
            )
        )

    return result


def main():
    """Command-line entry point."""

    parser = argparse.ArgumentParser(
        description="Wazuh threat-enrichment utility"
    )

    parser.add_argument(
        "alert",
        type=Path,
        help="Path to Wazuh JSON alert"
    )

    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use local test responses instead of external APIs"
    )

    args = parser.parse_args()

    try:

        alert = load_alert(args.alert)

    except FileNotFoundError:

        print(
            f"Error: alert file not found: {args.alert}"
        )

        raise SystemExit(1)

    except json.JSONDecodeError as error:

        print(
            f"Error: invalid JSON: {error}"
        )

        raise SystemExit(1)

    result = enrich_alert(
        alert,
        offline=args.offline
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )


if __name__ == "__main__":
    main()
