"""
mitre_mapper.py

Responsibility: Map a NormalizedAlert to a MITRE ATT&CK
tactic and technique using two layers:

  Layer 1 — Static lookup table (fast, free, deterministic)
  Layer 2 — LLM enrichment (for findings not in the table)

CONCEPT: Separation of concerns
This module only does one thing: ATT&CK mapping.
It does not triage, does not generate tickets, does not log.
Single-responsibility modules are easier to test, debug, and replace.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

# Add project root to path so we can import from sibling packages
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingest.normalizer import NormalizedAlert


# ─────────────────────────────────────────────────────────────
# CONCEPT: Lookup table as a dict-of-dicts
#
# The outer key is the GuardDuty finding type string.
# The value is a dict with exactly 4 keys that map to
# the MITRE ATT&CK Navigator fields.
#
# Why a dict and not a database or external file?
# For ~30 entries, an in-memory dict is the right tool:
# - O(1) lookup (hash table under the hood)
# - No I/O overhead
# - Version-controlled alongside the code
# - Readable by security engineers without a DB client
#
# At 300+ entries you'd move this to a JSON or SQLite file.
# ─────────────────────────────────────────────────────────────
GUARDDUTY_TO_ATTACK: dict[str, dict] = {

    # ── Discovery ──────────────────────────────────────────────
    "Recon:IAMUser/MaliciousIPCaller": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Cloud service discovery", "technique_id": "T1526"
    },
    "Recon:IAMUser/NetworkPermissions": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Cloud infrastructure discovery", "technique_id": "T1580"
    },
    "Recon:IAMUser/ResourcePermissions": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Cloud infrastructure discovery", "technique_id": "T1580"
    },
    "Recon:EC2/PortProbeUnprotectedPort": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Network service discovery", "technique_id": "T1046"
    },
    "Recon:EC2/Portscan": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique": "Network service scanning", "technique_id": "T1046"
    },

    # ── Credential Access ──────────────────────────────────────
    "UnauthorizedAccess:EC2/SSHBruteForce": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": "Brute force — SSH", "technique_id": "T1110.003"
    },
    "UnauthorizedAccess:EC2/RDPBruteForce": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": "Brute force — RDP", "technique_id": "T1110.001"
    },
    "CredentialAccess:IAMUser/AnomalousBehavior": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": "Valid accounts — cloud accounts", "technique_id": "T1078.004"
    },

    # ── Privilege Escalation ───────────────────────────────────
    "PrivilegeEscalation:IAMUser/AnomalousBehavior": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Abuse elevation control mechanism", "technique_id": "T1098.001"
    },
    "PrivilegeEscalation:Lambda/AnomalousBehavior": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Abuse elevation control mechanism", "technique_id": "T1098"
    },
    "Policy:IAMUser/RootCredentialUsage": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Valid accounts — root account", "technique_id": "T1078.003"
    },

    # ── Persistence ────────────────────────────────────────────
    "Persistence:IAMUser/AnomalousBehavior": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique": "Account manipulation", "technique_id": "T1098.001"
    },
    "Stealth:IAMUser/CloudTrailLoggingDisabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique": "Impair defenses — disable cloud logs", "technique_id": "T1562.008"
    },
    "Stealth:IAMUser/PasswordPolicyChange": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique": "Account manipulation", "technique_id": "T1098"
    },
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique": "Valid accounts — cloud accounts", "technique_id": "T1078.004"
    },

    # ── Exfiltration ───────────────────────────────────────────
    "Exfiltration:S3/AnomalousBehavior": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique": "Exfiltration over web service", "technique_id": "T1567.002"
    },
    "Exfiltration:S3/ObjectRead.Unusual": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique": "Exfiltration over web service", "technique_id": "T1567"
    },
    "Exfiltration:IAMUser/AnomalousBehavior": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique": "Transfer data to cloud account", "technique_id": "T1537"
    },

    # ── Lateral Movement ───────────────────────────────────────
    "LateralMovement:IAMUser/AnomalousBehavior": {
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "technique": "Use alternate auth material", "technique_id": "T1550.001"
    },

    # ── Impact ─────────────────────────────────────────────────
    "Impact:EC2/BitcoinDomainRequest.Reputation": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Resource hijacking", "technique_id": "T1496"
    },
    "Impact:EC2/MaliciousDomainRequest.Reputation": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Data destruction", "technique_id": "T1485"
    },
    "Impact:S3/MaliciousIPCaller": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Data destruction", "technique_id": "T1485"
    },

    # ── Runtime threats ────────────────────────────────────────
    "Backdoor:Runtime/C&CActivity.B!DNS": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": "Application layer protocol — DNS", "technique_id": "T1071.004"
    },
    "Trojan:Runtime/DropPoint": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique": "Exfiltration over web service", "technique_id": "T1567"
    },
    "Trojan:Runtime/DriveBySourceTraffic!DNS": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique": "Application layer protocol — DNS", "technique_id": "T1071.004"
    },
    "Execution:Runtime/NewBinaryExecuted": {
        "tactic": "Execution", "tactic_id": "TA0002",
        "technique": "User execution — malicious file", "technique_id": "T1204.002"
    },
    "Execution:Runtime/SuspiciousShellCreated": {
        "tactic": "Execution", "tactic_id": "TA0002",
        "technique": "Command and scripting interpreter", "technique_id": "T1059"
    },
    "DefenseEvasion:EC2/UnusualDNSResolver": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique": "Hide artifacts", "technique_id": "T1564"
    },
    "PrivilegeEscalation:Kubernetes/AnomalousBehavior": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Exploitation for privilege escalation", "technique_id": "T1068"
    },
    "PrivilegeEscalation:Runtime/ElevationToRoot": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Exploitation for privilege escalation", "technique_id": "T1068"
    },
    "PrivilegeEscalation:Runtime/UserfaultfdSyscall": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique": "Exploitation for privilege escalation", "technique_id": "T1068"
    },
    "Impact:Runtime/SuspiciousDomainRequest.Reputation": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Resource hijacking", "technique_id": "T1496"
    },
    "Impact:Runtime/AbusedDomainRequest.Reputation": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Resource hijacking", "technique_id": "T1496"
    },
    "Impact:IAMUser/AnomalousBehavior": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Account access removal", "technique_id": "T1531"
    },
    "Impact:Kubernetes/MaliciousIPCaller.Custom": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique": "Resource hijacking", "technique_id": "T1496"
    },
    "Persistence:Runtime/SuspiciousCommand": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique": "Event triggered execution", "technique_id": "T1546"
    },
    "CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique": "Brute force — password spraying", "technique_id": "T1110.003"
    },
    "UnauthorizedAccess:EC2/TorClient": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique": "Proxy — Tor", "technique_id": "T1090.003"
    },
    # Note: Policy:IAMUser/RootCredentialUsage is defined above under
    # Privilege Escalation — the duplicate entry that was here has been removed.
}

# Sentinel value — signals "LLM enrichment needed"
UNKNOWN_MAPPING = {
    "tactic": "Unknown",
    "tactic_id": "TA0000",
    "technique": "Pending LLM enrichment",
    "technique_id": "T0000",
    "llm_enriched": False
}


def static_lookup(finding_type: str) -> Optional[dict]:
    """
    Layer 1: O(1) dict lookup.
    Returns the mapping if found, None if not.
    Returning None (not UNKNOWN_MAPPING) lets the caller
    decide whether to try the LLM fallback.
    """
    return GUARDDUTY_TO_ATTACK.get(finding_type)


def llm_enrich(alert: NormalizedAlert, client) -> dict:
    """
    Layer 2: LLM enrichment for unknown finding types.

    CONCEPT: Structured output prompting
    We constrain the LLM to return ONLY a JSON object.
    No preamble, no markdown, no explanation.
    The system prompt sets the role and rules.
    The user prompt provides the specific data.

    CONCEPT: Why separate system and user messages?
    - System message: persistent instructions and role definition
    - User message: the specific data for this request
    This separation helps the model maintain context and
    follow instructions more reliably.
    """
    system_prompt = """You are a MITRE ATT&CK expert specialising in cloud security.
Given an AWS security finding, return ONLY a valid JSON object — no markdown, 
no explanation, no preamble. The object must have exactly these 4 keys:
- tactic (string): the ATT&CK tactic name
- tactic_id (string): e.g. "TA0006"  
- technique (string): the specific technique name
- technique_id (string): e.g. "T1110.003"

If you are uncertain, make your best educated guess based on the finding type name 
and description. Never return null values."""

    user_prompt = f"""Map this AWS GuardDuty finding to MITRE ATT&CK:

Finding type: {alert.finding_type}
Severity: {alert.severity_label} ({alert.severity})
Resource: {alert.resource_type} — {alert.resource_id}
Description: {alert.description}

Return only the JSON object."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt}
            ],
            temperature=0,      # deterministic — same input = same output
            max_tokens=150      # JSON object is small — cap tokens to control cost
        )

        raw = response.choices[0].message.content.strip()

        # CONCEPT: Defensive JSON parsing
        # Strip markdown fences if the model adds them despite instructions.
        # Models sometimes add ```json ... ``` even when told not to.
        raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

        mapping = json.loads(raw)
        mapping["llm_enriched"] = True
        return mapping

    except json.JSONDecodeError as e:
        # LLM returned something unparseable — fall back to unknown
        print(f"[mitre_mapper] LLM returned invalid JSON: {e}")
        return {**UNKNOWN_MAPPING, "llm_enriched": False}

    except Exception as e:
        print(f"[mitre_mapper] LLM call failed: {e}")
        return {**UNKNOWN_MAPPING, "llm_enriched": False}


def map_alert(alert: NormalizedAlert, client=None) -> NormalizedAlert:
    """
    Main entry point: enrich one alert with ATT&CK mapping.

    CONCEPT: Mutating a dataclass
    Dataclasses are mutable by default. We add the 'mitre'
    key to the alert dict (via asdict conversion later) by
    attaching it as an attribute here.

    We use object.__setattr__ because dataclasses can be
    made frozen (immutable). This pattern works either way.
    """
    # Try static lookup first
    mapping = static_lookup(alert.finding_type)

    if mapping is None:
        # Static lookup missed — try LLM if client provided
        if client:
            print(f"[mitre_mapper] No static mapping for '{alert.finding_type}' — calling LLM")
            mapping = llm_enrich(alert, client)
        else:
            mapping = {**UNKNOWN_MAPPING}
    else:
        mapping = {**mapping, "llm_enriched": False}

    # Attach mapping to the alert object
    alert.mitre = mapping
    return alert


def map_all(alerts: list[NormalizedAlert], client=None) -> list[NormalizedAlert]:
    """
    Enrich a list of alerts. Tracks how many needed LLM enrichment
    so you can monitor your API usage.
    """
    llm_calls = 0
    for alert in alerts:
        map_alert(alert, client)
        if getattr(alert, 'mitre', {}).get('llm_enriched'):
            llm_calls += 1

    static_hits = len(alerts) - llm_calls
    print(f"[mitre_mapper] Mapped {len(alerts)} alerts → "
          f"{static_hits} static lookups, {llm_calls} LLM calls")
    return alerts


# ── Smoke test ────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table
    from dataclasses import asdict

    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingest.normalizer import load_and_normalize

    console = Console()

    # Load and normalize alerts
    alerts = load_and_normalize("ingest/mock_alerts.json")

    # Map without LLM client (static only for now — we add API key in Session 3)
    alerts = map_all(alerts, client=None)

    # Display results
    table = Table(title="ATT&CK Mapped Alerts", show_lines=True)
    table.add_column("Severity",  style="bold",   width=10)
    table.add_column("Finding",   style="cyan",   width=28)
    table.add_column("Tactic",    style="purple", width=22)
    table.add_column("Technique", style="green",  width=28)
    table.add_column("ID",        style="yellow", width=12)
    table.add_column("Source",    style="dim",    width=8)

    severity_colors = {
        "CRITICAL": "[red]CRITICAL[/red]",
        "HIGH":     "[orange3]HIGH[/orange3]",
        "MEDIUM":   "[yellow]MEDIUM[/yellow]",
        "LOW":      "[green]LOW[/green]",
    }

    for a in alerts:
        mitre = getattr(a, 'mitre', UNKNOWN_MAPPING)
        source = "LLM" if mitre.get("llm_enriched") else "static"
        table.add_row(
            severity_colors.get(a.severity_label, a.severity_label),
            a.finding_type.split(":")[-1],   # shorten for display
            mitre.get("tactic", "—"),
            mitre.get("technique", "—"),
            mitre.get("technique_id", "—"),
            source
        )

    console.print(table)