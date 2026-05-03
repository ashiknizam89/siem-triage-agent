"""
normalizer.py

Responsibility: take raw GuardDuty JSON (messy, nested, inconsistent)
and produce a clean list of NormalizedAlert dicts.

Key concepts demonstrated:
- Dataclasses for schema enforcement
- Hash-based deduplication
- Defensive field extraction (never crash on missing data)
- Type hints for code clarity
"""

import json
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# CONCEPT: Dataclass as a schema contract
#
# A dataclass is a Python class that exists purely
# to hold structured data. It's like a database row
# definition — it tells anyone reading the code exactly
# what fields a NormalizedAlert has.
#
# Why not just use a plain dict?
# - Dicts give no autocomplete, no type checking
# - A dataclass gives you both, plus a free __repr__
#   so you can print it cleanly for debugging
# ─────────────────────────────────────────────
@dataclass
class NormalizedAlert:
    alert_id:       str             # GuardDuty finding ID
    source:         str             # always "guardduty" for now
    account_id:     str             # AWS account ID
    region:         str             # AWS region
    timestamp:      str             # ISO8601 — when first seen
    finding_type:   str             # e.g. "UnauthorizedAccess:EC2/SSHBruteForce"
    severity:       float           # GuardDuty numeric severity (1.0–10.0)
    severity_label: str             # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
    title:          str             # human-readable finding title
    description:    str             # full finding description for LLM context
    resource_type:  str             # "Instance", "AccessKey", "S3Bucket", etc.
    resource_id:    str             # the specific resource affected
    actor_ip:       Optional[str]   # attacker IP if available
    actor_country:  Optional[str]   # attacker country if available
    event_count:    int             # how many times this was observed
    environment:    str             # "production" / "development" / "unknown"
    fingerprint:    str             # dedup hash — explained below
    raw:            dict            # original finding kept for reference


def _severity_label(score: float) -> str:
    """
    CONCEPT: GuardDuty severity bands
    GuardDuty uses a numeric scale. We convert to
    human-readable labels matching standard SOC terminology.
    """
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    return "LOW"


def _extract_resource_id(resource: dict) -> tuple[str, str]:
    """
    Extract resource type and ID. Assumes keys already lowercased
    by _lowercase_keys() in normalize().
    """
    rtype = resource.get("resourcetype", "Unknown")

    if rtype.lower() == "instance":
        details = resource.get("instancedetails", {})
        rid = details.get("instanceid", "unknown-instance")

    elif rtype.lower() == "accesskey":
        details = resource.get("accesskeydetails", {})
        rid = details.get("username") or details.get("accesskeyid") or "unknown-key"

    elif rtype.lower() == "s3bucket":
        buckets = resource.get("s3bucketdetails", [])
        rid = buckets[0].get("name", "unknown-bucket") if buckets else "unknown-bucket"

    elif rtype.lower() == "ekscluster":
        rid = resource.get("eksclusterdetails", {}).get("name", "unknown-eks-cluster")

    elif rtype.lower() == "kubernetescluster":
        rid = resource.get("kubernetesdetails", {}).get(
            "kubernetesworkloaddetails", {}
        ).get("name", "unknown-k8s-workload")

    elif rtype.lower() == "ecscluster":
        rid = resource.get("ecsclusterdetails", {}).get("name", "unknown-ecs-cluster")

    elif rtype.lower() == "rdsdbinstance":
        rid = resource.get("rdsdbinstancedetails", {}).get(
            "dbinstanceidentifier", "unknown-rds-instance"
        )

    elif rtype.lower() == "rdslimitlessdb":
        rid = resource.get("rdslimitlessdbdetails", {}).get(
            "dbclusteridentifier", "unknown-rds-limitless"
        )

    elif rtype.lower() == "lambda":
        rid = resource.get("lambdadetails", {}).get("functionname", "unknown-lambda")

    elif rtype.lower() == "container":
        rid = resource.get("containerdetails", {}).get("name", "unknown-container")

    else:
        rid = f"unknown-{rtype.lower()}-resource"

    return rtype, rid


def _extract_actor(action: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Extract attacker IP and country from the action block.
    GuardDuty nests this differently for network vs API actions.

    Note: action dict has already been through _lowercase_keys(), so all
    keys are lowercase (e.g. "networkconnectionaction", not "networkConnectionAction").
    """
    # Network connection finding (e.g. SSH brute force)
    net = action.get("networkconnectionaction", {})
    if net:
        ip_details = net.get("remoteipdetails", {})
        return (
            ip_details.get("ipaddressv4"),
            ip_details.get("country", {}).get("countryname")
        )

    # API call finding (e.g. CloudTrail disabled, S3 exfil)
    api = action.get("awsapicallaction", {})
    if api:
        ip_details = api.get("remoteipdetails", {})
        return (
            ip_details.get("ipaddressv4"),
            ip_details.get("country", {}).get("countryname")
        )

    return None, None


def _extract_environment(resource: dict) -> str:
    """
    Check resource tags for an Environment tag.
    This lets the LLM know if the affected asset is
    production (higher priority) or development.

    Note: resource dict has already been through _lowercase_keys(), so all
    keys are lowercase (e.g. "instancedetails", not "instanceDetails").
    Parentheses around the ternary make operator precedence explicit.
    """
    tags = (
        resource.get("instancedetails", {}).get("tags", []) or
        (resource.get("s3bucketdetails", [{}])[0].get("tags", [])
         if resource.get("s3bucketdetails") else [])
    )
    for tag in tags:
        if tag.get("key", "").lower() == "environment":
            return tag.get("value", "unknown").lower()
    return "unknown"


def _make_fingerprint(finding_type: str, resource_id: str, account_id: str) -> str:
    """
    CONCEPT: Hash-based deduplication fingerprint

    We combine the fields that define a UNIQUE alert:
    - finding_type: the category of threat
    - resource_id: which specific resource is affected
    - account_id: which AWS account

    We deliberately EXCLUDE timestamp — the same SSH brute
    force against the same instance is the same alert even
    if GuardDuty re-emits it an hour later.

    hashlib.sha256 produces a deterministic 64-char hex string.
    We take the first 16 chars — enough to be unique, shorter
    to store and display.
    """
    raw_string = f"{finding_type}::{resource_id}::{account_id}"
    return hashlib.sha256(raw_string.encode()).hexdigest()[:16]

def _lowercase_keys(obj):
    """
    CONCEPT: Recursive key normalisation
    AWS Boto3 returns PascalCase keys (Type, Id, AccountId).
    Our normalizer expects camelCase/lowercase (type, id, accountId).
    
    This function recursively converts every dict key in the
    entire finding to lowercase — so 'AccountId' becomes 'accountid',
    'ResourceType' becomes 'resourcetype', etc.
    
    We do this ONCE at the entry point so all downstream
    extraction functions can use consistent lowercase keys
    without any changes.
    """
    if isinstance(obj, dict):
        return {k.lower(): _lowercase_keys(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_lowercase_keys(i) for i in obj]
    return obj


def normalize(raw_finding: dict) -> NormalizedAlert:
    """
    Core normalization function.
    Takes one raw GuardDuty finding dict, returns one NormalizedAlert.
    """
    # Normalise all keys to lowercase — handles both mock (camelCase)
    # and live AWS API responses (PascalCase) transparently
    raw_finding = _lowercase_keys(raw_finding)

    resource = raw_finding.get("resource", {})
    service  = raw_finding.get("service", {})
    action   = service.get("action", {})

    resource_type, resource_id = _extract_resource_id(resource)
    actor_ip, actor_country    = _extract_actor(action)
    environment                = _extract_environment(resource)
    severity                   = float(raw_finding.get("severity", 0.0))
    finding_type               = raw_finding.get("type", "Unknown")
    account_id                 = raw_finding.get("accountId", "unknown")

    return NormalizedAlert(
        alert_id       = raw_finding.get("id", "no-id"),
        source         = "guardduty",
        account_id     = account_id,
        region         = raw_finding.get("region", "unknown"),
        timestamp      = raw_finding.get("createdAt", datetime.now(timezone.utc).isoformat()),
        finding_type   = finding_type,
        severity       = severity,
        severity_label = _severity_label(severity),
        title          = raw_finding.get("title", "Untitled finding"),
        description    = raw_finding.get("description", ""),
        resource_type  = resource_type,
        resource_id    = resource_id,
        actor_ip       = actor_ip,
        actor_country  = actor_country,
        event_count    = service.get("count", 1),
        environment    = environment,
        fingerprint    = _make_fingerprint(finding_type, resource_id, account_id),
        raw            = raw_finding
    )


def normalize_all(findings: list[dict]) -> list[NormalizedAlert]:
    """
    CONCEPT: Pipeline with deduplication

    Processes a list of raw findings. Maintains a set of
    seen fingerprints. Sets are O(1) lookup — checking if
    a fingerprint exists is near-instant even with thousands
    of alerts.
    """
    alerts   = []
    seen     = set()   # fingerprints we've already processed
    skipped  = 0

    for finding in findings:
        try:
            alert = normalize(finding)

            # CONCEPT: set membership check for deduplication
            if alert.fingerprint in seen:
                skipped += 1
                continue

            seen.add(alert.fingerprint)
            alerts.append(alert)

        except Exception as e:
            # Never let one bad finding crash the whole pipeline
            print(f"[WARN] Skipping malformed finding: {e}")
            continue

    print(f"[normalizer] Processed {len(findings)} findings → "
          f"{len(alerts)} unique alerts, {skipped} duplicates dropped")
    return alerts


def load_and_normalize(filepath: str) -> list[NormalizedAlert]:
    """
    Convenience function: load JSON file and normalize everything in it.
    Uses pathlib.Path — more robust than raw string paths.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Alert file not found: {filepath}")

    with open(path) as f:
        raw_findings = json.load(f)

    return normalize_all(raw_findings)


# ─────────────────────────────────────────────
# CONCEPT: if __name__ == "__main__"
#
# This block only runs when you execute this file
# directly (python normalizer.py). It does NOT run
# when another module imports this file.
# This makes it perfect for a quick smoke test.
# ─────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    alerts = load_and_normalize("ingest/mock_alerts.json")

    table = Table(title="Normalized Alerts", show_lines=True)
    table.add_column("Severity",     style="bold")
    table.add_column("Type",         style="cyan")
    table.add_column("Resource",     style="green")
    table.add_column("Actor IP",     style="red")
    table.add_column("Environment",  style="yellow")
    table.add_column("Fingerprint",  style="dim")

    severity_colors = {
        "CRITICAL": "[red]CRITICAL[/red]",
        "HIGH":     "[orange3]HIGH[/orange3]",
        "MEDIUM":   "[yellow]MEDIUM[/yellow]",
        "LOW":      "[green]LOW[/green]",
    }

    for a in alerts:
        table.add_row(
            severity_colors.get(a.severity_label, a.severity_label),
            a.finding_type,
            f"{a.resource_type}: {a.resource_id}",
            a.actor_ip or "—",
            a.environment,
            a.fingerprint
        )

    console.print(table)