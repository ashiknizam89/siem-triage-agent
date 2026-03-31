"""
cloudtrail_fetcher.py

Responsibility: Pull recent CloudTrail events to give the
triage agent context about API calls made around the time
of a GuardDuty finding.

CONCEPT: Why CloudTrail alongside GuardDuty?
GuardDuty tells you WHAT threat was detected.
CloudTrail tells you WHAT HAPPENED — every API call made
in your account. Correlating both gives the LLM much
richer context for triage decisions.

Example: GuardDuty fires "CloudTrail logging disabled".
CloudTrail shows: 5 minutes before that, the same IAM user
also called CreateAccessKey and AttachUserPolicy.
That context changes IMMEDIATE → ACTIVE BREACH.
"""

import boto3
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))


def fetch_cloudtrail_events(
    region:        str = "eu-central-1",
    hours_back:    int = 24,
    max_events:    int = 50,
    username:      Optional[str] = None,
    event_names:   Optional[list[str]] = None
) -> list[dict]:
    """
    Pull CloudTrail events with optional filtering.

    CONCEPT: LookupEvents vs CloudTrail Lake
    lookup_events() is the simple, free API — searches
    the last 90 days of management events.
    CloudTrail Lake is the advanced query engine (costs money).
    For this project, lookup_events() is sufficient.

    CONCEPT: AttributeKey filtering
    We can filter by Username, EventName, ResourceName, etc.
    Filtering by username lets us pull "everything this IAM
    user did in the last 24 hours" — very useful for
    correlating with a GuardDuty IAM finding.
    """
    client = boto3.client("cloudtrail", region_name=region)

    start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

    # Build lookup attributes — CloudTrail only accepts ONE
    # attribute filter at a time via this API
    lookup_attrs = []
    if username:
        lookup_attrs.append({
            "AttributeKey": "Username",
            "AttributeValue": username
        })

    kwargs = {
        "StartTime": start_time,
        "MaxResults": max_events
    }
    if lookup_attrs:
        kwargs["LookupAttributes"] = lookup_attrs

    print(f"[cloudtrail] Fetching events since "
          f"{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
          f"(filter: {lookup_attrs or 'none'})")

    events = []
    # CONCEPT: Manual pagination for APIs without a paginator
    # Some Boto3 APIs don't have a get_paginator() method.
    # You handle pagination manually with a while loop and
    # the NextToken from each response.
    while True:
        response = client.lookup_events(**kwargs)
        batch    = response.get("Events", [])
        events.extend(batch)

        next_token = response.get("NextToken")
        if not next_token or len(events) >= max_events:
            break
        kwargs["NextToken"] = next_token

    # Optional: filter by event name in Python
    # (CloudTrail API doesn't support EventName + Username together)
    if event_names:
        events = [
            e for e in events
            if e.get("EventName") in event_names
        ]

    print(f"[cloudtrail] Fetched {len(events)} events")
    return events


def get_security_relevant_events(
    region:     str = "eu-central-1",
    hours_back: int = 24
) -> list[dict]:
    """
    Fetch a curated set of high-value security events.
    These are the CloudTrail calls most associated with
    attacker activity in AWS environments.
    """

    # CONCEPT: High-value security event names
    # These API calls are most commonly seen in attack scenarios.
    # Grouped by ATT&CK tactic for clarity.
    security_events = [
        # Defense Evasion
        "StopLogging", "DeleteTrail", "UpdateTrail",
        "PutEventSelectors", "DeleteFlowLogs",

        # Persistence
        "CreateAccessKey", "CreateUser", "AttachUserPolicy",
        "AttachRolePolicy", "PutUserPolicy", "CreateLoginProfile",
        "UpdateLoginProfile",

        # Privilege Escalation
        "CreateRole", "PutRolePolicy", "AttachRolePolicy",
        "UpdateAssumeRolePolicy", "PassRole",

        # Exfiltration
        "GetObject", "PutBucketPolicy", "DeleteBucketPolicy",
        "PutBucketAcl",

        # Discovery
        "ListBuckets", "DescribeInstances", "ListUsers",
        "GetAccountAuthorizationDetails",

        # Impact
        "TerminateInstances", "DeleteBucket",
        "RunInstances",   # cryptomining
    ]

    events = fetch_cloudtrail_events(
        region=region,
        hours_back=hours_back,
        max_events=100,
        event_names=security_events
    )

    return events


def format_events_for_context(events: list[dict]) -> str:
    """
    CONCEPT: Context formatting for LLM consumption
    We convert CloudTrail events into a compact text format
    that reads naturally for the LLM — not raw JSON.
    This becomes an optional extra block in the triage prompt.

    Format: TIMESTAMP  USERNAME  EVENT_NAME  SOURCE_IP
    """
    if not events:
        return "No relevant CloudTrail events found in the time window."

    lines = ["Recent security-relevant API calls:"]
    lines.append("-" * 60)

    for event in events[:20]:  # Cap at 20 to keep prompt size manageable
        ts       = event.get("EventTime", "")
        if hasattr(ts, "strftime"):
            ts = ts.strftime("%Y-%m-%d %H:%M:%S")
        name     = event.get("EventName", "?")
        username = event.get("Username", "?")
        source   = event.get("SourceIPAddress", "?")
        lines.append(f"  {ts}  {username:25}  {name:35}  {source}")

    return "\n".join(lines)


# ── Smoke test ────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("\n[bold]Fetching security-relevant CloudTrail events...[/bold]\n")

    events = get_security_relevant_events(
        region="eu-north-1",
        hours_back=168   # last 7 days for lab
    )

    if not events:
        console.print(
            "[yellow]No security-relevant events found.[/yellow]\n"
            "This is expected in a quiet lab environment."
        )
    else:
        table = Table(
            title=f"Security-Relevant CloudTrail Events ({len(events)})",
            show_lines=True
        )
        table.add_column("Time",       width=20)
        table.add_column("User",       width=25)
        table.add_column("Event",      width=30)
        table.add_column("Source IP",  width=18)
        table.add_column("Region",     width=12)

        for e in events[:20]:
            ts = e.get("EventTime", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M")
            table.add_row(
                str(ts),
                e.get("Username", "?"),
                e.get("EventName", "?"),
                e.get("SourceIPAddress", "?"),
                e.get("AwsRegion", "?")
            )

        console.print(table)
        console.print(
            "\n[bold]Formatted for LLM context:[/bold]\n"
        )
        console.print(format_events_for_context(events))