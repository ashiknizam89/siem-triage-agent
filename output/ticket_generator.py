"""
ticket_generator.py

Responsibility: Convert a (NormalizedAlert, TriageDecision) pair
into a structured TriageTicket — the final output of the pipeline.

In production this would POST to Jira, ServiceNow, or PagerDuty.
Here we generate a structured dataclass and print it.
"""

import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from ingest.normalizer import NormalizedAlert
from agent.triage_agent import TriageDecision


@dataclass
class TriageTicket:
    """
    The canonical output object of the entire pipeline.
    One ticket per alert. This is what gets logged, displayed,
    and eventually sent to a SOAR platform or ticketing system.
    """
    # Ticket identity
    ticket_id:        str       # unique ticket ID (UUID)
    created_at:       str       # ISO8601 timestamp

    # From the alert
    alert_id:         str
    finding_type:     str
    severity_label:   str
    severity_score:   float
    resource_type:    str
    resource_id:      str
    environment:      str
    actor_ip:         Optional[str]
    actor_country:    Optional[str]
    event_count:      int
    region:           str

    # From MITRE mapping
    mitre_tactic:     str
    mitre_tactic_id:  str
    mitre_technique:  str
    mitre_tech_id:    str

    # From triage decision
    is_true_positive:     bool
    confidence:           int
    priority:             str
    analyst_summary:      str
    attack_narrative:     str
    immediate_actions:    list[str]
    escalate_to_tier2:    bool
    false_positive_reason: Optional[str]

    # Pipeline metadata
    llm_model:        str = "gpt-4o-mini"
    pipeline_version: str = "1.0.0"


def generate_ticket(
    alert: NormalizedAlert,
    decision: TriageDecision
) -> TriageTicket:
    """
    Assemble a TriageTicket from an alert and its triage decision.

    CONCEPT: Single assembly point
    All field mapping happens here in one place. If the schema
    changes upstream (new field in NormalizedAlert), you only
    update this one function — not every downstream consumer.
    """
    mitre = getattr(alert, 'mitre', {})

    return TriageTicket(
        # Ticket identity
        ticket_id   = str(uuid.uuid4())[:8].upper(),  # short readable ID
        created_at  = datetime.now(timezone.utc).isoformat(),

        # Alert fields
        alert_id      = alert.alert_id,
        finding_type  = alert.finding_type,
        severity_label= alert.severity_label,
        severity_score= alert.severity,
        resource_type = alert.resource_type,
        resource_id   = alert.resource_id,
        environment   = alert.environment,
        actor_ip      = alert.actor_ip,
        actor_country = alert.actor_country,
        event_count   = alert.event_count,
        region        = alert.region,

        # MITRE fields
        mitre_tactic    = mitre.get("tactic", "Unknown"),
        mitre_tactic_id = mitre.get("tactic_id", "TA0000"),
        mitre_technique = mitre.get("technique", "Unknown"),
        mitre_tech_id   = mitre.get("technique_id", "T0000"),

        # Decision fields
        is_true_positive     = decision.is_true_positive,
        confidence           = decision.confidence,
        priority             = decision.priority,
        analyst_summary      = decision.analyst_summary,
        attack_narrative     = decision.attack_narrative,
        immediate_actions    = decision.immediate_actions,
        escalate_to_tier2    = decision.escalate_to_tier2,
        false_positive_reason= decision.false_positive_reason,
    )


def generate_all(results: list[tuple]) -> list[TriageTicket]:
    """Generate tickets for all (alert, decision) pairs."""
    tickets = []
    for alert, decision in results:
        ticket = generate_ticket(alert, decision)
        tickets.append(ticket)
        print(f"[ticket_generator] Created ticket {ticket.ticket_id} "
              f"→ {ticket.priority} | {ticket.finding_type}")
    return tickets


def format_ticket_text(ticket: TriageTicket) -> str:
    """
    Format a ticket as a human-readable text report.
    This is what you'd paste into an incident report or
    send via Slack/email notification.
    """
    tp_label = "TRUE POSITIVE" if ticket.is_true_positive else "FALSE POSITIVE"
    escalate = "YES — Escalate to Tier-2" if ticket.escalate_to_tier2 else "No"
    actions  = "\n".join(f"  {i+1}. {a}"
                         for i, a in enumerate(ticket.immediate_actions))
    fp_block = (f"\nFalse Positive Reason:\n  {ticket.false_positive_reason}"
                if ticket.false_positive_reason else "")

    return f"""
══════════════════════════════════════════════════════════════
TRIAGE TICKET  #{ticket.ticket_id}
Created:       {ticket.created_at}
══════════════════════════════════════════════════════════════

FINDING
  Type:        {ticket.finding_type}
  Severity:    {ticket.severity_label} ({ticket.severity_score}/10)
  Priority:    {ticket.priority}
  Assessment:  {tp_label} ({ticket.confidence}% confidence)
  Escalate:    {escalate}

AFFECTED RESOURCE
  Type:        {ticket.resource_type}
  ID:          {ticket.resource_id}
  Environment: {ticket.environment.upper()}
  Region:      {ticket.region}

THREAT ACTOR
  IP:          {ticket.actor_ip or "Unknown"}
  Country:     {ticket.actor_country or "Unknown"}
  Occurrences: {ticket.event_count}

MITRE ATT&CK
  Tactic:      {ticket.mitre_tactic} ({ticket.mitre_tactic_id})
  Technique:   {ticket.mitre_technique} ({ticket.mitre_tech_id})

ANALYST SUMMARY
  {ticket.analyst_summary}

ATTACK NARRATIVE
  {ticket.attack_narrative}
{fp_block}
IMMEDIATE ACTIONS
{actions}

══════════════════════════════════════════════════════════════
""".strip()