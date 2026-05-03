"""
triage_agent.py

Responsibility: Take a NormalizedAlert (with ATT&CK mapping attached)
and produce a structured TriageDecision using GPT-4o-mini.

This is the core intelligence of the entire pipeline.

Key concepts:
- Prompt engineering for security analysis
- Pydantic for output schema validation
- Chain-of-thought reasoning
- Cost-aware API usage
"""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field, ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))
from ingest.normalizer import NormalizedAlert, load_and_normalize
from agent.mitre_mapper import map_all, UNKNOWN_MAPPING

# Load .env so OPENAI_API_KEY is available as an env variable
# CONCEPT: Never hardcode secrets. load_dotenv() reads your .env
# file and injects values into os.environ at runtime.
load_dotenv()


# ─────────────────────────────────────────────────────────────
# CONCEPT: Pydantic models as output contracts
#
# Pydantic is a data validation library. A BaseModel subclass
# defines the exact shape and types we expect from the LLM.
#
# If the LLM returns:
#   - a string where we expect an int → Pydantic raises ValidationError
#   - a missing required field → Pydantic raises ValidationError
#   - an int where we expect a string → Pydantic coerces it
#
# This makes our pipeline robust against LLM inconsistency.
# ─────────────────────────────────────────────────────────────
class TriageDecision(BaseModel):
    """
    The structured output the LLM must produce for every alert.
    Field() lets us add descriptions — these get passed to the LLM
    as part of the output schema, improving compliance.
    """

    is_true_positive: bool = Field(
        description="Is this alert likely a real threat vs a false positive?"
    )
    confidence: int = Field(
        ge=0, le=100,
        description="Confidence in the assessment, 0-100"
    )
    priority: Literal["IMMEDIATE", "HIGH", "MEDIUM", "LOW"] = Field(
        description="Response priority: IMMEDIATE / HIGH / MEDIUM / LOW"
    )
    analyst_summary: str = Field(
        description="2-3 sentence plain-English explanation of what is happening"
    )
    attack_narrative: str = Field(
        description="Describe the likely attacker goal and technique in 1-2 sentences"
    )
    immediate_actions: list[str] = Field(
        description="Ordered list of specific containment/investigation actions"
    )
    escalate_to_tier2: bool = Field(
        description="Should this be escalated to a senior analyst?"
    )
    false_positive_reason: Optional[str] = Field(
        default=None,
        description="If is_true_positive is false, explain why this might be benign"
    )


# ─────────────────────────────────────────────────────────────
# CONCEPT: The system prompt — the agent's identity
#
# The system prompt is the persistent instruction layer.
# It sets the role, the rules, and the output contract.
# It never changes between alerts — only the user prompt changes.
#
# Why does this improve output quality?
# The model associates the "senior SOC analyst" persona with
# a specific reasoning style it has seen in training data:
# structured, evidence-based, action-oriented security analysis.
# ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a senior SOC (Security Operations Centre) analyst with 10 years 
of experience in cloud security and incident response. You specialise in AWS environments 
and MITRE ATT&CK-based threat analysis.

Your job is to triage security alerts and produce structured analyst decisions.

RULES:
1. Base your assessment ONLY on the evidence provided — do not assume information not given
2. Production environment alerts are higher priority than development
3. High event counts suggest automated/persistent attacks, single events may be targeted or FP
4. Disabled logging (T1562.008) combined with other alerts = likely active incident
5. Always provide specific, actionable response steps — not generic advice

OUTPUT FORMAT:
You must respond with ONLY a valid JSON object matching this exact schema.
No markdown fences, no explanation, no preamble — just the raw JSON object.

Schema:
{
  "is_true_positive": boolean,
  "confidence": integer 0-100,
  "priority": "IMMEDIATE" | "HIGH" | "MEDIUM" | "LOW",
  "analyst_summary": string (2-3 sentences),
  "attack_narrative": string (1-2 sentences),  
  "immediate_actions": [string, string, ...],
  "escalate_to_tier2": boolean,
  "false_positive_reason": string or null
}"""


def _build_user_prompt(alert: NormalizedAlert) -> str:
    """
    CONCEPT: User prompt as a structured briefing
    
    We format the alert data as a structured text briefing —
    not as raw JSON. This is intentional: natural language
    structure (labels, colons, line breaks) is easier for the
    LLM to parse than nested JSON brackets.

    Think of it as writing a briefing note to a human analyst.
    The LLM reasons better when input resembles its training data
    (security reports, incident tickets) than raw API payloads.

    CONCEPT: Chain-of-thought instruction
    "Analyze the indicators carefully, then produce your assessment"
    explicitly asks the model to reason before concluding.
    This is called zero-shot chain-of-thought prompting and
    measurably improves accuracy on multi-factor judgements.
    """
    mitre = getattr(alert, 'mitre', UNKNOWN_MAPPING)

    # Format the immediate actions context
    env_context = (
        "⚠️  PRODUCTION ENVIRONMENT — higher priority"
        if alert.environment == "production"
        else f"Environment: {alert.environment}"
    )

    prompt = f"""SECURITY ALERT — TRIAGE REQUIRED

=== ALERT DETAILS ===
Finding type:   {alert.finding_type}
Severity score: {alert.severity} / 10.0  ({alert.severity_label})
Title:          {alert.title}
Description:    {alert.description}

=== AFFECTED RESOURCE ===
Resource type:  {alert.resource_type}
Resource ID:    {alert.resource_id}
{env_context}
AWS region:     {alert.region}
AWS account:    {alert.account_id}

=== THREAT ACTOR ===
Source IP:      {alert.actor_ip or "Not available"}
Country:        {alert.actor_country or "Unknown"}
Event count:    {alert.event_count} occurrences
First seen:     {alert.timestamp}

=== MITRE ATT&CK MAPPING ===
Tactic:         {mitre.get('tactic')} ({mitre.get('tactic_id')})
Technique:      {mitre.get('technique')} ({mitre.get('technique_id')})
Mapping source: {"LLM-enriched" if mitre.get('llm_enriched') else "Verified static mapping"}

=== INSTRUCTION ===
Analyze the indicators carefully, then produce your triage assessment.
Consider: Is this a credible threat? What is the attacker trying to do?
What must the analyst do RIGHT NOW?

Return only the JSON object."""

    return prompt


def triage_alert(alert: NormalizedAlert, client: OpenAI) -> TriageDecision:
    """
    Core triage function: one alert in, one TriageDecision out.

    CONCEPT: Why we validate twice
    First we json.loads() the response — this catches invalid JSON.
    Then we TriageDecision(**data) — Pydantic validates types and
    required fields. Two different failure modes, two different catches.
    """
    user_prompt = _build_user_prompt(alert)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt}
            ],
            temperature=0,        # deterministic triage decisions
            max_tokens=600        # enough for full JSON + reasoning
        )

        raw = response.choices[0].message.content.strip()

        # Strip markdown fences defensively
        raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

        # Parse JSON
        data = json.loads(raw)

        # Validate against Pydantic schema
        decision = TriageDecision(**data)
        return decision

    except json.JSONDecodeError as e:
        print(f"[triage_agent] JSON parse error for {alert.finding_type}: {e}")
        print(f"[triage_agent] Raw response was: {raw[:200]}")
        raise

    except ValidationError as e:
        print(f"[triage_agent] Schema validation error for {alert.finding_type}:")
        for err in e.errors():
            print(f"  - {err['loc']}: {err['msg']}")
        raise

    except Exception as e:
        print(f"[triage_agent] Unexpected error: {e}")
        raise


def triage_all(alerts: list[NormalizedAlert], client: OpenAI) -> list[tuple]:
    """
    Triage a list of alerts. Returns list of (alert, decision) tuples.

    CONCEPT: Why tuples?
    We pair each alert with its decision so downstream modules
    (ticket generator, logger) have access to both the original
    alert data and the LLM's assessment without passing them
    separately through the pipeline.
    """
    results = []
    for i, alert in enumerate(alerts, 1):
        print(f"[triage_agent] Triaging {i}/{len(alerts)}: {alert.finding_type}")
        try:
            decision = triage_alert(alert, client)
            results.append((alert, decision))
        except Exception as e:
            print(f"[triage_agent] Failed to triage alert {alert.alert_id}: {e}")
            continue

    print(f"[triage_agent] Completed: {len(results)}/{len(alerts)} alerts triaged")
    return results


# ── Smoke test ────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    console = Console()

    # Initialise OpenAI client
    # CONCEPT: The client reads OPENAI_API_KEY from os.environ
    # automatically — we never pass the key explicitly in code
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        console.print("[red]ERROR: OPENAI_API_KEY not set in .env file[/red]")
        sys.exit(1)

    client = OpenAI()

    # Run the full pipeline: load → normalize → map → triage
    console.print("\n[bold]Step 1:[/bold] Loading and normalizing alerts...")
    alerts = load_and_normalize("ingest/mock_alerts.json")

    console.print("[bold]Step 2:[/bold] Mapping to MITRE ATT&CK...")
    alerts = map_all(alerts, client=None)   # static only for mapping

    console.print("[bold]Step 3:[/bold] Running LLM triage...\n")
    results = triage_all(alerts, client)

    # Display each triage decision as a rich panel
    priority_colors = {
        "IMMEDIATE": "red",
        "HIGH":      "orange3",
        "MEDIUM":    "yellow",
        "LOW":       "green"
    }

    for alert, decision in results:
        color = priority_colors.get(decision.priority, "white")
        tp_label = "TRUE POSITIVE" if decision.is_true_positive else "FALSE POSITIVE"
        tp_color = "red" if decision.is_true_positive else "green"

        # Build panel content
        content = Text()
        content.append(f"[{tp_color}]{tp_label}[/{tp_color}]", style="bold")
        content.append(f"  |  Confidence: {decision.confidence}%")
        content.append(f"  |  Escalate: {'YES' if decision.escalate_to_tier2 else 'no'}\n\n")

        content.append("MITRE: ", style="dim")
        mitre = getattr(alert, 'mitre', {})
        content.append(f"{mitre.get('tactic')} → {mitre.get('technique')} ({mitre.get('technique_id')})\n\n")

        content.append("Summary\n", style="bold")
        content.append(f"{decision.analyst_summary}\n\n")

        content.append("Attack narrative\n", style="bold")
        content.append(f"{decision.attack_narrative}\n\n")

        content.append("Immediate actions\n", style="bold")
        for i, action in enumerate(decision.immediate_actions, 1):
            content.append(f"  {i}. {action}\n")

        if decision.false_positive_reason:
            content.append(f"\nFP reason: {decision.false_positive_reason}", style="dim")

        panel = Panel(
            content,
            title=f"[{color}][{decision.priority}][/{color}]  {alert.severity_label} | {alert.finding_type}",
            border_style=color,
            padding=(1, 2)
        )
        console.print(panel)
        console.print()