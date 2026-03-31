"""
logger.py

Responsibility: Persist triage tickets to SQLite.

CONCEPT: Why SQLite for a security project?
- Zero setup — single .db file, stdlib only
- Full SQL query power — filter by severity, date, priority
- Auditable — every triage decision is permanently recorded
- Portable — copy the .db file to share the entire history

In production: swap SQLite for PostgreSQL or Elasticsearch.
The SQL queries here work identically on both.
"""

import json
import sqlite3
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from output.ticket_generator import TriageTicket


# CONCEPT: Path management with pathlib
# __file__ is the path of this script.
# .parent.parent goes up two levels to the project root.
# This means the .db file always lives at project root
# regardless of where you run the script from.
DB_PATH = Path(__file__).parent.parent / "triage_history.db"


def get_connection() -> sqlite3.Connection:
    """
    CONCEPT: Row factory
    By default sqlite3 returns rows as plain tuples.
    Setting row_factory = sqlite3.Row makes rows behave
    like dicts — you can access columns by name:
      row["priority"]  instead of  row[4]
    This makes queries much more readable.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Create the tickets table if it doesn't exist.

    CONCEPT: CREATE TABLE IF NOT EXISTS
    This is idempotent — safe to call every time the app starts.
    If the table already exists, nothing happens.
    If it's a fresh database, it gets created.

    CONCEPT: Column types in SQLite
    SQLite uses dynamic typing — TEXT, INTEGER, REAL, BLOB.
    We store complex fields (immediate_actions list) as
    JSON TEXT and deserialise on read.
    """
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            -- Identity
            ticket_id        TEXT PRIMARY KEY,
            created_at       TEXT NOT NULL,

            -- Alert
            alert_id         TEXT,
            finding_type     TEXT,
            severity_label   TEXT,
            severity_score   REAL,
            resource_type    TEXT,
            resource_id      TEXT,
            environment      TEXT,
            actor_ip         TEXT,
            actor_country    TEXT,
            event_count      INTEGER,
            region           TEXT,

            -- MITRE
            mitre_tactic     TEXT,
            mitre_tactic_id  TEXT,
            mitre_technique  TEXT,
            mitre_tech_id    TEXT,

            -- Decision
            is_true_positive     INTEGER,  -- SQLite has no BOOL; 0=false, 1=true
            confidence           INTEGER,
            priority             TEXT,
            analyst_summary      TEXT,
            attack_narrative     TEXT,
            immediate_actions    TEXT,     -- JSON array stored as text
            escalate_to_tier2    INTEGER,
            false_positive_reason TEXT,

            -- Metadata
            llm_model        TEXT,
            pipeline_version TEXT
        )
    """)
    conn.commit()
    conn.close()
    print(f"[logger] Database ready: {DB_PATH}")


def save_ticket(ticket: TriageTicket) -> None:
    """
    Insert one ticket. Uses INSERT OR REPLACE so re-running
    the pipeline with the same data updates rather than errors.

    CONCEPT: Parameterised queries
    We use ? placeholders, never f-strings in SQL.
    F-strings in SQL = SQL injection vulnerability.
    Parameterised queries are safe — the library handles escaping.
    """
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO tickets VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )
    """, (
        ticket.ticket_id,
        ticket.created_at,
        ticket.alert_id,
        ticket.finding_type,
        ticket.severity_label,
        ticket.severity_score,
        ticket.resource_type,
        ticket.resource_id,
        ticket.environment,
        ticket.actor_ip,
        ticket.actor_country,
        ticket.event_count,
        ticket.region,
        ticket.mitre_tactic,
        ticket.mitre_tactic_id,
        ticket.mitre_technique,
        ticket.mitre_tech_id,
        int(ticket.is_true_positive),
        ticket.confidence,
        ticket.priority,
        ticket.analyst_summary,
        ticket.attack_narrative,
        json.dumps(ticket.immediate_actions),  # list → JSON string
        int(ticket.escalate_to_tier2),
        ticket.false_positive_reason,
        ticket.llm_model,
        ticket.pipeline_version,
    ))
    conn.commit()
    conn.close()


def save_all(tickets: list[TriageTicket]) -> None:
    """Save a list of tickets and report summary."""
    init_db()
    for ticket in tickets:
        save_ticket(ticket)
        print(f"[logger] Saved ticket {ticket.ticket_id} → {DB_PATH.name}")
    print(f"[logger] {len(tickets)} tickets persisted to database")


def query_recent(limit: int = 10) -> list[sqlite3.Row]:
    """Fetch the most recent tickets — useful for the dashboard."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM tickets
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def query_by_priority(priority: str) -> list[sqlite3.Row]:
    """Fetch all tickets of a given priority level."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT ticket_id, finding_type, severity_label,
               resource_id, actor_ip, confidence, created_at
        FROM tickets
        WHERE priority = ?
        ORDER BY created_at DESC
    """, (priority,)).fetchall()
    conn.close()
    return rows


def summary_stats() -> dict:
    """
    Aggregate stats across all tickets.
    This powers the dashboard header metrics.
    """
    conn = get_connection()
    stats = {}

    stats["total"] = conn.execute(
        "SELECT COUNT(*) FROM tickets"
    ).fetchone()[0]

    stats["true_positives"] = conn.execute(
        "SELECT COUNT(*) FROM tickets WHERE is_true_positive = 1"
    ).fetchone()[0]

    stats["by_priority"] = {
        row["priority"]: row["cnt"]
        for row in conn.execute(
            "SELECT priority, COUNT(*) as cnt FROM tickets GROUP BY priority"
        ).fetchall()
    }

    stats["escalated"] = conn.execute(
        "SELECT COUNT(*) FROM tickets WHERE escalate_to_tier2 = 1"
    ).fetchone()[0]

    conn.close()
    return stats


# ── Smoke test ────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table
    import os
    from openai import OpenAI
    from dotenv import load_dotenv

    load_dotenv()
    console = Console()
    client  = OpenAI()

    from ingest.normalizer import load_and_normalize
    from agent.mitre_mapper import map_all
    from agent.triage_agent import triage_all
    from output.ticket_generator import generate_all, format_ticket_text

    # Full pipeline run
    console.print("\n[bold]Running full pipeline...[/bold]\n")
    alerts  = load_and_normalize("ingest/mock_alerts.json")
    alerts  = map_all(alerts, client=None)
    results = triage_all(alerts, client)
    tickets = generate_all(results)

    # Save to database
    save_all(tickets)

    # Print formatted tickets
    console.print("\n[bold]── Triage Tickets ──[/bold]\n")
    for ticket in tickets:
        console.print(format_ticket_text(ticket))

    # Print summary stats
    stats = summary_stats()
    console.print("\n[bold]── Database Summary ──[/bold]")
    console.print(f"  Total tickets:   {stats['total']}")
    console.print(f"  True positives:  {stats['true_positives']}")
    console.print(f"  Escalated:       {stats['escalated']}")
    console.print(f"  By priority:     {stats['by_priority']}")