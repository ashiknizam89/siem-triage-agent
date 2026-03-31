"""
dashboard.py

Streamlit dashboard for the SIEM Triage Agent.
Reads from triage_history.db and renders a live SOC-style UI.

Run with:  streamlit run store/dashboard.py
"""

import json
import sqlite3
import sys
from pathlib import Path

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))
from store.logger import get_connection, summary_stats, query_recent

# ─────────────────────────────────────────────────────────────
# CONCEPT: Streamlit page config must be the FIRST st call.
# It sets the browser tab title, icon, and layout width.
# "wide" layout uses the full browser width — better for tables.
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SIEM Triage Agent",
    page_icon="🛡️",
    layout="wide"
)

# ── Custom CSS — minimal dark-SOC aesthetic ───────────────────
st.markdown("""
<style>
  .metric-card {
    background: #1e1e2e;
    border: 1px solid #313244;
    border-radius: 8px;
    padding: 1rem 1.5rem;
    text-align: center;
  }
  .metric-val  { font-size: 2rem; font-weight: 700; margin: 0; }
  .metric-lab  { font-size: 0.8rem; color: #888; margin: 0; }
  .crit  { color: #f38ba8; }
  .high  { color: #fab387; }
  .med   { color: #f9e2af; }
  .low   { color: #a6e3a1; }
  .imm   { color: #f38ba8; }
  .ticket-box {
    background: #1e1e2e;
    border-left: 3px solid #cba6f7;
    border-radius: 4px;
    padding: 1rem 1.5rem;
    margin: 0.5rem 0;
    font-family: monospace;
    font-size: 0.85rem;
    white-space: pre-wrap;
  }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# CONCEPT: st.cache_data
# Streamlit reruns the entire script on every interaction.
# Without caching, every widget click would re-query the DB.
# @st.cache_data caches the return value — the function only
# re-executes if its arguments change.
# ttl=30 means "expire cache after 30 seconds" — picks up
# new tickets written by the pipeline automatically.
# ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_all_tickets() -> list[dict]:
    """Load all tickets from SQLite as a list of dicts."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM tickets ORDER BY created_at DESC"
    ).fetchall()
    conn.close()

    tickets = []
    for row in rows:
        t = dict(row)
        # Deserialise the JSON-stored list back to Python list
        t["immediate_actions"] = json.loads(t["immediate_actions"] or "[]")
        tickets.append(t)
    return tickets


@st.cache_data(ttl=30)
def load_stats() -> dict:
    return summary_stats()


def severity_badge(label: str) -> str:
    css = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
    return f'<span class="{css.get(label, "")}">{label}</span>'


def priority_badge(p: str) -> str:
    css = {"IMMEDIATE": "imm", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
    return f'<span class="{css.get(p, "")}">{p}</span>'


# ── Header ────────────────────────────────────────────────────
st.title("🛡️ SIEM Triage Agent")
st.caption("LLM-assisted alert triage · MITRE ATT&CK mapped · Powered by GPT-4o-mini")

st.divider()

# ── Load data ─────────────────────────────────────────────────
tickets = load_all_tickets()
stats   = load_stats()

if not tickets:
    st.warning("No tickets in database yet. Run `python store/logger.py` first.")
    st.stop()

# ── Metric row ────────────────────────────────────────────────
# CONCEPT: st.columns splits the page into N equal columns.
# Each column is a context — widgets inside render side by side.
col1, col2, col3, col4, col5 = st.columns(5)

by_p = stats.get("by_priority", {})

with col1:
    st.metric("Total Alerts",    stats["total"])
with col2:
    st.metric("True Positives",  stats["true_positives"])
with col3:
    st.metric("Escalated",       stats["escalated"])
with col4:
    st.metric("IMMEDIATE",       by_p.get("IMMEDIATE", 0))
with col5:
    tp_rate = int(stats["true_positives"] / stats["total"] * 100) if stats["total"] else 0
    st.metric("TP Rate",         f"{tp_rate}%")

st.divider()

# ── Two-column layout: charts left, filters right ─────────────
left, right = st.columns([2, 1])

with right:
    st.subheader("Filters")

    # CONCEPT: st.multiselect returns a list of selected values.
    # We use it to filter the ticket table dynamically.
    priority_filter = st.multiselect(
        "Priority",
        options=["IMMEDIATE", "HIGH", "MEDIUM", "LOW"],
        default=["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]
    )
    severity_filter = st.multiselect(
        "Severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )
    tp_filter = st.radio(
        "Assessment",
        options=["All", "True Positive", "False Positive"],
        horizontal=True
    )

with left:
    st.subheader("Tactic distribution")

    # Count by MITRE tactic
    tactic_counts: dict[str, int] = {}
    for t in tickets:
        tactic = t.get("mitre_tactic", "Unknown")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    if tactic_counts:
        fig = px.bar(
            x=list(tactic_counts.values()),
            y=list(tactic_counts.keys()),
            orientation="h",
            color=list(tactic_counts.values()),
            color_continuous_scale="Reds",
            labels={"x": "Alert count", "y": "ATT&CK Tactic"}
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            coloraxis_showscale=False,
            margin=dict(l=0, r=0, t=0, b=0),
            height=220
        )
        fig.update_xaxes(showgrid=False)
        fig.update_yaxes(showgrid=False)
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# ── Alert table ───────────────────────────────────────────────
st.subheader("Alert queue")

# Apply filters
filtered = tickets
if priority_filter:
    filtered = [t for t in filtered if t["priority"] in priority_filter]
if severity_filter:
    filtered = [t for t in filtered if t["severity_label"] in severity_filter]
if tp_filter == "True Positive":
    filtered = [t for t in filtered if t["is_true_positive"]]
elif tp_filter == "False Positive":
    filtered = [t for t in filtered if not t["is_true_positive"]]

st.caption(f"Showing {len(filtered)} of {len(tickets)} tickets")

# CONCEPT: st.expander creates a collapsible section.
# We render one expander per ticket — click to expand full detail.
for ticket in filtered:
    tp_icon  = "🔴" if ticket["is_true_positive"] else "🟢"
    sev      = ticket["severity_label"]
    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
    esc_icon = "⬆️" if ticket["escalate_to_tier2"] else ""

    label = (
        f"{tp_icon} [{ticket['priority']}] {sev_icon} {sev}  |  "
        f"{ticket['finding_type']}  |  "
        f"{ticket['resource_id']}  |  "
        f"#{ticket['ticket_id']}  {esc_icon}"
    )

    with st.expander(label):
        c1, c2 = st.columns(2)

        with c1:
            st.markdown("**Finding**")
            st.code(ticket["finding_type"], language=None)

            st.markdown("**MITRE ATT&CK**")
            st.markdown(
                f"`{ticket['mitre_tactic_id']}` {ticket['mitre_tactic']}  →  "
                f"`{ticket['mitre_tech_id']}` {ticket['mitre_technique']}"
            )

            st.markdown("**Analyst summary**")
            st.info(ticket["analyst_summary"])

            st.markdown("**Attack narrative**")
            st.warning(ticket["attack_narrative"])

        with c2:
            st.markdown("**Resource**")
            st.markdown(f"""
- Type: `{ticket['resource_type']}`
- ID: `{ticket['resource_id']}`
- Environment: `{ticket['environment'].upper()}`
- Region: `{ticket['region']}`
""")
            st.markdown("**Threat actor**")
            st.markdown(f"""
- IP: `{ticket['actor_ip'] or 'Unknown'}`
- Country: `{ticket['actor_country'] or 'Unknown'}`
- Occurrences: `{ticket['event_count']}`
""")

            st.markdown("**Immediate actions**")
            for i, action in enumerate(ticket["immediate_actions"], 1):
                st.markdown(f"{i}. {action}")

            if ticket.get("false_positive_reason"):
                st.markdown("**False positive reason**")
                st.success(ticket["false_positive_reason"])

        st.caption(
            f"Ticket #{ticket['ticket_id']} · "
            f"Created {ticket['created_at'][:19].replace('T',' ')} UTC · "
            f"Confidence {ticket['confidence']}% · "
            f"Model: {ticket['llm_model']}"
        )

st.divider()
st.caption("SIEM Triage Agent v1.0.0 · Built with Python, OpenAI GPT-4o-mini, MITRE ATT&CK")