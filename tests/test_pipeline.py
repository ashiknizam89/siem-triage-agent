"""
tests/test_pipeline.py

Unit tests for the GuardDuty triage pipeline stages.
No network calls and no OpenAI API key are needed. The OpenAI
client is replaced with a MagicMock wherever the code calls it.

Test groups:
  TestNormalizer       — Field extraction and hash-based deduplication
  TestMitreMapper      — Static lookup, LLM fallback, no-client fallback
  TestTriageDecision   — Pydantic schema rejects malformed LLM output
  TestTriageAlert      — triage_alert() with a mocked OpenAI client
  TestTicketGenerator  — generate_ticket() field assembly
"""

import copy
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.mitre_mapper import UNKNOWN_MAPPING, map_alert, static_lookup
from agent.triage_agent import TriageDecision, triage_alert
from ingest.normalizer import normalize, normalize_all
from output.ticket_generator import TriageTicket, generate_ticket


# ── Fixture data ─────────────────────────────────────────────
# First finding in ingest/mock_alerts.json:
# UnauthorizedAccess:EC2/SSHBruteForce against i-0abc123def456789
MOCK_ALERTS = Path(__file__).parent.parent / "ingest" / "mock_alerts.json"

VALID_DECISION = {
    "is_true_positive": True,
    "confidence": 85,
    "priority": "HIGH",
    "analyst_summary": "An external IP is brute forcing SSH on a production instance.",
    "attack_narrative": "The attacker is trying to gain initial access via valid accounts.",
    "immediate_actions": ["Block the source IP", "Review SSH auth logs"],
    "escalate_to_tier2": True,
    "false_positive_reason": None,
}


@pytest.fixture
def ssh_finding() -> dict:
    with open(MOCK_ALERTS) as f:
        return copy.deepcopy(json.load(f)[0])


def _mock_client(content: str) -> MagicMock:
    """Build a MagicMock that mimics client.chat.completions.create()."""
    client = MagicMock()
    response = MagicMock()
    response.choices[0].message.content = content
    client.chat.completions.create.return_value = response
    return client


# ── Normalizer ───────────────────────────────────────────────

class TestNormalizer:

    def test_extracts_core_fields(self, ssh_finding):
        alert = normalize(ssh_finding)
        assert alert.finding_type == "UnauthorizedAccess:EC2/SSHBruteForce"
        assert alert.resource_type == "Instance"
        assert alert.resource_id == "i-0abc123def456789"
        assert alert.actor_ip == "198.51.100.23"
        assert alert.severity == 8.0
        assert alert.environment == "production"

    def test_extracts_account_and_created_at(self, ssh_finding):
        alert = normalize(ssh_finding)
        assert alert.account_id == "123456789012"
        assert alert.timestamp == "2026-03-28T08:00:00Z"

    def test_same_finding_twice_gives_one_alert(self, ssh_finding):
        alerts = normalize_all([ssh_finding, copy.deepcopy(ssh_finding)])
        assert len(alerts) == 1

    def test_reemitted_finding_with_new_timestamp_is_deduplicated(self, ssh_finding):
        reemitted = copy.deepcopy(ssh_finding)
        reemitted["id"] = "different-finding-id"
        reemitted["createdAt"] = "2026-03-29T08:00:00Z"
        alerts = normalize_all([ssh_finding, reemitted])
        assert len(alerts) == 1

    def test_different_resource_is_not_deduplicated(self, ssh_finding):
        other = copy.deepcopy(ssh_finding)
        other["resource"]["instanceDetails"]["instanceId"] = "i-0fff000000000000"
        alerts = normalize_all([ssh_finding, other])
        assert len(alerts) == 2

    def test_pascal_case_keys_from_boto3_are_handled(self):
        boto3_style = {
            "Id": "pascal-1",
            "Type": "Recon:IAMUser/MaliciousIPCaller",
            "Severity": 5.0,
            "Region": "eu-north-1",
            "Resource": {"ResourceType": "AccessKey"},
            "Service": {"Count": 3},
        }
        alert = normalize(boto3_style)
        assert alert.finding_type == "Recon:IAMUser/MaliciousIPCaller"
        assert alert.severity == 5.0
        assert alert.event_count == 3


# ── MITRE mapper ─────────────────────────────────────────────

class TestMitreMapper:

    def test_static_lookup_known_type(self):
        mapping = static_lookup("Recon:IAMUser/MaliciousIPCaller")
        assert mapping["tactic"] == "Discovery"
        assert mapping["tactic_id"] == "TA0007"
        assert mapping["technique_id"] == "T1526"

    def test_static_lookup_unknown_type_returns_none(self):
        assert static_lookup("Made:Up/FindingType") is None

    def test_known_type_does_not_call_llm(self, ssh_finding):
        ssh_finding["type"] = "Recon:IAMUser/MaliciousIPCaller"
        client = _mock_client("{}")
        alert = map_alert(normalize(ssh_finding), client=client)
        client.chat.completions.create.assert_not_called()
        assert alert.mitre["llm_enriched"] is False
        assert alert.mitre["tactic_id"] == "TA0007"

    def test_unknown_type_calls_llm(self, ssh_finding):
        ssh_finding["type"] = "Made:Up/FindingType"
        client = _mock_client(json.dumps({
            "tactic": "Impact", "tactic_id": "TA0040",
            "technique": "Resource Hijacking", "technique_id": "T1496",
        }))
        alert = map_alert(normalize(ssh_finding), client=client)
        client.chat.completions.create.assert_called_once()
        assert alert.mitre["llm_enriched"] is True
        assert alert.mitre["technique_id"] == "T1496"

    def test_unknown_type_with_invalid_llm_json_falls_back(self, ssh_finding):
        ssh_finding["type"] = "Made:Up/FindingType"
        alert = map_alert(normalize(ssh_finding), client=_mock_client("not json"))
        assert alert.mitre["tactic_id"] == UNKNOWN_MAPPING["tactic_id"]
        assert alert.mitre["llm_enriched"] is False

    def test_unknown_type_without_client_falls_back(self, ssh_finding):
        ssh_finding["type"] = "Made:Up/FindingType"
        alert = map_alert(normalize(ssh_finding), client=None)
        assert alert.mitre["tactic_id"] == UNKNOWN_MAPPING["tactic_id"]


# ── TriageDecision schema ────────────────────────────────────

class TestTriageDecision:

    def test_valid_decision_accepted(self):
        decision = TriageDecision(**VALID_DECISION)
        assert decision.priority == "HIGH"

    def test_missing_field_rejected(self):
        data = {k: v for k, v in VALID_DECISION.items() if k != "priority"}
        with pytest.raises(ValidationError):
            TriageDecision(**data)

    def test_priority_outside_literal_rejected(self):
        with pytest.raises(ValidationError):
            TriageDecision(**{**VALID_DECISION, "priority": "URGENT"})

    @pytest.mark.parametrize("confidence", [-1, 101])
    def test_confidence_out_of_range_rejected(self, confidence):
        with pytest.raises(ValidationError):
            TriageDecision(**{**VALID_DECISION, "confidence": confidence})


# ── triage_alert with mocked client ──────────────────────────

class TestTriageAlert:

    def test_valid_response_returns_decision(self, ssh_finding):
        client = _mock_client(json.dumps(VALID_DECISION))
        decision = triage_alert(normalize(ssh_finding), client)
        assert isinstance(decision, TriageDecision)
        assert decision.priority == "HIGH"

    def test_markdown_fenced_response_is_parsed(self, ssh_finding):
        client = _mock_client("```json\n" + json.dumps(VALID_DECISION) + "\n```")
        decision = triage_alert(normalize(ssh_finding), client)
        assert decision.confidence == 85

    def test_uses_temperature_zero(self, ssh_finding):
        client = _mock_client(json.dumps(VALID_DECISION))
        triage_alert(normalize(ssh_finding), client)
        kwargs = client.chat.completions.create.call_args.kwargs
        assert kwargs["temperature"] == 0

    def test_invalid_json_raises(self, ssh_finding):
        with pytest.raises(json.JSONDecodeError):
            triage_alert(normalize(ssh_finding), _mock_client("not json"))

    def test_schema_violation_raises(self, ssh_finding):
        bad = {**VALID_DECISION, "priority": "URGENT"}
        with pytest.raises(ValidationError):
            triage_alert(normalize(ssh_finding), _mock_client(json.dumps(bad)))


# ── Ticket generator ─────────────────────────────────────────

class TestTicketGenerator:

    def test_ticket_combines_alert_mapping_and_decision(self, ssh_finding):
        alert = map_alert(normalize(ssh_finding), client=None)
        decision = TriageDecision(**VALID_DECISION)
        ticket = generate_ticket(alert, decision)

        assert isinstance(ticket, TriageTicket)
        assert len(ticket.ticket_id) == 8
        assert ticket.alert_id == alert.alert_id
        assert ticket.finding_type == "UnauthorizedAccess:EC2/SSHBruteForce"
        assert ticket.resource_id == "i-0abc123def456789"
        assert ticket.mitre_tactic_id == alert.mitre["tactic_id"]
        assert ticket.mitre_tech_id == alert.mitre["technique_id"]
        assert ticket.priority == "HIGH"
        assert ticket.immediate_actions == VALID_DECISION["immediate_actions"]
        assert ticket.llm_model == "gpt-4o-mini"

    def test_ticket_ids_are_unique(self, ssh_finding):
        alert = map_alert(normalize(ssh_finding), client=None)
        decision = TriageDecision(**VALID_DECISION)
        ids = {generate_ticket(alert, decision).ticket_id for _ in range(20)}
        assert len(ids) == 20
