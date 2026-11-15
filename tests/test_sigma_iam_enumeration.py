"""Tests for the AWS IAM enumeration detection use case.

Scope note (read this before citing these tests as evidence of anything):

Three different things are tested here, with very different strengths:

  1. Structural tests  - the rule is valid Sigma, references resolve, ATT&CK
                         tags are well-formed. Strong: pySigma is doing the work.
  2. Conversion tests  - the ruleset compiles to a real Elastic ES|QL query.
                         Strong: the backend is doing the work.
  3. Behavioural tests - synthetic CloudTrail events are matched against a
                         MINIMAL evaluator written below, not a real Sigma
                         engine. This proves the rule's *intent* is what I
                         think it is; it does NOT prove the rule behaves
                         identically in Elastic or Sentinel. The evaluator
                         supports only the constructs this rule uses
                         (field equality, field-in-list, negated filters).

The threshold assertions below encode the current tuning choice (>= 15 distinct
operations / 10 min). They are regression guards against accidentally changing
the threshold, not evidence that 15 is the correct value for any environment.
"""

from datetime import datetime, timedelta

import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

RULE_PATH = "detections/aws_iam_enumeration.yml"

ATTACK_TAG_PREFIX = "attack."


@pytest.fixture(scope="module")
def collection() -> SigmaCollection:
    return SigmaCollection.load_ruleset([RULE_PATH])


@pytest.fixture(scope="module")
def base_rule(collection) -> SigmaRule:
    rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    assert len(rules) == 1
    return rules[0]


@pytest.fixture(scope="module")
def correlation_rule(collection) -> SigmaCorrelationRule:
    rules = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    assert len(rules) == 1
    return rules[0]


# --------------------------------------------------------------------------
# 1. Structural
# --------------------------------------------------------------------------


def test_ruleset_contains_base_and_correlation(collection):
    assert len(collection.rules) == 2


def test_base_rule_is_informational(base_rule):
    """The base rule must never be promoted to an alerting severity.

    On its own it fires on ordinary read-only API calls and would bury an
    analyst. If someone raises this level, that is a tuning regression.
    """
    assert base_rule.level.name.lower() == "informational"


def test_correlation_references_resolve(correlation_rule, base_rule):
    """A correlation whose reference does not resolve is silently dead."""
    referenced = [r.reference for r in correlation_rule.rules]
    assert str(base_rule.name) in referenced


def test_attack_tags_are_wellformed(base_rule, correlation_rule):
    for rule in (base_rule, correlation_rule):
        attack_tags = [str(t) for t in rule.tags if str(t).startswith(ATTACK_TAG_PREFIX)]
        assert attack_tags, f"{rule.title} carries no ATT&CK tags"
        for tag in attack_tags:
            suffix = tag[len(ATTACK_TAG_PREFIX):]
            assert suffix.startswith("t") or suffix in {
                "discovery",
                "credential-access",
                "reconnaissance",
            }, f"unexpected ATT&CK tag: {tag}"


def test_falsepositives_are_documented(base_rule, correlation_rule):
    """An undocumented FP section means the rule was never tuned."""
    for rule in (base_rule, correlation_rule):
        assert rule.falsepositives, f"{rule.title} documents no false positives"


def test_placeholder_filters_are_obvious():
    """Deployment-specific filters must be impossible to miss.

    If the REPLACE-ME marker is ever removed without the values being replaced,
    the rule ships with filters that exclude nothing and look intentional.
    """
    with open(RULE_PATH) as fh:
        content = fh.read()
    assert "REPLACE-ME" in content


# --------------------------------------------------------------------------
# 2. Conversion
# --------------------------------------------------------------------------


def test_converts_to_esql(collection):
    esql = pytest.importorskip("sigma.backends.elasticsearch")
    queries = esql.ESQLBackend().convert(collection)
    assert len(queries) == 1
    query = queries[0]
    assert "count_distinct(eventName)" in query
    assert "value_count >= 15" in query


def test_lucene_backend_cannot_express_the_correlation(collection):
    """Documents a real limitation rather than hiding it.

    The Lucene backend has no aggregation support, so the correlation cannot be
    deployed as a Lucene query. This is why the repo ships hand-written KQL for
    Sentinel instead of claiming automatic conversion everywhere.
    """
    esql = pytest.importorskip("sigma.backends.elasticsearch")
    with pytest.raises(NotImplementedError):
        esql.LuceneBackend().convert(collection)


# --------------------------------------------------------------------------
# 3. Behavioural (minimal evaluator - see module docstring)
# --------------------------------------------------------------------------

DISCOVERY_OPS = [
    "GetAccountAuthorizationDetails",
    "GetAccountSummary",
    "ListAccessKeys",
    "ListAttachedGroupPolicies",
    "ListAttachedRolePolicies",
    "ListAttachedUserPolicies",
    "ListGroupPolicies",
    "ListGroups",
    "ListGroupsForUser",
    "ListInstanceProfiles",
    "ListMFADevices",
    "ListPolicies",
    "ListRolePolicies",
    "ListRoles",
    "ListSSHPublicKeys",
    "ListUserPolicies",
    "ListUsers",
    "ListVirtualMFADevices",
]

THRESHOLD = 15
WINDOW = timedelta(minutes=10)


def cloudtrail_event(event_name, source="iam.amazonaws.com", arn="arn:aws:iam::111122223333:user/dev", identity_type="IAMUser", ts=None):
    return {
        "eventSource": source,
        "eventName": event_name,
        "userIdentity": {"type": identity_type, "arn": arn},
        "eventTime": (ts or datetime(2026, 8, 3, 12, 0, 0)).isoformat(),
    }


def matches_base_rule(event):
    """Minimal evaluator for this rule only. Not a general Sigma engine."""
    src = event["eventSource"]
    name = event["eventName"]
    selected = (src == "iam.amazonaws.com" and name in DISCOVERY_OPS) or (
        src == "sts.amazonaws.com" and name == "GetCallerIdentity"
    )
    filtered = event["userIdentity"]["type"] == "AWSService"
    return selected and not filtered


def correlation_fires(events):
    """Reimplements value_count over a single window, grouped by principal."""
    by_principal = {}
    for e in events:
        if not matches_base_rule(e):
            continue
        by_principal.setdefault(e["userIdentity"]["arn"], set()).add(e["eventName"])
    return any(len(ops) >= THRESHOLD for ops in by_principal.values())


def test_base_rule_matches_discovery_call():
    assert matches_base_rule(cloudtrail_event("ListUsers"))


def test_base_rule_matches_sts_caller_identity():
    assert matches_base_rule(
        cloudtrail_event("GetCallerIdentity", source="sts.amazonaws.com")
    )


def test_base_rule_ignores_mutating_call():
    """CreateUser is not discovery. It belongs to a different use case."""
    assert not matches_base_rule(cloudtrail_event("CreateUser"))


def test_base_rule_ignores_aws_service_principal():
    assert not matches_base_rule(
        cloudtrail_event("ListRoles", identity_type="AWSService")
    )


def test_correlation_does_not_fire_below_threshold():
    events = [cloudtrail_event(op) for op in DISCOVERY_OPS[: THRESHOLD - 1]]
    assert not correlation_fires(events)


def test_correlation_fires_at_threshold():
    events = [cloudtrail_event(op) for op in DISCOVERY_OPS[:THRESHOLD]]
    assert correlation_fires(events)


def test_repeated_single_operation_does_not_fire():
    """The core tuning claim: volume alone is not the signal, breadth is.

    A polling script calling ListUsers 500 times is the single most likely
    false positive for a naive count-based rule. value_count on eventName is
    what makes this rule survive contact with a real account.
    """
    events = [cloudtrail_event("ListUsers") for _ in range(500)]
    assert not correlation_fires(events)


def test_breadth_split_across_two_principals_does_not_fire():
    """Documents the evasion noted in the rule file.

    Splitting enumeration across two assumed roles defeats the group-by. This
    test asserts the limitation exists so it is not mistaken for coverage.
    """
    half = THRESHOLD // 2 + 1
    events = [
        cloudtrail_event(op, arn="arn:aws:iam::111122223333:user/a")
        for op in DISCOVERY_OPS[:half]
    ] + [
        cloudtrail_event(op, arn="arn:aws:iam::111122223333:user/b")
        for op in DISCOVERY_OPS[half : half * 2]
    ]
    assert not correlation_fires(events)
