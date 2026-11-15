# Backend queries for `aws_iam_enumeration.yml`

These are the deployable forms of the Sigma rules in `../aws_iam_enumeration.yml`.
Everything marked *generated* was produced by `sigma-cli` / pySigma and can be
regenerated; everything marked *hand-written* had to be written manually because
no backend supports the construct, and is documented as such rather than
presented as tool output.

Regenerate with:

```bash
pip install pysigma pysigma-backend-elasticsearch
sigma convert -t esql detections/aws_iam_enumeration.yml
```

Check what your installed version actually supports before assuming a target
exists — `sigma list targets` and `sigma list pipelines`. Backend capabilities
change between releases, and correlation support in particular is uneven.

---

## Elastic — ES|QL (*generated*, correlation included)

The ES|QL backend supports Sigma correlations, so the aggregation survives
conversion intact. This is the deployable form of the full use case.

```esql
from * metadata _id, _index, _version
| where (eventSource=="iam.amazonaws.com" and (eventName in ("GetAccountAuthorizationDetails", "GetAccountSummary", "ListAccessKeys", "ListAttachedGroupPolicies", "ListAttachedRolePolicies", "ListAttachedUserPolicies", "ListGroupPolicies", "ListGroups", "ListGroupsForUser", "ListInstanceProfiles", "ListMFADevices", "ListPolicies", "ListRolePolicies", "ListRoles", "ListSSHPublicKeys", "ListUserPolicies", "ListUsers", "ListVirtualMFADevices")) or eventSource=="sts.amazonaws.com" and eventName=="GetCallerIdentity") and not (userIdentity.type=="AWSService" or userIdentity.sessionContext.sessionIssuer.userName in ("REPLACE-ME-cspm-scanner-role", "REPLACE-ME-terraform-plan-role"))
| eval timebucket=date_trunc(10minutes, @timestamp)
| stats value_count=count_distinct(eventName) by timebucket, userIdentity.arn
| where value_count >= 15
```

Note the `date_trunc` bucketing: this is a **tumbling** window, not a sliding
one. An enumeration burst that straddles a bucket boundary can be split into two
sub-threshold groups and missed. That is a property of the generated query, not
of the Sigma rule, and it is the main reason the ES|QL form is not simply
equivalent to the KQL form below.

## Elastic — Lucene (*generated*, base rule only)

The Lucene backend has no aggregation support and raises
`NotImplementedError` on the correlation rule. Only the base selection converts,
which on its own is a hunting query, not an alert:

```
((eventSource:iam.amazonaws.com AND (eventName:(GetAccountAuthorizationDetails OR GetAccountSummary OR ListAccessKeys OR ListAttachedGroupPolicies OR ListAttachedRolePolicies OR ListAttachedUserPolicies OR ListGroupPolicies OR ListGroups OR ListGroupsForUser OR ListInstanceProfiles OR ListMFADevices OR ListPolicies OR ListRolePolicies OR ListRoles OR ListSSHPublicKeys OR ListUserPolicies OR ListUsers OR ListVirtualMFADevices))) OR (eventSource:sts.amazonaws.com AND eventName:GetCallerIdentity)) AND (NOT (userIdentity.type:AWSService OR (userIdentity.sessionContext.sessionIssuer.userName:(REPLACE\-ME\-cspm\-scanner\-role OR REPLACE\-ME\-terraform\-plan\-role))))
```

## Microsoft Sentinel — KQL (*hand-written*)

The Kusto backend silently produced no output for this ruleset: its processing
pipelines map Microsoft product tables (Defender XDR, ASIM), and there is no
pipeline for `product: aws / service: cloudtrail`. Rules whose logsource does not
map are dropped without error, which is worth knowing — an empty conversion is
easy to mistake for a successful one.

The query below is therefore written by hand against the `AWSCloudTrail` table
that Sentinel's AWS connector populates. Column names differ from the raw
CloudTrail JSON field names used in the Sigma rule (`EventName` vs `eventName`,
`UserIdentityArn` vs `userIdentity.arn`) — that mapping is the field-normalisation
problem this repo's parser stage solves for its own pipeline.

```kql
let threshold = 15;
let window = 10m;
let discoveryOps = dynamic([
    "GetAccountAuthorizationDetails", "GetAccountSummary", "ListAccessKeys",
    "ListAttachedGroupPolicies", "ListAttachedRolePolicies", "ListAttachedUserPolicies",
    "ListGroupPolicies", "ListGroups", "ListGroupsForUser", "ListInstanceProfiles",
    "ListMFADevices", "ListPolicies", "ListRolePolicies", "ListRoles",
    "ListSSHPublicKeys", "ListUserPolicies", "ListUsers", "ListVirtualMFADevices"
]);
let knownAutomation = dynamic([
    "REPLACE-ME-cspm-scanner-role", "REPLACE-ME-terraform-plan-role"
]);
AWSCloudTrail
| where (EventSource == "iam.amazonaws.com" and EventName in (discoveryOps))
     or (EventSource == "sts.amazonaws.com" and EventName == "GetCallerIdentity")
| where UserIdentityType != "AWSService"
| where UserIdentityPrincipalid !has_any (knownAutomation)
// hop=1m gives a sliding window and avoids the bucket-boundary blind spot
// that the tumbling ES|QL version has.
| summarize
    DistinctOps = dcount(EventName),
    Operations  = make_set(EventName, 25),
    FirstSeen   = min(TimeGenerated),
    LastSeen    = max(TimeGenerated),
    SourceIPs   = make_set(SourceIpAddress, 10)
    by UserIdentityArn, bin_at(TimeGenerated, window, ago(1d))
| where DistinctOps >= threshold
| extend
    AccountEntity = UserIdentityArn,
    TechniqueId   = "T1087.004"
| order by DistinctOps desc
```

The `make_set` aggregations are not part of the detection logic — they exist so
the analyst receiving the alert gets the operations and source IPs without a
second query. Alert enrichment at query time is cheaper than enrichment at
triage time.

---

## Known differences between the three forms

| | Correlation | Window type | Enrichment |
|---|---|---|---|
| ES\|QL | yes (generated) | tumbling | none |
| Lucene | no (unsupported) | n/a | none |
| KQL | yes (hand-written) | sliding-ish via `bin_at` | ops + source IPs |

These are not equivalent detections. Publishing them as if they were would be
the mistake; they are three deployments of one use case with different fidelity,
and the ES|QL form is the weakest of the two that work.
