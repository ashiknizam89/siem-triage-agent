# 🛡️ LLM-Assisted SIEM Triage Agent

> LLM-assisted triage of AWS GuardDuty findings with MITRE ATT&CK mapping and schema-validated output.

[![CI](https://github.com/ashiknizam89/siem-triage-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/ashiknizam89/siem-triage-agent/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-green)
![AWS](https://img.shields.io/badge/AWS-GuardDuty-orange)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

---

## The problem

A Tier-1 SOC analyst triages each alert by hand:

- Reading and understanding the finding
- Mapping it to a threat framework (MITRE ATT&CK)
- Assessing true positive vs false positive
- Determining response priority
- Writing up recommended actions

At volume, critical threats get buried in noise.

## What this does

A pipeline that ingests AWS GuardDuty findings and produces one structured triage ticket per finding, with a MITRE ATT&CK mapping, a confidence score, a priority and a list of response actions. The LLM output is validated against a Pydantic schema before it is stored.

---

## Architecture

```
AWS GuardDuty → Normalizer → MITRE Mapper → LLM Triage Agent → Ticket → SQLite → Dashboard
                    ↓               ↓                ↓
               Deduplicate    Static lookup     GPT-4o-mini
               + enrich       + LLM fallback    JSON → Pydantic
```

### Pipeline stages

| Stage     | Module                 | What it does                                           |
| --------- | ---------------------- | ------------------------------------------------------ |
| Ingest    | `guardduty_fetcher.py` | Pulls findings from AWS via Boto3 with pagination      |
| Normalize | `normalizer.py`        | Extracts key fields, deduplicates by fingerprint hash  |
| Map       | `mitre_mapper.py`      | Maps finding types to ATT&CK tactics/techniques        |
| Triage    | `triage_agent.py`      | LLM classifies severity, generates analyst summary     |
| Output    | `ticket_generator.py`  | Produces structured SOC tickets                        |
| Persist   | `logger.py`            | Saves to SQLite with queryable history                 |
| Visualise | `dashboard.py`         | Streamlit SOC dashboard                                |

---

## Detection Engineering

### Scope: where this sits in a detection pipeline

This project is a **post-detection triage and enrichment layer**, not a detection
source. The alerts it consumes are produced by AWS GuardDuty; GuardDuty's own
detection logic is proprietary and is not something this repo reimplements or
claims credit for.

What the repo *does* own, end to end:

- the parsing and normalisation of GuardDuty findings into a stable internal schema,
- the deduplication and noise-reduction logic applied before an analyst sees anything,
- the mapping of findings to MITRE ATT&CK techniques, including an LLM path for findings with no static mapping,
- the triage decision — severity, priority, and a written analyst-facing rationale,
- the detection rules under [`detections/`](detections/), which are authored here and are the one part of this repo that performs detection rather than triage.

That distinction is deliberate. A triage layer and a detection engine are
different problems, and conflating them in a README is the fastest way to lose
credibility with someone who does this for a living.

### Pipeline stages mapped to detection-engineering concepts

| Pipeline stage | Detection-engineering concept | What it actually does | Honest limitation |
|---|---|---|---|
| GuardDuty ingestion (Boto3) | Log source onboarding | Pulls findings from the GuardDuty API | Single log source; no pagination yet. A real SOC normalises many; the schema below has only been exercised against one. |
| Normalisation | Parser development, field mapping | Flattens the nested GuardDuty finding into a flat internal schema with consistent field names and types | The internal schema is bespoke, not ECS or OCSF. Portability to a commercial SIEM is therefore unproven. |
| Hash-based deduplication | Alert deduplication / volume reduction | Collapses repeat findings with the same finding type, resource and account within one batch | This reduces **duplicate alert volume**. It is not false-positive reduction — a deduplicated alert that was a false positive is still a false positive, just counted once. |
| ATT&CK mapping (static lookup) | Detection coverage labelling | Maps known GuardDuty finding types to technique IDs from a maintained lookup table | Labelling and enrichment, not use-case development. |
| ATT&CK mapping (LLM fallback) | Coverage for unmapped findings | Asks a model to propose a technique for finding types absent from the lookup | Accuracy is unmeasured against ground truth. Treated as a suggestion for analyst review, not an authoritative label. |
| LLM triage | Alert triage, severity assignment, prioritisation | Produces a severity, a priority, and a natural-language rationale | See the [Evaluation](#evaluation) section — the sample is small. |
| Pydantic validation | Output schema enforcement | Rejects structurally invalid model output before it reaches storage | Validates structure, not correctness. A well-formed wrong answer passes. |
| `detections/` (Sigma) | **Detection use-case development** | Rule authoring, tuning, threshold selection, backend deployment | Two rules covering one use case. This is a demonstration of method, not coverage. |

### The detection use case in `detections/`

[`detections/aws_iam_enumeration.yml`](detections/aws_iam_enumeration.yml)
contains one use case expressed as two Sigma rules:

- a **base rule** matching individual IAM/STS discovery API calls, deliberately
  at `informational` level because on its own it is noise;
- a **correlation rule** (`value_count`) that fires when a single principal
  touches ≥ 15 *distinct* discovery operations within 10 minutes.

The design choice worth explaining: the signal is **breadth, not volume**. A
polling script calling `ListUsers` five hundred times is the single most likely
false positive for a naive count-based threshold, and `value_count` on
`eventName` eliminates it by construction. There is a test asserting exactly
that ([`tests/test_sigma_iam_enumeration.py`](tests/test_sigma_iam_enumeration.py)).

The rules are tested at three levels — Sigma validity and reference resolution,
backend conversion, and behaviour against synthetic CloudTrail events using a
minimal evaluator. The third level proves intent, not runtime equivalence; the
test module says so explicitly.

Deployable query forms for Elastic (ES|QL, generated) and Microsoft Sentinel
(KQL, hand-written) are in [`detections/queries/`](detections/queries/), along
with a comparison of where the three backends differ. They are not equivalent
detections and the file does not pretend they are.

#### Tuning status

The `>= 15` threshold has **not** been baselined against production telemetry.
It was chosen from the structure of the rule (19 operations listed; enumeration
tooling walks nearly all of them) and from small-scale lab observation. Deploying
this without measuring the distribution of distinct discovery calls per principal
in the target environment would be malpractice, and the rule file says so.

#### Known evasion

Pacing calls beyond the 10-minute window, or splitting enumeration across two
assumed roles, defeats the correlation. There is a test asserting the
two-principal case does *not* fire, so the gap is documented as a gap rather
than left to be discovered.

### What is deliberately not claimed

- No claim of detection coverage. One use case is not coverage.
- No claim that the threshold is correct for any environment other than the lab.
- No claim of deterministic LLM output. `temperature=0` reduces sampling
  variance; it does not make the API deterministic, and run-to-run variance here
  is currently unmeasured.
- No claim of false-positive *rate*. The evaluation set measures severity
  agreement against manual labels, which is a different quantity.

---


## Key technical decisions

**Two-layer ATT&CK mapping**: a static lookup table (38 GuardDuty finding types) is tried first and needs no API call. Finding types that are not in the table go to the LLM. On the 20-finding evaluation sample, 16 were mapped by the static lookup and 4 by the LLM.

**`temperature=0` for all classifications**: temperature=0 reduces variation but doesn't guarantee identical output, which is one reason every response is validated with Pydantic before storage.

**Hash-based deduplication**: GuardDuty re-emits the same finding repeatedly. The normalizer fingerprints on `finding_type + resource_id + account_id` (excluding timestamp) and drops duplicates before they reach the LLM, so a repeated finding costs no tokens and produces no duplicate ticket.

**Pydantic output validation**: LLM responses are parsed as JSON and validated against the `TriageDecision` schema (required fields, `priority` limited to `IMMEDIATE` / `HIGH` / `MEDIUM` / `LOW`, `confidence` 0–100). `triage_alert()` raises on a response that fails either step; `triage_all()` logs the error and skips that alert, so no ticket is created from it.

**Read-only AWS access**: live mode only reads. The IAM user needs `AmazonGuardDutyReadOnlyAccess` and `AWSCloudTrail_ReadOnlyAccess`, nothing else.

**Mock/live mode switching**: `fetcher.py` abstracts the data source. `mode="mock"` uses local JSON fixtures, which the tests and CI also use. `mode="live"` pulls from real AWS. The rest of the pipeline is identical in both modes.

---

## Evaluation

20 GuardDuty sample findings from eu-north-1, each labelled by me:

- **Triage labels:** 19 of 20 matched my label (Wilson 95% CI roughly 76–99%).
- **ATT&CK mapping:** 16 findings were mapped by the static lookup and 4 by the LLM.
- **No false-positive rate:** the sample contains no benign findings, so no false-positive rate can be claimed.

Small sample: this shows the pipeline works end to end, not production accuracy.

**Method:** the evaluation was done manually, by comparing the model's triage label with my own label for each of the 20 sample findings. The labels and the evaluation script are not included in this repo.

The 20 findings are committed as `ingest/live_findings.json` (account ID replaced with the AWS documentation placeholder `123456789012`). The 16/4 mapping split can be reproduced offline, because it depends only on the static table:

```bash
python -c "
import json
from ingest.normalizer import normalize_all
from agent.mitre_mapper import map_all
alerts = map_all(normalize_all(json.load(open('ingest/live_findings.json'))), client=None)
print(sum(a.mitre['tactic_id'] != 'TA0000' for a in alerts), 'of', len(alerts), 'mapped by static lookup')
"
```

---

## CVE parser (standalone module)

`ingest/cve_parser.py` fetches a CVE from the NVD API 2.0 and parses it into a Pydantic-validated `CVENotification`: CVSS v3.1 score, severity and vector, CWE IDs, the CPEs marked as vulnerable, reference URLs, the NVD status and the English description. It is not yet connected to the GuardDuty triage pipeline.

```python
from ingest.cve_parser import fetch_cve, batch_fetch_cves

cve = fetch_cve("CVE-2024-21762")   # Fortinet FortiOS out-of-bounds write

print(cve.cvss_v31_score)     # 9.8
print(cve.cvss_v31_severity)  # "CRITICAL"
print(cve.cwe_ids)            # ["CWE-787"]
print(cve.to_ticket_summary())  # one-paragraph text summary

# Batch fetch: sleeps between requests to respect NVD rate limits (6 s by default).
# Pass api_key= and rate_delay=0.6 when you have an NVD API key.
cves = batch_fetch_cves(["CVE-2024-21762", "CVE-2021-44228", "CVE-2023-44487"])
```

What it handles (all covered by tests with mocked HTTP):

- CVE ID format validation before any network call
- CVEs without CVSS data yet (for example "Awaiting Analysis"): score fields are `None`
- 404 and zero-result responses raise `ValueError`; other HTTP errors propagate
- `batch_fetch_cves()` skips invalid, missing or failing IDs and continues with the rest
- Schema checks: score between 0 and 10, valid severity label, `CVSS:3.1/` vector prefix

---

## Tech stack

| Layer             | Technology                         |
| ----------------- | ---------------------------------- |
| Language          | Python 3.11 (CI also tests 3.12)   |
| LLM               | OpenAI GPT-4o-mini                 |
| AWS SDK           | Boto3                              |
| Output validation | Pydantic                           |
| Database          | SQLite (stdlib)                    |
| Dashboard         | Streamlit + Plotly                 |
| Terminal UI       | Rich                               |
| Secret management | python-dotenv                      |
| Tests             | pytest, GitHub Actions             |

---

## Project structure

```
siem-triage-agent/
├── .github/workflows/ci.yml      # pytest on Python 3.11 and 3.12
├── ingest/
│   ├── mock_alerts.json          # GuardDuty-format test fixtures
│   ├── live_findings.json        # The 20 evaluation findings (account ID redacted)
│   ├── normalizer.py             # Parse, flatten, deduplicate, enrich
│   ├── guardduty_fetcher.py      # Live AWS GuardDuty integration
│   ├── cloudtrail_fetcher.py     # CloudTrail context fetcher
│   ├── fetcher.py                # Unified mock/live entry point
│   └── cve_parser.py             # NVD API 2.0 CVE fetch + Pydantic validation
├── agent/
│   ├── mitre_mapper.py           # ATT&CK mapping (static + LLM)
│   └── triage_agent.py           # Core LLM triage with Pydantic validation
├── output/
│   └── ticket_generator.py       # Structured SOC ticket generation
├── store/
│   ├── logger.py                 # SQLite persistence
│   └── dashboard.py              # Streamlit SOC dashboard
├── tests/
│   ├── test_cve_parser.py        # CVE parser (mocked HTTP)
│   └── test_pipeline.py          # Normalizer, mapper, triage schema, tickets (mocked OpenAI)
├── .env.example                  # Copy to .env (not committed)
├── requirements.txt
├── requirements-dev.txt          # requirements.txt + pytest
├── LICENSE
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.11+
- OpenAI API key (for pipeline runs; the tests don't need one)
- For live mode only: an AWS account with GuardDuty enabled and an IAM user with `AmazonGuardDutyReadOnlyAccess` + `AWSCloudTrail_ReadOnlyAccess`

### Installation

```bash
git clone https://github.com/ashiknizam89/siem-triage-agent.git
cd siem-triage-agent

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements-dev.txt

cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Live mode only
aws configure
```

### Run the tests

```bash
pytest -q
```

66 tests. They make no network calls and need no API key: HTTP and the OpenAI client are mocked.

### Run with mock data (no AWS needed, needs `OPENAI_API_KEY`)

```bash
python store/logger.py
streamlit run store/dashboard.py
```

### Run with live AWS data

```bash
python -c "
from dotenv import load_dotenv
from openai import OpenAI
load_dotenv()

from ingest.guardduty_fetcher import fetch_guardduty_findings
from ingest.normalizer import normalize_all
from agent.mitre_mapper import map_all
from agent.triage_agent import triage_all
from output.ticket_generator import generate_all
from store.logger import save_all
from store.logger import summary_stats

raw     = fetch_guardduty_findings(region='eu-north-1', severity_threshold=4.0, hours_back=24)
alerts  = normalize_all(raw)
client  = OpenAI()
alerts  = map_all(alerts, client=client)
results = triage_all(alerts, client)
tickets = generate_all(results)
save_all(tickets)
print(summary_stats())
"

streamlit run store/dashboard.py
```

---

## Limitations

- **Live mode needs an AWS account with GuardDuty enabled.** The AWS account used during development is currently deactivated, so the committed fixtures (`ingest/mock_alerts.json`, `ingest/live_findings.json`) are the runnable path.
- **The LLM steps need an OpenAI API key** (triage, and ATT&CK mapping for finding types not in the static table). The tests don't: they mock the OpenAI client and NVD HTTP calls.
- **Test coverage:** the tests cover the CVE parser, the normalizer and deduplication, the static and LLM-fallback ATT&CK mapping, `TriageDecision` schema validation, `triage_alert()` response handling, and ticket generation. They don't cover the AWS fetchers, the SQLite logger or the Streamlit dashboard, and they don't measure LLM answer quality.
- **Evaluation:** 20 sample findings, labelled manually, all malicious. See [Evaluation](#evaluation).
- The 19/20 evaluation ran before the normaliser fix in [`180f44e`](https://github.com/ashiknizam89/siem-triage-agent/commit/180f44e). At that time the model saw 'AWS account: unknown' and the ingestion time instead of the finding's createdAt.

---

## What I learned building this

- **Prompt engineering for structured output**: constraining LLM responses to valid JSON with specific fields using system prompts and Pydantic validation
- **Pipeline design**: separating concerns across discrete modules that each do one thing, making the system testable and extensible
- **AWS security tooling**: GuardDuty finding schema, CloudTrail event structure, Boto3 pagination patterns, and IAM least-privilege design
- **Handling unreliable LLM output**: defensive JSON parsing, fallback chains, hash-based deduplication, and why temperature=0 alone doesn't make output reproducible

---

## Roadmap

- [ ] Slack/email dispatcher for IMMEDIATE priority alerts
- [ ] Connect the CVE parser to the triage pipeline
- [ ] Multi-account AWS support
- [ ] Alert correlation across finding types
- [ ] LangGraph stateful agent with memory

---

## Author

**Mohammed Ashik Nizamudeen**
M.Sc. Cybersecurity · CEH · Munich, Germany
[LinkedIn](https://linkedin.com/in/mohammed-ashik-n) · [GitHub](https://github.com/ashiknizam89)
