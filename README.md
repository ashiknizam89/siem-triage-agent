# 🛡️ LLM-Assisted SIEM Triage Agent

> Autonomous security alert triage powered by GPT-4o-mini and MITRE ATT&CK — reducing mean-time-to-respond from minutes to seconds.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-green)
![AWS](https://img.shields.io/badge/AWS-GuardDuty-orange)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## The problem

A Tier-1 SOC analyst manually triages hundreds of alerts per shift. Each alert requires:

- Reading and understanding the finding
- Mapping it to a threat framework (MITRE ATT&CK)
- Assessing true positive vs false positive
- Determining response priority
- Writing up recommended actions

This takes **5–15 minutes per alert**. At scale, critical threats get buried in noise.

## The solution

An agentic pipeline that ingests raw AWS GuardDuty findings and produces structured triage decisions in **under 2 seconds per alert** — with MITRE ATT&CK mapping, confidence scoring, and prioritised response actions.

---

## Architecture

```
AWS GuardDuty → Normalizer → MITRE Mapper → LLM Triage Agent → Ticket → SQLite → Dashboard
                    ↓               ↓                ↓
               Deduplicate    Static lookup     GPT-4o-mini
               + enrich       + LLM fallback    structured output
```

### Pipeline stages

| Stage     | Module                 | What it does                                           |
| --------- | ---------------------- | ------------------------------------------------------ |
| Ingest    | `guardduty_fetcher.py` | Pulls findings from AWS via Boto3 with pagination      |
| Normalize | `normalizer.py`        | Flattens nested JSON, deduplicates by fingerprint hash |
| Map       | `mitre_mapper.py`      | Maps finding types to ATT&CK tactics/techniques        |
| Triage    | `triage_agent.py`      | LLM classifies severity, generates analyst summary     |
| Output    | `ticket_generator.py`  | Produces structured SOC tickets                        |
| Persist   | `logger.py`            | Saves to SQLite with queryable history                 |
| Visualise | `dashboard.py`         | Streamlit SOC dashboard                                |

---

## Key technical decisions

**Two-layer ATT&CK mapping** — static lookup table handles ~80% of findings instantly (free, deterministic). LLM enrichment handles the remaining 20% of novel finding types. This minimises API cost while maintaining coverage.

**`temperature=0` for all classifications** — security triage decisions must be deterministic and auditable. The same alert always produces the same ATT&CK mapping and priority assessment.

**Hash-based deduplication** — GuardDuty re-emits the same finding repeatedly. We fingerprint on `finding_type + resource_id + account_id` (excluding timestamp) to suppress duplicates before they reach the LLM, saving tokens and preventing duplicate tickets.

**Pydantic output validation** — LLM responses are validated against a strict schema before entering the pipeline. Malformed outputs are caught and logged rather than propagating silently.

**Least-privilege IAM** — uses a dedicated `siem-triage-dev` IAM user with only `AmazonGuardDutyReadOnlyAccess` and `AWSCloudTrail_ReadOnlyAccess`. No write permissions, no admin access.

**Mock/live mode switching** — `fetcher.py` abstracts the data source. `mode="mock"` uses local JSON fixtures for development and CI. `mode="live"` pulls from real AWS. The rest of the pipeline is identical in both modes.

---

## Results on live AWS data

Running against 20 real GuardDuty sample findings (eu-north-1):

- **20/20 alerts** normalized and deduplicated
- **12 static** ATT&CK lookups + **8 LLM** enrichments
- **20 triage tickets** generated in ~45 seconds
- **19 true positives** identified (95% TP rate on sample data)
- Finding types covered: EC2, EKS, RDS, S3, IAM, Kubernetes, Runtime, ECS

---

## Vulnerability Intelligence Extension

`ingest/cve_parser.py` extends the pipeline to consume **structured vulnerability feeds from the NVD**, bridging the gap between raw SIEM alerts and the vendor advisory processing workflows at the core of enterprise vulnerability intelligence teams.

### How it connects to real workflows

Enterprise vulnerability teams (e.g. Siemens ProductCERT) receive hundreds of vendor advisories per week — Fortinet PSIRTs, Microsoft Patch Tuesdays, Cisco Security Advisories. The manual review cycle is:

1. Receive advisory → extract CVE IDs
2. Look up each CVE in NVD for CVSS score, affected CPE scope, CWE root cause
3. Validate that the affected products match the internal asset inventory
4. Generate a customer-facing notification or internal impact ticket

`cve_parser.py` automates steps 1–3. The validated `CVENotification` object maps directly to the fields in `TriageTicket`, so CVE data can be injected into the same LLM triage pipeline that handles GuardDuty alerts.

### Fetching and parsing CVE-2024-21762 (Fortinet SSL-VPN RCE)

```python
from ingest.cve_parser import fetch_cve, batch_fetch_cves

# Single CVE — Fortinet FortiOS out-of-bounds write, CVSS 9.8 CRITICAL
# Actively exploited in the wild before the patch was available
cve = fetch_cve("CVE-2024-21762")

print(cve.cve_id)            # "CVE-2024-21762"
print(cve.cvss_v31_score)    # 9.8
print(cve.cvss_v31_severity) # "CRITICAL"
print(cve.cvss_v31_vector)   # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
print(cve.cwe_ids)           # ["CWE-787"]
print(cve.affected_cpes)
# ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
#  "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*"]

# Compatible with the existing ticket pipeline
print(cve.to_ticket_summary())
# "CVE-2024-21762 (CVSS v3.1 base score 9.8 (CRITICAL)). Root cause: CWE-787.
#  A out-of-bounds write vulnerability in Fortinet FortiOS..."

# Batch fetch — respects NVD rate limits (6s between requests by default)
# Pass api_key= and rate_delay=0.6 when you have an NVD API key
patch_tuesday = batch_fetch_cves([
    "CVE-2024-21762",  # Fortinet FortiOS RCE
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
])
critical = [c for c in patch_tuesday if c.cvss_v31_score and c.cvss_v31_score >= 9.0]
```

### Connection to enterprise notification workflows

| CVENotification field | Vendor advisory use case |
|---|---|
| `cve_id` | Deduplicate incoming advisories from multiple CNAs |
| `cvss_v31_score` + `cvss_v31_severity` | Triage priority for internal patching SLA |
| `affected_cpes` | Match against CMDB / asset inventory to determine exposure |
| `cwe_ids` | Root cause classification for recurrence prevention |
| `reference_urls` | Link to vendor patch, PoC, and workaround documentation |
| `vuln_status` | Gate notifications — only "Analyzed" CVEs have complete NVD data |
| `to_ticket_summary()` | Pre-fill the LLM triage prompt or Jira ticket description |

---

## Tech stack

| Layer             | Technology         |
| ----------------- | ------------------ |
| Language          | Python 3.11        |
| LLM               | OpenAI GPT-4o-mini |
| AWS SDK           | Boto3              |
| Output validation | Pydantic           |
| Database          | SQLite (stdlib)    |
| Dashboard         | Streamlit + Plotly |
| Terminal UI       | Rich               |
| Secret management | python-dotenv      |

---

## Project structure

```
siem-triage-agent/
├── ingest/
│   ├── mock_alerts.json          # Realistic GuardDuty test fixtures
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
│   └── test_cve_parser.py        # Unit tests for CVE parser (mocked HTTP)
├── .env                          # API keys (not committed)
├── requirements.txt
└── README.md
```

---

## Setup

### Prerequisites

- Python 3.11+
- OpenAI API key
- AWS account with GuardDuty enabled
- AWS IAM user with `AmazonGuardDutyReadOnlyAccess` + `AWSCloudTrail_ReadOnlyAccess`

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/siem-triage-agent.git
cd siem-triage-agent

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Configure AWS credentials
aws configure
```

### Run with mock data (no AWS needed)

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

## What I learned building this

- **Prompt engineering for structured output** — constraining LLM responses to valid JSON with specific fields using system prompts and Pydantic validation
- **Agentic pipeline design** — separating concerns across discrete modules that each do one thing, making the system testable and extensible
- **AWS security tooling** — GuardDuty finding schema, CloudTrail event structure, Boto3 pagination patterns, and IAM least-privilege design
- **Production reliability patterns** — defensive JSON parsing, graceful fallback chains, hash-based deduplication, temperature=0 for determinism

---

## Roadmap

- [ ] Slack/email dispatcher for IMMEDIATE priority alerts
- [ ] Autonomous recon agent (Project 2)
- [ ] Multi-account AWS support
- [ ] Alert correlation across finding types
- [ ] LangGraph stateful agent with memory

---

## Author

**Mohammed Ashik Nizamudeen**
M.Sc. Cybersecurity · CEH · Munich, Germany
[LinkedIn](https://linkedin.com/in/mohammed-ashik-n) · [GitHub](https://github.com/yourusername)
