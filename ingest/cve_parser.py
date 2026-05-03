"""
cve_parser.py

Responsibility: Fetch and parse CVE entries from the NVD API 2.0.
Validates all extracted fields against a strict Pydantic schema (CVENotification).

Designed to integrate with the existing SIEM triage pipeline — CVENotification
objects are compatible with the TriageTicket format and can drive vendor
advisory processing workflows.

NVD API 2.0 docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits: 5 requests/30s (unauthenticated) · 50 requests/30s (with API key)
"""

import logging
import re
import time
from typing import Optional

import requests
from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Conservative default: 6s between requests stays within the unauthenticated
# 5 req/30s limit even accounting for clock skew.
# Pass rate_delay=0.6 when using an NVD API key.
_DEFAULT_RATE_DELAY = 6.0


class CVENotification(BaseModel):
    """
    Strict Pydantic schema for a parsed NVD CVE entry.

    Optional fields handle the real-world inconsistency of NVD data:
    - Reserved CVEs have no CVSS score yet
    - Disputed CVEs may lack configuration data
    - New CNAs may omit CWE classifications

    Compatible with TriageTicket format — to_ticket_summary() produces
    a string suitable for the analyst_summary field.
    """

    cve_id: str = Field(description="CVE identifier, e.g. CVE-2024-21762")
    description: str = Field(description="English vulnerability description from NVD")

    # CVSS v3.1 — all Optional because not all CVEs have scores assigned
    cvss_v31_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS v3.1 base score (0.0–10.0)",
    )
    cvss_v31_vector: Optional[str] = Field(
        default=None,
        description="CVSS v3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/...",
    )
    cvss_v31_severity: Optional[str] = Field(
        default=None,
        description="CVSS v3.1 qualitative severity: NONE/LOW/MEDIUM/HIGH/CRITICAL",
    )

    # Affected scope
    affected_cpes: list[str] = Field(
        default_factory=list,
        description="CPE 2.3 URIs for all vulnerable product/version ranges",
    )

    # References and classification
    reference_urls: list[str] = Field(
        default_factory=list,
        description="Reference URLs (vendor advisories, patches, PoCs, etc.)",
    )
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="CWE IDs for root cause classification, e.g. ['CWE-787']",
    )

    # Metadata
    published: str = Field(description="ISO8601 publication timestamp from NVD")
    last_modified: str = Field(description="ISO8601 last-modification timestamp")
    vuln_status: str = Field(description="NVD status, e.g. 'Analyzed', 'Awaiting Analysis'")
    source_identifier: str = Field(description="CNA or NVD source identifier")

    # ── Validators ────────────────────────────────────────────

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id_format(cls, v: str) -> str:
        if not re.match(r"^CVE-\d{4}-\d{4,}$", v):
            raise ValueError(
                f"Invalid CVE ID format: {v!r}. Expected CVE-YYYY-NNNNN+"
            )
        return v

    @field_validator("cvss_v31_severity")
    @classmethod
    def validate_severity_label(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(
                f"Invalid CVSS severity {v!r}. Must be one of {sorted(allowed)}"
            )
        return upper

    @field_validator("cvss_v31_vector")
    @classmethod
    def validate_vector_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith("CVSS:3"):
            raise ValueError(
                f"CVSS vector {v!r} does not start with 'CVSS:3'"
            )
        return v

    # ── Helpers ───────────────────────────────────────────────

    def to_ticket_summary(self) -> str:
        """
        Produce a one-paragraph analyst summary compatible with
        TriageTicket.analyst_summary.

        Used when injecting CVE data into the existing triage pipeline,
        e.g. when a GuardDuty alert maps to a known CVE.
        """
        if self.cvss_v31_score is not None:
            score_str = (
                f"CVSS v3.1 base score {self.cvss_v31_score} ({self.cvss_v31_severity})"
            )
        else:
            score_str = "no CVSS score assigned yet"

        cwes = ", ".join(self.cwe_ids) if self.cwe_ids else "no CWE classification"
        truncated = (
            self.description[:200] + "..."
            if len(self.description) > 200
            else self.description
        )
        return (
            f"{self.cve_id} ({score_str}). "
            f"Root cause: {cwes}. "
            f"{truncated}"
        )


# ── Internal parser ───────────────────────────────────────────

def _parse_nvd_response(data: dict) -> CVENotification:
    """
    Parse a raw NVD API 2.0 response dict into a CVENotification.

    All field extractions are defensive — missing keys return safe
    defaults rather than raising, because NVD data quality varies by
    CVE age, source CNA, and publication stage.
    """
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError("NVD response contains no vulnerability entries")

    cve_obj = vulnerabilities[0].get("cve", {})

    # ── Identity ──────────────────────────────────────────────
    cve_id = cve_obj.get("id", "")

    # ── Description (prefer English) ─────────────────────────
    descriptions = cve_obj.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No English description available",
    )

    # ── CVSS v3.1 (Optional) ─────────────────────────────────
    cvss_v31_score: Optional[float] = None
    cvss_v31_vector: Optional[str] = None
    cvss_v31_severity: Optional[str] = None

    metrics = cve_obj.get("metrics", {})
    cvss_entries = metrics.get("cvssMetricV31", [])
    if cvss_entries:
        # Prefer NVD's own "Primary" entry; fall back to the first entry from
        # any CNA if NVD hasn't scored it yet
        primary = next(
            (e for e in cvss_entries if e.get("type") == "Primary"),
            cvss_entries[0],
        )
        cvss_data = primary.get("cvssData", {})
        cvss_v31_score = cvss_data.get("baseScore")
        cvss_v31_vector = cvss_data.get("vectorString")
        cvss_v31_severity = cvss_data.get("baseSeverity")

    # ── CWE IDs ───────────────────────────────────────────────
    cwe_ids: list[str] = []
    for weakness in cve_obj.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            # Exclude NVD placeholder values that aren't real CWEs
            if value.startswith("CWE-") and value not in ("CWE-noinfo", "CWE-Other"):
                if value not in cwe_ids:
                    cwe_ids.append(value)

    # ── Affected CPEs ─────────────────────────────────────────
    affected_cpes: list[str] = []
    for config in cve_obj.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    criteria = cpe_match.get("criteria", "")
                    if criteria and criteria not in affected_cpes:
                        affected_cpes.append(criteria)

    # ── Reference URLs ────────────────────────────────────────
    reference_urls: list[str] = [
        ref["url"]
        for ref in cve_obj.get("references", [])
        if ref.get("url")
    ]

    return CVENotification(
        cve_id=cve_id,
        description=description,
        cvss_v31_score=cvss_v31_score,
        cvss_v31_vector=cvss_v31_vector,
        cvss_v31_severity=cvss_v31_severity,
        affected_cpes=affected_cpes,
        reference_urls=reference_urls,
        cwe_ids=cwe_ids,
        published=cve_obj.get("published", ""),
        last_modified=cve_obj.get("lastModified", ""),
        vuln_status=cve_obj.get("vulnStatus", "Unknown"),
        source_identifier=cve_obj.get("sourceIdentifier", ""),
    )


# ── Public API ────────────────────────────────────────────────

def fetch_cve(
    cve_id: str,
    api_key: Optional[str] = None,
    timeout: int = 30,
) -> CVENotification:
    """
    Fetch a single CVE from the NVD API 2.0 and return a validated
    CVENotification.

    Args:
        cve_id:   CVE identifier, e.g. "CVE-2024-21762"
        api_key:  Optional NVD API key. Without one, rate limit is 5 req/30s.
                  Register at https://nvd.nist.gov/developers/request-an-api-key
        timeout:  HTTP request timeout in seconds.

    Returns:
        CVENotification — all fields Pydantic-validated.

    Raises:
        ValueError:            If cve_id format is invalid or CVE not found in NVD.
        requests.HTTPError:    On non-200 HTTP responses (except 404, re-raised as ValueError).
        pydantic.ValidationError: If parsed data fails schema validation.
    """
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise ValueError(
            f"Invalid CVE ID format: {cve_id!r}. Expected CVE-YYYY-NNNNN+"
        )

    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        if response.status_code == 404:
            raise ValueError(
                f"CVE {cve_id!r} not found in NVD database"
            ) from exc
        raise

    data = response.json()

    if data.get("totalResults", 0) == 0:
        raise ValueError(f"CVE {cve_id!r} not found in NVD database")

    return _parse_nvd_response(data)


def batch_fetch_cves(
    cve_ids: list[str],
    api_key: Optional[str] = None,
    timeout: int = 30,
    rate_delay: float = _DEFAULT_RATE_DELAY,
) -> list[CVENotification]:
    """
    Fetch multiple CVEs from NVD, respecting the API rate limit.

    Mirrors the resilience pattern of normalizer.normalize_all():
    a single failed CVE is logged and skipped — the batch never aborts.
    This is intentional for bulk advisory processing where partial results
    are more useful than a hard failure.

    Args:
        cve_ids:    List of CVE identifiers to fetch.
        api_key:    Optional NVD API key. Pass to increase rate limit.
        timeout:    Per-request timeout in seconds.
        rate_delay: Seconds to sleep between requests. Default 6.0s is safe
                    for unauthenticated use. Set to 0.6 with a valid api_key.

    Returns:
        List of successfully parsed CVENotification objects.
        Order matches input; failed entries are absent (not None placeholders).
    """
    results: list[CVENotification] = []

    for i, cve_id in enumerate(cve_ids):
        logger.info("[cve_parser] Fetching %d/%d: %s", i + 1, len(cve_ids), cve_id)

        try:
            notification = fetch_cve(cve_id, api_key=api_key, timeout=timeout)
            results.append(notification)
            logger.info(
                "[cve_parser] Parsed %s — CVSS: %s (%s)",
                cve_id,
                notification.cvss_v31_score,
                notification.cvss_v31_severity or "no score",
            )

        except ValueError as exc:
            logger.warning("[cve_parser] Skipping %s: %s", cve_id, exc)
            continue

        except ValidationError as exc:
            logger.warning(
                "[cve_parser] Schema validation failed for %s: %s", cve_id, exc
            )
            continue

        except requests.RequestException as exc:
            logger.warning("[cve_parser] HTTP error fetching %s: %s", cve_id, exc)
            continue

        # Rate limit compliance — skip the delay after the last request
        if i < len(cve_ids) - 1:
            time.sleep(rate_delay)

    logger.info(
        "[cve_parser] Completed: %d/%d CVEs fetched successfully",
        len(results),
        len(cve_ids),
    )
    return results


# ── Smoke test ────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Fetch the Fortinet SSL-VPN RCE used as the workflow example
    try:
        cve = fetch_cve("CVE-2024-21762")
        print(json.dumps(cve.model_dump(), indent=2))
        print("\n--- Ticket summary ---")
        print(cve.to_ticket_summary())
    except Exception as exc:
        print(f"Error: {exc}")
