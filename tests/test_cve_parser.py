"""
tests/test_cve_parser.py

Unit tests for ingest/cve_parser.py.
No real NVD API calls are made — all HTTP responses are mocked.

Test groups:
  TestFetchCVEFullData   — CVE with complete CVSS v3.1 data (CVE-2024-21762)
  TestFetchCVEMissingCVSS — CVE in "Awaiting Analysis" state (no score yet)
  TestInvalidCVEID       — Format errors and 404 / zero-results responses
  TestBatchFetchCVEs     — Resilience and rate-limiting in batch_fetch_cves()
  TestCVENotificationSchema — Direct Pydantic validator tests
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests as req
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))

from ingest.cve_parser import CVENotification, batch_fetch_cves, fetch_cve


# ── Fixture data ─────────────────────────────────────────────
# Mirrors the real NVD API 2.0 response structure for CVE-2024-21762
# (Fortinet FortiOS out-of-bounds write, CVSS 9.8 CRITICAL)

NVD_FULL_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-21762",
                "sourceIdentifier": "psirt@fortinet.com",
                "published": "2024-02-09T10:15:08.173",
                "lastModified": "2024-03-19T00:15:10.073",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "A out-of-bounds write vulnerability [CWE-787] in Fortinet FortiOS "
                            "version 7.4.0 through 7.4.2 allows a remote unauthenticated attacker "
                            "to execute arbitrary code or command via specially crafted HTTP requests."
                        ),
                    },
                    {
                        "lang": "fr",
                        "value": "Une vulnérabilité d'écriture hors limites [CWE-787] ...",
                    },
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-787"}],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "7.4.0",
                                        "versionEndExcluding": "7.4.3",
                                        "matchCriteriaId": "fixture-id-1",
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "7.4.0",
                                        "versionEndExcluding": "7.4.3",
                                        "matchCriteriaId": "fixture-id-2",
                                    },
                                    {
                                        # non-vulnerable entry — should NOT appear in affected_cpes
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:fortinet:fortios:7.5.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "fixture-id-3",
                                    },
                                ],
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://fortiguard.com/psirt/FG-IR-24-015",
                        "source": "psirt@fortinet.com",
                    }
                ],
            }
        }
    ],
}

# CVE in "Awaiting Analysis" state — no CVSS, no CPEs, no CWEs
NVD_NO_CVSS_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-99999",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2024-06-01T00:00:00.000",
                "lastModified": "2024-06-01T00:00:00.000",
                "vulnStatus": "Awaiting Analysis",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability in Example Software allows remote code execution.",
                    }
                ],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
            }
        }
    ],
}

NVD_NOT_FOUND_RESPONSE = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


# ── Helpers ───────────────────────────────────────────────────

def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    if status_code >= 400:
        mock.raise_for_status.side_effect = req.exceptions.HTTPError(
            response=mock
        )
    else:
        mock.raise_for_status.return_value = None
    return mock


# ── TestFetchCVEFullData ──────────────────────────────────────

class TestFetchCVEFullData:
    """CVE-2024-21762: Fortinet FortiOS — full CVSS 9.8 CRITICAL data."""

    def test_returns_cve_notification_instance(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert isinstance(result, CVENotification)

    def test_cve_id_matches(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert result.cve_id == "CVE-2024-21762"

    def test_cvss_score_is_9_8(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert result.cvss_v31_score == 9.8

    def test_severity_is_critical(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert result.cvss_v31_severity == "CRITICAL"

    def test_vector_string_is_parsed(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert result.cvss_v31_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_only_vulnerable_cpes_extracted(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        # Fixture has 2 vulnerable + 1 non-vulnerable; only 2 should appear
        assert len(result.affected_cpes) == 2
        assert "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" in result.affected_cpes
        assert "cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*" in result.affected_cpes
        # The non-vulnerable entry must NOT be present
        assert "cpe:2.3:o:fortinet:fortios:7.5.0:*:*:*:*:*:*:*" not in result.affected_cpes

    def test_cwe_787_extracted(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert "CWE-787" in result.cwe_ids

    def test_reference_url_extracted(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert len(result.reference_urls) == 1
        assert "fortiguard.com" in result.reference_urls[0]

    def test_description_is_english(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        # Should pick the "en" description, not the French one
        assert "FortiOS" in result.description
        assert "out-of-bounds write" in result.description
        assert "vulnérabilité" not in result.description

    def test_vuln_status_is_analyzed(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        assert result.vuln_status == "Analyzed"

    def test_to_ticket_summary_includes_score_and_severity(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            result = fetch_cve("CVE-2024-21762")
        summary = result.to_ticket_summary()
        assert "9.8" in summary
        assert "CRITICAL" in summary
        assert "CVE-2024-21762" in summary
        assert "CWE-787" in summary


# ── TestFetchCVEMissingCVSS ───────────────────────────────────

class TestFetchCVEMissingCVSS:
    """CVE in 'Awaiting Analysis' state: no CVSS, no CPEs, no CWEs."""

    def test_returns_notification_without_cvss(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_NO_CVSS_RESPONSE)):
            result = fetch_cve("CVE-2024-99999")
        assert isinstance(result, CVENotification)

    def test_all_cvss_fields_are_none(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_NO_CVSS_RESPONSE)):
            result = fetch_cve("CVE-2024-99999")
        assert result.cvss_v31_score is None
        assert result.cvss_v31_vector is None
        assert result.cvss_v31_severity is None

    def test_empty_collections_for_absent_fields(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_NO_CVSS_RESPONSE)):
            result = fetch_cve("CVE-2024-99999")
        assert result.affected_cpes == []
        assert result.reference_urls == []
        assert result.cwe_ids == []

    def test_to_ticket_summary_handles_missing_score_gracefully(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_NO_CVSS_RESPONSE)):
            result = fetch_cve("CVE-2024-99999")
        summary = result.to_ticket_summary()
        assert "no CVSS score" in summary
        assert "CVE-2024-99999" in summary
        # Must not raise even with None CVSS fields
        assert isinstance(summary, str)

    def test_description_still_extracted(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_NO_CVSS_RESPONSE)):
            result = fetch_cve("CVE-2024-99999")
        assert "remote code execution" in result.description


# ── TestInvalidCVEID ─────────────────────────────────────────

class TestInvalidCVEID:
    """Format validation and not-found handling."""

    def test_raises_for_completely_invalid_id(self):
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            fetch_cve("NOT-A-CVE")

    def test_raises_for_wrong_prefix(self):
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            fetch_cve("CWE-787")

    def test_raises_for_truncated_id(self):
        # Year present but sequence missing
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            fetch_cve("CVE-2024")

    def test_raises_for_short_sequence(self):
        # Sequence must be at least 4 digits
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            fetch_cve("CVE-2024-123")

    def test_raises_for_empty_string(self):
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            fetch_cve("")

    def test_raises_when_nvd_returns_zero_results(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_NOT_FOUND_RESPONSE)):
            with pytest.raises(ValueError, match="not found in NVD database"):
                fetch_cve("CVE-2099-00001")

    def test_raises_as_value_error_on_404_http(self):
        """NVD returns HTTP 404 for completely unknown CVE IDs."""
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response({}, status_code=404)):
            with pytest.raises(ValueError, match="not found in NVD database"):
                fetch_cve("CVE-2099-00001")

    def test_propagates_non_404_http_errors(self):
        """Server errors (500, 503) should propagate as HTTPError, not be swallowed."""
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response({}, status_code=503)):
            with pytest.raises(req.exceptions.HTTPError):
                fetch_cve("CVE-2024-21762")

    def test_no_network_call_for_invalid_format(self):
        """Format validation must happen before hitting the network."""
        with patch("ingest.cve_parser.requests.get") as mock_get:
            with pytest.raises(ValueError):
                fetch_cve("INVALID")
            mock_get.assert_not_called()


# ── TestBatchFetchCVEs ────────────────────────────────────────

class TestBatchFetchCVEs:
    """Resilience, rate-limiting, and partial-success semantics."""

    def test_returns_list_of_notifications(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            with patch("ingest.cve_parser.time.sleep"):
                results = batch_fetch_cves(["CVE-2024-21762"], rate_delay=0)
        assert len(results) == 1
        assert isinstance(results[0], CVENotification)

    def test_skips_invalid_ids_without_aborting(self):
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            with patch("ingest.cve_parser.time.sleep"):
                results = batch_fetch_cves(
                    ["INVALID-ID", "CVE-2024-21762"],
                    rate_delay=0,
                )
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-21762"

    def test_skips_not_found_cve_without_aborting(self):
        not_found = _mock_response(NVD_NOT_FOUND_RESPONSE)
        found = _mock_response(NVD_FULL_RESPONSE)

        with patch("ingest.cve_parser.requests.get", side_effect=[not_found, found]):
            with patch("ingest.cve_parser.time.sleep"):
                results = batch_fetch_cves(
                    ["CVE-2099-00001", "CVE-2024-21762"],
                    rate_delay=0,
                )
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-21762"

    def test_skips_http_error_without_aborting(self):
        error_resp = _mock_response({}, status_code=503)
        found = _mock_response(NVD_FULL_RESPONSE)

        with patch("ingest.cve_parser.requests.get", side_effect=[error_resp, found]):
            with patch("ingest.cve_parser.time.sleep"):
                results = batch_fetch_cves(
                    ["CVE-2024-11111", "CVE-2024-21762"],
                    rate_delay=0,
                )
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-21762"

    def test_empty_list_returns_empty(self):
        results = batch_fetch_cves([], rate_delay=0)
        assert results == []

    def test_no_sleep_after_last_request(self):
        """rate_delay sleep must not be called after the final CVE."""
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            with patch("ingest.cve_parser.time.sleep") as mock_sleep:
                batch_fetch_cves(["CVE-2024-21762"], rate_delay=6.0)
        mock_sleep.assert_not_called()

    def test_sleep_called_between_multiple_requests(self):
        """rate_delay sleep must be called N-1 times for N CVEs."""
        with patch("ingest.cve_parser.requests.get",
                   return_value=_mock_response(NVD_FULL_RESPONSE)):
            with patch("ingest.cve_parser.time.sleep") as mock_sleep:
                batch_fetch_cves(
                    ["CVE-2024-21762", "CVE-2024-21762"],
                    rate_delay=6.0,
                )
        assert mock_sleep.call_count == 1
        mock_sleep.assert_called_with(6.0)


# ── TestCVENotificationSchema ─────────────────────────────────

class TestCVENotificationSchema:
    """Direct Pydantic validator tests — no HTTP involved."""

    def test_valid_full_construction(self):
        cve = CVENotification(
            cve_id="CVE-2024-21762",
            description="Test",
            cvss_v31_score=9.8,
            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_v31_severity="CRITICAL",
            affected_cpes=["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"],
            reference_urls=["https://fortiguard.com/psirt/FG-IR-24-015"],
            cwe_ids=["CWE-787"],
            published="2024-02-09T10:15:08.173",
            last_modified="2024-03-19T00:15:10.073",
            vuln_status="Analyzed",
            source_identifier="psirt@fortinet.com",
        )
        assert cve.cve_id == "CVE-2024-21762"

    def test_invalid_cve_id_raises_validation_error(self):
        with pytest.raises(ValidationError, match="Invalid CVE ID format"):
            CVENotification(
                cve_id="NOTACVE",
                description="test",
                published="2024-01-01",
                last_modified="2024-01-01",
                vuln_status="Analyzed",
                source_identifier="test",
            )

    def test_cvss_score_above_10_raises(self):
        with pytest.raises(ValidationError):
            CVENotification(
                cve_id="CVE-2024-21762",
                description="test",
                cvss_v31_score=10.1,
                published="2024-01-01",
                last_modified="2024-01-01",
                vuln_status="Analyzed",
                source_identifier="test",
            )

    def test_cvss_score_below_0_raises(self):
        with pytest.raises(ValidationError):
            CVENotification(
                cve_id="CVE-2024-21762",
                description="test",
                cvss_v31_score=-0.1,
                published="2024-01-01",
                last_modified="2024-01-01",
                vuln_status="Analyzed",
                source_identifier="test",
            )

    def test_invalid_severity_label_raises(self):
        with pytest.raises(ValidationError):
            CVENotification(
                cve_id="CVE-2024-21762",
                description="test",
                cvss_v31_severity="EXTREME",
                published="2024-01-01",
                last_modified="2024-01-01",
                vuln_status="Analyzed",
                source_identifier="test",
            )

    def test_severity_normalised_to_uppercase(self):
        cve = CVENotification(
            cve_id="CVE-2024-21762",
            description="test",
            cvss_v31_severity="critical",
            published="2024-01-01",
            last_modified="2024-01-01",
            vuln_status="Analyzed",
            source_identifier="test",
        )
        assert cve.cvss_v31_severity == "CRITICAL"

    def test_invalid_vector_prefix_raises(self):
        with pytest.raises(ValidationError, match="does not start with 'CVSS:3'"):
            CVENotification(
                cve_id="CVE-2024-21762",
                description="test",
                cvss_v31_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published="2024-01-01",
                last_modified="2024-01-01",
                vuln_status="Analyzed",
                source_identifier="test",
            )

    def test_optional_cvss_fields_default_to_none(self):
        cve = CVENotification(
            cve_id="CVE-2024-21762",
            description="test",
            published="2024-01-01",
            last_modified="2024-01-01",
            vuln_status="Analyzed",
            source_identifier="test",
        )
        assert cve.cvss_v31_score is None
        assert cve.cvss_v31_vector is None
        assert cve.cvss_v31_severity is None

    def test_list_fields_default_to_empty_lists(self):
        cve = CVENotification(
            cve_id="CVE-2024-21762",
            description="test",
            published="2024-01-01",
            last_modified="2024-01-01",
            vuln_status="Analyzed",
            source_identifier="test",
        )
        assert cve.affected_cpes == []
        assert cve.reference_urls == []
        assert cve.cwe_ids == []

    def test_five_digit_cve_sequence_is_valid(self):
        """CVE IDs with 5+ digit sequences are valid (e.g. 2021-44228)."""
        cve = CVENotification(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            published="2021-12-10",
            last_modified="2021-12-10",
            vuln_status="Analyzed",
            source_identifier="cve@mitre.org",
        )
        assert cve.cve_id == "CVE-2021-44228"
