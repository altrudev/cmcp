"""Regression tests for Opaque managed-attestation success semantics (#594)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from cmcp_verify.opaque import verify_opaque_measurement

_MEASUREMENT = "sha384:" + "a" * 96
_ENDPOINT = "https://attest.example.com/v1/verify"
_EVIDENCE = bytes(64)


def _response(payload: bytes) -> MagicMock:
    response = MagicMock()
    response.__enter__ = lambda s: s
    response.__exit__ = MagicMock(return_value=False)
    response.read.return_value = payload
    return response


def test_opaque_requires_verified_and_measurement_matched() -> None:
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_open.return_value = _response(
            b'{"verified": true, "measurement_matched": true}'
        )
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is True
    assert result.failure_reason is None
    assert "opaque_managed_attestation" in result.verified_fields
    assert "opaque_managed_attestation" not in result.unverified_fields


def test_opaque_refuses_verified_response_when_measurement_did_not_match() -> None:
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_open.return_value = _response(
            b'{"verified": true, "measurement_matched": false}'
        )
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is False
    assert result.failure_reason == "opaque_verification_failed"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_refuses_verified_response_when_measurement_result_is_absent() -> None:
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_open.return_value = _response(b'{"verified": true}')
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is False
    assert result.failure_reason == "opaque_verification_failed"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_network_error_is_not_positive_verification() -> None:
    with patch(
        "cmcp_verify.opaque.urllib.request.urlopen",
        side_effect=OSError("timeout"),
    ):
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is False
    assert result.failure_reason == "opaque_verification_error"
    assert "opaque_managed_attestation" in result.unverified_fields
    assert result.details.get("opaque_error") == "OSError"


def test_opaque_malformed_response_is_not_positive_verification() -> None:
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_open.return_value = _response(b"not-json")
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is False
    assert result.failure_reason == "opaque_verification_error"
    assert "opaque_managed_attestation" in result.unverified_fields
    assert result.details.get("opaque_error") == "JSONDecodeError"
