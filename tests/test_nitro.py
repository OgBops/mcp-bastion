"""Nitro Enclave attestation graceful-fallback test.

We cannot run inside an actual enclave from CI, so we verify:
  - is_in_enclave() returns False on this host
  - get_attestation() returns a structured "not in enclave" report rather
    than throwing
"""

from mcp_firewall import nitro_enclave


def test_not_in_enclave_on_dev_host():
    assert nitro_enclave.is_in_enclave() is False


def test_attestation_fallback_is_structured():
    report = nitro_enclave.get_attestation(nonce=b"test-nonce")
    assert report.in_enclave is False
    assert report.document_b64 is None
    assert report.error is not None
    assert "Nitro Enclave" in report.error
    j = nitro_enclave.attestation_to_json(report)
    assert j["in_enclave"] is False
    assert j["nonce_b64"] is not None  # echoed back base64
