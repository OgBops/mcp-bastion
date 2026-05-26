"""AWS Nitro Enclaves attestation.

When the proxy is running inside a Nitro Enclave, customers can request a
cryptographically attested report that proves:

  - which signed binary is executing (PCR values)
  - the enclave's ephemeral public key
  - a fresh nonce supplied by the customer

The customer verifies the attestation against the AWS Nitro root CA and
matches the PCRs against the published mcp-bastion release artifacts. This
defends against a "compromised proxy" supply-chain attack — the only thing
the customer has to trust is AWS's root CA and our published PCR values.

Outside an enclave (laptop, CI), this module returns a clear "not running in
an enclave" error so the same code paths work everywhere.

References:
  - https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html
  - https://github.com/aws/aws-nitro-enclaves-nsm-api
"""

from __future__ import annotations

import base64
import os
import platform
from dataclasses import dataclass
from typing import Any


NSM_DEVICE_PATH = "/dev/nsm"


@dataclass
class AttestationReport:
    """The customer-facing shape we return from /attestation."""

    in_enclave: bool
    platform: str
    document_b64: str | None  # CBOR-encoded, COSE-signed attestation document
    error: str | None
    public_key_b64: str | None
    nonce_b64: str | None


def is_in_enclave() -> bool:
    """Detect Nitro Enclave by presence of the NSM device."""
    return os.path.exists(NSM_DEVICE_PATH)


def get_attestation(
    nonce: bytes | None = None,
    public_key: bytes | None = None,
    user_data: bytes | None = None,
) -> AttestationReport:
    """Generate a Nitro attestation document, or explain why we can't.

    Falls back gracefully on non-enclave platforms so the proxy can still
    advertise an /attestation endpoint that returns a clear "not attested"
    response.
    """
    plat = platform.platform()

    if not is_in_enclave():
        return AttestationReport(
            in_enclave=False,
            platform=plat,
            document_b64=None,
            error="not running inside an AWS Nitro Enclave (/dev/nsm absent)",
            public_key_b64=base64.b64encode(public_key).decode("ascii") if public_key else None,
            nonce_b64=base64.b64encode(nonce).decode("ascii") if nonce else None,
        )

    # Inside an enclave, use the NSM API to request an attestation document.
    try:
        # Lazy import: aws-nitro-enclaves-nsm-api is only available inside
        # enclave images. Outside, the import will fail — that's fine.
        from aws_nitro_enclaves_nsm_api import (  # type: ignore[import-not-found]
            attestation,
        )
    except ImportError:
        return AttestationReport(
            in_enclave=True,
            platform=plat,
            document_b64=None,
            error="NSM device present but `aws_nitro_enclaves_nsm_api` not installed",
            public_key_b64=base64.b64encode(public_key).decode("ascii") if public_key else None,
            nonce_b64=base64.b64encode(nonce).decode("ascii") if nonce else None,
        )

    try:
        doc: bytes = attestation.get_attestation_doc(  # type: ignore[attr-defined]
            user_data=user_data,
            nonce=nonce,
            public_key=public_key,
        )
    except Exception as e:  # pragma: no cover
        return AttestationReport(
            in_enclave=True,
            platform=plat,
            document_b64=None,
            error=f"NSM attestation request failed: {e}",
            public_key_b64=base64.b64encode(public_key).decode("ascii") if public_key else None,
            nonce_b64=base64.b64encode(nonce).decode("ascii") if nonce else None,
        )

    return AttestationReport(
        in_enclave=True,
        platform=plat,
        document_b64=base64.b64encode(doc).decode("ascii"),
        error=None,
        public_key_b64=base64.b64encode(public_key).decode("ascii") if public_key else None,
        nonce_b64=base64.b64encode(nonce).decode("ascii") if nonce else None,
    )


def attestation_to_json(report: AttestationReport) -> dict[str, Any]:
    return {
        "in_enclave": report.in_enclave,
        "platform": report.platform,
        "document_b64": report.document_b64,
        "error": report.error,
        "public_key_b64": report.public_key_b64,
        "nonce_b64": report.nonce_b64,
    }
