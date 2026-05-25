"""Post-quantum signatures for audit log entries.

Uses ML-DSA-44 (FIPS 204, formerly Dilithium2) — NIST-standardized August 2024.
Signature size ~2420 bytes; public key ~1312 bytes; secret key ~2560 bytes.

Why ML-DSA instead of Ed25519:
  - Ed25519 is broken by Shor's algorithm on a sufficiently large quantum
    computer. ML-DSA is believed to resist quantum attacks.
  - Compliance buyers (FedRAMP, HIPAA, PCI auditors) increasingly ask for
    NIST PQC algorithms by name.

Key storage:
  - Generated on first call to ensure_keypair().
  - Stored at ~/.mcp-firewall/keys/audit_signing.* with mode 0600.
  - In v0.2 we keep the key local. v0.3 will support HSM / KMS / TEE-attested
    key custody.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# pqcrypto exposes both name spellings depending on version; try both.
try:
    from pqcrypto.sign import ml_dsa_44 as _mldsa  # type: ignore
except ImportError:  # pragma: no cover
    from pqcrypto.sign import dilithium2 as _mldsa  # type: ignore


SIGNING_ALGORITHM = "ML-DSA-44"
KEY_DIR = Path("~/.mcp-firewall/keys").expanduser()
PUBLIC_KEY_PATH = KEY_DIR / "audit_signing.pub"
SECRET_KEY_PATH = KEY_DIR / "audit_signing.key"


@dataclass
class KeyPair:
    public_key: bytes
    secret_key: bytes


def ensure_keypair(
    public_path: Path = PUBLIC_KEY_PATH,
    secret_path: Path = SECRET_KEY_PATH,
) -> KeyPair:
    """Load (or generate + persist) the audit signing keypair."""
    if public_path.exists() and secret_path.exists():
        return KeyPair(
            public_key=public_path.read_bytes(),
            secret_key=secret_path.read_bytes(),
        )
    pk, sk = _mldsa.generate_keypair()
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(pk)
    secret_path.write_bytes(sk)
    os.chmod(secret_path, 0o600)
    os.chmod(public_path, 0o644)
    return KeyPair(public_key=pk, secret_key=sk)


def sign(secret_key: bytes, message: bytes) -> bytes:
    return _mldsa.sign(secret_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff the signature is valid for (public_key, message).

    pqcrypto's ML-DSA wrapper uses detached signatures: verify(pk, msg, sig)
    returns True on valid, raises on invalid.
    """
    try:
        return bool(_mldsa.verify(public_key, message, signature))
    except Exception:
        return False
