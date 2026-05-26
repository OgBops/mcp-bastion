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
    public_path: Path | None = None,
    secret_path: Path | None = None,
) -> KeyPair:
    # Late-bind so monkeypatched module attributes work in tests.
    public_path = public_path if public_path is not None else PUBLIC_KEY_PATH
    secret_path = secret_path if secret_path is not None else SECRET_KEY_PATH
    """Load (or atomically generate + persist) the audit signing keypair.

    Hardening:
      - Key directory created with mode 0700 (other users cannot list).
      - Secret key written with O_CREAT|O_EXCL so two concurrent processes
        cannot race past the existence check and clobber each other; the
        second process re-reads the winner's keys.
      - Secret key written 0600, public key 0644.
    """
    public_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(public_path.parent, 0o700)
    except OSError:
        pass

    # Fast path: both files already exist.
    if public_path.exists() and secret_path.exists():
        return KeyPair(
            public_key=public_path.read_bytes(),
            secret_key=secret_path.read_bytes(),
        )

    pk, sk = _mldsa.generate_keypair()

    # Atomic O_EXCL write of the secret key. If we lose the race, fall back
    # to reading whatever the winning process produced.
    try:
        fd = os.open(
            secret_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        # Another process wrote it first; load theirs.
        return KeyPair(
            public_key=public_path.read_bytes(),
            secret_key=secret_path.read_bytes(),
        )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(sk)
    except Exception:
        # Best-effort cleanup so we don't leave a half-written secret key.
        try:
            os.unlink(secret_path)
        except OSError:
            pass
        raise

    # Public key — same race-safe path. If it loses, that's fine.
    try:
        pfd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(pfd, "wb") as f:
                f.write(pk)
        except Exception:
            try:
                os.unlink(public_path)
            except OSError:
                pass
            raise
    except FileExistsError:
        pass

    os.chmod(secret_path, 0o600)
    os.chmod(public_path, 0o644)
    return KeyPair(public_key=pk, secret_key=sk)


def public_key_fingerprint(public_key: bytes) -> str:
    """SHA256 fingerprint of the public key, used for out-of-band pinning."""
    import hashlib

    return hashlib.sha256(public_key).hexdigest()


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
