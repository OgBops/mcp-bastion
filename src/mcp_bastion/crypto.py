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
  - Stored at ~/.mcp-bastion/keys/audit_signing.* with mode 0600.
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
KEY_DIR = Path("~/.mcp-bastion/keys").expanduser()
PUBLIC_KEY_PATH = KEY_DIR / "audit_signing.pub"
SECRET_KEY_PATH = KEY_DIR / "audit_signing.key"

# OS keychain identifiers. Using keyring lets us delegate secret storage to
# macOS Keychain, Linux Secret Service / kwallet, or Windows Credential
# Locker. Set MCP_BASTION_KEYRING=0 to disable and use file storage only.
KEYRING_SERVICE = "mcp-bastion"
KEYRING_SECRET_KEY = "audit_signing.secret"


def _keyring_enabled() -> bool:
    return os.environ.get("MCP_BASTION_KEYRING", "1") != "0"


def _try_keyring_get() -> bytes | None:
    if not _keyring_enabled():
        return None
    try:
        import keyring  # type: ignore[import-not-found]

        b64 = keyring.get_password(KEYRING_SERVICE, KEYRING_SECRET_KEY)
    except Exception:  # broad: any keyring backend can fail
        return None
    if not b64:
        return None
    import base64

    try:
        return base64.b64decode(b64)
    except Exception:
        return None


def _try_keyring_set(secret_key: bytes) -> bool:
    if not _keyring_enabled():
        return False
    try:
        import base64

        import keyring  # type: ignore[import-not-found]

        keyring.set_password(
            KEYRING_SERVICE,
            KEYRING_SECRET_KEY,
            base64.b64encode(secret_key).decode("ascii"),
        )
        return True
    except Exception:
        return False


@dataclass
class KeyPair:
    public_key: bytes
    secret_key: bytes


def ensure_keypair(
    public_path: Path | None = None,
    secret_path: Path | None = None,
) -> KeyPair:
    """Load (or atomically generate + persist) the audit signing keypair.

    Hardening:
      - Prefers OS keychain (macOS Keychain, Linux Secret Service, Windows
        Credential Locker) for the secret key. Root can still bypass, but
        every read leaves an OS-level audit trail.
      - File-fallback when keyring unavailable (Nitro Enclave, headless
        server). Set MCP_BASTION_KEYRING=0 to force file storage.
      - Key directory created with mode 0700.
      - Secret key file written with O_CREAT|O_EXCL — two concurrent
        processes cannot race past the existence check and clobber each
        other.
      - Secret key file 0600, public key 0644.
    """
    # Late-bind so monkeypatched module attributes work in tests.
    public_path = public_path if public_path is not None else PUBLIC_KEY_PATH
    secret_path = secret_path if secret_path is not None else SECRET_KEY_PATH
    public_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(public_path.parent, 0o700)
    except OSError:
        pass

    # Fast path: public key on disk + secret in keyring (preferred).
    if public_path.exists():
        keyring_secret = _try_keyring_get()
        if keyring_secret is not None:
            return KeyPair(
                public_key=public_path.read_bytes(),
                secret_key=keyring_secret,
            )
        # Fall through to file fallback below.
        if secret_path.exists():
            return KeyPair(
                public_key=public_path.read_bytes(),
                secret_key=secret_path.read_bytes(),
            )

    pk, sk = _mldsa.generate_keypair()

    # Try the keyring FIRST. If it succeeds, we still write the public key
    # to disk (it's not secret) but skip the secret key file entirely.
    keyring_ok = _try_keyring_set(sk)

    # File fallback for the secret key (used when keyring is unavailable
    # or explicitly disabled — e.g., inside Nitro Enclaves).
    if not keyring_ok:
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
            try:
                os.unlink(secret_path)
            except OSError:
                pass
            raise
        os.chmod(secret_path, 0o600)

    # Public key — write race-safe. (No secret content; chmod 0644.)
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
