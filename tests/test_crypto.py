from pathlib import Path

from mcp_firewall import crypto


def test_ensure_keypair_persists(tmp_path: Path):
    pub = tmp_path / "k.pub"
    sec = tmp_path / "k.key"
    kp1 = crypto.ensure_keypair(public_path=pub, secret_path=sec)
    kp2 = crypto.ensure_keypair(public_path=pub, secret_path=sec)
    assert kp1.public_key == kp2.public_key
    assert kp1.secret_key == kp2.secret_key
    assert (sec.stat().st_mode & 0o777) == 0o600


def test_sign_and_verify_roundtrip(tmp_path: Path):
    pub = tmp_path / "k.pub"
    sec = tmp_path / "k.key"
    kp = crypto.ensure_keypair(public_path=pub, secret_path=sec)
    msg = b"audit row hash"
    sig = crypto.sign(kp.secret_key, msg)
    assert crypto.verify(kp.public_key, msg, sig)
    # Tampered message must fail
    assert not crypto.verify(kp.public_key, msg + b"x", sig)
    # Tampered signature must fail
    bad = bytearray(sig)
    bad[0] ^= 0xFF
    assert not crypto.verify(kp.public_key, msg, bytes(bad))
