"""HKDF-SHA256 key derivation for secure session traffic."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_directional_keys(
    shared_secret: bytes,
    salt: bytes,
    protocol_version: int,
) -> tuple[bytes, bytes]:
    if len(salt) != 16:
        raise ValueError("session salt must be 16 bytes")
    c2s_info = f"secure-network/v{protocol_version}/client-to-server".encode("ascii")
    s2c_info = f"secure-network/v{protocol_version}/server-to-client".encode("ascii")
    c2s = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=c2s_info
    ).derive(shared_secret)
    s2c = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=s2c_info
    ).derive(shared_secret)
    return c2s, s2c
