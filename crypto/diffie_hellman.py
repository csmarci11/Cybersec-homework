"""RFC 3526 MODP group 14 Diffie-Hellman operations."""

from hashlib import sha256
import secrets


# Exact RFC 3526 MODP group 14: 2048-bit finite-field group.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC"
    "2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
Q = (P - 1) // 2
PRIVATE_EXPONENT_MIN = 2


def modular_pow(base: int, exponent: int, modulus: int) -> int:
    """Compute modular exponentiation with the educational square-and-multiply algorithm."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def generate_private_exponent() -> int:
    """Generate a fresh private exponent in the valid range [2, p-2]."""
    return secrets.randbelow(P - PRIVATE_EXPONENT_MIN - 1) + PRIVATE_EXPONENT_MIN


def public_value(private_exponent: int) -> int:
    if not PRIVATE_EXPONENT_MIN <= private_exponent <= P - 2:
        raise ValueError("private exponent is outside the valid range")
    return modular_pow(G, private_exponent, P)


def validate_peer_public(peer_public: int) -> None:
    if not isinstance(peer_public, int):
        raise ValueError("peer public value must be an integer")
    if peer_public <= 1 or peer_public >= P - 1:
        raise ValueError("peer public value is outside the valid range")
    if modular_pow(peer_public, Q, P) != 1:
        raise ValueError("peer public value is not in the selected subgroup")


def shared_secret(private_exponent: int, peer_public: int) -> bytes:
    validate_peer_public(peer_public)
    secret = modular_pow(peer_public, private_exponent, P)
    return secret.to_bytes((P.bit_length() + 7) // 8, "big")


def handshake_fingerprint(
    protocol_version: int,
    client_public: int,
    server_public: int,
    salt: bytes,
) -> str:
    transcript = (
        f"secure-network:v{protocol_version}:"
        f"{client_public:x}:{server_public:x}:{salt.hex()}"
    ).encode("ascii")
    return sha256(transcript).hexdigest()[:24]
