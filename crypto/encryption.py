"""AES-256-GCM authenticated encryption wrappers."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AuthenticationError(Exception):
    pass


class DirectionalCipher:
    def __init__(self, key: bytes, nonce_prefix: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 keys must be 32 bytes")
        if len(nonce_prefix) != 4:
            raise ValueError("nonce prefix must be 4 bytes")
        self._aes = AESGCM(key)
        self._nonce_prefix = nonce_prefix
        self._counter = 0

    def _nonce(self, counter: int) -> bytes:
        if counter < 0 or counter >= (1 << 64):
            raise OverflowError("nonce counter exhausted")
        return self._nonce_prefix + counter.to_bytes(8, "big")

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, int]:
        nonce = self._nonce(self._counter)
        ciphertext = self._aes.encrypt(nonce, plaintext, aad)
        used_counter = self._counter
        self._counter += 1
        return ciphertext, used_counter

    def decrypt(self, ciphertext: bytes, aad: bytes, counter: int) -> bytes:
        try:
            return self._aes.decrypt(self._nonce(counter), ciphertext, aad)
        except InvalidTag as exc:
            raise AuthenticationError("AES-GCM authentication failed") from exc

    def encrypt_at(self, plaintext: bytes, aad: bytes, counter: int) -> bytes:
        nonce = self._nonce(counter)
        ciphertext = self._aes.encrypt(nonce, plaintext, aad)
        if counter >= self._counter:
            self._counter = counter + 1
        return ciphertext
