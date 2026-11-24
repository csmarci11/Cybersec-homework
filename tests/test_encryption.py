from crypto.encryption import AuthenticationError, DirectionalCipher


def test_round_trip():
    cipher = DirectionalCipher(b"a" * 32, b"1234")
    ciphertext = cipher.encrypt_at(b"hello", b"aad", 0)
    receiver = DirectionalCipher(b"a" * 32, b"1234")
    assert receiver.decrypt(ciphertext, b"aad", 0) == b"hello"


def test_modified_ciphertext_is_rejected():
    cipher = DirectionalCipher(b"a" * 32, b"1234")
    ciphertext = bytearray(cipher.encrypt_at(b"hello", b"aad", 0))
    ciphertext[-1] ^= 1
    receiver = DirectionalCipher(b"a" * 32, b"1234")
    try:
        receiver.decrypt(bytes(ciphertext), b"aad", 0)
    except AuthenticationError:
        return
    raise AssertionError("modified ciphertext was accepted")


def test_modified_aad_is_rejected():
    cipher = DirectionalCipher(b"a" * 32, b"1234")
    ciphertext = cipher.encrypt_at(b"hello", b"aad", 0)
    receiver = DirectionalCipher(b"a" * 32, b"1234")
    try:
        receiver.decrypt(ciphertext, b"wrong", 0)
    except AuthenticationError:
        return
    raise AssertionError("modified AAD was accepted")
