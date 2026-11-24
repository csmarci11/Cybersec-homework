from crypto.encryption import AuthenticationError, DirectionalCipher
from networking.protocol import (
    TYPE_TEXT,
    decode_record,
    encode_record,
)


def test_record_round_trip():
    sender = DirectionalCipher(b"k" * 32, b"abcd")
    receiver = DirectionalCipher(b"k" * 32, b"abcd")
    frame = encode_record(sender, TYPE_TEXT, 0, b"Hello")
    header, plaintext = decode_record(receiver, frame, 0)
    assert header["type"] == TYPE_TEXT
    assert plaintext == b"Hello"


def test_sequence_mismatch_is_rejected():
    sender = DirectionalCipher(b"k" * 32, b"abcd")
    receiver = DirectionalCipher(b"k" * 32, b"abcd")
    frame = encode_record(sender, TYPE_TEXT, 0, b"Hello")
    try:
        decode_record(receiver, frame, 1)
    except Exception:
        return
    raise AssertionError("sequence mismatch was accepted")
