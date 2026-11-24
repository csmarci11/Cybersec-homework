"""Versioned application records with authenticated metadata."""

import json
from typing import Any

from crypto.encryption import AuthenticationError, DirectionalCipher


PROTOCOL_VERSION = 1
TYPE_TEXT = "text"
TYPE_FILE_METADATA = "file_metadata"
TYPE_FILE_CHUNK = "file_chunk"
TYPE_FILE_END = "file_end"
MAX_TEXT_LENGTH = 64 * 1024


class ProtocolError(Exception):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def aad_for_header(header: dict[str, Any]) -> bytes:
    aad = {
        "version": header["version"],
        "type": header["type"],
        "seq": header["seq"],
        "transfer_id": header.get("transfer_id"),
        "chunk_index": header.get("chunk_index"),
    }
    return canonical_json(aad)


def encode_record(
    cipher: DirectionalCipher,
    record_type: str,
    sequence: int,
    plaintext: bytes,
    transfer_id: str | None = None,
    chunk_index: int | None = None,
) -> bytes:
    if len(plaintext) > MAX_TEXT_LENGTH and record_type == TYPE_TEXT:
        raise ProtocolError("text record is too large")
    header: dict[str, Any] = {
        "version": PROTOCOL_VERSION,
        "type": record_type,
        "seq": sequence,
        "transfer_id": transfer_id,
        "chunk_index": chunk_index,
    }
    ciphertext = cipher.encrypt_at(plaintext, aad_for_header(header), sequence)
    return canonical_json(header) + b"\n" + ciphertext


def decode_record(
    cipher: DirectionalCipher,
    frame: bytes,
    expected_sequence: int,
) -> tuple[dict[str, Any], bytes]:
    try:
        header_bytes, ciphertext = frame.split(b"\n", 1)
        header = json.loads(header_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("malformed record header") from exc
    if not isinstance(header, dict):
        raise ProtocolError("record header must be a JSON object")
    if not {"version", "type", "seq"}.issubset(header):
        raise ProtocolError("record header is missing required fields")
    if set(header) - {
        "version", "type", "seq", "transfer_id", "chunk_index"
    }:
        raise ProtocolError("unexpected record header fields")
    if header.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    if header.get("seq") != expected_sequence:
        raise ProtocolError("unexpected record sequence")
    if header.get("type") not in {
        TYPE_TEXT,
        TYPE_FILE_METADATA,
        TYPE_FILE_CHUNK,
        TYPE_FILE_END,
    }:
        raise ProtocolError("unsupported record type")
    try:
        plaintext = cipher.decrypt(ciphertext, aad_for_header(header), expected_sequence)
    except AuthenticationError as exc:
        raise ProtocolError("record authentication failed") from exc
    return header, plaintext
