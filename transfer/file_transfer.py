"""Chunked authenticated file transfer and safe receiver file writes."""

import hashlib
import os
import secrets
import tempfile
from pathlib import Path
from typing import BinaryIO

from crypto.encryption import DirectionalCipher
from networking.connection import send_frame
from networking.protocol import (
    TYPE_FILE_CHUNK,
    TYPE_FILE_END,
    TYPE_FILE_METADATA,
    canonical_json,
    encode_record,
)


class FileTransferError(Exception):
    pass


def safe_filename(raw_name: str) -> str:
    name = os.path.basename(raw_name.replace("\\", "/"))
    if not name or name in {".", ".."}:
        raise FileTransferError("invalid or unsafe filename")
    if "\x00" in name:
        raise FileTransferError("invalid filename")
    return name


def send_file(
    connection,
    cipher: DirectionalCipher,
    source_path: str,
    chunk_size: int,
    start_sequence: int,
    max_file_size: int,
) -> tuple[int, str]:
    path = Path(source_path)
    if not path.is_file():
        raise FileTransferError("source file does not exist")
    file_size = path.stat().st_size
    if file_size > max_file_size:
        raise FileTransferError("source file exceeds the configured size limit")

    transfer_id = secrets.token_hex(16)
    digest = hashlib.sha256()
    seq = start_sequence
    metadata = {
        "filename": safe_filename(path.name),
        "total_size": file_size,
        "chunk_size": chunk_size,
    }
    frame = encode_record(
        cipher,
        TYPE_FILE_METADATA,
        seq,
        canonical_json(metadata),
        transfer_id,
        None,
    )
    send_frame(connection, frame)
    seq += 1

    bytes_sent = 0
    chunk_count = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            frame = encode_record(
                cipher,
                TYPE_FILE_CHUNK,
                seq,
                chunk,
                transfer_id,
                chunk_count,
            )
            send_frame(connection, frame)
            bytes_sent += len(chunk)
            chunk_count += 1
            seq += 1
            print(f"\rSent {bytes_sent}/{file_size} bytes", end="", flush=True)
    print()

    completion = {
        "total_size": bytes_sent,
        "chunk_count": chunk_count,
        "sha256": digest.hexdigest(),
    }
    frame = encode_record(
        cipher,
        TYPE_FILE_END,
        seq,
        canonical_json(completion),
        transfer_id,
        None,
    )
    send_frame(connection, frame)
    return seq + 1, digest.hexdigest()


class FileReceiver:
    def __init__(
        self,
        receive_directory: str,
        max_file_size: int,
    ) -> None:
        self.receive_directory = Path(receive_directory)
        self.receive_directory.mkdir(parents=True, exist_ok=True)
        self.max_file_size = max_file_size
        self._active_id: str | None = None
        self._metadata: dict | None = None
        self._output: BinaryIO | None = None
        self._temp_path: Path | None = None
        self._received_bytes = 0
        self._received_chunks = 0
        self._digest = hashlib.sha256()

    def _cleanup(self) -> None:
        if self._output is not None:
            self._output.close()
            self._output = None
        if self._temp_path is not None:
            try:
                self._temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._temp_path = None

    def abort(self) -> None:
        self._cleanup()
        self._active_id = None
        self._metadata = None

    def process(self, header: dict, plaintext: bytes) -> str | None:
        record_type = header["type"]
        transfer_id = header.get("transfer_id")
        if not isinstance(transfer_id, str) or len(transfer_id) != 32:
            raise FileTransferError("invalid file transfer identifier")

        if record_type == TYPE_FILE_METADATA:
            if self._active_id is not None:
                raise FileTransferError("a file transfer is already active")
            try:
                metadata = __import__("json").loads(plaintext.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise FileTransferError("invalid file metadata") from exc
            filename = safe_filename(metadata.get("filename", ""))
            total_size = metadata.get("total_size")
            chunk_size = metadata.get("chunk_size")
            if not isinstance(total_size, int) or total_size < 0:
                raise FileTransferError("invalid file size")
            if total_size > self.max_file_size:
                raise FileTransferError("file exceeds the configured size limit")
            if not isinstance(chunk_size, int) or chunk_size <= 0 or chunk_size > 1024 * 1024:
                raise FileTransferError("invalid chunk size")
            fd, temp_name = tempfile.mkstemp(prefix=".secure-transfer-", dir=self.receive_directory)
            self._temp_path = Path(temp_name)
            self._output = os.fdopen(fd, "wb")
            self._active_id = transfer_id
            self._metadata = {
                "filename": filename,
                "total_size": total_size,
                "chunk_size": chunk_size,
            }
            self._received_bytes = 0
            self._received_chunks = 0
            self._digest = hashlib.sha256()
            return None

        if transfer_id != self._active_id:
            raise FileTransferError("chunk belongs to an unknown transfer")

        if record_type == TYPE_FILE_CHUNK:
            if header.get("chunk_index") != self._received_chunks:
                raise FileTransferError("missing, duplicated or out-of-order chunk")
            if self._received_bytes + len(plaintext) > self._metadata["total_size"]:
                raise FileTransferError("received more file bytes than declared")
            if len(plaintext) > self._metadata["chunk_size"]:
                raise FileTransferError("chunk exceeds declared chunk size")
            self._output.write(plaintext)
            self._digest.update(plaintext)
            self._received_bytes += len(plaintext)
            self._received_chunks += 1
            print(
                f"\rReceived {self._received_bytes}/{self._metadata['total_size']} bytes",
                end="",
                flush=True,
            )
            return None

        if record_type == TYPE_FILE_END:
            try:
                completion = __import__("json").loads(plaintext.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise FileTransferError("invalid completion record") from exc
            if completion.get("total_size") != self._received_bytes:
                raise FileTransferError("completed byte count does not match")
            if completion.get("chunk_count") != self._received_chunks:
                raise FileTransferError("completed chunk count does not match")
            if self._received_bytes != self._metadata["total_size"]:
                raise FileTransferError("file ended before the declared size")
            if completion.get("sha256") != self._digest.hexdigest():
                raise FileTransferError("file SHA-256 mismatch")

            final_path = self.receive_directory / safe_filename(self._metadata["filename"])
            if final_path.exists():
                final_path = self.receive_directory / (
                    final_path.stem + "-" + secrets.token_hex(4) + final_path.suffix
                )
            self._output.flush()
            os.fsync(self._output.fileno())
            self._output.close()
            self._output = None
            os.replace(self._temp_path, final_path)
            self._temp_path = None
            self._active_id = None
            self._metadata = None
            print()
            return str(final_path)

        raise FileTransferError("unsupported file record")
