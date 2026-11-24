"""TCP socket lifecycle and exact length-prefixed framing."""

import socket
import struct


MAX_FRAME_SIZE = 1024 * 1024


class ConnectionError(Exception):
    pass


def receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        try:
            chunk = connection.recv(size - len(chunks))
        except socket.timeout as exc:
            raise ConnectionError("socket timeout while receiving data") from exc
        except OSError as exc:
            raise ConnectionError("socket receive failed") from exc
        if not chunk:
            raise ConnectionError("peer closed the connection during a record")
        chunks.extend(chunk)
    return bytes(chunks)


def send_frame(connection: socket.socket, payload: bytes, max_size: int = MAX_FRAME_SIZE) -> None:
    if len(payload) > max_size:
        raise ConnectionError("outgoing frame exceeds configured size limit")
    frame = struct.pack("!I", len(payload)) + payload
    try:
        connection.sendall(frame)
    except socket.timeout as exc:
        raise ConnectionError("socket timeout while sending data") from exc
    except OSError as exc:
        raise ConnectionError("socket send failed") from exc


def receive_frame(connection: socket.socket, max_size: int = MAX_FRAME_SIZE) -> bytes:
    length_bytes = receive_exact(connection, 4)
    length = struct.unpack("!I", length_bytes)[0]
    if length == 0:
        raise ConnectionError("zero-length frame is invalid")
    if length > max_size:
        raise ConnectionError("incoming frame exceeds configured size limit")
    return receive_exact(connection, length)
