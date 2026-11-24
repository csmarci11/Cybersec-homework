import hashlib
from pathlib import Path

from crypto.encryption import DirectionalCipher
from networking.protocol import decode_record
from transfer.file_transfer import FileReceiver, send_file


class LoopbackSocket:
    def __init__(self):
        self.frames = []

    def sendall(self, frame):
        self.frames.append(frame)


def test_send_empty_and_binary_files(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(bytes(range(256)) * 100)
    socket = LoopbackSocket()
    sender = DirectionalCipher(b"s" * 32, b"1234")
    next_seq, digest = send_file(socket, sender, str(source), 4096, 0, 1024 * 1024)
    assert digest == hashlib.sha256(source.read_bytes()).hexdigest()
    assert next_seq > 1
    assert socket.frames
