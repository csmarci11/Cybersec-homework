"""Secure communication server command-line entry point."""

import argparse
import json
import secrets
import socket
from pathlib import Path

from crypto.diffie_hellman import (
    handshake_fingerprint,
    generate_private_exponent,
    public_value,
    shared_secret,
)
from crypto.encryption import DirectionalCipher
from crypto.key_derivation import derive_directional_keys
from networking.connection import ConnectionError, receive_frame, send_frame
from networking.protocol import (
    PROTOCOL_VERSION,
    TYPE_TEXT,
    canonical_json,
    decode_record,
    ProtocolError,
)
from transfer.file_transfer import FileReceiver, FileTransferError


CONFIG_PATH = Path(__file__).with_name("config") / "settings.json"


def load_settings() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def handshake(connection: socket.socket) -> tuple[DirectionalCipher, DirectionalCipher, str]:
    try:
        hello = json.loads(receive_frame(connection).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectionError("malformed client handshake") from exc
    if not isinstance(hello, dict):
        raise ConnectionError("malformed client handshake")
    if hello.get("version") != PROTOCOL_VERSION:
        raise ConnectionError("unsupported protocol version")
    try:
        client_public = int(hello["public"], 16)
        salt = bytes.fromhex(hello["salt"])
        client_nonce_prefix = bytes.fromhex(hello["nonce_prefix"])
    except (KeyError, ValueError) as exc:
        raise ConnectionError("malformed client handshake fields") from exc
    if len(salt) != 16:
        raise ConnectionError("invalid session salt")
    if len(client_nonce_prefix) != 4:
        raise ConnectionError("invalid client nonce prefix")

    private = generate_private_exponent()
    server_public = public_value(private)
    nonce_prefix = secrets.token_bytes(4)
    response = {
        "version": PROTOCOL_VERSION,
        "public": f"{server_public:x}",
        "salt": salt.hex(),
        "nonce_prefix": nonce_prefix.hex(),
    }
    send_frame(connection, canonical_json(response))

    secret = shared_secret(private, client_public)
    c2s_key, s2c_key = derive_directional_keys(secret, salt, PROTOCOL_VERSION)
    fingerprint = handshake_fingerprint(
        PROTOCOL_VERSION, client_public, server_public, salt
    )
    return (
        DirectionalCipher(c2s_key, client_nonce_prefix),
        DirectionalCipher(s2c_key, nonce_prefix),
        fingerprint,
    )


def main() -> int:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Secure communication server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=settings["port"])
    parser.add_argument("--timeout", type=float, default=settings["socket_timeout_seconds"])
    parser.add_argument("--max-file-size", type=int, default=settings["max_file_size"])
    parser.add_argument("--receive-directory", default=settings["receive_directory"])
    args = parser.parse_args()

    listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening.bind((args.host, args.port))
    listening.listen(1)
    listening.settimeout(args.timeout)
    print(f"Listening on {args.host}:{args.port}")
    try:
        connection, address = listening.accept()
        print(f"Client connected: {address[0]}:{address[1]}")
        connection.settimeout(args.timeout)
        c2s_cipher, s2c_cipher, fingerprint = handshake(connection)
        print("Secure handshake completed.")
        print(f"Handshake fingerprint: {fingerprint}")
        print("Compare this fingerprint with the client through a trusted channel.")

        receiver = FileReceiver(args.receive_directory, args.max_file_size)
        seq = 0
        while True:
            try:
                frame = receive_frame(connection)
                header, plaintext = decode_record(c2s_cipher, frame, seq)
            except ConnectionError as exc:
                print(f"Connection ended: {exc}")
                receiver.abort()
                break
            except ProtocolError as exc:
                print(f"Security/protocol error: {exc}")
                receiver.abort()
                break

            if header["type"] == TYPE_TEXT:
                try:
                    message = plaintext.decode("utf-8")
                except UnicodeDecodeError:
                    print("Text record contained invalid UTF-8.")
                    receiver.abort()
                    break
                print(f"\nAuthenticated text: {message}")
            else:
                try:
                    final_path = receiver.process(header, plaintext)
                    if final_path:
                        print(f"\nFile transfer complete: {final_path}")
                except FileTransferError as exc:
                    print(f"File transfer error: {exc}")
                    receiver.abort()
                    break
            seq += 1
        return 0
    except (ConnectionError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        listening.close()


if __name__ == "__main__":
    raise SystemExit(main())
