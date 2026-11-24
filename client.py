"""Secure communication client command-line entry point."""

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
    encode_record,
)
from transfer.file_transfer import FileTransferError, send_file


CONFIG_PATH = Path(__file__).with_name("config") / "settings.json"


def load_settings() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def handshake(connection: socket.socket) -> tuple[DirectionalCipher, DirectionalCipher, str]:
    private = generate_private_exponent()
    client_public = public_value(private)
    salt = secrets.token_bytes(16)
    nonce_prefix = secrets.token_bytes(4)
    hello = {
        "version": PROTOCOL_VERSION,
        "public": f"{client_public:x}",
        "salt": salt.hex(),
        "nonce_prefix": nonce_prefix.hex(),
    }
    send_frame(connection, canonical_json(hello))

    try:
        response = json.loads(receive_frame(connection).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectionError("malformed server handshake") from exc
    if not isinstance(response, dict):
        raise ConnectionError("malformed server handshake")
    if response.get("version") != PROTOCOL_VERSION:
        raise ConnectionError("unsupported protocol version")
    if response.get("salt") != salt.hex():
        raise ConnectionError("server did not echo the session salt")
    try:
        server_public = int(response["public"], 16)
        server_nonce_prefix = bytes.fromhex(response["nonce_prefix"])
    except (KeyError, ValueError) as exc:
        raise ConnectionError("malformed server handshake fields") from exc
    if len(server_nonce_prefix) != 4:
        raise ConnectionError("invalid server nonce prefix")

    secret = shared_secret(private, server_public)
    c2s_key, s2c_key = derive_directional_keys(secret, salt, PROTOCOL_VERSION)
    fingerprint = handshake_fingerprint(
        PROTOCOL_VERSION, client_public, server_public, salt
    )
    return (
        DirectionalCipher(c2s_key, nonce_prefix),
        DirectionalCipher(s2c_key, server_nonce_prefix),
        fingerprint,
    )


def main() -> int:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="Secure communication client")
    parser.add_argument("--host", default=settings["host"])
    parser.add_argument("--port", type=int, default=settings["port"])
    parser.add_argument("--timeout", type=float, default=settings["socket_timeout_seconds"])
    parser.add_argument("--chunk-size", type=int, default=settings["chunk_size"])
    parser.add_argument("--max-file-size", type=int, default=settings["max_file_size"])
    args = parser.parse_args()

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(args.timeout)
    try:
        print(f"Connecting to {args.host}:{args.port}...")
        connection.connect((args.host, args.port))
        c2s_cipher, s2c_cipher, fingerprint = handshake(connection)
        print("Secure handshake completed.")
        print(f"Handshake fingerprint: {fingerprint}")
        print("Compare this fingerprint with the server through a trusted channel.")
        seq = 0
        while True:
            command = input("secure-client> ").strip()
            if command == "/quit":
                print("Closing connection.")
                break
            if command == "/status":
                print("Connected; next outgoing sequence:", seq)
                continue
            if command.startswith("/send "):
                text = command[len("/send ") :]
                if not text:
                    print("Text message cannot be empty.")
                    continue
                frame = encode_record(
                    c2s_cipher,
                    TYPE_TEXT,
                    seq,
                    text.encode("utf-8"),
                )
                send_frame(connection, frame)
                print("Message sent and authenticated.")
                seq += 1
                continue
            if command.startswith("/file "):
                path = command[len("/file ") :].strip().strip('"')
                try:
                    seq, digest = send_file(
                        connection,
                        c2s_cipher,
                        path,
                        args.chunk_size,
                        seq,
                        args.max_file_size,
                    )
                    print(f"File transfer completed. SHA-256: {digest}")
                except (FileTransferError, ConnectionError, OSError) as exc:
                    print(f"File transfer failed: {exc}")
                continue
            print("Commands: /send TEXT | /file PATH | /status | /quit")
        return 0
    except (ConnectionError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
