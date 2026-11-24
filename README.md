# Secure Network Communication

Python 3 CLI demonstration of Diffie-Hellman key exchange and AES-256-GCM protected TCP text and file transfer.

## Security scope

This is a learning application. Diffie-Hellman is unauthenticated. Before accepting the session, compare the displayed 24-character fingerprint in both terminals through a separate trusted channel. An active network attacker can otherwise substitute public values.

## Setup

Windows, macOS or Linux:

```text
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

Terminal 1:

```text
python server.py --host 127.0.0.1 --port 5000
```

Terminal 2:

```text
python client.py --host 127.0.0.1 --port 5000
```

Compare the printed handshake fingerprints. At the client prompt:

```text
/send Hello, secure world!
/file ./documents/sample.pdf
/status
/quit
```

Received files are written to `received/`. The server removes interrupted temporary files. The client and server default to the settings in `config/settings.json`.

## Testing

```text
python -m pytest -q
```

For file verification, calculate the source and received hashes:

```text
python -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" source-file
```
