English · [简体中文](./README.zh-CN.md)

# zhcrypt

**zhcrypt** is an end-to-end encrypted communication toolkit built for Chinese users. It combines Argon2id key derivation, AES-256-GCM authenticated encryption, RSA-4096-OAEP-SHA512 hybrid encryption, and X3DH + Double Ratchet forward secrecy, with TOFU safety codes for out-of-band MITM verification. It ships as a CLI (`zhcrypt`), a GUI (`zhcrypt-gui`), and a self-hosted Flask/WebSocket server. See `manual.md` and `docs/` for full usage.

## Components

| Component | Description |
|---|---|
| `zhcrypt.exe` | Command-line tool (console) |
| `zhcrypt-gui.exe` | Graphical interface (tkinter) |
| `server.py` / `chat_server.py` | Self-hosted server (Flask + websockets) |

## Quick start

```bash
# Create an identity (also supported inside the GUI)
zhcrypt init alice
# Encrypt / decrypt
zhcrypt encrypt "机密内容"
zhcrypt decrypt <ciphertext>
# Chat
zhcrypt chat-send -t bob "你好"
zhcrypt chat-poll
```

For full usage see `manual.md` and the `docs/` directory (threat model, server deployment, key backup & recovery).

## Security features

- **Argon2id** (RFC 9106 parameters, 256MB memory) — resists GPU/ASIC brute force
- **AES-256-GCM** — authenticated encryption, prevents tampering and ciphertext-pattern leakage
- **RSA-4096 + OAEP(SHA-512)** — hybrid encryption
- **X3DH + Double Ratchet** — forward secrecy (session keys advance per message)
- **TOFU safety codes** — out-of-band comparison, MITM prevention; any unexpected change in the signed public key rejects the session
- **Certificate pinning (SPKI pinning)** — optional, guards against rogue CAs

## Security hardening (authorized audit, 2026-08-13)

This authorized security-audit round fixed the following issues, all regression-tested (`test_all` 38/38, `test_security_fixes` 66/66, `test_x3dh_full` 25/25, `test_chat` 18/18, 161 unit tests passed):

- **AEAD nonce reuse**: one-time prekey batch wrapping now uses an independent nonce per item (the previous key+nonce reuse triggered GCM keystream reuse).
- **Prekey identity ownership**: the server rejects silently overwriting another identity's signed public key (prevents prekey poisoning / impersonation).
- **Path traversal**: streamed file decryption output names are forcibly basename-sanitized; identity names are whitelist-validated across the full server/client chain.
- **Argon2id memory DoS**: added a `memory×parallelism` product clamp (≤2GiB).
- **Rate-limit bypass**: the message rate-limit key now uses `X-Real-IP` (no longer trusts the spoofable `X-Forwarded-For`).
- **Temporary passphrase entropy**: the temporary passphrase wordlist grew from 20 to 256 words (≈48 bit, previously 17.3 bit).
- **Double Ratchet message-number clamping**: rejects huge `message_number` jumps (prevents CPU DoS).
- **Local key protection**: file AES keys are encrypted at rest with the local `device.key`; private key files tightened to 0600.
- **X25519 low-order point protection**: rejects all-zero shared secrets.

### Known outstanding items (require a protocol version bump, scheduled for the next major release)

Double Ratchet post-compromise self-healing is only partially in place (cross-chain out-of-order prestorage is implemented, full restart resynchronization is not); ciphertext-header Argon2id parameters are not covered by the GCM AAD (streaming headers rely on the clamp as a fallback); fixed HKDF salt; Shamir standard safe primes; explicit X3DH AD binding. See the leftover list in `docs/autopilot_report.md` and `RELEASE_NOTES_3.2.0.md`.

### Deployment security essentials

- Production environments must enable HTTPS/WSS + certificate pinning:
  `zhcrypt set-server https://your-domain --token <tok> --pin <fingerprint>`
- The server auth token is injected only via the `ZHPREKEY_TOKEN` environment variable; committing it to version control is strictly forbidden.
- With port 5000 exposed directly (no Nginx), `ZHPREKEY_TRUST_PROXY=0` is mandatory, otherwise clients can spoof `X-Real-IP` to bypass message rate limiting (default 1 keeps reverse-proxy deployments compatible).
- Small-scale / LAN deployments may enable native TLS (no Nginx needed, see option 2 in `docs/zhcrypt_nginx_tls.md`):
  `ZHPREKEY_TLS_CERT=/path/cert.pem ZHPREKEY_TLS_KEY=/path/key.pem python server.py`

### Scripted usage example

```bash
# Keep the password out of shell history: pipe it into the strength check
echo "你的密码" | zhcrypt strength --stdin
```

## Building

```bash
py -3.13 -m venv packaging\buildenv
packaging\buildenv\Scripts\pip install -r requirements.lock.txt
powershell -ExecutionPolicy Bypass -File packaging\build.ps1
```

Artifacts: `packaging\dist\zhcrypt\` (includes SHA256SUMS.txt).
Dependency lock: `requirements.lock.txt`; SBOM: `SBOM.json`; build info: `buildinfo.json`.

## Server deployment

See `docs/DEPLOY.md`. The server auth token is injected via the `ZHPREKEY_TOKEN` environment variable; clients configure it with `zhcrypt set-server <url> --token <token>`.

## License

MIT (see LICENSE). Third-party component licenses in THIRD_PARTY_NOTICES.txt.
