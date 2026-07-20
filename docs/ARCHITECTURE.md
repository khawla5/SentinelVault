# SecureVault — Architecture

## Overview

SecureVault is split into four cooperating packages plus a thin API layer. The
guiding principle is **separation of trust**: the cryptography that protects
secrets is isolated from the web layer, the persistence layer never sees a
plaintext password, and the threat-detection scanner runs independently of the
vault so a compromise of one does not automatically compromise the other.

```
React frontend (planned)
        │  HTTPS + JWT bearer token
        ▼
FastAPI backend  ── backend/main.py
   ├── security.py   sessions, JWT, idle timeout, in-memory vault key
   ├── audit.py      security event logging (DB + append-only JSONL)
   ├── backup.py     encrypted vault.sec export/import
   └── schemas.py    request/response contracts
        │
        ├── crypto/     Argon2id, AES-256-GCM, HIBP, secure memory
        ├── database/   SQLAlchemy models + SQLite engine
        └── scanner/    process / clipboard / FIM / memory monitors
```

## Request lifecycle (add a credential)

1. Client sends `POST /vault` with a bearer JWT and the plaintext to store.
2. `security.get_current_session` validates the JWT, enforces the idle timeout,
   and retrieves the **in-memory vault key** for that session (never from DB).
3. `crypto.cipher.encrypt` produces `(ciphertext, iv, tag)` with a fresh random
   IV, binding the ciphertext to the user id via GCM associated data.
4. Only the ciphertext components are persisted through `database.models`.
5. `audit.record` logs an `ADD_ENTRY` event.

At no point does the plaintext touch disk.

## Key management

- **Master password → verifier**: hashed with Argon2id and stored. Used only to
  decide whether a login succeeds.
- **Master password → vault key**: Argon2id (raw, 32-byte output) using a
  per-user salt stored in the `users` row. This key is regenerated on every
  login and held only in the process-local session store. On logout / idle
  timeout the key `bytearray` is zeroed.

Because the vault key is a pure function of the master password + salt, the
server is effectively zero-knowledge: DB theft yields only ciphertext.

## Persistence

SQLite via SQLAlchemy 2.0 ORM. Three tables:

- `users` — username, Argon2id master hash, key salt, brute-force state.
- `vault_entries` — label/username/url + AES-GCM ciphertext/iv/tag.
- `activity_logs` — audit trail for the dashboard.

## Scanner

The scanner is deliberately decoupled and can run as a separate process
(`python -m scanner.run_scanner --watch`). It reads system state via `psutil`
and writes alerts to `logs/threats.jsonl`, which the audit dashboard can chart
alongside application events. It has no access to the vault key or plaintext.
```
```
