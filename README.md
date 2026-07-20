# SentinelVault 🔐

**An encrypted password manager with built-in malware & threat detection.**

SentinelVault stores credentials using authenticated, military-grade encryption
(AES-256-GCM with keys derived via Argon2id) while monitoring the host for
credential-stealing malware behaviour — suspicious processes, clipboard
hijacking, file tampering, and code-injection indicators.

Built as a portfolio project demonstrating practical **secure software
engineering**, **applied cryptography**, and **defensive malware engineering**
in a single codebase.

> ⚠️ **Defensive by design.** Every "malware" module here *detects* threats —
> it never performs any offensive action. This is a security tool, not malware.

---

## Features

**Vault & cryptography**
- Argon2id master-password hashing — plaintext passwords are never stored
- AES-256-GCM authenticated encryption per credential, with random IVs and integrity tags
- Zero-knowledge design: the vault key is *derived* from the master password and never persisted
- Cryptographically secure password generator (CSPRNG, configurable length & character classes)
- Entropy-based password strength analyzer with actionable suggestions
- Have I Been Pwned leak check via **k-Anonymity** — only the first 5 SHA-1 chars ever leave the machine
- Encrypted, portable vault backup/restore (`vault.sec`)

**Session & account security**
- JWT sessions with a 5-minute idle auto-lock
- Brute-force protection: 5 failed logins → 2-minute lockout
- Clipboard auto-clear 20 seconds after copying a password
- In-memory vault-key wipe on logout + secure delete of removed entries
- Full audit log of security events with timestamp, IP, and machine name

**Malware / threat detection**
- **Process monitor** — flags known infostealers (RedLine, Lumma, Raccoon, Vidar…) and suspicious tooling (keyloggers, injectors, clippers)
- **Clipboard-hijack detector** — catches "clippers" that overwrite the clipboard right after a copy
- **File Integrity Monitoring** — SHA-256 baseline of the vault DB; alerts on unexpected change or deletion
- **Memory / injection heuristics** — flags Writable+eXecutable (RWX) memory regions, a hallmark of injected shellcode; documents the Win32-API remote-thread approach for Windows builds
- Unified severity model: `INFO` / `WARNING` / `CRITICAL`, logged for the audit dashboard

**Web interface**
- Built-in single-page UI served by the backend — no build step, no external front-end libraries
- Bilingual: **English / العربية** with full RTL support, persisted per user
- Dark & light themes with smooth, flash-free switching
- Seven professional grayscale accent themes (Slate, Blue Gray, Graphite, Charcoal, Steel Blue, Cool Gray, Dark Navy)
- Abstract SVG line-art background, custom SVG icon set, responsive layout

---

## Architecture

```
                        ┌──────────────────────────────┐
                        │      Built-in Web UI          │
                        │  i18n (EN/AR) · themes · vault │
                        └───────────────┬──────────────┘
                                        │ JWT over HTTP
                        ┌───────────────▼──────────────┐
                        │       FastAPI Backend         │
                        │  auth · vault CRUD · tools     │
                        │  backup · audit · sessions     │
                        └───┬───────────┬──────────┬────┘
                            │           │          │
                    ┌───────▼──┐  ┌─────▼────┐  ┌──▼──────────┐
                    │  crypto  │  │ database │  │   scanner   │
                    │ Argon2id │  │ SQLite / │  │ process/FIM │
                    │ AES-GCM  │  │ Postgres │  │ clipboard/  │
                    │ HIBP     │  │  models  │  │ memory      │
                    └──────────┘  └──────────┘  └─────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full design.

---

## Encryption design

| Purpose | Primitive | Notes |
|---|---|---|
| Master-password verifier | **Argon2id** (t=3, m=64 MiB, p=4) | Stored hash only; gates login |
| Vault-key derivation | **Argon2id** raw → 32 bytes | Derived from master password + per-user salt; **never stored** |
| Credential encryption | **AES-256-GCM** | Random 96-bit IV per entry; 128-bit auth tag; user id bound as associated data |
| Backup encryption | **AES-256-GCM** + Argon2id | Separate backup passphrase so backups are portable |
| Leak check | **SHA-1 k-Anonymity** | SHA-1 used *only* as HIBP's index, never to protect passwords |

The master password is the single root of trust: without it, stored ciphertext
is unrecoverable even to someone with full database access.

---

## Project structure

```
SentinelVault/
├── backend/         FastAPI app: auth, vault CRUD, tools, backup, audit, sessions
│   ├── main.py          API routes + web UI route
│   ├── security.py      JWT + in-memory session store + idle timeout
│   ├── audit.py         activity logging (DB + JSONL)
│   ├── backup.py        encrypted vault.sec export/import
│   └── schemas.py       Pydantic models
├── crypto/          Cryptography layer
│   ├── kdf.py           Argon2id hashing + vault-key derivation
│   ├── cipher.py        AES-256-GCM encrypt/decrypt
│   ├── secure_mem.py    memory wipe + secure file delete
│   ├── generator.py     CSPRNG password generator
│   ├── strength.py      entropy analyzer
│   └── hibp.py          Have I Been Pwned k-Anonymity
├── database/        SQLAlchemy engine + ORM models (SQLite or Postgres/Supabase)
├── scanner/         Malware / threat detection
│   ├── rules.py             signature + severity rules
│   ├── process_monitor.py   suspicious-process detection
│   ├── clipboard_monitor.py hijack detection + auto-clear
│   ├── fim.py               file integrity monitoring
│   ├── memory_monitor.py    injection / RWX heuristics
│   ├── logger.py            unified alert logging
│   └── run_scanner.py       orchestrator (one-shot / --watch)
├── web/             Built-in single-page UI (i18n, theming, no dependencies)
├── tests/           pytest suite (36 tests)
├── docs/            architecture, threat model, publishing guide
├── config.py        central config (secrets via .env)
└── run.py           entry point
```

---

## Installation

Requires **Python 3.10+**.

```bash
# 1. Clone
git clone https://github.com/khawla5/SentinelVault.git && cd SentinelVault

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure secrets
cp .env.example .env
# then generate a JWT secret:
python3 -c "import secrets; print(secrets.token_hex(32))"
# and paste it into .env as SECUREVAULT_JWT_SECRET

# 5. Run
python run.py
```

Then open **http://127.0.0.1:8000/** for the app
(interactive API docs at `/docs`).

### Optional: use Supabase / PostgreSQL

```bash
pip install "psycopg[binary]"
# add to .env:
# DATABASE_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
```

The app auto-detects the driver and enables SSL. Only ciphertext and Argon2id
hashes are ever written — never plaintext.

### Run the threat scanner

```bash
python -m scanner.run_scanner            # one full scan
python -m scanner.run_scanner --watch    # continuous monitoring
```

### Run the tests

```bash
pytest            # 36 tests: crypto, generator, strength, HIBP, backup, scanner rules
```

---

## API quick reference

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Create account, returns JWT |
| POST | `/auth/login` | Log in (brute-force protected) |
| POST | `/auth/logout` | Log out, wipe in-memory key |
| GET/POST | `/vault` | List / add credentials (encrypted) |
| GET | `/vault/{id}/reveal` | Decrypt a single credential on demand |
| DELETE | `/vault/{id}` | Secure-delete a credential |
| POST | `/tools/generate` | Generate a strong password |
| POST | `/tools/strength` | Analyze password strength |
| POST | `/tools/leak-check` | Check HIBP via k-Anonymity |
| GET | `/vault/export` | Download encrypted `vault.sec` |
| GET | `/logs`, `/logs/stats` | Audit log + dashboard stats |
| GET | `/health` | Status + active database backend |

---

## Threat-detection examples

| Observed process | Verdict |
|---|---|
| `taskmgr.exe`, `chrome.exe` | ✅ Normal |
| `keylogger.exe`, `injector.exe` | ⚠ Warning (suspicious tooling) |
| `RedLine.exe`, `Lumma.exe`, `Raccoon.exe` | ⛔ Critical (known infostealer) |
| Process with RWX memory regions | ⚠ Warning (possible code injection) |
| Vault database hash changed unexpectedly | ⚠ Warning (integrity violation) |

---

## Roadmap

- Audit dashboard with charts for logins, alerts, and weak/leaked passwords
- PyInstaller desktop packaging with native OS clipboard hooks
- Windows-native injection detection via pywin32 (remote-thread enumeration)
- YARA integration for richer file/process signatures
- ML classifier (normal vs. malicious process) over CPU/RAM/network/DLL/thread features
- TOTP-based two-factor authentication

---

## Security notes & honest limitations

This is a **learning / portfolio** project, not an audited product.

- Python cannot guarantee secrets are fully erased from memory; `secure_mem`
  demonstrates the correct *minimise-lifetime + overwrite mutable buffer*
  pattern and is transparent about its limits.
- Name-based process signatures are a weak first-pass signal (malware renames
  binaries); the RWX-memory and file-integrity checks add harder-to-evade
  behavioural signals.
- The in-memory session store suits a single-instance desktop-style app; a
  multi-worker deployment would need a different key-handling strategy.
- Don't store real passwords in a development instance.

---

## License

MIT — see [`LICENSE`](LICENSE).
