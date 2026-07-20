# SecureVault — Threat Model

## Assets
- The user's stored credentials (highest value).
- The master password (root of trust for all decryption).
- The audit log (integrity matters for incident response).

## Trust boundaries
- **Network ↔ API**: authenticated with JWT; only the ciphertext and derived
  tokens cross this boundary. Plaintext credentials cross only on an explicit
  `/vault/{id}/reveal` request initiated by the authenticated user.
- **API ↔ Database**: the DB is treated as untrusted-at-rest — it stores only
  ciphertext + non-secret metadata + Argon2id hashes.
- **Host ↔ Application**: the local machine may be compromised; the scanner
  exists precisely to surface that case.

## Adversaries & mitigations

| Adversary / attack | Mitigation |
|---|---|
| Database theft (offline attacker) | AES-256-GCM ciphertext + Argon2id-derived key that is never stored → data unrecoverable without the master password |
| Master-password guessing | Argon2id (memory-hard) verifier; 5-attempt brute-force lockout (2 min) |
| Password reuse / known-breached passwords | HIBP k-Anonymity leak check + entropy strength analyzer |
| Tampering with stored ciphertext | GCM authentication tag + user-id associated data → tamper raises `InvalidTag` |
| Clipboard-stealing malware ("clippers") | Clipboard-hijack detector + 20 s auto-clear after copy |
| Keyloggers / infostealers running locally | Process monitor with signature + keyword rules (RedLine, Lumma, Raccoon, keylogger, injector…) |
| Code injection into a trusted process | RWX-memory heuristic; documented Win32 remote-thread enumeration for Windows |
| Vault file tampering / ransomware | SHA-256 File Integrity Monitoring with alerting |
| Session hijack after user walks away | 5-minute idle auto-lock; in-memory key wiped on lock/logout |
| Secrets lingering in memory | `secure_mem` minimises decrypted-secret lifetime and overwrites mutable buffers |
| Recovering deleted secrets | Secure delete overwrites ciphertext bytes before row removal |

## Explicit non-goals / known limitations
- No protection against a kernel-level rootkit or a fully compromised OS —
  the scanner raises signals but cannot guarantee host integrity.
- Python memory-wiping is best-effort (immutable `str`/`bytes` may leave copies).
- Name-based process signatures are evadable by renaming; behavioural signals
  (RWX, FIM) are the more robust layer.
- Not independently security-audited; intended as a portfolio/learning project.
