"""Cryptography package for SecureVault.

Public surface:
    kdf        -> Argon2id master-password hashing + vault-key derivation
    cipher     -> AES-256-GCM authenticated encryption
    secure_mem -> best-effort in-memory wipe + secure file deletion
    generator  -> cryptographically secure password generation
    strength   -> entropy-based password strength analysis
    hibp       -> Have I Been Pwned k-anonymity leak check
"""
