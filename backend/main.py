"""
SecureVault REST API (FastAPI).

Routes
------
Auth      POST /auth/register, POST /auth/login, POST /auth/logout
Vault     GET/POST /vault, GET /vault/{id}/reveal, DELETE /vault/{id}
Tools     POST /tools/generate, POST /tools/strength, POST /tools/leak-check
Backup    GET  /vault/export, POST /vault/import
Audit     GET  /logs, GET /logs/stats

Security features wired in here:
  * Argon2id master-password hashing (Phase 1)
  * AES-256-GCM per-entry encryption with an in-memory, per-session key (Phase 2)
  * Password generator / strength / HIBP leak check (Phases 3-5)
  * Brute-force lockout after N failures (Phase: Brute Force Protection)
  * Idle session timeout + JWT (Phase 7)
  * Encrypted backup/restore (Phase 8)
  * Activity logging (Phase 9)
  * In-memory vault-key wipe on logout (Memory Protection)
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import audit, backup
from backend.schemas import (
    GenerateRequest,
    GenerateResponse,
    LeakResponse,
    LogOut,
    LoginRequest,
    RegisterRequest,
    StrengthRequest,
    StrengthResponse,
    TokenResponse,
    VaultEntryCreate,
    VaultEntryOut,
    VaultEntryReveal,
)
from backend.security import (
    CurrentUser,
    create_session,
    destroy_session,
    get_current_session,
)
from config import settings
from crypto import cipher, hibp, kdf
from crypto.generator import GeneratorOptions, generate_password
from crypto.secure_mem import sensitive_bytes, wipe
from crypto.strength import analyze
from database.db import current_backend, get_session, init_db
from database.models import ActivityLog, User, VaultEntry

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables on startup.
    init_db()
    yield


app = FastAPI(title="SecureVault API", version="1.0.0", lifespan=lifespan)

# Frontend (React dev server) origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


# --------------------------------------------------------------------------- #
#  Auth
# --------------------------------------------------------------------------- #
@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_session)):
    existing = db.scalar(select(User).where(User.username == body.username))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")

    key_salt = kdf.new_key_salt()
    user = User(
        username=body.username,
        master_hash=kdf.hash_master_password(body.master_password),
        key_salt=key_salt,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit.record(db, audit.REGISTER, user_id=user.id, ip_address=_client_ip(request))

    vault_key = kdf.derive_vault_key(body.master_password, key_salt)
    token = create_session(user.id, vault_key)
    return TokenResponse(access_token=token, expires_in_minutes=settings.ACCESS_TOKEN_TTL_MINUTES)


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_session)):
    user = db.scalar(select(User).where(User.username == body.username))
    ip = _client_ip(request)

    # Uniform error message avoids username enumeration.
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    if user is None:
        raise invalid

    # Brute-force lockout check.
    now = datetime.now(timezone.utc)
    if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > now:
        remaining = int((user.locked_until.replace(tzinfo=timezone.utc) - now).total_seconds())
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Account locked. Try again in {remaining}s.",
        )

    if not kdf.verify_master_password(user.master_hash, body.master_password):
        user.failed_attempts += 1
        detail = f"attempt {user.failed_attempts}/{settings.MAX_FAILED_LOGINS}"
        if user.failed_attempts >= settings.MAX_FAILED_LOGINS:
            from datetime import timedelta
            user.locked_until = now + timedelta(seconds=settings.LOCKOUT_SECONDS)
            user.failed_attempts = 0
            audit.record(db, audit.ACCOUNT_LOCKED, user_id=user.id, ip_address=ip, detail=detail)
        db.commit()
        audit.record(db, audit.LOGIN_FAILED, user_id=user.id, ip_address=ip, detail=detail)
        raise invalid

    # Success: reset counters, transparently upgrade hash if params changed.
    user.failed_attempts = 0
    user.locked_until = None
    if kdf.needs_rehash(user.master_hash):
        user.master_hash = kdf.hash_master_password(body.master_password)
    db.commit()

    audit.record(db, audit.LOGIN, user_id=user.id, ip_address=ip)

    vault_key = kdf.derive_vault_key(body.master_password, user.key_salt)
    token = create_session(user.id, vault_key)
    return TokenResponse(access_token=token, expires_in_minutes=settings.ACCESS_TOKEN_TTL_MINUTES)


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    cur: CurrentUser = Depends(get_current_session),
    db: Session = Depends(get_session),
):
    audit.record(db, audit.LOGOUT, user_id=cur.user_id, ip_address=_client_ip(request))
    destroy_session(cur.jti)  # wipes the in-memory vault key
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
#  Vault CRUD
# --------------------------------------------------------------------------- #
@app.get("/vault", response_model=list[VaultEntryOut])
def list_entries(cur: CurrentUser = Depends(get_current_session), db: Session = Depends(get_session)):
    entries = db.scalars(
        select(VaultEntry).where(VaultEntry.user_id == cur.user_id).order_by(VaultEntry.label)
    ).all()
    return entries


@app.post("/vault", response_model=VaultEntryOut, status_code=status.HTTP_201_CREATED)
def add_entry(
    body: VaultEntryCreate,
    request: Request,
    cur: CurrentUser = Depends(get_current_session),
    db: Session = Depends(get_session),
):
    # Bind ciphertext to this user's id as associated data (integrity).
    aad = str(cur.user_id).encode()
    with sensitive_bytes(bytes(cur.vault_key)) as key:
        enc = cipher.encrypt(bytes(key), body.password, associated_data=aad)

    entry = VaultEntry(
        user_id=cur.user_id,
        label=body.label,
        username=body.username,
        url=body.url,
        ciphertext=enc.ciphertext,
        iv=enc.iv,
        tag=enc.tag,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    audit.record(db, audit.ADD_ENTRY, user_id=cur.user_id, detail=body.label, ip_address=_client_ip(request))
    return entry


@app.get("/vault/{entry_id}/reveal", response_model=VaultEntryReveal)
def reveal_entry(
    entry_id: int,
    request: Request,
    cur: CurrentUser = Depends(get_current_session),
    db: Session = Depends(get_session),
):
    entry = db.get(VaultEntry, entry_id)
    if entry is None or entry.user_id != cur.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entry not found")

    aad = str(cur.user_id).encode()
    enc = cipher.Encrypted(ciphertext=entry.ciphertext, iv=entry.iv, tag=entry.tag)
    with sensitive_bytes(bytes(cur.vault_key)) as key:
        plaintext = cipher.decrypt(bytes(key), enc, associated_data=aad)

    audit.record(db, audit.REVEAL_ENTRY, user_id=cur.user_id, detail=entry.label, ip_address=_client_ip(request))
    # NOTE: the plaintext necessarily crosses the wire to the client here; the
    # client is responsible for minimising its on-screen lifetime + clipboard
    # auto-clear (Phase 6, handled client-side / in the desktop shell).
    return VaultEntryReveal(
        id=entry.id, label=entry.label, username=entry.username, url=entry.url,
        created_at=entry.created_at, updated_at=entry.updated_at, password=plaintext,
    )


@app.delete("/vault/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_entry(
    entry_id: int,
    request: Request,
    cur: CurrentUser = Depends(get_current_session),
    db: Session = Depends(get_session),
):
    entry = db.get(VaultEntry, entry_id)
    if entry is None or entry.user_id != cur.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entry not found")

    # Secure delete: overwrite the ciphertext bytes in place before removing the
    # row, so the freed pages don't retain recoverable ciphertext.
    blob = bytearray(entry.ciphertext)
    wipe(blob)
    entry.ciphertext = bytes(blob)
    db.add(entry)
    db.commit()

    db.delete(entry)
    db.commit()

    audit.record(db, audit.DELETE_ENTRY, user_id=cur.user_id, detail=entry.label, ip_address=_client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
#  Tools
# --------------------------------------------------------------------------- #
@app.post("/tools/generate", response_model=GenerateResponse)
def tool_generate(body: GenerateRequest):
    opts = GeneratorOptions(
        length=body.length,
        use_upper=body.use_upper,
        use_lower=body.use_lower,
        use_digits=body.use_digits,
        use_symbols=body.use_symbols,
    )
    try:
        return GenerateResponse(password=generate_password(opts))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@app.post("/tools/strength", response_model=StrengthResponse)
def tool_strength(body: StrengthRequest):
    r = analyze(body.password)
    return StrengthResponse(
        rating=r.rating, entropy_bits=r.entropy_bits,
        pool_size=r.pool_size, suggestions=r.suggestions,
    )


@app.post("/tools/leak-check", response_model=LeakResponse)
async def tool_leak_check(body: StrengthRequest):
    try:
        count = await hibp.check_password(body.password)
    except httpx.HTTPError:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Could not reach breach database")
    return LeakResponse(breached=count > 0, count=count)


# --------------------------------------------------------------------------- #
#  Backup / restore
# --------------------------------------------------------------------------- #
@app.get("/vault/export")
def export_vault(
    passphrase: str,
    request: Request,
    cur: CurrentUser = Depends(get_current_session),
    db: Session = Depends(get_session),
):
    if len(passphrase) < 8:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Backup passphrase too short")

    entries = db.scalars(select(VaultEntry).where(VaultEntry.user_id == cur.user_id)).all()
    aad = str(cur.user_id).encode()

    dump: list[dict] = []
    with sensitive_bytes(bytes(cur.vault_key)) as key:
        for e in entries:
            enc = cipher.Encrypted(ciphertext=e.ciphertext, iv=e.iv, tag=e.tag)
            pw = cipher.decrypt(bytes(key), enc, associated_data=aad)
            dump.append({"label": e.label, "username": e.username, "url": e.url, "password": pw})

    blob = backup.export_vault(dump, passphrase)
    audit.record(db, audit.EXPORT_VAULT, user_id=cur.user_id, detail=f"{len(dump)} entries", ip_address=_client_ip(request))
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=vault.sec"},
    )


# --------------------------------------------------------------------------- #
#  Audit dashboard data
# --------------------------------------------------------------------------- #
@app.get("/logs", response_model=list[LogOut])
def get_logs(
    limit: int = 100,
    cur: CurrentUser = Depends(get_current_session),
    db: Session = Depends(get_session),
):
    rows = db.scalars(
        select(ActivityLog)
        .where(ActivityLog.user_id == cur.user_id)
        .order_by(ActivityLog.timestamp.desc())
        .limit(limit)
    ).all()
    return rows


@app.get("/logs/stats")
def get_log_stats(cur: CurrentUser = Depends(get_current_session), db: Session = Depends(get_session)):
    """Aggregate counts for the audit dashboard charts."""
    rows = db.scalars(select(ActivityLog).where(ActivityLog.user_id == cur.user_id)).all()
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.event] = counts.get(r.event, 0) + 1
    return {
        "successful_logins": counts.get(audit.LOGIN, 0),
        "failed_logins": counts.get(audit.LOGIN_FAILED, 0),
        "entries_added": counts.get(audit.ADD_ENTRY, 0),
        "entries_deleted": counts.get(audit.DELETE_ENTRY, 0),
        "reveals": counts.get(audit.REVEAL_ENTRY, 0),
        "lockouts": counts.get(audit.ACCOUNT_LOCKED, 0),
        "by_event": counts,
    }


@app.get("/health")
def health():
    return {"status": "ok", "database": current_backend()}


# --------------------------------------------------------------------------- #
#  Web UI  (the actual user-facing page, served at http://127.0.0.1:8000/)
# --------------------------------------------------------------------------- #
_WEB_INDEX = settings.BASE_DIR / "web" / "index.html"


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(_WEB_INDEX)
