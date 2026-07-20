"""
Activity logging (Phase 9).

Writes security events both to the database (for the audit dashboard) and to a
JSON-lines file on disk (tamper-evident-ish append-only trail that survives a DB
reset). Records timestamp, event type, IP and machine name.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from config import settings
from database.models import ActivityLog

# Event constants.
LOGIN = "LOGIN"
LOGIN_FAILED = "LOGIN_FAILED"
LOGOUT = "LOGOUT"
REGISTER = "REGISTER"
ADD_ENTRY = "ADD_ENTRY"
DELETE_ENTRY = "DELETE_ENTRY"
REVEAL_ENTRY = "REVEAL_ENTRY"
EXPORT_VAULT = "EXPORT_VAULT"
ACCOUNT_LOCKED = "ACCOUNT_LOCKED"

_LOG_FILE = settings.LOG_DIR / "activity.jsonl"


def _machine_name() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def record(
    db: Session,
    event: str,
    *,
    user_id: int | None = None,
    detail: str = "",
    ip_address: str = "",
) -> None:
    machine = _machine_name()
    entry = ActivityLog(
        user_id=user_id,
        event=event,
        detail=detail,
        ip_address=ip_address,
        machine_name=machine,
    )
    db.add(entry)
    db.commit()

    line = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "user_id": user_id,
        "detail": detail,
        "ip": ip_address,
        "machine": machine,
    }
    with open(_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
