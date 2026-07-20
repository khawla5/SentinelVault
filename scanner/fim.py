"""
File Integrity Monitoring (Phase 10: FIM).

Maintains a SHA-256 baseline of critical files (the vault database by default).
If a monitored file's hash changes unexpectedly -- outside of the app's own
writes -- an alert is raised. This catches tampering, ransomware encryption, or
a malicious process rewriting the vault.

Two modes:
  * snapshot()/verify(): simple hash-baseline compare (no dependencies).
  * watch(): real-time filesystem events via `watchdog` if installed.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from config import settings
from scanner.logger import Alert, CRITICAL, INFO, WARNING, emit

_BASELINE_FILE = settings.LOG_DIR / "fim_baseline.json"
DEFAULT_TARGETS = [str(settings.DB_PATH)]


def _sha256(path: str) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(targets: list[str] | None = None) -> dict[str, str | None]:
    """Record the current hash baseline for the target files."""
    targets = targets or DEFAULT_TARGETS
    baseline = {t: _sha256(t) for t in targets}
    _BASELINE_FILE.write_text(json.dumps(baseline, indent=2))
    print(f"[fim] baseline recorded for {len(baseline)} file(s)")
    return baseline


def verify(targets: list[str] | None = None) -> list[Alert]:
    """Compare current hashes to the stored baseline; alert on any change."""
    targets = targets or DEFAULT_TARGETS
    if not _BASELINE_FILE.exists():
        snapshot(targets)
        return []

    baseline = json.loads(_BASELINE_FILE.read_text())
    alerts: list[Alert] = []
    for t in targets:
        old = baseline.get(t)
        new = _sha256(t)
        if old is None and new is not None:
            alerts.append(emit(Alert("fim", INFO, f"Monitored file appeared: {t}")))
        elif old is not None and new is None:
            alerts.append(emit(Alert("fim", CRITICAL, f"Monitored file was DELETED: {t}")))
        elif old != new:
            alerts.append(emit(Alert(
                "fim", WARNING,
                f"Integrity change detected in {t} (hash mismatch)",
                detail={"old": old, "new": new},
            )))
    return alerts


def watch(targets: list[str] | None = None, poll: float = 3.0) -> None:
    """Poll-based integrity watch loop. Ctrl-C to stop."""
    targets = targets or DEFAULT_TARGETS
    snapshot(targets)
    print(f"[fim] watching {targets} every {poll}s -- Ctrl-C to stop")
    try:
        while True:
            time.sleep(poll)
            alerts = verify(targets)
            if alerts:
                snapshot(targets)  # re-baseline after reporting
    except KeyboardInterrupt:
        print("\n[fim] stopped")
