"""
Unified threat-alert logging for the scanner.

Alerts are printed to the console and appended to logs/threats.jsonl so the
audit dashboard can chart them alongside the app's own activity log.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

# Severity levels used across the scanner.
INFO = "INFO"
WARNING = "WARNING"
CRITICAL = "CRITICAL"

_LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "threats.jsonl"


@dataclass
class Alert:
    source: str          # e.g. "process_monitor"
    severity: str        # INFO | WARNING | CRITICAL
    message: str
    detail: dict | None = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def emit(alert: Alert) -> Alert:
    """Log an alert to console + file and return it (for programmatic use)."""
    icon = {"INFO": "•", "WARNING": "⚠", "CRITICAL": "⛔"}.get(alert.severity, "•")
    print(f"[{alert.severity}] {icon} ({alert.source}) {alert.message}")

    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(alert)) + "\n")
    return alert
