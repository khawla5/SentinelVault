"""
Process monitor (Phase 10: Detect Keyloggers / Stealers).

Enumerates running processes with psutil and classifies each name against the
signature rules. Cross-platform. Can run a one-shot scan or a continuous watch
loop that only alerts on newly-seen suspicious processes (avoids alert spam).
"""
from __future__ import annotations

import time
from collections.abc import Iterator

import psutil

from scanner import rules
from scanner.logger import Alert, emit


def iter_processes() -> Iterator[dict]:
    """Yield {pid, name, exe} for every accessible process."""
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info
            yield {"pid": info["pid"], "name": info.get("name") or "", "exe": info.get("exe") or ""}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def scan_once() -> list[Alert]:
    """Single pass over running processes; returns any alerts raised."""
    alerts: list[Alert] = []
    for p in iter_processes():
        verdict = rules.classify(p["name"])
        if verdict is None:
            continue
        severity, reason = verdict
        alerts.append(
            emit(Alert(
                source="process_monitor",
                severity=severity,
                message=reason,
                detail={"pid": p["pid"], "exe": p["exe"]},
            ))
        )
    return alerts


def watch(interval: float = 5.0) -> None:
    """
    Continuous monitoring loop. Alerts only when a suspicious PID first appears.
    Ctrl-C to stop.
    """
    seen_suspicious: set[int] = set()
    print(f"[process_monitor] watching every {interval}s -- Ctrl-C to stop")
    try:
        while True:
            current_bad: set[int] = set()
            for p in iter_processes():
                verdict = rules.classify(p["name"])
                if verdict is None:
                    continue
                current_bad.add(p["pid"])
                if p["pid"] not in seen_suspicious:
                    severity, reason = verdict
                    emit(Alert(
                        source="process_monitor",
                        severity=severity,
                        message=reason,
                        detail={"pid": p["pid"], "exe": p["exe"]},
                    ))
            seen_suspicious = current_bad
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[process_monitor] stopped")


if __name__ == "__main__":
    scan_once()
