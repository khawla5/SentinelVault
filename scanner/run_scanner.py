"""
Scanner orchestrator -- run all detection modules in one pass or continuously.

Usage:
    python -m scanner.run_scanner            # single full scan
    python -m scanner.run_scanner --watch    # continuous monitoring
"""
from __future__ import annotations

import argparse
import time

from scanner import fim, memory_monitor, process_monitor


def full_scan() -> int:
    """Run every one-shot detector; return the number of alerts raised."""
    print("=== SecureVault threat scan ===")
    alerts = []
    print("\n[1/3] Process signatures...")
    alerts += process_monitor.scan_once()
    print("\n[2/3] File integrity...")
    alerts += fim.verify()
    print("\n[3/3] Memory / injection heuristics...")
    alerts += memory_monitor.scan_once()

    print(f"\n=== Scan complete: {len(alerts)} alert(s) ===")
    if not alerts:
        print("No suspicious activity detected.")
    return len(alerts)


def watch(interval: float = 5.0) -> None:
    fim.snapshot()
    print(f"Continuous monitoring every {interval}s -- Ctrl-C to stop")
    try:
        while True:
            process_monitor.scan_once()
            fim.verify()
            memory_monitor.scan_once()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureVault threat scanner")
    parser.add_argument("--watch", action="store_true", help="run continuously")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if args.watch:
        watch(args.interval)
    else:
        full_scan()
