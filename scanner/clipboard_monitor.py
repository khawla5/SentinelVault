"""
Clipboard-hijacking detector (Phase 10 + Phase 6).

Two related jobs:

1. auto_clear(seconds): after the app copies a password, clear the clipboard
   after a timeout (Phase 6 clipboard protection).

2. HijackDetector: infostealers/"clippers" watch the clipboard and instantly
   replace copied data (e.g. swapping a copied crypto address, or scraping a
   password). If the clipboard content changes within a suspiciously short
   window *after we copied something*, that's a red flag -> alert.

Clipboard access is via the optional `pyperclip` package if present; otherwise
platform fallbacks (pbpaste/pbcopy on macOS, `clip`/powershell on Windows,
xclip on Linux) are used. If none are available the module degrades gracefully.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time

from scanner.logger import Alert, WARNING, emit


def _get_clipboard() -> str | None:
    try:
        import pyperclip  # type: ignore
        return pyperclip.paste()
    except Exception:
        pass
    try:
        if sys.platform == "darwin":
            return subprocess.check_output(["pbpaste"], text=True)
        if sys.platform.startswith("linux") and shutil.which("xclip"):
            return subprocess.check_output(["xclip", "-selection", "clipboard", "-o"], text=True)
        if sys.platform == "win32":
            return subprocess.check_output(
                ["powershell", "-command", "Get-Clipboard"], text=True
            ).rstrip("\r\n")
    except Exception:
        return None
    return None


def _set_clipboard(text: str) -> bool:
    try:
        import pyperclip  # type: ignore
        pyperclip.copy(text)
        return True
    except Exception:
        pass
    try:
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text, text=True, check=True)
            return True
        if sys.platform.startswith("linux") and shutil.which("xclip"):
            subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, check=True)
            return True
        if sys.platform == "win32":
            subprocess.run(["clip"], input=text, text=True, check=True)
            return True
    except Exception:
        return False
    return False


def auto_clear(seconds: int = 20) -> None:
    """Blank the clipboard after `seconds` (Phase 6). Runs in a daemon thread."""
    def _job():
        time.sleep(seconds)
        _set_clipboard("")
        print(f"[clipboard_monitor] clipboard cleared after {seconds}s")

    threading.Thread(target=_job, daemon=True).start()


class HijackDetector:
    """
    Watches for the clipboard being overwritten immediately after a copy.

    Usage:
        det = HijackDetector(reaction_window=2.0)
        det.note_copy(password)     # right after the app copies a secret
        ... detector polls ...
    """

    def __init__(self, reaction_window: float = 2.0, poll: float = 0.25):
        self.reaction_window = reaction_window
        self.poll = poll
        self._expected: str | None = None
        self._copied_at: float = 0.0
        self._stop = threading.Event()

    def note_copy(self, value: str) -> None:
        self._expected = value
        self._copied_at = time.monotonic()

    def _check(self) -> Alert | None:
        if self._expected is None:
            return None
        elapsed = time.monotonic() - self._copied_at
        if elapsed > self.reaction_window:
            self._expected = None  # window passed; stop watching this copy
            return None
        current = _get_clipboard()
        if current is not None and current != self._expected and current != "":
            alert = emit(Alert(
                source="clipboard_monitor",
                severity=WARNING,
                message="Clipboard was modified within the reaction window after a "
                        "password copy -- possible clipboard hijacker (clipper).",
                detail={"elapsed_s": round(elapsed, 3)},
            ))
            self._expected = None
            return alert
        return None

    def watch(self) -> None:
        while not self._stop.is_set():
            self._check()
            time.sleep(self.poll)

    def stop(self) -> None:
        self._stop.set()
