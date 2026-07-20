"""
Detection rules: known-bad process signatures and severity mapping.

This is a heuristic, name-based signature list -- the same idea a lightweight
YARA-style rule or an EDR allowlist uses as a first pass. Real infostealers
often rename their binaries, so name matching is only ONE weak signal; the
memory_monitor (injection heuristics) and fim (integrity) modules add
behavioural signals that are harder to evade.

Severity:
    CRITICAL -> named infostealer / RAT families known to target credentials
    WARNING  -> generic suspicious tooling (keyloggers, injectors, sniffers)
    INFO     -> benign but security-relevant (e.g. task manager)
"""
from __future__ import annotations

from scanner.logger import CRITICAL, INFO, WARNING

# Known infostealer / credential-theft malware family binaries (lowercased).
CRITICAL_NAMES = {
    "redline.exe", "lumma.exe", "raccoon.exe", "vidar.exe", "azorult.exe",
    "mars.exe", "meta.exe", "rhadamanthys.exe", "stealc.exe", "aurora.exe",
    "agenttesla.exe", "formbook.exe",
}

# Generic malicious-tooling keywords -- matched as substrings.
WARNING_KEYWORDS = (
    "keylog", "stealer", "injector", "inject", "hijack", "clipper",
    "sniffer", "grabber", "rat", "backdoor",
)

# Benign processes we explicitly recognise so we don't cry wolf.
KNOWN_GOOD = {
    "taskmgr.exe", "explorer.exe", "python", "python.exe", "code", "code.exe",
    "chrome.exe", "firefox.exe", "safari", "finder", "systemsettings",
}


def classify(process_name: str) -> tuple[str, str] | None:
    """
    Classify a process name.

    Returns (severity, reason) if suspicious, or None if benign/unknown.
    """
    name = process_name.strip().lower()
    if not name:
        return None

    if name in KNOWN_GOOD:
        return None

    if name in CRITICAL_NAMES:
        return CRITICAL, f"Matches known infostealer signature: {process_name}"

    for kw in WARNING_KEYWORDS:
        if kw in name:
            return WARNING, f"Process name contains suspicious keyword '{kw}': {process_name}"

    return None
