"""
Process-injection heuristics (Phase 10: Detect Process Injection).

Credential stealers commonly inject code into a trusted process (e.g. a browser)
to read decrypted passwords from its memory. The classic Windows injection
primitive chain is:

    OpenProcess()  ->  VirtualAllocEx()  ->  WriteProcessMemory()  ->  CreateRemoteThread()

We can't hook those kernel calls from userland Python without a driver/ETW, so
this module uses a well-known *behavioural side-effect* heuristic instead:
memory regions that are simultaneously Writable AND eXecutable (RWX / W^X
violations). Legitimate code is rarely both writable and executable; shellcode
written by an injector almost always is. Flagging RWX private regions is a
standard, evasion-resistant signal used by real EDRs.

Platform notes:
  * Windows: full support via psutil memory maps (RWX detection). The Win32-API
    approach (enumerating remote threads with CreateToolhelp32Snapshot and
    checking thread start addresses against module ranges) is documented in
    `windows_injection_notes()` for reviewers, and requires pywin32.
  * macOS/Linux: RWX-region scanning is attempted where the OS exposes it; the
    module degrades gracefully and is clearly marked as best-effort off-Windows.
"""
from __future__ import annotations

import sys

import psutil

from scanner.logger import Alert, WARNING, emit

IS_WINDOWS = sys.platform == "win32"


def _region_is_rwx(perms: str) -> bool:
    """True if a memory region is both writable and executable."""
    perms = perms.lower()
    if "rwx" in perms:                       # some platforms report 'rwx'
        return True
    return ("w" in perms) and ("x" in perms)  # unix-style 'rwxp' etc.


def scan_process_rwx(pid: int) -> list[dict]:
    """Return RWX regions for a single process (empty if none / inaccessible)."""
    findings: list[dict] = []
    try:
        proc = psutil.Process(pid)
        maps = proc.memory_maps(grouped=False)
    except (psutil.NoSuchProcess, psutil.AccessDenied, NotImplementedError, Exception):
        return findings

    for m in maps:
        perms = getattr(m, "perms", "") or ""
        if _region_is_rwx(perms):
            findings.append({"path": getattr(m, "path", ""), "perms": perms})
    return findings


def scan_once() -> list[Alert]:
    """
    Sweep all accessible processes for RWX memory regions -- a strong indicator
    of injected shellcode.
    """
    alerts: list[Alert] = []
    for proc in psutil.process_iter(["pid", "name"]):
        pid = proc.info["pid"]
        name = proc.info.get("name") or ""
        rwx = scan_process_rwx(pid)
        if rwx:
            alerts.append(emit(Alert(
                source="memory_monitor",
                severity=WARNING,
                message=f"Process '{name}' (pid {pid}) has {len(rwx)} writable+executable "
                        f"memory region(s) -- possible code injection.",
                detail={"regions": rwx[:5]},
            )))
    return alerts


def windows_injection_notes() -> str:
    """
    Reference implementation sketch for the Win32-API detection path.

    Not executed here -- documents how a Windows build would enumerate remote
    threads and flag those whose start address falls outside any loaded module
    (a hallmark of CreateRemoteThread-based injection).
    """
    return (
        "Windows API approach (requires pywin32 / ctypes):\n"
        "  1. CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) to list all threads.\n"
        "  2. For each thread, OpenThread + NtQueryInformationThread to get its\n"
        "     start address.\n"
        "  3. Enumerate the owning process's modules (Module32First/Next).\n"
        "  4. If a thread's start address is NOT inside any module's address\n"
        "     range, the thread was likely created by CreateRemoteThread -> flag.\n"
        "  5. Cross-check for recently VirtualAllocEx'd RWX regions via\n"
        "     VirtualQueryEx (MEM_PRIVATE + PAGE_EXECUTE_READWRITE)."
    )


if __name__ == "__main__":
    if not IS_WINDOWS:
        print("[memory_monitor] Note: full injection detection targets Windows; "
              "running best-effort RWX scan on this platform.")
    scan_once()
