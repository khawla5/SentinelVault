"""
Malware / threat-detection scanner package (Phase 10).

This is a DEFENSIVE toolkit. Every module observes the local system for signs
that credential-stealing malware may be present and raises alerts -- it never
performs any offensive action. Modules:

    rules             -> known-bad process signatures + severity mapping
    process_monitor   -> flags suspicious running processes (keyloggers, stealers)
    clipboard_monitor -> detects clipboard-hijacking after a password copy
    fim               -> file-integrity monitoring for the vault DB
    memory_monitor    -> Windows process-injection API-usage heuristics
    logger            -> unified threat-alert logging
"""
