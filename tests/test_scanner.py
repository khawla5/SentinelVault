"""Tests for the scanner detection rules and backup roundtrip."""
from scanner import rules
from scanner.logger import CRITICAL, WARNING


def test_known_infostealer_is_critical():
    sev, reason = rules.classify("RedLine.exe")
    assert sev == CRITICAL
    assert "infostealer" in reason.lower()


def test_lumma_and_raccoon_critical():
    assert rules.classify("Lumma.exe")[0] == CRITICAL
    assert rules.classify("Raccoon.exe")[0] == CRITICAL


def test_keyword_match_is_warning():
    sev, _ = rules.classify("keylogger.exe")
    assert sev == WARNING
    assert rules.classify("stealer.exe")[0] == WARNING
    assert rules.classify("injector.exe")[0] == WARNING


def test_known_good_is_none():
    assert rules.classify("taskmgr.exe") is None
    assert rules.classify("explorer.exe") is None
    assert rules.classify("chrome.exe") is None


def test_unknown_process_is_none():
    assert rules.classify("myrandomapp.exe") is None
    assert rules.classify("") is None


def test_case_insensitive():
    assert rules.classify("REDLINE.EXE")[0] == CRITICAL
    assert rules.classify("KeyLog_svc.exe")[0] == WARNING
