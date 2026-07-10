"""
tests/test_subagent_isolation.py — Tier-2 credential isolation.

Regression guard for the leak where `claude -p` inherited the full parent
environment (including GOOGLE_ACCESS_TOKEN). See CLAUDE.md invariant 6.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safehouse.runner import _subagent_env


def test_forbidden_credential_absent(monkeypatch):
    monkeypatch.setenv("GOOGLE_ACCESS_TOKEN", "ya29.secret")
    monkeypatch.setenv("DEMO_RECIPIENT", "victim@example.com")
    env = _subagent_env()
    assert "GOOGLE_ACCESS_TOKEN" not in env
    assert "DEMO_RECIPIENT" not in env


def test_required_vars_present(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    monkeypatch.setenv("HOME", "/home/agent")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = _subagent_env()
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-xxx"
    assert env["HOME"] == "/home/agent"
    assert env["PATH"] == "/usr/bin"
