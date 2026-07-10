"""
tests/test_intro.py — the IronFlow intro must not block on non-interactive runs.

Regression: `safehouse --non-interactive "task"` (no --json) used to crash with
EOFError because the intro called input() unconditionally.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tracer


def test_intro_does_not_prompt_when_noninteractive(monkeypatch):
    def _boom(*a):
        raise AssertionError("input() called in a non-interactive intro")
    monkeypatch.setattr("builtins.input", _boom)
    tracer.ironflow_intro(interactive=False)      # must not touch input()


def test_intro_prompts_when_interactive(monkeypatch):
    seen = {}
    monkeypatch.setattr("builtins.input", lambda *a: seen.setdefault("asked", True) or "")
    tracer.ironflow_intro(interactive=True)
    assert seen.get("asked")
