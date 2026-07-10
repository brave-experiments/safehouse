"""
tests/test_configure.py — `safehouse configure` behavior.

FIX-1 regression: pressing Enter at every prompt on a second pass must not
change the stored config (keep-current must not wipe secrets).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safehouse_cli import configure


def _answer(monkeypatch, getpass_vals, input_vals):
    g, i = iter(getpass_vals), iter(input_vals)
    monkeypatch.setattr(configure, "getpass", lambda *a: next(g))
    monkeypatch.setattr("builtins.input", lambda *a: next(i))


def test_configure_idempotent_on_keep(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    monkeypatch.setenv("SAFEHOUSE_CONFIG", str(cfg))

    # Pass 1: set anthropic key + static token + recipient; blank approve/timeout.
    # getpass order: anthropic key, google access token.  input order: mode, recipient, approve, timeout.
    _answer(monkeypatch, ["sk-ant-1", "ya29.tok"], ["static", "me@x.com", "", ""])
    assert configure.run_configure([]) == 0
    first = cfg.read_bytes()

    # Pass 2: Enter to keep everything.
    _answer(monkeypatch, ["", ""], ["", "", "", ""])
    assert configure.run_configure([]) == 0

    assert cfg.read_bytes() == first          # keep-current preserved the token (FIX-1)


def test_configure_preserves_unknown_sections(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[custom]\nkeep = "me"\n')
    cfg.chmod(0o600)
    monkeypatch.setenv("SAFEHOUSE_CONFIG", str(cfg))

    _answer(monkeypatch, ["", ""], ["static", "", "", ""])
    assert configure.run_configure([]) == 0
    assert 'keep = "me"' in cfg.read_text()   # hand-added section survived (FIX-6a)
