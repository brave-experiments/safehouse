"""
tests/test_settings.py — config-file loading, precedence, and subcommand routing.

Covers settings.py (load/resolve/write, permission + malformed-TOML errors) and
the RunConfig precedence CLI flag > env var > config file, plus split_command.
No network, no API keys.
"""
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import tomli_w

from safehouse_cli import settings as S
from safehouse_cli.config import ConfigError, RunConfig, split_command


def _write(path, data, mode=0o600):
    with open(path, "wb") as f:
        tomli_w.dump(data, f)
    os.chmod(path, mode)


# ── settings loading ──────────────────────────────────────────────────

def test_absent_file_is_empty(tmp_path):
    s = S.load_settings(path=tmp_path / "nope.toml", env={})
    assert s.anthropic_api_key is None
    assert s.google_token is None
    assert s.demo_recipient is None
    assert s.google_auth == "static"


def test_malformed_toml_raises(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("this is = not = valid")
    with pytest.raises(ConfigError):
        S.load_raw(p)


def test_secret_file_lax_perms_raises(tmp_path):
    p = tmp_path / "config.toml"
    _write(p, {"anthropic": {"api_key": "sk-secret"}}, mode=0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        S.load_raw(p)


def test_no_secret_lax_perms_ok(tmp_path):
    p = tmp_path / "config.toml"
    _write(p, {"defaults": {"demo_recipient": "x@y.com"}}, mode=0o644)
    assert S.load_raw(p)["defaults"]["demo_recipient"] == "x@y.com"


def test_env_overrides_file(tmp_path):
    p = tmp_path / "config.toml"
    _write(p, {"anthropic": {"api_key": "file-key"},
               "google": {"access_token": "file-token"}})
    s = S.load_settings(path=p, env={"ANTHROPIC_API_KEY": "env-key",
                                     "GOOGLE_ACCESS_TOKEN": "env-token"})
    assert s.anthropic_api_key == "env-key"
    assert s.google_token == "env-token"


def test_file_used_when_env_absent(tmp_path):
    p = tmp_path / "config.toml"
    _write(p, {"anthropic": {"api_key": "file-key"},
               "google": {"access_token": "file-token"},
               "defaults": {"demo_recipient": "d@e.com", "timeout": 42}})
    s = S.load_settings(path=p, env={})
    assert s.anthropic_api_key == "file-key"
    assert s.google_token == "file-token"
    assert s.demo_recipient == "d@e.com"
    assert s.timeout == 42


def test_write_config_is_atomic_and_0600(tmp_path):
    p = tmp_path / "sub" / "config.toml"
    S.write_config({"anthropic": {"api_key": "k"}}, p)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert S.load_raw(p)["anthropic"]["api_key"] == "k"


# ── subcommand routing ────────────────────────────────────────────────

def test_split_command_bare_flags_imply_run():
    assert split_command(["--task", "x"]) == ("run", ["--task", "x"])


def test_split_command_explicit():
    assert split_command(["run", "--task", "x"]) == ("run", ["--task", "x"])
    assert split_command(["configure", "--show"]) == ("configure", ["--show"])


def test_split_command_empty():
    assert split_command([]) == ("run", [])


# ── RunConfig precedence (flag > env > file) ──────────────────────────

def _settings_from(tmp_path, data, env=None):
    p = tmp_path / "config.toml"
    _write(p, data)
    return S.load_settings(path=p, env=env or {})


def test_runconfig_takes_file_defaults(tmp_path):
    settings = _settings_from(tmp_path, {
        "anthropic": {"api_key": "file-key"},
        "google": {"access_token": "file-token"},
        "defaults": {"demo_recipient": "file@r.com", "approve": "auto", "timeout": 12},
    })
    cfg = RunConfig.from_args(["--task", "t", "--non-interactive"], settings=settings)
    assert cfg.recipient == "file@r.com"
    assert cfg.approval.value == "auto"
    assert cfg.timeout_s == 12
    assert cfg.anthropic_api_key == "file-key"
    assert cfg.google_token == "file-token"


def test_runconfig_flag_beats_file(tmp_path):
    settings = _settings_from(tmp_path, {"defaults": {"demo_recipient": "file@r.com",
                                                      "approve": "auto", "timeout": 12}})
    cfg = RunConfig.from_args(
        ["--task", "t", "--recipient", "cli@r.com", "--approve", "deny", "--timeout", "99"],
        settings=settings)
    assert cfg.recipient == "cli@r.com"
    assert cfg.approval.value == "deny"
    assert cfg.timeout_s == 99


def test_runconfig_invalid_file_approve_raises(tmp_path):
    settings = _settings_from(tmp_path, {"defaults": {"approve": "bogus"}})
    with pytest.raises(ConfigError, match="invalid approve"):
        RunConfig.from_args(["--task", "t", "--non-interactive"], settings=settings)


# ── PR-G: task resolution (positional / --task / stdin) ───────────────

def test_positional_task():
    assert RunConfig.from_args(["do the thing"], settings=S.Settings()).task == "do the thing"


def test_flag_task_still_works():
    assert RunConfig.from_args(["--task", "x"], settings=S.Settings()).task == "x"


def test_both_positional_and_flag_rejected():
    with pytest.raises(ConfigError, match="not both"):
        RunConfig.from_args(["a", "--task", "b"], settings=S.Settings())


def test_no_task_rejected():
    with pytest.raises(ConfigError, match="provide a task"):
        RunConfig.from_args([], settings=S.Settings())


def test_task_from_stdin(monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("task from stdin\n"))
    cfg = RunConfig.from_args(["-"], settings=S.Settings())
    assert cfg.task == "task from stdin"      # trailing newline stripped
    assert cfg.interactive is False           # stdin consumed → non-interactive


def test_stdin_dash_rejected_on_tty(monkeypatch):
    import io

    class _TTY(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", _TTY("x"))
    with pytest.raises(ConfigError, match="stdin is a terminal"):
        RunConfig.from_args(["-"], settings=S.Settings())


def test_version_string():
    from safehouse_cli.config import _version_string
    assert _version_string().startswith("safehouse 0.1.0")


# ── PR-G: XDG config-path resolution ──────────────────────────────────

def test_config_path_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEHOUSE_CONFIG", str(tmp_path / "c.toml"))
    assert S.config_path() == tmp_path / "c.toml"


def test_config_path_legacy_when_present(tmp_path, monkeypatch):
    monkeypatch.delenv("SAFEHOUSE_CONFIG", raising=False)
    home = tmp_path / "home"
    (home / ".safehouse").mkdir(parents=True)
    legacy = home / ".safehouse" / "config.toml"
    legacy.write_text("")
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    assert S.config_path() == legacy


def test_config_path_xdg_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SAFEHOUSE_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    assert S.config_path() == home / ".config" / "safehouse" / "config.toml"


def test_config_path_xdg_env(tmp_path, monkeypatch):
    monkeypatch.delenv("SAFEHOUSE_CONFIG", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert S.config_path() == tmp_path / "xdg" / "safehouse" / "config.toml"
