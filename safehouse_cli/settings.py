"""
settings.py — ~/.safehouse/config.toml loading and precedence resolution.

Resolves credentials and run defaults with precedence (highest first):
CLI flag > environment variable > config file. CLI flags are applied later in
RunConfig; this module resolves the env-vs-file layers into a frozen Settings.

The file is the persistent secret store; env vars bypass it entirely, so
containers/CI that only export env vars are unaffected (and never trigger the
permission check).
"""
from __future__ import annotations

import contextlib
import os
import stat
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

import tomli_w

from .config import ConfigError


def config_path() -> Path:
    """Config file path — SAFEHOUSE_CONFIG override, else ~/.safehouse/config.toml."""
    override = os.environ.get("SAFEHOUSE_CONFIG")
    return Path(override) if override else Path.home() / ".safehouse" / "config.toml"


SECRET_KEYS = ("api_key", "access_token")


def _has_secret(data: dict) -> bool:
    return any(body.get(k) for body in data.values()
               if isinstance(body, dict) for k in SECRET_KEYS)


def load_raw(path: Path | None = None) -> dict:
    """Parse the config file, or {} if absent. Raises ConfigError on bad TOML or lax perms."""
    path = path or config_path()
    if not path.exists():
        return {}
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    if _has_secret(data) and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} holds secrets but is group/world-accessible.  "
                          f"Fix with:  chmod 600 {path}")
    return data


@dataclass(frozen=True)
class Settings:
    """Env+file-resolved credentials and run defaults. CLI flags override these later."""
    anthropic_api_key: str | None   = None
    google_token:      str | None   = None
    demo_recipient:    str | None   = None
    approve:           str | None   = None
    timeout:           float | None = None


def load_settings(path: Path | None = None, env: dict | None = None) -> Settings:
    env  = os.environ if env is None else env
    data = load_raw(path)
    google, defaults = data.get("google", {}), data.get("defaults", {})
    return Settings(
        anthropic_api_key = env.get("ANTHROPIC_API_KEY", "").strip() or data.get("anthropic", {}).get("api_key"),
        google_token      = env.get("GOOGLE_ACCESS_TOKEN", "").strip() or google.get("access_token"),
        demo_recipient    = env.get("DEMO_RECIPIENT", "").strip() or defaults.get("demo_recipient"),
        approve           = defaults.get("approve"),
        timeout           = defaults.get("timeout"),
    )


def write_config(data: dict, path: Path | None = None) -> None:
    """Atomically write config (file 0600, dir 0700)."""
    path = path or config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # tomli_w cannot serialize None; drop empty values and empty sections.
    data = {s: kept for s, body in data.items()
            if (kept := {k: v for k, v in body.items() if v is not None and v != ""})}
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            tomli_w.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
