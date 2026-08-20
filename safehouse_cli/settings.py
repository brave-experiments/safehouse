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
import json
import os
import stat
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

import tomli_w

from .config import ConfigError


def config_path() -> Path:
    """Resolve the config path: SAFEHOUSE_CONFIG > existing ~/.safehouse > XDG default."""
    override = os.environ.get("SAFEHOUSE_CONFIG")
    if override:
        return Path(override)
    legacy = Path.home() / ".safehouse" / "config.toml"
    if legacy.exists():                                   # back-compat for existing installs
        return legacy
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "safehouse" / "config.toml"


SECRET_KEYS = ("api_key", "access_token")


def _has_secret(data: dict) -> bool:
    return any(body.get(k) for body in data.values()
               if isinstance(body, dict) for k in SECRET_KEYS)


def assert_private(path: Path) -> None:
    """Raise ConfigError if a secret-bearing file is group/world-accessible."""
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} is group/world-accessible.  Fix with:  chmod 600 {path}")


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
    if _has_secret(data):
        assert_private(path)
    return data


@dataclass(frozen=True)
class Settings:
    """Env+file-resolved credentials and run defaults. CLI flags override these later."""
    anthropic_api_key:       str | None   = None
    duffel_token:            str | None   = None
    liteapi_key:             str | None   = None
    passenger:               dict | None  = None
    max_booking_amount:      str | None   = None   # "<amount> <currency>", e.g. "300 GBP"
    google_token:            str | None   = None
    google_auth:             str          = "static"
    google_token_command:    str | None   = None
    google_credentials_path: Path | None  = None
    demo_recipient:          str | None   = None
    approve:                 str | None   = None
    timeout:                 float | None = None


def load_settings(path: Path | None = None, env: dict | None = None) -> Settings:
    env  = os.environ if env is None else env
    path = path or config_path()            # resolve once (avoids a second legacy-path stat)
    data = load_raw(path)
    google, defaults = data.get("google", {}), data.get("defaults", {})
    env_token = env.get("GOOGLE_ACCESS_TOKEN", "").strip()
    if env_token:                                    # an env token forces static mode
        google_auth, google_token, token_command = "static", env_token, None
    else:
        google_auth   = google.get("auth", "static")
        google_token  = google.get("access_token")
        token_command = google.get("token_command")
    return Settings(
        anthropic_api_key       = env.get("ANTHROPIC_API_KEY", "").strip() or data.get("anthropic", {}).get("api_key"),
        max_booking_amount      = env.get("SAFEHOUSE_MAX_BOOKING", "").strip() or defaults.get("max_booking_amount"),
        passenger               = (data.get("passenger") or None),
        liteapi_key             = env.get("LITEAPI_SANDBOX_KEY", "").strip() or data.get("liteapi", {}).get("api_key"),
        duffel_token            = env.get("DUFFEL_ACCESS_TOKEN", "").strip() or data.get("duffel", {}).get("access_token"),
        google_token            = google_token,
        google_auth             = google_auth,
        google_token_command    = token_command,
        google_credentials_path = path.parent / "google_credentials.json",
        demo_recipient          = env.get("DEMO_RECIPIENT", "").strip() or defaults.get("demo_recipient"),
        approve                 = defaults.get("approve"),
        timeout                 = defaults.get("timeout"),
    )


def _atomic_write(path: Path, write_fn) -> None:
    """Write via tempfile + os.replace; result is 0600, parent dir 0700."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            write_fn(f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def write_config(data: dict, path: Path | None = None) -> None:
    """Atomically write config.toml (0600), dropping empty values/sections (tomli_w rejects None)."""
    path = path or config_path()
    data = {s: kept for s, body in data.items()
            if (kept := {k: v for k, v in body.items() if v is not None and v != ""})}
    _atomic_write(path, lambda f: tomli_w.dump(data, f))


def write_credentials_json(data: dict, path: Path) -> None:
    """Atomically write an authorized-user credentials JSON (0600)."""
    _atomic_write(path, lambda f: f.write(json.dumps(data).encode()))
