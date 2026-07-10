"""
configure.py — `safehouse configure`: interactive setup of ~/.safehouse/config.toml.

Secrets are prompted with getpass; pressing Enter keeps the current value.
`--show` prints the current file with secrets redacted.
"""
from __future__ import annotations

import argparse
import sys
from getpass import getpass

from . import settings as _settings
from .settings import SECRET_KEYS

_APPROVE_CHOICES = ("interactive", "auto", "deny")


def _prompt(label: str, current, *, secret: bool = False) -> str | None:
    reader = getpass if secret else input
    val = reader(f"  {label} [{'set' if current else 'unset'}] (Enter to keep): ").strip()
    return val or (str(current) if current is not None else None)


def _show(data: dict, path) -> None:
    if not data:
        print(f"No config at {path}")
        return
    print(f"# {path}")
    for section, body in data.items():
        print(f"[{section}]")
        for k, v in body.items():
            print(f"  {k} = {'***' if k in SECRET_KEYS else repr(v)}")


def run_configure(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="safehouse configure",
        description="Set up ~/.safehouse/config.toml (Anthropic key, Google token, defaults).",
    )
    p.add_argument("--show", action="store_true",
                   help="print current settings with secrets redacted")
    args = p.parse_args(argv)

    path = _settings.config_path()
    data = _settings.load_raw(path)

    if args.show:
        _show(data, path)
        return 0

    anthropic = data.get("anthropic", {})
    google    = data.get("google", {})
    defaults  = data.get("defaults", {})

    print(f"Configuring {path}  (Enter keeps the current value)\n")
    anthropic["api_key"] = _prompt("Anthropic API key", anthropic.get("api_key"), secret=True)
    print("\n  Google access token — static, expires ~1h; mint at")
    print("  https://developers.google.com/oauthplayground\n")
    google["access_token"] = _prompt("Google access token", google.get("access_token"), secret=True)
    print()
    defaults["demo_recipient"] = _prompt("Default recipient email", defaults.get("demo_recipient"))

    approve = _prompt(f"Default approval {'/'.join(_APPROVE_CHOICES)}", defaults.get("approve"))
    if approve and approve not in _APPROVE_CHOICES:
        print(f"error: approve must be one of {_APPROVE_CHOICES}", file=sys.stderr)
        return 2
    defaults["approve"] = approve

    timeout = _prompt("Default timeout seconds", defaults.get("timeout"))
    if timeout:
        try:
            defaults["timeout"] = float(timeout)
        except ValueError:
            print("error: timeout must be a number", file=sys.stderr)
            return 2
    else:
        defaults["timeout"] = None

    _settings.write_config(
        {"anthropic": anthropic, "google": google, "defaults": defaults}, path)
    print(f"\nSaved {path}")
    return 0
