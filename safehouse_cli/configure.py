"""
configure.py — `safehouse configure`: interactive setup of ~/.safehouse/config.toml.

Secrets are prompted with getpass; pressing Enter keeps the current value.
`--show` prints the current file with secrets redacted.
"""
from __future__ import annotations

import argparse
import json
import sys
from getpass import getpass

from . import settings as _settings
from .settings import SECRET_KEYS

_APPROVE_CHOICES = ("interactive", "auto", "deny")
_GOOGLE_AUTH_CHOICES = ("static", "token_command", "oauth")
_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar",
]


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


def _configure_oauth(config_path) -> int:
    """Write ~/.safehouse/google_credentials.json (authorized-user format). Returns exit code."""
    creds_path = config_path.parent / "google_credentials.json"
    existing = json.loads(creds_path.read_text()) if creds_path.exists() else {}
    print("\n  OAuth refresh credentials — mint a refresh token at")
    print("  https://developers.google.com/oauthplayground (use your own OAuth client).")
    refresh       = _prompt("Refresh token", existing.get("refresh_token"), secret=True)
    client_id     = _prompt("OAuth client_id", existing.get("client_id"))
    client_secret = _prompt("OAuth client_secret", existing.get("client_secret"), secret=True)
    if not (refresh and client_id and client_secret):
        print("error: oauth needs refresh_token, client_id, and client_secret", file=sys.stderr)
        return 2
    _settings.write_credentials_json({
        "type": "authorized_user",
        "refresh_token": refresh,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": _OAUTH_SCOPES,
    }, creds_path)
    print(f"  Wrote {creds_path}")
    return 0


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

    print(f"\n  Google auth mode {'/'.join(_GOOGLE_AUTH_CHOICES)}:")
    print("    static        — paste an access token (expires ~1h)")
    print("    token_command — a command that prints a fresh token to stdout")
    print("    oauth         — refresh-token flow (needs: pip install 'safehouse[google]')")
    mode = _prompt("Google auth mode", google.get("auth") or "static")
    if mode not in _GOOGLE_AUTH_CHOICES:
        print(f"error: auth must be one of {_GOOGLE_AUTH_CHOICES}", file=sys.stderr)
        return 2
    google["auth"] = mode
    google["access_token"] = google["token_command"] = None
    if mode == "static":
        print("  Mint a token at https://developers.google.com/oauthplayground")
        google["access_token"] = _prompt("Google access token", google.get("access_token"), secret=True)
    elif mode == "token_command":
        google["token_command"] = _prompt("Token command", google.get("token_command"))
    else:
        if (rc := _configure_oauth(path)):
            return rc

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
