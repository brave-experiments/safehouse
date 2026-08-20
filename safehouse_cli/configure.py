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

from safehouse.runner import _GITHUB_INTEGRITY_LEVELS

from . import settings as _settings
from .config import _version_string
from .settings import SECRET_KEYS

_APPROVE_CHOICES = ("interactive", "auto", "deny")
_GOOGLE_AUTH_CHOICES = ("static", "token_command", "oauth")
_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar",
]


def _prompt(label: str, current, *, secret: bool = False) -> str | None:
    # Secrets show set/unset; non-secrets show the actual value so the user
    # can see what pressing Enter will keep.
    shown = ("set" if current else "unset") if secret else (current if current not in (None, "") else "unset")
    reader = getpass if secret else input
    val = reader(f"  {label} [{shown}] (Enter to keep): ").strip()
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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Set up the safehouse config file (Anthropic key, Google token, defaults).",
        epilog="Note: hand-added TOML comments are not preserved when the file is saved.",
    )
    p.add_argument("--version", "-V", action="version", version=_version_string())
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
    # Capture current values BEFORE clearing, so "Enter to keep" preserves them;
    # clearing still drops the other modes' stale fields.
    cur_token, cur_cmd = google.get("access_token"), google.get("token_command")
    google["auth"] = mode
    google["access_token"] = google["token_command"] = None
    if mode == "static":
        print("  Mint a token at https://developers.google.com/oauthplayground")
        google["access_token"] = _prompt("Google access token", cur_token, secret=True)
    elif mode == "token_command":
        google["token_command"] = _prompt("Token command", cur_cmd)
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

    # ── Duffel travel booking (flights; hotels via Stays) ──────────────
    print("\n  Duffel travel API — flight/hotel search + booking (paid from your Duffel balance):")
    print("    Create a token at Duffel → Developers → Access tokens (test mode = duffel_test_...)")
    duffel = data.get("duffel", {})
    duffel["access_token"] = _prompt("Duffel access token", duffel.get("access_token"), secret=True)

    print("\n  LiteAPI — hotel search + booking (sign up free at liteapi.travel → dashboard → API Keys):")
    liteapi = data.get("liteapi", {})
    liteapi["api_key"] = _prompt("LiteAPI key (sandbox sand_… or production)", liteapi.get("api_key"), secret=True)

    defaults["max_booking_amount"] = _prompt(
        "Max booking amount — hard spend ceiling for book_* tools, "
        "as '<amount> <currency>' (e.g. '300 GBP')",
        defaults.get("max_booking_amount"))

    # Update into the loaded dict so any hand-added sections/keys are preserved.
    # ── GitHub issues/PRs ─────────────────────────────────────────────
    print("\n  GitHub — read issues/PRs + post comments:")
    print("    Create a PAT at https://github.com/settings/tokens")
    print("    Scopes: public_repo for public repositories, repo to include private ones")
    github = data.get("github", {})
    github["access_token"] = _prompt("GitHub token", github.get("access_token"), secret=True)

    print("\n  Integrity gate — issue/PR text is attacker-reachable, so each item is")
    print("  kept only if its derived integrity ranks at or above this floor.")
    print("  Integrity comes from the author's standing AND whether the content")
    print("  was merged to the default branch (merged outranks any author).")
    print(f"    {' > '.join(_GITHUB_INTEGRITY_LEVELS)}")
    print("    'approved' is a reasonable default; leave unset to DISABLE the gate")
    print("    (unset means anonymous comments reach the drafting model unfiltered).")
    floor = _prompt("Minimum GitHub integrity", defaults.get("min_github_integrity"))
    if floor and floor not in _GITHUB_INTEGRITY_LEVELS:
        print(f"error: min_github_integrity must be one of {_GITHUB_INTEGRITY_LEVELS}",
              file=sys.stderr)
        return 2
    defaults["min_github_integrity"] = floor

    print("\n  Passenger profile — used for flight booking; stays on your machine, never sent to the LLM:")
    passenger = data.get("passenger", {})
    for field, label in (
        ("title",        "Title (mr/ms/mrs/miss)"),
        ("given_name",   "Given name"),
        ("family_name",  "Family name"),
        ("born_on",      "Date of birth (YYYY-MM-DD)"),
        ("gender",       "Gender (m/f)"),
        ("email",        "Email"),
        ("phone_number", "Phone (+E.164, e.g. +442080160509)"),
    ):
        passenger[field] = _prompt(label, passenger.get(field))
    passenger = {k: v for k, v in passenger.items() if v}   # drop unset → clean [passenger]

    # Update into the loaded dict so any hand-added sections/keys are preserved.
    data["anthropic"], data["google"], data["defaults"] = anthropic, google, defaults
    data["duffel"], data["liteapi"], data["passenger"] = duffel, liteapi, passenger
    data["github"] = github
    _settings.write_config(data, path)
    print(f"\nSaved {path}")
    return 0
