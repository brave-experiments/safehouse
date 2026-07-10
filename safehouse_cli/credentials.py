"""
credentials.py — Google access-token providers, selected by [google].auth.

The provider is built once at the CLI boundary and produces a fresh token at
run time (never at import). Tokens are never logged. See CLAUDE.md
"Credential isolation".
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Protocol

from .config import ConfigError
from .settings import write_credentials_json


class CredentialError(Exception):
    """Google credential resolution failed (bad token command, expired refresh, …)."""


class GoogleTokenProvider(Protocol):
    def get_access_token(self) -> str: ...


class StaticTokenProvider:
    """A pre-supplied access token (env or config). Expires ~hourly."""

    def __init__(self, token: str) -> None:
        self._token = token

    def get_access_token(self) -> str:
        return self._token


class TokenCommandProvider:
    """Run a user command whose stdout is the access token. Never logs the token."""

    def __init__(self, command: str, *, timeout: int = 30) -> None:
        self._command, self._timeout = command, timeout

    def get_access_token(self) -> str:
        try:
            proc = subprocess.run(self._command, shell=True, capture_output=True,
                                  text=True, timeout=self._timeout)
        except subprocess.TimeoutExpired as exc:
            raise CredentialError(f"token_command timed out after {self._timeout}s") from exc
        if proc.returncode != 0:
            raise CredentialError(
                f"token_command failed (exit {proc.returncode}): {proc.stderr.strip()[:200]}")
        token = proc.stdout.strip()
        if not token:
            raise CredentialError("token_command produced no output")
        return token


class OAuthRefreshProvider:
    """Refresh a Google access token from an authorized-user credentials file."""

    def __init__(self, credentials_path: Path) -> None:
        self._path = credentials_path

    def get_access_token(self) -> str:
        try:
            from google.auth.exceptions import RefreshError
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
        except ImportError as exc:
            raise CredentialError(
                "oauth mode needs google-auth.  Install:  pip install 'safehouse[google]'"
            ) from exc
        if not self._path.exists():
            raise CredentialError(
                f"{self._path} not found.  Run `safehouse configure` and choose oauth.")
        creds = Credentials.from_authorized_user_file(str(self._path))
        if not creds.valid:
            try:
                creds.refresh(Request())
            except RefreshError as exc:
                raise CredentialError(_refresh_hint(str(exc))) from exc
            write_credentials_json(json.loads(creds.to_json()), self._path)
        return creds.token


def _refresh_hint(detail: str) -> str:
    if "invalid_rapt" in detail:
        return ("Google session reauth required (invalid_rapt) — re-authenticate per your "
                "organization's policy, then re-run.")
    return ("Refresh token expired or revoked.  Re-mint in the OAuth Playground, then run "
            "`safehouse configure` and paste the new refresh token.")


def build_provider(settings) -> GoogleTokenProvider:
    """Select a Google token provider from resolved settings ([google].auth)."""
    auth = settings.google_auth
    if auth == "static":
        return StaticTokenProvider(settings.google_token or "")
    if auth == "token_command":
        if not settings.google_token_command:
            raise ConfigError("google.auth = token_command but no token_command is set")
        return TokenCommandProvider(settings.google_token_command)
    if auth == "oauth":
        return OAuthRefreshProvider(settings.google_credentials_path)
    raise ConfigError(f"unknown google.auth: {auth!r} (expected static, token_command, or oauth)")
