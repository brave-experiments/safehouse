"""
tests/test_credentials.py — Google token providers.

Covers static/token_command/oauth selection and the OAuth refresh logic with
the google-auth modules faked (no dependency, no network).
"""
import os
import stat
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from safehouse_cli.config import ConfigError
from safehouse_cli.credentials import (
    CredentialError, OAuthRefreshProvider, StaticTokenProvider,
    TokenCommandProvider, build_provider,
)
from safehouse_cli.settings import Settings

try:
    import google.oauth2.credentials  # noqa: F401
    _HAS_GOOGLE = True
except ImportError:
    _HAS_GOOGLE = False


# ── static / token_command ────────────────────────────────────────────

def test_static_provider():
    assert StaticTokenProvider("tok").get_access_token() == "tok"


def test_token_command_success():
    assert TokenCommandProvider("printf ya29.cmd").get_access_token() == "ya29.cmd"


def test_token_command_nonzero_exit():
    with pytest.raises(CredentialError, match="exit 3"):
        TokenCommandProvider("exit 3").get_access_token()


def test_token_command_empty_output():
    with pytest.raises(CredentialError, match="no output"):
        TokenCommandProvider("true").get_access_token()


def test_token_command_timeout():
    with pytest.raises(CredentialError, match="timed out"):
        TokenCommandProvider("sleep 5", timeout=1).get_access_token()


# ── build_provider selection ──────────────────────────────────────────

def test_build_static():
    p = build_provider(Settings(google_token="t", google_auth="static"))
    assert p.get_access_token() == "t"


def test_build_token_command_requires_command():
    with pytest.raises(ConfigError, match="token_command"):
        build_provider(Settings(google_auth="token_command"))


def test_build_unknown_auth():
    with pytest.raises(ConfigError, match="unknown google.auth"):
        build_provider(Settings(google_auth="bogus"))


# ── OAuth refresh (google-auth faked) ─────────────────────────────────

def _install_fake_google(monkeypatch, *, valid, refresh_error=None,
                         refreshed_json='{"token": "new"}', token="fresh-token"):
    class RefreshError(Exception):
        pass

    class Credentials:
        def __init__(self):
            self.valid, self.token = valid, token

        @classmethod
        def from_authorized_user_file(cls, path):
            return cls()

        def refresh(self, request):
            if refresh_error:
                raise RefreshError(refresh_error)
            self.token = token

        def to_json(self):
            return refreshed_json

    mods = {
        "google": types.ModuleType("google"),
        "google.oauth2": types.ModuleType("google.oauth2"),
        "google.oauth2.credentials": types.ModuleType("google.oauth2.credentials"),
        "google.auth": types.ModuleType("google.auth"),
        "google.auth.transport": types.ModuleType("google.auth.transport"),
        "google.auth.transport.requests": types.ModuleType("google.auth.transport.requests"),
        "google.auth.exceptions": types.ModuleType("google.auth.exceptions"),
    }
    mods["google.oauth2.credentials"].Credentials = Credentials
    mods["google.auth.transport.requests"].Request = type("Request", (), {})
    mods["google.auth.exceptions"].RefreshError = RefreshError
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)


def test_oauth_refresh_persists_new_json(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refreshed_json='{"token": "new"}')
    creds = tmp_path / "google_credentials.json"
    creds.write_text('{"stale": true}')
    token = OAuthRefreshProvider(creds).get_access_token()
    assert token == "fresh-token"
    assert creds.read_text() == '{"token": "new"}'          # refreshed JSON persisted
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600


def test_oauth_valid_skips_refresh(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=True, token="cached")
    creds = tmp_path / "google_credentials.json"
    creds.write_text('{"ok": true}')
    assert OAuthRefreshProvider(creds).get_access_token() == "cached"
    assert creds.read_text() == '{"ok": true}'              # unchanged


def test_oauth_invalid_grant_hint(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refresh_error="invalid_grant: bad")
    creds = tmp_path / "google_credentials.json"
    creds.write_text("{}")
    with pytest.raises(CredentialError, match="Re-mint in the OAuth Playground"):
        OAuthRefreshProvider(creds).get_access_token()


def test_oauth_invalid_rapt_hint(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refresh_error="invalid_rapt")
    creds = tmp_path / "google_credentials.json"
    creds.write_text("{}")
    with pytest.raises(CredentialError, match="invalid_rapt"):
        OAuthRefreshProvider(creds).get_access_token()


def test_oauth_missing_file(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=True)
    with pytest.raises(CredentialError, match="not found"):
        OAuthRefreshProvider(tmp_path / "nope.json").get_access_token()


@pytest.mark.skipif(_HAS_GOOGLE, reason="google-auth is installed")
def test_oauth_missing_dependency(tmp_path):
    creds = tmp_path / "google_credentials.json"
    creds.write_text("{}")
    with pytest.raises(CredentialError, match=r"safehouse\[google\]"):
        OAuthRefreshProvider(creds).get_access_token()
