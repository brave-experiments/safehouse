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

def _install_fake_google(monkeypatch, *, valid, refresh_error=None, error_kind="refresh",
                         refreshed_json='{"token": "new"}', token="fresh-token"):
    class GoogleAuthError(Exception):
        pass

    class RefreshError(GoogleAuthError):
        pass

    class TransportError(GoogleAuthError):
        pass

    class Credentials:
        def __init__(self):
            self.valid, self.token = valid, token

        @classmethod
        def from_authorized_user_file(cls, path):
            return cls()

        def refresh(self, request):
            if refresh_error is not None:
                raise (TransportError if error_kind == "transport" else RefreshError)(refresh_error)
            self.token = token

        def to_json(self):
            return refreshed_json

    exc = types.ModuleType("google.auth.exceptions")
    exc.GoogleAuthError, exc.RefreshError, exc.TransportError = (
        GoogleAuthError, RefreshError, TransportError)
    cred = types.ModuleType("google.oauth2.credentials"); cred.Credentials = Credentials
    req = types.ModuleType("google.auth.transport.requests"); req.Request = type("Request", (), {})
    mods = {
        "google": types.ModuleType("google"),
        "google.oauth2": types.ModuleType("google.oauth2"),
        "google.oauth2.credentials": cred,
        "google.auth": types.ModuleType("google.auth"),
        "google.auth.transport": types.ModuleType("google.auth.transport"),
        "google.auth.transport.requests": req,
        "google.auth.exceptions": exc,
    }
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)


def _creds(tmp_path, content="{}"):
    """Write a 0600 credentials fixture and return its path."""
    p = tmp_path / "google_credentials.json"
    p.write_text(content)
    p.chmod(0o600)
    return p


def test_oauth_refresh_persists_new_json(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refreshed_json='{"token": "new"}')
    creds = _creds(tmp_path, '{"stale": true}')
    token = OAuthRefreshProvider(creds).get_access_token()
    assert token == "fresh-token"
    assert creds.read_text() == '{"token": "new"}'          # refreshed JSON persisted
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600


def test_oauth_valid_skips_refresh(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=True, token="cached")
    creds = _creds(tmp_path, '{"ok": true}')
    assert OAuthRefreshProvider(creds).get_access_token() == "cached"
    assert creds.read_text() == '{"ok": true}'              # unchanged


def test_oauth_invalid_grant_hint(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refresh_error="invalid_grant: bad")
    with pytest.raises(CredentialError, match="Re-mint in the OAuth Playground"):
        OAuthRefreshProvider(_creds(tmp_path)).get_access_token()


def test_oauth_invalid_rapt_hint(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refresh_error="invalid_rapt")
    with pytest.raises(CredentialError, match="invalid_rapt"):
        OAuthRefreshProvider(_creds(tmp_path)).get_access_token()


def test_oauth_transport_error_maps_to_credential_error(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=False, refresh_error="network down",
                         error_kind="transport")
    with pytest.raises(CredentialError, match="Google auth failed"):
        OAuthRefreshProvider(_creds(tmp_path)).get_access_token()


def test_oauth_lax_perms_rejected(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=True)
    creds = _creds(tmp_path)
    creds.chmod(0o644)
    with pytest.raises(CredentialError, match="chmod 600"):
        OAuthRefreshProvider(creds).get_access_token()


def test_oauth_missing_file(tmp_path, monkeypatch):
    _install_fake_google(monkeypatch, valid=True)
    with pytest.raises(CredentialError, match="not found"):
        OAuthRefreshProvider(tmp_path / "nope.json").get_access_token()


@pytest.mark.skipif(_HAS_GOOGLE, reason="google-auth is installed")
def test_oauth_missing_dependency(tmp_path):
    with pytest.raises(CredentialError, match=r"safehouse\[google\]"):
        OAuthRefreshProvider(_creds(tmp_path)).get_access_token()


# ── FIX-2: token_command works keyless; token reaches the header, not Tier-2 ──

def test_token_command_reaches_header_not_subagent(monkeypatch):
    from safehouse.runner import _google_auth_headers, _subagent_env
    from safehouse_cli.settings import Settings
    sentinel = "ya29.SENTINEL_TOKEN_XYZ"                     # GOOGLE_ACCESS_TOKEN cleared by conftest
    provider = build_provider(Settings(google_auth="token_command",
                                       google_token_command=f"printf %s {sentinel}"))
    token = provider.get_access_token()
    assert token == sentinel                                 # keyless token_command resolves
    assert _google_auth_headers(token) == {"Authorization": f"Bearer {sentinel}"}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    assert not any(sentinel in v for v in _subagent_env().values())   # never in Tier-2 env
