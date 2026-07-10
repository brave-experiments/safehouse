"""
conftest.py — test hermeticity.

Point SAFEHOUSE_CONFIG at a nonexistent path and clear credential env vars so
tests never read the developer's real ~/.safehouse/config.toml or exported
credentials. Tests that need specific values set them via monkeypatch, which
overrides this autouse fixture.
"""
import pytest


@pytest.fixture(autouse=True)
def _hermetic_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEHOUSE_CONFIG", str(tmp_path / "no-config.toml"))
    # The only credential/config env vars load_settings() consults.
    for var in ("ANTHROPIC_API_KEY", "GOOGLE_ACCESS_TOKEN", "DEMO_RECIPIENT"):
        monkeypatch.delenv(var, raising=False)
