"""
tests/test_secret_containment.py — invariant #6, the "never in a slot" clause.

Slot content is the one channel that reaches both the Tier-2 model and, via a
Tier-3 release, the outside world. A credential landing there is therefore an
exfiltration path, not merely an untidy log line. These tests assert the two
boundary behaviours and the drift guard that keeps them complete.

See safehouse/secrets.py for why slots deny and traces redact.
"""
import base64
import json
import os
import sys
from dataclasses import dataclass, fields

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from safehouse import driver as driver_mod
from safehouse import trace as trace_mod
from safehouse.driver import ProviderConfig, build_secret_registry
from safehouse.labels import Label
from safehouse.secrets import SecretLeak, SecretRegistry
from safehouse.slots import SlotStore

TOKEN = "sk-liteapi-SENTINELsentinel0123456789"


def _store() -> SlotStore:
    store = SlotStore(SecretRegistry({"liteapi_key": TOKEN}))
    store.create("out")
    return store


# ── 1. The slot boundary denies ───────────────────────────────────────

def test_a_credential_cannot_be_written_into_a_slot():
    store = _store()
    body  = f'{{"message":"Bad credentials for {TOKEN}"}}'
    with pytest.raises(SecretLeak) as exc:
        store.write("out", body, Label.U_priv())
    assert "liteapi_key" in str(exc.value)
    assert TOKEN not in str(exc.value), "the error message must not repeat the secret"


def test_a_refused_write_leaves_the_slot_unwritten():
    """Fail at the boundary, not one step later: the slot must remain writable-
    but-unwritten so the pipeline reports a fetch failure rather than reading
    a half-populated slot."""
    store = _store()
    with pytest.raises(SecretLeak):
        store.write("out", f"leaked {TOKEN}", Label.U_priv())
    assert not store.is_written("out")


def test_ordinary_content_is_unaffected():
    store = _store()
    store.write("out", "a perfectly normal issue body", Label.U_priv())
    assert store.read("out").value == "a perfectly normal issue body"


def test_a_store_without_a_registry_does_not_scan():
    """Unit tests build bare stores; they have no credentials to contain."""
    store = SlotStore()
    store.create("out")
    store.write("out", f"contains {TOKEN}", Label.U_priv())
    assert store.is_written("out")


# ── 2. Encodings the raw scan would miss ──────────────────────────────

@pytest.mark.parametrize("wrap", [
    pytest.param(lambda s: base64.urlsafe_b64encode(s.encode()).decode(), id="base64url"),
    pytest.param(lambda s: base64.b64encode(s.encode()).decode(),         id="base64"),
    pytest.param(lambda s: json.dumps({"err": s}),                        id="json"),
    pytest.param(lambda s: f"https://api.example.com/x?t={s}",            id="url"),
])
def test_encoded_credentials_are_caught(wrap):
    """send_reply base64url-encodes the entire MIME message before sending, so a
    credential inside one is invisible to a raw substring scan."""
    store = _store()
    with pytest.raises(SecretLeak):
        store.write("out", wrap(TOKEN), Label.U_priv())


def test_base64_is_caught_at_every_byte_alignment():
    """Base64 encodes 3 bytes to 4 chars, so the secret's encoding depends on its
    offset mod 3. All three alignments must match, not just the lucky one."""
    reg = SecretRegistry({"liteapi_key": TOKEN})
    for prefix in ("", "x", "yz", "abc", "abcd"):
        blob = base64.b64encode((prefix + TOKEN + "tail").encode()).decode()
        assert reg.find(blob) == "liteapi_key", f"missed at prefix len {len(prefix)}"


# ── 3. The trace boundary redacts ─────────────────────────────────────

def test_trace_redacts_rather_than_raising():
    """A provider error is the most likely carrier of a credential. Denying here
    would turn a clean, reportable failure into a crash and destroy the audit
    record of it."""
    seen = []

    class _Capture(trace_mod.Tracer):
        def on_event(self, event): seen.append(event)

    trace_mod.set_tracer(_Capture())
    trace_mod.set_secret_registry(SecretRegistry({"liteapi_key": TOKEN}))
    try:
        trace_mod.emit(trace_mod.EvDriverStart(task=f"boom: {TOKEN} rejected"))
    finally:
        trace_mod.set_secret_registry(None)

    assert len(seen) == 1
    assert TOKEN not in seen[0].task
    assert "[REDACTED:liteapi_key]" in seen[0].task
    assert "boom:" in seen[0].task, "surrounding context must survive redaction"


def test_trace_redaction_does_not_mutate_the_emitters_object():
    """emit() rebuilds; the caller's event object is left alone."""
    trace_mod.set_tracer(trace_mod.Tracer())
    original = trace_mod.EvDriverStart(task=f"x {TOKEN}")
    trace_mod.set_secret_registry(SecretRegistry({"liteapi_key": TOKEN}))
    try:
        trace_mod.emit(original)
    finally:
        trace_mod.set_secret_registry(None)
    assert original.task == f"x {TOKEN}"


# ── 4. The registry cannot leak itself ────────────────────────────────

def test_registry_repr_hides_its_values():
    """The registry is held by the store and the tracer, both of which appear in
    reprs and traceback frames."""
    reg = SecretRegistry({"liteapi_key": TOKEN})
    assert TOKEN not in repr(reg)
    assert TOKEN not in str(reg)
    assert TOKEN not in f"{reg}"


def test_short_values_are_not_registered():
    """A short needle would collide with ordinary prose and deny valid writes."""
    reg = SecretRegistry({"tiny": "abc"})
    assert not reg
    assert reg.find("abc def") is None


# ── 5. Drift guard ────────────────────────────────────────────────────

def test_every_provider_config_field_is_classified():
    """Adding a credential to ProviderConfig must force a containment decision.

    Without this, a new token field defaults to unregistered — the gate stays
    green while silently not covering it.
    """
    declared = {f.name for f in fields(ProviderConfig)}
    classified = driver_mod._SECRET_CONFIG_FIELDS | driver_mod._NON_SECRET_CONFIG_FIELDS
    assert declared == classified, (
        f"unclassified ProviderConfig fields {sorted(declared - classified)}; "
        f"stale entries {sorted(classified - declared)} — add each to "
        f"_SECRET_CONFIG_FIELDS or _NON_SECRET_CONFIG_FIELDS in driver.py"
    )
    assert not (driver_mod._SECRET_CONFIG_FIELDS & driver_mod._NON_SECRET_CONFIG_FIELDS)


def test_registry_builder_covers_exactly_the_secret_fields():
    """The builder's signature is the thing that actually registers values;
    a field in _SECRET_CONFIG_FIELDS but absent here would never be scanned."""
    import inspect
    params = set(inspect.signature(build_secret_registry).parameters)
    assert params == driver_mod._SECRET_CONFIG_FIELDS


def test_builder_registers_every_secret_it_is_given():
    long = {f: f"{f}_VALUE_0123456789abcdef" for f in driver_mod._SECRET_CONFIG_FIELDS}
    reg  = build_secret_registry(**long)
    for name, value in long.items():
        assert reg.find(f"prefix {value} suffix") == name


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
