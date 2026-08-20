"""
tests/test_subagent_isolation.py — Tier-2 isolation.

The Tier-2 processor runs via the Anthropic SDK in-process, not as a `claude -p`
subprocess. That changes how isolation is achieved, so these tests assert the
property rather than any one mechanism.

Under a subprocess the model had tools, so a foreign credential in the child's
environment was reachable (a Bash tool could read it) — hence the previous
env-allowlist guard. In-process there is no child environment and, more
importantly, no tool: the request carries only the system prompt and the slot
content, so nothing ambient can be read at all.

See CLAUDE.md invariant 6.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import safehouse.runner as runner_mod
from safehouse.labels import Label
from safehouse.slots import SlotStore
from safehouse.trace import Tracer, set_tracer


class _CapturedRequest(Exception):
    """Abort the SDK call once the request payload has been captured."""


def _run_processor(monkeypatch, *, slot_body: str, api_key: str | None) -> dict:
    """Intercept the processor's SDK request; return the captured kwargs."""
    captured: dict = {}

    class _Messages:
        def stream(self, **kwargs):
            captured.update(kwargs)
            raise _CapturedRequest

    class _Client:
        def __init__(self, *a, **kw):
            captured["_client_kwargs"] = kw
            self.messages = _Messages()

    monkeypatch.setattr(runner_mod.anthropic, "AsyncAnthropic", _Client)

    store = SlotStore()
    store.create("dirty")
    store.writer_for("dirty", Label.U_priv(), agent_id="t").write(slot_body)
    store.create("out")
    out    = store.writer_for("out", Label.U_priv(), agent_id="p")
    reader = store.reader_for(["dirty"], agent_id="p", max_label=Label.U_priv())

    set_tracer(Tracer())
    with pytest.raises(_CapturedRequest):
        asyncio.run(runner_mod.run_processor(
            ["dirty"], reader, out,
            system_prompt="SYS", agent_id="p", api_key=api_key,
        ))
    return captured


# ── 1. Nothing ambient reaches the model ──────────────────────────────

def test_foreign_credential_cannot_reach_the_processor(monkeypatch):
    """A Google token in the environment must not appear anywhere in the request.

    Previously enforced by scrubbing the subprocess env. Now it holds because the
    request is built from exactly two values — the system prompt and the slot
    content — and the model has no tool with which to read anything else.
    """
    monkeypatch.setenv("GOOGLE_ACCESS_TOKEN", "ya29.SENTINEL")
    monkeypatch.setenv("DEMO_RECIPIENT", "victim@example.com")
    captured = _run_processor(monkeypatch, slot_body="just some slot text",
                             api_key="sk-ant-x")
    blob = repr(captured)
    assert "ya29.SENTINEL" not in blob
    assert "victim@example.com" not in blob


def test_request_carries_only_system_prompt_and_slot_content(monkeypatch):
    """Pin the request shape: anything added later is a new channel into Tier 2."""
    captured = _run_processor(monkeypatch, slot_body="SLOT_BODY_MARKER",
                             api_key="sk-ant-x")
    assert set(captured) <= {"_client_kwargs", "model", "max_tokens", "system", "messages"}
    assert captured["system"] == "SYS"
    assert captured["messages"][0]["role"] == "user"
    assert "SLOT_BODY_MARKER" in captured["messages"][0]["content"]


# ── 2. No tools, structurally ─────────────────────────────────────────

def test_no_tools_are_offered(monkeypatch):
    """Isolation by omission, not by a flag that could be mis-set.

    The subprocess form passed `--tools ""`, which does NOT yield zero tools:
    `--tools` is variadic, so an empty string is a tool *name*. Omitting the
    argument entirely leaves the model nothing to call.
    """
    captured = _run_processor(monkeypatch, slot_body="x", api_key="sk-ant-x")
    for key in ("tools", "tool_choice", "mcp_servers"):
        assert key not in captured, f"{key} must never be offered to the processor"


# ── 3. Credential is an explicit parameter ────────────────────────────

def test_api_key_is_passed_explicitly_not_read_from_env(monkeypatch):
    """Invariant #6: resolved in the CLI layer, passed as a parameter."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-AMBIENT")
    captured = _run_processor(monkeypatch, slot_body="x", api_key="sk-ant-EXPLICIT")
    assert captured["_client_kwargs"].get("api_key") == "sk-ant-EXPLICIT"


# ── 4. Model is pinned, not inherited ─────────────────────────────────

def test_model_is_pinned_in_the_request(monkeypatch):
    """Tier-2's model must be a property of the code, not of local CLI config —
    otherwise the same manifest behaves differently per machine."""
    captured = _run_processor(monkeypatch, slot_body="x", api_key="sk-ant-x")
    assert captured["model"] == runner_mod._PROCESSOR_MODEL
    assert captured["max_tokens"] == runner_mod._PROCESSOR_MAX_TOKENS


# ── 5. No subprocess machinery remains ────────────────────────────────

def test_runner_cannot_spawn_a_subprocess_at_all():
    """A subprocess reintroduces disk-loaded config (settings, CLAUDE.md, hooks,
    MCP servers), an ambient credential path, and a PATH-shimmable binary.

    Asserted structurally on the AST rather than on source text: the module must
    not import subprocess and must contain no Popen/run/exec call. A text search
    would match the prose in _llm_processor's docstring explaining why it does not
    spawn one.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(runner_mod))

    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "subprocess" not in imported, "runner.py imports subprocess again"
    assert "pty" not in imported and "multiprocessing" not in imported

    spawners = {"Popen", "system", "fork", "execv", "execvp", "spawnv", "check_output"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            assert name not in spawners, f"process spawn via {name!r} in runner.py"


def test_a_missing_key_raises_rather_than_falling_back_to_the_environment(monkeypatch):
    """The SDK resolves api_key from ANTHROPIC_API_KEY when it is None, which would
    be a second credential path the CLI does not control — and one an AST sweep of
    this package cannot see, because the read happens inside the SDK rather than in
    our code. Refusing an empty key keeps the CLI the only resolver.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-AMBIENT")
    with pytest.raises(RuntimeError, match="explicit API key"):
        _run_processor(monkeypatch, slot_body="x", api_key="")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
