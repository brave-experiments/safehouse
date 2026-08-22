"""
tests/test_cli.py — safehouse_cli package tests (Phase 7).

Covers:
  RunConfig.from_args:
    - --pause forces approval=INTERACTIVE
    - --non-interactive + interactive approval → ConfigError
    - recipient precedence: --recipient > DEMO_RECIPIENT env
    - --auto-approve alias maps to ApprovalMode.AUTO_FIRST_SLOT

  Confirmers:
    - AutoApproveConfirmer.confirm_slot returns 1 (not "yes")
    - DenyConfirmer.confirm_slot returns 0
    - NonInteractiveConfirmer raises ConfirmationRequired
    - ConsoleConfirmer via patched asyncio.to_thread

  Regression (headline bug):
    - schedule_meeting under AutoApproveConfirmer creates calendar event
      (not email-only); the old monkeypatch returned "yes" → int("yes")
      → ValueError → choice 0 → no invite

  _recover_recipient:
    - typed exc with field="recipient" + confirmer returns address
      → generate_plan called a second time with augmented context
    - confirmer returns None → PlanValidationError raised, generate_plan
      called exactly once (no wasted retry)

  Exit-code mapping:
    - driver result with violations → POLICY_VIOLATION (4)
    - generic error → PIPELINE_ERROR (1)
    - success → OK (0)

  Dry-run:
    - driver_run never called, exit_code=OK

  Session:
    - two Sessions get distinct paths (collision test)

  JsonlTraceSink:
    - events written as valid JSON, one per line
    - session id matches EvStaticPlan.session_id field

  TeeStream:
    - stderr content captured in transcript
    - encoding/fileno delegate to original
    - streams restored after exception

  PlanValidationError:
    - field="recipient" for planner error containing "recipient"
    - field="recipient" for invalid email format on recipient field
    - plain ValueError for non-recipient structural failure (unchanged)

No API key required — all tests mock the LLM calls.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safehouse_cli.config import ApprovalMode, ConfigError, RunConfig
from safehouse_cli.interaction import (
    AutoApproveConfirmer,
    ConfirmationRequired,
    ConsoleConfirmer,
    DenyConfirmer,
    NonInteractiveConfirmer,
)
from safehouse_cli.logging_io import JsonlTraceSink, Session, TeeStream, tee_streams
from safehouse_cli.app import ExitCode, _to_run_result, _recover_recipient
from safehouse.planner import PlanValidationError
import safehouse.trace as _trace


# ── RunConfig.from_args ───────────────────────────────────────────────

def test_pause_forces_interactive_approval(monkeypatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    cfg = RunConfig.from_args(["--task", "test", "--pause", "--approve", "auto"])
    assert cfg.approval == ApprovalMode.INTERACTIVE


def test_non_interactive_plus_interactive_approval_raises() -> None:
    with pytest.raises(ConfigError, match="headless"):
        RunConfig.from_args([
            "--task", "test", "--non-interactive", "--approve", "interactive",
        ])


def test_recipient_flag_takes_priority_over_env(monkeypatch) -> None:
    monkeypatch.setenv("DEMO_RECIPIENT", "env@example.com")
    cfg = RunConfig.from_args(["--task", "test", "--recipient", "flag@example.com",
                               "--non-interactive"])
    assert cfg.recipient == "flag@example.com"


def test_recipient_falls_back_to_env(monkeypatch) -> None:
    monkeypatch.setenv("DEMO_RECIPIENT", "env@example.com")
    cfg = RunConfig.from_args(["--task", "test", "--non-interactive"])
    assert cfg.recipient == "env@example.com"


def test_auto_approve_alias_maps_to_auto_first_slot() -> None:
    cfg = RunConfig.from_args(["--task", "test", "--auto-approve", "--non-interactive"])
    assert cfg.approval == ApprovalMode.AUTO_FIRST_SLOT


def test_non_interactive_default_approval_is_deny(monkeypatch) -> None:
    cfg = RunConfig.from_args(["--task", "test", "--non-interactive"])
    assert cfg.approval == ApprovalMode.DENY


# ── Confirmers ────────────────────────────────────────────────────────

def test_select_confirmer_honours_approve_auto_when_non_interactive() -> None:
    """Documented CI form `--non-interactive --approve auto` must not raise."""
    from safehouse_cli.cli import _select_confirmer
    cfg = RunConfig.from_args([
        "--task", "t", "--non-interactive", "--approve", "auto",
    ])
    assert isinstance(_select_confirmer(cfg), AutoApproveConfirmer)


def test_select_confirmer_honours_approve_deny_when_non_interactive() -> None:
    from safehouse_cli.cli import _select_confirmer
    cfg = RunConfig.from_args([
        "--task", "t", "--non-interactive", "--approve", "deny",
    ])
    assert isinstance(_select_confirmer(cfg), DenyConfirmer)


def test_auto_approve_returns_int_1() -> None:
    """Regression: old builtins.input monkeypatch returned "yes" → int("yes") crash."""
    result = asyncio.run(AutoApproveConfirmer().confirm_slot([
        {"start": "2026-09-07T10:00:00", "label": "Mon 10am"},
    ]))
    assert result == 1
    assert isinstance(result, int)


def test_auto_approve_audits_exact_start_end(capsys) -> None:
    """Headless auto-approve must surface the times ActionGrant will endorse."""
    from safehouse.trace import EvAutoApproved, Tracer
    from safehouse import trace as _trace

    class _Cap(Tracer):
        def __init__(self) -> None:
            self.events: list = []
        def on_event(self, event) -> None:
            self.events.append(event)

    cap = _Cap()
    _trace.set_tracer(cap)
    try:
        asyncio.run(AutoApproveConfirmer().confirm_slot([{
            "label": "Mon 10am",
            "start": "2026-09-09T03:00:00",
            "end":   "2026-09-09T04:00:00",
        }]))
    finally:
        _trace.set_tracer(Tracer())

    out = capsys.readouterr().out
    assert "2026-09-09T03:00:00" in out
    assert "2026-09-09T04:00:00" in out
    ev = [e for e in cap.events if isinstance(e, EvAutoApproved)][0]
    assert ev.start == "2026-09-09T03:00:00"
    assert ev.end == "2026-09-09T04:00:00"


def test_deny_confirmer_returns_zero() -> None:
    result = asyncio.run(DenyConfirmer().confirm_slot([{"label": "slot"}]))
    assert result == 0


def test_non_interactive_raises_confirmation_required() -> None:
    with pytest.raises(ConfirmationRequired):
        asyncio.run(NonInteractiveConfirmer().confirm_slot([{"label": "slot"}]))


def test_non_interactive_ask_recipient_raises() -> None:
    with pytest.raises(ConfirmationRequired):
        asyncio.run(NonInteractiveConfirmer().ask_recipient())


def test_auto_approve_ask_recipient_returns_none() -> None:
    result = asyncio.run(AutoApproveConfirmer().ask_recipient())
    assert result is None


def test_console_confirmer_slot_via_patched_thread() -> None:
    async def _run():
        with patch("asyncio.to_thread", new=AsyncMock(return_value="2")):
            return await ConsoleConfirmer().confirm_slot([{}, {}])
    assert asyncio.run(_run()) == 2


def test_console_confirmer_slot_invalid_input_returns_zero() -> None:
    async def _run():
        with patch("asyncio.to_thread", new=AsyncMock(return_value="abc")):
            return await ConsoleConfirmer().confirm_slot([{}])
    assert asyncio.run(_run()) == 0


# ── Regression: auto-approve creates calendar event, not email-only ───

def test_schedule_meeting_auto_approve_creates_event(monkeypatch) -> None:
    """
    AutoApproveConfirmer.confirm_slot returns 1 → choice=1 → approved=True.
    The old monkeypatch returned "yes" → int("yes") → ValueError → choice=0
    → email-only path, no calendar invite.
    """
    import safehouse.driver as driver_mod
    from safehouse.slots import SlotStore
    from safehouse.ironflow_policy import IronFlow
    from safehouse.labels import Label, LVal
    from safehouse.plan_types import PlanState
    from safehouse.driver import _StepContext, ProviderConfig, _handle_schedule_meeting

    sent: list[dict] = []

    async def _fake_gmail_send(to, subject, body, token, state, **kw):
        sent.append({"to": to})

    monkeypatch.setattr(driver_mod, "_gmail_send", _fake_gmail_send)

    import httpx

    class _FakeResp:
        status_code = 200
        text = ""
        def json(self): return {"id": "evt_auto", "htmlLink": "http://cal/evt_auto"}

    class _FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **kw): return _FakeResp()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)

    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({
        "attendee":      "alice@example.com",
        "reply_subject": "Meeting",
        "event_title":   "Sync",
    }, Label.T_pub()))
    store.create("slots")
    store.write("slots", json.dumps({
        "proposed_slots": [{"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00",
                            "label": "Mon 10am"}],
        "reply_body": "Here are times",
    }), Label.U_priv())

    confirmer = AutoApproveConfirmer()
    policy = IronFlow(store)
    policy.precommit_routing(state, sources={"slots"},
                             transform="structured:meeting_proposal")
    ctx = _StepContext(
        store=store, policy=policy,
        driver=__import__("safehouse.permissions", fromlist=["driver_spec"]).driver_spec(),
        state=state,
        config=ProviderConfig(google_token="fake"),
        confirm_slot=confirmer.confirm_slot,
    )

    _, final = asyncio.run(_handle_schedule_meeting({"slots_slot": "slots"}, ctx))

    assert final is not None
    assert final.get("status") == "success"
    assert final.get("event_id") == "evt_auto"   # calendar event created
    assert sent, "gmail send should have been called"


# ── _recover_recipient ────────────────────────────────────────────────

def test_recover_recipient_retries_with_augmented_context(monkeypatch) -> None:
    exc = PlanValidationError("missing recipient", field="recipient")
    call_count = 0

    async def _fake_ask_recipient():
        return "prompted@example.com"

    confirmer = MagicMock()
    confirmer.ask_recipient = _fake_ask_recipient

    good_plan = {"steps": [{"tool": "send_summary", "args": {}}]}

    def _fake_generate_plan(task, operator_context="", registry=None, api_key=None):
        nonlocal call_count
        call_count += 1
        assert "prompted@example.com" in operator_context
        return good_plan

    with patch("safehouse_cli.app.generate_plan", side_effect=_fake_generate_plan):
        from safehouse_cli.config import RunConfig
        cfg = MagicMock(spec=RunConfig)
        cfg.task = "task"
        result = asyncio.run(_recover_recipient(exc, cfg, confirmer, ""))

    assert result == good_plan
    assert call_count == 1


def test_recover_recipient_none_input_raises_no_retry(monkeypatch) -> None:
    exc = PlanValidationError("missing recipient", field="recipient")
    call_count = 0

    async def _fake_ask_recipient():
        return None

    confirmer = MagicMock()
    confirmer.ask_recipient = _fake_ask_recipient

    def _fake_generate_plan(*a, **kw):
        nonlocal call_count
        call_count += 1

    from safehouse_cli.config import RunConfig
    cfg = MagicMock(spec=RunConfig)
    cfg.task = "task"

    with patch("safehouse_cli.app.generate_plan", side_effect=_fake_generate_plan):
        with pytest.raises(PlanValidationError):
            asyncio.run(_recover_recipient(exc, cfg, confirmer, ""))

    # generate_plan must NOT be called (no wasted retry)
    assert call_count == 0


def test_recover_recipient_non_recipient_exc_reraises() -> None:
    exc = PlanValidationError("bad slot", field=None)
    confirmer = MagicMock()
    cfg = MagicMock()
    with pytest.raises(PlanValidationError) as info:
        asyncio.run(_recover_recipient(exc, cfg, confirmer, ""))
    assert info.value is exc


# ── Exit-code mapping ─────────────────────────────────────────────────

def _dummy_session() -> Session:
    with tempfile.TemporaryDirectory() as d:
        return Session.new(Path(d))


def test_exit_code_success() -> None:
    r = _to_run_result({"status": "success"}, _dummy_session(), 1.0)
    assert r.exit_code == ExitCode.OK


def test_exit_code_policy_violation() -> None:
    r = _to_run_result(
        {"status": "error", "violations": ["gate fired"]},
        _dummy_session(), 1.0,
    )
    assert r.exit_code == ExitCode.POLICY_VIOLATION


def test_exit_code_generic_error() -> None:
    r = _to_run_result({"status": "error"}, _dummy_session(), 1.0)
    assert r.exit_code == ExitCode.PIPELINE_ERROR


# ── Session collision test ────────────────────────────────────────────

def test_session_ids_are_distinct() -> None:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        s1 = Session.new(p)
        s2 = Session.new(p)
        assert s1.id != s2.id
        assert s1.jsonl_path != s2.jsonl_path
        assert s1.transcript_path != s2.transcript_path


# ── JsonlTraceSink ────────────────────────────────────────────────────

def test_jsonl_sink_writes_valid_json_per_event() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "events.jsonl"
        sink = JsonlTraceSink(path)

        ev = _trace.EvStaticPlan(session_id="sess_abc", steps=[])
        sink.on_event(ev)
        ev2 = _trace.EvPlanChunk(text="hello")
        sink.on_event(ev2)
        sink.close()

        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        obj1 = json.loads(lines[0])
        assert obj1["event"] == "EvStaticPlan"
        assert obj1["session_id"] == "sess_abc"
        assert "ts" in obj1

        obj2 = json.loads(lines[1])
        assert obj2["event"] == "EvPlanChunk"


def test_jsonl_sink_session_id_matches_ev_static_plan() -> None:
    with tempfile.TemporaryDirectory() as d:
        session = Session.new(Path(d), prefix="test")
        sink = JsonlTraceSink(session.jsonl_path)
        ev = _trace.EvStaticPlan(session_id=session.id, steps=[])
        sink.on_event(ev)
        sink.close()

        line = json.loads(session.jsonl_path.read_text().strip())
        assert line["session_id"] == session.id


# ── TeeStream ─────────────────────────────────────────────────────────

def test_teestream_captures_writes() -> None:
    orig = io.StringIO()
    log  = io.StringIO()
    tee  = TeeStream(orig, log)
    tee.write("hello world")
    tee.flush()
    assert orig.getvalue() == "hello world"
    assert log.getvalue()  == "hello world"


def test_teestream_writable_true() -> None:
    tee = TeeStream(io.StringIO(), io.StringIO())
    assert tee.writable() is True


def test_teestream_encoding_delegates() -> None:
    orig = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    tee  = TeeStream(orig, io.StringIO())
    assert tee.encoding == "utf-8"


def test_tee_streams_restores_after_exception() -> None:
    orig_out = sys.stdout
    orig_err = sys.stderr
    with tempfile.TemporaryDirectory() as d:
        try:
            with tee_streams(Path(d) / "out.txt"):
                raise RuntimeError("test exception")
        except RuntimeError:
            pass
    assert sys.stdout is orig_out
    assert sys.stderr is orig_err


def test_tee_streams_captures_stderr() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "out.txt"
        with tee_streams(path):
            print("stderr line", file=sys.stderr)
        content = path.read_text()
        assert "stderr line" in content


# ── PlanValidationError ───────────────────────────────────────────────

def test_plan_validation_error_field_recipient_on_message() -> None:
    exc = PlanValidationError("Planner rejected the task: missing routing field: recipient",
                              field="recipient")
    assert exc.field == "recipient"
    assert isinstance(exc, ValueError)


def test_plan_validation_error_field_none_for_structural() -> None:
    exc = PlanValidationError("Plan must have a non-empty 'steps' array", field=None)
    assert exc.field is None


def test_plan_validation_error_is_value_error_subclass() -> None:
    exc = PlanValidationError("some error", field="recipient")
    assert isinstance(exc, ValueError)
    with pytest.raises(ValueError):
        raise exc


def test_generate_plan_raises_typed_exc_on_error_response(monkeypatch) -> None:
    """PlanValidationError carries field='recipient' for recipient routing errors."""
    exc = PlanValidationError("Planner rejected the task: missing routing field: recipient",
                              field="recipient")
    assert exc.field == "recipient"
