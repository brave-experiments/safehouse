"""
tests/test_multi_pipeline.py — multi-action pipeline support.

Covers planner validation, routing pre-commitment, and per-pipeline
state isolation. No API key required.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import safehouse.driver as driver_mod
import safehouse.trace as _trace
from safehouse.driver import ProviderConfig, _StepContext, run as driver_run
from safehouse.ironflow_policy import IronFlow
from safehouse.labels import LVal, Label
from safehouse.permissions import driver_spec
from safehouse.plan_types import PlanState
from safehouse.planner import (
    PlanValidationError, _MAX_PIPELINES, _map_sub_plans, _precheck_shape,
    _validate_plan,
)
from safehouse.registry import DEFAULT_REGISTRY
from safehouse.slots import SlotStore
from safehouse.trace import Tracer


def _reply_pipeline(sender: str, slot_suffix: str) -> dict:
    return {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": sender, "limit": 1},
            "slot_id": f"email_{slot_suffix}",
            "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": [f"email_{slot_suffix}"],
            "out_slot": f"reply_{slot_suffix}",
            "instruction": "Write a reply.",
        }},
        {"tool": "send_reply", "args": {
            "recipient": sender,
            "subject": f"Re: test {slot_suffix}",
            "body_slot": f"reply_{slot_suffix}",
        }},
    ]}


# ── Validation ────────────────────────────────────────────────────────

def test_precheck_rejects_both_keys():
    with pytest.raises(ValueError, match="both"):
        _precheck_shape({"steps": [], "pipelines": []})


def test_precheck_rejects_empty_pipelines():
    with pytest.raises(ValueError, match="non-empty"):
        _precheck_shape({"pipelines": []})


def test_precheck_rejects_over_cap():
    with pytest.raises(ValueError, match=str(_MAX_PIPELINES)):
        _precheck_shape({"pipelines": [{"steps": []}] * (_MAX_PIPELINES + 1)})


def test_precheck_rejects_non_dict_sub_plan():
    with pytest.raises(ValueError, match="Pipeline 1"):
        _precheck_shape({"pipelines": ["not a dict"]})


def test_validate_plan_runs_per_sub_plan():
    plan = {"pipelines": [
        _reply_pipeline("a@corp.com", "a"),
        _reply_pipeline("b@corp.com", "b"),
    ]}
    mapped = _map_sub_plans(plan, DEFAULT_REGISTRY)
    # Both sub-plans valid — should not raise
    for sub in mapped["pipelines"]:
        _validate_plan(sub, task="reply to a@corp.com and b@corp.com")


def test_validate_plan_catches_invalid_sub_plan():
    # Pipeline 2 has an injected recipient not in the task — AXIOM must reject it.
    plan = {"pipelines": [
        _reply_pipeline("a@corp.com", "a"),
        _reply_pipeline("injected@evil.com", "b"),   # not in task
    ]}
    mapped = _map_sub_plans(plan, DEFAULT_REGISTRY)
    with pytest.raises(PlanValidationError, match="AXIOM"):
        for sub in mapped["pipelines"]:
            _validate_plan(sub, task="reply to a@corp.com")


def test_send_reply_rejects_q_only_email_search():
    """filter.q='from:…' is not enough — send_reply requires named filter.from."""
    plan = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"q": "from:alice@corp.com", "limit": 1},
            "slot_id": "email", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["email"], "out_slot": "reply", "instruction": "Write a reply.",
        }},
        {"tool": "send_reply", "args": {
            "recipient": "bob@corp.com", "subject": "Re: x", "body_slot": "reply",
        }},
    ]}
    with pytest.raises(PlanValidationError, match="filter.from"):
        _validate_plan(plan, task="reply to alice@corp.com and bob@corp.com")


def test_send_reply_rejects_multiple_email_searches():
    """Two fetches in one send_reply plan make thread_id provenance ambiguous."""
    plan = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "alice@corp.com", "limit": 1},
            "slot_id": "e1", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "bob@corp.com", "limit": 1},
            "slot_id": "e2", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["e1", "e2"], "out_slot": "reply", "instruction": "Write a reply.",
        }},
        {"tool": "send_reply", "args": {
            "recipient": "bob@corp.com", "subject": "Re: x", "body_slot": "reply",
        }},
    ]}
    with pytest.raises(PlanValidationError, match="at most one mcp_email_search"):
        _validate_plan(plan, task="reply to alice@corp.com and bob@corp.com")


def test_send_reply_rejects_from_recipient_mismatch():
    plan = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "alice@corp.com", "limit": 1},
            "slot_id": "email", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["email"], "out_slot": "reply", "instruction": "Write a reply.",
        }},
        {"tool": "send_reply", "args": {
            "recipient": "bob@corp.com", "subject": "Re: x", "body_slot": "reply",
        }},
    ]}
    with pytest.raises(PlanValidationError, match="does not include") as info:
        _validate_plan(plan, task="reply to alice@corp.com and bob@corp.com")
    # Structural — must not open ask_recipient recovery in run_task.
    assert info.value.field is None


def test_send_reply_structural_errors_are_not_recipient_recoverable():
    """Multi-search / missing filter.from must use field=None (hard planning failure)."""
    q_only = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"q": "from:alice@corp.com", "limit": 1},
            "slot_id": "email", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["email"], "out_slot": "reply", "instruction": "x",
        }},
        {"tool": "send_reply", "args": {
            "recipient": "alice@corp.com", "subject": "Re", "body_slot": "reply",
        }},
    ]}
    with pytest.raises(PlanValidationError) as info:
        _validate_plan(q_only, task="reply to alice@corp.com")
    assert info.value.field is None

    multi = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "alice@corp.com", "limit": 1},
            "slot_id": "e1", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "bob@corp.com", "limit": 1},
            "slot_id": "e2", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["e1", "e2"], "out_slot": "reply", "instruction": "x",
        }},
        {"tool": "send_reply", "args": {
            "recipient": "bob@corp.com", "subject": "Re", "body_slot": "reply",
        }},
    ]}
    with pytest.raises(PlanValidationError) as info:
        _validate_plan(multi, task="reply to alice@corp.com and bob@corp.com")
    assert info.value.field is None


# ── State isolation ───────────────────────────────────────────────────

class _ListTracer(Tracer):
    def __init__(self):
        self.events = []
    def on_event(self, event):
        self.events.append(event)


def test_pipeline_state_isolation():
    """Pipeline 2's routing must not be contaminated by pipeline 1's state."""
    plan_1 = {"steps": [{"tool": "send_reply", "args": {
        "recipient": "a@corp.com", "subject": "Re: a", "body_slot": "body_a",
    }}]}
    plan_2 = {"steps": [{"tool": "send_reply", "args": {
        "recipient": "b@corp.com", "subject": "Re: b", "body_slot": "body_b",
    }}]}

    tr = _ListTracer()
    _trace.set_tracer(tr)
    try:
        for plan in (plan_1, plan_2):
            store = SlotStore()    # fresh store per pipeline — same store used for IronFlow
            asyncio.run(driver_run("t", plan, store, IronFlow(store), google_token=""))
    finally:
        _trace.set_tracer(Tracer())

    locked = [e for e in tr.events if isinstance(e, _trace.EvRoutingLocked)]
    recipients = [e.routing.get("recipient") for e in locked]
    assert recipients.count("a@corp.com") == 1
    assert recipients.count("b@corp.com") == 1


# ── Thread-ID propagation ─────────────────────────────────────────────

def test_send_reply_carries_email_thread_id(monkeypatch):
    """
    thread_id from mcp_email_search must reach GmailClient.send even though
    body_slot (processor output) differs from the email-search slot_id.
    """
    from safehouse.labels import Label

    async def _fake_email_search(spec, filter_p, writer, policy, *, google_token=""):
        writer.write("From: alice@corp.com\nBody: Hello")
        return {
            "thread_id": "tid_pipeline_a",
            "message_id": "<msg-a@mail.example>",
            "references": "",
            "subject": "Hello from Alice",
        }

    async def _fake_processor(reads, reader, writer, *, system_prompt="", agent_id="", timeout=300):
        writer.write("Dear Alice, thank you for your email.")

    sent_args: list[dict] = []

    async def _fake_client_send(self, to, subject, body, thread_id="", **kw):
        sent_args.append({"to": to, "subject": subject, "thread_id": thread_id, **kw})
        return "fake_msg_id"

    monkeypatch.setattr(driver_mod, "run_mcp_email_search", _fake_email_search)
    monkeypatch.setattr(driver_mod, "run_processor", _fake_processor)
    monkeypatch.setattr(driver_mod.GmailClient, "send", _fake_client_send)

    plan = _reply_pipeline("alice@corp.com", "a")
    store = SlotStore()
    result = asyncio.run(driver_run(
        "reply to alice", plan, store, IronFlow(store), google_token="fake-token"
    ))

    assert result.get("status") == "success", f"pipeline failed: {result}"
    assert sent_args, "GmailClient.send was never called"
    assert sent_args[0]["thread_id"] == "tid_pipeline_a", (
        f"expected 'tid_pipeline_a', got {sent_args[0]['thread_id']!r} "
        "— thread_id not forwarded from email-search slot to send"
    )
    assert sent_args[0]["in_reply_to"] == "<msg-a@mail.example>"
    assert sent_args[0]["references"] == "<msg-a@mail.example>"
    assert sent_args[0]["subject"] == "Re: test a"  # gated routing — not fetched Subject


def test_send_reply_thread_id_isolated_per_pipeline(monkeypatch):
    """
    In a multi-pipeline run, pipeline B's send must carry pipeline B's thread_id,
    not pipeline A's (each pipeline has its own PlanState from driver_run).
    """
    from safehouse.labels import Label

    call_n = [0]
    thread_ids_by_suffix = {"a": "tid_a", "b": "tid_b"}

    async def _fake_email_search(spec, filter_p, writer, policy, *, google_token=""):
        # Identify which pipeline by slot_id suffix embedded in the spec id.
        suffix = "b" if "email_b" in spec.id else "a"
        writer.write(f"email content for {suffix}")
        return {
            "thread_id": thread_ids_by_suffix[suffix],
            "message_id": f"<msg-{suffix}@mail.example>",
            "references": "",
            "subject": f"Subject {suffix}",
        }

    async def _fake_processor(reads, reader, writer, *, system_prompt="", agent_id="", timeout=300):
        writer.write("reply body")

    sent_per_pipeline: list[str] = []

    async def _fake_client_send(self, to, subject, body, thread_id="", **kw):
        sent_per_pipeline.append(thread_id)
        return "fake_msg_id"

    monkeypatch.setattr(driver_mod, "run_mcp_email_search", _fake_email_search)
    monkeypatch.setattr(driver_mod, "run_processor", _fake_processor)
    monkeypatch.setattr(driver_mod.GmailClient, "send", _fake_client_send)

    tr = _ListTracer()
    _trace.set_tracer(tr)
    try:
        for suffix, sender in [("a", "alice@corp.com"), ("b", "bob@corp.com")]:
            plan = _reply_pipeline(sender, suffix)
            store = SlotStore()
            asyncio.run(driver_run(
                f"reply to {sender}", plan, store, IronFlow(store), google_token="fake-token"
            ))
    finally:
        _trace.set_tracer(Tracer())

    assert sent_per_pipeline == ["tid_a", "tid_b"], (
        f"thread isolation broken: {sent_per_pipeline}"
    )


def test_schedule_meeting_carries_email_thread_headers(monkeypatch):
    """
    schedule_meeting must thread the confirmation email into the fetched request
    (body_slot=slots_slot → _thread_source → In-Reply-To / matching Subject).
    """
    async def _fake_email_search(spec, filter_p, writer, policy, *, google_token=""):
        writer.write("From: alice@corp.com\nPlease schedule a meeting.")
        return {
            "thread_id": "tid_meet",
            "message_id": "<meet-req@mail.example>",
            "references": "",
            "subject": "Can we meet next week?",
        }

    async def _fake_cal(spec, filter_p, writer, policy, *, google_token=""):
        writer.write("No events")

    async def _fake_processor(reads, reader, writer, *, system_prompt="", agent_id="", timeout=300):
        import json as _json
        writer.write(_json.dumps({
            "proposed_slots": [{
                "start": "2026-07-14T10:00:00+01:00",
                "end": "2026-07-14T10:30:00+01:00",
                "label": "Tue 10am",
            }],
            "reply_body": "Here are some times.",
        }))

    sent: list[dict] = []

    async def _fake_client_send(self, to, subject, body, thread_id="", **kw):
        sent.append({"to": to, "subject": subject, "thread_id": thread_id, **kw})
        return "fake_msg_id"

    class _Resp:
        status_code = 200
        text = ""
        def json(self):
            return {"id": "evt1", "htmlLink": "http://cal/evt1"}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **k): return _Resp()

    import httpx
    monkeypatch.setattr(driver_mod, "run_mcp_email_search", _fake_email_search)
    monkeypatch.setattr(driver_mod, "run_mcp_calendar_search", _fake_cal)
    monkeypatch.setattr(driver_mod, "run_processor", _fake_processor)
    monkeypatch.setattr(driver_mod.GmailClient, "send", _fake_client_send)
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    plan = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "alice@corp.com", "limit": 1},
            "slot_id": "email_content", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "mcp_calendar_search", "args": {
            "filter": {"timeMin": "2026-07-13T00:00:00+01:00", "timeMax": "2026-07-17T23:59:00+01:00"},
            "slot_id": "calendar_events", "capability": "CALENDAR_READ",
            "api_url": "https://www.googleapis.com/calendar/v3",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["email_content", "calendar_events"],
            "out_slot": "meeting_proposal", "instruction": "Propose slots.",
        }},
        {"tool": "schedule_meeting", "args": {
            "attendee": "alice@corp.com", "event_title": "Sync",
            "reply_subject": "Re: invented", "slots_slot": "meeting_proposal",
        }},
    ]}

    async def _confirm_one(slots):
        return 1

    store = SlotStore()
    result = asyncio.run(driver_run(
        "schedule with alice@corp.com", plan, store, IronFlow(store),
        google_token="fake-token", confirm_slot=_confirm_one,
    ))
    assert result.get("status") == "success", result
    assert sent, "GmailClient.send was never called"
    assert sent[0]["thread_id"] == "tid_meet"
    assert sent[0]["in_reply_to"] == "<meet-req@mail.example>"
    assert sent[0]["subject"] == "Re: invented"  # gated reply_subject — not fetched Subject


def test_schedule_meeting_rejects_email_limit_gt_one():
    plan = {"steps": [
        {"tool": "mcp_email_search", "args": {
            "filter": {"from": "alice@corp.com", "limit": 5},
            "slot_id": "email", "capability": "EMAIL_READ",
            "api_url": "https://gmail.googleapis.com/gmail/v1",
        }},
        {"tool": "mcp_calendar_search", "args": {
            "filter": {"timeMin": "2026-07-13T00:00:00Z", "timeMax": "2026-07-17T23:59:00Z"},
            "slot_id": "cal", "capability": "CALENDAR_READ",
            "api_url": "https://www.googleapis.com/calendar/v3",
        }},
        {"tool": "spawn_processor", "args": {
            "reads": ["email", "cal"], "out_slot": "prop", "instruction": "x",
        }},
        {"tool": "schedule_meeting", "args": {
            "attendee": "alice@corp.com", "event_title": "Sync",
            "reply_subject": "Re", "slots_slot": "prop",
        }},
    ]}
    with pytest.raises(PlanValidationError, match="limit must be 1"):
        _validate_plan(plan, task="schedule with alice@corp.com")


def test_run_manifest_partial_sets_do_not_retry(monkeypatch):
    """When any sub-pipeline succeeds and another fails, aggregate warns against retry."""
    from safehouse.driver import run_manifest

    call = [0]

    async def _fake_run(task, plan, store, policy, **kw):
        call[0] += 1
        if call[0] == 1:
            return {"status": "success", "violations": []}
        return {"status": "error", "reason": "boom", "violations": []}

    monkeypatch.setattr(driver_mod, "run", _fake_run)
    plan = {"pipelines": [
        {"steps": [{"tool": "send_summary", "args": {
            "recipient": "a@corp.com", "subject": "S1", "body_slot": "b1",
        }}]},
        {"steps": [{"tool": "send_summary", "args": {
            "recipient": "b@corp.com", "subject": "S2", "body_slot": "b2",
        }}]},
    ]}
    result = asyncio.run(run_manifest("t", plan))
    assert result["status"] == "partial"
    assert result["do_not_retry"] is True
    assert len(result["actions"]) == 2


def test_run_manifest_do_not_retry_on_partial_send_without_success(monkeypatch):
    """status=error with sent=[] still means mail left the building — do not retry."""
    from safehouse.driver import run_manifest

    async def _fake_run(task, plan, store, policy, **kw):
        return {
            "status": "error",
            "reason": "send failed for bob@corp.com",
            "sent": ["alice@corp.com"],
            "violations": [],
        }

    monkeypatch.setattr(driver_mod, "run", _fake_run)
    plan = {"pipelines": [
        {"steps": [{"tool": "send_summary", "args": {
            "recipient": ["alice@corp.com", "bob@corp.com"],
            "subject": "S", "body_slot": "b", "delivery": "separate",
        }}]},
    ]}
    result = asyncio.run(run_manifest("t", plan))
    assert result["status"] == "error"
    assert result["do_not_retry"] is True


def test_run_manifest_single_plan_do_not_retry_on_event_id(monkeypatch):
    """Single-plan calendar-created / reply-failed must also set do_not_retry."""
    from safehouse.driver import run_manifest

    async def _fake_run(task, plan, store, policy, **kw):
        return {
            "status": "error",
            "reason": "Gmail 500. Calendar event already created.",
            "event_id": "evt_partial",
            "violations": [],
        }

    monkeypatch.setattr(driver_mod, "run", _fake_run)
    plan = {"steps": [{"tool": "schedule_meeting", "args": {
        "attendee": "a@corp.com", "event_title": "Sync",
        "reply_subject": "Re", "slots_slot": "s",
    }}]}
    result = asyncio.run(run_manifest("t", plan))
    assert result["status"] == "error"
    assert result["do_not_retry"] is True
    assert result["event_id"] == "evt_partial"


def test_schedule_meeting_gmail_fail_after_calendar_includes_event_id(monkeypatch):
    """Machine-readable event_id on partial failure — not prose-only."""
    from safehouse.driver import _handle_schedule_meeting, GmailSendError

    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({
        "attendee": "alice@corp.com",
        "event_title": "Sync",
        "reply_subject": "Re: Sync",
    }, Label.T_pub()))
    store.create("meeting_proposal")
    store.write("meeting_proposal", json.dumps({
        "proposed_slots": [{
            "label": "Tue 10:00",
            "start": "2026-07-14T10:00:00+01:00",
            "end": "2026-07-14T10:30:00+01:00",
        }],
        "reply_body": "Shall we meet?",
    }), Label.U_pub())

    class _Resp:
        status_code = 200
        def json(self):
            return {"id": "evt_created", "htmlLink": "https://cal.example/e"}

    class _Client:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, *a, **k):
            return _Resp()

    async def _boom(*a, **k):
        raise GmailSendError("gmail down")

    async def _confirm(slots):
        return 1

    monkeypatch.setattr("safehouse.driver.httpx.AsyncClient", lambda **k: _Client())
    monkeypatch.setattr(driver_mod, "_gmail_send", _boom)

    ctx = _StepContext(
        store=store, policy=IronFlow(store), driver=driver_spec(),
        state=state, config=ProviderConfig(google_token="tok"),
        confirm_slot=_confirm,
    )
    _, final = asyncio.run(_handle_schedule_meeting({
        "slots_slot": "meeting_proposal",
    }, ctx))
    assert final["status"] == "error"
    assert final["event_id"] == "evt_created"
    assert "Do not retry" in final["reason"]


# ── run_task end-to-end with a pipelines plan (mocked) ───────────────

def _pipelines_plan():
    return {"pipelines": [
        {"steps": [{"tool": "send_summary", "args": {
            "recipient": "a@corp.com", "subject": "S1", "body_slot": "b1",
        }}]},
        {"steps": [{"tool": "send_summary", "args": {
            "recipient": "b@corp.com", "subject": "S2", "body_slot": "b2",
        }}]},
    ]}


def _run_cfg(tmp_path, settings=None):
    from safehouse_cli.config import RunConfig
    from safehouse_cli.settings import Settings
    return RunConfig.from_args(
        ["--task", "t", "--non-interactive", "--approve", "deny",
         "--results-dir", str(tmp_path)],
        settings=settings or Settings(),
    )


def test_run_task_pipelines_fresh_state_per_pipeline(tmp_path, monkeypatch):
    """
    run_task with {"pipelines": [...]} delegates to driver_run_manifest with the
    full plan. State isolation is an invariant of driver.run_manifest, not app.py.
    """
    from unittest.mock import patch
    from safehouse_cli.app import ExitCode, run_task
    from safehouse_cli.interaction import DenyConfirmer

    manifest_calls: list[dict] = []
    plan = _pipelines_plan()

    async def _fake_manifest(task, received_plan, **kw):
        manifest_calls.append({"plan": received_plan})
        return {
            "status": "success", "violations": [],
            "actions": [
                {"status": "success", "labels": {"recipient": "(T,pub)"}},
                {"status": "success", "labels": {"recipient": "(T,pub)"}},
            ],
        }

    with patch("safehouse_cli.app.generate_plan", return_value=plan), \
         patch("safehouse_cli.app.driver_run_manifest", new=_fake_manifest), \
         patch("safehouse_cli.app._tracer_mod.pipeline_needs_google", return_value=False):
        result = asyncio.run(run_task(_run_cfg(tmp_path), DenyConfirmer()))

    assert len(manifest_calls) == 1
    assert manifest_calls[0]["plan"] is plan
    assert result.exit_code == ExitCode.OK
    assert result.detail["status"] == "success"
    assert len(result.detail["actions"]) == 2


def test_run_task_pipelines_partial_failure(tmp_path):
    """One pipeline fails → aggregate 'partial', exit PIPELINE_ERROR."""
    from unittest.mock import patch
    from safehouse_cli.app import ExitCode, run_task
    from safehouse_cli.interaction import DenyConfirmer

    async def _fake(task, plan, **kw):
        return {
            "status": "partial", "violations": [],
            "actions": [{"status": "success"}, {"status": "error", "reason": "fail"}],
        }

    with patch("safehouse_cli.app.generate_plan", return_value=_pipelines_plan()), \
         patch("safehouse_cli.app.driver_run_manifest", new=_fake), \
         patch("safehouse_cli.app._tracer_mod.pipeline_needs_google", return_value=False):
        result = asyncio.run(run_task(_run_cfg(tmp_path), DenyConfirmer()))

    assert result.detail["status"] == "partial"
    assert result.exit_code == ExitCode.PIPELINE_ERROR


def test_run_task_pipelines_all_failed(tmp_path):
    """All pipelines fail → aggregate 'error', exit PIPELINE_ERROR."""
    from unittest.mock import patch
    from safehouse_cli.app import ExitCode, run_task
    from safehouse_cli.interaction import DenyConfirmer

    async def _fake(task, plan, **kw):
        return {
            "status": "error", "violations": [],
            "actions": [{"status": "error", "reason": "fail"}, {"status": "error", "reason": "fail"}],
        }

    with patch("safehouse_cli.app.generate_plan", return_value=_pipelines_plan()), \
         patch("safehouse_cli.app.driver_run_manifest", new=_fake), \
         patch("safehouse_cli.app._tracer_mod.pipeline_needs_google", return_value=False):
        result = asyncio.run(run_task(_run_cfg(tmp_path), DenyConfirmer()))

    assert result.detail["status"] == "error"
    assert result.exit_code == ExitCode.PIPELINE_ERROR


# ── B3 regression: distinct-content/same-recipient pipelines must pass ─

def test_precheck_allows_distinct_content_same_recipient():
    """Same driver tool + same recipient is fine if step content differs (e.g. different URL)."""
    plan = {"pipelines": [
        {"steps": [
            {"tool": "mcp_page_content", "args": {"url": "https://a.com", "capability": "WEB_FETCH", "slot_id": "c1"}},
            {"tool": "send_summary", "args": {"recipient": "alice@corp.com", "subject": "Page A", "body_slot": "c1"}},
        ]},
        {"steps": [
            {"tool": "mcp_page_content", "args": {"url": "https://b.com", "capability": "WEB_FETCH", "slot_id": "c2"}},
            {"tool": "send_summary", "args": {"recipient": "alice@corp.com", "subject": "Page B", "body_slot": "c2"}},
        ]},
    ]}
    _precheck_shape(plan)   # must not raise


def test_precheck_rejects_truly_identical_pipelines():
    """Pipelines with identical steps (same URL, same recipient) are duplicate."""
    sub = {"steps": [
        {"tool": "mcp_page_content", "args": {"url": "https://a.com", "capability": "WEB_FETCH", "slot_id": "c"}},
        {"tool": "send_summary", "args": {"recipient": "alice@corp.com", "subject": "S", "body_slot": "c"}},
    ]}
    with pytest.raises(ValueError, match="duplicate"):
        _precheck_shape({"pipelines": [sub, sub]})


# ── B4 regression: partial+violation → exit code POLICY_VIOLATION ──────

def test_to_run_result_partial_with_violation_maps_to_policy_violation(tmp_path):
    from safehouse_cli.app import ExitCode, RunResult, _to_run_result
    from safehouse_cli.logging_io import Session
    session = Session.new(tmp_path)
    result = _to_run_result(
        {"status": "partial", "violations": [{"gate": "IPI_BLOCK"}], "actions": []},
        session, 0.1,
    )
    assert result.exit_code == ExitCode.POLICY_VIOLATION


# ── B4 regression: ConfirmationRequired propagates to exit code 5 ──────

def test_confirmation_required_maps_to_exit5(tmp_path):
    from unittest.mock import patch
    from safehouse_cli.app import ExitCode, run_task
    from safehouse_cli.interaction import DenyConfirmer
    from safehouse.exceptions import ConfirmationRequired

    async def _fake(task, plan, **kw):
        raise ConfirmationRequired("please confirm")

    with patch("safehouse_cli.app.generate_plan", return_value=_pipelines_plan()), \
         patch("safehouse_cli.app.driver_run_manifest", new=_fake), \
         patch("safehouse_cli.app._tracer_mod.pipeline_needs_google", return_value=False):
        result = asyncio.run(run_task(_run_cfg(tmp_path), DenyConfirmer()))

    assert result.exit_code == ExitCode.CONFIRMATION_REQUIRED


def test_run_task_emits_one_static_plan_for_pipelines(tmp_path, monkeypatch):
    """Multi-pipeline manifests emit a single EvStaticPlan with all steps flattened."""
    import json
    from unittest.mock import patch
    from safehouse_cli.app import ExitCode, run_task
    from safehouse_cli.interaction import DenyConfirmer

    async def _fake(task, plan, **kw):
        return {
            "status": "success", "violations": [],
            "actions": [{"status": "success"}, {"status": "success"}],
        }

    with patch("safehouse_cli.app.generate_plan", return_value=_pipelines_plan()), \
         patch("safehouse_cli.app.driver_run_manifest", new=_fake), \
         patch("safehouse_cli.app._tracer_mod.pipeline_needs_google", return_value=False):
        result = asyncio.run(run_task(_run_cfg(tmp_path), DenyConfirmer()))

    assert result.exit_code == ExitCode.OK
    events = [
        json.loads(line)
        for line in result.session.jsonl_path.read_text().splitlines()
        if line.strip()
    ]
    static = [e for e in events if e.get("event") == "EvStaticPlan"]
    assert len(static) == 1
    assert len(static[0]["steps"]) == 2
    assert {s["pipeline"] for s in static[0]["steps"]} == {0, 1}


# ── Lock-before-first-step: EvRoutingLocked precedes EvDriverStart ─────

def test_routing_locked_emitted_before_driver_start():
    """All EvRoutingLocked events appear before any EvPlanStep in the trace."""
    from safehouse.driver import run_manifest
    from safehouse.labels import Label, LVal
    from safehouse.plan_types import PlanState

    tr = _ListTracer()
    _trace.set_tracer(tr)
    try:
        plan = {"pipelines": [
            {"steps": [{"tool": "send_summary", "args": {
                "recipient": "a@corp.com", "subject": "S1", "body_slot": "b1",
            }}]},
            {"steps": [{"tool": "send_summary", "args": {
                "recipient": "b@corp.com", "subject": "S2", "body_slot": "b2",
            }}]},
        ]}
        asyncio.run(run_manifest("t", plan))
    finally:
        _trace.set_tracer(Tracer())

    routing_locked_indices = [i for i, e in enumerate(tr.events) if isinstance(e, _trace.EvRoutingLocked)]
    plan_step_indices      = [i for i, e in enumerate(tr.events) if isinstance(e, _trace.EvPlanStep)]

    assert routing_locked_indices, "no EvRoutingLocked events emitted"
    if plan_step_indices:
        assert max(routing_locked_indices) < min(plan_step_indices), (
            "EvRoutingLocked must all precede the first EvPlanStep"
        )
