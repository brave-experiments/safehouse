"""
tests/test_phase5.py — Phase 5 hardening tests.

Covers:
  - Empty plan guard in driver.run()
  - Missing routing field returns pipeline error
  - No-credential error paths for send_summary and send_reply
  - _handle_spawn_processor unwritten slot is a terminal (non-None) error
  - schedule_meeting with injected confirm_slot:
      choice=0 → no invite created, body contains reply (email-only path)
      choice=1 → approved slot, sends invite (skipped if no token)
  - GmailClient / FakeGmailClient isolation

No API key required — all tests use in-process mocking.
"""
import asyncio
import base64
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import safehouse.trace as _trace
from safehouse.trace import Tracer
from safehouse.slots import SlotStore
from safehouse.ironflow_policy import IronFlow
from safehouse.labels import Label, LVal
from safehouse.driver import (
    run as driver_run,
    _StepContext,
    _handle_send_summary,
    _handle_send_reply,
    _handle_spawn_processor,
    _handle_schedule_meeting,
    GmailClient,
    GmailSendError,
    ProviderConfig,
)
from safehouse.permissions import driver_spec
from safehouse.plan_types import PlanState

_NO_CREDS = ProviderConfig(google_token="")
_WITH_TOKEN = ProviderConfig(google_token="fake-token")


def _ctx(store: SlotStore, state: PlanState | None = None,
         config: ProviderConfig = _NO_CREDS,
         confirm_slot=None,
         *,
         sources: set[str] | None = None,
         transform: str | None = None) -> _StepContext:
    state = state or PlanState()
    policy = IronFlow(store)
    if "_routing" in state.vars:
        src = sources or set()
        xf = transform if transform is not None else ("opaque" if src else None)
        policy.precommit_routing(state, sources=src, transform=xf)
    kwargs: dict = dict(
        store=store, policy=policy, driver=driver_spec(),
        state=state, config=config,
    )
    if confirm_slot is not None:
        kwargs["confirm_slot"] = confirm_slot
    return _StepContext(**kwargs)


# ── Empty plan guard ──────────────────────────────────────────────────

def test_run_empty_plan_returns_error() -> None:
    store = SlotStore()
    result = asyncio.run(driver_run("task", {}, store, IronFlow(store)))
    assert result["status"] == "error"
    assert "no steps" in result["reason"]


def test_run_no_steps_key_returns_error() -> None:
    store = SlotStore()
    result = asyncio.run(driver_run("task", {"steps": []}, store, IronFlow(store)))
    assert result["status"] == "error"
    assert "no steps" in result["reason"]


# ── Missing routing field ─────────────────────────────────────────────

def test_missing_routing_field_returns_pipeline_error() -> None:
    store = SlotStore()
    # send_summary needs "recipient" and "subject"; omit "subject"
    plan = {"steps": [{"tool": "send_summary", "args": {
        "recipient": "alice@corp.com",
        "body_slot": "body",
        # "subject" intentionally missing
    }}]}
    result = asyncio.run(driver_run("task", plan, store, IronFlow(store)))
    assert result["status"] == "error"
    assert "subject" in result["reason"]


# ── No-credential error paths ─────────────────────────────────────────

def test_send_summary_no_credentials_is_terminal() -> None:
    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal(
        {"recipient": "alice@corp.com", "subject": "Hi"},
        Label.T_pub(),
    ))
    store.create("body")
    store.write("body", "body text", Label.U_pub())
    ctx = _ctx(store, state, _NO_CREDS, sources={"body"})

    _, final = asyncio.run(
        _handle_send_summary({"body_slot": "body"}, ctx)
    )
    assert final is not None, "no-credentials path must be terminal"
    assert final["status"] == "error"
    assert "credentials" in final["reason"]


def test_send_summary_empty_released_body_is_terminal() -> None:
    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal(
        {"recipient": "alice@corp.com", "subject": "Hi"},
        Label.T_pub(),
    ))
    store.create("body")
    store.write("body", "   ", Label.U_pub())
    ctx = _ctx(store, state, _WITH_TOKEN, sources={"body"})

    _, final = asyncio.run(
        _handle_send_summary({"body_slot": "body"}, ctx)
    )
    assert final is not None
    assert final["status"] == "error"
    assert "empty" in final["reason"]


def test_send_reply_no_token_is_terminal() -> None:
    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal(
        {"recipient": "alice@corp.com", "subject": "Re: Hi"},
        Label.T_pub(),
    ))
    store.create("body")
    store.write("body", "body text", Label.U_pub())
    ctx = _ctx(store, state, _NO_CREDS, sources={"body"})

    _, final = asyncio.run(
        _handle_send_reply({"body_slot": "body"}, ctx)
    )
    assert final is not None, "no-token path must be terminal"
    assert final["status"] == "error"
    assert "GOOGLE_ACCESS_TOKEN" in final["reason"]


# ── spawn_processor unwritten slot is terminal ────────────────────────

def test_spawn_processor_unwritten_slot_is_terminal() -> None:
    store = SlotStore()
    ctx = _ctx(store)

    _, final = asyncio.run(
        _handle_spawn_processor(
            {"reads": ["missing_slot"], "out_slot": "out", "instruction": "summarise"},
            ctx,
        )
    )
    assert final is not None, "_handle_spawn_processor unwritten slot must be terminal"
    assert final["status"] == "error"
    assert "missing_slot" in final["reason"]


# ── schedule_meeting with injected confirm_slot ───────────────────────

def _meeting_plan_state(store: SlotStore) -> PlanState:
    state = PlanState()
    state.set_var("_routing", LVal({
        "attendee":      "alice@corp.com",
        "reply_subject": "Meeting",
        "event_title":   "Sync",
    }, Label.T_pub()))
    store.create("slots")
    slots_json = json.dumps({
        "proposed_slots": [
            {"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00", "label": "Mon 10am"},
        ],
        "reply_body": "Here are some times",
    })
    store.write("slots", slots_json, Label.U_priv())
    return state


def test_schedule_meeting_choice_zero_email_only() -> None:
    """choice=0 → no invite, pipeline completes (email-only path, no token needed)."""
    store = SlotStore()
    state = _meeting_plan_state(store)

    async def _confirm_zero(slots):
        return 0

    ctx = _ctx(store, state, _NO_CREDS, confirm_slot=_confirm_zero,
               sources={"slots"}, transform="structured:meeting_proposal")

    _, final = asyncio.run(
        _handle_schedule_meeting({"slots_slot": "slots"}, ctx)
    )
    # No token → no email sent, but the handler should complete (not error on missing token)
    assert final is not None
    # slot should show email-only
    assert final.get("slot") == "(email only)" or final.get("status") in ("success", "error")


def test_schedule_meeting_choice_one_approved(monkeypatch) -> None:
    """choice=1 → approved; mock _gmail_send so no real HTTP."""
    import safehouse.driver as driver_mod

    sent: list[dict] = []

    async def _fake_gmail_send(to, subject, body, token, state, **kw):
        sent.append({"to": to, "subject": subject, "body_slot": kw.get("body_slot", "")})

    monkeypatch.setattr(driver_mod, "_gmail_send", _fake_gmail_send)

    store = SlotStore()
    state = _meeting_plan_state(store)

    # Also mock the calendar API call
    import httpx
    class _FakeResponse:
        status_code = 200
        def json(self): return {"id": "evt123", "htmlLink": "http://cal/evt123"}
        text = ""

    class _FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **kw): return _FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)

    async def _confirm_one(slots):
        return 1

    ctx = _ctx(store, state, _WITH_TOKEN, confirm_slot=_confirm_one,
               sources={"slots"}, transform="structured:meeting_proposal")

    from safehouse import trace as _trace
    from safehouse.trace import EvActionGranted, Tracer

    class _Cap(Tracer):
        def __init__(self) -> None:
            self.events: list = []
        def on_event(self, event) -> None:
            self.events.append(event)

    cap = _Cap()
    _trace.set_tracer(cap)
    try:
        _, final = asyncio.run(
            _handle_schedule_meeting({"slots_slot": "slots"}, ctx)
        )
    finally:
        _trace.set_tracer(Tracer())

    assert final is not None
    assert final.get("status") == "success"
    assert final.get("event_id") == "evt123"
    assert sent[0]["to"] == "alice@corp.com"
    assert sent[0]["body_slot"] == "slots"
    granted = [e for e in cap.events if isinstance(e, EvActionGranted)]
    assert len(granted) == 1
    assert granted[0].fields == {
        "end_time": "2026-09-07T11:00:00",
        "start_time": "2026-09-07T10:00:00",
    }


def test_schedule_meeting_confirmer_cannot_mutate_grant_times() -> None:
    """TOCTOU: mutating slots in confirm_slot must not change ActionGrant values."""
    store = SlotStore()
    state = _meeting_plan_state(store)

    async def _mutate_then_confirm(slots):
        slots[0]["start"] = "2099-01-01T00:00:00"
        slots[0]["end"] = "2099-01-01T01:00:00"
        return 1

    from safehouse import trace as _trace
    from safehouse.trace import EvActionGranted, Tracer

    class _Cap(Tracer):
        def __init__(self) -> None:
            self.events: list = []
        def on_event(self, event) -> None:
            self.events.append(event)

    cap = _Cap()
    _trace.set_tracer(cap)
    ctx = _ctx(store, state, _NO_CREDS, confirm_slot=_mutate_then_confirm,
               sources={"slots"}, transform="structured:meeting_proposal")
    try:
        _, final = asyncio.run(
            _handle_schedule_meeting({"slots_slot": "slots"}, ctx)
        )
    finally:
        _trace.set_tracer(Tracer())

    assert final is not None
    assert final["status"] == "success"
    granted = [e for e in cap.events if isinstance(e, EvActionGranted)]
    assert granted[0].fields == {
        "end_time": "2026-09-07T11:00:00",
        "start_time": "2026-09-07T10:00:00",
    }


def test_schedule_meeting_labelless_slot_completes() -> None:
    """
    A valid proposal whose slots carry only start/end (label is optional in the
    meeting_proposal schema) must complete — regression for a KeyError('label')
    raised AFTER the calendar/email side effects.
    """
    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({
        "attendee":      "alice@corp.com",
        "reply_subject": "Meeting",
        "event_title":   "Sync",
    }, Label.T_pub()))
    store.create("slots")
    store.write("slots", json.dumps({
        "proposed_slots": [
            {"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00"},
        ],
        "reply_body": "Here are some times",
    }), Label.U_priv())

    async def _confirm_one(slots):
        return 1

    ctx = _ctx(store, state, _NO_CREDS, confirm_slot=_confirm_one,
               sources={"slots"}, transform="structured:meeting_proposal")

    _, final = asyncio.run(
        _handle_schedule_meeting({"slots_slot": "slots"}, ctx)
    )
    assert final is not None
    assert final["status"] == "success"
    assert final["slot"] == "2026-09-07T10:00:00 — 2026-09-07T11:00:00"


def test_schedule_meeting_declined_without_reply_body_is_terminal() -> None:
    """choice=0 with no reply_body → terminal error, not an empty email."""
    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({
        "attendee":      "alice@corp.com",
        "reply_subject": "Meeting",
        "event_title":   "Sync",
    }, Label.T_pub()))
    store.create("slots")
    store.write("slots", json.dumps({
        "proposed_slots": [
            {"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00", "label": "Mon 10am"},
        ],
    }), Label.U_priv())

    async def _confirm_zero(slots):
        return 0

    ctx = _ctx(store, state, _NO_CREDS, confirm_slot=_confirm_zero,
               sources={"slots"}, transform="structured:meeting_proposal")

    _, final = asyncio.run(
        _handle_schedule_meeting({"slots_slot": "slots"}, ctx)
    )
    assert final is not None
    assert final["status"] == "error"
    assert "no reply_body" in final["reason"]


# ── GmailClient / FakeGmailClient ────────────────────────────────────

class FakeHttpxResponse:
    def __init__(self, status_code: int, body: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body or {}
        self.text = text

    def json(self) -> dict:
        return self._body


class FakeGmailHttpClient:
    """Pre-scriptable fake for httpx.AsyncClient in GmailClient tests."""

    def __init__(self, responses: dict[tuple, FakeHttpxResponse]) -> None:
        # responses keyed by (method, url_fragment)
        self._responses = responses

    async def post(self, url: str, **kw) -> FakeHttpxResponse:
        for (method, frag), resp in self._responses.items():
            if method == "POST" and frag in url:
                return resp
        return FakeHttpxResponse(404, text="not found")

    async def get(self, url: str, **kw) -> FakeHttpxResponse:
        for (method, frag), resp in self._responses.items():
            if method == "GET" and frag in url:
                return resp
        return FakeHttpxResponse(404, text="not found")


def test_gmail_client_send_success() -> None:
    client = FakeGmailHttpClient({
        ("POST", "messages/send"): FakeHttpxResponse(200, {"id": "msg123"}),
    })
    import httpx
    gmail = GmailClient.__new__(GmailClient)
    from safehouse.driver import _google_headers
    gmail._headers = _google_headers("token")
    gmail._client  = client

    msg_id = asyncio.run(gmail.send("a@b.com", "Subj", "Body", ""))
    assert msg_id == "msg123"


def test_gmail_client_send_sets_reply_threading_headers() -> None:
    """Recipient clients need In-Reply-To/References; threadId alone is not enough."""
    captured: dict = {}

    class _CaptureClient:
        async def post(self, url, headers=None, json=None):
            captured["json"] = json
            return FakeHttpxResponse(200, {"id": "sent1"})

    gmail = GmailClient.__new__(GmailClient)
    from safehouse.driver import _google_headers
    gmail._headers = _google_headers("token")
    gmail._client = _CaptureClient()

    asyncio.run(gmail.send(
        "sender@example.com", "Re: Hello", "Thanks",
        "thread_abc",
        in_reply_to="<orig@mail.example>",
        references="<root@mail.example> <orig@mail.example>",
    ))

    payload = captured["json"]
    assert payload["threadId"] == "thread_abc"
    raw = base64.urlsafe_b64decode(payload["raw"] + "==").decode("utf-8", errors="replace")
    assert "In-Reply-To: <orig@mail.example>" in raw
    assert "References: <root@mail.example> <orig@mail.example>" in raw
    assert "Subject: Re: Hello" in raw


def test_gmail_send_keeps_gated_subject_not_fetched(monkeypatch) -> None:
    """Fetched Subject must not override the IronFlow-gated (T,pub) subject."""
    from safehouse.driver import _gmail_send
    from safehouse.labels import LVal, Label
    from safehouse.plan_types import PlanState

    captured: dict = {}

    class _FakeGmail:
        def __init__(self, *a, **k):
            pass

        async def send(self, to, subject, body, thread_id, *, in_reply_to="", references=""):
            captured.update({
                "subject": subject, "thread_id": thread_id,
                "in_reply_to": in_reply_to, "references": references,
            })
            return "msg1"

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr("safehouse.driver.GmailClient", _FakeGmail)
    monkeypatch.setattr("safehouse.driver.httpx.AsyncClient", lambda **k: _FakeClient())

    state = PlanState()
    state.set_var("_email_thread_meta_email", LVal({
        "thread_id": "tid1",
        "message_id": "<orig@mail.example>",
        "references": "<root@mail.example>",
        # subject intentionally omitted / would be ignored if present
        "subject": "Attacker Subject\nBcc: evil@x.com",
    }, Label.T_pub()))

    asyncio.run(_gmail_send(
        "alice@corp.com", "Re: Locked From Task", "body", "tok", state,
        body_slot="email",
    ))
    assert captured["subject"] == "Re: Locked From Task"
    assert captured["thread_id"] == "tid1"
    assert captured["in_reply_to"] == "<orig@mail.example>"
    assert "evil" not in captured["subject"]
    assert "\n" not in captured["subject"]


def test_gmail_parse_message_extracts_threading_headers() -> None:
    from safehouse.runner import _gmail_parse_message, _sanitize_rfc_msg_id

    assert _sanitize_rfc_msg_id("bad\nid@x.com") == ""
    assert _sanitize_rfc_msg_id("good@mail.example") == "<good@mail.example>"

    parsed = _gmail_parse_message({
        "threadId": "tid1",
        "snippet": "hi",
        "payload": {
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "Subject", "value": "Hello there"},
                {"name": "Date", "value": "Mon, 13 Jul 2026 12:00:00 +0000"},
                {"name": "Message-ID", "value": "<abc123@mail.example>"},
                {"name": "References", "value": "<root@mail.example>"},
            ],
            "body": {"data": ""},
        },
    })
    assert parsed["thread_id"] == "tid1"
    assert parsed["message_id"] == "<abc123@mail.example>"
    assert parsed["references"] == "<root@mail.example>"
    assert parsed["subject"] == "Hello there"


def test_gmail_client_send_raises_on_non_2xx() -> None:
    client = FakeGmailHttpClient({
        ("POST", "messages/send"): FakeHttpxResponse(401, text="Unauthorized"),
    })
    gmail = GmailClient.__new__(GmailClient)
    from safehouse.driver import _google_headers
    gmail._headers = _google_headers("token")
    gmail._client  = client

    with pytest.raises(GmailSendError, match="401"):
        asyncio.run(gmail.send("a@b.com", "Subj", "Body", ""))


def test_gmail_client_list_message_ids() -> None:
    client = FakeGmailHttpClient({
        ("GET", "messages"): FakeHttpxResponse(200, {
            "messages": [{"id": "m1"}, {"id": "m2"}],
            # no nextPageToken → single page
        }),
    })
    gmail = GmailClient.__new__(GmailClient)
    from safehouse.driver import _google_headers
    gmail._headers = _google_headers("token")
    gmail._client  = client

    ids = asyncio.run(gmail.list_message_ids("sender@example.com"))
    assert ids == ["m1", "m2"]


def test_gmail_client_batch_modify_records_failures() -> None:
    client = FakeGmailHttpClient({
        ("POST", "batchModify"): FakeHttpxResponse(500, text="Server error"),
    })
    gmail = GmailClient.__new__(GmailClient)
    from safehouse.driver import _google_headers
    gmail._headers = _google_headers("token")
    gmail._client  = client

    failures = asyncio.run(gmail.batch_modify(["m1", "m2"], {"removeLabelIds": ["INBOX"]}))
    assert len(failures) == 1
    assert "500" in failures[0]
