"""
tests/test_multi_recipient.py — multiple recipients / attendees.

Security core: every address must appear verbatim in the task (AXIOM), so a list
cannot smuggle in an address the operator never named; the whole list is locked
(T,pub) — as an immutable tuple — before step 0, so fetched content can never add
to it.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

import safehouse.driver as driver_mod
import safehouse.trace as _trace
import tracer as _tracermod
from safehouse.driver import (
    GmailSendError, ProviderConfig, _StepContext, _addr_header, _addr_list,
    _handle_schedule_meeting, _handle_send_summary, run as driver_run,
)
from safehouse.ironflow_policy import IronFlow
from safehouse.labels import Label, LVal
from safehouse.permissions import driver_spec
from safehouse.plan_types import PlanState
from safehouse.planner import (
    PlanValidationError, _MISSING_RECIPIENT_SIGNAL, _recipient_recovery_field,
    _validate_plan, build_planner_system_prompt,
)
from safehouse.slots import SlotStore
from safehouse.trace import Tracer


def _precommitted_policy(
    store: SlotStore, state: PlanState, *, sources: set[str], transform: str,
) -> IronFlow:
    policy = IronFlow(store)
    policy.precommit_routing(state, sources=sources, transform=transform)
    return policy


def _plan(recipient):
    return {"steps": [
        {"tool": "mcp_page_content", "args": {"url": "https://example.com", "capability": "WEB_FETCH", "slot_id": "c"}},
        {"tool": "spawn_processor", "args": {"instruction": "x", "reads": ["c"], "out_slot": "s"}},
        {"tool": "send_summary", "args": {"recipient": recipient, "subject": "Briefing", "body_slot": "s"}},
    ]}


def _reply_plan(recipient):
    return {"steps": [
        {"tool": "mcp_page_content", "args": {"url": "https://example.com", "capability": "WEB_FETCH", "slot_id": "draft"}},
        {"tool": "send_reply", "args": {"recipient": recipient, "subject": "Re", "body_slot": "draft"}},
    ]}


# ── AXIOM: every element must appear verbatim in the task ──────────────

def test_recipient_list_all_verbatim_passes():
    _validate_plan(_plan(["alice@example.com", "bob@example.com"]),
                   task="email a briefing to alice@example.com and bob@example.com")


def test_recipient_list_one_not_in_task_rejected():
    with pytest.raises(PlanValidationError, match="AXIOM"):
        _validate_plan(_plan(["alice@example.com", "attacker@evil.com"]),
                       task="email a briefing to alice@example.com")


def test_recipient_list_invalid_email_rejected():
    with pytest.raises(PlanValidationError, match="valid email"):
        _validate_plan(_plan(["alice@example.com", "not-an-email"]),
                       task="email alice@example.com and not-an-email")


def test_recipient_empty_list_rejected():
    with pytest.raises((PlanValidationError, ValueError)):
        _validate_plan(_plan([]), task="anything")


def test_recipient_single_string_backward_compat():
    _validate_plan(_plan("alice@example.com"), task="email alice@example.com")


def test_recipient_list_boundary_collision_rejected():
    with pytest.raises(PlanValidationError, match="AXIOM"):
        _validate_plan(_plan(["a@b.com"]), task="send to attacker-a@b.com")


# ── F3: send_reply is capped at one recipient ─────────────────────────

def test_send_reply_rejects_multiple_recipients():
    with pytest.raises(PlanValidationError, match="at most 1"):
        _validate_plan(_reply_plan(["a@example.com", "b@example.com"]),
                       task="reply to a@example.com and b@example.com")


def test_send_reply_single_recipient_ok():
    _validate_plan(_reply_plan("a@example.com"), task="reply to a@example.com")


# ── F4: comma in an address is rejected (would split on the wire) ─────

def test_comma_in_address_rejected():
    with pytest.raises(PlanValidationError, match="valid email"):
        _validate_plan(_plan("alice,bob@example.com"), task="email alice,bob@example.com")


# ── F5: sentence-final period after an address is fine; boundary holds ─

def test_trailing_period_passes_axiom():
    _validate_plan(_plan("alice@example.com"), task="please email alice@example.com.")


def test_boundary_still_rejects_substring():
    with pytest.raises(PlanValidationError, match="AXIOM"):
        _validate_plan(_plan("a@b.co"), task="send to a@b.co.uk only")


# ── F6: error classifier is exact-match and non-string safe ───────────

def test_classifier_exact_missing_signal():
    assert _recipient_recovery_field("missing routing field: recipient") == "recipient"


def test_classifier_other_recipient_error_is_none():
    assert _recipient_recovery_field("no tool matches; task names a recipient") is None


def test_classifier_nonstring_is_none():
    assert _recipient_recovery_field({"reason": "x"}) is None


# ── address helpers (F7/F8: tuple-aware + de-dup) ─────────────────────

def test_addr_list_normalizes_and_dedups():
    assert _addr_list("a@b.com") == ["a@b.com"]
    assert _addr_list(["a@b.com", "a@b.com", "c@d.com"]) == ["a@b.com", "c@d.com"]
    assert _addr_list(("a@b.com", "c@d.com")) == ["a@b.com", "c@d.com"]   # tuple accepted


def test_addr_header_joins():
    assert _addr_header(("a@b.com", "c@d.com", "a@b.com")) == "a@b.com, c@d.com"


def test_audit_scan_handles_list_and_tuple():
    assert not _tracermod._addrs_clean(["x@attacker.com"])
    assert not _tracermod._addrs_clean(("x@attacker.com",))
    assert _tracermod._addrs_clean(["a@example.com", "b@example.com"])
    assert _tracermod._addrs_clean("a@example.com")


# ── routing lock captures the list as an immutable (T,pub) tuple ──────

class _ListTracer(Tracer):
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


def test_routing_lock_captures_recipient_list_as_tuple():
    tr = _ListTracer()
    _trace.set_tracer(tr)
    try:
        recips = ["alice@example.com", "bob@example.com"]
        plan = {"steps": [{"tool": "send_summary", "args": {
            "recipient": recips, "subject": "Digest", "body_slot": "body",
        }}]}
        store = SlotStore()
        asyncio.run(driver_run("t", plan, store, IronFlow(store)))
        recips.append("attacker@evil.com")   # F7: mutate the plan's list AFTER the lock
    finally:
        _trace.set_tracer(Tracer())
    locked = [e for e in tr.events if isinstance(e, _trace.EvRoutingLocked)]
    assert len(locked) == 1
    assert locked[0].routing["recipient"] == ("alice@example.com", "bob@example.com")   # tuple, immutable
    assert "attacker@evil.com" not in locked[0].routing["recipient"]


# ── F1: multi-attendee schedule_meeting executes (no _declassify crash) ─

def test_schedule_meeting_multi_attendee_e2e(monkeypatch):
    sent = {}

    async def _fake_send(to, subject, body, token, state, **kw):
        sent["to"] = to
        sent["body_slot"] = kw.get("body_slot", "")
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake_send)

    cal = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"id": "evt1", "htmlLink": "http://cal/evt1"}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, headers=None, json=None):
            cal["attendees"] = json["attendees"]
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({                       # attendee locked as a tuple by run()
        "attendee": ("alice@example.com", "bob@example.com"),
        "reply_subject": "Meeting", "event_title": "Sync",
    }, Label.T_pub()))
    store.create("slots")
    store.write("slots", json.dumps({
        "proposed_slots": [{"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00", "label": "Mon 10am"}],
        "reply_body": "times",
    }), Label.U_priv())

    async def _confirm_one(slots):
        return 1

    ctx = _StepContext(
        store=store,
        policy=_precommitted_policy(store, state, sources={"slots"},
                                    transform="structured:meeting_proposal"),
        driver=driver_spec(),
        state=state,
        config=ProviderConfig(google_token="tok"),
        confirm_slot=_confirm_one,
    )
    _, final = asyncio.run(_handle_schedule_meeting({"slots_slot": "slots"}, ctx))

    assert final["status"] == "success"
    assert cal["attendees"] == [{"email": "alice@example.com"}, {"email": "bob@example.com"}]   # per-attendee
    assert sent["to"] == "alice@example.com, bob@example.com"                                    # joined To:
    assert sent["body_slot"] == "slots"   # thread into meeting-request email via slots_slot


# ── "separate emails" delivery mode ───────────────────────────────────

def test_delivery_separate_validates():
    p = _plan(["a@example.com", "b@example.com"])
    p["steps"][-1]["args"]["delivery"] = "separate"
    _validate_plan(p, task="email a@example.com and b@example.com separately")


def test_delivery_mode_must_be_valid():
    p = _plan("a@example.com")
    p["steps"][-1]["args"]["delivery"] = "bogus"
    with pytest.raises(PlanValidationError, match="delivery"):
        _validate_plan(p, task="email a@example.com")


def _summary_ctx(recipients):
    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({"recipient": recipients, "subject": "S"}, Label.T_pub()))
    store.create("body")
    store.write("body", "summary text", Label.U_pub())
    ctx = _StepContext(store=store, policy=_precommitted_policy(store, state, sources={"body"},
                       transform="opaque"),
                       driver=driver_spec(),
                       state=state, config=ProviderConfig(google_token="tok"))
    return ctx


def test_send_summary_separate_one_per_recipient(monkeypatch):
    tos = []

    async def _fake(to, subject, body, token, state):
        tos.append(to)
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake)

    ctx = _summary_ctx(("alice@example.com", "bob@example.com"))
    _, final = asyncio.run(_handle_send_summary({"body_slot": "body", "delivery": "separate"}, ctx))
    assert final["status"] == "success"
    assert tos == ["alice@example.com", "bob@example.com"]        # one send each, no cross-visibility


def test_send_summary_combined_single_send(monkeypatch):
    tos = []

    async def _fake(to, subject, body, token, state):
        tos.append(to)
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake)

    ctx = _summary_ctx(("alice@example.com", "bob@example.com"))
    _, final = asyncio.run(_handle_send_summary({"body_slot": "body"}, ctx))   # no separate
    assert tos == ["alice@example.com, bob@example.com"]          # one combined message


def test_send_summary_separate_partial_failure_reports(monkeypatch):
    async def _fake(to, subject, body, token, state):
        if to == "bob@example.com":
            raise GmailSendError("boom")
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake)

    ctx = _summary_ctx(("alice@example.com", "bob@example.com"))
    _, final = asyncio.run(_handle_send_summary({"body_slot": "body", "delivery": "separate"}, ctx))
    assert final["status"] == "error"
    assert "Already sent to ['alice@example.com']" in final["reason"]
    assert "Do not retry" in final["reason"]
    assert final["sent"] == ["alice@example.com"]       # structured, not just prose
    assert final["unsent"] == ["bob@example.com"]


def test_missing_recipient_signal_pinned_in_prompt():
    # the classifier matches this exact string — the prompt must still emit it
    assert _MISSING_RECIPIENT_SIGNAL in build_planner_system_prompt()


# ── F1: modify_emails.sender must stay a string ───────────────────────

def _modify_plan(sender):
    return {"steps": [{"tool": "modify_emails", "args": {"sender": sender, "action": "archive"}}]}


def test_modify_emails_sender_list_rejected():
    with pytest.raises(PlanValidationError, match="must be a string"):
        _validate_plan(_modify_plan(["a@x.com", "b@x.com"]), task="archive emails from a@x.com and b@x.com")


def test_modify_emails_sender_string_ok():
    _validate_plan(_modify_plan("newsletters@x.com"), task="archive emails from newsletters@x.com")


# ── F2: address cap enforced on send_summary / schedule_meeting ───────

def test_send_summary_over_cap_rejected():
    addrs = [f"u{i}@example.com" for i in range(26)]
    task  = "email " + " and ".join(addrs)
    p = _plan(addrs)
    with pytest.raises(PlanValidationError, match="at most 25"):
        _validate_plan(p, task=task)


def test_send_summary_at_cap_ok():
    addrs = [f"u{i}@example.com" for i in range(25)]
    task  = "email " + " and ".join(addrs)
    _validate_plan(_plan(addrs), task=task)


# ── F3: _gmail_send body_slot (send_reply + schedule_meeting; not send_summary) ─

def test_send_reply_passes_thread_true(monkeypatch):
    import safehouse.driver as drv
    calls = {}

    async def _fake(to, subject, body, token, state, *, body_slot=""):
        calls["body_slot"] = body_slot
    monkeypatch.setattr(drv, "_gmail_send", _fake)

    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({"recipient": "a@example.com", "subject": "Re: hi"}, Label.T_pub()))
    store.create("body")
    store.write("body", "reply text", Label.U_pub())
    ctx = _StepContext(store=store, policy=_precommitted_policy(store, state, sources={"body"},
                       transform="opaque"),
                       driver=driver_spec(),
                       state=state, config=ProviderConfig(google_token="tok"))
    from safehouse.driver import _handle_send_reply
    asyncio.run(_handle_send_reply({"body_slot": "body"}, ctx))
    assert calls["body_slot"] == "body"


def test_schedule_meeting_passes_body_slot_for_threading(monkeypatch):
    """Meeting confirmation emails must thread into the fetched request email."""
    calls = {}

    async def _fake(to, subject, body, token, state, *, body_slot=""):
        calls["body_slot"] = body_slot
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake)

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

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    store = SlotStore()
    state = PlanState()
    state.set_var("_routing", LVal({
        "attendee": "alice@example.com", "reply_subject": "Re: Meeting",
        "event_title": "Sync",
    }, Label.T_pub()))
    store.create("meeting_proposal")
    store.write("meeting_proposal", json.dumps({
        "proposed_slots": [{"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00", "label": "Mon 10am"}],
        "reply_body": "times",
    }), Label.U_priv())

    async def _confirm_one(slots):
        return 1

    ctx = _StepContext(
        store=store,
        policy=_precommitted_policy(store, state, sources={"meeting_proposal"},
                                    transform="structured:meeting_proposal"),
        driver=driver_spec(),
        state=state,
        config=ProviderConfig(google_token="tok"),
        confirm_slot=_confirm_one,
    )
    asyncio.run(_handle_schedule_meeting({"slots_slot": "meeting_proposal"}, ctx))
    assert calls["body_slot"] == "meeting_proposal"


def test_send_summary_passes_thread_false(monkeypatch):
    calls = {}

    async def _fake(to, subject, body, token, state, *, body_slot=""):
        calls["body_slot"] = body_slot
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake)

    ctx = _summary_ctx(("a@example.com",))
    asyncio.run(_handle_send_summary({"body_slot": "body"}, ctx))
    assert calls["body_slot"] == ""


# ── F4: trace reconciles 1:1 with egress in separate mode ─────────────

def test_separate_mode_emits_one_action_fired_per_group(monkeypatch):
    async def _fake(to, subject, body, token, state, *, body_slot=""):
        pass
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake)

    tr = _ListTracer()
    _trace.set_tracer(tr)
    try:
        ctx = _summary_ctx(("a@example.com", "b@example.com", "c@example.com"))
        asyncio.run(_handle_send_summary({"body_slot": "body", "delivery": "separate"}, ctx))
    finally:
        _trace.set_tracer(Tracer())

    fired = [e for e in tr.events if isinstance(e, _trace.EvActionFired)]
    assert len(fired) == 3                    # one per group — trace reconciles with egress
    assert [e.recipient for e in fired] == ["a@example.com", "b@example.com", "c@example.com"]


# ── F7: casefolded dedup in _addr_list + duplicate rejection ──────────

def test_addr_list_casefolded_dedup():
    result = _addr_list(["Alice@Example.com", "alice@example.com", "BOB@example.com"])
    assert result == ["Alice@Example.com", "BOB@example.com"]   # first occurrence kept, lower-dup dropped


def test_validate_plan_rejects_case_duplicate():
    with pytest.raises(PlanValidationError, match="duplicate"):
        _validate_plan(_plan(["alice@example.com", "Alice@Example.com"]),
                       task="email alice@example.com and Alice@Example.com")
