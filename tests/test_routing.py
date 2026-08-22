"""
tests/test_routing.py — Routing lock and precommit gate tests.

Covers:
  - driver.run() pre-commits _routing before step 0 and emits EvRoutingLocked
  - _handle_send_summary fails closed when _routing is absent

No API key required — all tests use in-process mocking.
"""
import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import safehouse.trace as _trace
from safehouse.trace import Tracer
from safehouse.slots import SlotStore
from safehouse.ironflow_policy import IronFlow, IronFlowViolation
from safehouse.driver import (
    run as driver_run,
    _DRIVER_ROUTING_FIELDS,
    _StepContext,
    ProviderConfig,
)
from safehouse.release import DRIVER_RELEASE
from safehouse.plan_types import PlanState
from safehouse.permissions import driver_spec

_NO_CREDS = ProviderConfig(google_token="")


# ── Test tracer ───────────────────────────────────────────────────────

class _ListTracer(Tracer):
    def __init__(self) -> None:
        self.events: list = []

    def on_event(self, event: object) -> None:
        self.events.append(event)


# ── _DRIVER_ROUTING_FIELDS ────────────────────────────────────────────

def test_driver_routing_fields_covers_email_tools() -> None:
    for tool in ("send_summary", "send_reply", "schedule_meeting"):
        assert tool in _DRIVER_ROUTING_FIELDS, f"missing routing fields for {tool!r}"


def test_send_summary_routing_fields_correct() -> None:
    assert set(_DRIVER_ROUTING_FIELDS["send_summary"]) == {"recipient", "subject"}


def test_driver_release_slots_match_known_tools() -> None:
    assert DRIVER_RELEASE["send_summary"].slot_args == ("body_slot",)
    assert DRIVER_RELEASE["send_reply"].slot_args == ("body_slot",)
    assert DRIVER_RELEASE["schedule_meeting"].slot_args == ("slots_slot",)
    assert DRIVER_RELEASE["modify_emails"].slot_args == ()
    assert DRIVER_RELEASE["send_summary"].transform == "opaque"
    assert DRIVER_RELEASE["schedule_meeting"].transform == "structured:meeting_proposal"
    assert DRIVER_RELEASE["modify_emails"].transform is None


# ── driver.run() emits EvRoutingLocked before step 0 ─────────────────

def test_routing_lock_emitted_before_any_step() -> None:
    tracer = _ListTracer()
    _trace.set_tracer(tracer)
    try:
        plan = {"steps": [{"tool": "send_summary", "args": {
            "recipient": "alice@example.com",
            "subject": "Weekly digest",
            "body_slot": "body",
        }}]}
        store = SlotStore()
        asyncio.run(driver_run("test task", plan, store, IronFlow(store)))
    finally:
        _trace.set_tracer(Tracer())   # restore to null tracer

    locked = [e for e in tracer.events if isinstance(e, _trace.EvRoutingLocked)]
    assert len(locked) == 1, "expected exactly one EvRoutingLocked"
    assert locked[0].driver_tool == "send_summary"
    assert locked[0].routing["recipient"] == "alice@example.com"
    assert locked[0].routing["subject"] == "Weekly digest"

    # EvRoutingLocked must arrive before the first EvPlanStep
    plan_steps = [e for e in tracer.events if isinstance(e, _trace.EvPlanStep)]
    assert tracer.events.index(locked[0]) < tracer.events.index(plan_steps[0])
    precommit = [
        e for e in tracer.events
        if isinstance(e, _trace.EvGate) and e.gate == "PRECOMMIT" and e.passed
    ]
    assert len(precommit) == 1
    assert tracer.events.index(precommit[0]) < tracer.events.index(plan_steps[0])


def test_routing_lock_emitted_for_modify_emails() -> None:
    """modify_emails routing fields (sender, action) are pre-committed like all Tier 3 tools."""
    tracer = _ListTracer()
    _trace.set_tracer(tracer)
    try:
        plan = {"steps": [{"tool": "modify_emails", "args": {
            "sender": "newsletter@example.com",
            "action": "archive",
        }}]}
        store = SlotStore()
        asyncio.run(driver_run("test task", plan, store, IronFlow(store)))
    finally:
        _trace.set_tracer(Tracer())

    locked = [e for e in tracer.events if isinstance(e, _trace.EvRoutingLocked)]
    assert len(locked) == 1
    assert locked[0].driver_tool == "modify_emails"
    assert locked[0].routing["sender"] == "newsletter@example.com"
    assert locked[0].routing["action"] == "archive"


# ── _handle_send_summary reads _routing, not args ─────────────────────

def test_send_summary_fails_closed_without_routing() -> None:
    """Handler must return error when _routing is absent — it must NOT read from args."""
    from safehouse.driver import _handle_send_summary  # type: ignore[attr-defined]
    from safehouse.labels import Label
    import json

    store  = SlotStore()
    policy = IronFlow(store)
    state  = PlanState()              # no _routing set

    # Write the body slot so the handler reaches the routing check
    store.create("body")
    store.write("body", "body text", Label.U_pub())

    ctx = _StepContext(store=store, policy=policy, driver=driver_spec(), state=state, config=_NO_CREDS)
    result_json, final = asyncio.run(
        _handle_send_summary(
            {"body_slot": "body", "recipient": "ignored@evil.com", "subject": "ignored"},
            ctx,
        )
    )
    result = json.loads(result_json)
    assert "routing not pre-committed" in result.get("reason", "")
    assert final is not None          # returns (json, dict), never (json, None)


def test_send_reply_fails_closed_without_routing() -> None:
    from safehouse.driver import _handle_send_reply
    from safehouse.labels import Label
    import json

    store = SlotStore()
    store.create("body")
    store.write("body", "body text", Label.U_pub())
    ctx = _StepContext(
        store=store, policy=IronFlow(store), driver=driver_spec(),
        state=PlanState(), config=_NO_CREDS,
    )
    result_json, final = asyncio.run(
        _handle_send_reply(
            {"body_slot": "body", "recipient": "evil@x.com", "subject": "x"}, ctx,
        )
    )
    assert "routing not pre-committed" in json.loads(result_json)["reason"]
    assert final is not None


def test_schedule_meeting_fails_closed_without_routing() -> None:
    from safehouse.driver import _handle_schedule_meeting
    from safehouse.labels import Label
    import json

    store = SlotStore()
    store.create("slots")
    store.write("slots", '{"proposed_slots":[]}', Label.U_priv())
    ctx = _StepContext(
        store=store, policy=IronFlow(store), driver=driver_spec(),
        state=PlanState(), config=_NO_CREDS,
    )
    result_json, final = asyncio.run(
        _handle_schedule_meeting(
            {"slots_slot": "slots", "attendee": "evil@x.com",
             "event_title": "x", "reply_subject": "x"},
            ctx,
        )
    )
    assert "routing not pre-committed" in json.loads(result_json)["reason"]
    assert final is not None


def test_modify_emails_fails_closed_without_routing() -> None:
    from safehouse.driver import _handle_modify_emails
    import json

    store = SlotStore()
    ctx = _StepContext(
        store=store, policy=IronFlow(store), driver=driver_spec(),
        state=PlanState(), config=_NO_CREDS,
    )
    result_json, final = asyncio.run(
        _handle_modify_emails(
            {"sender": "evil@x.com", "action": "archive"}, ctx,
        )
    )
    assert "routing not pre-committed" in json.loads(result_json)["reason"]
    assert final is not None


def test_send_summary_reads_routing_from_state() -> None:
    """When _routing IS set, handler should read recipient/subject from it."""
    from safehouse.driver import _handle_send_summary  # type: ignore[attr-defined]
    import json
    from safehouse.labels import Label, LVal

    store  = SlotStore()
    policy = IronFlow(store)
    state  = PlanState()
    state.set_var("_routing", LVal(
        {"recipient": "correct@example.com", "subject": "Correct Subject"},
        Label.T_pub(),
    ))
    ctx = _StepContext(store=store, policy=policy, driver=driver_spec(), state=state, config=_NO_CREDS)

    result_json, final = asyncio.run(
        _handle_send_summary(
            # args supply different values — handler must use state, not these
            {"body_slot": "body", "recipient": "wrong@evil.com", "subject": "Wrong"},
            ctx,
        )
    )
    result = json.loads(result_json)
    # body_slot not written → error, but NOT a routing error
    assert "routing not pre-committed" not in result.get("reason", "")
    assert result.get("reason", "").startswith("body_slot")


def test_context_rejects_policy_bound_to_different_store() -> None:
    with pytest.raises(ValueError, match="must be bound"):
        _StepContext(
            store=SlotStore(),
            policy=IronFlow(SlotStore()),
            driver=driver_spec(),
            state=PlanState(),
            config=_NO_CREDS,
        )


def test_run_rejects_policy_bound_to_different_store() -> None:
    plan = {"steps": [{"tool": "modify_emails", "args": {
        "sender": "sender@example.com", "action": "archive",
    }}]}
    result = asyncio.run(
        driver_run("task", plan, SlotStore(), IronFlow(SlotStore())),
    )
    assert result["status"] == "error"
    assert "must be bound" in result["reason"]


def test_run_rejects_reused_precommitted_policy() -> None:
    plan = {"steps": [{"tool": "modify_emails", "args": {
        "sender": "sender@example.com", "action": "archive",
    }}]}
    store = SlotStore()
    policy = IronFlow(store)
    asyncio.run(driver_run("first", plan, store, policy))
    result = asyncio.run(driver_run("second", plan, store, policy))
    assert result["status"] == "error"
    assert "already precommitted" in result["reason"]


def test_written_summary_requires_policy_precommit() -> None:
    from safehouse.driver import _handle_send_summary
    from safehouse.labels import Label, LVal

    store = SlotStore()
    store.create("body")
    store.write("body", "body text", Label.U_pub())
    state = PlanState()
    state.set_var(
        "_routing",
        LVal({"recipient": "safe@example.com", "subject": "Summary"}, Label.T_pub()),
    )
    ctx = _StepContext(
        store=store,
        policy=IronFlow(store),
        driver=driver_spec(),
        state=state,
        config=ProviderConfig(google_token="token"),
    )

    with pytest.raises(IronFlowViolation, match="not bound"):
        asyncio.run(_handle_send_summary({"body_slot": "body"}, ctx))


def test_summary_rejects_policy_precommitted_for_different_state() -> None:
    from safehouse.driver import _handle_send_summary
    from safehouse.labels import Label, LVal

    store = SlotStore()
    store.create("body")
    store.write("body", "private body", Label.U_priv())

    committed = PlanState()
    committed.set_var(
        "_routing",
        LVal({"recipient": "safe@example.com", "subject": "Summary"}, Label.T_pub()),
    )
    policy = IronFlow(store)
    policy.precommit_routing(committed, sources={"body"}, transform="opaque")

    other = PlanState()
    other.set_var(
        "_routing",
        LVal({"recipient": "attacker@example.com", "subject": "Summary"}, Label.T_pub()),
    )
    ctx = _StepContext(
        store=store,
        policy=policy,
        driver=driver_spec(),
        state=other,
        config=ProviderConfig(google_token="token"),
    )

    with pytest.raises(IronFlowViolation, match="not bound"):
        asyncio.run(_handle_send_summary({"body_slot": "body"}, ctx))




