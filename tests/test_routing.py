"""
tests/test_routing.py — Routing lock and domain-check gate tests.

Covers:
  - driver.run() pre-commits _routing before step 0 and emits EvRoutingLocked
  - _handle_send_summary fails closed when _routing is absent
  - _check_domain_whitelist emits EvGate("DOMAIN_CHECK") on pass and fail

No API key required — all tests use in-process mocking.
"""
import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import safehouse.trace as _trace
from safehouse.trace import Tracer
from safehouse.slots import SlotStore
from safehouse.ironflow_policy import IronFlow
from safehouse.driver import (
    run as driver_run,
    _DRIVER_ROUTING_FIELDS,
    _StepContext,
    _check_domain_whitelist,
    ProviderConfig,
)
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


# ── driver.run() emits EvRoutingLocked before step 0 ─────────────────

def test_routing_lock_emitted_before_any_step() -> None:
    tracer = _ListTracer()
    _trace.set_tracer(tracer)
    try:
        plan = {"steps": [{"tool": "send_summary", "args": {
            "recipient": "alice@corp.com",
            "subject": "Weekly digest",
            "body_slot": "body",
        }}]}
        asyncio.run(driver_run("test task", plan, SlotStore(), IronFlow(SlotStore())))
    finally:
        _trace.set_tracer(Tracer())   # restore to null tracer

    locked = [e for e in tracer.events if isinstance(e, _trace.EvRoutingLocked)]
    assert len(locked) == 1, "expected exactly one EvRoutingLocked"
    assert locked[0].driver_tool == "send_summary"
    assert locked[0].routing["recipient"] == "alice@corp.com"
    assert locked[0].routing["subject"] == "Weekly digest"

    # EvRoutingLocked must arrive before the first EvPlanStep
    plan_steps = [e for e in tracer.events if isinstance(e, _trace.EvPlanStep)]
    assert tracer.events.index(locked[0]) < tracer.events.index(plan_steps[0])


def test_routing_lock_emitted_for_modify_emails() -> None:
    """modify_emails routing fields (sender, action) are pre-committed like all Tier 3 tools."""
    tracer = _ListTracer()
    _trace.set_tracer(tracer)
    try:
        plan = {"steps": [{"tool": "modify_emails", "args": {
            "sender": "newsletter@example.com",
            "action": "archive",
        }}]}
        asyncio.run(driver_run("test task", plan, SlotStore(), IronFlow(SlotStore())))
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


# ── _check_domain_whitelist audit visibility ──────────────────────────

def test_domain_whitelist_emits_gate_on_pass() -> None:
    tracer = _ListTracer()
    _trace.set_tracer(tracer)
    try:
        err = _check_domain_whitelist(
            "alice@corp.com", ["corp.com"], "empty", "trusted_reply_domains"
        )
    finally:
        _trace.set_tracer(Tracer())

    assert err is None
    gates = [e for e in tracer.events
             if isinstance(e, _trace.EvGate) and e.gate == "DOMAIN_CHECK"]
    assert len(gates) == 1
    assert gates[0].passed is True


def test_domain_whitelist_emits_gate_on_fail() -> None:
    tracer = _ListTracer()
    _trace.set_tracer(tracer)
    try:
        err = _check_domain_whitelist(
            "alice@evil.com", ["corp.com"], "empty", "trusted_reply_domains"
        )
    finally:
        _trace.set_tracer(Tracer())

    assert err is not None
    gates = [e for e in tracer.events
             if isinstance(e, _trace.EvGate) and e.gate == "DOMAIN_CHECK"]
    assert len(gates) == 1
    assert gates[0].passed is False
    assert gates[0].blocked != ""


def test_domain_whitelist_case_insensitive() -> None:
    err = _check_domain_whitelist("alice@CORP.COM", ["corp.com"], "empty", "k")
    assert err is None


def test_domain_whitelist_rejects_empty_trusted_list() -> None:
    err = _check_domain_whitelist("alice@corp.com", [], "no domains configured", "k")
    assert err is not None
    assert "no domains configured" in err


