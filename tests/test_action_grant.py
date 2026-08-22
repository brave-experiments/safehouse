"""tests/test_action_grant.py — exact-value ActionGrant for calendar times."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from safehouse.ironflow_policy import IronFlow, IronFlowViolation, Role
from safehouse.labels import Label, LVal
from safehouse.plan_types import PlanState
from safehouse.slots import SlotStore
from safehouse import trace as _trace
from safehouse.trace import Tracer

T_pub = Label.T_pub()
_NULL = Tracer()


@pytest.fixture(autouse=True)
def _reset_tracer():
    _trace.set_tracer(_NULL)
    yield
    _trace.set_tracer(_NULL)


class _CapturingTracer(Tracer):
    def __init__(self) -> None:
        self.events: list = []

    def on_event(self, event) -> None:
        self.events.append(event)


def _precommitted() -> tuple[IronFlow, PlanState]:
    store = SlotStore()
    policy = IronFlow(store)
    state = PlanState()
    state.set_var(
        "_routing",
        LVal({"attendee": "a@example.com", "reply_subject": "Re", "event_title": "Sync"}, T_pub),
    )
    policy.precommit_routing(
        state,
        sources={"slots"},
        transform="structured:meeting_proposal",
    )
    return policy, state


def test_start_time_without_grant_denied() -> None:
    policy, _ = _precommitted()
    with pytest.raises(IronFlowViolation, match="ACTION GRANT REQUIRED"):
        policy.before_action(
            "schedule_meeting", "start_time", LVal("2026-09-07T10:00:00", T_pub), Role.ROUTING,
        )


def test_grant_wrong_state_denied() -> None:
    policy, _state = _precommitted()
    other = PlanState()
    other.set_var("_routing", LVal({"attendee": "x"}, T_pub))
    with pytest.raises(IronFlowViolation, match="exact PlanState"):
        policy.issue_action_grant(
            other,
            tool="schedule_meeting",
            fields={"start_time": "a", "end_time": "b"},
        )
    with pytest.raises(IronFlowViolation, match="ACTION GRANT REQUIRED"):
        policy.before_action(
            "schedule_meeting", "start_time", LVal("a", T_pub), Role.ROUTING,
        )


def test_grant_value_mismatch_denied() -> None:
    policy, state = _precommitted()
    policy.issue_action_grant(
        state,
        tool="schedule_meeting",
        fields={"start_time": "2026-09-07T10:00:00", "end_time": "2026-09-07T11:00:00"},
    )
    with pytest.raises(IronFlowViolation, match="ACTION GRANT MISMATCH"):
        policy.before_action(
            "schedule_meeting", "start_time",
            LVal("2026-09-07T99:00:00", T_pub), Role.ROUTING,
        )


def test_grant_happy_path_consumes_both_fields() -> None:
    tracer = _CapturingTracer()
    _trace.set_tracer(tracer)
    policy, state = _precommitted()
    start, end = "2026-09-07T10:00:00", "2026-09-07T11:00:00"
    policy.issue_action_grant(
        state,
        tool="schedule_meeting",
        fields={"start_time": start, "end_time": end},
    )
    granted = [e for e in tracer.events if isinstance(e, _trace.EvActionGranted)]
    assert len(granted) == 1
    assert granted[0].fields == {"end_time": end, "start_time": start}

    policy.before_action(
        "schedule_meeting", "start_time", LVal(start, T_pub), Role.ROUTING,
    )
    policy.before_action(
        "schedule_meeting", "end_time", LVal(end, T_pub), Role.ROUTING,
    )
    with pytest.raises(IronFlowViolation, match="ACTION GRANT REQUIRED"):
        policy.before_action(
            "schedule_meeting", "start_time", LVal(start, T_pub), Role.ROUTING,
        )


def test_duplicate_outstanding_grant_denied() -> None:
    policy, state = _precommitted()
    fields = {"start_time": "a", "end_time": "b"}
    policy.issue_action_grant(state, tool="schedule_meeting", fields=fields)
    with pytest.raises(IronFlowViolation, match="already outstanding"):
        policy.issue_action_grant(state, tool="schedule_meeting", fields=fields)


def test_second_grant_after_consumption_denied() -> None:
    """At most one grant per run — consuming the first must not re-arm issuance."""
    policy, state = _precommitted()
    policy.issue_action_grant(
        state, tool="schedule_meeting",
        fields={"start_time": "a", "end_time": "b"},
    )
    policy.before_action("schedule_meeting", "start_time", LVal("a", T_pub), Role.ROUTING)
    policy.before_action("schedule_meeting", "end_time",   LVal("b", T_pub), Role.ROUTING)
    # Consume nulls _grant; _grant_issued latch — not "_grant is not None" — blocks re-issue.
    assert policy._grant is None
    assert policy._grant_issued is True
    with pytest.raises(IronFlowViolation, match="one action grant"):
        policy.issue_action_grant(
            state, tool="schedule_meeting",
            fields={"start_time": "x", "end_time": "y"},
        )


def test_wrong_role_cannot_bypass_grant() -> None:
    """Passing CONTENT for a grant-required field must deny, not skip the grant."""
    policy, state = _precommitted()
    policy.issue_action_grant(
        state, tool="schedule_meeting",
        fields={"start_time": "a", "end_time": "b"},
    )
    with pytest.raises(IronFlowViolation, match="ACTION GRANT ROLE"):
        policy.before_action(
            "schedule_meeting", "start_time", LVal("a", T_pub), Role.CONTENT,
        )
    # The mis-roled call must not have consumed the field either:
    policy.before_action("schedule_meeting", "start_time", LVal("a", T_pub), Role.ROUTING)


def test_options_display_shows_endorsed_times(capsys) -> None:
    """
    The human-confirmation display must show the exact start/end values the
    grant will endorse — an attacker-supplied label must not replace them.
    """
    import tracer as display
    from safehouse.trace import EvMeetingOptionsReady

    ev = EvMeetingOptionsReady(
        attendee="a@example.com", event_title="Sync",
        proposed_slots=[{
            "label": "Mon Sep 7, 10-11am",             # untrusted, misleading
            "start": "2026-09-09T03:00:00",            # what actually gets booked
            "end":   "2026-09-09T04:00:00",
        }],
    )
    display._meeting_on_options_ready(None, ev)
    out = capsys.readouterr().out
    assert "2026-09-09T03:00:00" in out
    assert "2026-09-09T04:00:00" in out


def test_ordinary_routing_still_needs_no_grant() -> None:
    """recipient/attendee remain routing-lock only — not grant-required."""
    policy, _ = _precommitted()
    policy.before_action(
        "send_summary", "recipient", LVal("safe@example.com", T_pub), Role.ROUTING,
    )


def test_grant_rejects_incomplete_fields() -> None:
    policy, state = _precommitted()
    with pytest.raises(IronFlowViolation, match="fields must be exactly"):
        policy.issue_action_grant(
            state, tool="schedule_meeting", fields={"start_time": "a"},
        )


def test_grant_rejects_tool_without_grant_fields() -> None:
    policy, state = _precommitted()
    with pytest.raises(IronFlowViolation, match="no grant-required"):
        policy.issue_action_grant(
            state, tool="send_summary",
            fields={"start_time": "a", "end_time": "b"},
        )


def test_wrong_role_denied_even_without_outstanding_grant() -> None:
    policy, _ = _precommitted()
    with pytest.raises(IronFlowViolation, match="ACTION GRANT ROLE"):
        policy.before_action(
            "schedule_meeting", "start_time", LVal("a", T_pub), Role.CONTENT,
        )
