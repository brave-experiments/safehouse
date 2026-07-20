"""tests/test_release.py — release transforms (opaque + structured)."""
from __future__ import annotations

import json

import pytest

from safehouse.labels import Label, LVal
from safehouse.release import (
    EMAIL_BODY_MAX_CHARS,
    ReleaseGate,
    ReleaseTransformError,
    apply_release_transform,
)

U_pub = Label.U_pub()


def test_opaque_passthrough_short() -> None:
    out = apply_release_transform("opaque", LVal("hello", U_pub))
    assert out.value == "hello"
    assert out.label == U_pub


def test_opaque_truncates() -> None:
    big = "x" * (EMAIL_BODY_MAX_CHARS + 50)
    out = apply_release_transform("opaque", LVal(big, U_pub))
    assert len(out.value) == EMAIL_BODY_MAX_CHARS


def test_meeting_proposal_valid() -> None:
    payload = {
        "proposed_slots": [
            {"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00", "label": "Mon 10am"},
        ],
        "reply_body": "Here are times",
    }
    out = apply_release_transform(
        "structured:meeting_proposal", LVal(json.dumps(payload), U_pub),
    )
    assert isinstance(out.value, dict)
    assert out.value["proposed_slots"][0]["label"] == "Mon 10am"
    assert out.value["reply_body"] == "Here are times"


def test_meeting_proposal_rejects_bad_json() -> None:
    with pytest.raises(ReleaseTransformError, match="JSON"):
        apply_release_transform("structured:meeting_proposal", LVal("not-json", U_pub))


@pytest.mark.parametrize("slots", [
    pytest.param([], id="empty"),
    pytest.param([{"start": "2026-09-05T10:00:00", "end": "2026-09-05T11:00:00"}],
                 id="weekend"),                                       # Saturday
    pytest.param([{"start": "n/a", "end": "also-n/a", "label": "Mon 10am"}],
                 id="unparseable"),                                   # garbage times
    pytest.param([{"start": "2026-09-07T11:00:00", "end": "2026-09-07T10:00:00"}],
                 id="end_before_start"),                              # inverted
    pytest.param([{"start": "2026-09-07T10:00:00Z", "end": "2026-09-07T11:00:00"}],
                 id="mixed_tz_awareness"),  # fail closed; must not TypeError
])
def test_meeting_proposal_rejects_bad_slots(slots) -> None:
    """Unusable slots fail closed — nothing reaches ActionGrant."""
    with pytest.raises(ReleaseTransformError, match="no usable"):
        apply_release_transform(
            "structured:meeting_proposal",
            LVal(json.dumps({"proposed_slots": slots, "reply_body": "x"}), U_pub),
        )


def test_meeting_proposal_accepts_consistent_tz_aware_times() -> None:
    """A well-formed tz-aware pair (both aware) still validates and orders."""
    out = apply_release_transform(
        "structured:meeting_proposal",
        LVal(json.dumps({
            "proposed_slots": [
                {"start": "2026-09-07T10:00:00Z", "end": "2026-09-07T11:00:00Z"},
            ],
            "reply_body": "x",
        }), U_pub),
    )
    assert out.value["proposed_slots"][0]["start"] == "2026-09-07T10:00:00Z"


def test_meeting_proposal_caps_slot_count() -> None:
    weekdays = []
    day = 7  # Monday 2026-09-07
    while len(weekdays) < 12:
        weekdays.append({
            "start": f"2026-09-{day:02d}T10:00:00",
            "end":   f"2026-09-{day:02d}T11:00:00",
        })
        day += 1
    out = apply_release_transform(
        "structured:meeting_proposal",
        LVal(json.dumps({"proposed_slots": weekdays, "reply_body": "x"}), U_pub),
    )
    assert len(out.value["proposed_slots"]) == 8


def test_meeting_proposal_caps_label() -> None:
    payload = {
        "proposed_slots": [
            {"start": "2026-09-07T10:00:00", "end": "2026-09-07T11:00:00",
             "label": "L" * 500},
        ],
        "reply_body": "x",
    }
    out = apply_release_transform(
        "structured:meeting_proposal", LVal(json.dumps(payload), U_pub),
    )
    assert len(out.value["proposed_slots"][0]["label"]) == 120


def test_unknown_transform() -> None:
    with pytest.raises(ReleaseTransformError, match="unknown"):
        apply_release_transform("trusted:nope", LVal("x", U_pub))


def test_release_gate_invariants() -> None:
    with pytest.raises(ValueError):
        ReleaseGate(("body_slot",), None)
    with pytest.raises(ValueError):
        ReleaseGate((), "opaque")
