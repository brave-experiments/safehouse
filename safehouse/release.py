"""
release.py — Tier-3 content release transforms.

Applied by the driver after `declassify_slot`. Closed vocabulary:
  opaque                  — string body, truncated to EMAIL_BODY_MAX_CHARS
  structured:<schema_id>  — parse + validate a registered projection

Does not mutate SlotStore; does not elevate integrity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from .labels import LVal


EMAIL_BODY_MAX_CHARS = 8000
_LABEL_MAX_CHARS = 120
_MAX_PROPOSED_SLOTS = 8


class ReleaseTransformError(ValueError):
    """Released content failed its precommitted transform."""


@dataclass(frozen=True)
class ReleaseGate:
    """Per-driver-tool release policy: which step args name source slots, and how."""
    slot_args: tuple[str, ...]
    transform: str | None = None  # None iff slot_args is empty

    def __post_init__(self) -> None:
        if self.slot_args and not self.transform:
            raise ValueError("ReleaseGate with slot_args requires a transform id")
        if not self.slot_args and self.transform is not None:
            raise ValueError("ReleaseGate without slot_args must have transform=None")


# Closed vocabulary — every is_driver_tool must appear here (drift-tested).
DRIVER_RELEASE: dict[str, ReleaseGate] = {
    "send_summary":     ReleaseGate(("body_slot",), "opaque"),
    "send_reply":       ReleaseGate(("body_slot",), "opaque"),
    "schedule_meeting": ReleaseGate(("slots_slot",), "structured:meeting_proposal"),
    "modify_emails":    ReleaseGate(()),
}


def apply_release_transform(transform_id: str, lval: LVal) -> LVal:
    """
    Project authorized pub content under a precommitted transform id.

    Returns a new LVal; never mutates the store. Preserves integrity.
    """
    if transform_id == "opaque":
        return _opaque(lval)
    if transform_id.startswith("structured:"):
        schema_id = transform_id.removeprefix("structured:")
        return _structured(schema_id, lval)
    raise ReleaseTransformError(f"unknown release transform {transform_id!r}")


def _opaque(lval: LVal) -> LVal:
    text = str(lval.value)
    if len(text) > EMAIL_BODY_MAX_CHARS:
        text = text[:EMAIL_BODY_MAX_CHARS]
    return LVal(text, lval.label)


def _structured(schema_id: str, lval: LVal) -> LVal:
    if schema_id == "meeting_proposal":
        return _meeting_proposal(lval)
    raise ReleaseTransformError(f"unknown structured schema {schema_id!r}")


def _parse_slot_dt(value: object) -> datetime | None:
    """Parse ISO-ish start/end; None if unusable (fail closed)."""
    text = str(value).strip()
    if not text:
        return None
    # Accept trailing Z and bare date+time without timezone.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    for candidate in (text, text[:19]):  # 2nd: strip fractional/offset tail
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _meeting_proposal(lval: LVal) -> LVal:
    try:
        data = json.loads(str(lval.value))
    except json.JSONDecodeError as exc:
        raise ReleaseTransformError(
            "meeting_proposal must be JSON with 'proposed_slots' and 'reply_body'"
        ) from exc
    if not isinstance(data, dict):
        raise ReleaseTransformError("meeting_proposal JSON must be an object")

    raw_slots = data.get("proposed_slots")
    if not isinstance(raw_slots, list):
        raise ReleaseTransformError("meeting_proposal missing 'proposed_slots' list")

    proposed: list[dict] = []
    for item in raw_slots:
        if not isinstance(item, dict):
            continue
        if "start" not in item or "end" not in item:
            continue
        start_dt = _parse_slot_dt(item["start"])
        end_dt = _parse_slot_dt(item["end"])
        if start_dt is None or end_dt is None:
            continue  # fail closed — garbage times must not reach ActionGrant
        if (start_dt.tzinfo is None) != (end_dt.tzinfo is None):
            continue  # mixed awareness — cannot order; fail closed, don't TypeError
        if end_dt <= start_dt or start_dt.weekday() >= 5:
            continue
        slot: dict = {
            "start": str(item["start"]).strip(),
            "end":   str(item["end"]).strip(),
        }
        if "label" in item and item["label"] is not None:
            slot["label"] = str(item["label"])[:_LABEL_MAX_CHARS]
        proposed.append(slot)
        if len(proposed) >= _MAX_PROPOSED_SLOTS:
            break
    if not proposed:
        raise ReleaseTransformError("meeting_proposal has no usable weekday proposed_slots")

    reply = data.get("reply_body", "")
    reply_body = str(reply)[:EMAIL_BODY_MAX_CHARS] if reply is not None else ""
    return LVal(
        {"proposed_slots": proposed, "reply_body": reply_body},
        lval.label,
    )
