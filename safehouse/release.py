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
    # book_flight releases the processor's (U,pub) offer pick through a structured
    # transform that validates the offer_id (fail-closed) before any provider call.
    # The amount is re-fetched from the provider; passenger PII is a trusted driver param.
    "book_flight":      ReleaseGate(("offer_slot",), "structured:flight_offer"),
    "book_hotel":       ReleaseGate(("offer_slot",), "structured:hotel_offer"),
}


def _loads_object(raw: object) -> dict:
    """Parse a JSON object from possibly-fenced LLM output.

    Processors sometimes wrap their JSON in a ```json … ``` fence or add prose
    around it. Parse strictly first; on failure, extract the first-brace..last-brace
    span. Raises ReleaseTransformError if no JSON object can be recovered.
    """
    text = str(raw).strip()
    # Include the head of the content in failures. Without it the operator sees
    # only "no JSON object found", which hides the actual cause — a Tier-1 empty
    # result sentinel ("(no flight offers found)") or a processor that refused and
    # explained itself in prose both surface identically otherwise.
    head = (text[:120] + "…") if len(text) > 120 else text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        i, j = text.find("{"), text.rfind("}")
        if i == -1 or j <= i:
            raise ReleaseTransformError(
                f"no JSON object found in released content (begins: {head!r})")
        try:
            obj = json.loads(text[i:j + 1])
        except json.JSONDecodeError as exc:
            raise ReleaseTransformError(
                f"released content is not valid JSON (begins: {head!r})") from exc
    if not isinstance(obj, dict):
        raise ReleaseTransformError("released content must be a JSON object")
    return obj


def _flight_offer(lval: LVal) -> LVal:
    """Validate the processor's chosen offer: {offer_id, total_amount, total_currency}.
    Fail closed if offer_id is missing — a garbage pick must not reach a booking call."""
    data = _loads_object(lval.value)
    offer_id = str(data.get("offer_id", "")).strip()
    if not offer_id:
        raise ReleaseTransformError("flight_offer missing 'offer_id'")
    return LVal(
        {
            "offer_id":       offer_id,
            "total_amount":   str(data.get("total_amount", "")),
            "total_currency": str(data.get("total_currency", "")),
        },
        lval.label,
    )

def _hotel_offer(lval: LVal) -> LVal:
    """Validate the processor's chosen hotel offer. Carries the re-search context
    (hotel_id + dates + occupancy) so book_hotel can obtain a FRESH offer before
    prebook — LiteAPI rate offers expire fast, so the stale offer_id is only a hint.
    Fail closed if hotel_id is missing — a garbage pick must not reach a booking call."""
    data = _loads_object(lval.value)
    hotel_id = str(data.get("hotel_id", "")).strip()
    checkin  = str(data.get("checkin", "")).strip()
    checkout = str(data.get("checkout", "")).strip()
    if not (hotel_id and checkin and checkout):
        raise ReleaseTransformError("hotel_offer missing hotel_id / checkin / checkout")
    try:
        adults = max(1, int(data.get("adults", 1) or 1))
    except (TypeError, ValueError):
        adults = 1
    return LVal(
        {
            "offer_id":     str(data.get("offer_id", "")).strip(),   # stale hint only
            "hotel_id":     hotel_id,
            "hotel":        str(data.get("hotel", "")),
            "checkin":      checkin,
            "checkout":     checkout,
            "adults":       adults,
            "country_code": str(data.get("country_code", "")).strip(),
            "amount":       str(data.get("amount", "")),
            "currency":     str(data.get("currency", "")) or "GBP",
        },
        lval.label,
    )


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
    if schema_id == "flight_offer":
        return _flight_offer(lval)
    if schema_id == "hotel_offer":
        return _hotel_offer(lval)
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
    data = _loads_object(lval.value)

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
