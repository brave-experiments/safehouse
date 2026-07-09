"""
test_registry_drift.py — cross-module consistency for the tool taxonomy.

The tool vocabulary is deliberately closed (that's the IPI-resistance design),
but it is spelled out in four places that must stay in agreement:

  1. safehouse.planner.TOOL_SCHEMA          — what the planner may emit / validates
  2. safehouse.driver._HANDLERS             — what the driver can execute
  3. safehouse.driver._DRIVER_ROUTING_FIELDS — which driver tools get the
     routing-lock (pre-committed (T,pub) routing before step 0)
  4. tracer.detect_pipeline / _PIPELINE_ENV
     — pipeline classification and env requirements

Nothing cross-checks these at runtime, and the failure modes of drift are
silent: an unrouted driver tool skips the routing lock (a security property),
and an unclassified tool falls into the "briefing" bucket (wrong env checks).
These tests convert every such drift into a CI
failure with a message that says exactly which registry to update.

No API keys, no network, no asyncio — pure import-and-compare.
"""

from __future__ import annotations

import pytest

from safehouse.planner import TOOL_SCHEMA
from safehouse.driver import _DRIVER_ROUTING_FIELDS, _HANDLERS

import tracer


# ── Expected classification ──────────────────────────────────────────
# detect_pipeline() has no explicit "briefing" branch — briefing is the
# fall-through. This allowlist makes the fall-through *intentional*: a tool
# may only land in "briefing" if it is listed here. A new tool that is
# neither claimed by a branch nor added here fails test_detect_pipeline_is_exhaustive.

BRIEFING_FALLBACK_TOOLS: frozenset[str] = frozenset({
    "mcp_page_content",   # generic fetch — used by briefing, harmless elsewhere
    "spawn_processor",    # Tier 2 transform — pipeline-neutral
    "send_summary",       # generic "email the result" driver tool
})

EXPECTED_PIPELINE_BY_TOOL: dict[str, str] = {
    "mcp_flight_search":   "trip",
    "mcp_hotel_search":    "trip",
    "mcp_calendar_search": "calendar",
    "schedule_meeting":    "calendar",
    "mcp_email_search":    "email",
    "send_reply":          "email",
    "modify_emails":       "email",
    **{t: "briefing" for t in BRIEFING_FALLBACK_TOOLS},
}


# ── 1. Planner ↔ driver ──────────────────────────────────────────────

def test_planner_and_driver_vocabularies_agree() -> None:
    """Every tool the planner can emit is executable, and vice versa."""
    schema_only  = set(TOOL_SCHEMA) - set(_HANDLERS)
    handler_only = set(_HANDLERS) - set(TOOL_SCHEMA)
    assert not schema_only, (
        f"tools in TOOL_SCHEMA with no driver handler {sorted(schema_only)} — "
        f"the planner can emit plans the driver cannot execute; "
        f"add handlers to safehouse.driver._HANDLERS"
    )
    assert not handler_only, (
        f"driver handlers with no TOOL_SCHEMA entry {sorted(handler_only)} — "
        f"these tools bypass plan validation entirely; "
        f"add contracts to safehouse.planner.TOOL_SCHEMA"
    )


# ── 2. Routing lock covers every driver tool ─────────────────────────

def test_every_driver_tool_has_routing_lock() -> None:
    """
    A driver tool absent from _DRIVER_ROUTING_FIELDS gets routing_keys=[],
    which SILENTLY SKIPS the pre-committed routing lock — degrading the core
    IPI guarantee instead of failing. This must never happen.
    """
    driver_tools = {name for name, sc in TOOL_SCHEMA.items() if sc.is_driver_tool}
    routed       = set(_DRIVER_ROUTING_FIELDS)

    unrouted = driver_tools - routed
    assert not unrouted, (
        f"driver tools with NO routing lock {sorted(unrouted)} — their routing "
        f"fields are not pre-committed as (T,pub) before step 0; "
        f"add them to safehouse.driver._DRIVER_ROUTING_FIELDS"
    )

    stale = routed - driver_tools
    assert not stale, (
        f"_DRIVER_ROUTING_FIELDS entries for non-driver tools {sorted(stale)} — "
        f"remove them or mark the tools is_driver_tool=True in TOOL_SCHEMA"
    )

    empty = [t for t, fields in _DRIVER_ROUTING_FIELDS.items() if not fields]
    assert not empty, (
        f"driver tools with an EMPTY routing-field list {sorted(empty)} — "
        f"an empty list is indistinguishable from a missing entry"
    )


def test_driver_tool_must_terminate_plans() -> None:
    """At least one driver tool exists (every valid plan must end with one)."""
    assert any(sc.is_driver_tool for sc in TOOL_SCHEMA.values())


# ── 3. detect_pipeline is exhaustive over the vocabulary ─────────────

def test_detect_pipeline_is_exhaustive() -> None:
    """
    Every tool in the vocabulary must be deliberately classified: either
    claimed by an explicit detect_pipeline branch or allowlisted for the
    briefing fall-through. A new tool added to TOOL_SCHEMA without a
    classification decision fails here — instead of silently running under
    the 'briefing' banner with briefing's env checks and no data_slots reset.
    """
    unclassified = set(TOOL_SCHEMA) - set(EXPECTED_PIPELINE_BY_TOOL)
    assert not unclassified, (
        f"tools with no pipeline classification {sorted(unclassified)} — "
        f"add a detect_pipeline branch (and EXPECTED_PIPELINE_BY_TOOL entry), "
        f"or allowlist in BRIEFING_FALLBACK_TOOLS if briefing is truly correct"
    )

    for tool, expected in EXPECTED_PIPELINE_BY_TOOL.items():
        got = tracer.detect_pipeline({tool})
        assert got == expected, (
            f"detect_pipeline({{{tool!r}}}) = {got!r}, expected {expected!r} — "
            f"either detect_pipeline changed or this test's map is stale"
        )

    phantom = set(EXPECTED_PIPELINE_BY_TOOL) - set(TOOL_SCHEMA)
    assert not phantom, (
        f"EXPECTED_PIPELINE_BY_TOOL references unknown tools {sorted(phantom)}"
    )


def test_detect_pipeline_precedence_is_stable() -> None:
    """
    detect_pipeline's branches are ordered: trip > calendar > email > briefing.
    Mixed tool sets resolve by that precedence. Pin it so a reorder of the
    if-chain is a conscious, test-breaking decision.
    """
    assert tracer.detect_pipeline(set(TOOL_SCHEMA)) == "trip"
    assert tracer.detect_pipeline(
        {"mcp_calendar_search", "mcp_email_search", "send_summary"}
    ) == "calendar"
    assert tracer.detect_pipeline({"mcp_email_search", "send_summary"}) == "email"
    assert tracer.detect_pipeline({"mcp_page_content", "send_summary"}) == "briefing"
    assert tracer.detect_pipeline(set()) == "briefing"  # degenerate fall-through


# ── 4. Every detectable pipeline is known to env/reset maps ──────────

DETECTABLE_PIPELINES: frozenset[str] = frozenset(EXPECTED_PIPELINE_BY_TOOL.values())


def test_every_pipeline_has_env_entry() -> None:
    """
    pipeline_env() returns [] for unknown names (a silent no-check). Require
    an explicit _PIPELINE_ENV entry for every detectable pipeline, so 'no env
    vars needed' is a written-down decision, not a KeyError swallowed by .get().
    """
    env_map = tracer._PIPELINE_ENV
    missing = DETECTABLE_PIPELINES - set(env_map)
    assert not missing, (
        f"pipelines with no _PIPELINE_ENV entry {sorted(missing)} — "
        f"add an entry (an explicit empty list is fine) to tracer._PIPELINE_ENV"
    )


def test_handlers_are_granted_or_internal() -> None:
    """Every _HANDLERS key is either a driver_spec CanCallTool grant or on the
    explicit internal-only allowlist. Prevents a handler that is callable-but-
    ungrantable (or grantable-but-should-not-be) from drifting silently."""
    from safehouse.driver import _HANDLERS
    from safehouse.permissions import driver_spec, CanCallTool
    granted = {p.tool_id for p in driver_spec().perms if isinstance(p, CanCallTool)}
    # query_slot is a driver-internal endorsement path, not a plannable manifest
    # tool (absent from DEFAULT_REGISTRY and TOOL_SCHEMA by design).
    INTERNAL_ONLY = {"query_slot"}
    ungoverned = set(_HANDLERS) - granted - INTERNAL_ONLY
    assert not ungoverned, (
        f"handlers neither granted nor marked internal-only: {sorted(ungoverned)} — "
        f"add a CanCallTool grant in driver_spec() or add to INTERNAL_ONLY with justification"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
