"""
test_registry_drift.py — cross-module consistency for the tool taxonomy.

The tool vocabulary is deliberately closed (that's the IPI-resistance design),
but it is spelled out in four places that must stay in agreement:

  1. safehouse.planner.TOOL_SCHEMA          — what the planner may emit / validates
  2. safehouse.driver._HANDLERS             — what the driver can execute
  3. safehouse.driver._DRIVER_ROUTING_FIELDS — which driver tools get the
     routing-lock (pre-committed (T,pub) routing before step 0)
  3b. safehouse.release.DRIVER_RELEASE — release slot args + transform id
     per driver tool (opaque | structured:<id> | None)
  4. tracer.detect_pipeline / _PIPELINE_ENV
     — pipeline classification and env requirements

Nothing cross-checks these at runtime, and the failure modes of drift are
silent: an unrouted driver tool skips the routing lock (a security property),
a tool missing from DRIVER_RELEASE cannot precommit sources/transform, and an
unclassified tool falls into the "briefing" bucket (wrong env checks).
These tests convert every such drift into a CI
failure with a message that says exactly which registry to update.

No API keys, no network, no asyncio — pure import-and-compare.
"""

from __future__ import annotations

import pytest

from safehouse.planner import TOOL_SCHEMA
from safehouse.driver import _DRIVER_ROUTING_FIELDS, _HANDLERS
from safehouse.release import DRIVER_RELEASE

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
    "book_flight":         "booking",
    "book_hotel":          "booking",
    "mcp_calendar_search": "calendar",
    "schedule_meeting":    "calendar",
    "create_calendar_event": "calendar",
    "mcp_email_search":    "email",
    "send_reply":          "email",
    "modify_emails":       "email",
    "mcp_github_issue_read": "github",
    "mcp_github_issue_search": "github",
    "add_comment":         "github",
    "mcp_github_issue_list": "github",
    "mcp_github_pr_read":  "github",
    "mcp_github_pr_search": "github",
    "submit_pr_review":    "github",
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


def test_every_driver_tool_has_release_slots() -> None:
    """
    Every driver tool must declare release-slot arg names (possibly empty) and
    a transform id (None iff no slots). Must stay aligned with TOOL_SCHEMA.slot_refs.
    """
    driver_tools = {name for name, sc in TOOL_SCHEMA.items() if sc.is_driver_tool}
    released = set(DRIVER_RELEASE)

    missing = driver_tools - released
    assert not missing, (
        f"driver tools with NO DRIVER_RELEASE entry {sorted(missing)} — "
        f"add them (use ReleaseGate(()) for routing-only tools)"
    )

    stale = released - driver_tools
    assert not stale, (
        f"DRIVER_RELEASE entries for non-driver tools {sorted(stale)}"
    )

    for tool, gate in DRIVER_RELEASE.items():
        expected = TOOL_SCHEMA[tool].slot_refs
        assert gate.slot_args == expected, (
            f"{tool}: DRIVER_RELEASE.slot_args={gate.slot_args!r} != "
            f"TOOL_SCHEMA.slot_refs={expected!r}"
        )
        if gate.slot_args:
            assert gate.transform, f"{tool}: content release requires transform id"
            assert gate.transform == "opaque" or gate.transform.startswith("structured:")
        else:
            assert gate.transform is None

    # Exact transform map — format-only checks allow schedule_meeting→opaque
    # which would skip meeting_proposal validation before ActionGrant.
    assert {t: g.transform for t, g in DRIVER_RELEASE.items()} == {
        "send_summary":     "opaque",
        "send_reply":       "opaque",
        "schedule_meeting": "structured:meeting_proposal",
        "modify_emails":    None,
        "book_flight":      "structured:flight_offer",
        "book_hotel":       "structured:hotel_offer",
        "create_calendar_event": None,
        "add_comment":      "opaque",
        "submit_pr_review": "opaque",
    }


def test_driver_routing_fields_match_schema_routing_keys() -> None:
    """
    Exact routing-key sets — a non-empty but incomplete list still "has a lock"
    while silently skipping fields the handler later reads from args.
    """
    expected = {
        "send_summary":     ["recipient", "subject"],
        "send_reply":       ["recipient", "subject"],
        "schedule_meeting": ["attendee", "event_title", "reply_subject"],
        "modify_emails":    ["sender", "action"],
        "book_flight":      ["provider"],
        "book_hotel":       ["provider"],
        "create_calendar_event": ["event_title", "start", "end"],
        "add_comment":      ["repo", "issue_number"],
        "submit_pr_review": ["repo", "pull_number", "event"],
    }
    assert _DRIVER_ROUTING_FIELDS == expected


def test_optional_routing_fields_are_real_routing_fields() -> None:
    """
    _DRIVER_ROUTING_OPTIONAL lets a routing field be absent at plan time because a
    Tier 1 tool resolves it mid-run. An entry naming a field that is NOT in that
    tool's _DRIVER_ROUTING_FIELDS would make the exemption silently meaningless,
    and one naming an unknown tool would be dead config.
    """
    from safehouse.driver import _DRIVER_ROUTING_OPTIONAL

    for tool, optional in _DRIVER_ROUTING_OPTIONAL.items():
        assert tool in _DRIVER_ROUTING_FIELDS, (
            f"_DRIVER_ROUTING_OPTIONAL names {tool!r} which has no routing fields"
        )
        stray = set(optional) - set(_DRIVER_ROUTING_FIELDS[tool])
        assert not stray, (
            f"{tool}: optional routing fields {sorted(stray)} are not in "
            f"_DRIVER_ROUTING_FIELDS[{tool!r}] = {_DRIVER_ROUTING_FIELDS[tool]}"
        )
        assert set(optional) != set(_DRIVER_ROUTING_FIELDS[tool]), (
            f"{tool}: every routing field is optional, so the routing lock can be "
            f"skipped entirely — at least one field must be required at plan time"
        )

    # Pin the current exemptions so adding one is a deliberate, reviewed decision.
    assert {t: sorted(v) for t, v in _DRIVER_ROUTING_OPTIONAL.items()} == {
        "add_comment": ["issue_number"],
        "submit_pr_review": ["event", "pull_number"],
    }


def test_every_github_fetcher_applies_the_integrity_gate() -> None:
    """
    The integrity floor is applied inside each Tier-1 GitHub fetcher, so that
    below-floor content never enters the slot store at all — stronger confinement
    than filtering on the way out, but it means a NEW fetcher can silently omit
    the gate. That is the same class of failure as a driver tool missing from
    _DRIVER_ROUTING_FIELDS: it degrades a security property instead of erroring.

    Every GITHUB_READ fetcher's source must therefore reach _github_meets_floor,
    directly or through the shared _github_write_issue helper.

    LIMITATION, so nobody over-trusts this: source inspection proves the gate is
    *referenced*, not that it is applied to every item. A fetcher that gates its
    selection but not its content read would still pass here, because the name
    appears either way. Behavioural coverage for that lives in tests/test_github.py
    (test_low_integrity_comment_dropped_by_floor,
    test_floor_applied_during_selection_blocks_capture). This test's job is only to
    catch the blunt regression: a fetcher that forgets the gate entirely.
    """
    import inspect
    import safehouse.runner as runner_mod
    from safehouse.labels import Capability
    from safehouse.registry import DEFAULT_REGISTRY

    github_tools = [
        spec.name for spec in DEFAULT_REGISTRY._specs.values()
        if spec.capability is Capability.GITHUB_READ
    ]
    assert github_tools, "no GITHUB_READ providers registered — has the capability moved?"

    # Registry tool name → the runner coroutine the driver dispatches it to.
    runner_for = {
        "mcp_github_issue_read":   runner_mod.run_github_issue_read,
        "mcp_github_issue_search": runner_mod.run_github_issue_search,
        "mcp_github_issue_list":   runner_mod.run_github_issue_list,
        "mcp_github_pr_read":      runner_mod.run_github_pr_read,
        "mcp_github_pr_search":    runner_mod.run_github_pr_search,
    }
    unmapped = set(github_tools) - set(runner_for)
    assert not unmapped, (
        f"GITHUB_READ tools with no runner in this test's map {sorted(unmapped)} — "
        f"add the mapping so its integrity gate is checked"
    )

    # Shared projection helpers: a fetcher may reach the floor through one of these
    # instead of calling it directly, so each must itself be gated.
    gating_helpers = ("_github_write_issue", "_github_write_pr")
    for helper in gating_helpers:
        helper_src = inspect.getsource(getattr(runner_mod, helper))
        assert "_github_meets_floor" in helper_src, (
            f"{helper} no longer applies the integrity floor — every GitHub read "
            f"that funnels through it just became ungated"
        )

    for tool, fn in runner_for.items():
        src = inspect.getsource(fn)
        gated = "_github_meets_floor" in src or any(h in src for h in gating_helpers)
        assert gated, (
            f"{fn.__name__} (tool {tool!r}) never reaches _github_meets_floor — "
            f"below-floor issue/comment content would reach the processor ungated"
        )


def test_grant_required_wired_in_schedule_meeting_handler() -> None:
    """
    _GRANT_REQUIRED must match before_action field names in the handler source.
    Pinning the frozenset alone does not catch deleting the grant calls.
    """
    import inspect
    from safehouse.ironflow_policy import _GRANT_REQUIRED
    from safehouse.driver import _handle_schedule_meeting, _handle_book_flight, _handle_book_hotel

    handler_for = {
        "schedule_meeting": _handle_schedule_meeting,
        "book_flight":      _handle_book_flight,
        "book_hotel":       _handle_book_hotel,
    }
    for tool, field in _GRANT_REQUIRED:
        src = inspect.getsource(handler_for[tool])
        assert "issue_action_grant" in src
        needle = f'before_action("{tool}", "{field}"'
        assert needle in src, (
            f"_handle_{tool} must call {needle}... — "
            f"otherwise _GRANT_REQUIRED is dead configuration"
        )


def test_grant_required_fields_reference_real_driver_tools() -> None:
    """
    _GRANT_REQUIRED entries must name existing driver tools, and the calendar
    time endorsement must stay pinned. Renaming schedule_meeting (or dropping
    start/end) without updating _GRANT_REQUIRED would silently disable the
    single-use ActionGrant requirement — a security regression, not an error.
    """
    from safehouse.ironflow_policy import _GRANT_REQUIRED

    driver_tools = {name for name, sc in TOOL_SCHEMA.items() if sc.is_driver_tool}
    for tool, grant_field in _GRANT_REQUIRED:
        assert tool in driver_tools, (
            f"_GRANT_REQUIRED references {tool!r} which is not a driver tool — "
            f"update safehouse/ironflow_policy.py _GRANT_REQUIRED"
        )
        assert tool in _HANDLERS, f"_GRANT_REQUIRED references unhandled tool {tool!r}"

    assert _GRANT_REQUIRED == frozenset({
        ("schedule_meeting", "start_time"),
        ("schedule_meeting", "end_time"),
        ("book_flight",      "amount"),
        ("book_hotel",       "amount"),
    }), "calendar start/end + book_flight/book_hotel amount must remain grant-required (exact human endorsement)"


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
    detect_pipeline's branches are ordered:
    booking > trip > calendar > email > github > briefing.
    Mixed tool sets resolve by that precedence. Pin it so a reorder of the
    if-chain is a conscious, test-breaking decision.
    """
    assert tracer.detect_pipeline(set(TOOL_SCHEMA)) == "booking"       # book_flight wins
    assert tracer.detect_pipeline({"mcp_flight_search", "mcp_hotel_search", "send_summary"}) == "trip"
    assert tracer.detect_pipeline(
        {"mcp_calendar_search", "mcp_email_search", "send_summary"}
    ) == "calendar"
    assert tracer.detect_pipeline({"mcp_email_search", "send_summary"}) == "email"
    assert tracer.detect_pipeline({"mcp_github_issue_read", "add_comment"}) == "github"
    assert tracer.detect_pipeline({"mcp_email_search", "add_comment"}) == "email"  # email before github
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
    ungoverned = set(_HANDLERS) - granted
    assert not ungoverned, (
        f"handlers not granted in driver_spec(): {sorted(ungoverned)} — "
        f"add a CanCallTool grant in driver_spec()"
    )


# ── 5. Closed maps that silently skip a security check if they drift ──

def test_credential_tool_sets_cover_the_tools_that_consume_them() -> None:
    """Preflight keys off these frozensets. Omitting a terminal tool means a
    search-less plan (structurally valid: offer_slot from another fetcher)
    skips CONFIG_ERROR and fails mid-action with an empty token."""
    from safehouse.registry import DUFFEL_TOOLS, LITEAPI_TOOLS, GITHUB_TOOLS, GOOGLE_TOOLS

    # Writers need the token even without a read step in the same plan: a
    # search-less booking plan would otherwise skip CONFIG_ERROR and fail
    # mid-action with an empty token.
    assert {"mcp_flight_search", "book_flight"} <= DUFFEL_TOOLS
    assert {"mcp_hotel_search", "book_hotel"} <= LITEAPI_TOOLS
    assert {"add_comment", "submit_pr_review"} <= GITHUB_TOOLS
    assert {"send_summary", "create_calendar_event"} <= GOOGLE_TOOLS
    unknown = (DUFFEL_TOOLS | LITEAPI_TOOLS | GITHUB_TOOLS | GOOGLE_TOOLS) - set(TOOL_SCHEMA)
    assert not unknown, f"credential sets name unknown tools {sorted(unknown)}"


def test_pipeline_env_mentions_every_provider_a_pipeline_can_need() -> None:
    """pipeline_env is hints, not preflight — but an incomplete list is how an
    operator concludes a hotel booking needs no LiteAPI key. Pin var names."""
    vars_of = {p: [v for v, _ in tracer.pipeline_env(p)] for p in DETECTABLE_PIPELINES}
    assert "DUFFEL_ACCESS_TOKEN" in vars_of["booking"]
    assert "LITEAPI_SANDBOX_KEY" in vars_of["booking"]
    assert "DUFFEL_ACCESS_TOKEN" in vars_of["trip"]
    assert "LITEAPI_SANDBOX_KEY" in vars_of["trip"]
    assert "GITHUB_TOKEN" in vars_of["github"]
    assert "GOOGLE_ACCESS_TOKEN" in vars_of["email"]


def test_event_union_includes_every_ev_dataclass() -> None:
    """CLAUDE.md checklist: add Ev* to the Event union. A booking event omitted
    here still emits at runtime but is invisible to typed sinks."""
    import inspect
    import safehouse.trace as trace_mod
    from dataclasses import is_dataclass

    ev_classes = {
        obj for name, obj in vars(trace_mod).items()
        if inspect.isclass(obj) and name.startswith("Ev") and is_dataclass(obj)
    }
    union_args = set(trace_mod.Event.__args__)
    missing = ev_classes - union_args
    stale = union_args - ev_classes
    assert not missing, (
        f"Ev* dataclasses missing from Event union {sorted(c.__name__ for c in missing)} — "
        f"add them to safehouse/trace.py Event"
    )
    assert not stale, (
        f"Event union names unknown types {sorted(c.__name__ for c in stale)}"
    )


def test_tier1_batch_set_agrees_with_the_registry() -> None:
    """_TIER1_TOOLS is derived from TOOL_SCHEMA's shape (writes a slot, reads none,
    not terminal), so it cannot disagree with the schema. The drift that remains is
    against the *registry*: a tool registered as a fetcher but shaped otherwise in
    the schema — or the reverse — would batch inconsistently with how it is declared.
    """
    from safehouse.driver import _TIER1_TOOLS
    from safehouse.registry import DEFAULT_REGISTRY

    registered = {s.name for s in DEFAULT_REGISTRY.all_specs()}
    assert registered == _TIER1_TOOLS, (
        f"registry fetchers not batchable {sorted(registered - _TIER1_TOOLS)}; "
        f"batchable but not registered fetchers {sorted(_TIER1_TOOLS - registered)} — "
        f"a tool's registry category and its TOOL_SCHEMA shape disagree"
    )



def test_capability_summary_lists_every_fetcher() -> None:
    """Sharing a Capability must not hide a tool: GITHUB_READ has five providers
    that do different things. A first-provider-wins summary tells the planner
    that GitHub is only mcp_github_issue_read."""
    from safehouse.registry import DEFAULT_REGISTRY

    summary = DEFAULT_REGISTRY.capability_summary()
    # Match the start of a rendered entry, not the whole string: several catalog
    # descriptions cross-reference other tools by name ("bound automatically from
    # mcp_github_pr_read"), so a substring check passes even when the tool has no
    # entry of its own — which is precisely the regression being guarded.
    listed = {line.split()[0] for line in summary.splitlines()
              if line.startswith("  ") and not line.startswith("   ") and line.split()}
    missing = [s.name for s in DEFAULT_REGISTRY.all_specs() if s.name not in listed]
    assert not missing, (
        f"fetchers absent from capability_summary() {missing} — a first-provider-wins "
        f"summary tells the planner these tools do not exist"
    )


def test_catalog_required_args_match_schema_for_non_fetchers() -> None:
    """TOOL CATALOG is what the planner sees. If it marks issue_number required
    while TOOL_SCHEMA (and the search-resolved few-shots) treat it as optional,
    the planner over-specifies fields the driver is designed to omit."""
    from safehouse.registry import DEFAULT_REGISTRY

    for spec in DEFAULT_REGISTRY.all_catalog_specs():
        if spec.category == "fetcher":
            continue  # catalog args (params/filter) are rewritten in Phase 2
        schema = TOOL_SCHEMA[spec.name]
        catalog_required = {a.name for a in spec.args if a.required}
        schema_required = set(schema.required)
        assert catalog_required == schema_required, (
            f"{spec.name}: catalog required {sorted(catalog_required)} != "
            f"TOOL_SCHEMA.required {sorted(schema_required)}"
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
