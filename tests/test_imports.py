"""tests/test_imports.py — Smoke test: all core modules import without error."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_all_core_modules_import() -> None:
    import safehouse.labels
    import safehouse.slots
    import safehouse.permissions
    import safehouse.ironflow_policy
    import safehouse.plan_types
    import safehouse.planner
    import safehouse.driver
    import safehouse.runner
    import safehouse.trace
    import safehouse.registry


def test_dispatch_registries_are_aligned() -> None:
    """_HANDLERS, driver_spec() CanCallTool, and TOOL_SCHEMA must name the same tools."""
    from safehouse.driver import _HANDLERS
    from safehouse.permissions import driver_spec, CanCallTool
    from safehouse.planner import TOOL_SCHEMA

    handler_tools  = set(_HANDLERS)
    driver_tools   = {p.tool_id for p in driver_spec().perms if isinstance(p, CanCallTool)}
    schema_tools   = set(TOOL_SCHEMA)

    assert handler_tools == driver_tools, (
        f"_HANDLERS and driver_spec() are out of sync.\n"
        f"  only in _HANDLERS:   {handler_tools - driver_tools}\n"
        f"  only in driver_spec: {driver_tools - handler_tools}"
    )
    assert handler_tools == schema_tools, (
        f"_HANDLERS and TOOL_SCHEMA are out of sync.\n"
        f"  only in _HANDLERS:  {handler_tools - schema_tools}\n"
        f"  only in TOOL_SCHEMA: {schema_tools - handler_tools}"
    )
