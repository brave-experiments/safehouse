# SafeHouse — Claude Code Reference

> IPI-resistant multi-agent pipeline. Three tiers of execution: **Tier 1** deterministic data sub-agents (no LLM) → **Tier 2** isolated processor sub-agents (sandboxed `claude -p`) → **Tier 3** driver tools (act on the world). IronFlow enforces information-flow labels `L = I × C` at every boundary in pure Python — the LLM cannot reason past it.

---

## Commands

```bash
python3 -m pytest tests/ -v                                          # full test suite — no API key needed
python3 -m py_compile safehouse/*.py safehouse_cli/*.py tracer.py    # syntax check all modules
python3 -c "from safehouse.planner import build_planner_system_prompt; print(build_planner_system_prompt())"  # inspect live planner prompt
```

---

## Key Files

| File | Owns |
|---|---|
| `safehouse/driver.py` | Manifest executor; all `_handle_*` tool handlers; `_HANDLERS`; `_DRIVER_ROUTING_FIELDS`; `ProviderConfig`; `GmailClient` |
| `safehouse/release.py` | Tier-3 release transforms — `DRIVER_RELEASE`, `opaque` / `structured:*`, `apply_release_transform()` |
| `safehouse/ironflow_policy.py` | `IronFlow` engine — gates, `precommit_routing`, `declassify_slot`, `issue_action_grant`, `apply_bridge_field`; `Role` enum (`ROUTING`/`CONTENT`) |
| `safehouse/runner.py` | All sub-agent execution — `run_mcp_*` (Tier 1), `run_processor` (Tier 2) |
| `safehouse/planner.py` | Three-phase manifest planner — `TOOL_SCHEMA`; `_PIPELINE_SHAPES`; `_map_to_concrete`; `_validate_plan` |
| `safehouse/registry.py` | `MCPSpec`; `CatalogSpec`; `ToolRegistry`; `DEFAULT_REGISTRY`; `CAPABILITY_DESCRIPTION` |
| `safehouse/labels.py` | Label lattice `L = I × C`; `Capability` enum; `CAPABILITY_LABEL`; `taint_all` |
| `safehouse/plan_types.py` | `PlanState` (trusted vars + step audit trail) |
| `safehouse/permissions.py` | `AgentSpec`; `fetcher_spec` / `processor_spec` / `driver_spec` factories; capability tokens |
| `safehouse/trace.py` | Typed event system — all `Ev*` dataclasses; `Event` union; `emit` / `set_tracer` |
| `safehouse_cli/` | CLI: `config.py` (flags + `RunConfig`); `app.py` (`ExitCode`, `RunResult`, `run_task`); `cli.py` (entry point) |
| `tracer.py` | All display logic; `DemoSpec`; `detect_pipeline`; `_PIPELINE_ENV` |
| `tests/test_registry_drift.py` | Cross-module consistency guard — **update this when adding any new tool or pipeline** |

---

## Hard Invariants

Violating any of these introduces silent failures or security regressions. The error they produce is listed so you can trace them fast.

### 1 — Handler return contract
Every `_handle_*` in `driver.py` must return `(json_str, dict)` — **never** `(json_str, None)`.
`final is not None` is the completion signal. A `None` second value produces:
> `"manifest completed without terminal step"`

### 2 — No `(U,_)` in `state.vars`
`PlanState.set_var()` raises `ValueError` on any label other than `(T,pub)`.
Routing fields and trusted metadata only — never slot content.

### 3 — Labels only degrade
`SlotWriter` is minted by the driver with a fixed label ceiling derived from `AgentSpec.max_label`.
Writing a slot with a higher-trust label than declared is structurally prevented — the
driver never creates a `SlotWriter` that would permit it.

### 4 — No `print()` in `safehouse/`
All output from `safehouse/` goes through `trace.emit()`. `print()` belongs only in `safehouse_cli/` (CLI UX) and `tracer.py`. Stray prints break the structured audit trail.

### 5 — `_DRIVER_ROUTING_FIELDS` and `DRIVER_RELEASE` must cover every driver tool
A driver tool absent from `_DRIVER_ROUTING_FIELDS` gets an empty routing-key list — the routing lock is **silently skipped**. A tool absent from `DRIVER_RELEASE` cannot precommit sources/transform. Both are security regressions. `test_registry_drift.py` catches them.

### 6 — Credential isolation
Credentials are resolved in the CLI layer and passed into core as explicit parameters. They must never appear in a slot, label, task string, trace event payload, or any Tier 1/2 sub-agent input or environment. The Tier-2 `claude -p` sub-agent runs with an allowlisted env (`runner._subagent_env`) — adding a credential to that allowlist is a regression.

### 7 — Policy identity is per pipeline run
Construct one fresh `IronFlow(store)` per pipeline. `declassify_slot()` must receive the exact
`PlanState` whose immutable `_routing` block was precommitted before the first sub-agent spawn,
and may only release slots listed in that precommit's `sources` set. Content shaping uses the
precommitted `transform` id via driver `_release_slot` (not inside `declassify_slot`).
Do not reuse a policy across runs or pair it with another store/state.

---

## Adding a Tier 3 Driver Tool — Complete Checklist

Steps are ordered; each one has a downstream dependency on the previous.

1. **`safehouse/trace.py`** — add `Ev<ToolName>` dataclass; add to `Event` union
2. **`safehouse/planner.py`** — add `ToolContract` entry to `TOOL_SCHEMA` (`is_driver_tool=True`); add `PipelinePattern` to `_PIPELINE_SHAPES`; update the driver-tool-not-found error message
3. **`safehouse/registry.py`** — add `CatalogSpec("<tool_name>", category="terminal_auto"` or `"terminal_confirmed"`)`
4. **`safehouse/permissions.py`** — add `CanCallTool("<tool_name>")` to `driver_spec()`
5. **`safehouse/driver.py`** — add `_handle_<tool_name>() -> tuple[str, dict]`; register in `_HANDLERS`; add entry to `_DRIVER_ROUTING_FIELDS` with the exact routing field names; add `ReleaseGate` to `safehouse/release.py` `DRIVER_RELEASE` (slot arg names + `opaque` / `structured:<id>` / `None`)
6. **`tracer.py`** — add event handler(s) to `_UNIVERSAL_SPEC` / the matching audit; if this is a new pipeline type, update `detect_pipeline()` and add an entry to `_PIPELINE_ENV`
7. **`tests/test_registry_drift.py`** — add tool to `EXPECTED_PIPELINE_BY_TOOL`

Run `python3 -m pytest tests/ -v` after each step. `test_registry_drift.py` will tell you exactly which registry is missing the new tool.

---

## Failure Mode Index

| Runtime message | Root cause | Where to fix |
|---|---|---|
| `"manifest completed without terminal step"` | `_handle_*` returned `(str, None)` | Return `(json_str, dict)` — use `_terminal_error()` for error paths |
| `"LABEL CEILING … label exceeds max_label"` | `store.reader_for()` called with a slot whose label exceeds `max_label` | Check `processor_spec` `max_label` — pass `max_label=Label.U_priv()` when processor reads priv slots |
| `"IPI BLOCKED — routing field …"` | A `(U,_)` value reached a ROUTING field | Routing must come from `state.vars` (T,pub), not a slot |
| `"ROUTING CONFIDENTIALITY — routing field …"` | A `(T,priv)` value reached a ROUTING field | Routing must originate as `(T,pub)`; never declassify content into routing |
| `"ACTION GRANT REQUIRED / MISMATCH / ROLE …"` | Grant-required ROUTING field (e.g. meeting start/end) used without a matching single-use endorsement, with a wrong value, or gated with a non-ROUTING role | Call `policy.issue_action_grant(state, tool=…, fields=…)` after human confirm with exact values; gate the field as `Role.ROUTING` (one grant per run) |
| `"[Confinement] … confidentiality=priv"` | `(_, priv)` slot crossed the bridge without declassification | Call `policy.declassify_slot(slot_id, ...)` before `apply_bridge_field()` |
| `"var '…' is already committed"` | `set_var()` called twice for the same key without `overwrite=True` | Check for duplicate routing-lock calls in `run()` |
| `"slot '…' already written"` | `SlotStore.write()` called twice for same `slot_id` | Duplicate `slot_id` in plan — `_validate_plan` should catch this at plan time |
| `"Planning var '…' not in state.vars"` | `get_var()` called before `set_var()` | Ensure routing lock (`step 0`) runs before the handler that reads it |
