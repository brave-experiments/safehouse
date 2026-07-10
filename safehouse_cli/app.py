"""
app.py — run_task() orchestrator for safehouse_cli.

Invariants (do not change without updating tests):
  - No argparse, no sys.exit, no direct print-for-humans.
    All human output goes through trace events or is returned in RunResult.
    This keeps app.py importable and fully testable.
  - Pipeline type is derived FROM the plan. Planning necessarily precedes env
    checks — one planner call is always spent before an env failure can surface.
    Do NOT reorder planning vs env checks to "fix" this; the ordering is correct.
  - No retry/backoff around driver_run. Retrying a pipeline that sends emails
    is a duplicate-send generator. Idempotency is a driver concern that does
    not exist yet. If driver_run fails, return PIPELINE_ERROR immediately.
  - driver_run is called exactly once per run_task() invocation.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

from safehouse.driver import run as driver_run
from safehouse.ironflow_policy import IronFlow
from safehouse.planner import generate_plan, PlanValidationError
from safehouse.slots import SlotStore
from safehouse.trace import emit, set_tracer, EvStaticPlan, MultiTracer

from .config import ConfigError, RunConfig
from .credentials import CredentialError, GoogleTokenProvider
from .interaction import Confirmer, ConfirmationRequired
from .logging_io import Session, JsonlTraceSink

# Import tracer public facade from project-root tracer.py.
# tracer.py lives at the project root (not under safehouse/) — always import
# from the package-root module, never from a relative path.
import tracer as _tracer_mod


# ── Exit codes ────────────────────────────────────────────────────────

class ExitCode(IntEnum):
    OK                    = 0
    PIPELINE_ERROR        = 1
    CONFIG_ERROR          = 2
    PLANNING_FAILED       = 3
    POLICY_VIOLATION      = 4   # IronFlow violation: distinct, monitorable outcome
    CONFIRMATION_REQUIRED = 5
    CREDENTIAL_ERROR      = 6   # Google credential resolution failed (bad command, expired refresh)
    INTERRUPTED           = 130


# ── Result ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RunResult:
    exit_code: ExitCode
    status:    str          # "success" | "error" | "dry_run" | "timeout"
    detail:    dict         # driver result dict, or {"plan": ...} for dry-run
    session:   Session | None
    elapsed_s: float


def _to_run_result(driver_result: dict, session: Session, elapsed: float) -> RunResult:
    """
    Map a driver result dict to a RunResult with the correct exit code.

    Policy violations (violations list non-empty) map to POLICY_VIOLATION
    rather than generic PIPELINE_ERROR — a fired IronFlow gate is a distinct,
    monitorable outcome for an IPI-resistance pipeline.
    """
    status = driver_result.get("status", "error")
    if status == "success":
        return RunResult(ExitCode.OK, status, driver_result, session, elapsed)
    violations = driver_result.get("violations", [])
    if violations:
        return RunResult(ExitCode.POLICY_VIOLATION, status, driver_result, session, elapsed)
    return RunResult(ExitCode.PIPELINE_ERROR, status, driver_result, session, elapsed)


# ── Operator context ──────────────────────────────────────────────────

def build_operator_context(cfg: RunConfig) -> str:
    """
    Build the trusted operator context string from RunConfig.

    Only includes the recipient line when cfg.recipient is set.
    Pure function — no side effects, no I/O.
    """
    lines: list[str] = []
    if cfg.recipient:
        lines.append(f"recipient: {cfg.recipient}")
    return "\n".join(lines)


# ── Recipient recovery ────────────────────────────────────────────────

async def _recover_recipient(
    exc: PlanValidationError,
    cfg: RunConfig,
    confirmer: Confirmer,
    operator_context: str,
    api_key: str | None = None,
) -> dict:
    """
    One-shot recovery when the planner rejects a task due to a missing recipient.

    Raises PlanValidationError (re-raised) for non-recipient failures.
    Raises PlanValidationError for empty/None input (no wasted retry).
    Calls generate_plan exactly once (with augmented context) on success.

    The old code retried generate_plan with IDENTICAL inputs when the user
    entered an empty string — a guaranteed-to-fail paid LLM call. This
    function fails immediately on empty/None input instead.
    """
    if not (isinstance(exc, PlanValidationError) and exc.field == "recipient"):
        raise exc   # not recoverable here

    prompted = await confirmer.ask_recipient()
    if not prompted:
        raise PlanValidationError(
            "recipient required: pass --recipient or set DEMO_RECIPIENT",
            field="recipient",
        ) from exc

    augmented = (operator_context + f"\nrecipient: {prompted}").strip()
    return generate_plan(cfg.task, operator_context=augmented, api_key=api_key)


# ── Orchestrator ──────────────────────────────────────────────────────

async def run_task(cfg: RunConfig, confirmer: Confirmer,
                   google_provider: GoogleTokenProvider | None = None) -> RunResult:
    """
    Full pipeline: plan → env check → execute → result.

    No argparse, no sys.exit, no direct print-for-humans.

    NOTE: planning precedes env checks because the pipeline type is derived
    FROM the plan. This is intentional — do not reorder.
    """
    t0 = time.monotonic()
    session = Session.new(cfg.results_dir)
    sink    = JsonlTraceSink(session.jsonl_path)

    # Wire tracer BEFORE generate_plan so planning events reach both sinks.
    spec          = _tracer_mod.get_universal_spec()
    console_tracer = _tracer_mod.make_tracer(spec, pause=cfg.pause)
    set_tracer(MultiTracer(console_tracer, sink))

    operator_context = build_operator_context(cfg)

    # ── Banner (human-facing; suppressed under --json via cli.py) ──────
    # Banner/intro printing is done in cli.py before calling run_task so
    # that app.py contains no direct print-for-humans.

    # ── Planning ───────────────────────────────────────────────────────
    try:
        plan = generate_plan(cfg.task, operator_context=operator_context, api_key=cfg.anthropic_api_key)
    except PlanValidationError as exc:
        try:
            plan = await _recover_recipient(exc, cfg, confirmer, operator_context, api_key=cfg.anthropic_api_key)
        except PlanValidationError as exc2:
            elapsed = time.monotonic() - t0
            sink.close()
            return RunResult(
                ExitCode.PLANNING_FAILED, "error",
                {"reason": str(exc2)}, session, elapsed,
            )

    # ── Pipeline detection and env checks ──────────────────────────────
    # NOTE: planning precedes env checks — pipeline type is derived from the plan.
    tools    = {s["tool"] for s in plan["steps"]}
    pipeline = _tracer_mod.detect_pipeline(tools)
    console_tracer.set_pipeline(pipeline)

    # Check env vars required by this pipeline (only what is actually needed).
    # Rename session files in place to use the detected pipeline prefix.
    session = session.rename_prefix(pipeline)
    sink.rename(session.jsonl_path)
    set_tracer(MultiTracer(console_tracer, sink))

    google_token = cfg.google_token or ""
    if _tracer_mod.pipeline_needs_google(pipeline):
        try:
            if google_provider is not None:
                google_token = google_provider.get_access_token()
        except CredentialError as exc:
            elapsed = time.monotonic() - t0
            sink.close()
            return RunResult(ExitCode.CREDENTIAL_ERROR, "error", {"reason": str(exc)}, session, elapsed)
        if not google_token:
            hint = next(h for v, h in _tracer_mod.pipeline_env(pipeline) if v == "GOOGLE_ACCESS_TOKEN")
            elapsed = time.monotonic() - t0
            sink.close()
            return RunResult(ExitCode.CONFIG_ERROR, "error",
                             {"reason": f"GOOGLE_ACCESS_TOKEN is not set.  {hint}"}, session, elapsed)

    # ── Dry run ────────────────────────────────────────────────────────
    if cfg.dry_run:
        emit(EvStaticPlan(
            session_id = session.id,
            steps      = [
                {"step_index": i, "tool": s["tool"], "args": s["args"]}
                for i, s in enumerate(plan["steps"])
            ],
        ))
        elapsed = time.monotonic() - t0
        sink.close()
        return RunResult(ExitCode.OK, "dry_run", {"plan": plan}, session, elapsed)

    # ── Execution ──────────────────────────────────────────────────────
    store  = SlotStore()
    policy = IronFlow(store)

    emit(EvStaticPlan(
        session_id = session.id,
        steps      = [
            {"step_index": i, "tool": s["tool"], "args": s["args"]}
            for i, s in enumerate(plan["steps"])
        ],
    ))

    try:
        driver_kwargs = {"confirm_slot": confirmer.confirm_slot, "google_token": google_token}
        if cfg.timeout_s is not None:
            result = await asyncio.wait_for(
                driver_run(cfg.task, plan, store, policy, **driver_kwargs),
                timeout=cfg.timeout_s,
            )
        else:
            result = await driver_run(cfg.task, plan, store, policy, **driver_kwargs)
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - t0
        sink.close()
        return RunResult(
            ExitCode.PIPELINE_ERROR, "timeout",
            {"reason": f"execution timed out after {cfg.timeout_s}s"},
            session, elapsed,
        )

    elapsed = time.monotonic() - t0

    # ── Audit hook ────────────────────────────────────────────────────
    if spec.audit_fn:
        spec.audit_fn(console_tracer, result, elapsed=elapsed)

    sink.close()
    return _to_run_result(result, session, elapsed)
