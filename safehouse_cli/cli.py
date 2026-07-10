"""
cli.py — Entry point for safehouse_cli: argument parsing, confirmer selection,
exit-code mapping, and signal handling.

This module contains ONLY I/O policy: parse flags, select confirmer, install
tee streams, handle errors that cross the asyncio boundary. All pipeline logic
lives in app.py. app.py has no argparse, no sys.exit, no print-for-humans.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from .app import ExitCode, RunResult, run_task
from .config import ApprovalMode, ConfigError, RunConfig, split_command
from .interaction import (
    AutoApproveConfirmer,
    Confirmer,
    ConfirmationRequired,
    ConsoleConfirmer,
    DenyConfirmer,
    NonInteractiveConfirmer,
)
from .logging_io import tee_streams

import tracer as _tracer_mod


def _select_confirmer(cfg: RunConfig) -> Confirmer:
    if not cfg.interactive:
        return NonInteractiveConfirmer()
    if cfg.approval == ApprovalMode.AUTO_FIRST_SLOT:
        return AutoApproveConfirmer()
    if cfg.approval == ApprovalMode.DENY:
        return DenyConfirmer()
    return ConsoleConfirmer()


def main() -> None:
    command, rest = split_command(sys.argv[1:])
    if command == "configure":
        from .configure import run_configure
        try:
            sys.exit(run_configure(rest))
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(ExitCode.CONFIG_ERROR)

    try:
        cfg = RunConfig.from_args(rest)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(ExitCode.CONFIG_ERROR)

    confirmer = _select_confirmer(cfg)

    # Banner / intro (suppressed under --json — human chatter goes to stderr).
    if not cfg.json_output:
        _tracer_mod.banner(_tracer_mod.get_universal_spec().task_banner)
        for line in cfg.task.splitlines():
            print(f"  {line}")
        _tracer_mod.ironflow_intro()

    transcript_path: Path | None = None
    result: RunResult | None = None

    with tee_streams(cfg.results_dir / "session_pending.txt"):
        if cfg.json_output:
            # Route all tracer/human output to stderr so stdout carries only
            # the final JSON object. tee_streams restores the real stdout on exit.
            sys.stdout = sys.stderr
        try:
            result = asyncio.run(run_task(cfg, confirmer))
        except KeyboardInterrupt:
            print("\n  interrupted", file=sys.stderr, flush=True)
            sys.exit(ExitCode.INTERRUPTED)
        except ConfirmationRequired as exc:
            print(f"confirmation required: {exc}", file=sys.stderr)
            sys.exit(ExitCode.CONFIRMATION_REQUIRED)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(ExitCode.CONFIG_ERROR)

    if result is None:
        sys.exit(ExitCode.PIPELINE_ERROR)

    # Rename session_pending.txt to the session transcript path now that we know it.
    if result.session:
        pending = cfg.results_dir / "session_pending.txt"
        transcript_path = result.session.transcript_path
        try:
            pending.rename(transcript_path)
        except Exception:
            transcript_path = pending  # fall back to the pending name if rename fails

    if cfg.json_output:
        # Under --json the result object is the ONLY thing on stdout.
        # Human chatter went to stderr. JSONL trace is in result.session.jsonl_path
        # (SENSITIVE — do not include its contents here).
        out = {
            "exit_code": result.exit_code,
            "status":    result.status,
            "detail":    result.detail,
            "session_id": result.session.id if result.session else None,
            "elapsed_s": round(result.elapsed_s, 3),
        }
        print(json.dumps(out))
    else:
        if transcript_path:
            print(f"\n  session → {transcript_path}", file=sys.stderr)

    sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
