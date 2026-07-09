"""
config.py — RunConfig and environment resolution for safehouse_cli.

Design decisions (intentional, do not "fix"):
  - No config-file format (YAML/TOML runtime config). Env vars + CLI flags
    are the right surface at this scale; adding a config file would duplicate
    flag semantics without adding value.
  - ApprovalMode is an enum so exhaustive matching is possible without string
    comparison across modules.
  - require_env raises ConfigError (not sys.exit) so callers own the error path;
    cli.py maps it to exit code 2. This makes app.py testable without subprocess.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


_PROJECT_DIR = Path(__file__).parent.parent


class ApprovalMode(Enum):
    INTERACTIVE    = "interactive"   # ask a human (default when TTY)
    AUTO_FIRST_SLOT = "auto"         # approve slot 1 automatically
    DENY           = "deny"          # never approve; email-only paths proceed


class ConfigError(Exception):
    """Raised by RunConfig.from_args() or require_env() on bad configuration."""


def require_env(var: str, hint: str) -> str:
    """
    Return the stripped value of env var `var`, or raise ConfigError.

    cli.py maps ConfigError → exit code 2. This replaces the old _require_env()
    which called print() + sys.exit() directly (untestable).
    """
    val = os.environ.get(var, "").strip()
    if not val:
        raise ConfigError(f"{var} is not set.  {hint}")
    return val


@dataclass(frozen=True)
class RunConfig:
    """
    Immutable snapshot of a single run's configuration.

    Built once by from_args() and passed through the call stack unchanged.
    All fields have tested, documented semantics — no silent defaults that
    differ from what --help describes.
    """
    task:           str
    recipient:      str | None        # --recipient flag; falls back to DEMO_RECIPIENT
    pause:          bool
    approval:       ApprovalMode
    dry_run:        bool
    json_output:    bool
    results_dir:    Path
    interactive:    bool              # default sys.stdin.isatty(); --non-interactive forces False
    timeout_s:      float | None      # --timeout SECONDS; None = no ceiling

    @classmethod
    def from_args(cls, argv: list[str] | None = None) -> "RunConfig":
        """
        Parse argv (or sys.argv[1:]) into a RunConfig.

        Encodes all configuration rules with tests:
          - --pause forces approval=INTERACTIVE and prints one explanatory line.
          - --non-interactive + approval=INTERACTIVE → ConfigError.
          - recipient = --recipient > DEMO_RECIPIENT env (both stripped).
          - --auto-approve is a hidden alias for --approve auto (deprecated).
        """
        p = argparse.ArgumentParser(
            description=(
                "IPI-resistant pipeline — provide any task, "
                "the pipeline type is auto-detected from the plan."
            ),
        )
        p.add_argument("--task", required=True,
                       help="Task string to execute")
        p.add_argument("--recipient",
                       help="Recipient email (overrides DEMO_RECIPIENT)")
        p.add_argument("--pause", action="store_true",
                       help="Pause at key steps for demo/video recording")
        p.add_argument("--approve", choices=["interactive", "auto", "deny"],
                       default=None,
                       help="Approval mode for confirmation prompts "
                            "(default: interactive when TTY, deny otherwise)")
        # Deprecated alias — keep for one release.
        p.add_argument("--auto-approve", action="store_true",
                       help=argparse.SUPPRESS)
        p.add_argument("--dry-run", action="store_true",
                       help="Plan but do not execute; print the manifest and exit")
        p.add_argument("--json", action="store_true", dest="json_output",
                       help="Write a single JSON result object to stdout (human chatter → stderr)")
        p.add_argument("--results-dir", type=Path,
                       default=_PROJECT_DIR / "results",
                       help="Directory for session transcripts and JSONL traces")
        p.add_argument("--non-interactive", action="store_true",
                       help="Disable all blocking prompts (headless / CI use)")
        p.add_argument("--timeout", type=float, dest="timeout_s", default=None,
                       help="Abort execution after SECONDS (no ceiling by default)")

        args = p.parse_args(argv)

        # Resolve interactive flag.
        interactive = not args.non_interactive and sys.stdin.isatty()

        # Resolve approval mode.
        if args.auto_approve:
            # Deprecated --auto-approve alias.
            approval = ApprovalMode.AUTO_FIRST_SLOT
        elif args.approve is not None:
            approval = ApprovalMode(args.approve)
        elif interactive:
            approval = ApprovalMode.INTERACTIVE
        else:
            approval = ApprovalMode.DENY

        # --pause forces interactive approval (scheduling confirmation must be human-reviewed).
        if args.pause and approval != ApprovalMode.INTERACTIVE:
            approval = ApprovalMode.INTERACTIVE
            if not args.json_output:
                sys.stderr.write("  note: --pause forces --approve interactive\n")

        # Headless runs cannot block for human input.
        if not interactive and approval == ApprovalMode.INTERACTIVE:
            raise ConfigError(
                "headless run cannot use interactive approval; "
                "pass --approve auto or --approve deny"
            )

        # Recipient precedence: --recipient > DEMO_RECIPIENT env.
        recipient: str | None = None
        if args.recipient:
            recipient = args.recipient.strip() or None
        elif env_r := os.environ.get("DEMO_RECIPIENT", "").strip():
            recipient = env_r

        return cls(
            task         = args.task,
            recipient    = recipient,
            pause        = args.pause,
            approval     = approval,
            dry_run      = args.dry_run,
            json_output  = args.json_output,
            results_dir  = args.results_dir,
            interactive  = interactive,
            timeout_s    = args.timeout_s,
        )
