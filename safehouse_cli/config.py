"""
config.py — RunConfig and environment resolution for safehouse_cli.

Design decisions:
  - Credentials and run defaults resolve with precedence CLI flag > env var >
    ~/.safehouse/config.toml (see settings.py). The earlier env-vars-only
    design was superseded once hourly Google-token expiry made a persistent
    config file worth its keep.
  - ApprovalMode is an enum so exhaustive matching is possible without string
    comparison across modules.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .settings import Settings


_PROJECT_DIR = Path(__file__).parent.parent


class ApprovalMode(Enum):
    INTERACTIVE    = "interactive"   # ask a human (default when TTY)
    AUTO_FIRST_SLOT = "auto"         # approve slot 1 automatically
    DENY           = "deny"          # never approve; email-only paths proceed


class ConfigError(Exception):
    """Raised by RunConfig.from_args() on bad configuration."""


def _version_string() -> str:
    """`safehouse X.Y.Z (Python A.B.C, platform)` — version from installed metadata."""
    import importlib.metadata
    import platform
    return (f"safehouse {importlib.metadata.version('safehouse')} "
            f"(Python {platform.python_version()}, {sys.platform})")


# Deferred CLI features (do not re-propose ad hoc): shell completions, --quiet,
# User-Agent version headers.


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
    approval:       ApprovalMode
    dry_run:        bool
    json_output:    bool
    results_dir:    Path
    interactive:    bool              # default sys.stdin.isatty(); --non-interactive forces False
    timeout_s:      float | None      # --timeout SECONDS; None = no ceiling
    anthropic_api_key: str | None     # resolved: env > config file
    duffel_token:      str | None     # resolved: env > config file (Duffel flights)
    liteapi_key:       str | None     # resolved: env > config file (LiteAPI hotels)
    passenger:         dict | None    # trusted passenger/guest profile from config
    max_booking_amount: str | None    # operator spend ceiling
    github_token:      str | None     # resolved: env > config file (GitHub REST)
    min_github_integrity: str | None  # object-integrity floor for GitHub reads; None = gate off
    github_blocked_users: list | None # logins never trusted at any integrity level
    google_token:      str | None     # resolved: env > config file

    @classmethod
    def from_args(cls, argv: list[str] | None = None,
                  settings: "Settings | None" = None) -> "RunConfig":
        """
        Parse argv (or sys.argv[1:]) into a RunConfig.

        Encodes all configuration rules with tests:
          - --pause forces approval=INTERACTIVE and prints one explanatory line.
          - --non-interactive + approval=INTERACTIVE → ConfigError.
          - recipient = --recipient > DEMO_RECIPIENT env (both stripped).
          - --auto-approve is a hidden alias for --approve auto (deprecated).
        """
        if settings is None:
            from .settings import load_settings
            settings = load_settings()
        p = argparse.ArgumentParser(
            prog="safehouse",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=(
                "IPI-resistant pipeline — provide any task, "
                "the pipeline type is auto-detected from the plan."
            ),
            epilog=(
                "Examples:\n"
                '  safehouse "fetch these articles and email me a briefing: <url>"\n'
                '  safehouse --dry-run "reply to the latest email from alice@example.com"\n'
                '  safehouse --non-interactive --approve deny --json "..."   # CI form\n'
                "  echo \"...\" | safehouse run -                            # task from stdin\n"
                "\n"
                "Subcommands: run (default), configure.  Bare flags/text imply 'run'.\n"
                "See SETUP.md for full documentation."
            ),
        )
        p.add_argument("--version", "-V", action="version", version=_version_string())
        p.add_argument("task_pos", nargs="?", metavar="TASK",
                       help="Task to execute (use '-' to read the task from stdin)")
        p.add_argument("--task",
                       help="Task to execute (alternative to the positional TASK)")
        p.add_argument("--recipient",
                       help="Recipient email (overrides DEMO_RECIPIENT)")
        p.add_argument("--pause", action="store_true",
                       help="Force --approve interactive (alias for walkthroughs)")
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

        # Resolve the task: exactly one of positional TASK / --task.
        if args.task_pos and args.task:
            raise ConfigError("provide the task once — positional or --task, not both")
        task = args.task_pos or args.task
        if not task:
            raise ConfigError('provide a task:  safehouse "..."  or  --task "..."')
        task_from_stdin = False
        if task == "-":
            if sys.stdin.isatty():
                raise ConfigError("reading task from stdin ('-') but stdin is a terminal")
            task = sys.stdin.read().rstrip("\n")
            task_from_stdin = True

        # Resolve interactive flag. A task read from stdin has consumed stdin,
        # so interactive prompts are impossible.
        interactive = not args.non_interactive and sys.stdin.isatty() and not task_from_stdin

        # Resolve approval mode.
        if args.auto_approve:
            # Deprecated --auto-approve alias.
            approval = ApprovalMode.AUTO_FIRST_SLOT
        elif args.approve is not None:
            approval = ApprovalMode(args.approve)
        elif settings.approve is not None:
            try:
                approval = ApprovalMode(settings.approve)
            except ValueError:
                raise ConfigError(
                    f"invalid approve in config: {settings.approve!r} "
                    "(expected interactive, auto, or deny)") from None
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
        elif settings.demo_recipient:
            recipient = settings.demo_recipient

        return cls(
            task         = task,
            recipient    = recipient,
            approval     = approval,
            dry_run      = args.dry_run,
            json_output  = args.json_output,
            results_dir  = args.results_dir,
            interactive  = interactive,
            timeout_s    = args.timeout_s if args.timeout_s is not None else settings.timeout,
            anthropic_api_key = settings.anthropic_api_key,
            duffel_token      = settings.duffel_token,
            liteapi_key       = settings.liteapi_key,
            passenger         = settings.passenger,
            max_booking_amount = settings.max_booking_amount,
            github_token      = settings.github_token,
            min_github_integrity = settings.min_github_integrity,
            github_blocked_users = settings.github_blocked_users,
            google_token      = settings.google_token,
        )


def split_command(argv: list[str]) -> tuple[str, list[str]]:
    """Route argv to a subcommand. Bare flags imply `run` (back-compat)."""
    if argv and argv[0] in ("run", "configure"):
        return argv[0], argv[1:]
    return "run", argv
