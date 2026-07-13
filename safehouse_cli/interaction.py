"""
interaction.py — Confirmer protocol and implementations for safehouse_cli.

The headline bug this module fixes:
  The headline bug: the old harness monkeypatched builtins.input to return
  the string "yes". The schedule_meeting driver then called int("yes"), which
  raised ValueError, was caught as choice=0, and silently created no calendar
  invite while logging that it had approved. AutoApproveConfirmer returning 1
  is the correct fix: slot index 1 is "choose the first proposed slot".

Design:
  - Confirmer is a Protocol (structural typing) so test doubles need no imports.
  - Each implementation is self-contained; cli.py selects based on ApprovalMode.
  - No builtins monkeypatching anywhere in this module or its callers.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Protocol, runtime_checkable

from safehouse.exceptions import ConfirmationRequired
from safehouse.trace import emit, EvAutoApproved
from safehouse.trace import Tracer   # for type hints only


@runtime_checkable
class Confirmer(Protocol):
    async def confirm_slot(self, slots: list[dict]) -> int:
        """
        Return the 1-based index of the chosen slot, or 0 for email-only.
        Called by _handle_schedule_meeting via driver.run(confirm_slot=...).
        """
        ...

    async def ask_recipient(self) -> str | None:
        """
        Prompt for a recipient email address.
        Returns None if unavailable (non-interactive or auto confirmer).
        """
        ...

    async def ask_clarification(self, message: str) -> str | None:
        """
        Prompt for a rephrased task when the planner detects semantic ambiguity.
        Returns None if unavailable (non-interactive or auto confirmer).
        """
        ...


class ConsoleConfirmer:
    """Interactive confirmer — wraps input() via asyncio.to_thread."""

    async def confirm_slot(self, slots: list[dict]) -> int:
        n = len(slots)
        answer = await asyncio.to_thread(
            input,
            f"  Create calendar invite? Choose slot (1–{n}), or 0 to send email only: ",
        )
        try:
            return int(answer.strip())
        except ValueError:
            return 0

    async def ask_recipient(self) -> str | None:
        answer = await asyncio.to_thread(
            input,
            "  Recipient email (where results will be sent): ",
        )
        return answer.strip() or None

    async def ask_clarification(self, message: str) -> str | None:
        sys.stdout.write(f"\n  {message}\n")
        sys.stdout.flush()
        answer = await asyncio.to_thread(input, "  Rephrase your task: ")
        return answer.strip() or None


class AutoApproveConfirmer:
    """
    Headless confirmer that automatically selects slot 1.

    Fixes the old monkeypatch bug: returning "yes" caused int("yes") → ValueError
    → choice=0 → email-only path with no calendar invite, despite logging "approved".
    This implementation returns the integer 1 directly.

    Always prints and emits a trace event so the auto-decision is auditable.
    """

    async def confirm_slot(self, slots: list[dict]) -> int:
        label = slots[0].get("label", slots[0].get("start", "slot 1")) if slots else "slot 1"
        sys.stdout.write(f"  [auto-approve] selecting slot 1: {label}\n")
        sys.stdout.flush()
        emit(EvAutoApproved(slot_index=1, label=str(label)))
        return 1

    async def ask_recipient(self) -> str | None:
        return None

    async def ask_clarification(self, message: str) -> str | None:
        return None


class DenyConfirmer:
    """Confirmer that declines all slot confirmations (email-only path)."""

    async def confirm_slot(self, slots: list[dict]) -> int:
        return 0

    async def ask_recipient(self) -> str | None:
        return None

    async def ask_clarification(self, message: str) -> str | None:
        return None


class NonInteractiveConfirmer:
    """
    Confirmer for headless runs that must never block.

    Both methods raise ConfirmationRequired — cli.py maps this to exit code 5.
    Use this when approval=INTERACTIVE but --non-interactive was passed; the
    ConfigError in RunConfig.from_args() prevents that combination in practice,
    but this class remains available for programmatic use where the caller knows
    what it's doing.
    """

    async def confirm_slot(self, slots: list[dict]) -> int:
        raise ConfirmationRequired(
            "schedule_meeting requires human slot confirmation; "
            "pass --approve auto or --approve deny for headless runs"
        )

    async def ask_recipient(self) -> str | None:
        raise ConfirmationRequired(
            "recipient required; pass --recipient or set DEMO_RECIPIENT "
            "for headless runs"
        )

    async def ask_clarification(self, message: str) -> str | None:
        raise ConfirmationRequired(
            "task is ambiguous; rephrase and re-run for headless use"
        )
