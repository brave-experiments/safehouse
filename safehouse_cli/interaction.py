"""
interaction.py — Confirmer protocol and implementations for safehouse_cli.

Confirmers return a 1-based slot index (or 0 for email-only). Grant integrity
depends on start/end values, not labels — AutoApprove emits those explicitly.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Protocol, runtime_checkable

from safehouse.exceptions import ConfirmationRequired
from safehouse.trace import emit, EvAutoApproved, format_meeting_slot


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
    """Selects slot 1 and emits the exact start/end ActionGrant will endorse."""

    async def confirm_slot(self, slots: list[dict]) -> int:
        slot = slots[0] if slots else {}
        start = str(slot.get("start", ""))
        end = str(slot.get("end", ""))
        label = str(slot.get("label", "") or start or "slot 1")
        display = format_meeting_slot(slot) if (start or end) else label
        sys.stdout.write(f"  [auto-approve] selecting slot 1: {display}\n")
        sys.stdout.flush()
        emit(EvAutoApproved(slot_index=1, label=label, start=start, end=end))
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

    Raises ConfirmationRequired — cli.py maps this to exit code 5.
    Used when approval=INTERACTIVE but prompts are impossible; RunConfig
    forbids that combo for CLI, but programmatic callers may still use it.
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
