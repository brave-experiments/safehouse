"""
plan_types.py — Shared types for the agentic planning loop.

  PlanState — mutable state threaded through the loop: endorsed vars
              and a step audit trail.
"""

from __future__ import annotations
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from .labels import LVal, Label


# ── Plan state ────────────────────────────────────────────────────────

@dataclass
class PlanState:
    """
    Mutable state threaded through the agentic loop.

    vars contains ONLY (T, pub) endorsed facts — enforced by set_var.
    Direct dict writes to vars are blocked; use set_var exclusively.
    steps_done is an audit trail of step type names.
    trusted_action_urls holds the driver-declared external-action URL whitelist,
    sourced from the manifest (auto-populated from registry booking_domain values).

    "_routing" is pre-committed by driver.run() before step 0 with terminal-step
    routing fields as (T,pub). Release source slot ids are bound on IronFlow at
    the same precommit (not stored in vars).

    vars_summary() strips labels for external consumers (all vars are T,pub
    by invariant — enforced by set_var).
    """
    _vars:               dict[str, LVal]  = field(default_factory=dict)
    steps_done:          list[str]        = field(default_factory=list)
    trusted_action_urls: tuple[str, ...]  = field(default_factory=tuple)

    @property
    def vars(self) -> Mapping[str, LVal]:
        """Read-only view of endorsed vars. Write via set_var only."""
        return MappingProxyType(self._vars)

    def set_var(self, name: str, lval: LVal, *, overwrite: bool = False) -> None:
        if lval.label != Label.T_pub():
            raise ValueError(
                f"state.vars may only hold (T,pub) values; "
                f"got {lval.label} for '{name}'"
            )
        if name == "_routing":
            if name in self._vars:
                raise ValueError("routing is permanently committed")
            if not isinstance(lval.value, Mapping):
                raise TypeError("routing must be a mapping")
            frozen = {
                key: tuple(value) if isinstance(value, list) else value
                for key, value in lval.value.items()
            }
            lval = LVal(MappingProxyType(frozen), lval.label)
        if name in self._vars and not overwrite:
            raise ValueError(
                f"var '{name}' is already committed; pass overwrite=True to replace it"
            )
        self._vars[name] = lval

    def get_var(self, name: str) -> LVal:
        if name not in self._vars:
            raise KeyError(f"Planning var '{name}' not in state.vars")
        return self._vars[name]

    def record_step(self, step_name: str) -> None:
        self.steps_done.append(step_name)

    def vars_summary(self) -> dict[str, Any]:
        """Values only — labels implicit (all T,pub by set_var invariant)."""
        return {
            key: dict(lval.value) if isinstance(lval.value, Mapping) else lval.value
            for key, lval in self._vars.items()
        }
