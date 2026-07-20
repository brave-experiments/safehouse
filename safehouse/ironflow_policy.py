"""
ironflow_policy.py — IronFlow: structural information-flow enforcement engine.

IronFlow is the enforcement engine at the heart of Brave SafeHouse. Every
consequential operation is gated by IronFlow before it executes. Enforcement
is deterministic Python — the LLM cannot reason past it, argue with it, or be
social-engineered around it.

Five structural principles, always active:

  Context Purity:
      The driver's context is never populated by (U,_) data. Sub-agents
      process untrusted content in isolation — sandboxed, no tools, no memory.


  Integrity Gate:
      ROUTING fields (recipient, subject, attendee) require integrity T.
      No (U,_) value can structurally reach them — ever.
      This is the core IPI-resistance property.

  Taint Propagation:
      Label monotonicity: any U input makes output U. Labels degrade, never
      launder. Integrity uses MEET (U poisons T); confidentiality uses JOIN
      (priv propagates forward).

  Confinement:
      (_, priv) data cannot cross the bridge to an external action —
      it must be explicitly declassified first. declassify_slot only releases
      slots named in the precommit sources set; the driver then applies the
      precommitted transform id.

  Least Privilege:
      Agents hold explicit permission tokens declared before execution begins.
      No implicit access. A reader cannot write routing fields; a processor
      cannot call the network.

Every violation is attributed to its principle in IronFlowViolation and the
audit log. Violations are non-recoverable — callers must not retry with
modified args.
"""

from __future__ import annotations
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field as dc_field
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING
from .labels import Label, LVal, I, C
from .slots import SlotStore
from .permissions import AgentSpec, CanNetwork
from . import trace as _trace

if TYPE_CHECKING:
    from .plan_types import PlanState


# ROUTING fields that may not pass before_action on a forged (T,pub) alone —
# they require a single-use ActionGrant issued after human confirmation.
_GRANT_REQUIRED: frozenset[tuple[str, str]] = frozenset({
    ("schedule_meeting", "start_time"),
    ("schedule_meeting", "end_time"),
})


@dataclass(frozen=True)
class ActionGrant:
    """Exact-value endorsement for grant-required ROUTING fields."""
    tool:   str
    fields: Mapping[str, object]


# ── Five Principles ───────────────────────────────────────────────────

class Principle(str, Enum):
    """
    The five structural enforcement principles of IronFlow.
    Every gate violation is attributed to the principle it enforces.
    """
    CONTEXT_PURITY    = "Context Purity"
    INTEGRITY_GATE    = "Integrity Gate"
    TAINT_PROPAGATION = "Taint Propagation"
    CONFINEMENT       = "Confinement"
    LEAST_PRIVILEGE   = "Least Privilege"


PRINCIPLES: list[tuple[str, Principle, str]] = [
    ("I",   Principle.CONTEXT_PURITY,
     "Driver context never populated by (U,_) data; sub-agents process "
     "untrusted content in isolation"),
    ("II",  Principle.INTEGRITY_GATE,
     "ROUTING fields require integrity T — no (U,_) value can reach "
     "recipient, subject, attendee"),
    ("III", Principle.TAINT_PROPAGATION,
     "Label monotonicity: any U input → U output; labels degrade, never launder"),
    ("IV",  Principle.CONFINEMENT,
     "(_, priv) data cannot cross the bridge to an external action"),
    ("V",   Principle.LEAST_PRIVILEGE,
     "Agents hold explicit permission tokens; no implicit access"),
]


# ── Violation ─────────────────────────────────────────────────────────

class IronFlowViolation(Exception):
    """
    Raised when IronFlow blocks an operation.

    Carries the Principle that was violated so audit logs and error messages
    are self-documenting. Non-recoverable — callers must not retry the
    blocked operation with modified args.
    """
    def __init__(self, principle: Principle, message: str) -> None:
        self.principle = principle
        super().__init__(f"[{principle.value}] {message}")


# ── Flow schema types ─────────────────────────────────────────────────

class FlowMode(str, Enum):
    """How a field crosses the IronFlow bridge. INJECT preserves the label; integrity checked if declared."""
    INJECT = "INJECT"


class Role(StrEnum):
    """
    Role of a field in before_action. StrEnum so f-string renders as 'ROUTING',
    not 'Role.ROUTING' — preserving EvGate.detail byte-for-byte with plain strings.
    Callers may pass Role members or plain strings interchangeably.
    """
    ROUTING = "ROUTING"
    CONTENT = "CONTENT"


@dataclass(frozen=True)
class FlowField:
    """
    Declares one field in a FlowSchema.

    mode=INJECT — value passes through; label preserved; integrity checked
                  if required_integrity=T.

    type_params is excluded from hashing (hash=False); treat as immutable —
    do not mutate after construction.
    """
    name:               str
    base_type:          str           # "bool" | "enum" | "int" | "float" | "str" | "list"
    type_params:        dict = dc_field(default_factory=dict, hash=False)
    required_integrity: I    = I.U
    mode:               FlowMode = FlowMode.INJECT



# ── IronFlow engine ───────────────────────────────────────────────────

class IronFlow:
    """
    Structural enforcement engine — one instance per pipeline run.

    Context Purity is structural (SlotReader/SlotWriter facets). All other
    principles are enforced by the gate methods below; any denial raises
    IronFlowViolation attributed to its principle.
    """

    def __init__(self, store: SlotStore) -> None:
        self._store  = store
        self._audit: list[str] = []          # actual violations only
        self._declassify_log: list[str] = [] # explicit confidentiality downgrades
        self._routing_state: PlanState | None = None
        self._routing: Mapping[str, object] | None = None
        self._sources: frozenset[str] | None = None
        self._transform: str | None = None
        self._grant: ActionGrant | None = None
        self._grant_pending: set[str] = set()
        # Issued-once latch; must stay True after consume clears `_grant`.
        self._grant_issued = False

    def bound_to(self, store: SlotStore) -> bool:
        return self._store is store

    def _deny(self, principle: Principle, msg: str) -> None:
        """Attribute violation to a principle, append to audit log, and raise."""
        exc = IronFlowViolation(principle, msg)
        self._audit.append(str(exc))
        raise exc

    def _require(self, ok: bool, *, gate: str, who: str, detail: str,
                 principle: Principle, msg: str) -> None:
        """Emit a failed gate event and deny when a condition is not met. The only deny path."""
        if not ok:
            _trace.emit(_trace.EvGate(gate=gate, who=who, detail=detail,
                                      passed=False, blocked=msg))
            self._deny(principle, msg)

    def _passed(self, gate: str, who: str, detail: str) -> None:
        """Emit a passed gate event. Called at the end of every gate that did not deny."""
        _trace.emit(_trace.EvGate(gate=gate, who=who, detail=detail, passed=True))

    # ── Least Privilege ───────────────────────────────────────────────

    def before_network(self, agent: AgentSpec, url: str) -> None:
        """Must be called before any HTTP request, including redirect hops."""
        self._require(
            agent.can_network(url),
            gate="NET", who=agent.id, detail=f"url={url!r}",
            principle=Principle.LEAST_PRIVILEGE,
            msg=(f"NETWORK DENIED — '{agent.id}' lacks NET({url}).\n"
                 f"Permitted prefixes: "
                 f"{[str(p) for p in agent.perms if isinstance(p, CanNetwork)]}"),
        )
        self._passed("NET", agent.id, f"url={url!r}")

    def before_tool(self, agent: AgentSpec, tool_id: str) -> None:
        """Must be called before the driver invokes any registered tool."""
        self._require(
            agent.can_call_tool(tool_id),
            gate="TOOL", who=agent.id, detail=f"tool={tool_id!r}",
            principle=Principle.LEAST_PRIVILEGE,
            msg=f"TOOL DENIED — '{agent.id}' lacks TOOL({tool_id}).",
        )
        self._passed("TOOL", agent.id, f"tool={tool_id!r}")

    def before_spawn(self, agent: AgentSpec) -> None:
        """Must be called before any sub-agent is launched."""
        self._require(
            agent.can_spawn(),
            gate="SPAWN", who=agent.id, detail="CanSpawn check",
            principle=Principle.LEAST_PRIVILEGE,
            msg=f"SPAWN DENIED — '{agent.id}' lacks SPAWN permission.",
        )
        self._require(
            self._routing_state is not None,
            gate="PRECOMMIT", who=agent.id, detail="routing fixed before observation",
            principle=Principle.CONFINEMENT,
            msg=(
                "ROUTING PRECOMMIT REQUIRED — routing must be committed as "
                "(T,pub) before any sub-agent can observe external content."
            ),
        )
        self._passed("SPAWN", agent.id, "CanSpawn check")

    # ── Confinement — Destination precommit + declassification ────────

    def precommit_routing(
        self,
        state: "PlanState",
        *,
        sources: Collection[str],
        transform: str | None = None,
    ) -> None:
        """
        Bind this run to one non-empty, immutable routing block, an exact set of
        releasable source slot ids, and the content-release transform id.

        sources may be empty (routing-only tools such as modify_emails); then
        transform must be None. Non-empty sources require a non-empty transform id
        (applied by the driver after declassify_slot — not by IronFlow).
        """
        self._require(
            self._routing_state is None,
            gate="PRECOMMIT", who="driver", detail="one-shot routing commitment",
            principle=Principle.CONFINEMENT,
            msg="ROUTING PRECOMMIT FAILED — routing is already precommitted.",
        )
        try:
            routing = state.get_var("_routing")
        except KeyError:
            routing = None
        self._require(
            routing is not None and routing.label == Label.T_pub(),
            gate="PRECOMMIT", who="driver", detail="state.vars['_routing'] label",
            principle=Principle.CONFINEMENT,
            msg="ROUTING PRECOMMIT FAILED — state.vars['_routing'] must be (T,pub).",
        )
        routing_value = routing.value if routing is not None else None
        self._require(
            isinstance(routing_value, Mapping) and bool(routing_value),
            gate="PRECOMMIT", who="driver", detail="state.vars['_routing'] value",
            principle=Principle.CONFINEMENT,
            msg="ROUTING PRECOMMIT FAILED — routing must be a non-empty mapping.",
        )
        frozen_sources = frozenset(str(s) for s in sources)
        if frozen_sources:
            self._require(
                isinstance(transform, str) and bool(transform),
                gate="PRECOMMIT", who="driver", detail="release transform",
                principle=Principle.CONFINEMENT,
                msg=(
                    "ROUTING PRECOMMIT FAILED — non-empty release sources require "
                    "a non-empty transform id."
                ),
            )
        else:
            self._require(
                transform is None,
                gate="PRECOMMIT", who="driver", detail="release transform",
                principle=Principle.CONFINEMENT,
                msg=(
                    "ROUTING PRECOMMIT FAILED — routing-only tools must precommit "
                    "with transform=None."
                ),
            )
        self._routing_state = state
        self._routing = routing_value
        self._sources = frozen_sources
        self._transform = transform
        self._passed(
            "PRECOMMIT", "driver",
            f"routing=(T,pub); sources={sorted(frozen_sources)}; "
            f"transform={transform!r}; before first spawn",
        )

    def release_transform(self) -> str | None:
        return self._transform

    def issue_action_grant(
        self,
        state: "PlanState",
        *,
        tool: str,
        fields: Mapping[str, object],
    ) -> None:
        """
        Bind a single-use exact-value endorsement for grant-required ROUTING fields.

        Must use the same PlanState as precommit_routing. Each field is consumed
        on the first matching before_action; naked LVal(..., T_pub()) cannot pass
        those fields without this grant.
        """
        self._require(
            self._routing_state is state,
            gate="GRANT", who="driver", detail=f"tool={tool!r}",
            principle=Principle.INTEGRITY_GATE,
            msg=(
                "ACTION GRANT DENIED — grant must be issued for the exact "
                "PlanState precommitted for this run."
            ),
        )
        self._require(
            self._grant is None and not self._grant_pending,
            gate="GRANT", who="driver", detail=f"tool={tool!r}",
            principle=Principle.INTEGRITY_GATE,
            msg="ACTION GRANT DENIED — an unused action grant is already outstanding.",
        )
        self._require(
            not self._grant_issued,
            gate="GRANT", who="driver", detail=f"tool={tool!r}",
            principle=Principle.INTEGRITY_GATE,
            msg="ACTION GRANT DENIED — only one action grant may be issued per run.",
        )
        required = {field for t, field in _GRANT_REQUIRED if t == tool}
        self._require(
            bool(required),
            gate="GRANT", who="driver", detail=f"tool={tool!r}",
            principle=Principle.INTEGRITY_GATE,
            msg=f"ACTION GRANT DENIED — tool '{tool}' has no grant-required fields.",
        )
        self._require(
            set(fields.keys()) == required,
            gate="GRANT", who="driver", detail=f"tool={tool!r}",
            principle=Principle.INTEGRITY_GATE,
            msg=(
                f"ACTION GRANT DENIED — fields must be exactly {sorted(required)}; "
                f"got {sorted(fields)}."
            ),
        )
        frozen = MappingProxyType({key: fields[key] for key in sorted(required)})
        self._grant = ActionGrant(tool=tool, fields=frozen)
        self._grant_pending = set(required)
        self._grant_issued = True
        _trace.emit(_trace.EvActionGranted(tool=tool, fields=dict(frozen)))
        self._passed(
            "GRANT", "driver",
            f"tool={tool!r}; fields={sorted(required)}; single-use",
        )

    def declassify_slot(
        self, slot_id: str, *, state: "PlanState", reason: str,
    ) -> LVal:
        """
        Lower one written slot's confidentiality: (_, priv) → (_, pub).

        Requires the exact PlanState and sources set from precommit_routing.
        Content shaping is the driver's precommitted transform, not this gate.
        """
        if not reason:
            raise ValueError("declassify_slot: reason must be non-empty")
        try:
            current_routing = state.get_var("_routing")
        except KeyError:
            current_routing = None
        self._require(
            self._routing_state is state
            and current_routing is not None
            and current_routing.value is self._routing,
            gate="DECLASSIFY", who="driver", detail=f"slot={slot_id!r}",
            principle=Principle.CONFINEMENT,
            msg=(
                f"DECLASSIFY DENIED — slot '{slot_id}' is not bound to this "
                "run's checked routing precommit."
            ),
        )
        self._require(
            self._sources is not None and slot_id in self._sources,
            gate="DECLASSIFY", who="driver", detail=f"slot={slot_id!r}",
            principle=Principle.CONFINEMENT,
            msg=(
                f"DECLASSIFY DENIED — slot '{slot_id}' is not in this run's "
                f"release sources {sorted(self._sources or ())}."
            ),
        )
        self._require(
            self._store.is_written(slot_id),
            gate="DECLASSIFY", who="driver", detail=f"slot={slot_id!r}",
            principle=Principle.CONFINEMENT,
            msg=f"DECLASSIFY DENIED — slot '{slot_id}' is missing or unwritten.",
        )

        lval         = self._store.read(slot_id)
        if lval.label.confidentiality != C.priv:
            self._passed("DECLASSIFY", "driver", f"slot={slot_id!r}; already public")
            return lval
        label_before = lval.label
        label_after  = Label(lval.label.integrity, C.pub)
        result       = LVal(lval.value, label_after)

        self._passed("DECLASSIFY", "driver", f"slot={slot_id!r}; priv→pub")
        _trace.emit(_trace.EvDeclassify(
            field         = slot_id,
            label_before  = str(label_before),
            label_after   = str(label_after),
            authority     = "DRIVER",
            reason        = reason,
            preconditions = [
                'this exact state.vars["_routing"] committed as (T,pub)',
                f"slot '{slot_id}' listed in precommit release sources",
                "routing precommit checked before every sub-agent spawn",
                f"source read from write-once slot '{slot_id}'",
            ],
        ))
        self._declassify_log.append(
            f"DECLASSIFY slot={slot_id} {label_before}→{label_after} "
            f"by=DRIVER reason={reason!r}"
        )
        return result

    # ── Confinement + Integrity Gate — Bridge schema enforcement ──────

    def apply_bridge_field(self, spec: FlowField, raw: LVal) -> LVal:
        """
        Enforce one field of the FlowSchema at the bridge crossing.

        Confinement: (_, priv) cannot cross.
        Integrity Gate: routing integrity enforced if required_integrity=T.
        """
        detail = f"label={raw.label}"
        self._require(
            raw.label.confidentiality != C.priv,
            gate="BRIDGE", who=spec.name, detail=detail,
            principle=Principle.CONFINEMENT,
            msg=(f"CONFIDENTIALITY — field '{spec.name}' contains private data "
                 f"(label={raw.label}). Private data must not cross the bridge."),
        )
        self._require(
            not (spec.required_integrity == I.T and raw.label.integrity != I.T),
            gate="BRIDGE", who=spec.name, detail=detail,
            principle=Principle.INTEGRITY_GATE,
            msg=(f"INTEGRITY — field '{spec.name}' requires integrity=T "
                 f"but source label={raw.label}."),
        )
        self._passed("BRIDGE", spec.name, detail)
        return raw

    # ── Integrity Gate + Confinement — Final gate before action executes

    def before_action(self, tool_id: str, field: str,
                      lval: LVal, role: Role | str) -> None:
        """
        Final label check before a consequential action fires.

        role=ROUTING — Integrity Gate then Confinement (must be (T,pub)).
        role=CONTENT — Confinement only (may be (U,pub); must not be (_,priv)).

        Grant-required fields are checked before the role branch so a wrong
        role cannot skip the grant; they must still be gated as ROUTING.
        Accepts Role members or plain strings interchangeably.
        """
        try:
            role = Role(role)
        except ValueError:
            msg = f"before_action: unknown role {role!r}; must be 'ROUTING' or 'CONTENT'"
            _trace.emit(_trace.EvGate(gate="ACTION", who=field,
                                      detail=f"field='{field}' role={role} label={lval.label}",
                                      passed=False, blocked=msg))
            raise ValueError(msg)
        detail = f"field='{field}' role={role} label={lval.label}"
        if (tool_id, field) in _GRANT_REQUIRED:
            self._require(
                role is Role.ROUTING,
                gate="GRANT", who=field, detail=detail,
                principle=Principle.INTEGRITY_GATE,
                msg=(f"ACTION GRANT ROLE — grant-required field '{field}' of "
                     f"'{tool_id}' must be gated as ROUTING, not {role}."),
            )
            self._consume_action_grant(tool_id, field, lval)
        if role is Role.ROUTING:
            self._require(
                lval.label.integrity == I.T,
                gate="ACTION", who=field, detail=detail,
                principle=Principle.INTEGRITY_GATE,
                msg=(f"IPI BLOCKED — routing field '{field}' of '{tool_id}' "
                     f"requires label (T,pub) but got {lval.label}. "
                     f"A prompt injection may have attempted to redirect this action."),
            )
            self._require(
                lval.label.confidentiality == C.pub,
                gate="ACTION", who=field, detail=detail,
                principle=Principle.CONFINEMENT,
                msg=(f"ROUTING CONFIDENTIALITY — routing field '{field}' of '{tool_id}' "
                     f"carries private data (label={lval.label}); "
                     f"routing addresses must be (T,pub)."),
            )
        if role is Role.CONTENT:
            self._require(
                lval.label.confidentiality != C.priv,
                gate="ACTION", who=field, detail=detail,
                principle=Principle.CONFINEMENT,
                msg=(f"EXFILTRATION BLOCKED — content field '{field}' of '{tool_id}' "
                     f"contains private data (label={lval.label})."),
            )
        self._passed("ACTION", field, detail)

    def _consume_action_grant(self, tool_id: str, field: str, lval: LVal) -> None:
        """Require and consume one grant-required ROUTING field (exact value)."""
        detail = f"field='{field}' tool={tool_id!r}"
        self._require(
            self._grant is not None
            and self._grant.tool == tool_id
            and field in self._grant_pending,
            gate="GRANT", who=field, detail=detail,
            principle=Principle.INTEGRITY_GATE,
            msg=(
                f"ACTION GRANT REQUIRED — routing field '{field}' of '{tool_id}' "
                "needs a matching single-use human endorsement; forged (T,pub) is not enough."
            ),
        )
        grant = self._grant
        assert grant is not None
        self._require(
            grant.fields.get(field) == lval.value,
            gate="GRANT", who=field, detail=detail,
            principle=Principle.INTEGRITY_GATE,
            msg=(
                f"ACTION GRANT MISMATCH — routing field '{field}' of '{tool_id}' "
                "does not match the endorsed value."
            ),
        )
        self._grant_pending.discard(field)
        if not self._grant_pending:
            self._grant = None
        self._passed("GRANT", field, f"{detail}; consumed")

    # ── Audit ─────────────────────────────────────────────────────────

    def violations(self) -> list[str]:
        """Actual IronFlow violations (gates that were denied)."""
        return list(self._audit)

    def declassify_log(self) -> list[str]:
        """Authorised declassifications — separate from violations."""
        return list(self._declassify_log)

    def clean(self) -> bool:
        return len(self._audit) == 0
