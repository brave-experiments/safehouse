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
      it must be explicitly declassified first. Private data stays
      internal regardless of what the LLM produces.

      Declassification is safe only when the destination was locked
      before the private data was fetched, so the data could not have
      influenced where it goes (robust declassification, Zdancewic &
      Myers). Two structural conditions hold at every declassify() site:
        - Routing pre-committed before step 0 (lock before fetch).
        - Processor sub-agents isolated: no CanNetwork, no CanCallTool.

  Least Privilege:
      Agents hold explicit permission tokens declared before execution begins.
      No implicit access. A reader cannot write routing fields; a processor
      cannot call the network.

Every violation is attributed to its principle in IronFlowViolation and the
audit log. Violations are non-recoverable — callers must not retry with
modified args.
"""

from __future__ import annotations
from dataclasses import dataclass, field as dc_field
from enum import Enum, StrEnum
from .labels import Label, LVal, I, C
from .slots import SlotStore
from .permissions import AgentSpec, CanNetwork
from . import trace as _trace


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
    IronFlow — structural security enforcement engine.

    Instantiated once per session. Every consequential operation calls an
    IronFlow gate before it executes. All five principles are enforced
    simultaneously; a violation in any gate raises IronFlowViolation
    immediately, attributed to the principle that was breached.

    Gate methods (Least Privilege, Integrity Gate, Taint Propagation, and
    Confinement enforced via gates; Context Purity enforced structurally —
    slot read/write access is controlled by scoped SlotReader/SlotWriter facets,
    not by IronFlow gate calls):

        engine.before_network(agent_spec, url)                          — Least Privilege
        engine.before_tool(agent_spec, tool_id)                         — Least Privilege
        engine.before_spawn(agent_spec)                                 — Least Privilege
        engine.declassify(lval, *, field, reason, authority, ...)       — Confinement (explicit)
        engine.apply_bridge_field(flow_field, raw_lval)                 — Confinement + Integrity Gate
        engine.before_action(tool, field, lval, role)                   — Integrity Gate + Confinement
    """

    def __init__(self, store: SlotStore) -> None:
        self._store  = store
        self._audit: list[str] = []          # actual violations only
        self._declassify_log: list[str] = [] # explicit declassifications (authorised)

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
        self._passed("SPAWN", agent.id, "CanSpawn check")

    # ── Confinement — Explicit declassification ───────────────────────

    def declassify(
        self,
        lval: LVal,
        *,
        field: str,
        reason: str,
        authority: str = "DRIVER",
        preconditions: list[str] | None = None,
    ) -> LVal:
        """
        Explicit, logged confidentiality downgrade: (_, priv) → (_, pub).

        This is the ONLY sanctioned path for private data to cross the bridge.
        The caller MUST provide a non-empty reason. Preconditions document the
        structural conditions that make declassification safe — typically:

          - Destination (recipient / attendee) was locked BEFORE the private
            data was fetched, so the data could not have influenced where it goes
            (robust declassification per Zdancewic & Myers).
          - Sub-agent that processed the data was isolated (no CanNetwork,
            no CanCallTool, no CanSpawn) — it could not have exfiltrated it.

        Only DRIVER-level handlers call this; sub-agents never hold an IronFlow
        reference, so this is structurally enforced.

        Returns a new LVal with confidentiality lowered to pub; integrity unchanged.
        Raises ValueError if reason is empty.
        """
        if not reason:
            raise ValueError("declassify: reason must be non-empty")

        label_before = lval.label
        label_after  = Label(lval.label.integrity, C.pub)
        result       = LVal(lval.value, label_after)

        _trace.emit(_trace.EvDeclassify(
            field         = field,
            label_before  = str(label_before),
            label_after   = str(label_after),
            authority     = authority,
            reason        = reason,
            preconditions = list(preconditions or []),
        ))
        self._declassify_log.append(
            f"DECLASSIFY field={field} {label_before}→{label_after} "
            f"by={authority} reason={reason!r}"
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

        role=ROUTING — Integrity Gate + Confinement: recipient, subject, attendee.
                       Integrity checked first ("IPI BLOCKED"): any U label means a
                       prompt injection may have tampered with the routing target.
                       Confidentiality checked second ("ROUTING CONFIDENTIALITY"):
                       routing addresses must be public — (T,priv) is not valid.
        role=CONTENT — Confinement: body, payload, text.
                       May be (U, pub). Must not be (_, priv).

        Accepts Role members or plain strings ("ROUTING" / "CONTENT") interchangeably.
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

    # ── Audit ─────────────────────────────────────────────────────────

    def violations(self) -> list[str]:
        """Actual IronFlow violations (gates that were denied)."""
        return list(self._audit)

    def declassify_log(self) -> list[str]:
        """Authorised declassifications — separate from violations."""
        return list(self._declassify_log)

    def clean(self) -> bool:
        return len(self._audit) == 0
