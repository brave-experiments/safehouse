"""
trace.py — Structured event system for the IPI pipeline.

Components (driver, runner, policy) emit typed events via emit().
Consumers register a Tracer via set_tracer() to receive them.

No print statements live in the core files — they emit events.
The demo (or any other consumer) renders those events however it wants.
"""

from __future__ import annotations
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any


# ── Event types ───────────────────────────────────────────────────────

@dataclass
class EvStaticPlan:
    """Plan produced by the single static-planning SDK call (no tools)."""
    session_id: str
    steps: list[dict]   # each: {step_index, tool, args}

@dataclass
class EvDriverStart:
    task: str

@dataclass
class EvPlanStep:
    """Manifest executor is beginning a step."""
    turn:    int
    tool:    str
    args:    dict

@dataclass
class EvAgentSpawned:
    """A sub-agent was created and authorised to run."""
    kind:        str          # "mcp_page_content" | "mcp_search" | "mcp_email_search" | "processor"
    agent_id:    str
    trust:       str          # "T" | "U"
    permissions: list[str]    # human-readable permission list
    detail:      dict         # url/domain for fetchers; reads/out_slot for processor

@dataclass
class EvFetch:
    """A deterministic data fetcher is making a network request."""
    agent_id: str
    url:      str
    shallow:  bool
    mcp_tool: str = ""   # set for MCP searchers and Gmail email readers; empty for plain HTTP readers

@dataclass
class EvSlotWritten:
    """A slot was written (after taint + permission checks passed)."""
    agent_id: str
    slot_id:  str
    label:    str
    chars:    int

@dataclass
class EvSlotRead:
    """A slot was loaded into a sub-agent's context."""
    agent_id: str
    slot_id:  str
    label:    str

@dataclass
class EvTaint:
    """Taint propagation result for a processor's output."""
    agent_id:      str
    input_labels:  list[str]
    output_label:  str

@dataclass
class EvGate:
    """An IronFlow enforcement gate fired."""
    gate:    str    # SPAWN | NET | READ | WRITE | BRIDGE | ACTION
    who:     str    # agent_id or field name
    detail:  str
    passed:  bool
    blocked: str = ""   # message if not passed

@dataclass
class EvEmailSent:
    """Email delivered via Gmail API."""
    from_addr:  str
    to:         str
    message_id: str


@dataclass
class EvActionFired:
    """send_summary executed successfully."""
    recipient:       str
    recipient_label: str
    subject:         str
    subject_label:   str
    body_chars:      int
    body_label:      str
    body_preview:    str


@dataclass
class EvBookingUrlsExtracted:
    """Operator code extracted booking URLs from MCP response (no LLM)."""
    agent_id: str
    slot_id:  str
    count:    int
    strategy: str        # "json" | "regex" | "none"
    urls:     list[str]  # all trusted-domain URLs found, in MCP response order

@dataclass
class EvRoutingLocked:
    """Routing fields pre-committed to state.vars[\"_routing\"] before step 0.

    Emitted by driver.run() after it reads routing fields from the Tier 3
    driver tool step args (task string → planner → manifest) and stores them
    as (T,pub) in state.vars before any sub-agent executes.
    """
    driver_tool: str         # e.g. "send_reply", "schedule_meeting"
    routing:     dict        # locked fields, all (T,pub)
    pipeline:    int = -1    # -1 for single-plan; 0-based index for multi-pipeline

@dataclass
class EvMeetingOptionsReady:
    """Proposed meeting slots ready for human confirmation.

    Emitted immediately before the blocking input() so the tracer can
    display slot options. All routing fields are (T,pub).
    """
    attendee:        str
    event_title:     str
    proposed_slots:  list[dict]   # [{label, start, end}]
    trusted_domains: list[str] = field(default_factory=list)

@dataclass
class EvMeetingConfirmation:
    """Human decision recorded after the slot-selection prompt."""
    proposed_slots: list[dict]
    chosen_index:   int    # 0-based index; -1 if cancelled
    approved:       bool

@dataclass
class EvMeetingScheduled:
    """Calendar event created and reply sent by schedule_meeting."""
    attendee:          str
    attendee_label:    str
    event_title:       str
    start_time:        str    # ISO 8601; "" if no slot chosen
    end_time:          str
    start_label:       str    # "(T,pub)" after human confirmation
    end_label:         str
    event_id:          str    # Google Calendar event id; "" in dry-run
    event_link:        str
    reply_sent:        bool
    body_chars:        int
    body_label_before: str    # e.g. "(U,priv)"
    body_label_after:  str    # e.g. "(U,pub)"


@dataclass
class EvAutoApproved:
    """Auto-approve confirmer selected slot 1 without human input.

    Emitted by AutoApproveConfirmer so headless --approve auto decisions
    are visible in JSONL audit logs alongside all other gate events.
    """
    slot_index: int    # always 1 — first proposed slot
    label:      str    # human-readable slot label, e.g. "Mon 14 Jul 10:00 BST"


@dataclass
class EvEmailsModified:
    """Gmail batch modification applied to all messages from sender.

    sender and action are (T,pub) from the task string.
    No email content is ever read — only opaque message IDs are touched.

    action: one of add_label | remove_label | archive | mark_read |
                   mark_unread | star | unstar
    label_name / label_id: non-empty only for add_label / remove_label.
    """
    sender:        str
    action:        str
    label_name:    str   # "" for non-label actions
    label_id:      str   # "" for system-label actions
    message_count: int
    sender_label:  str   # "(T,pub)"
    action_label:  str   # "(T,pub)"


@dataclass
class EvDeclassify:
    """Explicit, logged declassification: (_, priv) → (_, pub).

    Only the DRIVER may call this. The reason and preconditions fields form
    the audit proof that the declassification is safe (typically: destination
    was locked before the private data was fetched — robust declassification).
    """
    field:         str         # slot_id or field name being declassified
    label_before:  str         # e.g. "(U,priv)"
    label_after:   str         # e.g. "(U,pub)"
    authority:     str         # always "DRIVER" in current architecture
    reason:        str         # human-readable justification
    preconditions: list[str]   # conditions that make the declassification safe

@dataclass
class EvReplyActionFired:
    """send_reply executed — routing from locked template var (T,pub)."""
    recipient:        str
    recipient_label:  str
    subject:          str
    subject_label:    str
    body_chars:       int
    body_label_before: str   # label before declassification, e.g. "(U,priv)"
    body_label_after:  str   # label after declassification, e.g. "(U,pub)"
    body_preview:     str

@dataclass
class EvPipelineEnd:
    """Pipeline finished (success or error)."""
    status:     str
    violations: list[str]
    inventory:  list[dict]


# ── Planning-phase events ──────────────────────────────────────────────

@dataclass
class EvPlanPhase1Start:
    """Phase 1 abstract planning is starting — banner cue for tracer."""
    system: str = ""   # full system prompt; rendered by tracer if SAFEHOUSE_SHOW_PROMPT=1

@dataclass
class EvPlanChunk:
    """A streaming text chunk from the Phase 1 SDK call."""
    text: str

@dataclass
class EvPlanPhase2:
    """Phase 2 concrete mapping complete — deterministic, no LLM."""
    plan:          dict
    abstract_plan: dict

@dataclass
class EvPlanPhase3:
    """Phase 3 structural validation passed."""
    plan: dict


Event = (
    EvPlanPhase1Start | EvPlanChunk | EvPlanPhase2 | EvPlanPhase3 |
    EvStaticPlan | EvDriverStart | EvPlanStep | EvAgentSpawned |
    EvFetch | EvSlotWritten | EvSlotRead | EvTaint |
    EvGate | EvEmailSent | EvActionFired |
    EvBookingUrlsExtracted |
    EvRoutingLocked | EvDeclassify | EvReplyActionFired |
    EvMeetingOptionsReady | EvMeetingConfirmation | EvMeetingScheduled |
    EvAutoApproved | EvEmailsModified |
    EvPipelineEnd
)


# ── Tracer interface ──────────────────────────────────────────────────

class Tracer:
    def on_event(self, event: Event) -> None:
        pass


class _NullTracer(Tracer):
    pass


_current: ContextVar[Tracer] = ContextVar("tracer", default=_NullTracer())


class MultiTracer(Tracer):
    """Fan-out tracer — delivers every event to all registered sinks in order."""
    def __init__(self, *tracers: Tracer) -> None:
        self._tracers = list(tracers)

    def on_event(self, event: Event) -> None:
        for t in self._tracers:
            t.on_event(event)


def set_tracer(t: Tracer) -> None:
    _current.set(t)


def emit(event: Event) -> None:
    _current.get().on_event(event)
