"""
trace.py — Structured event system for the IPI pipeline.

Components (driver, runner, policy) emit typed events via emit().
Consumers register a Tracer via set_tracer() to receive them.

No print statements live in the core files — they emit events.
The demo (or any other consumer) renders those events however it wants.
"""

from __future__ import annotations
from contextvars import ContextVar
from typing import TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from .secrets import SecretRegistry

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
    kind:        str          # fetcher kind or "processor"
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
    gate:    str    # PRECOMMIT | DECLASSIFY | SPAWN | NET | BRIDGE | ACTION
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
class EvActionGranted:
    """Single-use exact-value endorsement issued after human confirmation.

    Grant-required ROUTING fields (e.g. schedule_meeting start/end) may only
    pass before_action when values match this grant; forged (T,pub) is denied.
    """
    tool:   str
    fields: dict  # exact endorsed values, e.g. {"start_time": "...", "end_time": "..."}


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
    start/end are the exact values ActionGrant will endorse — label is
    untrusted annotation only.
    """
    slot_index: int    # always 1 — first proposed slot
    label:      str    # untrusted annotation, e.g. "Mon 14 Jul 10:00 BST"
    start:      str = ""  # exact ISO start endorsed by ActionGrant
    end:        str = ""  # exact ISO end endorsed by ActionGrant


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
    """Explicit, logged confidentiality downgrade: (_,priv) → (_,pub).

    Only the DRIVER may call this. Preconditions are generated from checked
    policy state: this exact routing state was committed before any sub-agent
    spawn, and the source came from a write-once slot.
    """
    field:         str         # slot_id being declassified
    label_before:  str         # e.g. "(U,priv)"
    label_after:   str         # e.g. "(U,pub)"
    authority:     str         # always "DRIVER" in current architecture
    reason:        str         # human-readable justification
    preconditions: list[str]   # checked evidence for destination independence

@dataclass
class EvReplyActionFired:
    """send_reply executed — routing from locked `_routing` var (T,pub)."""
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


@dataclass
class EvBookingProposed:
    """Re-validated flight offer shown to the human before the booking grant.
    Emitted just before the confirm prompt so the endorsement is on a visible fare."""
    owner:    str
    route:    str
    amount:   str
    currency: str
    offer_id: str

@dataclass
class EvBookFlight:
    """Flight order created by book_flight (Duffel), paid from balance."""
    provider:         str
    offer_id:         str
    amount:           str    # re-validated total charged
    currency:         str
    owner:            str    # airline
    route:            str
    order_id:         str    # Duffel order id; "" if not created
    booking_reference: str   # PNR; "" if not created
    confirmed:        bool

@dataclass
class EvBookHotel:
    """Hotel booking created by book_hotel (LiteAPI), paid from wallet.

    LiteAPI's /rates/book request has no price field to enforce the grant-endorsed
    amount server-side, so `amount`/`currency` here are the ACTUAL charge reported
    by the booking response — not the pre-booking prebook estimate that was
    endorsed. `amount_endorsed`/`currency_endorsed` (empty unless confirmed) carry
    that pre-booking value so a divergence is visible rather than silently dropped.
    """
    provider:          str
    offer_id:          str
    amount:            str
    currency:          str
    hotel:             str
    booking_id:        str    # LiteAPI booking id; "" if not created
    confirmed:         bool
    amount_endorsed:   str = ""
    currency_endorsed: str = ""


@dataclass
class EvCalendarEventCreated:
    """Personal calendar event created by create_calendar_event — no attendee, no email."""
    event_title: str
    start:       str    # ISO 8601, (T,pub) — fixed at plan time, not processor-derived
    end:         str
    event_id:    str    # Google Calendar event id; "" if not created
    event_link:  str
    confirmed:   bool


@dataclass
class EvGithubIssueSelected:
    """A deterministic filter resolved one issue from a task-derived predicate.

    Emitted by run_github_issue_search. `eligible` counts issues that cleared the
    provenance floor AND the predicate — the gap between `considered` and
    `eligible` is what the floor and filter excluded from selection.
    """
    agent_id:   str
    repo:       str
    considered: int
    eligible:   int
    select:     str
    floor:      str
    number:     int          # 0 when nothing matched
    title:      str
    author:     str


@dataclass
class EvGithubCommentProposed:
    """add_comment is about to ask for human approval.

    The confirmer only reads len(slots), so anything the approver needs must be
    traced before the prompt — this is the human's only view of what they are
    endorsing, including whether the draft was written from provenance-filtered
    text or from unfiltered third-party prose.
    """
    repo:         str
    issue_number: int
    body_chars:   int
    body_preview: str
    gate:         str          # provenance floor in effect, or "disabled"


@dataclass
class EvGithubCommentAdded:
    """Comment posted on a GitHub issue/PR by add_comment.

    repo/issue_number are the (T,pub) routing values; body is declassified slot
    content. comment_id is "" when the post was declined or failed.
    """
    repo:         str
    issue_number: int
    body_chars:   int
    body_label:   str
    comment_id:   str
    comment_url:  str
    confirmed:    bool


@dataclass
class EvGithubPrSelected:
    """A deterministic filter resolved one pull request from a task-derived predicate.

    `drafts_skipped` is reported separately from the floor: a draft excluded
    because its author said it is unfinished is a different outcome from one
    excluded by provenance, and an operator debugging an empty result needs to
    tell them apart.
    """
    agent_id:       str
    repo:           str
    considered:     int
    eligible:       int
    drafts_skipped: int
    select:         str
    floor:          str
    number:         int
    title:          str
    author:         str


@dataclass
class EvGithubReviewProposed:
    """submit_pr_review is about to ask for human approval.

    Carries `event` because REQUEST_CHANGES and COMMENT differ in consequence:
    one blocks the pull request, the other does not. The approver sees which.
    """
    repo:         str
    pull_number:  int
    event:        str          # COMMENT | REQUEST_CHANGES — never APPROVE
    commit_id:    str
    body_chars:   int
    body_preview: str
    gate:         str          # provenance floor in effect, or "disabled"


@dataclass
class EvGithubReviewSubmitted:
    """Review posted on a pull request by submit_pr_review.

    `commit_id` is the head SHA published by mcp_github_pr_read, so the audit
    records which commit the review was bound to rather than only which PR.
    review_id is "" when the submission was declined or failed.
    """
    repo:         str
    pull_number:  int
    event:        str
    commit_id:    str
    body_chars:   int
    body_label:   str
    review_id:    str
    review_url:   str
    confirmed:    bool


@dataclass
class EvGithubItemsFiltered:
    """Provenance gate dropped issue/comment items below the integrity floor.

    Deterministic operator code, no LLM: each item's author_association is
    compared against the operator-configured floor before the slot is written.
    """
    agent_id: str
    slot_id:  str
    floor:    str
    dropped:  int
    kept:     int


Event = (
    EvPlanPhase1Start | EvPlanChunk | EvPlanPhase2 | EvPlanPhase3 |
    EvStaticPlan | EvDriverStart | EvPlanStep | EvAgentSpawned |
    EvFetch | EvSlotWritten | EvSlotRead | EvTaint |
    EvGate | EvEmailSent | EvActionFired |
    EvRoutingLocked | EvDeclassify | EvReplyActionFired |
    EvMeetingOptionsReady | EvMeetingConfirmation | EvActionGranted | EvMeetingScheduled |
    EvBookingProposed | EvBookFlight | EvBookHotel |
    EvCalendarEventCreated |
    EvGithubIssueSelected | EvGithubPrSelected |
    EvGithubCommentProposed | EvGithubCommentAdded |
    EvGithubReviewProposed | EvGithubReviewSubmitted |
    EvGithubItemsFiltered |
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


_secrets: ContextVar["SecretRegistry | None"] = ContextVar("secret_registry", default=None)


def set_secret_registry(registry: "SecretRegistry | None") -> None:
    """Install the run's credential registry so emit() can redact payloads."""
    _secrets.set(registry)


def emit(event: Event) -> None:
    registry = _secrets.get()
    # repr() of an event is small (payloads carry metadata, not slot bodies), so
    # this single scan is the fast path: only a positive hit pays for a rebuild.
    if registry and registry.find(repr(event)) is not None:
        event = registry.scrub(event)
    _current.get().on_event(event)


def format_meeting_slot(slot: dict, *, index: int | None = None) -> str:
    """Render start→end; optional label is annotation only."""
    line = f"{slot.get('start', '?')} → {slot.get('end', '?')}"
    if slot.get("label"):
        line += f"  ({slot['label']})"
    if index is not None:
        return f"  [{index}] {line}"
    return line
