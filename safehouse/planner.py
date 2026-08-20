"""
planner.py — Three-phase manifest planner.

═══════════════════════════════════════════════════════════════
 STRUCTURE
═══════════════════════════════════════════════════════════════

  PROMPT SYSTEM
    _ABSTRACT_PLAN_SYSTEM_TEMPLATE     stable LLM prompt with {available_capabilities}
                                       and {tool_catalog} placeholders; never embeds
                                       provider URLs or MCP tool names
    build_planner_system_prompt()      fills placeholders from the registry

  VALIDATION SCHEMA
    TOOL_SCHEMA                        declarative per-tool contracts (required args,
                                       slot/var refs, field formats); _validate_plan
                                       interprets these mechanically — adding a new tool
                                       requires only a new dict entry here

  PLANNER PIPELINE
    generate_plan()       Phase 1      SDK call → Phase 2 → Phase 3
    _map_to_concrete()    Phase 2      capability → provider details (pure Python, no LLM)
    _validate_plan()      Phase 3      structural validation — hard stop on any violation

  VALIDATION CHECKS  (_validate_plan · driven by TOOL_SCHEMA)
    Structure
      • plan["steps"] is a non-empty list
      • every step["tool"] is a known TOOL_SCHEMA key — unknown tools rejected before any I/O
      • every step["args"] is a dict
    Per-step (TOOL_SCHEMA keys interpreted mechanically)
      • required        all listed args present and non-falsy (catches absent, "", [], {})
      • slot_output     slot named by this step added to declared_slots; duplicate = error
                          (write-once invariant — mirrors SlotStore.write() RuntimeError)
      • slot_inputs     arg is a list; every element declared in a strictly earlier step
      • slot_refs       single slot ref; must be declared in a strictly earlier step
      • email_fields    arg is a string containing '@' (required fields; present by construction)
      • https_fields    arg starts with 'https://' — provider REST API base URLs (api_url, domain)
      • http_fields     arg starts with 'http'    — page fetch URLs (url); rejects file://, ftp://
      • dict_fields     arg is a dict when present (output_format, search_params)
      • literal_fields  arg is in allowed set when present
                          modify_emails.action: add_label · remove_label · archive ·
                          mark_read · mark_unread · star · unstar
      • is_driver_tool     driver tool mid-plan → error (unreachable steps after it)
    Post-loop
      • final step must have is_driver_tool=True (one of: send_summary · send_reply ·
          schedule_meeting · modify_emails); plans ending without a driver tool are rejected
    Not checked here (intentional)
      • trusted_action_urls — validated by IronFlow before_action gates at use time
      • modify_emails.sender — Gmail query param, not an addressee; may be a domain, not a full address
      • spawn_processor instruction/output_format semantics — validated by the subprocess runner
      • search_params key/value semantics — provider-specific, validated by MCP handler at runtime


═══════════════════════════════════════════════════════════════
 PLANNING MODEL  (generate_plan)
═══════════════════════════════════════════════════════════════

  1. Abstract — one SDK call (no tools) on the trusted task string.
     The planner sees three sections from the registry/prompt builder:
       • capability_summary() — registered services, labels, abstract params
       • build_patterns_section() — pipeline shape examples (abstract tool names only)
       • tool_catalog() — full arg schemas for every tool
     Never sees provider domains, MCP tool names, or raw parameter schemas.
  2. Concrete — _map_to_concrete() fills in provider details (domain,
     mcp_tool, renamed params, trusted_action_urls) from the registry.
     Pure Python, no LLM.
  3. Verify — _validate_plan() applies full structural validation. Hard
     stop on any constraint violation before the manifest is returned.

The planner runs once, on trusted input, before any sub-agent executes.
It never sees slot content — structurally immune to IPI.
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit
import anthropic
from .registry import ToolRegistry, DEFAULT_REGISTRY
from . import trace as _trace


class PlanValidationError(ValueError):
    """
    Raised by generate_plan() when the planner output fails validation.

    field — the plan arg name that failed (e.g. "recipient"); None for structural
    failures (bad JSON, unknown tool, slot chain errors) that are not field-specific.

    Subclasses ValueError so existing ``except ValueError`` callers are unaffected.
    """
    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


_MISSING_RECIPIENT_SIGNAL = "missing routing field: recipient"


def _recipient_recovery_field(msg: object) -> str | None:
    """Return "recipient" if msg is the exact planner missing-recipient signal, else None."""
    if isinstance(msg, str) and msg.startswith(_MISSING_RECIPIENT_SIGNAL):
        return "recipient"
    return None


def _get_client(api_key: str | None = None) -> anthropic.Anthropic:
    # Left as None the SDK resolves a key from the environment itself, below this
    # package, where the sweep in test_credential_isolation.py cannot see it.
    # Both model call sites take the key from the CLI or fail.
    if not api_key:
        raise RuntimeError(
            "planner requires an explicit API key; none was threaded from the CLI layer")
    return anthropic.Anthropic(api_key=api_key)


_PLANNER_MODEL      = "claude-sonnet-4-6"
_PLANNER_MAX_TOKENS = 4096
_PLANNER_TIMEOUT    = 60   # seconds — single SDK call, no tool I/O; 60 s is generous
_MAX_PIPELINES      = 5    # bounded blast radius — caps total world-actions per run


# ── Pipeline pattern shapes ────────────────────────────────────────────

@dataclass(frozen=True)
class PipelinePattern:
    """
    One reusable pipeline shape keyed by the Tier 3 driver tool it satisfies.

    Patterns are driver-tool-centric, not demo-centric: adding a new demo that
    uses an existing driver tool requires zero new patterns.  Adding a new
    driver tool requires exactly one new entry here.
    """
    driver_tool: str   # name of the Tier 3 driver tool this shape satisfies
    description: str   # one-line: when to select this shape
    example:     str   # prompt text; {timezone} replaced by build_patterns_section


# Four shapes — one per Tier 3 driver tool currently exposed to the abstract planner.
_PIPELINE_SHAPES: list[PipelinePattern] = [

    PipelinePattern(
        driver_tool = "book_flight",
        description = (
            "BOOK/RESERVE/PURCHASE a flight (not just search or email). "
            "Search flights, pick the cheapest via spawn_processor, then book_flight — "
            "paid from the operator's Duffel balance after human confirmation. "
            "Use this (NOT send_summary) whenever the task says book / reserve / purchase a flight. "
            "ROUND / RETURN trips: use ONE mcp_flight_search with both date AND return_date — that "
            "returns a single round-trip offer covering BOTH legs. Do NOT run two one-way searches; "
            "book_flight books one offer_id, so two one-ways would book only the outbound leg."
        ),
        example     = """\
{"steps": [
  {"tool": "mcp_flight_search", "args": {
    "params": {"origin": "<IATA verbatim>", "destination": "<IATA verbatim>", "date": "<verbatim>", "return_date": "<verbatim if round trip, else omit>"}, "slot_id": "flight_offers"}},
  {"tool": "spawn_processor", "args": {
    "reads": ["flight_offers"], "out_slot": "best_offer",
    "instruction": "From the offers JSON, select the single cheapest (each offer already covers all legs). Output ONLY valid JSON: {\"offer_id\": \"<id>\", \"total_amount\": \"<amount>\", \"total_currency\": \"<ccy>\"}"}},
  {"tool": "book_flight", "args": {"provider": "duffel", "offer_slot": "best_offer"}}
]}""",
    ),
    PipelinePattern(
        driver_tool = "book_hotel",
        description = (
            "BOOK/RESERVE a hotel (not just search). Search hotels, pick the cheapest via "
            "spawn_processor, then book_hotel — paid from the operator's LiteAPI wallet after "
            "human confirmation. country_code is the ISO-2 code inferred from the city "
            "(e.g. Lisbon → PT). Use this (NOT send_summary) whenever the task says book/reserve a hotel."
        ),
        example     = """\
{"steps": [
  {"tool": "mcp_hotel_search", "args": {
    "params": {"city": "<city verbatim>", "country_code": "<ISO-2 for the city>", "check_in": "<verbatim>", "check_out": "<verbatim>", "adults": 1}, "slot_id": "hotel_offers"}},
  {"tool": "spawn_processor", "args": {
    "reads": ["hotel_offers"], "out_slot": "best_hotel",
    "instruction": "From the offers JSON, select the single best-value entry and output it VERBATIM as JSON, copying every field of that entry exactly: {\"offer_id\": ..., \"hotel_id\": ..., \"hotel\": ..., \"checkin\": ..., \"checkout\": ..., \"adults\": ..., \"country_code\": ..., \"amount\": ..., \"currency\": ...}"}},
  {"tool": "book_hotel", "args": {"provider": "liteapi", "offer_slot": "best_hotel"}}
]}""",
    ),
    PipelinePattern(
        driver_tool = "send_summary",
        description = "Fetch content, emails, or search results, synthesise, and email the result to a recipient.",
        example     = """\
{"steps": [
  {"tool": "mcp_page_content", "args": {"url": "<url verbatim from task>", "slot_id": "page_content"}},
  {"tool": "spawn_processor",  "args": {"reads": ["page_content"], "out_slot": "summary",
    "instruction": "<specify exact output format>"}},
  {"tool": "send_summary",     "args": {"recipient": "<verbatim email>", "subject": "<verbatim>",
    "body_slot": "summary"}}
]}
{"steps": [
  {"tool": "mcp_email_search", "args": {"filter": {"from": "<sender verbatim>", "limit": 10}, "slot_id": "emails"}},
  {"tool": "spawn_processor",  "args": {"reads": ["emails"], "out_slot": "summary",
    "instruction": "<specify exact output format>"}},
  {"tool": "send_summary",     "args": {"recipient": "<verbatim email or OPERATOR DEFAULT>", "subject": "<inferred>",
    "body_slot": "summary"}}
]}
{"steps": [
  {"tool": "mcp_flight_search", "args": {
    "params": {"origin": "<verbatim>", "destination": "<verbatim>", "date": "<verbatim>"},
    "slot_id": "flight_results"}},
  {"tool": "mcp_hotel_search", "args": {
    "params": {"city": "<full city name>", "check_in": "<verbatim>", "check_out": "<verbatim>", "adults": 1},
    "slot_id": "hotel_results"}},
  {"tool": "spawn_processor",  "args": {"reads": ["flight_results", "hotel_results"], "out_slot": "travel_summary",
    "instruction": "Select the best flight and hotel. Output ONLY the email body (plain text or light markdown): top flight with price/times/airline + booking URL if present; top hotel with name/price/total + booking URL; combined total. Do NOT include a Subject line, greeting preamble, or meta commentary. Keep under 7000 characters."}},
  {"tool": "send_summary",     "args": {"recipient": "<verbatim email or OPERATOR DEFAULT>", "subject": "<inferred>",
    "body_slot": "travel_summary"}}
]}
{"steps": [
  {"tool": "mcp_page_content", "args": {"url": "<url verbatim from task>", "slot_id": "page_content"}},
  {"tool": "spawn_processor",  "args": {"reads": ["page_content"], "out_slot": "digest",
    "instruction": "<specify exact output format>"}},
  {"tool": "send_summary",     "args": {
    "recipient": ["<verbatim email A>", "<verbatim email B>"], "subject": "<verbatim>",
    "body_slot": "digest", "delivery": "combined"}}
]}""",
    ),

    PipelinePattern(
        driver_tool = "send_reply (multi-pipeline)",
        description = "Reply independently to N senders — one pipeline per sender, each with its own fetch and thread context.",
        example     = """\
{"pipelines": [
  {"steps": [
    {"tool": "mcp_email_search", "args": {"filter": {"from": "<sender A verbatim>", "limit": 1}, "slot_id": "email_a"}},
    {"tool": "spawn_processor", "args": {"reads": ["email_a"], "out_slot": "reply_a",
      "instruction": "Write a polite reply based strictly on the email. Output ONLY the reply text."}},
    {"tool": "send_reply", "args": {"recipient": "<sender A verbatim>", "subject": "<verbatim>", "body_slot": "reply_a"}}
  ]},
  {"steps": [
    {"tool": "mcp_email_search", "args": {"filter": {"from": "<sender B verbatim>", "limit": 1}, "slot_id": "email_b"}},
    {"tool": "spawn_processor", "args": {"reads": ["email_b"], "out_slot": "reply_b",
      "instruction": "Write a polite reply based strictly on the email. Output ONLY the reply text."}},
    {"tool": "send_reply", "args": {"recipient": "<sender B verbatim>", "subject": "<verbatim>", "body_slot": "reply_b"}}
  ]}
]}""",
    ),

    PipelinePattern(
        driver_tool = "send_reply",
        description = "Fetch the latest email, draft reply, send to the routing-locked recipient.",
        example     = """\
{"steps": [
  {"tool": "mcp_email_search", "args": {
    "filter": {"from": "<sender verbatim>", "limit": 1}, "slot_id": "email_content"}},
  {"tool": "spawn_processor", "args": {"reads": ["email_content"], "out_slot": "reply_body",
    "instruction": "Write a polite reply body based strictly on what the email says. Do not invent dates, facts, or context not present in the email. Output ONLY the reply text — no subject, no greeting preamble."}},
  {"tool": "send_reply", "args": {"recipient": "<verbatim sender email>",
    "subject": "<verbatim>", "body_slot": "reply_body"}}
]}""",
    ),

    PipelinePattern(
        driver_tool = "schedule_meeting",
        description = "Fetch email request + calendar, propose free slots, schedule with human confirmation.",
        example     = """\
{"steps": [
  {"tool": "mcp_email_search", "args": {
    "filter": {"from": "<sender verbatim>", "limit": 1}, "slot_id": "email_content"}},
  {"tool": "mcp_calendar_search", "args": {
    "filter": {"timeMin": "<ISO8601 Mon 00:00>", "timeMax": "<ISO8601 Fri 23:59>"}, "slot_id": "calendar_events"}},
  {"tool": "spawn_processor", "args": {
    "reads": ["email_content", "calendar_events"], "out_slot": "meeting_proposal",
    "instruction": "Find 2-3 free <N>-minute slots on weekdays (09:00-18:00 {timezone}) that do not overlap any existing calendar event. Output ONLY valid JSON: {\"proposed_slots\": [{\"label\": \"<readable weekday date+time+tz>\", \"start\": \"<ISO8601+tz>\", \"end\": \"<ISO8601+tz>\"}], \"reply_body\": \"<polite email body proposing the times — no subject line>\"}"}},
  {"tool": "schedule_meeting", "args": {"attendee": "<verbatim email from task>",
    "event_title": "<verbatim from task, else 'Meeting'>",
    "reply_subject": "Re: Meeting Request", "slots_slot": "meeting_proposal"}}
]}""",
    ),

    PipelinePattern(
        driver_tool = "modify_emails",
        description = (
            "Apply a bulk Gmail action to all emails from a sender. "
            "No content read, no sub-agents. "
            "action must be one of: add_label | remove_label | archive | "
            "mark_read | mark_unread | star | unstar. "
            "label_name is required only for add_label and remove_label."
        ),
        example     = """\
{"steps": [
  {"tool": "modify_emails", "args": {"sender": "<verbatim sender name or email from task>", "action": "add_label", "label_name": "<verbatim label name>"}}
]}
{"steps": [
  {"tool": "modify_emails", "args": {"sender": "<verbatim sender name or email from task>", "action": "archive"}}
]}""",
    ),
]


def build_patterns_section() -> str:
    """Render _PIPELINE_SHAPES as the FEW-SHOT EXAMPLES section of the planner prompt."""
    lines = []
    for i, p in enumerate(_PIPELINE_SHAPES, 1):
        lines.append(f"Shape {i} — {p.driver_tool}: {p.description}")
        lines.append(p.example)
        lines.append("")
    return "\n".join(lines).rstrip()


# ── Planner system prompt ──────────────────────────────────────────────

_ABSTRACT_PLAN_SYSTEM_TEMPLATE = """\
You are a planning agent for an IPI-resistant multi-agent pipeline.
This is a STATIC manifest: all steps are fixed before any execution begins —
no step can be added, branched, or modified at runtime based on what a fetcher returns.
Output ONLY valid JSON — no explanation, no markdown fences, no prose.
If you cannot form a valid plan for the given task, output ONLY:
{"error": "<brief reason — e.g. 'missing routing field: recipient'>"}
Args marked * are required; unmarked are optional.

Today's date: {today}. Local timezone: {timezone}.

AXIOM: Routing fields (recipient, attendee) must appear verbatim
in the task text or OPERATOR DEFAULTS — never constructed or inferred from context.

MULTI-ACTION: When the task requires N independent actions for N distinct recipients
or contexts (e.g. "reply to A and reply to B"), emit {"pipelines": [{steps}, ...]}
where each sub-plan is a complete independent pipeline ending with one driver tool.
Each recipient must satisfy the AXIOM. Maximum {max_pipelines} pipelines per run.
Use a single {"steps": [...]} plan when one action covers all recipients.

══ REGISTERED CAPABILITIES ══

All sub-agents and driver tools registered for this deployment.
Full arg schemas for every tool are in the TOOL CATALOG below.

{available_capabilities}

══ FEW-SHOT EXAMPLES ══

One complete pipeline per Tier 3 driver tool — imitate the structure, not the literal values.
<WARNING>Do not reuse the slot_ids or tool names from these examples literally.</WARNING>

{patterns}

══ TOOL CATALOG ══

Full arg schemas for all tiers:
  Tier 1 — Data sub-agents        (fetch data, write slot)
  Tier 2 — Processor sub-agents   (transform slots via LLM)
  Tier 3 — Driver tools           (act on the world; automated or human-confirmed)

{tool_catalog}

══ REASON BEFORE WRITING ══

Reason through these internally — do not output this reasoning, only the final JSON:

  1. DRIVER TOOL — choose the Tier 3 driver tool from the TOOL CATALOG whose description best
       matches the task's intended outcome. Do not force-fit; if no tool matches, output an error.
  2. ROUTING FIELDS — apply the AXIOM. Additionally:
       subject/reply_subject may be inferred from task context (e.g. "Summarise my invoices" → "Invoice Summary").
       event_title: use a title that appears in the task; if the task names none, use a short
       generic title such as "Meeting" or "30-minute meeting". NEVER invent a person's name by
       splitting or guessing from an email local-part (e.g. ashahinshamsabadi@… → not "Asha …").
       Include routing fields as args on the Tier 3 driver tool step.
       If OPERATOR DEFAULTS contains a recipient, use it — it carries (T,pub) trust.
       Missing recipient with no OPERATOR DEFAULT → output {"error": "missing routing field: recipient"}.
       If the task is semantically ambiguous (multiple valid interpretations exist), describe the
       ambiguity clearly in the error and suggest two concrete phrasings that would resolve it.
       Example: {"error": "missing routing field: recipient — unclear whether you want a combined
       summary sent to you, or a separate summary sent to each person. Try: 'summarise and send
       me the result' or 'send each of them their own summary'."}
  3. SLOT CHAIN — slots are write-once and immutable after first write. Every slot_id used in reads
       must be declared as an output in a strictly earlier step; no two steps within the same
       pipeline may share a slot_id (slot names may repeat across parallel pipelines).

══ RULES ══

  1. Use only the tool names shown under REGISTERED CAPABILITIES and TOOL CATALOG —
     the only sub-agents and driver tools registered for this deployment; do not invent names.
  2. Only include args listed in the TOOL CATALOG for each tool. Provider-specific fields
     (domain, api_url, mcp_tool, search_params, trusted_action_urls, system_prompt) are
     injected by the concrete mapper — never include them yourself.
  3. slot_id values must be unique within each pipeline and snake_case — slots are write-once
     immutable; a duplicate slot_id within the same pipeline is a runtime error.
  4. reads and body_slot must reference slot_ids declared in earlier steps.
  5. The final step must be exactly one Tier 3 driver tool.
  6. Multi-step sampling — when a task specifies an open-ended range rather than a fixed point
     (e.g. "in August", "cheapest in Q3", "best option across multiple dates/locations"):
     emit one search step per representative sample — typically 3–4 steps spaced evenly across
     the range — each writing to a distinct slot_id. Then add a spawn_processor step that reads
     all result slots and selects the best option. For fixed points, use a single step.
  7. Email bodies (spawn_processor → send_summary / send_reply body_slot): instruct the
     processor to output ONLY the message body — no Subject line, no "here is the email"
     preamble. Subject is a separate (T,pub) routing field. Keep the body under 7000 characters.
"""


def build_planner_system_prompt(
    registry:         ToolRegistry | None = None,
    operator_context: str                 = "",
) -> str:
    """
    Build the Phase 1 system prompt from the template and registry.

    Fills {available_capabilities}, {patterns}, {tool_catalog}, {today}, {timezone}.
    Appends OPERATOR DEFAULTS block when operator_context is non-empty.
    The {timezone} token inside pattern examples is replaced in the same pass.
    """
    if registry is None:
        registry = DEFAULT_REGISTRY
    # NOTE: {today} and {timezone} are substituted in the same pass as {patterns}.
    # Pattern examples contain {timezone} literally — this is intentional; registry
    # content is operator-controlled and uses these tokens deliberately.
    now      = datetime.now().astimezone()
    today    = now.strftime("%Y-%m-%d (%A)")
    timezone = now.strftime("%Z") or "UTC"
    prompt = (
        _ABSTRACT_PLAN_SYSTEM_TEMPLATE
        .replace("{available_capabilities}", registry.capability_summary())
        .replace("{patterns}",               build_patterns_section())
        .replace("{tool_catalog}",           registry.tool_catalog())
        .replace("{today}",                  today)
        .replace("{timezone}",               timezone)
        .replace("{max_pipelines}",          str(_MAX_PIPELINES))
    )
    if operator_context:
        prompt += (
            "\n\n══ OPERATOR DEFAULTS ══\n\n"
            "Operator-supplied values carrying (T,pub) trust — same as verbatim task text.\n"
            "Use only the fields required by your chosen Tier 3 driver tool; ignore the rest.\n\n"
            + operator_context
        )
    return prompt




# ── Validation helpers ────────────────────────────────────────────────

def _is_http_url(value: object, *, https_only: bool = False) -> bool:
    """True if value is a string with a proper http(s):// scheme and non-empty host."""
    if not isinstance(value, str):
        return False
    parts = urlsplit(value)
    allowed = {"https"} if https_only else {"http", "https"}
    return parts.scheme in allowed and bool(parts.netloc)


_EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")
# Lookbehind: conservative — any email-valid char before the address is a boundary violation.
_EMAIL_BOUNDARY = r"[A-Za-z0-9.+_@-]"
# Lookahead: a trailing dot blocks only if followed by an alphanumeric (i.e. part of a longer
# domain like .co.uk or .evil), not when it's a sentence-final period.
_EMAIL_TRAILING = r"(?:[A-Za-z0-9+_@-]|\.[A-Za-z0-9])"


def _is_plausible_email(value: object) -> bool:
    """True if value is a string with exactly one @, non-empty local/domain, no whitespace."""
    return isinstance(value, str) and bool(_EMAIL_RE.fullmatch(value))


# ── ToolContract ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class ToolContract:
    """
    Per-tool structural contract for _validate_plan.

    Authoring invariant enforced by __post_init__: every field listed in
    slot_output / slot_inputs / slot_refs / email_fields / https_fields / http_fields
    must also appear in required.  _validate_plan uses args[f] directly for these fields
    and relies on the required check to have confirmed presence first.
    """
    required:       tuple[str, ...] = ()
    slot_output:    str | None      = None
    slot_inputs:    tuple[str, ...] = ()
    slot_refs:      tuple[str, ...] = ()
    email_fields:   tuple[str, ...] = ()
    https_fields:   tuple[str, ...] = ()
    http_fields:    tuple[str, ...] = ()
    dict_fields:    tuple[str, ...] = ()
    literal_fields: dict[str, frozenset[str]] = field(
        default_factory=dict, hash=False, compare=False,
    )
    is_driver_tool:  bool            = False
    max_uses:        int | None     = None   # Tier 1 tools: 1 (Rule 6)
    max_email_list:  int | None     = None   # max addresses in email_fields; None = unlimited
    string_fields:   tuple[str, ...] = ()    # args that must be a plain str, not a list

    def __post_init__(self) -> None:
        indexed = (
            set(self.slot_inputs)
            | set(self.slot_refs)
            | set(self.email_fields)
            | set(self.https_fields)
            | set(self.http_fields)
        )
        if self.slot_output is not None:
            indexed.add(self.slot_output)
        missing = indexed - set(self.required)
        if missing:
            raise AssertionError(
                f"ToolContract authoring error: {sorted(missing)} are format/slot-checked "
                f"but not listed in 'required'"
            )

# Each entry is the structural contract for one tool.  _validate_plan interprets
# these mechanically — adding a new tool requires only a new dict entry here;
# the validation function itself never needs to change.
#
# Keys:
#   required              — args that must be present and non-falsy (absent, "", [], {} all fail)
#   slot_output           — arg whose value names the slot this step writes; checked for uniqueness
#                           (write-once: a duplicate slot_id is a runtime error in SlotStore)
#   slot_inputs           — args whose values are lists of slot refs; every element must be
#                           declared in a strictly earlier step (arg itself validated as a list)
#   slot_refs             — args whose values are single slot refs; must be declared in an earlier step
#   email_fields          — args that must be a string containing '@' (required; present by construction)
#   https_fields          — args that must start with 'https://' (provider API base URLs)
#   http_fields           — args that must start with 'http' (allows http or https; used for page URLs)
#   dict_fields           — args that must be a dict when present (optional structured params)
#   literal_fields        — {arg: set_of_allowed_values}; checked only when arg is present
#   is_driver_tool        — marks a Tier 3 driver tool; must appear exactly as the last step
#
# Schema authoring contract (enforced by ToolContract.__post_init__ at import time):
# every field listed in slot_output, slot_inputs, slot_refs, email_fields, https_fields,
# and http_fields must also appear in required. _validate_plan accesses these fields via
# args[f] directly, relying on the required check to have confirmed presence first.
# __post_init__ raises AssertionError on any violation so no bad schema can reach runtime.
TOOL_SCHEMA: dict[str, ToolContract] = {
    # ── Tier 1 — Data Sub-Agents ───────────────────────────────────────────
    # max_uses=5: allows multiple sender-filtered fetches (each filter verbatim from task via AXIOM);
    #             prevents unbounded sampling but allows "fetch from A and B" in one plan.
    # max_uses=None: multi-step permitted (page fetch — multiple URLs; flight/hotel — range sampling)
    "mcp_page_content": ToolContract(
        required     = ("url", "slot_id"),
        slot_output  = "slot_id",
        http_fields  = ("url",),   # accepts http or https; rejects file://, ftp://, httpfoo://
    ),
    "mcp_email_search": ToolContract(
        required     = ("api_url", "slot_id"),
        slot_output  = "slot_id",
        https_fields = ("api_url",),
        max_uses     = 5,
    ),
    "mcp_calendar_search": ToolContract(
        required     = ("api_url", "slot_id"),
        slot_output  = "slot_id",
        https_fields = ("api_url",),
        max_uses     = 5,
    ),
    "mcp_flight_search": ToolContract(
        required     = ("domain", "mcp_tool", "slot_id"),
        slot_output  = "slot_id",
        https_fields = ("domain",),
        dict_fields  = ("search_params",),
        # max_uses=None: range searches may emit multiple steps (Rule 6 weekly sampling)
    ),
    "mcp_hotel_search": ToolContract(
        required     = ("domain", "mcp_tool", "slot_id"),
        slot_output  = "slot_id",
        https_fields = ("domain",),
        dict_fields  = ("search_params",),
        # max_uses=None: range searches may emit multiple steps (Rule 6 weekly sampling)
    ),
    # ── Tier 2 — Processor Sub-Agents ─────────────────────────────────────
    "spawn_processor": ToolContract(
        required     = ("reads", "out_slot", "instruction"),
        slot_output  = "out_slot",
        slot_inputs  = ("reads",),
        dict_fields  = ("output_format",),  # optional; appended to instruction as JSON Schema
    ),
    # ── Tier 3 — Driver Tools ──────────────────────────────────────────────
    # Routing fields (recipient, subject, attendee, reply_subject) come from the task string
    # via the planner. driver.run() pre-commits them to state.vars["_routing"] as (T,pub)
    # before step 0 — structurally locked before any sub-agent executes.
    "send_reply": ToolContract(
        required        = ("recipient", "subject", "body_slot"),
        email_fields    = ("recipient",),
        slot_refs       = ("body_slot",),
        max_email_list  = 1,   # send_reply is strictly one-to-one
        is_driver_tool  = True,
    ),
    "send_summary": ToolContract(
        required        = ("recipient", "subject", "body_slot"),
        email_fields    = ("recipient",),
        slot_refs       = ("body_slot",),
        literal_fields  = {"delivery": frozenset({"combined", "separate"})},
        max_email_list  = 25,
        is_driver_tool  = True,
    ),
    "schedule_meeting": ToolContract(
        required        = ("attendee", "event_title", "reply_subject", "slots_slot"),
        email_fields    = ("attendee",),
        slot_refs       = ("slots_slot",),
        max_email_list  = 10,
        is_driver_tool  = True,
    ),
    "book_flight": ToolContract(
        required        = ("provider", "offer_slot"),
        slot_refs       = ("offer_slot",),
        literal_fields  = {"provider": frozenset({"duffel"})},
        is_driver_tool  = True,
    ),
    "book_hotel": ToolContract(
        required        = ("provider", "offer_slot"),
        slot_refs       = ("offer_slot",),
        literal_fields  = {"provider": frozenset({"liteapi"})},
        is_driver_tool  = True,
    ),
    "modify_emails": ToolContract(
        required        = ("sender", "action"),
        string_fields   = ("sender",),
        literal_fields  = {"action": frozenset({
            "add_label", "remove_label", "archive",
            "mark_read", "mark_unread", "star", "unstar",
        })},
        is_driver_tool  = True,
    ),
}


# Fields that _map_to_concrete must inject from the registry.
# Tools that list these in required but have no registry entry → descriptive error in Phase 2.
_PROVIDER_REQUIRED_ARGS = frozenset({"api_url", "domain"})


def _validate_plan(
    plan:             dict,
    *,
    task:             str = "",
    operator_context: str = "",
) -> None:
    """
    Phase 3 — hard-stop structural validation of the LLM-generated manifest.
    Raises PlanValidationError on field-level failures, ValueError on structural ones.
    Driven entirely by TOOL_SCHEMA — adding a tool requires only a new schema entry.

    AXIOM: email_fields values must appear as complete tokens in task or operator_context
    (boundary-matched to prevent substring collisions like a@b.co inside attacker-a@b.com).
    Skipped when both are empty — structural-only mode for tests and hand-built plans.

    Checks (in order): non-empty steps list → per-step: dict shape, known tool, dict args,
    max_uses, required args, slot uniqueness, slot chain ordering, email format + AXIOM,
    https/http URL format, dict_fields type, literal_fields values, driver tool position →
    post-loop: final step is a Tier 3 driver tool.

    Not checked here (intentional):
      trusted_action_urls       — IronFlow before_action gates enforce at use time.
      modify_emails.sender      — Gmail query param, not an addressee; may be a domain.
      spawn_processor semantics — subprocess runner validates instruction/output_format.
      search_params content     — provider-specific; MCP handler validates at runtime.
    """
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("Plan must have a non-empty 'steps' array")

    axiom_haystack      = f"{task}\n{operator_context}".lower() if (task or operator_context) else None
    last_idx            = len(steps) - 1
    declared_slots: set[str]      = set()
    tool_usage:     dict[str, int] = {}

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(f"Step {i + 1}: expected a JSON object, got {type(step).__name__}")
        tool = step.get("tool") or ""
        args = step.get("args", {})
        ctx  = f"Step {i + 1} ({tool})"

        if tool not in TOOL_SCHEMA:
            raise ValueError(f"{ctx}: unknown tool")
        if not isinstance(args, dict):
            raise ValueError(f"{ctx}: 'args' must be a dict, got {type(args).__name__}")

        sc = TOOL_SCHEMA[tool]

        # max_uses: None means unlimited (flight/hotel range sampling); set means capped.
        if sc.max_uses is not None:
            tool_usage[tool] = tool_usage.get(tool, 0) + 1
            if tool_usage[tool] > sc.max_uses:
                raise ValueError(
                    f"{ctx}: '{tool}' used {tool_usage[tool]} times — "
                    f"max_uses={sc.max_uses} (does not support multi-step range sampling)"
                )

        # Required — falsy covers absent, "", [], {}.
        for req in sc.required:
            if not args.get(req):
                raise ValueError(f"{ctx}: missing required arg '{req}'")

        # Slot output — write-once; catches duplicates before SlotStore raises at runtime.
        if sc.slot_output is not None:
            sid = args[sc.slot_output]
            if sid in declared_slots:
                raise ValueError(f"{ctx}: duplicate slot_id '{sid}' (slots are write-once)")
            declared_slots.add(sid)

        # Slot list inputs — each element must be declared in a strictly earlier step.
        for f in sc.slot_inputs:
            reads = args[f]
            if not isinstance(reads, list):
                raise ValueError(f"{ctx}: '{f}' must be a list, got {type(reads).__name__}")
            for slot in reads:
                if slot not in declared_slots:
                    raise ValueError(f"{ctx}: '{f}' references undeclared slot '{slot}'")

        # Single slot refs — must be declared in a strictly earlier step.
        for f in sc.slot_refs:
            slot = args[f]
            if slot not in declared_slots:
                raise ValueError(f"{ctx}: '{f}' references undeclared slot '{slot}'")

        # string_fields — must be a plain str, not a list (e.g. modify_emails.sender).
        for f in sc.string_fields:
            val = args.get(f)
            if val is not None and not isinstance(val, str):
                raise PlanValidationError(
                    f"{ctx}: '{f}' must be a string, got {type(val).__name__}", field=f,
                )

        # Email fields — accept str | list[str]; validate format + AXIOM per element.
        for f in sc.email_fields:
            raw  = args[f]
            addrs: list[str] = list(raw) if isinstance(raw, (list, tuple)) else [raw]

            if not addrs:
                raise PlanValidationError(f"{ctx}: '{f}' must not be empty", field=f)

            if sc.max_email_list is not None and len(addrs) > sc.max_email_list:
                raise PlanValidationError(
                    f"{ctx}: '{f}' has {len(addrs)} addresses — at most {sc.max_email_list} allowed",
                    field=f,
                )

            seen_lower: set[str] = set()
            for addr in addrs:
                if not _is_plausible_email(addr):
                    raise PlanValidationError(
                        f"{ctx}: '{f}'='{addr}' is not a valid email address", field=f,
                    )
                lo = addr.lower()
                if lo in seen_lower:
                    raise PlanValidationError(
                        f"{ctx}: '{f}' contains duplicate address '{addr}'", field=f,
                    )
                seen_lower.add(lo)
                if axiom_haystack is not None:
                    if not re.search(
                        rf"(?<!{_EMAIL_BOUNDARY}){re.escape(lo)}(?!{_EMAIL_TRAILING})",
                        axiom_haystack,
                    ):
                        raise PlanValidationError(
                            f"{ctx}: '{f}'='{addr}' does not appear verbatim in the task or OPERATOR DEFAULTS (AXIOM violation)",
                            field=f,
                        )

        for f in sc.https_fields:
            if not _is_http_url(args[f], https_only=True):
                raise PlanValidationError(f"{ctx}: '{f}'='{args[f]}' must be a valid https:// URL", field=f)

        for f in sc.http_fields:
            if not _is_http_url(args[f], https_only=False):
                raise PlanValidationError(f"{ctx}: '{f}'='{args[f]}' must be a valid http(s):// URL", field=f)

        for f in sc.dict_fields:
            if f in args and not isinstance(args[f], dict):
                raise ValueError(f"{ctx}: '{f}' must be a dict")

        for f, allowed in sc.literal_fields.items():
            if f in args and args[f] not in allowed:
                raise PlanValidationError(f"{ctx}: '{f}' must be one of {sorted(allowed)}, got '{args[f]}'", field=f)

        if sc.is_driver_tool and i != last_idx:
            raise ValueError(f"{ctx}: driver tool must be the last step ({last_idx - i} unreachable step(s) follow)")

    # Every tool was validated above, so direct indexing is safe.
    last_step = steps[-1]
    last_sc = TOOL_SCHEMA[last_step["tool"]]
    if not last_sc.is_driver_tool:
        driver_tools = ", ".join(n for n, sc in TOOL_SCHEMA.items() if sc.is_driver_tool)
        raise ValueError(
            f"Plan must end with a Tier 3 driver tool — "
            f"last step is '{last_step['tool']}'; expected one of: {driver_tools}"
        )

    # Threaded reply drivers (send_reply, schedule_meeting): at most one email fetch,
    # named filter.from required, routing address must match, limit must be 1.
    # Keeps In-Reply-To / thread_id provenance unambiguous. field=None — structural,
    # must NOT open recipient recovery.
    _THREADED_TOOLS = ("send_reply", "schedule_meeting")
    last_tool = last_step.get("tool")
    if last_tool in _THREADED_TOOLS:
        email_searches = [s for s in steps if s.get("tool") == "mcp_email_search"]
        if len(email_searches) > 1:
            raise PlanValidationError(
                f"Step {last_idx + 1} ({last_tool}): at most one mcp_email_search allowed — "
                f"use pipelines for multiple recipients",
            )
        if email_searches:
            filt = email_searches[0].get("args", {}).get("filter")
            if not isinstance(filt, dict):
                filt = {}
            f_from = filt.get("from")
            if not (isinstance(f_from, str) and f_from.strip()):
                raise PlanValidationError(
                    f"Step {last_idx + 1} ({last_tool}): mcp_email_search requires "
                    f"filter.from (not only filter.q)",
                )
            limit = filt.get("limit", 1)
            try:
                limit_n = int(limit)
            except (TypeError, ValueError):
                limit_n = -1
            if limit_n != 1:
                raise PlanValidationError(
                    f"Step {last_idx + 1} ({last_tool}): mcp_email_search filter.limit "
                    f"must be 1 (got {limit!r}) — threading uses the first fetched message",
                )
            routing_key = "recipient" if last_tool == "send_reply" else "attendee"
            routing_raw = last_step.get("args", {}).get(routing_key, "")
            if isinstance(routing_raw, (list, tuple)):
                routing_addrs = [str(a).lower() for a in routing_raw]
            else:
                routing_addrs = [str(routing_raw).lower()]
            if f_from.strip().lower() not in routing_addrs:
                raise PlanValidationError(
                    f"Step {last_idx + 1} ({last_tool}): '{routing_key}'={routing_raw!r} does not "
                    f"include mcp_email_search filter.from='{f_from}' — "
                    f"fetching email from one sender and acting for a different address "
                    f"is likely a planning error",
                )


_ISO_DATE = "%Y-%m-%d"


def _reformat_date(value: str, target_fmt: str) -> str:
    """
    Convert an ISO 8601 date string to provider format; return original if not parseable.

    NOTE: silent fallback means a malformed date reaches the provider without an audit trail.
    A future improvement would emit a trace event here. Callers should validate date format
    upstream when correctness is critical.
    """
    try:
        return datetime.strptime(value, _ISO_DATE).strftime(target_fmt)
    except ValueError:
        return value




def _precheck_shape(plan: dict) -> None:
    """
    Phase 1.5 — lightweight shape check on raw LLM output before concrete mapping.

    Verifies that every step is a dict with a non-empty string tool and a dict args
    (when present). Full structural validation (TOOL_SCHEMA, slot chains, field formats)
    runs in Phase 3 after provider fields are injected. This guard prevents AttributeError
    inside _map_to_concrete from non-dict steps or string args.

    Raises ValueError with a descriptive message on any shape violation.
    """
    if not isinstance(plan, dict):
        raise ValueError(f"Planner output must be a JSON object, got {type(plan).__name__}")
    if "pipelines" in plan and "steps" in plan:
        raise ValueError("Planner output must not contain both 'steps' and 'pipelines'")
    if "pipelines" in plan:
        pipelines = plan["pipelines"]
        if not isinstance(pipelines, list) or not pipelines:
            raise ValueError("'pipelines' must be a non-empty array")
        if len(pipelines) > _MAX_PIPELINES:
            raise ValueError(f"'pipelines' exceeds maximum of {_MAX_PIPELINES}")
        seen_sigs: set[str] = set()
        for i, sub in enumerate(pipelines):
            if not isinstance(sub, dict) or not isinstance(sub.get("steps"), list):
                raise ValueError(f"Pipeline {i + 1}: must be an object with a 'steps' array")
            _precheck_shape(sub)
            sig = json.dumps(sub, sort_keys=True)
            if sig in seen_sigs:
                raise ValueError(
                    f"Pipeline {i + 1} is a duplicate of an earlier pipeline "
                    f"(same driver tool and arguments)"
                )
            seen_sigs.add(sig)
        return
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("Planner output must have a non-empty 'steps' array")
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(
                f"Step {i + 1}: expected a JSON object, got {type(step).__name__}"
            )
        tool = step.get("tool") or ""
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError(f"Step {i + 1}: 'tool' must be a non-empty string")
        args = step.get("args")
        if args is not None and not isinstance(args, dict):
            raise ValueError(
                f"Step {i + 1}: 'args' must be a JSON object, got {type(args).__name__}"
            )

def _map_to_concrete(abstract_plan: dict, registry: ToolRegistry) -> dict:
    """
    Phase 2 — Concrete Mapping: fill provider details from ToolRegistry.

    Only Tier 1 data sub-agents are transformed; Tier 2 (spawn_processor) and
    Tier 3 driver tools pass through unchanged.

    Transforms:
      mcp_email_search / mcp_calendar_search (REST):
        filter={...}  →  api_url=<registry domain>, filter={...}

      mcp_flight_search / mcp_hotel_search (MCP):
        params={origin,...}  →  domain=<registry>, mcp_tool=<registry>,
                                search_params={flyFrom,...}
        (params renamed per MCPSpec.param_map; dates converted per date_fmt;
         values translated per value_maps; unmapped names pass through unchanged)

      mcp_page_content  — capability label injected; URL is caller-supplied, no provider URL added

    Also auto-populates manifest trusted_action_urls from MCPSpec.booking_domain for
    any MCP step whose provider has a booking_domain set.
    """
    concrete_steps:       list[dict] = []
    auto_booking_domains: list[str]  = []

    for step in abstract_plan.get("steps", []):
        tool = step.get("tool", "")
        args = dict(step.get("args", {}))
        spec = registry.find_by_name(tool)

        if spec is None:
            # If the tool requires provider-injected fields but has no registry entry,
            # Phase 3 would fail with a confusing "missing required arg" error. Fail loudly.
            tc = TOOL_SCHEMA.get(tool)
            if tc is not None and _PROVIDER_REQUIRED_ARGS & set(tc.required):
                missing_fields = sorted(_PROVIDER_REQUIRED_ARGS & set(tc.required))
                raise ValueError(
                    f"tool '{tool}' requires provider-injected fields {missing_fields} "
                    f"but has no registry entry — add it to DEFAULT_REGISTRY"
                )

        if spec is not None:
            args["capability"] = spec.capability.value

            if spec.domain != "*":          # "*" = fetch_web (any caller-supplied URL; no provider)
                if spec.tool_type == "rest":
                    args["api_url"] = spec.domain

                else:
                    # MCP fetchers are deterministic — strip any LLM-injected system_prompt.
                    args.pop("system_prompt", None)

                    # Rename params per MCPSpec.param_map; unmapped names pass through unchanged.
                    raw_params    = args.pop("params", {})
                    search_params: dict[str, object] = {
                        spec.param_map.get(k, k): v for k, v in raw_params.items()
                    }

                    # Convert ISO dates to provider-required format (e.g. "2026-07-10" → "10/07/2026").
                    if spec.date_fmt:
                        search_params = {
                            k: _reformat_date(v, spec.date_fmt) if isinstance(v, str) else v
                            for k, v in search_params.items()
                        }

                    # Translate values through provider-specific maps (e.g. cabin class codes).
                    for field, value_map in spec.value_maps.items():
                        if field in search_params and isinstance(search_params[field], str):
                            original           = search_params[field]
                            search_params[field] = value_map.get(original, original)

                    args["domain"]        = spec.domain
                    args["mcp_tool"]      = spec.mcp_tool
                    args["search_params"] = search_params

                    if spec.location_tool:
                        args.setdefault("location_tool", spec.location_tool)
                    if spec.booking_domain:
                        auto_booking_domains.append(spec.booking_domain)

        concrete_steps.append({"tool": tool, "args": args})

    # Whitelist-rebuild: only approved top-level keys propagate — planner-supplied
    # top-level keys (including any attempted trusted_action_urls injection) are dropped.
    result: dict = {"steps": concrete_steps}
    if auto_booking_domains:
        # Auto-populate from registry booking domains only; deduplicate.
        result["trusted_action_urls"] = list(dict.fromkeys(auto_booking_domains))
    return result


def _map_sub_plans(abstract_plan: dict, registry: ToolRegistry) -> dict:
    """Wrap _map_to_concrete to handle both single-plan and pipelines shapes."""
    if "pipelines" not in abstract_plan:
        return _map_to_concrete(abstract_plan, registry)
    return {"pipelines": [_map_to_concrete(sub, registry) for sub in abstract_plan["pipelines"]]}




_PLAN_DECODER = json.JSONDecoder()


def _extract_last_plan_json(raw: str) -> dict:
    """
    Scan raw text for top-level JSON objects; return the last planner-shaped object.

    Preference: last object with a \'steps\' or \'error\' key (planner answers).
    Fallback:   last dict of any shape.
    Raises ValueError with a truncated raw preview if no JSON object is found.

    The LLM sometimes self-corrects — emitting {"error":...} then reasoning prose
    then a valid plan, or vice versa. Taking the last plan-like object ensures the
    final answer wins.  Markdown code fences are handled implicitly: the JSONDecoder
    scanner skips non-JSON text including fence lines.
    """
    last_plan_like: dict | None = None
    last_any:       dict | None = None
    pos = 0
    while pos < len(raw):
        try:
            obj, pos = _PLAN_DECODER.raw_decode(raw, pos)
            if isinstance(obj, dict):
                last_any = obj
                if "steps" in obj or "error" in obj or "pipelines" in obj:
                    last_plan_like = obj
        except json.JSONDecodeError:
            pos += 1
    result = last_plan_like if last_plan_like is not None else last_any
    if result is None:
        raise ValueError(
            f"Planner returned no valid JSON object.\nRaw output:\n{raw[:500]}"
        )
    return result

def generate_plan(
    task:             str,
    operator_context: str                         = "",
    registry:         ToolRegistry | None         = None,
    *,
    api_key:          str | None                  = None,
    client:           anthropic.Anthropic | None  = None,
) -> dict:
    """
    Three-phase manifest planner — see module docstring for the full model.

    operator_context: trusted operator-supplied defaults (e.g. recipient, subject)
                      appended to the system prompt as OPERATOR DEFAULTS.
    registry:         provider registry used in Phases 1+2; defaults to DEFAULT_REGISTRY.
    client:           Anthropic client; defaults to _get_client(api_key).
                      Pass an explicit client in tests to avoid real API calls.

    Design note: the planner runs once, single-shot, with no retry on validation failure.
    Retrying with identical inputs on a transient LLM failure wastes one paid call;
    retrying after PlanValidationError must include the error text in the user message
    to be useful. If retry behaviour is added, gate it behind retries: int = 0 and
    trace both attempts.
    """
    if registry is None:
        registry = DEFAULT_REGISTRY
    _llm = client or _get_client(api_key)

    system = build_planner_system_prompt(registry, operator_context=operator_context)
    # SENSITIVE: system prompt includes operator_context which may contain personal emails.
    _trace.emit(_trace.EvPlanPhase1Start(system=system))
    chunks: list[str] = []
    with _llm.messages.stream(
        model      = _PLANNER_MODEL,
        max_tokens = _PLANNER_MAX_TOKENS,
        timeout    = _PLANNER_TIMEOUT,
        system     = system,
        messages   = [{"role": "user", "content": task}],
    ) as stream:
        for text in stream.text_stream:
            _trace.emit(_trace.EvPlanChunk(text=text))
            chunks.append(text)

    raw = "".join(chunks).strip()
    abstract_plan = _extract_last_plan_json(raw)

    if "error" in abstract_plan:
        msg = abstract_plan["error"]
        # field="recipient" opens the recovery path (ask_recipient or ask_clarification).
        # Both the exact missing-signal and ambiguity messages start with that signal;
        # any other recipient-mentioning rejection is a hard planning failure.
        raise PlanValidationError(f"Planner rejected the task: {msg}", field=_recipient_recovery_field(msg))

    _precheck_shape(abstract_plan)

    plan = _map_sub_plans(abstract_plan, registry)
    _trace.emit(_trace.EvPlanPhase2(plan=plan, abstract_plan=abstract_plan))

    sub_plans = plan["pipelines"] if "pipelines" in plan else [plan]
    for sub in sub_plans:
        _validate_plan(sub, task=task, operator_context=operator_context)
    _trace.emit(_trace.EvPlanPhase3(plan=plan))

    return plan
