"""
driver.py — Manifest executor and tool handlers.

═══════════════════════════════════════════════════════════════
 STRUCTURE
═══════════════════════════════════════════════════════════════

  TOOL HANDLERS
    _StepContext — frozen dataclass (store, policy, driver, state)

    Tier 1 — Data Sub-Agents (operator code, no LLM):
      _handle_mcp_page_content()       HTTP fetch → (U,pub) slot
      _handle_mcp_search()             MCP call → (U,pub) slot  [flight/hotel/any MCP search]
      _handle_mcp_email_search()       Mailbox API → (U,priv) slot + thread_meta
      _handle_mcp_calendar_search()    Calendar REST API → (U,priv) slot

    Tier 2 — Processor Sub-Agents (isolated claude -p):
      _handle_spawn_processor()        synthesise/transform → slot

    Tier 3 — Driver Tools (pure Python, no LLM, no network except the action itself):
      _handle_send_summary()           IronFlow bridge + gate → Gmail API
      _handle_send_reply()             domain check + declassify + bridge + mailbox send
      _handle_schedule_meeting()       human slot confirm + calendar event + reply email
      _handle_modify_emails()          bulk Gmail action on all messages from sender (no content read)

  _HANDLERS                            tool name → handler function
  _dispatch()                          before_tool gate → handler lookup → call

  MANIFEST EXECUTOR
    run(task, plan, store, policy)
      pre-commits routing fields from the Tier 3 driver tool step as (T,pub) before step 0
      (routing block — replaces the create_*_template pattern);
      loops steps via _dispatch; returns final result dict or error dict.
      No LLM involvement.

═══════════════════════════════════════════════════════════════
 EXECUTION MODEL  (run)
═══════════════════════════════════════════════════════════════

  The manifest is fixed before execution begins — no LLM at runtime.
  IronFlow gates fire deterministically before every operation.

  Security invariants (enforced by IronFlow, not by any LLM):
    1. Routing fields (recipient, subject, attendee) carry label (T,pub)
       — pre-committed to state.vars["_routing"] before step 0, sourced
       from the task string via the planner, never from fetched content.
    2. before_spawn() is checked before any sub-agent is launched.
    3. before_action() is the final gate: ROUTING fields must have
       integrity = T.
    4. The manifest is fully validated before execution begins; no
       step is added or modified at runtime.

  Planning is handled separately in planner.py (generate_plan).
  The interface between planner and executor is a plain dict (the manifest).
"""

from __future__ import annotations
import asyncio
import base64
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date
from email.mime.text import MIMEText
import httpx
from .labels import LVal, Label, I, C, taint_all, Capability
from .slots import SlotStore, SlotWriter
from .ironflow_policy import IronFlow, FlowField, FlowMode, IronFlowViolation, Role
from .permissions import AgentSpec, driver_spec, fetcher_spec, processor_spec
from .runner import run_mcp_page_content, run_mcp_search, run_mcp_email_search, run_mcp_calendar_search, run_processor
from .plan_types import PlanState
from . import trace as _trace


# ── Provider endpoint constants ───────────────────────────────────────
# Named here so every Tier 3 driver tool action uses the same string; switching
# providers requires only a change in this block (+ registry update).

_GMAIL_SEND_URL   = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
_GMAIL_REST_BASE  = "https://gmail.googleapis.com/gmail/v1/users/me"
_GCAL_EVENTS_BASE = "https://www.googleapis.com/calendar/v3/calendars"

_HTTP_TIMEOUT   = 15   # seconds — all single-request API calls
_BATCH_TIMEOUT  = 30   # seconds — Gmail batchModify (larger payload)

_BODY_MAX_CHARS = 2000  # matches _BODY_FLOW_FIELD type_params["max_chars"]

_ROUTING_MISSING = "routing not pre-committed — internal error in driver.run()"

_BODY_FLOW_FIELD = FlowField(
    name               = "body",
    base_type          = "BoundedString",
    type_params        = {"max_chars": _BODY_MAX_CHARS},
    required_integrity = I.U,
    mode               = FlowMode.INJECT,
)

# ── Provider config ───────────────────────────────────────────────────

@dataclass(frozen=True)
class ProviderConfig:
    """Immutable snapshot of email-provider credentials."""
    google_token: str


class GmailSendError(RuntimeError):
    """Raised when a Gmail REST API call returns a non-2xx response."""


class GmailClient:
    """
    Thin async wrapper around Gmail REST API calls.

    Takes a pre-created httpx.AsyncClient so callers (and tests) control
    the connection lifecycle. All methods raise GmailSendError on non-2xx
    or malformed JSON responses.
    """

    def __init__(self, token: str, client: httpx.AsyncClient) -> None:
        self._headers = _google_headers(token)
        self._client  = client

    async def send(self, to: str, subject: str, body: str, thread_id: str = "") -> str:
        """POST a MIME email. Returns the sent message id."""
        msg = MIMEText(body, "plain", "utf-8")
        msg["To"] = to; msg["From"] = "me"; msg["Subject"] = subject
        payload: dict = {"raw": base64.urlsafe_b64encode(msg.as_bytes()).decode()}
        if thread_id:
            payload["threadId"] = thread_id
        resp = await self._client.post(_GMAIL_SEND_URL, headers=self._headers, json=payload)
        if resp.status_code not in (200, 201):
            raise GmailSendError(f"Gmail send {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json().get("id", "")
        except Exception as exc:
            raise GmailSendError(f"Gmail send response not JSON: {exc}") from exc

    async def list_labels(self) -> list[dict]:
        """Return all Gmail labels for the authenticated user."""
        resp = await self._client.get(
            f"{_GMAIL_REST_BASE}/labels", headers=self._headers, timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code not in (200, 201):
            raise GmailSendError(f"Gmail labels list {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json().get("labels", [])
        except Exception as exc:
            raise GmailSendError(f"Gmail labels response not JSON: {exc}") from exc

    async def create_label(self, name: str) -> str:
        """Create a Gmail label and return its id. Raises GmailSendError on failure."""
        resp = await self._client.post(
            f"{_GMAIL_REST_BASE}/labels", headers=self._headers,
            json={"name": name}, timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code not in (200, 201):
            raise GmailSendError(
                f"Label {name!r} not found and creation failed "
                f"({resp.status_code}): {resp.text[:200]}"
            )
        try:
            return resp.json()["id"]
        except Exception as exc:
            raise GmailSendError(f"Label creation response unexpected: {exc}") from exc

    async def list_message_ids(self, sender: str) -> list[str]:
        """Return all message ids from sender (paginated)."""
        ids: list[str] = []
        page_token: str | None = None
        while True:
            params: dict = {"q": f"from:{sender}", "maxResults": 500}
            if page_token:
                params["pageToken"] = page_token
            resp = await self._client.get(
                f"{_GMAIL_REST_BASE}/messages", headers=self._headers,
                params=params, timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code not in (200, 201):
                raise GmailSendError(f"Gmail list {resp.status_code}: {resp.text[:200]}")
            try:
                body = resp.json()
                ids.extend(m["id"] for m in body.get("messages", []))
            except Exception as exc:
                raise GmailSendError(f"Gmail list response unexpected: {exc}") from exc
            page_token = body.get("nextPageToken")
            if not page_token:
                break
        return ids

    async def batch_modify(self, message_ids: list[str], modify_body: dict) -> list[str]:
        """Apply modify_body to message_ids in 1000-item batches. Returns failure strings."""
        failures: list[str] = []
        for i in range(0, len(message_ids), 1000):
            batch = message_ids[i : i + 1000]
            resp = await self._client.post(
                f"{_GMAIL_REST_BASE}/messages/batchModify",
                headers=self._headers,
                json={"ids": batch, **modify_body},
                timeout=_BATCH_TIMEOUT,
            )
            if resp.status_code not in (200, 204):
                failures.append(f"{resp.status_code}: {resp.text[:200]}")
        return failures


async def _default_confirm_slot(slots: list[dict]) -> int:
    """Console prompt for schedule_meeting — runs input() in a thread so the event loop is not blocked."""
    n = len(slots)
    answer = await asyncio.to_thread(
        input,
        f"  Create calendar invite? Choose slot (1–{n}), or 0 to send email only: ",
    )
    try:
        return int(answer.strip())
    except ValueError:
        return 0


# ── Tool dispatch ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class _StepContext:
    """Frozen context passed to every step handler.
    References are immutable; store and state are intentionally mutable — they
    accumulate slots and vars as the pipeline executes."""
    store:        SlotStore
    policy:       IronFlow
    driver:       AgentSpec
    state:        PlanState
    config:       ProviderConfig
    confirm_slot: Callable[[list[dict]], Awaitable[int]] = field(
        default=_default_confirm_slot
    )

_Handler = Callable[
    [dict, _StepContext],
    Awaitable[tuple[str, dict | None]],
]


# ── Handler helpers ───────────────────────────────────────────────────

def _google_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _emit_spawned(spec: AgentSpec, kind: str, detail: dict) -> None:
    _trace.emit(_trace.EvAgentSpawned(
        kind        = kind,
        agent_id    = spec.id,
        trust       = str(spec.trust_level),
        permissions = sorted(str(p) for p in spec.perms),
        detail      = detail,
    ))


def _create_slot(store: SlotStore, slot_id: str) -> tuple[str, dict] | None:
    """Return a terminal error tuple if the slot already exists, else create it and return None."""
    if store.exists(slot_id):
        return _terminal_error(f"slot '{slot_id}' already exists", store)
    store.create(slot_id)
    return None


def _slot_result(
    store: SlotStore, state: PlanState, slot_id: str, step_name: str
) -> tuple[str, None]:
    lval = store.read(slot_id)
    state.record_step(step_name)
    return json.dumps({"slot_id": slot_id, "label": str(lval.label),
                        "chars": len(str(lval.value)), "status": "written"}), None


def _get_routing(state: PlanState) -> dict | None:
    try:
        return state.get_var("_routing").value
    except KeyError:
        return None


def _routing_recipient_subject(routing: dict) -> tuple[LVal, LVal]:
    return (
        LVal(routing["recipient"], Label.T_pub()),
        LVal(routing["subject"],   Label.T_pub()),
    )


def _email_domain(address: str) -> str:
    return address.split("@")[-1].lower()


def _bridge_body(policy: IronFlow, lval: LVal) -> LVal:
    return policy.apply_bridge_field(_BODY_FLOW_FIELD, lval)


def _gate_email_action(
    policy: IronFlow, tool: str,
    recipient_lval: LVal, subject_lval: LVal, body_lval: LVal,
) -> None:
    policy.before_action(tool, "recipient", recipient_lval, Role.ROUTING)
    policy.before_action(tool, "subject",   subject_lval,   Role.ROUTING)
    policy.before_action(tool, "body",      body_lval,      Role.CONTENT)


def _email_action_result(
    store: SlotStore,
    recipient_lval: LVal, subject_lval: LVal, body_lval: LVal,
) -> dict:
    return {
        "status":    "success",
        "recipient": recipient_lval.value,
        "subject":   subject_lval.value,
        "body":      body_lval.value,
        "labels": {
            "recipient": str(recipient_lval.label),
            "subject":   str(subject_lval.label),
            "body":      str(body_lval.label),
        },
        "slot_inventory": store.inventory(),
    }


def _declassify_for_send(
    policy: IronFlow,
    lval: LVal,
    *,
    field: str,
    routing: dict,
    who: str,
    not_from: str,
    domain_checked: bool,
    always: bool = False,
) -> LVal:
    """Explicit (_,priv)→(_,pub) downgrade before the email bridge. Skipped when already pub unless always."""
    if not always and lval.label.confidentiality != C.priv:
        return lval
    preconditions = [
        'routing pre-committed in state.vars["_routing"] (T,pub) before step 0',
        f"{who} '{routing[who]}' predetermined from task — not from {not_from}",
        *([f"domain '{_email_domain(routing[who])}' derived from locked {who} — checked before declassify"]
          if domain_checked else []),
        "spawn_processor isolated: no CanNetwork, no CanCallTool, no CanSpawn",
    ]
    return policy.declassify(
        lval,
        field         = field,
        reason        = f"{who} pre-committed before step 0; sub-agent isolated; robust declassification",
        authority     = "DRIVER",
        preconditions = preconditions,
    )


def _check_domain_whitelist(
    address: str, trusted_domains: list[str], empty_msg: str, mismatch_key: str
) -> str | None:
    """Return a plain error reason string if address domain is not in trusted_domains, else None.
    Emits EvGate("DOMAIN_CHECK") on both pass and fail for audit visibility.
    """
    if not trusted_domains:
        return empty_msg
    domain = _email_domain(address)
    detail = f"domain={domain!r} key={mismatch_key!r}"
    if not any(d.lower() == domain for d in trusted_domains):
        msg = f"address domain '{domain}' not in {mismatch_key} {trusted_domains}"
        _trace.emit(_trace.EvGate(gate="DOMAIN_CHECK", who=mismatch_key,
                                  detail=detail, passed=False, blocked=msg))
        return msg
    _trace.emit(_trace.EvGate(gate="DOMAIN_CHECK", who=mismatch_key,
                              detail=detail + " trusted=True", passed=True))
    return None


def _is_weekday(slot: dict) -> bool:
    """True if slot start date is Mon–Fri; True on parse failure (human verifies)."""
    try:
        return date.fromisoformat(str(slot.get("start", ""))[:10]).weekday() < 5
    except (ValueError, TypeError):
        return True


async def _run_tier1(
    ctx: _StepContext,
    slot_id: str,
    spec: AgentSpec,
    kind: str,
    detail: dict,
    step_name: str,
    run_fn: Callable[[SlotWriter], Awaitable[object]],
) -> tuple[str, dict | None]:
    """Shared Tier 1 path: create slot → spawn gate → mint writer → await fetcher → slot result."""
    store, policy, driver, state = ctx.store, ctx.policy, ctx.driver, ctx.state
    if err := _create_slot(store, slot_id):
        return err
    _emit_spawned(spec, kind, detail)
    policy.before_spawn(driver)
    writer = store.writer_for(slot_id, spec.max_label, agent_id=spec.id)
    await run_fn(writer)
    return _slot_result(store, state, slot_id, step_name)


async def _gmail_send(
    to: str,
    subject: str,
    body: str,
    google_token: str,
    state: PlanState,
) -> None:
    """
    Send an email via Gmail. Sets threadId from _email_thread_meta if present
    (In-Reply-To/References omitted — Message-ID is sender-controlled and must not be trusted).
    Emits EvEmailSent on success. Raises GmailSendError on non-2xx response.
    """
    try:
        thread_id = state.get_var("_email_thread_meta").value.get("thread_id", "")
    except KeyError:
        thread_id = ""

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        msg_id = await GmailClient(google_token, client).send(to, subject, body, thread_id)
    _trace.emit(_trace.EvEmailSent(from_addr="me", to=to, message_id=msg_id))


def _pipeline_error(reason: str, policy: IronFlow, store: SlotStore) -> dict:
    violations = policy.violations()
    inventory  = store.inventory()
    _trace.emit(_trace.EvPipelineEnd(status="error", violations=violations, inventory=inventory))
    return {"status": "error", "reason": reason,
            "slot_inventory": inventory, "violations": violations}


def _terminal_error(msg: str, store: SlotStore) -> tuple[str, dict]:
    """Return a terminal (json_str, dict) error pair — stops the pipeline at this step."""
    payload = {"status": "error", "reason": msg}
    return json.dumps(payload), {**payload, "slot_inventory": store.inventory()}


# ── Tier 1 handlers ───────────────────────────────────────────────────

async def _handle_mcp_page_content(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    store, policy = ctx.store, ctx.policy
    url, slot_id = args["url"], args["slot_id"]
    spec = fetcher_spec(f"mcp_page_content_{slot_id}", Capability(args["capability"]), url=url)
    return await _run_tier1(
        ctx, slot_id, spec, "mcp_page_content",
        {"url": url, "slot_id": slot_id,
         "note": "operator code → HTTP fetch + HTML strip (no LLM)"},
        "McpPageContent",
        lambda w: run_mcp_page_content(spec, url, w, policy, shallow=False),
    )


async def _handle_mcp_search(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Shared handler for mcp_flight_search, mcp_hotel_search, and any future MCP search tool."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    domain        = args["domain"]
    mcp_tool      = args["mcp_tool"]
    search_params = args.get("search_params", {})
    location_tool = args.get("location_tool")
    slot_id       = args["slot_id"]

    spec = fetcher_spec(f"mcp_search_{slot_id}", Capability(args["capability"]), mcp_domain=domain)

    async def _run(w: SlotWriter) -> None:
        await run_mcp_search(
            spec, domain, mcp_tool, search_params, w, policy,
            trusted_action_urls=list(state.trusted_action_urls),
            location_tool=location_tool,
        )

    return await _run_tier1(
        ctx, slot_id, spec, "mcp_search",
        {"domain": domain, "mcp_tool": mcp_tool, "slot_id": slot_id,
         "search_params": search_params, "location_tool": location_tool,
         "note": "operator code → MCP call + deterministic URL extract (no LLM; ranking via spawn_processor)"},
        "McpSearch",
        _run,
    )


async def _handle_mcp_email_search(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    store, policy, state = ctx.store, ctx.policy, ctx.state
    api_url, filter_p, slot_id = args["api_url"], args.get("filter", {}), args["slot_id"]
    spec = fetcher_spec(f"mcp_email_search_{slot_id}", Capability(args["capability"]), url=api_url)

    async def _run(w: SlotWriter) -> None:
        thread_meta = await run_mcp_email_search(spec, filter_p, w, policy, google_token=ctx.config.google_token)
        if thread_meta.get("thread_id"):
            # thread_id is a Gmail API envelope field (provider-assigned), not sender-controlled —
            # promoting to (T,pub) is safe here.
            state.set_var("_email_thread_meta", LVal(thread_meta, Label.T_pub()))

    return await _run_tier1(
        ctx, slot_id, spec, "mcp_email_search",
        {"api_url": api_url, "filter": filter_p, "slot_id": slot_id,
         "note": "operator code → registered mailbox provider (no LLM)"},
        "McpEmailSearch",
        _run,
    )


async def _handle_mcp_calendar_search(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    store, policy = ctx.store, ctx.policy
    api_url, filter_p, slot_id = args["api_url"], args.get("filter", {}), args["slot_id"]
    spec = fetcher_spec(f"mcp_calendar_search_{slot_id}", Capability(args["capability"]), url=api_url)
    return await _run_tier1(
        ctx, slot_id, spec, "mcp_calendar_search",
        {"api_url": api_url, "filter": filter_p, "slot_id": slot_id,
         "note": "operator code → Google Calendar REST API (no LLM)"},
        "McpCalendarSearch",
        lambda w: run_mcp_calendar_search(spec, filter_p, w, policy, google_token=ctx.config.google_token),
    )


# ── Tier 2 handlers ───────────────────────────────────────────────────

async def _handle_spawn_processor(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    store, policy, driver, state = ctx.store, ctx.policy, ctx.driver, ctx.state
    reads, out_slot = args["reads"], args["out_slot"]
    instruction = args["instruction"]
    if output_format := args.get("output_format"):
        instruction = (
            f"{instruction}\n\n"
            f"Output ONLY valid JSON matching this schema:\n{json.dumps(output_format, indent=2)}"
        )

    for sid in reads:
        if not store.is_written(sid):
            return _terminal_error(f"slot '{sid}' not written", store)

    if err := _create_slot(store, out_slot):
        return err

    agent_base   = Label(I.U, C.pub)
    input_labels = [store.read(sid).label for sid in reads]
    out_label    = taint_all(input_labels + [agent_base])
    spec = processor_spec(f"proc_{out_slot}", out_label, instruction)
    _emit_spawned(spec, "processor", {"reads": reads, "out_slot": out_slot, "out_label": str(out_label)})
    policy.before_spawn(driver)
    reader = store.reader_for(reads, agent_id=spec.id, max_label=spec.max_label)
    writer = store.writer_for(out_slot, out_label, agent_id=spec.id)
    await run_processor(reads, reader, writer, system_prompt=spec.system_prompt, agent_id=spec.id, timeout=300)
    return _slot_result(store, state, out_slot, "SpawnProcessor")


# ── Tier 3 handlers ───────────────────────────────────────────────────

async def _handle_send_summary(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """
    Driver tool step: send a summary email using routing pre-committed by driver.run().

    recipient and subject are read from state.vars["_routing"] — committed as
    (T,pub) before step 0, before any external content was fetched.
    IPI-based routing injection is structurally impossible.
    """
    store, policy, state, config = ctx.store, ctx.policy, ctx.state, ctx.config
    body_slot = args["body_slot"]

    if not store.is_written(body_slot):
        return _terminal_error(f"body_slot '{body_slot}' not written", store)

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)

    if not config.google_token:
        return _terminal_error(
            "no email credentials configured (set GOOGLE_ACCESS_TOKEN)",
            store,
        )

    recipient_lval, subject_lval = _routing_recipient_subject(routing)
    # No domain whitelist check here: send_summary recipient comes directly from the
    # task string (never from a fetched email), so its domain is already operator-trusted.
    # send_reply adds a domain check because the recipient is derived from an email fetch.
    body_lval = _bridge_body(policy, _declassify_for_send(
        policy, store.read(body_slot), field=body_slot, routing=routing,
        who="recipient", not_from="fetched content", domain_checked=False,
    ))

    _gate_email_action(policy, "send_summary", recipient_lval, subject_lval, body_lval)

    try:
        await _gmail_send(
            recipient_lval.value, subject_lval.value,
            str(body_lval.value), config.google_token, state,
        )
    except GmailSendError as exc:
        return _terminal_error(str(exc), store)

    _trace.emit(_trace.EvActionFired(
        recipient=recipient_lval.value, recipient_label=str(recipient_lval.label),
        subject=subject_lval.value, subject_label=str(subject_lval.label),
        body_chars=len(str(body_lval.value)), body_label=str(body_lval.label),
        body_preview=str(body_lval.value)[:120],
    ))

    state.record_step("SendSummary")
    return json.dumps({"status": "delivered"}), _email_action_result(
        store, recipient_lval, subject_lval, body_lval,
    )


async def _handle_send_reply(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """
    Driver tool step: send a reply email using routing pre-committed by driver.run().

    recipient and subject are read from state.vars["_routing"] — committed as
    (T,pub) before step 0, before any external content was fetched.
    IPI-based routing injection is structurally impossible.
    """
    store, policy, state, config = ctx.store, ctx.policy, ctx.state, ctx.config
    body_slot = args["body_slot"]

    if not store.is_written(body_slot):
        return _terminal_error(f"body_slot '{body_slot}' not written", store)

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)

    # send_reply is Gmail-only (requires threadId for reply threading).
    if not config.google_token:
        return _terminal_error("GOOGLE_ACCESS_TOKEN not set (send_reply requires Gmail)", store)

    recipient_lval, subject_lval = _routing_recipient_subject(routing)
    if reason := _check_domain_whitelist(
        routing["recipient"], [_email_domain(routing["recipient"])],
        "invalid recipient in routing — driver.run() pre-commitment error",
        "trusted_reply_domains",
    ):
        return _terminal_error(reason, store)

    raw_body = store.read(body_slot)
    body_lval = _bridge_body(policy, _declassify_for_send(
        policy, raw_body, field=body_slot, routing=routing,
        who="recipient", not_from="email content", domain_checked=True, always=True,
    ))

    _gate_email_action(policy, "send_reply", recipient_lval, subject_lval, body_lval)

    try:
        await _gmail_send(
            recipient_lval.value, subject_lval.value,
            str(body_lval.value), config.google_token, state,
        )
    except GmailSendError as exc:
        return _terminal_error(str(exc), store)

    _trace.emit(_trace.EvReplyActionFired(
        recipient=recipient_lval.value, recipient_label=str(recipient_lval.label),
        subject=subject_lval.value, subject_label=str(subject_lval.label),
        body_chars=len(str(body_lval.value)),
        body_label_before=str(raw_body.label), body_label_after=str(body_lval.label),
        body_preview=str(body_lval.value)[:120],
    ))

    state.record_step("SendReply")
    return json.dumps({"status": "delivered"}), _email_action_result(
        store, recipient_lval, subject_lval, body_lval,
    )


async def _handle_schedule_meeting(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """
    Driver tool step: present proposed meeting slots to human, create calendar event
    for the chosen slot, and send a reply email proposing the times.

    Routing (attendee, reply_subject, event_title) read from state.vars["_routing"]
    — pre-committed before step 0 by driver.run() from the driver tool step args.
    IPI-based routing injection is structurally impossible.
    """
    store, policy, state = ctx.store, ctx.policy, ctx.state
    slots_slot = args["slots_slot"]

    if not store.is_written(slots_slot):
        return _terminal_error(f"slots_slot '{slots_slot}' not written", store)

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)

    attendee_lval = LVal(routing["attendee"],      Label.T_pub())
    subject_lval  = LVal(routing["reply_subject"], Label.T_pub())
    event_title   = routing["event_title"]
    calendar_id   = str(routing.get("calendarId", "primary"))
    google_token  = ctx.config.google_token
    trusted_domains = [_email_domain(routing["attendee"])]

    if reason := _check_domain_whitelist(
        routing["attendee"], trusted_domains,
        "invalid attendee in routing — driver.run() pre-commitment error",
        "trusted_attendee_domains",
    ):
        return _terminal_error(reason, store)

    raw_slots = store.read(slots_slot)
    slots_declassified = _declassify_for_send(
        policy, raw_slots, field=slots_slot, routing=routing,
        who="attendee", not_from="fetched content", domain_checked=True, always=True,
    )

    try:
        slots_data: dict = json.loads(str(slots_declassified.value))
    except json.JSONDecodeError:
        return _terminal_error(
            "processor output is not valid JSON — "
            "spawn_processor instruction must specify JSON output with "
            "'proposed_slots' and 'reply_body' keys",
            store,
        )

    proposed_slots: list[dict] = [s for s in slots_data.get("proposed_slots", []) if _is_weekday(s)]
    reply_body: str = slots_data.get("reply_body", str(slots_declassified.value))

    if not proposed_slots:
        return _terminal_error("no 'proposed_slots' in processor output", store)

    policy.before_action("schedule_meeting", "attendee", attendee_lval, Role.ROUTING)
    policy.before_action("schedule_meeting", "subject",  subject_lval,  Role.ROUTING)

    _trace.emit(_trace.EvMeetingOptionsReady(
        attendee=routing["attendee"], event_title=event_title,
        proposed_slots=proposed_slots, trusted_domains=trusted_domains,
    ))

    choice = await ctx.confirm_slot(proposed_slots)

    approved    = 1 <= choice <= len(proposed_slots)
    chosen_slot = proposed_slots[choice - 1] if approved else None

    _trace.emit(_trace.EvMeetingConfirmation(
        proposed_slots=proposed_slots,
        chosen_index=choice - 1 if approved else -1,
        approved=approved,
    ))

    if approved:
        slot_label = chosen_slot.get("label", f"{chosen_slot['start']} — {chosen_slot['end']}")
        reply_body_lval = LVal(
            f"Hi,\n\nI've confirmed our meeting for {slot_label}. "
            f"A calendar invite has been sent your way.\n\nLooking forward to it!",
            slots_declassified.label,
        )
    else:
        reply_body_lval = LVal(reply_body[:_BODY_MAX_CHARS], slots_declassified.label)

    body_lval = _bridge_body(policy, reply_body_lval)
    policy.before_action("schedule_meeting", "body", body_lval, Role.CONTENT)

    event_id, event_link = "", ""
    start_label, end_label = "(no invite)", "(no invite)"

    if approved:
        start_lval = LVal(chosen_slot["start"], Label.T_pub())
        end_lval   = LVal(chosen_slot["end"],   Label.T_pub())
        start_label, end_label = str(start_lval.label), str(end_lval.label)

        policy.before_action("schedule_meeting", "start_time", start_lval, Role.ROUTING)
        policy.before_action("schedule_meeting", "end_time",   end_lval,   Role.ROUTING)

        if google_token:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                cal_resp = await client.post(
                    f"{_GCAL_EVENTS_BASE}/{calendar_id}/events",
                    headers=_google_headers(google_token),
                    json={
                        "summary":   event_title,
                        "start":     {"dateTime": chosen_slot["start"]},
                        "end":       {"dateTime": chosen_slot["end"]},
                        "attendees": [{"email": routing["attendee"]}],
                    },
                )
            if cal_resp.status_code not in (200, 201):
                return _terminal_error(f"Calendar API {cal_resp.status_code}: {cal_resp.text[:200]}", store)
            ev_data    = cal_resp.json()
            event_id   = ev_data.get("id", "")
            event_link = ev_data.get("htmlLink", "")

    if google_token:
        try:
            await _gmail_send(
                attendee_lval.value, subject_lval.value,
                str(body_lval.value), google_token, state,
            )
        except GmailSendError as exc:
            return _terminal_error(str(exc), store)

    _trace.emit(_trace.EvMeetingScheduled(
        attendee=attendee_lval.value, attendee_label=str(attendee_lval.label),
        event_title=event_title,
        start_time=chosen_slot["start"] if chosen_slot else "",
        end_time=chosen_slot["end"] if chosen_slot else "",
        start_label=start_label, end_label=end_label,
        event_id=event_id, event_link=event_link,
        reply_sent=bool(google_token),
        body_chars=len(str(body_lval.value)),
        body_label_before=str(raw_slots.label), body_label_after=str(body_lval.label),
    ))

    state.record_step("ScheduleMeeting")
    return json.dumps({"status": "scheduled", "event_id": event_id}), {
        "status":      "success",
        "attendee":    attendee_lval.value,
        "event_title": event_title,
        "slot":        chosen_slot["label"] if chosen_slot else "(email only)",
        "event_id":    event_id,
        "labels": {
            "attendee":   str(attendee_lval.label),
            "subject":    str(subject_lval.label),
            "start_time": start_label,
            "end_time":   end_label,
            "body":       str(body_lval.label),
        },
        "slot_inventory": store.inventory(),
    }


# System-label actions that need no custom label resolution.
_GMAIL_SYSTEM_ACTIONS: dict[str, dict] = {
    "archive":     {"removeLabelIds": ["INBOX"]},
    "mark_read":   {"removeLabelIds": ["UNREAD"]},
    "mark_unread": {"addLabelIds":    ["UNREAD"]},
    "star":        {"addLabelIds":    ["STARRED"]},
    "unstar":      {"removeLabelIds": ["STARRED"]},
}
_GMAIL_LABEL_ACTIONS = frozenset({"add_label", "remove_label"})
_GMAIL_VALID_ACTIONS   = _GMAIL_LABEL_ACTIONS | frozenset(_GMAIL_SYSTEM_ACTIONS)


async def _handle_modify_emails(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """
    Driver tool step: apply a bulk Gmail action to every message from sender.

    sender and action are read from state.vars["_routing"] — pre-committed as (T,pub)
    before step 0 by driver.run(). Gmail API filters server-side — only opaque message
    IDs are handled; email content is never read. No (U,priv) slot is created.
    IPI surface: zero.

    label_name comes from step args (not routing) because it is a Gmail-internal label
    name, not a routing/security field — it does not require (T,pub) pre-commitment.
    """
    store, policy, state = ctx.store, ctx.policy, ctx.state
    label_name   = args.get("label_name", "")
    google_token = ctx.config.google_token

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)

    sender = routing["sender"]
    action = routing["action"]

    sender_lval = LVal(sender, Label.T_pub())
    action_lval = LVal(action, Label.T_pub())

    policy.before_action("modify_emails", "sender", sender_lval, Role.ROUTING)
    policy.before_action("modify_emails", "action", action_lval, Role.ROUTING)

    if not google_token:
        return json.dumps({"status": "skipped", "reason": "GOOGLE_ACCESS_TOKEN not set"}), {
            "status": "skipped", "sender": sender, "action": action,
            "labels": {"sender": str(sender_lval.label), "action": str(action_lval.label)},
            "slot_inventory": store.inventory(),
        }

    def _modify_err(reason: str) -> tuple[str, dict]:
        d = {"status": "error", "reason": reason,
             "labels": {"sender": str(sender_lval.label), "action": str(action_lval.label)},
             "slot_inventory": store.inventory()}
        return json.dumps({"status": "error", "reason": reason}), d

    if action not in _GMAIL_VALID_ACTIONS:
        return _modify_err(
            f"Unknown action {action!r}. Valid actions: {', '.join(sorted(_GMAIL_VALID_ACTIONS))}"
        )
    if action in _GMAIL_LABEL_ACTIONS and not label_name:
        return _modify_err(f"action '{action}' requires label_name")

    resolved_label_id = ""
    message_ids: list[str] = []
    batch_failures: list[str] = []

    async with httpx.AsyncClient() as client:
        gmail = GmailClient(google_token, client)
        try:
            if action in _GMAIL_SYSTEM_ACTIONS:
                modify_body = _GMAIL_SYSTEM_ACTIONS[action]
            else:
                all_labels = await gmail.list_labels()
                label_id: str | None = next(
                    (l["id"] for l in all_labels if l.get("name", "").lower() == label_name.lower()),
                    None,
                )
                if label_id is None:
                    if action == "remove_label":
                        return _modify_err(f"Label {label_name!r} not found in Gmail — nothing to remove")
                    label_id = await gmail.create_label(label_name)
                resolved_label_id = label_id
                modify_body = (
                    {"addLabelIds": [label_id]} if action == "add_label"
                    else {"removeLabelIds": [label_id]}
                )
            message_ids   = await gmail.list_message_ids(sender)
            batch_failures = await gmail.batch_modify(message_ids, modify_body)
        except GmailSendError as exc:
            return _modify_err(str(exc))

    _trace.emit(_trace.EvEmailsModified(
        sender=sender, action=action, label_name=label_name, label_id=resolved_label_id,
        message_count=len(message_ids),
        sender_label=str(sender_lval.label), action_label=str(action_lval.label),
    ))

    state.record_step("ModifyEmails")
    failed   = len(batch_failures)
    modified = len(message_ids) - failed
    result: dict = {
        "status": "success", "sender": sender, "action": action,
        "label_name": label_name, "label_id": resolved_label_id,
        "modified": modified, "failed": failed,
        "labels": {"sender": str(sender_lval.label), "action": str(action_lval.label)},
        "slot_inventory": store.inventory(),
    }
    if batch_failures:
        result["batch_failure_details"] = batch_failures
    return json.dumps({"status": "modified", "action": action, "modified": modified, "failed": failed}), result


# Tier 1 tools that produce a single slot output and have no slot_inputs.
# Only these are eligible for parallel batching in run().
_TIER1_TOOLS: frozenset[str] = frozenset({
    "mcp_page_content",
    "mcp_email_search",
    "mcp_calendar_search",
    "mcp_flight_search",
    "mcp_hotel_search",
})


def _next_batch_end(steps: list[dict], start: int) -> int:
    """
    Return the exclusive end index of the next execution batch starting at `start`.

    Consecutive Tier 1 steps are batched together when no step in the batch
    reads a slot written by another step in the same batch (i.e. they are
    mutually independent).  All other steps form singleton batches.
    """
    if steps[start]["tool"] not in _TIER1_TOOLS:
        return start + 1
    written: set[str] = set()
    j = start
    while j < len(steps):
        step = steps[j]
        if step["tool"] not in _TIER1_TOOLS:
            break
        if set(step["args"].get("reads", [])) & written:
            break   # depends on a slot produced inside this batch — split here
        slot_out = step["args"].get("slot_id")
        if slot_out:
            written.add(slot_out)
        j += 1
    return j


_HANDLERS: dict[str, _Handler] = {
    "mcp_page_content":    _handle_mcp_page_content,
    "mcp_email_search":    _handle_mcp_email_search,
    "mcp_calendar_search": _handle_mcp_calendar_search,
    "mcp_flight_search":   _handle_mcp_search,
    "mcp_hotel_search":    _handle_mcp_search,
    "spawn_processor":     _handle_spawn_processor,
    "send_summary":        _handle_send_summary,
    "send_reply":          _handle_send_reply,
    "schedule_meeting":    _handle_schedule_meeting,
    "modify_emails":       _handle_modify_emails,
}


async def _dispatch(
    name: str, args: dict, ctx: _StepContext,
) -> tuple[str, dict | None]:
    ctx.policy.before_tool(ctx.driver, name)
    handler = _HANDLERS.get(name)
    if handler is None:
        raise RuntimeError(f"no handler registered for tool '{name}' — add it to _HANDLERS")
    return await handler(args, ctx)


# Maps each Tier 3 driver tool to routing fields (T,pub) pre-committed before step 0.
_DRIVER_ROUTING_FIELDS: dict[str, list[str]] = {
    "send_summary":     ["recipient", "subject"],
    "send_reply":       ["recipient", "subject"],
    "schedule_meeting": ["attendee", "event_title", "reply_subject"],
    "modify_emails":    ["sender", "action"],
}


async def run(
    task: str, plan: dict, store: SlotStore, policy: IronFlow,
    *,
    google_token: str = "",
    confirm_slot: Callable[[list[dict]], Awaitable[int]] = _default_confirm_slot,
) -> dict:
    """
    Execute a validated manifest produced by generate_plan().

    Pre-commits routing fields from the Tier 3 driver tool step as (T,pub) before step 0,
    structurally locking routing before any fetch begins.
    Steps are dispatched in order with no LLM involvement. IronFlow gates fire
    deterministically before every operation. Returns the final result dict from
    the driver tool step, or an error dict on failure.

    confirm_slot — injected callback for schedule_meeting human approval;
                   defaults to console input() wrapped in asyncio.to_thread.
    """
    if not plan.get("steps"):
        return _pipeline_error("manifest has no steps", policy, store)

    driver = driver_spec()
    config = ProviderConfig(google_token=google_token)
    state  = PlanState(trusted_action_urls=tuple(plan.get("trusted_action_urls", [])))
    ctx    = _StepContext(
        store=store, policy=policy, driver=driver, state=state,
        config=config, confirm_slot=confirm_slot,
    )

    driver_step = plan["steps"][-1]
    driver_tool = driver_step.get("tool", "")
    driver_args = driver_step.get("args", {})
    if routing_keys := _DRIVER_ROUTING_FIELDS.get(driver_tool, []):
        routing_block: dict[str, object] = {
            k: driver_args[k] for k in routing_keys if k in driver_args
        }
        missing = [k for k in routing_keys if k not in routing_block]
        if missing:
            return _pipeline_error(
                f"{driver_tool} missing required routing fields: {missing}", policy, store
            )
        state.set_var("_routing", LVal(routing_block, Label.T_pub()))
        _trace.emit(_trace.EvRoutingLocked(driver_tool=driver_tool, routing=routing_block))

    _trace.emit(_trace.EvDriverStart(task=task))

    steps    = plan["steps"]
    pos      = 0
    step_num = 0
    while pos < len(steps):
        end   = _next_batch_end(steps, pos)
        batch = steps[pos:end]
        pos   = end

        if len(batch) == 1:
            step = batch[0]
            _trace.emit(_trace.EvPlanStep(
                turn=step_num + 1, tool=step["tool"], args=step["args"]
            ))
            step_num += 1
            try:
                _, final = await _dispatch(step["tool"], step["args"], ctx)
            except IronFlowViolation as exc:
                return _pipeline_error(f"policy violation: {exc}", policy, store)
            except Exception as exc:
                return _pipeline_error(str(exc), policy, store)
            finals = [final] if final is not None else []
        else:
            # Multi-step batch: announce and run each step in sequence.
            # asyncio.gather would interleave trace output — flight writes appearing
            # inside the hotel sub-agent section, back-to-back step announcements
            # before either sub-agent starts — making the pipeline trace unreadable.
            raw = []
            for s in batch:
                _trace.emit(_trace.EvPlanStep(
                    turn=step_num + 1, tool=s["tool"], args=s["args"]
                ))
                step_num += 1
                try:
                    raw.append(await _dispatch(s["tool"], s["args"], ctx))
                except Exception as e:
                    raw.append(e)
            finals = []
            for r in raw:
                if isinstance(r, IronFlowViolation):
                    return _pipeline_error(f"policy violation: {r}", policy, store)
                if isinstance(r, Exception):
                    return _pipeline_error(str(r), policy, store)
                _, f = r
                if f is not None:
                    finals.append(f)

        if finals:
            final = finals[0]
            _trace.emit(_trace.EvPipelineEnd(
                status=final.get("status", "success"),
                violations=policy.violations(),
                inventory=store.inventory(),
            ))
            return final

    return _pipeline_error("manifest completed without terminal step", policy, store)
