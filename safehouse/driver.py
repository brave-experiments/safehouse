"""
driver.py — Manifest executor and tool handlers.

═══════════════════════════════════════════════════════════════
 STRUCTURE
═══════════════════════════════════════════════════════════════

  TOOL HANDLERS
    _StepContext — frozen dataclass (store, policy, driver, state)

    Tier 1 — Data Sub-Agents (operator code, no LLM):
      _handle_mcp_page_content()       HTTP fetch → (U,pub) slot
      _handle_mcp_email_search()       Mailbox API → (U,priv) slot + thread_meta
      _handle_mcp_calendar_search()    Calendar REST API → (U,priv) slot
      _handle_duffel_flight_search()   Duffel REST → (U,pub) slot
      _handle_liteapi_hotel_search()   LiteAPI REST → (U,pub) slot

    Tier 2 — Processor Sub-Agents (isolated SDK call, no tools):
      _handle_spawn_processor()        synthesise/transform → slot

    Tier 3 — Driver Tools (pure Python, no LLM, no network except the action itself):
      _handle_send_summary()           IronFlow bridge + gate → Gmail API
      _handle_send_reply()             slot-bound declassify + bridge + mailbox send
      _handle_schedule_meeting()       human slot confirm + calendar event + reply email
      _handle_modify_emails()          bulk Gmail action on all messages from sender (no content read)
      _handle_book_flight()            re-validate offer + ceiling + grant → Duffel order
      _handle_book_hotel()             re-search + prebook + ceiling + grant → LiteAPI booking
      _handle_create_calendar_event()  routing-only calendar write (no slot content)

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
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from email.mime.text import MIMEText
import httpx
from .exceptions import ConfirmationRequired
from .labels import LVal, Label, I, C, taint_all, Capability
from .slots import SlotStore, SlotWriter
from .secrets import SecretRegistry
from .ironflow_policy import IronFlow, FlowField, FlowMode, IronFlowViolation, Role
from .permissions import AgentSpec, driver_spec, fetcher_spec, processor_spec
from .runner import ProviderAuthError, run_mcp_page_content, run_mcp_email_search, run_mcp_calendar_search, run_processor, run_duffel_flight_search, run_liteapi_hotel_search, run_github_issue_read, run_github_issue_search, run_github_issue_list, run_github_pr_read, run_github_pr_search, _duffel_auth_headers, _liteapi_headers, _github_headers
from .plan_types import PlanState
from .release import (
    DRIVER_RELEASE,
    EMAIL_BODY_MAX_CHARS,
    ReleaseTransformError,
    apply_release_transform,
)
from . import trace as _trace


# ── Provider endpoint constants ───────────────────────────────────────
# Named here so every Tier 3 driver tool action uses the same string; switching
# providers requires only a change in this block (+ registry update).

_GMAIL_SEND_URL   = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
_GMAIL_REST_BASE  = "https://gmail.googleapis.com/gmail/v1/users/me"
_GCAL_EVENTS_BASE = "https://www.googleapis.com/calendar/v3/calendars"

_HTTP_TIMEOUT   = 15   # seconds — all single-request API calls
_BATCH_TIMEOUT  = 30   # seconds — Gmail batchModify (larger payload)

_BODY_MAX_CHARS = EMAIL_BODY_MAX_CHARS

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
    """Immutable snapshot of provider credentials. Resolved in the CLI layer;
    never placed in a slot, label, trace payload, or sub-agent input (invariant #6)."""
    google_token: str
    duffel_token: str = ""
    liteapi_key:  str = ""
    passenger:    Mapping[str, str] | None = None   # profile from operator config — never a slot
    max_booking_amount: str = ""                     # "<amount> <currency>", e.g. "300 GBP" — see _check_spend_ceiling
    github_token: str = ""
    min_github_integrity: str = ""                       # object-integrity floor; "" = gate disabled
    github_blocked_users: frozenset[str] = frozenset()   # operator blocklist, lowercased logins
    anthropic_api_key: str = ""                      # Tier-2 processor's own credential


# ProviderConfig fields split by whether the value is a credential. Every field
# must appear in exactly one set, so adding one forces a decision about whether it
# needs containment rather than defaulting to "no".
_SECRET_CONFIG_FIELDS = frozenset({
    "google_token", "duffel_token", "liteapi_key", "github_token", "anthropic_api_key",
})
_NON_SECRET_CONFIG_FIELDS = frozenset({
    "passenger", "max_booking_amount", "min_github_integrity", "github_blocked_users",
})


def build_secret_registry(*, google_token: str = "", duffel_token: str = "",
                           liteapi_key: str = "", github_token: str = "",
                           anthropic_api_key: str = "") -> SecretRegistry:
    """Registry for one run. Keyword names are the reportable credential names,
    and are checked against _SECRET_CONFIG_FIELDS by signature introspection."""
    return SecretRegistry({
        "google_token":      google_token,
        "duffel_token":      duffel_token,
        "liteapi_key":       liteapi_key,
        "github_token":      github_token,
        "anthropic_api_key": anthropic_api_key,
    })


class GmailSendError(RuntimeError):
    """Raised when a Gmail REST API call returns a non-2xx response.

    Carries the HTTP status so callers can distinguish a rejected credential
    (401/403 — operator-fixable) from a genuine failure. Kept as its own type
    rather than raising ProviderAuthError because several handlers catch it to
    attach do-not-retry context (partial sends, an already-created event) that
    an escaping exception would lose.
    """

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


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

    async def send(
        self,
        to: str,
        subject: str,
        body: str,
        thread_id: str = "",
        *,
        in_reply_to: str = "",
        references: str = "",
    ) -> str:
        """
        POST a MIME email. Returns the sent message id.

        For threaded replies, pass thread_id plus In-Reply-To / References
        (RFC 5322). Recipients' clients key off those headers; threadId alone
        is not enough outside the sender's Gmail view.
        """
        msg = MIMEText(body, "plain", "utf-8")
        msg["To"] = to
        msg["From"] = "me"
        msg["Subject"] = subject
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
            msg["References"] = references or in_reply_to
        payload: dict = {"raw": base64.urlsafe_b64encode(msg.as_bytes()).decode()}
        if thread_id:
            payload["threadId"] = thread_id
        resp = await self._client.post(_GMAIL_SEND_URL, headers=self._headers, json=payload)
        if resp.status_code not in (200, 201):
            raise GmailSendError(f"Gmail send {resp.status_code}: {resp.text[:200]}")
        # 2xx already committed the send — never raise after this or do_not_retry is lost.
        try:
            return resp.json().get("id", "")
        except Exception:
            return ""

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
    """Console prompt for schedule_meeting — runs input() in a thread so the event loop is not blocked.

    Display of start→end is owned by EvMeetingOptionsReady / CLI confirmers
    (no print() in safehouse/). This fallback only collects the index.
    """
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
    accumulate slots and vars as the pipeline executes. The policy must govern
    this exact store and must already hold any routing precommit required by
    handlers called outside run()."""
    store:        SlotStore
    policy:       IronFlow
    driver:       AgentSpec
    state:        PlanState
    config:       ProviderConfig
    confirm_slot: Callable[[list[dict]], Awaitable[int]] = field(
        default=_default_confirm_slot
    )

    def __post_init__(self) -> None:
        if not self.policy.bound_to(self.store):
            raise ValueError("IronFlow policy must be bound to the context SlotStore")

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


def _get_routing(state: PlanState) -> Mapping[str, object] | None:
    try:
        return state.get_var("_routing").value
    except KeyError:
        return None


def _freeze_routing(routing: dict) -> dict:
    """Freeze any list values as tuples — prevents post-lock mutation of the routing block."""
    return {k: tuple(v) if isinstance(v, list) else v for k, v in routing.items()}


def _routing_recipient_subject(routing: Mapping[str, object]) -> tuple[LVal, LVal]:
    return (
        LVal(_addr_header(routing["recipient"]), Label.T_pub()),
        LVal(routing["subject"],                  Label.T_pub()),
    )


def _addr_list(v: object) -> list[str]:
    """Routing recipient/attendee value (str/list/tuple) → order-preserving, case-folded de-duped list."""
    if isinstance(v, (list, tuple)):
        seen: dict[str, str] = {}
        for a in v:
            seen.setdefault(str(a).lower(), str(a))
        return list(seen.values())
    return [str(v)]


def _addr_header(v: object) -> str:
    """RFC 5322 To:/attendee header from a str or address collection."""
    return ", ".join(_addr_list(v))


def _header_no_inject(value: str) -> str:
    """Strip CR/LF so attacker-controlled header text cannot inject MIME fields."""
    return (value or "").replace("\r", "").replace("\n", "").strip()


def _reply_references(message_id: str, prior: str) -> str:
    """Build References: prior chain + message being replied to."""
    mid = _header_no_inject(message_id)
    if not mid:
        return ""
    prior = _header_no_inject(prior)
    if prior and mid not in prior.split():
        return f"{prior} {mid}"
    return prior or mid


def _world_action_committed(result: dict) -> bool:
    """True if a sub-result already caused irreversible world side effects."""
    if result.get("status") == "success":
        return True
    if result.get("sent"):          # partial send_summary (separate delivery)
        return True
    if result.get("event_id"):      # calendar invite created; reply may have failed
        return True
    return False


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


def _release_slot(
    policy: IronFlow,
    *,
    slot_id: str,
    state: PlanState,
    routing: Mapping[str, object],
    who: str,
    not_from: str,
) -> LVal:
    """Authorize via declassify_slot, then apply the precommitted release transform."""
    recipient_display = _addr_header(routing[who])
    authorized = policy.declassify_slot(
        slot_id,
        state=state,
        reason=(
            f"{who} '{recipient_display}' pre-committed before observation; "
            f"not derived from {not_from}"
        ),
    )
    transform = policy.release_transform()
    if transform is None:
        raise RuntimeError(
            f"release transform missing for slot {slot_id!r} — "
            "content tools must precommit a transform id"
        )
    return apply_release_transform(transform, authorized)


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
    policy.before_spawn(driver)
    _emit_spawned(spec, kind, detail)
    writer = store.writer_for(slot_id, spec.max_label, agent_id=spec.id)
    await run_fn(writer)
    return _slot_result(store, state, slot_id, step_name)


async def _gmail_send(
    to: str,
    subject: str,
    body: str,
    google_token: str,
    state: PlanState,
    *,
    body_slot: str = "",
) -> None:
    """
    Send an email via Gmail.

    body_slot: when set (send_reply / schedule_meeting), resolve thread meta via
    _thread_source and attach threadId + In-Reply-To / References.
    Subject is always the IronFlow-gated (T,pub) value — never replaced from
    fetched headers (those are untrusted). message_id is MIME-threading only.
    Emits EvEmailSent on success. Raises GmailSendError on non-2xx.
    """
    thread_id = ""
    in_reply_to = ""
    references = ""
    if body_slot:
        try:
            thread_source = state.get_var("_thread_source").value
        except KeyError:
            thread_source = {}
        lookup_slot = thread_source.get(body_slot, body_slot)
        try:
            meta = state.get_var(f"_email_thread_meta_{lookup_slot}").value
        except KeyError:
            meta = {}
        thread_id = meta.get("thread_id", "") or ""
        in_reply_to = meta.get("message_id", "") or ""
        references = _reply_references(in_reply_to, meta.get("references", "") or "")

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        msg_id = await GmailClient(google_token, client).send(
            to, subject, body, thread_id,
            in_reply_to=in_reply_to, references=references,
        )
    _trace.emit(_trace.EvEmailSent(from_addr="me", to=to, message_id=msg_id))


def _auth_extra(status: int) -> dict:
    """See ProviderAuthError."""
    return {"credential_error": True} if status in (401, 403) else {}


def _provider_error(resp, what: str, store: SlotStore, **extra: object) -> tuple[str, dict]:
    """Non-raising twin of runner._require_ok.

    Driver tools must return (json_str, dict) on every path (invariant #1), and
    callers attach do-not-retry context an exception would lose.
    """
    msg = f"{what} failed (status {resp.status_code}): {resp.text[:200]}"
    return _terminal_error(msg, store, **_auth_extra(resp.status_code), **extra)


def _pipeline_error(reason: str, policy: IronFlow, store: SlotStore,
                    **extra: object) -> dict:
    violations = policy.violations()
    inventory  = store.inventory()
    _trace.emit(_trace.EvPipelineEnd(status="error", violations=violations, inventory=inventory))
    return {"status": "error", "reason": reason,
            "slot_inventory": inventory, "violations": violations, **extra}


def _terminal_error(msg: str, store: SlotStore, **extra: object) -> tuple[str, dict]:
    """Return a terminal (json_str, dict) error pair — stops the pipeline at this step."""
    payload: dict = {"status": "error", "reason": msg, **extra}
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


def _check_spend_ceiling(cap_config: str, amount: str, currency: str, what: str) -> str | None:
    """Validate a provider fare/rate against the operator's spend ceiling.

    Returns an error message if the booking must be aborted, else None. The
    ceiling must be configured as "<amount> <currency>" (e.g. "300 GBP") — a
    bare number cannot be safely compared against a fare in an unknown
    currency, so a currency-less or currency-mismatched ceiling is treated as
    a hard stop rather than silently comparing raw numbers across currencies.
    """
    cap_config = cap_config.strip()
    if not cap_config:
        return None
    parts = cap_config.split()
    if len(parts) != 2:
        return (
            f"max_booking_amount must be '<amount> <currency>' (e.g. '300 GBP'), "
            f"got {cap_config!r} — add the ceiling's currency to your config"
        )
    cap_str, cap_ccy = parts
    try:
        cap_val = float(cap_str)
    except ValueError:
        return f"max_booking_amount has an unparseable amount {cap_str!r}"
    try:
        amt_val = float(amount)
    except ValueError:
        return f"unparseable {what} amount {amount!r}"
    if cap_ccy.upper() != currency.upper():
        return (
            f"{what} is {amount} {currency}, but the spend ceiling is configured in "
            f"{cap_ccy.upper()} — cannot safely compare different currencies; "
            f"set max_booking_amount in {currency} or disable the ceiling"
        )
    if amt_val > cap_val:
        return f"{what} {amount} {currency} exceeds ceiling {cap_val:g} {cap_ccy.upper()}"
    return None


async def _handle_duffel_flight_search(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Tier 1 Duffel flight search (authenticated REST) → (U,pub) slot.

    Concrete args keep the MCP shape (domain + search_params) from _map_to_concrete,
    but the transport is Duffel REST, not an MCP call. duffel_token is injected from
    ctx.config — never a slot or a sub-agent env."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    domain        = args["domain"]
    search_params = args.get("search_params", {})
    slot_id       = args["slot_id"]

    spec = fetcher_spec(f"duffel_flight_{slot_id}", Capability(args["capability"]), mcp_domain=domain)

    async def _run(w: SlotWriter) -> None:
        await run_duffel_flight_search(
            spec, domain, search_params, w, policy, duffel_token=ctx.config.duffel_token,
        )

    return await _run_tier1(
        ctx, slot_id, spec, "mcp_search",
        {"domain": domain, "slot_id": slot_id, "search_params": search_params,
         "note": "operator code → Duffel REST offer_requests (no LLM; ranking via spawn_processor)"},
        "McpSearch",
        _run,
    )

async def _handle_liteapi_hotel_search(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Tier 1 LiteAPI hotel search (authenticated REST) → (U,pub) slot.

    Same MCP arg shape (domain + search_params) but the transport is LiteAPI REST.
    liteapi_key is injected from ctx.config — never a slot or a sub-agent env."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    domain        = args["domain"]
    search_params = args.get("search_params", {})
    slot_id       = args["slot_id"]

    spec = fetcher_spec(f"liteapi_hotel_{slot_id}", Capability(args["capability"]), mcp_domain=domain)

    async def _run(w: SlotWriter) -> None:
        await run_liteapi_hotel_search(
            spec, domain, search_params, w, policy, liteapi_key=ctx.config.liteapi_key,
        )

    return await _run_tier1(
        ctx, slot_id, spec, "mcp_search",
        {"domain": domain, "slot_id": slot_id, "search_params": search_params,
         "note": "operator code → LiteAPI REST /hotels/rates (no LLM; ranking via spawn_processor)"},
        "McpSearch",
        _run,
    )

_GITHUB_ISSUE_VAR  = "_github_issue_number"


_GITHUB_PR_SHA_VAR = "_github_pr_head_sha"


_GITHUB_PR_NUM_VAR = "_github_pr_number"


@dataclass(frozen=True)
class _GithubReader:
    """One Tier-1 GitHub tool.

    `publishes` names the (T,pub) vars its runner returns, in return order. An
    empty tuple means the tool publishes no routing at all — which is precisely
    what makes a broad listing safe to run, so it is declared here rather than
    left implicit in the absence of a set_var call.
    """
    runner:    Callable[..., Awaitable[object]]
    prefix:    str                      # sub-agent id prefix
    step:      str                      # PlanState step name
    note:      str                      # audit line
    publishes: tuple[str, ...] = ()


_GITHUB_READERS: dict[str, _GithubReader] = {
    "mcp_github_issue_read": _GithubReader(
        run_github_issue_read, "github_issue", "GithubIssueRead",
        "operator code → GitHub REST /issues (no LLM; provenance-gated by author_association)"),
    "mcp_github_issue_search": _GithubReader(
        run_github_issue_search, "github_search", "GithubIssueSearch",
        "operator code → GitHub REST /issues list+read (no LLM; floor applied during selection)",
        publishes=(_GITHUB_ISSUE_VAR,)),
    "mcp_github_issue_list": _GithubReader(
        run_github_issue_list, "github_list", "GithubIssueList",
        "operator code → GitHub REST /issues list (no LLM; per-item floor; publishes no routing)"),
    "mcp_github_pr_read": _GithubReader(
        run_github_pr_read, "github_pr", "GithubPrRead",
        "operator code → GitHub REST /pulls + /files (no LLM; diff unvetted by construction)",
        publishes=(_GITHUB_PR_SHA_VAR, _GITHUB_PR_NUM_VAR)),
    "mcp_github_pr_search": _GithubReader(
        run_github_pr_search, "github_prsearch", "GithubPrSearch",
        "operator code → GitHub REST /pulls list+read (no LLM; floor applied during "
        "selection; drafts excluded by default)",
        publishes=(_GITHUB_PR_SHA_VAR, _GITHUB_PR_NUM_VAR)),
}


def _github_reader_handler(tool: str) -> _Handler:
    """Build the driver handler for one Tier-1 GitHub reader.

    Whatever the runner returns is published under `publishes` as (T,pub).
    PlanState.set_var accepts nothing weaker, which is the structural check that
    fetched content can never arrive here: a runner returning author prose rather
    than a provider-assigned identifier is rejected by the label, not by
    convention. These values are discovered mid-run, so they are NOT
    precommitted-before-observation — the Tier-3 handler records which provenance
    applied via the result's `target_source` field.
    """
    reader = _GITHUB_READERS[tool]

    async def _handle(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
        domain        = args["domain"]
        search_params = args.get("search_params", {})
        slot_id       = args["slot_id"]
        spec = fetcher_spec(f"{reader.prefix}_{slot_id}",
                            Capability(args["capability"]), mcp_domain=domain)

        async def _run(w: SlotWriter) -> None:
            result = await reader.runner(
                spec, domain, search_params, w, ctx.policy,
                github_token=ctx.config.github_token,
                min_integrity=ctx.config.min_github_integrity,
                blocked_users=ctx.config.github_blocked_users,
            )
            if not reader.publishes:
                return
            values = result if isinstance(result, tuple) else (result,)
            # strict=True: a runner returning a different arity than the table
            # declares is a wiring error, not something to publish partially.
            for name, value in zip(reader.publishes, values, strict=True):
                ctx.state.set_var(name, LVal(value, Label.T_pub()))

        return await _run_tier1(
            ctx, slot_id, spec, "mcp_search",
            {"domain": domain, "slot_id": slot_id, "search_params": search_params,
             "note": reader.note},
            reader.step, _run,
        )

    return _handle



async def _handle_mcp_email_search(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    store, policy, state = ctx.store, ctx.policy, ctx.state
    api_url, filter_p, slot_id = args["api_url"], args.get("filter", {}), args["slot_id"]
    spec = fetcher_spec(f"mcp_email_search_{slot_id}", Capability(args["capability"]), url=api_url)

    async def _run(w: SlotWriter) -> None:
        thread_meta = await run_mcp_email_search(spec, filter_p, w, policy, google_token=ctx.config.google_token)
        # thread_id is Gmail envelope (provider-assigned). message_id / references
        # are sanitized header values used ONLY for In-Reply-To / References —
        # never as Subject or To. Subject stays the gated (T,pub) routing value.
        # Omit raw subject from state.vars: PlanState only accepts (T,pub) and
        # fetched Subject is untrusted content.
        if thread_meta.get("thread_id") or thread_meta.get("message_id"):
            state.set_var(
                f"_email_thread_meta_{slot_id}",
                LVal({
                    "thread_id":  thread_meta.get("thread_id", ""),
                    "message_id": thread_meta.get("message_id", ""),
                    "references": thread_meta.get("references", ""),
                }, Label.T_pub()),
            )

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
    policy.before_spawn(driver)
    _emit_spawned(spec, "processor", {"reads": reads, "out_slot": out_slot, "out_label": str(out_label)})
    reader = store.reader_for(reads, agent_id=spec.id, max_label=spec.max_label)
    writer = store.writer_for(out_slot, out_label, agent_id=spec.id)
    await run_processor(reads, reader, writer, system_prompt=spec.system_prompt,
                        agent_id=spec.id, timeout=300,
                        api_key=ctx.config.anthropic_api_key)
    return _slot_result(store, state, out_slot, "SpawnProcessor")


# ── Tier 3 handlers ───────────────────────────────────────────────────

async def _handle_send_summary(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """
    Driver tool step: send a summary email using routing pre-committed by driver.run().

    recipient in routing may be a str or tuple of strs (locked immutable before step 0).
    delivery='separate' (from step args) sends one message per recipient;
    default (combined) joins all addresses in a single To: header.
    IPI-based routing injection is structurally impossible.
    """
    store, policy, state, config = ctx.store, ctx.policy, ctx.state, ctx.config
    body_slot = args["body_slot"]
    delivery  = args.get("delivery", "combined")

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

    subject_lval = LVal(routing["subject"], Label.T_pub())
    try:
        body_lval = _bridge_body(policy, _release_slot(
            policy, slot_id=body_slot, state=state, routing=routing,
            who="recipient", not_from="fetched content",
        ))
    except ReleaseTransformError as exc:
        return _terminal_error(str(exc), store)

    if not str(body_lval.value).strip():
        return _terminal_error("released body is empty — nothing to send", store)

    recipients = _addr_list(routing["recipient"])
    groups     = [[r] for r in recipients] if delivery == "separate" else [recipients]
    body_str   = str(body_lval.value)

    sent: list[str] = []

    for gi, group in enumerate(groups):
        to_header      = _addr_header(group)
        recipient_lval = LVal(to_header, Label.T_pub())
        _gate_email_action(policy, "send_summary", recipient_lval, subject_lval, body_lval)
        try:
            await _gmail_send(
                to_header, subject_lval.value,
                body_str, config.google_token, state,
            )
        except GmailSendError as exc:
            if sent:
                reason = (
                    f"send failed for {group}: {exc}. "
                    f"Already sent to {sent!r}. Do not retry — partial delivery occurred."
                )
            else:
                reason = f"send failed for {group}: {exc}"
            unsent = [a for g in groups[gi:] for a in g]
            err_dict = {
                "status": "error", "reason": reason,
                "sent": sent, "unsent": unsent,
                "slot_inventory": store.inventory(),
            }
            return json.dumps(err_dict), err_dict
        sent.extend(group)
        _trace.emit(_trace.EvActionFired(
            recipient=to_header, recipient_label=str(recipient_lval.label),
            subject=subject_lval.value, subject_label=str(subject_lval.label),
            body_chars=len(body_str), body_label=str(body_lval.label),
            body_preview=body_str[:120],
        ))

    state.record_step("SendSummary")
    all_recipients_lval = LVal(_addr_header(recipients), Label.T_pub())
    final = _email_action_result(store, all_recipients_lval, subject_lval, body_lval)
    final["sent"] = sent
    return json.dumps({"status": "delivered", "sent": sent}), final


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

    raw_body = store.read(body_slot)
    try:
        body_lval = _bridge_body(policy, _release_slot(
            policy, slot_id=body_slot, state=state, routing=routing,
            who="recipient", not_from="email content",
        ))
    except ReleaseTransformError as exc:
        return _terminal_error(str(exc), store)

    if not str(body_lval.value).strip():
        return _terminal_error("released body is empty — nothing to send", store)

    _gate_email_action(policy, "send_reply", recipient_lval, subject_lval, body_lval)

    try:
        await _gmail_send(
            recipient_lval.value, subject_lval.value,
            str(body_lval.value), config.google_token, state,
            body_slot=body_slot,
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

    attendee_raw  = routing["attendee"]
    attendee_lval = LVal(_addr_header(attendee_raw), Label.T_pub())
    subject_lval  = LVal(routing["reply_subject"], Label.T_pub())
    event_title   = routing["event_title"]
    calendar_id   = "primary"
    google_token  = ctx.config.google_token

    raw_slots = store.read(slots_slot)
    try:
        slots_released = _release_slot(
            policy, slot_id=slots_slot, state=state, routing=routing,
            who="attendee", not_from="fetched content",
        )
    except ReleaseTransformError as exc:
        return _terminal_error(str(exc), store)

    slots_data = slots_released.value
    if not isinstance(slots_data, Mapping):
        return _terminal_error("meeting_proposal transform did not return an object", store)

    # Freeze a snapshot before confirm — confirmer must not TOCTOU-mutate
    # start/end between display and ActionGrant.
    proposed_slots: list[dict] = [
        {
            "start": str(s["start"]),
            "end":   str(s["end"]),
            **({"label": str(s["label"])} if "label" in s else {}),
        }
        for s in slots_data["proposed_slots"]
    ]
    reply_body: str = str(slots_data.get("reply_body", ""))

    if not proposed_slots:
        return _terminal_error("no 'proposed_slots' in processor output", store)

    policy.before_action("schedule_meeting", "attendee", attendee_lval, Role.ROUTING)
    policy.before_action("schedule_meeting", "subject",  subject_lval,  Role.ROUTING)

    _trace.emit(_trace.EvMeetingOptionsReady(
        attendee=_addr_header(attendee_raw), event_title=event_title,
        proposed_slots=proposed_slots,
    ))

    choice = await ctx.confirm_slot([dict(s) for s in proposed_slots])

    approved    = 1 <= choice <= len(proposed_slots)
    chosen_slot = dict(proposed_slots[choice - 1]) if approved else None

    _trace.emit(_trace.EvMeetingConfirmation(
        proposed_slots=proposed_slots,
        chosen_index=choice - 1 if approved else -1,
        approved=approved,
    ))

    if not approved and not reply_body.strip():
        return _terminal_error(
            "declined with no reply_body — nothing to send "
            "(processor output must include 'reply_body' for the email-only path)",
            store,
        )

    slot_label = "(email only)"
    start, end = "", ""
    if approved:
        start = str(chosen_slot["start"])
        end   = str(chosen_slot["end"])
        slot_label = chosen_slot.get("label") or f"{start} — {end}"
        confirmed = (
            f"Hi,\n\nI've confirmed our meeting for {slot_label}. "
            f"A calendar invite has been sent your way.\n\nLooking forward to it!"
        )
        reply_body_lval = LVal(confirmed[:_BODY_MAX_CHARS], slots_released.label)
    else:
        reply_body_lval = LVal(reply_body[:_BODY_MAX_CHARS], slots_released.label)

    body_lval = _bridge_body(policy, reply_body_lval)
    policy.before_action("schedule_meeting", "body", body_lval, Role.CONTENT)

    event_id, event_link = "", ""
    start_label, end_label = "(no invite)", "(no invite)"

    if approved:
        try:
            policy.issue_action_grant(
                state,
                tool="schedule_meeting",
                fields={"start_time": start, "end_time": end},
            )
        except IronFlowViolation as exc:
            return _terminal_error(str(exc), store)
        start_lval = LVal(start, Label.T_pub())
        end_lval   = LVal(end,   Label.T_pub())
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
                        "start":     {"dateTime": start},
                        "end":       {"dateTime": end},
                        "attendees": [{"email": a} for a in _addr_list(attendee_raw)],
                    },
                )
            if cal_resp.status_code not in (200, 201):
                return _terminal_error(f"Calendar API {cal_resp.status_code}: {cal_resp.text[:200]}", store)
            # 2xx already created the event — parse failures must still latch do_not_retry.
            try:
                ev_data = cal_resp.json()
            except Exception:
                return _terminal_error(
                    "Calendar API returned 2xx but response was not JSON — "
                    "invite may already exist; do not retry",
                    store, event_id="committed-unparsed",
                )
            if not isinstance(ev_data, dict):
                return _terminal_error(
                    "Calendar API returned 2xx with non-object JSON — "
                    "invite may already exist; do not retry",
                    store, event_id="committed-unparsed",
                )
            event_id   = ev_data.get("id", "") or "committed-unparsed"
            event_link = ev_data.get("htmlLink", "")

    if google_token:
        try:
            await _gmail_send(
                attendee_lval.value, subject_lval.value,
                str(body_lval.value), google_token, state,
                body_slot=slots_slot,  # thread into the fetched meeting-request email
            )
        except GmailSendError as exc:
            # Calendar event may already exist — surface it so the operator does not retry blindly.
            detail = str(exc)
            if event_id:
                detail = (
                    f"{detail}. Calendar event already created (event_id={event_id!r}). "
                    f"Do not retry — invite exists; reply was not sent."
                )
            return _terminal_error(
                detail, store, event_id=event_id, event_link=event_link,
            )

    _trace.emit(_trace.EvMeetingScheduled(
        attendee=_addr_header(attendee_raw), attendee_label=str(attendee_lval.label),
        event_title=event_title,
        start_time=start,
        end_time=end,
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
        "slot":        slot_label,
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


_LITEAPI_BASE = "https://api.liteapi.travel/v3.0"
_DUFFEL_AIR_BASE = "https://api.duffel.com/air"

async def _handle_book_flight(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Driver tool: book the processor-chosen Duffel offer, paid from the operator's
    prepaid Duffel balance, after re-validating the price and human confirmation.

    provider is (T,pub) routing (pre-committed). The offer pick is (U,pub) — a hint
    for WHICH offer, re-validated against Duffel before any charge. amount is
    grant-required (endorsed at action time). Passenger PII and the spend ceiling are
    trusted operator config (ctx.config) — never a slot, the task, or the LLM."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    offer_slot = args["offer_slot"]

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)
    provider = str(routing["provider"])
    policy.before_action("book_flight", "provider", LVal(provider, Label.T_pub()), Role.ROUTING)

    token = ctx.config.duffel_token
    if not token:
        return _terminal_error("DUFFEL_ACCESS_TOKEN is not set", store)
    passenger = ctx.config.passenger
    if not passenger:
        return _terminal_error(
            "no passenger profile configured — set [passenger] "
            "(given_name, family_name, born_on, gender, email, phone_number, title)", store)

    if not store.is_written(offer_slot):
        return _terminal_error(f"offer_slot '{offer_slot}' not written", store)
    try:
        released = _release_slot(
            policy, slot_id=offer_slot, state=state, routing=routing,
            who="provider", not_from="fetched flight offers",
        )
    except (ReleaseTransformError, IronFlowViolation) as exc:
        return _terminal_error(str(exc), store)
    offer_id = str(released.value["offer_id"])

    headers = _duffel_auth_headers(token)
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        offer_resp = await client.get(f"{_DUFFEL_AIR_BASE}/offers/{offer_id}", headers=headers)
    if offer_resp.status_code >= 400:
        return _provider_error(offer_resp, f"offer {offer_id} no longer bookable", store)
    offer    = offer_resp.json().get("data", {})
    amount   = str(offer.get("total_amount", ""))
    currency = str(offer.get("total_currency", ""))
    owner    = (offer.get("owner") or {}).get("name", "")
    _legs    = []
    for _sl in (offer.get("slices") or []):
        _s = _sl.get("segments") or []
        if _s:
            origin = (_s[0].get("origin") or {}).get("iata_code", "?")
            dest   = (_s[-1].get("destination") or {}).get("iata_code", "?")
            _legs.append(f"{origin}->{dest}")
    route    = " / ".join(_legs)   # both legs for a round trip, one for one-way

    if err := _check_spend_ceiling(ctx.config.max_booking_amount or "", amount, currency, "fare"):
        return _terminal_error(err, store)

    label  = f"{owner} {route} — {amount} {currency} (offer {offer_id})"
    _trace.emit(_trace.EvBookingProposed(owner=owner, route=route, amount=amount,
                                         currency=currency, offer_id=offer_id))
    _slices = offer.get("slices") or []
    _first  = (_slices[0].get("segments") or [{}])[0] if _slices else {}
    _last   = (_slices[-1].get("segments") or [{}])[-1] if _slices else {}
    choice = await ctx.confirm_slot([{
        "label": label,
        "start": _first.get("departing_at", ""),
        "end":   _last.get("arriving_at", ""),
    }])
    if choice != 1:
        _trace.emit(_trace.EvBookFlight(provider=provider, offer_id=offer_id, amount=amount,
            currency=currency, owner=owner, route=route, order_id="", booking_reference="", confirmed=False))
        return _terminal_error("flight booking not confirmed by human", store)

    try:
        policy.issue_action_grant(state, tool="book_flight", fields={"amount": amount})
    except IronFlowViolation as exc:
        return _terminal_error(str(exc), store)
    policy.before_action("book_flight", "amount", LVal(amount, Label.T_pub()), Role.ROUTING)

    pax = dict(passenger)
    pax_ids = [p.get("id") for p in offer.get("passengers", []) if p.get("id")]
    if pax_ids:
        pax["id"] = pax_ids[0]
    order_body = {"data": {
        "type":            "instant",
        "selected_offers": [offer_id],
        "payments":        [{"type": "balance", "amount": amount, "currency": currency}],
        "passengers":      [pax],
    }}
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        order_resp = await client.post(f"{_DUFFEL_AIR_BASE}/orders", headers=headers, json=order_body)
    if order_resp.status_code >= 400:
        _trace.emit(_trace.EvBookFlight(provider=provider, offer_id=offer_id, amount=amount,
            currency=currency, owner=owner, route=route, order_id="", booking_reference="", confirmed=False))
        return _provider_error(order_resp, "Duffel order", store)
    order    = order_resp.json().get("data", {})
    order_id = str(order.get("id", ""))
    pnr      = str(order.get("booking_reference", ""))

    _trace.emit(_trace.EvBookFlight(provider=provider, offer_id=offer_id, amount=amount,
        currency=currency, owner=owner, route=route, order_id=order_id,
        booking_reference=pnr, confirmed=True))
    final = {"provider": provider, "order_id": order_id, "booking_reference": pnr,
             "amount": amount, "currency": currency, "route": route, "owner": owner}
    return json.dumps(final), final

async def _handle_book_hotel(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Driver tool: book the processor-chosen LiteAPI hotel offer, paid from the
    operator's LiteAPI wallet, after re-validating the price (prebook) and human
    confirmation. Structural twin of book_flight."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    offer_slot = args["offer_slot"]

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)
    provider = str(routing["provider"])
    policy.before_action("book_hotel", "provider", LVal(provider, Label.T_pub()), Role.ROUTING)

    key = ctx.config.liteapi_key
    if not key:
        return _terminal_error("LITEAPI_SANDBOX_KEY is not set", store)
    guest = ctx.config.passenger
    if not guest:
        return _terminal_error(
            "no guest profile configured — set [passenger] (given_name, family_name, email)", store)

    if not store.is_written(offer_slot):
        return _terminal_error(f"offer_slot '{offer_slot}' not written", store)
    try:
        released = _release_slot(
            policy, slot_id=offer_slot, state=state, routing=routing,
            who="provider", not_from="fetched hotel offers",
        )
    except (ReleaseTransformError, IronFlowViolation) as exc:
        return _terminal_error(str(exc), store)
    pick     = released.value
    hotel_id = str(pick["hotel_id"])
    checkin  = str(pick["checkin"])
    checkout = str(pick["checkout"])
    country  = str(pick.get("country_code", "")) or "GB"
    currency = str(pick.get("currency", "")) or "GBP"
    hotel    = str(pick.get("hotel", "")) or hotel_id
    try:
        adults = max(1, int(pick.get("adults", 1) or 1))
    except (TypeError, ValueError):
        adults = 1

    headers = _liteapi_headers(key)
    # Re-search THIS hotel for a FRESH offer — LiteAPI rate offers expire quickly and
    # the plan→execute latency can stale the processor's pick. The fresh search picks
    # the cheapest current offer; prebook then returns the authoritative price, and
    # that is what the ceiling and the human grant bind to.
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        rt_resp = await client.post(f"{_LITEAPI_BASE}/hotels/rates", headers=headers,
            json={"hotelIds": [hotel_id], "checkin": checkin, "checkout": checkout,
                  "occupancies": [{"adults": adults}], "currency": currency,
                  "guestNationality": country})
    if rt_resp.status_code >= 400:
        return _provider_error(rt_resp, "hotel re-search", store)
    fresh_offer, fresh_amount = "", None
    for h in rt_resp.json().get("data", []):
        for rtp in h.get("roomTypes", []):
            for r in rtp.get("rates", []):
                tot = (r.get("retailRate") or {}).get("total") or []
                if not tot or tot[0].get("amount") is None:
                    continue
                amt = tot[0]["amount"]
                if fresh_amount is None or float(amt) < float(fresh_amount):
                    fresh_amount, fresh_offer = amt, rtp.get("offerId", "")
                    currency = tot[0].get("currency", currency)
    if not fresh_offer:
        return _terminal_error(f"{hotel} no longer available for {checkin}–{checkout}", store)

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        pre_resp = await client.post(f"{_LITEAPI_BASE}/rates/prebook",
                                     headers=headers, json={"offerId": fresh_offer, "usePaymentSdk": False})
    if pre_resp.status_code >= 400:
        return _provider_error(pre_resp, "hotel offer not bookable (prebook)", store)
    pre        = pre_resp.json().get("data", {})
    prebook_id = str(pre.get("prebookId", ""))
    amount     = str(pre.get("price", "") or fresh_amount)
    currency   = str(pre.get("currency", "") or currency)
    offer_id   = fresh_offer
    if not prebook_id:
        return _terminal_error("prebook returned no prebookId", store)

    if err := _check_spend_ceiling(ctx.config.max_booking_amount or "", amount, currency, "rate"):
        return _terminal_error(err, store)

    _trace.emit(_trace.EvBookingProposed(owner=hotel, route="",
                                         amount=amount, currency=currency, offer_id=offer_id))
    choice = await ctx.confirm_slot([{"label": f"{hotel} — {amount} {currency}",
                                      "start": "", "end": ""}])
    if choice != 1:
        _trace.emit(_trace.EvBookHotel(provider=provider, offer_id=offer_id, amount=amount,
            currency=currency, hotel=hotel, booking_id="", confirmed=False))
        return _terminal_error("hotel booking not confirmed by human", store)

    try:
        policy.issue_action_grant(state, tool="book_hotel", fields={"amount": amount})
    except IronFlowViolation as exc:
        return _terminal_error(str(exc), store)
    policy.before_action("book_hotel", "amount", LVal(amount, Label.T_pub()), Role.ROUTING)

    g      = dict(guest)
    holder = {"firstName": g.get("given_name", ""), "lastName": g.get("family_name", ""),
              "email": g.get("email", "")}
    # Only one guest profile is configurable ([passenger]) — same limitation as
    # book_flight's single passenger. What we CAN fix without a multi-guest config
    # feature is the occupant COUNT: submit one entry per confirmed adult (all
    # sharing the one configured identity) instead of silently booking 1 guest
    # against an N-adult prebook.
    guests = [
        {"occupancyNumber": i, "firstName": g.get("given_name", ""),
         "lastName": g.get("family_name", ""), "email": g.get("email", ""), "remarks": ""}
        for i in range(1, adults + 1)
    ]
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        bk_resp = await client.post(f"{_LITEAPI_BASE}/rates/book", headers=headers,
            json={"prebookId": prebook_id, "holder": holder, "guests": guests,
                  "payment": {"method": "WALLET"}})
    if bk_resp.status_code >= 400:
        _trace.emit(_trace.EvBookHotel(provider=provider, offer_id=offer_id, amount=amount,
            currency=currency, hotel=hotel, booking_id="", confirmed=False))
        return _provider_error(bk_resp, "LiteAPI booking", store)
    bk         = bk_resp.json().get("data", {})
    booking_id = str(bk.get("bookingId", ""))
    hotel_name = str((bk.get("hotel") or {}).get("name", "") or hotel)

    # LiteAPI's /rates/book request has no price field — it cannot enforce the
    # grant-endorsed `amount` server-side. The booking has already happened by
    # this point (irreversible), so a mismatch cannot be blocked — but it must
    # be surfaced honestly rather than silently reporting the stale pre-booking
    # estimate as if it were what was actually charged.
    charged_amount   = str(bk.get("price", "")) or amount
    charged_currency = str(bk.get("currency", "")) or currency
    try:
        amount_mismatch = (
            charged_currency != currency or abs(float(charged_amount) - float(amount)) > 0.01
        )
    except ValueError:
        amount_mismatch = True

    _trace.emit(_trace.EvBookHotel(provider=provider, offer_id=offer_id,
        amount=charged_amount, currency=charged_currency, hotel=hotel_name,
        booking_id=booking_id, confirmed=True,
        amount_endorsed=amount, currency_endorsed=currency))
    final = {"provider": provider, "booking_id": booking_id,
             "amount": charged_amount, "currency": charged_currency, "hotel": hotel_name,
             "amount_endorsed": amount, "currency_endorsed": currency,
             "amount_mismatch": amount_mismatch}
    if amount_mismatch:
        final["warning"] = (
            f"LiteAPI charged {charged_amount} {charged_currency}, which differs from "
            f"the human-endorsed {amount} {currency} — /rates/book accepts no price "
            f"field to enforce this server-side; the booking has already been made"
        )
    return json.dumps(final), final


async def _handle_create_calendar_event(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Driver tool: create a personal Google Calendar event — no attendee, no email sent,
    no Tier 1/2 fetch. event_title/start/end are (T,pub) routing fields pre-committed from
    the task string before step 0 — fixed at plan time, never touched by a sub-agent. This
    is why (unlike schedule_meeting's processor-picked start/end) no ActionGrant is issued:
    the grant exists to bind a human's confirmation to a value an untrusted process could
    otherwise substitute, and there is no such process in this tool's path. confirm_slot is
    still used as a plain "about to write to your real calendar" human check."""
    store, policy, state = ctx.store, ctx.policy, ctx.state

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)
    event_title = str(routing["event_title"])
    start       = str(routing["start"])
    end         = str(routing["end"])

    # Compare as real instants, not strings — start/end may carry different UTC
    # offsets (e.g. "-05:00" vs "+05:00"), where lexicographic order does not
    # match chronological order.
    try:
        start_dt, end_dt = datetime.fromisoformat(start), datetime.fromisoformat(end)
    except ValueError as exc:
        return _terminal_error(f"malformed start/end datetime: {exc}", store)
    if end_dt <= start_dt:
        return _terminal_error(f"end ({end}) must be after start ({start})", store)

    policy.before_action("create_calendar_event", "event_title", LVal(event_title, Label.T_pub()), Role.ROUTING)
    policy.before_action("create_calendar_event", "start", LVal(start, Label.T_pub()), Role.ROUTING)
    policy.before_action("create_calendar_event", "end", LVal(end, Label.T_pub()), Role.ROUTING)

    google_token = ctx.config.google_token
    if not google_token:
        return _terminal_error("GOOGLE_ACCESS_TOKEN is not set", store)

    choice = await ctx.confirm_slot([{"label": event_title, "start": start, "end": end}])
    if choice != 1:
        _trace.emit(_trace.EvCalendarEventCreated(
            event_title=event_title, start=start, end=end,
            event_id="", event_link="", confirmed=False))
        return _terminal_error("calendar event not confirmed by human", store)

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        cal_resp = await client.post(
            f"{_GCAL_EVENTS_BASE}/primary/events",
            headers=_google_headers(google_token),
            json={"summary": event_title, "start": {"dateTime": start}, "end": {"dateTime": end}},
        )
    if cal_resp.status_code not in (200, 201):
        _trace.emit(_trace.EvCalendarEventCreated(
            event_title=event_title, start=start, end=end,
            event_id="", event_link="", confirmed=False))
        return _provider_error(cal_resp, "Calendar event create", store)
    try:
        ev_data = cal_resp.json()
    except Exception:
        return _terminal_error(
            "Calendar API returned 2xx but response was not JSON — "
            "event may already exist; do not retry", store, event_id="committed-unparsed")
    if not isinstance(ev_data, dict):
        return _terminal_error(
            "Calendar API returned 2xx with non-object JSON — "
            "event may already exist; do not retry", store, event_id="committed-unparsed")
    event_id   = ev_data.get("id", "") or "committed-unparsed"
    event_link = ev_data.get("htmlLink", "")

    _trace.emit(_trace.EvCalendarEventCreated(
        event_title=event_title, start=start, end=end,
        event_id=event_id, event_link=event_link, confirmed=True))
    state.record_step("CreateCalendarEvent")
    final = {"status": "success", "event_title": event_title, "start": start, "end": end,
             "event_id": event_id, "event_link": event_link}
    return json.dumps(final), final


_GITHUB_API_BASE = "https://api.github.com"


_PR_REVIEW_EVENTS = ("COMMENT", "REQUEST_CHANGES")


async def _handle_add_comment(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Driver tool: post a comment on a GitHub issue or pull request.

    repo/issue_number are (T,pub) routing pre-committed before step 0, so injected
    issue text cannot redirect WHICH issue (or which repo) is commented on — only the
    body comes from a slot, declassified through the precommitted `opaque` transform
    and gated as CONTENT. One endpoint serves issues and PRs alike (every PR is an
    issue in GitHub's data model). Confirmed by a human because a comment is public
    and only retractable by a separate delete."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    body_slot = args["body_slot"]

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)
    repo = str(routing["repo"])

    try:
        issue_number, target_source = _resolve_target(
            routing, state, field="issue_number", var=_GITHUB_ISSUE_VAR)
    except KeyError:
        return _terminal_error(
            "no issue_number: name it in the task, or run mcp_github_issue_search "
            "first to resolve one", store)

    if not ctx.config.github_token:
        return _terminal_error("GITHUB_TOKEN is not set", store)
    if not store.is_written(body_slot):
        return _terminal_error(f"body_slot '{body_slot}' not written", store)

    try:
        body_lval = _bridge_body(policy, _release_slot(
            policy, slot_id=body_slot, state=state, routing=routing,
            who="repo", not_from="fetched issue content",
        ))
    except (ReleaseTransformError, IronFlowViolation) as exc:
        return _terminal_error(str(exc), store)
    body = str(body_lval.value).strip()
    if not body:
        return _terminal_error("released comment body is empty — nothing to post", store)

    policy.before_action("add_comment", "repo", LVal(repo, Label.T_pub()), Role.ROUTING)
    policy.before_action("add_comment", "issue_number",
                         LVal(str(issue_number), Label.T_pub()), Role.ROUTING)
    policy.before_action("add_comment", "body", body_lval, Role.CONTENT)

    def _not_posted() -> None:
        """Decline and provider-failure emit the same event; keep them identical."""
        _trace.emit(_trace.EvGithubCommentAdded(
            repo=repo, issue_number=issue_number, body_chars=len(body),
            body_label=str(body_lval.label), comment_id="", comment_url="",
            confirmed=False))

    # Trace the proposal BEFORE the prompt: the confirmer only reads len(slots),
    # so this event is the human's only view of what they are approving — and the
    # human is the enforcement point for a terminal_confirmed tool.
    _trace.emit(_trace.EvGithubCommentProposed(
        repo=repo, issue_number=issue_number, body_chars=len(body),
        body_preview=body[:160],
        gate=ctx.config.min_github_integrity or "disabled"))
    choice = await ctx.confirm_slot([{
        "label": f"comment on {repo}#{issue_number}", "start": "", "end": ""}])
    if choice != 1:
        _not_posted()
        return _terminal_error("comment not confirmed by human", store)

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.post(
            f"{_GITHUB_API_BASE}/repos/{repo}/issues/{issue_number}/comments",
            headers=_github_headers(ctx.config.github_token),
            json={"body": body},
        )
    if resp.status_code not in (200, 201):
        _not_posted()
        return _provider_error(resp, "GitHub comment", store)
    try:
        posted = resp.json()
    except ValueError:
        posted = None
    if not isinstance(posted, dict):
        return _terminal_error(
            "GitHub returned 2xx but response was not a JSON object — "
            "comment may already exist; do not retry", store, comment_id="committed-unparsed")
    comment_id  = str(posted.get("id", "") or "committed-unparsed")
    comment_url = str(posted.get("html_url", ""))

    _trace.emit(_trace.EvGithubCommentAdded(
        repo=repo, issue_number=issue_number, body_chars=len(body),
        body_label=str(body_lval.label), comment_id=comment_id,
        comment_url=comment_url, confirmed=True))
    state.record_step("AddComment")
    final = {"status": "success", "repo": repo, "issue_number": issue_number,
             "comment_id": comment_id, "comment_url": comment_url,
             "body_chars": len(body), "body_label": str(body_lval.label),
             "target_source": target_source}
    return json.dumps(final), final


async def _handle_submit_pr_review(args: dict, ctx: _StepContext) -> tuple[str, dict | None]:
    """Driver tool: submit a review on a GitHub pull request.

    APPROVE is structurally unreachable — it is absent from `_PR_REVIEW_EVENTS`
    and from the planner's literal_fields, checked in both places. An approving
    review can satisfy branch protection and let an automated merge proceed, so
    the write surface stays monotonic: it can add friction, never remove it.

    The reviewed commit is bound from the head SHA that mcp_github_pr_read
    published as (T,pub). Without it a review submitted after a force-push would
    attach to code nobody read; GitHub resolves an absent commit_id to whatever
    HEAD is at submission time, which is precisely the race we refuse to run."""
    store, policy, state = ctx.store, ctx.policy, ctx.state
    body_slot = args["body_slot"]

    routing = _get_routing(state)
    if routing is None:
        return _terminal_error(_ROUTING_MISSING, store)
    repo = str(routing["repo"])

    # The task-vs-search distinction carries more weight here than for a comment:
    # REQUEST_CHANGES blocks a pull request.
    try:
        pull_number, target_source = _resolve_target(
            routing, state, field="pull_number", var=_GITHUB_PR_NUM_VAR)
    except KeyError:
        return _terminal_error(
            "no pull_number: name it in the task, or run mcp_github_pr_search "
            "first to resolve one", store)
    except (TypeError, ValueError):
        return _terminal_error("submit_pr_review requires an integer pull_number", store)

    # Default COMMENT: the non-blocking verdict is the safe one to reach by omission.
    event = str(routing.get("event", "COMMENT")).strip().upper() or "COMMENT"
    if event not in _PR_REVIEW_EVENTS:
        return _terminal_error(
            f"event must be one of {_PR_REVIEW_EVENTS} (got {event!r}) — APPROVE is "
            f"deliberately not offered", store)

    try:
        commit_id = str(state.get_var(_GITHUB_PR_SHA_VAR).value)
        read_number = int(state.get_var(_GITHUB_PR_NUM_VAR).value)
    except KeyError:
        return _terminal_error(
            "no reviewed commit: run mcp_github_pr_read first so the review binds to "
            "the commit that was actually read", store)
    # Only meaningful when the plan named the number: on the search path both values
    # come from the same state var, so they cannot disagree. Both are task-derived,
    # so a mismatch is a planning error rather than an attack — but posting a SHA
    # from a different PR would otherwise surface as an opaque 422 on a write path.
    if target_source == "task" and read_number != pull_number:
        return _terminal_error(
            f"plan reviews #{pull_number} but mcp_github_pr_read read #{read_number} — "
            f"the review would carry a commit from a different pull request", store)

    if not ctx.config.github_token:
        return _terminal_error("GITHUB_TOKEN is not set", store)
    if not store.is_written(body_slot):
        return _terminal_error(f"body_slot '{body_slot}' not written", store)

    try:
        body_lval = _bridge_body(policy, _release_slot(
            policy, slot_id=body_slot, state=state, routing=routing,
            who="repo", not_from="fetched pull request content",
        ))
    except (ReleaseTransformError, IronFlowViolation) as exc:
        return _terminal_error(str(exc), store)
    body = str(body_lval.value).strip()
    if not body:
        return _terminal_error("released review body is empty — nothing to submit", store)

    policy.before_action("submit_pr_review", "repo", LVal(repo, Label.T_pub()), Role.ROUTING)
    policy.before_action("submit_pr_review", "pull_number",
                         LVal(str(pull_number), Label.T_pub()), Role.ROUTING)
    policy.before_action("submit_pr_review", "event", LVal(event, Label.T_pub()), Role.ROUTING)
    policy.before_action("submit_pr_review", "commit_id",
                         LVal(commit_id, Label.T_pub()), Role.ROUTING)
    policy.before_action("submit_pr_review", "body", body_lval, Role.CONTENT)

    def _not_submitted() -> None:
        """Decline and provider-failure emit the same event; keep them identical."""
        _trace.emit(_trace.EvGithubReviewSubmitted(
            repo=repo, pull_number=pull_number, event=event, commit_id=commit_id,
            body_chars=len(body), body_label=str(body_lval.label),
            review_id="", review_url="", confirmed=False))

    _trace.emit(_trace.EvGithubReviewProposed(
        repo=repo, pull_number=pull_number, event=event, commit_id=commit_id,
        body_chars=len(body), body_preview=body[:160],
        gate=ctx.config.min_github_integrity or "disabled"))
    choice = await ctx.confirm_slot([{
        "label": f"{event} review on {repo}#{pull_number} @ {commit_id[:7]}",
        "start": "", "end": ""}])
    if choice != 1:
        _not_submitted()
        return _terminal_error("review not confirmed by human", store)

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        resp = await client.post(
            f"{_GITHUB_API_BASE}/repos/{repo}/pulls/{pull_number}/reviews",
            headers=_github_headers(ctx.config.github_token),
            json={"commit_id": commit_id, "body": body, "event": event},
        )
    if resp.status_code not in (200, 201):
        _not_submitted()
        return _provider_error(resp, "GitHub review", store)
    try:
        posted = resp.json()
    except ValueError:
        posted = None
    if not isinstance(posted, dict):
        return _terminal_error(
            "GitHub returned 2xx but response was not a JSON object — the review may "
            "already exist; do not retry", store, review_id="committed-unparsed")
    review_id  = str(posted.get("id", "") or "committed-unparsed")
    review_url = str(posted.get("html_url", ""))

    _trace.emit(_trace.EvGithubReviewSubmitted(
        repo=repo, pull_number=pull_number, event=event, commit_id=commit_id,
        body_chars=len(body), body_label=str(body_lval.label),
        review_id=review_id, review_url=review_url, confirmed=True))
    state.record_step("SubmitPrReview")
    final = {"status": "success", "repo": repo, "pull_number": pull_number,
             "event": event, "commit_id": commit_id,
             "review_id": review_id, "review_url": review_url,
             "body_chars": len(body), "body_label": str(body_lval.label),
             "target_source": target_source}
    return json.dumps(final), final



_HANDLERS: dict[str, _Handler] = {
    "mcp_page_content":    _handle_mcp_page_content,
    "mcp_email_search":    _handle_mcp_email_search,
    "mcp_calendar_search": _handle_mcp_calendar_search,
    "mcp_flight_search":   _handle_duffel_flight_search,
    "mcp_hotel_search":    _handle_liteapi_hotel_search,
    "spawn_processor":     _handle_spawn_processor,
    "send_summary":        _handle_send_summary,
    "send_reply":          _handle_send_reply,
    "schedule_meeting":    _handle_schedule_meeting,
    "modify_emails":       _handle_modify_emails,
    "book_flight":         _handle_book_flight,
    "book_hotel":          _handle_book_hotel,
    "create_calendar_event": _handle_create_calendar_event,
    **{name: _github_reader_handler(name) for name in _GITHUB_READERS},
    "add_comment":         _handle_add_comment,
    "submit_pr_review":    _handle_submit_pr_review,
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
    "book_flight":      ["provider"],
    "book_hotel":       ["provider"],
    "create_calendar_event": ["event_title", "start", "end"],
    "add_comment":      ["repo", "issue_number"],
    "submit_pr_review": ["repo", "pull_number", "event"],
}

def _resolve_target(
    routing: Mapping[str, object], state: PlanState, *,
    field: str, var: str,
) -> tuple[int, str]:
    """Resolve a runtime-resolvable routing target, reporting its provenance.

    The two sources are both (T,pub) but NOT equally strong:
      plan args   — named in the task, precommitted before step 0 (strongest)
      state.vars  — resolved mid-run by a Tier-1 tool's deterministic filter;
                    provider-assigned, but discovered after observation

    Returns (value, provenance) where provenance is "task" or "search", so the
    handler records which applied instead of the audit claiming the stronger one.
    Raises KeyError when neither source has it; the caller turns that into a
    terminal error, since only it knows which Tier-1 tool to name.

    One helper rather than a copy per tool: this is the runtime-resolved routing
    pattern invariant #5 describes, and every _DRIVER_ROUTING_OPTIONAL entry that
    exists because a Tier-1 tool publishes the value needs exactly this.
    """
    if field in routing:
        return int(routing[field]), "task"          # type: ignore[arg-type]
    return int(state.get_var(var).value), "search"


# Routing fields that MAY be absent from the plan because a Tier 1 tool resolves
# them mid-run into state.vars as (T,pub) (e.g. mcp_github_issue_search publishing
# the issue number it selected). Everything else in _DRIVER_ROUTING_FIELDS stays
# mandatory at plan time. When such a field IS present in the plan it is still
# routing-locked normally — the handler reports which provenance applied, since a
# runtime-resolved value is not precommitted-before-observation.
_DRIVER_ROUTING_OPTIONAL: dict[str, frozenset[str]] = {
    "add_comment": frozenset({"issue_number"}),
    # event defaults to COMMENT when the task does not say otherwise; the
    # non-blocking verdict is the one that should be reachable by omission.
    # repo and pull_number stay mandatory, so the routing lock still applies.
    # pull_number is absent when mcp_github_pr_search resolves the target.
    # repo stays mandatory, so the routing lock still applies.
    "submit_pr_review": frozenset({"event", "pull_number"}),
}


def _routing_from_args(driver_tool: str, driver_args: Mapping[str, object]) -> tuple[dict, list[str]]:
    """Collect routing values present in the step args. Returns (routing, missing)."""
    keys     = _DRIVER_ROUTING_FIELDS.get(driver_tool, [])
    optional = _DRIVER_ROUTING_OPTIONAL.get(driver_tool, frozenset())
    missing  = [k for k in keys if k not in driver_args and k not in optional]
    return {k: driver_args[k] for k in keys if k in driver_args}, missing

def _release_gate_for(
    driver_tool: str, driver_args: Mapping[str, object],
) -> tuple[frozenset[str], str | None]:
    """Resolve precommit release sources + transform id from the terminal step args."""
    gate = DRIVER_RELEASE.get(driver_tool)
    if gate is None:
        raise ValueError(f"{driver_tool!r} missing from DRIVER_RELEASE")
    missing = [k for k in gate.slot_args if k not in driver_args]
    if missing:
        raise ValueError(
            f"{driver_tool} missing required release slot args: {missing}"
        )
    sources = frozenset(str(driver_args[k]) for k in gate.slot_args)
    return sources, gate.transform


def routing_block_for(plan: dict) -> dict | None:
    """
    Extract the routing block from a single sub-plan (must have 'steps') without executing it.

    Returns None if the driver tool has no routing fields.
    Raises ValueError for a pipelines-shaped plan or if any required routing field is missing.
    """
    if "pipelines" in plan:
        raise ValueError("routing_block_for requires a single sub-plan, not a pipelines-shaped plan")
    driver_step = plan["steps"][-1] if plan.get("steps") else {}
    driver_tool = driver_step.get("tool", "")
    driver_args = driver_step.get("args", {})
    if not _DRIVER_ROUTING_FIELDS.get(driver_tool):
        return None
    routing, missing = _routing_from_args(driver_tool, driver_args)
    if missing:
        raise ValueError(
            f"routing_block_for: {driver_tool} missing required routing fields: {missing}"
        )
    return routing


async def run(
    task: str, plan: dict, store: SlotStore, policy: IronFlow,
    *,
    google_token: str = "",
    duffel_token: str = "",
    liteapi_key: str = "",
    passenger: Mapping[str, str] | None = None,
    max_booking_amount: str = "",
    github_token: str = "",
    min_github_integrity: str = "",
    github_blocked_users: frozenset[str] = frozenset(),
    anthropic_api_key: str = "",
    confirm_slot: Callable[[list[dict]], Awaitable[int]] = _default_confirm_slot,
    routing: dict | None = None,
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

    store and policy are a one-run pair: policy must be freshly constructed as
    IronFlow(store). Reusing a precommitted policy is rejected.
    """
    if not plan.get("steps"):
        return _pipeline_error("manifest has no steps", policy, store)
    if not policy.bound_to(store):
        return _pipeline_error(
            "IronFlow policy must be bound to the execution SlotStore", policy, store,
        )

    driver = driver_spec()
    config = ProviderConfig(google_token=google_token, duffel_token=duffel_token,
                            liteapi_key=liteapi_key, passenger=passenger,
                            max_booking_amount=max_booking_amount,
                            github_token=github_token,
                            min_github_integrity=min_github_integrity,
                            github_blocked_users=github_blocked_users,
                            anthropic_api_key=anthropic_api_key)
    state  = PlanState(trusted_action_urls=tuple(plan.get("trusted_action_urls", [])))
    ctx    = _StepContext(
        store=store, policy=policy, driver=driver, state=state,
        config=config, confirm_slot=confirm_slot,
    )

    driver_step  = plan["steps"][-1]
    driver_tool  = driver_step.get("tool", "")
    emit_locked  = routing is None   # only emit EvRoutingLocked when we extract it here

    if routing is None:
        # Single-plan path: extract routing from the manifest step args.
        driver_args = driver_step.get("args", {})
        if _DRIVER_ROUTING_FIELDS.get(driver_tool):
            routing, missing = _routing_from_args(driver_tool, driver_args)
            if missing:
                return _pipeline_error(
                    f"{driver_tool} missing required routing fields: {missing}", policy, store,
                )

    if routing is not None:
        # set_var owns the freeze (list→tuple + MappingProxyType); no pre-freeze.
        state.set_var("_routing", LVal(routing, Label.T_pub()))
        try:
            sources, transform = _release_gate_for(driver_tool, driver_step.get("args", {}))
            policy.precommit_routing(state, sources=sources, transform=transform)
        except (IronFlowViolation, ValueError) as exc:
            return _pipeline_error(str(exc), policy, store)
        if emit_locked:
            _trace.emit(_trace.EvRoutingLocked(
                driver_tool=driver_tool,
                routing=dict(state.get_var("_routing").value),
            ))

    steps    = plan["steps"]

    # Build static provenance: maps each processor output slot to its email-search
    # ancestor slot so _gmail_send can resolve _email_thread_meta_<email_slot>.
    # Transitive: handles chained processors (processor reads another processor's output).
    email_slot_for: dict[str, str] = {}
    for step in steps:
        tool = step.get("tool", "")
        if tool == "mcp_email_search":
            sid = step["args"]["slot_id"]
            email_slot_for[sid] = sid
        elif tool == "spawn_processor":
            out = step["args"]["out_slot"]
            for r in step["args"].get("reads", []):
                if r in email_slot_for:
                    email_slot_for[out] = email_slot_for[r]
                    break
    if email_slot_for:
        state.set_var("_thread_source", LVal(email_slot_for, Label.T_pub()))

    _trace.emit(_trace.EvDriverStart(task=task))
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
            except ConfirmationRequired:
                raise
            except ProviderAuthError as exc:
                # Credential rejected (401/403) — operator-fixable, so flag it
                # rather than letting it read as a generic pipeline failure.
                return _pipeline_error(str(exc), policy, store, credential_error=True)
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
                except ConfirmationRequired:
                    raise
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


async def run_manifest(
    task: str,
    plan: dict,
    *,
    google_token: str = "",
    duffel_token: str = "",
    liteapi_key: str = "",
    passenger: Mapping[str, str] | None = None,
    max_booking_amount: str = "",
    github_token: str = "",
    min_github_integrity: str = "",
    github_blocked_users: frozenset[str] = frozenset(),
    anthropic_api_key: str = "",
    confirm_slot: Callable[[list[dict]], Awaitable[int]] = _default_confirm_slot,
) -> dict:
    """
    Execute a validated manifest for both single-plan and multi-pipeline shapes.

    For multi-pipeline plans, pre-extracts and emits ALL routing blocks before any
    SlotStore is constructed, making the "all routing locked before step 0" guarantee
    structural rather than audit-narrative. Violations from each pipeline are hoisted
    into the aggregate result so POLICY_VIOLATION exit codes propagate correctly.

    Timeout is the caller's responsibility — wrap this coroutine with asyncio.wait_for.
    Single-plan manifests delegate to run(); if the result is not success but already
    committed world side effects (sent / event_id), do_not_retry=True is attached.
    """
    sub_plans = plan.get("pipelines")

    # One registry for the whole invocation: the credentials are identical across
    # sub-pipelines, and the trace registry is process-scoped anyway.
    secrets = build_secret_registry(
        google_token=google_token, duffel_token=duffel_token,
        liteapi_key=liteapi_key, github_token=github_token,
        anthropic_api_key=anthropic_api_key)
    _trace.set_secret_registry(secrets)

    if sub_plans is None:
        store  = SlotStore(secrets)
        policy = IronFlow(store)
        result = await run(task, plan, store, policy,
                           google_token=google_token,
                           duffel_token=duffel_token, liteapi_key=liteapi_key,
                           passenger=passenger, max_booking_amount=max_booking_amount,
                           github_token=github_token,
                           min_github_integrity=min_github_integrity,
                           github_blocked_users=github_blocked_users,
                           anthropic_api_key=anthropic_api_key, confirm_slot=confirm_slot)
        if result.get("status") != "success" and _world_action_committed(result):
            result = {**result, "do_not_retry": True}
        return result

    # Pre-extract ALL routing blocks before constructing any SlotStore.
    routing_blocks: list[dict | None] = []
    for sub in sub_plans:
        try:
            rb = routing_block_for(sub)
        except ValueError as exc:
            return {"status": "error", "reason": str(exc), "violations": [], "actions": []}
        routing_blocks.append(_freeze_routing(rb) if rb is not None else None)

    # Emit all EvRoutingLocked events before the first pipeline executes.
    for idx, (sub, rb) in enumerate(zip(sub_plans, routing_blocks)):
        if rb is not None:
            driver_tool = sub["steps"][-1].get("tool", "")
            _trace.emit(_trace.EvRoutingLocked(
                driver_tool=driver_tool,
                routing=dict(rb),
                pipeline=idx,
            ))

    results:    list[dict] = []
    violations: list      = []

    for sub, rb in zip(sub_plans, routing_blocks):
        store  = SlotStore(secrets)
        policy = IronFlow(store)
        sub_result = await run(task, sub, store, policy,
                               google_token=google_token,
                               duffel_token=duffel_token, liteapi_key=liteapi_key,
                           passenger=passenger, max_booking_amount=max_booking_amount,
                           github_token=github_token,
                           min_github_integrity=min_github_integrity,
                           github_blocked_users=github_blocked_users,
                           anthropic_api_key=anthropic_api_key, confirm_slot=confirm_slot, routing=rb)
        results.append(sub_result)
        violations.extend(sub_result.get("violations", []))

    statuses = [r.get("status") for r in results]
    if all(s == "success" for s in statuses):
        agg_status = "success"
    elif all(s == "error" for s in statuses):
        agg_status = "error"
    else:
        agg_status = "partial"

    # Any irreversible side effect means blind retry is unsafe — even on status=error.
    do_not_retry = (
        any(_world_action_committed(r) for r in results) and agg_status != "success"
    )

    return {
        "status": agg_status,
        "actions": results,
        "violations": violations,
        "do_not_retry": do_not_retry,
    }
