"""
runner.py — Sub-agent execution for the IPI-resistant pipeline.

Three sections, matching the architecture:

  TIER 1 — DATA SUB-AGENTS (operator code only — no LLM):
    run_mcp_page_content     — HTTP fetch + HTML denoising → (U,pub) slot
    run_mcp_email_search     — Gmail REST API → (U,priv) slot
    run_mcp_calendar_search  — Google Calendar REST API → (U,priv) slot

  TIER 2 — PROCESSOR SUB-AGENTS (isolated SDK call, no tools, reads slots only):
    run_processor   — synthesise / transform (used by spawn_processor)

Key safety properties:
  - Output label is derived from the spec's AgentSpec.max_label — computed once
    in the driver handler via taint_all() before the spawn gate fires.
  - The only path from internet to LLM is through a slot (injection firewall).
  - HTTP fetching uses per-hop CanNetwork re-validation to prevent redirect-based
    permission bypass. HTML stripping is minimal: noise subtrees removed, tags
    stripped, entities decoded — sufficient because the Tier 2 processor handles
    all semantic interpretation.
"""

from __future__ import annotations
import asyncio
import base64
import html as _html
import json
import re
import shutil
import sys
from urllib.parse import urljoin, quote

import anthropic
import httpx

from .labels import Label
from .slots import SlotReader, SlotWriter
from .permissions import AgentSpec
from .ironflow_policy import IronFlow, IronFlowViolation
from . import trace as _trace



class ProviderAuthError(RuntimeError):
    """A provider rejected the credential (401/403).

    Operator-fixable and worth retrying after a refresh, unlike a 4xx/5xx on a
    valid credential — so the CLI maps it to ExitCode.CREDENTIAL_ERROR rather
    than PIPELINE_ERROR.
    """


def _require_ok(resp, what: str) -> None:
    """Raise on a non-2xx provider response, classifying auth failures."""
    if resp.status_code < 400:
        return
    msg = f"{what} failed (status {resp.status_code}): {resp.text[:200]}"
    raise (ProviderAuthError if resp.status_code in (401, 403) else RuntimeError)(msg)


# ── Module-level constants ─────────────────────────────────────────────

_MAX_STREAM_LINES      = 20              # live sub-agent output lines shown on terminal
_MAX_WEB_WORDS         = 6000            # words kept from a full web fetch
_MAX_WEB_WORDS_SHALLOW = 500             # words kept during exploration phase
_MAX_HTTP_REDIRECTS    = 5
_MAX_RESPONSE_BYTES    = 2 * 1024 * 1024 # 2 MB hard cap on HTTP response bodies

# Send a mainstream Chrome UA — some sites block unknown clients.
_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

_TZ_OFFSET_RE = re.compile(r"[+-]\d{2}:\d{2}$")


# ── Web fetch helpers ──────────────────────────────────────────────────

async def _http_get(spec: "AgentSpec", url: str, policy: "IronFlow") -> str:
    """
    GET `url`, re-validating every redirect hop against the agent's
    CanNetwork permission before following it.

    Prevents a server at allowed.example.com from redirecting to
    attacker.com to bypass the per-URL permission grant.

    Network and HTTP errors are returned as sentinel strings ("[FETCH ERROR: …]")
    so the processor can report a failed fetch rather than crashing the pipeline.
    IronFlowViolation (gate fired on a redirect hop) is never converted to a
    sentinel — it must propagate to produce the correct exit code and audit event.
    """
    policy.before_network(spec, url)
    current = url
    hops = 0

    async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
        while hops <= _MAX_HTTP_REDIRECTS:
            try:
                async with client.stream("GET", current, headers={"User-Agent": _USER_AGENT}) as r:
                    if r.is_redirect:
                        location = r.headers.get("location", "")
                        if not location:
                            return "[FETCH ERROR: redirect with no Location header]"
                        location = urljoin(current, location)  # handles relative, path-absolute, scheme-relative
                        policy.before_network(spec, location)  # re-validate every hop
                        current = location
                        hops += 1
                        continue
                    try:
                        r.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        return f"[HTTP ERROR: {exc}]"
                    ct = r.headers.get("content-type", "")
                    if ct and not any(t in ct for t in ("text/html", "text/plain", "application/xhtml")):
                        return f"[SKIP: non-text content-type {ct!r}]"
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in r.aiter_bytes():
                        total += len(chunk)
                        if total > _MAX_RESPONSE_BYTES:
                            break
                        chunks.append(chunk)
                    charset = r.charset_encoding or "utf-8"
                    return b"".join(chunks).decode(charset, errors="replace")
            except IronFlowViolation:
                raise  # gate violations must never become sentinels
            except httpx.HTTPError as exc:
                return f"[FETCH ERROR: {exc}]"

    return "[FETCH ERROR: exceeded maximum redirects]"


_TITLE_RE    = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_NOISE_SUB   = re.compile(
    r"<(script|style|nav|header|footer|aside|noscript)[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_STRIP   = re.compile(r"<[^>]+>")
_WHITESPACE  = re.compile(r"\s+")


def _extract_text_simple(raw: str) -> str:
    """
    Minimal HTML-to-text extraction.

    1. Extract <title>.
    2. Remove noise subtrees (script, style, nav, header, footer, aside, noscript).
    3. Strip all remaining HTML tags.
    4. Decode HTML entities and collapse whitespace.

    Sufficient for the current task set; the Tier 2 processor handles all
    semantic interpretation so block-level scoring is unnecessary.
    """
    title_m = _TITLE_RE.search(raw)
    title   = _html.unescape(re.sub(r"<[^>]+>", " ", title_m.group(1))).strip() if title_m else ""
    text    = _NOISE_SUB.sub(" ", raw)
    text    = _TAG_STRIP.sub(" ", text)
    text    = _html.unescape(text)
    text    = _WHITESPACE.sub(" ", text).strip()
    parts   = ([f"Title: {title}", text] if title else [text])
    return "\n\n".join(p for p in parts if p)


def _ensure_tz(ts: str) -> str:
    """Ensure ts is a full RFC 3339 datetime with timezone — Google Calendar requires it.

    Date-only strings (YYYY-MM-DD) are expanded to midnight before appending Z.
    Bare date-only + Z (e.g. '2026-07-06Z') is rejected by the Google API; it
    requires a full timestamp (e.g. '2026-07-06T00:00:00Z').
    """
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", ts):
        ts += "T00:00:00"
    return ts if (ts.endswith("Z") or _TZ_OFFSET_RE.search(ts)) else ts + "Z"


# ── Sub-agent spawner ──────────────────────────────────────────────────

# Tier-2 model is pinned here, not inherited from ambient CLI configuration, so a
# run is reproducible across machines and the model is a property of the code
# rather than of whoever's laptop it ran on.
_PROCESSOR_MODEL      = "claude-sonnet-4-6"
_PROCESSOR_MAX_TOKENS = 8192


async def _llm_processor(
    system: str, user: str, *, timeout: int = 300, api_key: str | None = None,
) -> str:
    """
    Run the isolated Tier-2 processor via the Anthropic SDK. Pure text generation.
    Streams to the terminal with "  │ " prefix for live progress; returns the
    complete response text.

    Isolation by omission: no `tools` argument, and nothing read from disk. See
    CLAUDE.md invariant #6 for why this must not become a subprocess again.

    Slot content, which may be (U,priv), travels as a message body rather than an
    argv element, so it cannot surface in `ps` output or /proc/*/cmdline.
    """
    # Explicit key only: left as None the SDK reads the environment itself, below
    # this package, where the sweep in test_credential_isolation.py cannot see it.
    if not api_key:
        raise RuntimeError(
            "Tier-2 processor requires an explicit API key; none was threaded "
            "from the CLI layer")
    client = anthropic.AsyncAnthropic(api_key=api_key, timeout=float(timeout))

    parts: list[str] = []
    col = min(shutil.get_terminal_size(fallback=(120, 40)).columns - 6, 134)
    shown = suppressed = 0
    pending = ""

    def _emit_line(line: str) -> None:
        nonlocal shown, suppressed
        if shown < _MAX_STREAM_LINES:
            display = line if len(line) <= col else line[: col - 1] + "…"
            sys.stdout.write("  │ " + display + "\n")
            sys.stdout.flush()
            shown += 1
        else:
            suppressed += 1

    try:
        async with client.messages.stream(
            model      = _PROCESSOR_MODEL,
            max_tokens = _PROCESSOR_MAX_TOKENS,
            system     = system,
            messages   = [{"role": "user", "content": user}],
        ) as stream:
            async for chunk in stream.text_stream:
                parts.append(chunk)
                # Display is line-oriented; the stream is token-oriented. Buffer
                # until a newline so a wrapped line is measured against `col` once.
                pending += chunk
                while "\n" in pending:
                    line, pending = pending.split("\n", 1)
                    _emit_line(line)
    except anthropic.APIStatusError as exc:
        # Typed separately from a generic failure because the remedy differs: an
        # expired or under-scoped key is operator-fixable. Callers that want a
        # distinct exit code catch ProviderAuthError.
        raise (ProviderAuthError if exc.status_code in (401, 403) else RuntimeError)(
            f"processor sub-agent failed (status {exc.status_code}): {str(exc)[:200]}"
        ) from exc
    except anthropic.APITimeoutError as exc:
        raise RuntimeError(f"sub-agent timed out after {timeout}s") from exc
    except anthropic.APIError as exc:
        raise RuntimeError(f"processor sub-agent failed: {str(exc)[:200]}") from exc

    if pending:
        _emit_line(pending)
    if suppressed:
        sys.stdout.write(f"  │  … (+{suppressed} more lines)\n")
        sys.stdout.flush()

    return "".join(parts).strip()


# ══════════════════════════════════════════════════════════════════════
# TIER 1 — DATA SUB-AGENTS
# Operator code only — no LLM. Slot boundary = injection firewall.
# ══════════════════════════════════════════════════════════════════════

# ── run_mcp_page_content ───────────────────────────────────────────────

async def run_mcp_page_content(
    spec:    AgentSpec,
    url:     str,
    writer:  SlotWriter,
    policy:  IronFlow,
    shallow: bool = False,
) -> None:
    """
    Fetch URL, strip HTML, write cleaned text to slot as (U,pub).
    Purely deterministic operator code — no LLM.

    shallow=True  → first 500 words  (exploration / planning phase)
    shallow=False → first 6000 words (full fetch)
    """
    _trace.emit(_trace.EvFetch(agent_id=spec.id, url=url, shallow=shallow))

    raw     = await _http_get(spec, url, policy)
    words   = _extract_text_simple(raw).split()
    content = " ".join(words[:_MAX_WEB_WORDS_SHALLOW if shallow else _MAX_WEB_WORDS])

    writer.write(content)


# ── run_mcp_email_search helpers ──────────────────────────────────────

_GMAIL_REST_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
_GCAL_V3         = "https://www.googleapis.com/calendar/v3"
_GCAL_REST_BASE  = f"{_GCAL_V3}/calendars"   # kept for driver.py import compat


def _google_auth_headers(google_token: str = "") -> dict[str, str]:
    """Return a Bearer auth header dict for google_token, or {} if unset."""
    return {"Authorization": f"Bearer {google_token}"} if google_token else {}


def _find_mime_part(part: dict, mime_type: str) -> str:
    """
    Recursively find the first MIME part matching mime_type and return its decoded text.

    Gmail omits base64 padding; appending "==" is safe — the decoder ignores excess padding.
    """
    if part.get("mimeType") == mime_type:
        data = part.get("body", {}).get("data", "")
        if data:
            try:
                return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            except ValueError:
                return ""
    for sub in part.get("parts", []):
        found = _find_mime_part(sub, mime_type)
        if found:
            return found
    return ""


def _sanitize_rfc_msg_id(value: str) -> str:
    """
    Return a single RFC 5322 msg-id suitable for In-Reply-To / References, or "".

    Rejects CR/LF (header injection) and values that are not a bracketed msg-id.
    Used only for MIME threading headers — never for routing fields.
    """
    v = (value or "").strip()
    if not v or "\r" in v or "\n" in v:
        return ""
    if not v.startswith("<"):
        v = f"<{v}>"
    # msg-id = "<" id-left "@" id-right ">" — keep permissive on internals, strict on shape.
    if not re.fullmatch(r"<[^<>\s]+@[^<>\s]+>", v):
        return ""
    return v


def _sanitize_references(value: str) -> str:
    """Keep only well-formed msg-ids from a References header; drop junk / injections."""
    if not value or "\r" in value or "\n" in value:
        return ""
    ids = re.findall(r"<[^<>\s]+@[^<>\s]+>", value)
    return " ".join(ids)


def _gmail_parse_message(msg: dict) -> dict:
    """
    Parse a Gmail messages.get response into {from, subject, date, body, thread_id,
    message_id, references}.
    Deterministic — no LLM.

    thread_id   — Gmail thread identifier (API envelope field, provider-assigned).
    message_id  — RFC 5322 Message-ID header. Sender-written, so it is NOT used for
                  routing. It is required for In-Reply-To / References so the
                  recipient's client threads the reply (threadId alone is not enough).
    references  — existing References chain from the fetched message, if any.

    Body extraction priority:
      1. text/plain  — used as-is; no stripping needed.
      2. text/html   — tags stripped, entities unescaped; covers HTML-only emails.
      3. snippet     — Gmail's 150-char preview; last resort.
    """
    payload = msg.get("payload", {})
    hdrs = {
        h["name"].lower(): h["value"]
        for h in payload.get("headers", [])
        if isinstance(h, dict) and "name" in h and "value" in h
    }

    def _decode_body(part: dict) -> str:
        plain = _find_mime_part(part, "text/plain")
        if plain:
            return plain
        html_body = _find_mime_part(part, "text/html")
        if html_body:
            return _html.unescape(re.sub(r"<[^>]+>", " ", html_body)).strip()
        return msg.get("snippet", "")

    message_id = _sanitize_rfc_msg_id(hdrs.get("message-id", ""))
    references = _sanitize_references(hdrs.get("references", ""))

    return {
        "from":        hdrs.get("from",       "(unknown)"),
        "subject":     hdrs.get("subject",     "(no subject)"),
        "date":        hdrs.get("date",        "(unknown)"),
        "body":        _decode_body(payload),
        "thread_id":   msg.get("threadId",     ""),
        "message_id":  message_id,
        "references":  references,
    }


# ── run_mcp_email_search ───────────────────────────────────────────────

async def run_mcp_email_search(
    spec:          AgentSpec,
    filter_params: dict,
    writer:        SlotWriter,
    policy:        IronFlow,
    *,
    google_token:  str = "",
) -> dict:
    """
    Fetch messages via Gmail REST API — operator code only, no LLM.
    Writes From/Subject/Date/Body to slot as (U,priv) — untrusted AND private.

    Step 1 — GET /gmail/v1/users/me/messages?q=from:sender&maxResults=N
    Step 2 — GET /gmail/v1/users/me/messages/{id}?format=full per result.
    Step 3 — Deterministic parser extracts headers + body.

    Returns thread_meta dict for send_reply threading:
      thread_id   — Gmail envelope id (provider-assigned)
      message_id  — sanitized RFC Message-ID (for In-Reply-To / References only)
      references  — prior References chain (sanitized)
      subject     — original Subject (slot display only; driver does not store or
                    send it — Subject on the wire is the gated (T,pub) routing value)

    Auth: google_token (gmail.readonly scope required).
    The From address MUST NOT reach any routing field without driver validation.
    message_id from headers is NEVER used as routing — only as MIME threading.
    """
    auth  = _google_auth_headers(google_token)
    limit = int(filter_params.get("limit", 1))

    # Build Gmail search query from supported filter fields.
    # Supported fields (all optional):
    #   from            — sender address or domain
    #   subject_contains — keyword(s) that must appear in the subject line
    #   after_date      — lower bound inclusive (YYYY-MM-DD)
    #   before_date     — upper bound exclusive (YYYY-MM-DD)
    #   label           — Gmail label name (e.g. "INBOX", "UNREAD")
    #   is_unread       — bool; adds is:unread when truthy
    #   has_attachment  — bool; adds has:attachment when truthy
    #   q               — raw Gmail query string (appended verbatim)
    parts: list[str] = []
    if filter_params.get("from"):
        parts.append(f"from:{filter_params['from']}")
    if filter_params.get("subject_contains"):
        parts.append(f"subject:{filter_params['subject_contains']}")
    if filter_params.get("after_date"):
        parts.append(f"after:{str(filter_params['after_date']).replace('-', '/')}")
    if filter_params.get("before_date"):
        parts.append(f"before:{str(filter_params['before_date']).replace('-', '/')}")
    if filter_params.get("label"):
        parts.append(f"label:{filter_params['label']}")
    if filter_params.get("is_unread"):
        parts.append("is:unread")
    if filter_params.get("has_attachment"):
        parts.append("has:attachment")
    if filter_params.get("q"):
        parts.append(str(filter_params["q"]))
    query = " ".join(parts) if parts else ""

    list_url = f"{_GMAIL_REST_BASE}/messages"
    policy.before_network(spec, list_url)
    _trace.emit(_trace.EvFetch(agent_id=spec.id, url=list_url, shallow=False, mcp_tool="messages.list"))

    async with httpx.AsyncClient(timeout=15.0) as client:
        list_resp = await client.get(
            list_url, headers=auth, params={"q": query, "maxResults": limit},
        )
        _require_ok(list_resp, "Gmail message list")

        try:
            message_ids = [m["id"] for m in list_resp.json().get("messages", [])]
        except (json.JSONDecodeError, KeyError):
            raise RuntimeError(
                f"Gmail list returned unexpected body (status {list_resp.status_code}): "
                f"{list_resp.text[:200]}"
            )
        if not message_ids:
            # No results is a valid API response — write an informative slot so
            # spawn_processor can report "nothing found" rather than crashing.
            writer.write(f"(no messages found for query: {query!r})")
            return {"thread_id": "", "message_id": "", "references": "", "subject": ""}

        msg_urls: list[str] = []
        for msg_id in message_ids:
            msg_url = f"{_GMAIL_REST_BASE}/messages/{msg_id}"
            policy.before_network(spec, msg_url)
            _trace.emit(_trace.EvFetch(
                agent_id=spec.id, url=msg_url, shallow=False, mcp_tool="messages.get"
            ))
            msg_urls.append(msg_url)

        async def _fetch_one(url: str) -> dict:
            resp = await client.get(url, headers=auth, params={"format": "full"})
            _require_ok(resp, "Gmail message fetch")
            return _gmail_parse_message(resp.json())

        emails: list[dict] = list(await asyncio.gather(*(_fetch_one(u) for u in msg_urls)))

    # Numbered headers with stated total make spoofing detectable: an injected
    # "=== MESSAGE N of N ===" in a body would produce a count mismatch.
    total = len(emails)
    content = "\n\n".join(
        f"=== MESSAGE {i} of {total} ===\n" + "\n".join([
            f"From:    {em['from']}",
            f"Subject: {em['subject']}",
            f"Date:    {em['date']}",
            "Body:",
            em["body"] or "(empty)",
        ])
        for i, em in enumerate(emails, 1)
    )

    writer.write(content)

    first = emails[0] if emails else {}
    return {
        "thread_id":  first.get("thread_id", ""),
        "message_id": first.get("message_id", ""),
        "references": first.get("references", ""),
        "subject":    first.get("subject", ""),
    }


# ── run_mcp_calendar_search ────────────────────────────────────────────

async def run_mcp_calendar_search(
    spec:          AgentSpec,
    filter_params: dict,
    writer:        SlotWriter,
    policy:        IronFlow,
    *,
    google_token:  str = "",
) -> None:
    """
    Fetch calendar events via Google Calendar REST API — operator code only, no LLM.
    Writes event data to slot as (U,priv) — untrusted AND private.

    GET /calendar/v3/calendars/{calendarId}/events?timeMin=...&timeMax=...

    filter_params keys (all optional):
      calendarId  — calendar to query (default: "primary")
      timeMin     — ISO 8601 datetime lower bound
      timeMax     — ISO 8601 datetime upper bound
      maxResults  — max events to return (default: 10)
      q           — free-text search query

    Auth: google_token (calendar.readonly scope required).
    Event titles, descriptions, and attendee lists are ALL (U,priv) — untrusted
    content that cannot reach any routing field without explicit declassification.
    """
    auth        = _google_auth_headers(google_token)
    base_params: dict = {"singleEvents": "true", "orderBy": "startTime"}
    for key in ("timeMin", "timeMax", "maxResults", "q"):
        if key in filter_params:
            val = filter_params[key]
            if key in ("timeMin", "timeMax") and isinstance(val, str):
                val = _ensure_tz(val)
            base_params[key] = val

    async with httpx.AsyncClient(timeout=20.0) as client:
        # Determine which calendars to query.
        # If calendarId is explicitly set, use only that one.
        # Otherwise fan out to all non-hidden calendars so events on work/shared
        # calendars are visible to the processor for overlap checking.
        # calendarList uses _GCAL_V3 — one authoritative base.
        if "calendarId" in filter_params:
            calendar_ids = [filter_params["calendarId"]]
        else:
            cl_url = f"{_GCAL_V3}/users/me/calendarList"
            policy.before_network(spec, cl_url)
            cl_resp = await client.get(cl_url, headers=auth)
            _require_ok(cl_resp, "Calendar list")
            calendar_ids = [
                c["id"] for c in cl_resp.json().get("items", [])
                if not c.get("hidden") and c.get("accessRole") in ("owner", "writer", "reader")
            ] or ["primary"]

        all_items: list[dict] = []
        for cal_id in calendar_ids:
            # quote() encodes calendar IDs that contain '/', '?', or other path
            # characters (e.g. en.usa#holiday@group.v.calendar.google.com).
            cal_url = f"{_GCAL_REST_BASE}/{quote(cal_id, safe='')}/events"
            policy.before_network(spec, cal_url)
            _trace.emit(_trace.EvFetch(
                agent_id=spec.id, url=cal_url, shallow=False, mcp_tool="events.list"
            ))

            # Paginate: Google Calendar's nextPageToken signals more results.
            # Not following it silently drops events — a correctness failure for
            # overlap-checking pipelines (default page size is 250; max is 2500).
            page_params = dict(base_params)
            while True:
                resp = await client.get(cal_url, headers=auth, params=page_params)
                if resp.status_code == 404:
                    break  # calendar exists in list but has no events endpoint
                _require_ok(resp, "Calendar events")
                try:
                    body = resp.json()
                except (json.JSONDecodeError, ValueError):
                    raise RuntimeError(
                        f"Calendar API returned unexpected body (status {resp.status_code}): "
                        f"{resp.text[:200]}"
                    )
                all_items.extend(body.get("items", []))
                if not (tok := body.get("nextPageToken")):
                    break
                page_params = {**base_params, "pageToken": tok}

    if not all_items:
        content = "(no events found for the requested period)"
    else:
        parts: list[str] = []
        for ev in all_items:
            start     = ev.get("start", {})
            end       = ev.get("end",   {})
            start_str = start.get("dateTime", start.get("date", "(unknown)"))
            end_str   = end.get("dateTime",   end.get("date",   "(unknown)"))
            attendees = [
                a.get("displayName") or a.get("email", "")
                for a in ev.get("attendees", [])
                if a.get("email")
            ]
            lines = [
                f"Title:     {ev.get('summary', '(no title)')}",
                f"When:      {start_str} — {end_str}",
            ]
            if ev.get("location"):
                lines.append(f"Where:     {ev['location']}")
            if attendees:
                lines.append(f"Attendees: {', '.join(attendees)}")
            if ev.get("description"):
                lines.append(f"Notes:     {ev['description'][:300]}")
            parts.append("\n".join(lines))
        content = "\n\n---\n\n".join(parts)

    # Cap to the same word budget as web fetches to avoid oversized processor inputs.
    words = content.split()
    if len(words) > _MAX_WEB_WORDS:
        content = " ".join(words[:_MAX_WEB_WORDS])

    writer.write(content)


# ── Duffel flights REST ───────────────────────────────────────────────
_LITEAPI_VERSION = "v3.0"
_DUFFEL_VERSION = "v2"

def _duffel_auth_headers(duffel_token: str = "") -> dict[str, str]:
    """Bearer + version headers for the Duffel API. Token is operator-supplied; never logged."""
    return {
        "Authorization":  f"Bearer {duffel_token}",
        "Duffel-Version":  _DUFFEL_VERSION,
        "Content-Type":    "application/json",
        "Accept":          "application/json",
    }

async def run_duffel_flight_search(
    spec:          AgentSpec,
    base_url:      str,
    search_params: dict,
    writer:        SlotWriter,
    policy:        IronFlow,
    *,
    duffel_token:  str = "",
    limit:         int = 10,
) -> None:
    """
    Tier 1 Data Sub-Agent (Duffel REST): operator code only — no LLM.

    POST {base_url}/offer_requests?return_offers=true → offers, then write the
    top-`limit` cheapest as a JSON array to a (U,pub) slot. Each entry carries
    what spawn_processor needs to pick and book_flight needs to re-validate. Ranking is delegated to the downstream spawn_processor step.

    Auth: duffel_token (operator-supplied; injected by the driver, never reaching
    an LLM sub-agent or a slot).
    """
    if not duffel_token:
        raise RuntimeError(
            "Duffel flight search requires DUFFEL_ACCESS_TOKEN (none provided)."
        )
    origin      = str(search_params.get("origin", "")).strip()
    destination = str(search_params.get("destination", "")).strip()
    depart      = str(search_params.get("departure_date", "")).strip()
    if not (origin and destination and depart):
        raise RuntimeError(
            "duffel flight search requires origin, destination, departure_date "
            f"(got {search_params!r})"
        )
    try:
        adults = max(1, int(search_params.get("passengers", 1) or 1))
    except (TypeError, ValueError):
        adults = 1
    cabin  = str(search_params.get("cabin_class", "economy")).strip() or "economy"
    return_date = str(search_params.get("return_date", "")).strip()

    # One slice = one-way; two slices (outbound + return) = a single round-trip
    # offer request → Duffel returns offers that cover BOTH legs at one total.
    slices = [{"origin": origin, "destination": destination, "departure_date": depart}]
    if return_date:
        slices.append({"origin": destination, "destination": origin, "departure_date": return_date})

    body = {"data": {
        "slices":      slices,
        "passengers":  [{"type": "adult"} for _ in range(adults)],
        "cabin_class": cabin,
    }}

    url = f"{base_url}/offer_requests?return_offers=true"
    policy.before_network(spec, url)
    _trace.emit(_trace.EvFetch(agent_id=spec.id, url=url, mcp_tool="offer_requests", shallow=False))

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers=_duffel_auth_headers(duffel_token), json=body)
        _require_ok(resp, "Duffel offer_requests")
        try:
            offers = resp.json().get("data", {}).get("offers", [])
        except json.JSONDecodeError:
            raise RuntimeError(
                f"Duffel returned non-JSON body (status {resp.status_code}): {resp.text[:200]}"
            )

    def _price(o: dict) -> float:
        try:
            return float(o.get("total_amount", "inf"))
        except (TypeError, ValueError):
            return float("inf")

    trimmed: list[dict] = []
    for o in sorted(offers, key=_price)[: max(1, limit)]:
        slices = o.get("slices") or []
        legs = []
        for sl in slices:
            s = sl.get("segments") or []
            if s:
                legs.append(f'{s[0]["origin"]["iata_code"]}->{s[-1]["destination"]["iata_code"]}')
        first_seg = (slices[0].get("segments") or [{}])[0] if slices else {}
        last_seg  = (slices[-1].get("segments") or [{}])[-1] if slices else {}
        trimmed.append({
            "offer_id":       o.get("id", ""),
            "total_amount":   o.get("total_amount", ""),   # covers ALL legs of the offer
            "total_currency": o.get("total_currency", ""),
            "owner":          (o.get("owner") or {}).get("name", ""),
            "route":          " / ".join(legs),
            "round_trip":     len(slices) > 1,
            "departs":        first_seg.get("departing_at", ""),
            "returns":        last_seg.get("arriving_at", "") if len(slices) > 1 else "",
            "expires_at":     o.get("expires_at", ""),
        })

    writer.write(json.dumps(trimmed, indent=2) if trimmed else "(no flight offers found)")

def _liteapi_headers(liteapi_key: str = "") -> dict[str, str]:
    """API-key + content headers for LiteAPI. Key is operator-supplied; never logged."""
    return {
        "X-API-Key":    liteapi_key,
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }

async def run_liteapi_hotel_search(
    spec:          AgentSpec,
    base_url:      str,
    search_params: dict,
    writer:        SlotWriter,
    policy:        IronFlow,
    *,
    liteapi_key:   str = "",
    limit:         int = 30,
) -> None:
    """
    Tier 1 Data Sub-Agent (LiteAPI REST): operator code only — no LLM.

    Resolve city → hotelIds+names+stars (GET /data/hotels), then POST
    /hotels/rates, and write the top-`limit` cheapest as a JSON array to a
    (U,pub) slot. `limit` defaults to the full /data/hotels lookup cap (30) so
    that non-price constraints in the processor's instruction (e.g. a minimum
    star rating) are evaluated against the whole fetched pool, not just the
    cheapest slice. Each entry carries what spawn_processor needs to pick and
    book_hotel needs to re-search before prebook.

    Auth: liteapi_key (operator-supplied; injected by the driver, never a slot).
    """
    if not liteapi_key:
        raise RuntimeError("LiteAPI hotel search requires LITEAPI_SANDBOX_KEY (none provided).")
    city    = str(search_params.get("city", "")).strip()
    country = str(search_params.get("country_code", "")).strip()
    checkin = str(search_params.get("checkin", "")).strip()
    checkout= str(search_params.get("checkout", "")).strip()
    if not (city and country and checkin and checkout):
        raise RuntimeError(
            "LiteAPI hotel search requires city, country_code, checkin, checkout "
            f"(got {search_params!r})"
        )
    try:
        adults = max(1, int(search_params.get("adults", 1) or 1))
    except (TypeError, ValueError):
        adults = 1
    headers = _liteapi_headers(liteapi_key)

    hotels_url = (f"{base_url}/data/hotels?countryCode={quote(country)}"
                  f"&cityName={quote(city)}&limit=30")
    policy.before_network(spec, hotels_url)
    _trace.emit(_trace.EvFetch(agent_id=spec.id, url=hotels_url, mcp_tool="data/hotels", shallow=False))
    async with httpx.AsyncClient(timeout=30.0) as client:
        hresp = await client.get(hotels_url, headers=headers)
        _require_ok(hresp, "LiteAPI hotels lookup")
        hotel_meta = hresp.json().get("data", [])
        names = {h.get("id"): h.get("name", "") for h in hotel_meta}
        star_ratings = {h.get("id"): h.get("stars") for h in hotel_meta}

    if not names:
        writer.write("(no hotels found)")
        return

    rates_url = f"{base_url}/hotels/rates"
    policy.before_network(spec, rates_url)
    _trace.emit(_trace.EvFetch(agent_id=spec.id, url=rates_url, mcp_tool="hotels/rates", shallow=False))
    body = {"hotelIds": list(names.keys()), "checkin": checkin, "checkout": checkout,
            "occupancies": [{"adults": adults}], "currency": "GBP", "guestNationality": country}
    async with httpx.AsyncClient(timeout=45.0) as client:
        rresp = await client.post(rates_url, headers=headers, json=body)
        _require_ok(rresp, "LiteAPI rates")
        hotels = rresp.json().get("data", [])

    def _cheapest(hotel: dict):
        best = None
        for rt in hotel.get("roomTypes", []):
            for r in rt.get("rates", []):
                tot = (r.get("retailRate") or {}).get("total") or []
                if not tot:
                    continue
                amt = tot[0].get("amount")
                if amt is None:
                    continue
                cand = {"offer_id": rt.get("offerId", ""), "amount": amt,
                        "currency": tot[0].get("currency", ""), "board": r.get("boardName", "")}
                if best is None or float(amt) < float(best["amount"]):
                    best = cand
        return best

    picks = []
    for h in hotels:
        c = _cheapest(h)
        if not c:
            continue
        c["hotel"] = names.get(h.get("hotelId"), h.get("hotelId", ""))
        c["hotel_id"] = h.get("hotelId", "")
        c["star_rating"] = star_ratings.get(h.get("hotelId"))
        # Carry the search context so book_hotel can re-search this hotel for a
        # FRESH offer just before prebook (LiteAPI rate offers expire quickly).
        c["checkin"] = checkin
        c["checkout"] = checkout
        c["adults"] = adults
        c["country_code"] = country
        picks.append(c)
    picks.sort(key=lambda x: float(x["amount"]))
    writer.write(json.dumps(picks[: max(1, limit)], indent=2) if picks else "(no hotel offers found)")

# ══════════════════════════════════════════════════════════════════════
# TIER 2 — PROCESSOR SUB-AGENTS
# Isolated claude -p, reads slots only, no network.
# ══════════════════════════════════════════════════════════════════════

async def run_processor(
    reads:         list[str],
    reader:        SlotReader,
    writer:        SlotWriter,
    *,
    system_prompt: str,
    agent_id:      str,
    timeout:       int = 300,
    api_key:       str | None = None,
) -> None:
    """
    Read dirty slots into context, run isolated LLM, write output slot.
    Output label is fixed on the SlotWriter by the driver before spawn fires.
    Write and trace are handled by writer.write(); read and trace by reader.read().
    """
    context_parts: list[str] = []
    input_labels:  list[Label] = []

    for slot_id in reads:
        lval = reader.read(slot_id)
        context_parts.append(f"[{slot_id}]\n{lval.value}")
        input_labels.append(lval.label)

    # Natively async — no thread hop.
    output = await _llm_processor(
        system_prompt,
        "\n\n".join(context_parts),
        timeout=timeout,
        api_key=api_key,
    )

    _trace.emit(_trace.EvTaint(
        agent_id=agent_id,
        input_labels=[str(lbl) for lbl in input_labels],
        output_label=str(writer.label),
    ))
    writer.write(output)


