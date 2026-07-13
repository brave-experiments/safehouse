"""
runner.py — Sub-agent execution for the IPI-resistant pipeline.

Three sections, matching the architecture:

  TIER 1 — DATA SUB-AGENTS (operator code only — no LLM):
    run_mcp_page_content     — HTTP fetch + HTML denoising → (U,pub) slot
    run_mcp_email_search     — Gmail REST API → (U,priv) slot
    run_mcp_calendar_search  — Google Calendar REST API → (U,priv) slot
    run_mcp_search           — MCP call + deterministic URL extract → (U,pub) slot

  TIER 2 — PROCESSOR SUB-AGENTS (isolated claude -p, reads slots only, no network):
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
import contextlib
import html as _html
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from urllib.parse import urlparse, urljoin, quote

import httpx

from .labels import Label
from .slots import SlotReader, SlotWriter
from .permissions import AgentSpec
from .ironflow_policy import IronFlow, IronFlowViolation
from . import trace as _trace

try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    _MCP_AVAILABLE = True
    import logging as _logging
    # Suppress benign "Session termination failed: 501" from MCP session cleanup.
    # Logger-level suppression is async-safe; concurrent MCP calls share the logger.
    _logging.getLogger("mcp").setLevel(_logging.CRITICAL)
    _logging.getLogger("mcp.client.streamable_http").setLevel(_logging.CRITICAL)
    _logging.getLogger("httpx").setLevel(_logging.WARNING)
except ImportError:
    _MCP_AVAILABLE = False


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

# Non-secret vars the Tier-2 sub-agent needs; ANTHROPIC_*/CLAUDE_* added in _subagent_env.
_SUBAGENT_ENV_KEEP = frozenset({
    "HOME", "PATH", "USER", "LOGNAME", "SHELL", "TERM", "TMPDIR",
    "LANG", "LC_ALL", "LC_CTYPE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
})


def _subagent_env() -> dict[str, str]:
    """Allowlisted env for the Tier-2 sub-agent — drops GOOGLE_ACCESS_TOKEN et al."""
    return {k: v for k, v in os.environ.items()
            if k in _SUBAGENT_ENV_KEEP or k.startswith(("ANTHROPIC_", "CLAUDE_"))}


def _claude_subagent(system: str, user: str, *, timeout: int = 300) -> str:
    """
    Spawn an isolated Claude Code sub-agent: claude -p --tools "".
    No memory, no tools, no slot access — pure text generation.
    Streams output to terminal with "  │ " prefix for live progress.
    Returns the complete response text.

    Security: user content (slot data, which may be (U,priv)) is passed via
    stdin — NOT as a positional argv argument — so it does not appear in ps
    output or /proc/*/cmdline and is not subject to ARG_MAX limits. The child
    runs with an allowlisted environment (_subagent_env) so ambient credentials
    such as GOOGLE_ACCESS_TOKEN never reach it.

    --system-prompt intentionally replaces Claude's entire default system
    prompt (including default tool guidance) — correct for isolated processors
    whose tool access must be empty ("").
    """
    proc = subprocess.Popen(
        # Static short prompt in argv; actual slot content arrives via stdin.
        ["claude", "-p", "Process the input per the system instructions.",
         "--system-prompt", system,
         "--tools", "",
         "--output-format", "text",
         "--dangerously-skip-permissions"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
        env=_subagent_env(),
    )

    # Write stdin on a thread: if the child starts streaming stdout before it
    # has consumed all stdin (which claude does), the parent blocks in stdin.write
    # while the child blocks writing stdout — a classic pipe deadlock. BrokenPipeError
    # is benign (child already exited).
    def _write_stdin() -> None:
        try:
            proc.stdin.write(user)   # type: ignore[union-attr]
            proc.stdin.close()       # type: ignore[union-attr]
        except BrokenPipeError:
            pass

    threading.Thread(target=_write_stdin, daemon=True).start()

    # Drain stderr on a thread — an unread PIPE deadlocks the child once the OS buffer fills.
    err_buf: list[str] = []
    err_thread = threading.Thread(
        target=lambda: err_buf.append(proc.stderr.read()),  # type: ignore[union-attr]
        daemon=True,
    )
    err_thread.start()

    # Kill timer: enforces the wall-clock timeout even when the child produces
    # no stdout (a silently hanging sub-agent never reaches proc.wait()).
    killer = threading.Timer(timeout, proc.kill)
    killer.start()

    parts: list[str] = []
    col = min(shutil.get_terminal_size(fallback=(120, 40)).columns - 6, 134)
    shown = 0
    suppressed = 0
    try:
        for line in proc.stdout:        # type: ignore[union-attr]
            parts.append(line)
            if shown < _MAX_STREAM_LINES:
                display = line.rstrip("\n")
                if len(display) > col:
                    display = display[:col - 1] + "…"
                sys.stdout.write("  │ " + display + "\n")
                sys.stdout.flush()
                shown += 1
            else:
                suppressed += 1
        if suppressed:
            sys.stdout.write(f"  │  … (+{suppressed} more lines)\n")
            sys.stdout.flush()
        proc.wait()
    finally:
        killer.cancel()

    if proc.returncode and proc.returncode < 0:   # killed by the timer
        raise RuntimeError(f"sub-agent timed out after {timeout}s")
    if proc.returncode != 0:
        err_thread.join(timeout=2)
        stderr_diag = (err_buf[0] if err_buf else "")[:200]
        raise RuntimeError(f"sub-agent failed (exit {proc.returncode}): {stderr_diag}")
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
        list_resp.raise_for_status()

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
            resp.raise_for_status()
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
            cl_resp.raise_for_status()
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
                resp.raise_for_status()
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


# ── run_mcp_search helpers ────────────────────────────────────────────

_URL_FIELDS = (
    "deepLink", "deep_link", "booking_url", "booking_link",
    "Accommodation URL", "link", "url",
)
_CONTEXT_FIELDS = (
    # Kiwi flight fields
    "price", "totalPrice", "total_price", "fare", "amount",
    "flyFrom", "flyTo", "cityFrom", "cityTo", "origin", "destination",
    "route", "duration", "airlines",
    # trivago hotel fields
    "name", "hotel_name", "property_name",
    "Accommodation Name", "Price Per Stay", "Price Per Night",
    "Hotel Rating", "Review Rating", "Review Count",
    "Distance To City Center", "Address", "Top Amenities",
)


def _extract_booking_urls(mcp_text: str, trusted_action_urls: list[str]) -> tuple[list[dict], str]:
    """
    Deterministic extraction of booking URLs from an MCP response.
    Never calls an LLM — injection-safe.

    Strategy 1a (top-level JSON): walks known container keys, extracts one URL
    per result object and captures context fields (price, name, route) so the
    downstream processor can correlate each URL with the option it ranks.

    Strategy 1b (embedded JSON): when the MCP response is mixed text + JSON
    fragments (e.g. trivago); scans for embedded objects containing list-valued
    keys and applies the same URL extraction.

    Strategy 2 (regex fallback): when no parseable JSON is found; extracts raw
    URLs from the text with no context available.

    Returns (results, strategy) where strategy is "json" | "regex" | "none".
    results is a list of {"url": str, "context": dict}, deduplicated, in response order.
    Empty list if no trusted-domain URLs are found.

    trusted excludes entries where netloc is empty — an unparseable trusted URL must
    never match a malformed candidate URL that also produces netloc="".
    """
    # Trust requires both matching scheme AND host (case-insensitive).
    # A netloc-only check would allow http://kiwi.com to match a trust list
    # containing only https://kiwi.com — a scheme-downgrade bypass.
    trusted: set[tuple[str, str]] = {
        (p.scheme, p.netloc.lower())
        for u in trusted_action_urls
        if (p := urlparse(u)).netloc
    }
    results: list[dict] = []
    seen: set[str] = set()

    def _scan(candidates: list[object]) -> None:
        for obj in candidates:
            if not isinstance(obj, dict):
                continue
            for field in _URL_FIELDS:
                val = obj.get(field, "")
                if isinstance(val, str) and val.startswith("http"):
                    p = urlparse(val)
                    if (p.scheme, p.netloc.lower()) in trusted and val not in seen:
                        seen.add(val)
                        results.append({
                            "url":     val,
                            "context": {k: obj[k] for k in _CONTEXT_FIELDS if k in obj},
                        })
                        break  # one URL per result object

    # Strategy 1a: top-level array (Kiwi) or dict with known container keys.
    # Only extracted sub-lists are scanned — not the envelope dict itself —
    # to avoid an envelope-level self-link consuming the one-URL-per-object slot.
    # If no known key matches, scan ALL list values in the dict — different MCP
    # servers use different envelope keys ("itineraries", "data", "offers", …).
    try:
        data = json.loads(mcp_text)
        if isinstance(data, list):
            _scan(data)
        elif isinstance(data, dict):
            candidates: list = []
            for key in ("flights", "results", "hotels", "accommodations", "items", "output",
                        "data", "itineraries", "offers", "content"):
                v = data.get(key)
                if isinstance(v, list):
                    candidates.extend(v)
                elif isinstance(v, str):
                    with contextlib.suppress(json.JSONDecodeError):
                        inner = json.loads(v)
                        if isinstance(inner, list):
                            candidates.extend(inner)
            if not candidates:  # unknown envelope key — scan any list containing dicts
                for v in data.values():
                    if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                        candidates.extend(v)
            _scan(candidates)
    except (json.JSONDecodeError, AttributeError):
        pass

    if results:
        return results, "json"

    # Strategy 1b: scan for embedded JSON arrays OR objects using raw_decode.
    # Handles MCP responses that mix plain-text with a JSON body — e.g.:
    #   "Here are the results:\n[{\"deepLink\": \"https://kiwi.com/u/...\", ...}]"
    # Strategy 1a's json.loads fails on the text prefix; raw_decode finds the
    # '[' or '{' start and decodes from there. Always prefer the earlier start
    # character so an array at position 20 is not missed in favour of a '{'
    # at position 21 (which would be inside the array, not the array itself).
    _decoder = json.JSONDecoder()
    pos = 0
    while pos < len(mcp_text):
        obj_pos = mcp_text.find("{", pos)
        arr_pos = mcp_text.find("[", pos)
        if obj_pos == -1 and arr_pos == -1:
            break
        if obj_pos == -1:
            start = arr_pos
        elif arr_pos == -1:
            start = obj_pos
        else:
            start = min(obj_pos, arr_pos)
        try:
            parsed, end = _decoder.raw_decode(mcp_text, start)
            pos = end
            if isinstance(parsed, list):
                _scan(parsed)
            elif isinstance(parsed, dict):
                for key in ("output", "results", "hotels", "accommodations",
                            "flights", "items", "data", "itineraries"):
                    v = parsed.get(key)
                    if isinstance(v, str):
                        with contextlib.suppress(json.JSONDecodeError):
                            inner = json.loads(v)
                            if isinstance(inner, list):
                                _scan(inner)
                    elif isinstance(v, list):
                        _scan(v)
            if results:
                return results, "json"
        except json.JSONDecodeError:
            pos = start + 1

    # Strategy 2: regex fallback — URL only, no context.
    # Decode \uXXXX escape sequences that some MCP servers (e.g. trivago) emit
    # as literal text rather than proper JSON unicode escapes.
    _UESCAPE = re.compile(r'\\u([0-9a-fA-F]{4})')
    for url in re.findall(r'https?://[^\s\'"<>]+', mcp_text):
        url = url.rstrip(".,;)")
        url = _UESCAPE.sub(lambda m: chr(int(m.group(1), 16)), url)
        p = urlparse(url)
        if (p.scheme, p.netloc.lower()) in trusted and url not in seen:
            seen.add(url)
            results.append({"url": url, "context": {}})

    return results, ("regex" if results else "none")


def _unwrap_exc(exc: BaseException) -> BaseException:
    """Recursively unwrap ExceptionGroup until a concrete exception is reached."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


# ── run_mcp_search ─────────────────────────────────────────────────────

async def run_mcp_search(
    spec:                AgentSpec,
    domain:              str,
    mcp_tool:            str,
    search_params:       dict,
    writer:              SlotWriter,
    policy:              IronFlow,
    trusted_action_urls: list[str] | None = None,
    location_tool:       str | None = None,
) -> None:
    """
    Tier 1 Data Sub-Agent (MCP): operator code only — no LLM.

    Step 0 — Optional location pre-lookup (e.g. trivago-search-suggestions).
              Resolves a city name to a numeric id/ns — deterministic, not injectable.
    Step 1 — Operator code calls the MCP server via ClientSession.call_tool().
    Step 2 — Operator code extracts booking URLs deterministically
              via _extract_booking_urls() (JSON parse → regex fallback, no LLM).
    Step 3 — Structured results (BOOKING_URLS_JSON + BOOKING_URL) written to
              the slot in MCP response order. Ranking is delegated to a downstream
              spawn_processor step — LLM processing stays outside the fetcher tier.

    Security: URL provenance is the MCP server (operator-declared infrastructure),
    then domain-validated again by the Tier 3 driver tool before any booking fires.
    """
    if not _MCP_AVAILABLE:
        raise RuntimeError("mcp package required: pip install 'mcp[cli]'")

    _trace.emit(_trace.EvFetch(agent_id=spec.id, url=domain, mcp_tool=mcp_tool, shallow=False))
    policy.before_network(spec, domain)

    params = dict(search_params)
    try:
        async with streamablehttp_client(domain) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                if location_tool and "location_query" in params:
                    loc_query = params.pop("location_query")
                    loc_result = await session.call_tool(
                        location_tool, arguments={"query": loc_query}
                    )
                    loc_text = "\n".join(
                        c.text for c in loc_result.content if hasattr(c, "text")
                    )
                    id_m = re.search(r'ID:(\d+)', loc_text)
                    ns_m = re.search(r'NS:(\d+)', loc_text)
                    if id_m and ns_m:
                        params["id"] = int(id_m.group(1))
                        params["ns"] = int(ns_m.group(1))
                    else:
                        raise RuntimeError(
                            f"location pre-lookup '{location_tool}' returned no ID/NS"
                        )

                result   = await session.call_tool(mcp_tool, arguments=params)
                mcp_text = "\n".join(
                    c.text for c in result.content if hasattr(c, "text")
                )
    except Exception as exc:
        # Unwrap ExceptionGroup raised by anyio TaskGroup inside streamablehttp_client.
        inner = _unwrap_exc(exc)
        if isinstance(inner, RuntimeError):
            raise inner from exc
        raise RuntimeError(f"MCP call failed for slot '{writer.slot_id}': {inner}") from exc

    # Step 2: extract booking URLs deterministically
    booking_entries, extraction_strategy = _extract_booking_urls(mcp_text, trusted_action_urls or [])
    _trace.emit(_trace.EvBookingUrlsExtracted(
        agent_id=spec.id, slot_id=writer.slot_id,
        count=len(booking_entries), strategy=extraction_strategy,
        urls=[e["url"] for e in booking_entries],
    ))

    # Step 3: write structured results in MCP response order.
    # Ranking is intentionally delegated to a downstream spawn_processor step
    # so that LLM-based processing stays outside the deterministic fetcher tier.
    # If no URLs were extracted, fall back to truncated raw text so the processor
    # is not handed an empty slot.
    # When the regex fallback ran (all contexts are empty), also include the raw
    # MCP text — the processor needs pricing and routing data to rank options,
    # and that data is only available in the original response at this point.
    header = (
        f"BOOKING_URLS_JSON: {json.dumps(booking_entries)}\n"
        f"BOOKING_URL: {booking_entries[0]['url']}\n"
    ) if booking_entries else ""
    has_context = booking_entries and any(e.get("context") for e in booking_entries)
    if not booking_entries:
        content = " ".join(mcp_text.split()[:_MAX_WEB_WORDS])
    elif has_context:
        content = header
    else:
        raw_excerpt = " ".join(mcp_text.split()[:_MAX_WEB_WORDS])
        content = header + f"\nRAW_MCP_RESPONSE:\n{raw_excerpt}"

    writer.write(content)


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

    # _claude_subagent is blocking (subprocess + synchronous pipe reads). Run it
    # in a thread so concurrent asyncio.gather calls (e.g. fetcher + processor)
    # are not stalled for the processor's full duration.
    output = await asyncio.to_thread(
        _claude_subagent,
        system_prompt,
        "\n\n".join(context_parts),
        timeout=timeout,
    )

    _trace.emit(_trace.EvTaint(
        agent_id=agent_id,
        input_labels=[str(lbl) for lbl in input_labels],
        output_label=str(writer.label),
    ))
    writer.write(output)


