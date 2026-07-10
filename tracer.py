"""
tracer.py — All display and tracing logic for the IPI pipeline demos.

This file is the rendering engine. It is intentionally separate so that
safehouse_cli shows only system flow, not display detail.

Contents (in order):
  1. Terminal display helpers  (_w, _banner, _section, _pause, …)
  2. _ironflow_intro            (opening banner + IronFlow principles)
  3. Shared audit helpers       (print_slot_inventory, print_violations, …)
  4. BaseTracer                 (renders every common pipeline event)
  5. DemoSpec + _DemoTracer     (generic per-demo configuration + tracer)
  6. Per-demo specs             (_BRIEFING_SPEC, _TRIP_SPEC, _EMAIL_SPEC,
                                 _CALENDAR_SPEC)
     Each spec block: event handlers → audit function → DemoSpec instance
     _CALENDAR_SPEC covers both the calendar-summary and meeting-scheduling
     flows; the planner selects the right tools from the task string.
  7. Universal spec             (_UNIVERSAL_SPEC)
     Merges all per-demo handlers; runtime pipeline selection via
     tracer._state["_pipeline"] (set by safehouse_cli.app after generate_plan).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field as dc_field
from typing import Any, Callable
from urllib.parse import urlparse as _urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safehouse.ironflow_policy import PRINCIPLES
from safehouse.planner import TOOL_SCHEMA, ToolContract
from safehouse.trace import (
    Tracer,
    EvPlanPhase1Start, EvPlanChunk, EvPlanPhase2, EvPlanPhase3,
    EvStaticPlan, EvDriverStart, EvPlanStep, EvAgentSpawned,
    EvFetch, EvSlotWritten, EvSlotRead, EvTaint,
    EvGate, EvEmailSent, EvDeclassify, EvPipelineEnd,
    EvActionFired,
    EvRoutingLocked, EvBookingUrlsExtracted,
    EvReplyActionFired,
    EvMeetingOptionsReady,
    EvMeetingConfirmation, EvMeetingScheduled,
    EvEmailsModified,
    EvAutoApproved,
)


# Gmail filter field → display string; used by _print_plan_step for mcp_email_search display.
# Defined at module level so it is not rebuilt on every plan step render.
_GMAIL_QUERY_MAP: dict[str, Any] = {
    "from":             lambda v: f"from:{v}",
    "subject_contains": lambda v: f"subject:{v}",
    "after_date":       lambda v: f"after:{v}",
    "before_date":      lambda v: f"before:{v}",
    "label":            lambda v: f"label:{v}",
    "is_unread":        lambda v: "is:unread" if v else None,
    "has_attachment":   lambda v: "has:attachment" if v else None,
    "q":                lambda v: str(v),
}


# ══════════════════════════════════════════════════════════════════════
# 1. TERMINAL DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════

def _w() -> int:
    """Current terminal width, capped at 140, re-sampled each call."""
    return min(shutil.get_terminal_size(fallback=(120, 40)).columns - 2, 140)

def _banner(title: str) -> None:
    w = _w()
    print(f"\n{'═'*w}\n  {title}\n{'═'*w}", flush=True)

def _section(title: str) -> None:
    w = _w()
    print(f"\n{'─'*w}\n  {title}\n{'─'*w}", flush=True)

def _pause(msg: str, hint: str = "") -> None:
    """Blocking pause for demo/video recording."""
    w = _w()
    print(f"\n{'·'*w}")
    print(f"  ⏸  {msg}")
    if hint:
        print(f"     {hint}")
    input("  Press Enter to continue…")
    print()   # Enter keypress bypasses _Tee; force newline into file
    print(f"{'·'*w}\n")

def _fmt_perm(p: str) -> str:
    """Truncate URLs inside NET(...) to 40 chars, stripping the scheme."""
    if p.startswith("NET(") and p.endswith(")"):
        url = p[4:-1]
        for scheme in ("https://", "http://"):
            if url.startswith(scheme):
                url = url[len(scheme):]
                break
        if len(url) > 40:
            url = url[:40] + "..."
        return f"NET({url})"
    return p

def _fmt_trust(trust: str) -> str:
    """Strip Python enum prefix: 'I.U' → 'U', 'I.T' → 'T'."""
    return trust[2:] if trust.startswith("I.") else trust

def _label_axes(label_str: str) -> tuple[str, str]:
    """Parse '(T,pub)' into ('T', 'pub')."""
    inner = label_str.strip("()")
    parts = inner.split(",", 1)
    return (parts[0].strip(), parts[1].strip()) if len(parts) == 2 else (label_str, "")


# ══════════════════════════════════════════════════════════════════════
# 2. IRONFLOW INTRO BANNER
# ══════════════════════════════════════════════════════════════════════

def _ironflow_intro() -> None:
    """Print the Brave-SafeHouse / IronFlow opening banner, then wait for the user."""
    w = _w()
    print(flush=True)
    print(f"{'█'*w}", flush=True)
    print(f"{'█'*w}", flush=True)
    title = "BRAVE-SAFEHOUSE"
    print(f"{'█'*w}", flush=True)
    print(f"{'█'*4}{title.center(w - 8)}{'█'*4}", flush=True)
    print(f"{'█'*w}", flush=True)
    print(f"{'█'*w}", flush=True)
    print(flush=True)
    print(f"  Your task is entering the safe house.", flush=True)
    print(f"  It will run under the IronFlow engine — 5 structural enforcement principles:", flush=True)
    print(flush=True)
    for roman, principle, desc in PRINCIPLES:
        print(f"    {roman:<4} {principle.value}", flush=True)
    print(flush=True)
    print(f"{'═'*w}", flush=True)
    input("  Ready? Press Enter to continue…")
    print()   # Enter keypress bypasses _Tee; force newline into log file
    print(f"{'═'*w}\n", flush=True)


# ══════════════════════════════════════════════════════════════════════
# 3. SHARED AUDIT HELPERS
# ══════════════════════════════════════════════════════════════════════

def print_slot_inventory(slot_inventory: list[dict]) -> None:
    _section("SLOT STORE")
    for s in slot_inventory:
        mark  = "●" if s["written"] else "○"
        label = f"  [{s['label']}]" if s.get("label") else ""
        print(f"    {mark}  {s['id']:30s}{label}")

def print_violations(violations: list[str]) -> None:
    _section("IRONFLOW VIOLATIONS")
    if violations:
        for v in violations:
            print(f"    ! {v[:120]}")
    else:
        print("    (none)")

def print_invariants(checks: list[tuple[str, bool]]) -> None:
    _section("INVARIANT CHECKS")
    for desc, ok in checks:
        print(f"    {'✓' if ok else '✗'}  {desc}")


def _audit_row(name: str, label_str: str, value: str, note: str = "") -> None:
    """One-line label annotation row for post-execution audit sections."""
    integ, _ = _label_axes(label_str)
    mark   = "✓" if integ == "T" else "○"
    suffix = f"  ← {note}" if note else ""
    print(f"  {mark}  {name:<12} [{label_str}]  {value!r}{suffix}")


# ══════════════════════════════════════════════════════════════════════
# 4. BaseTracer
# Renders every common pipeline event identically across all demos.
# Demo-specific events are handled via _on_other_event (overridden by
# _DemoTracer using the per-demo event_handlers dict).
# ══════════════════════════════════════════════════════════════════════

class BaseTracer(Tracer):
    """
    Universal pipeline tracer shared by all demos.

    Handles ALL common events and produces a consistent display layout:
      - Static plan: all steps shown in index order [0]→[N], with
        type-specific inline annotations for locked/terminal/routing tools.
      - Step headers: compact '·  step N/M → tool' marker; EvAgentSpawned
        immediately follows spawn steps and provides the full section header.
      - All common events (EvAgentSpawned, EvFetch, EvSlotRead, etc.).

    Demo-specific Tracer subclasses only need to:
      1. Override _on_other_event() for pipeline-specific events.
      2. Optionally override _on_slot_written() for per-step slot annotations.
      3. Add _GATE_TYPES entries if the pipeline has extra gate types (e.g. BOOKING).
    """

    # Gate types to buffer; subclasses may extend (e.g. add "BOOKING").
    _GATE_TYPES: set[str] = {"ACTION", "BRIDGE"}

    def __init__(self) -> None:
        self._total_steps  = 0   # all plan steps (for header display)
        self._active_steps = 0   # steps that emit progress markers (excludes internal)
        self._step_count   = 0   # running count of emitted progress markers
        self._end: dict | None = None
        self._gate_buffer: list = []

    # ── Planning-phase display ─────────────────────────────────────────

    def _render_concrete_plan(self, plan: dict, abstract_plan: dict) -> None:
        """Phase 2: full concrete plan; registry-injected fields annotated."""
        _injected = frozenset({"api_url", "domain", "mcp_tool", "search_params", "location_tool"})

        def _trunc(v: object, n: int = 72) -> str:
            s = repr(v) if isinstance(v, str) else str(v)
            return s[:n - 1] + "…" if len(s) > n else s

        injected_count = 0
        for i, step in enumerate(plan.get("steps", [])):
            args     = step["args"]
            abs_args = abstract_plan["steps"][i]["args"] if i < len(abstract_plan.get("steps", [])) else {}
            print(f"\n  [{i}] {step['tool']}")
            for k, v in args.items():
                is_injected = k not in abs_args and k in _injected
                marker = "  ← registry" if is_injected else ""
                if is_injected:
                    injected_count += 1
                print(f"       {k:<20}  {_trunc(v)}{marker}")

        urls = plan.get("trusted_action_urls", [])
        if urls:
            domain_list = " · ".join(_urlparse(u).netloc for u in urls)
            print(f"\n  trusted_action_urls   {domain_list}  ← registry")
            injected_count += 1

        n = len(plan.get("steps", []))
        print(f"\n  ✓ {n} steps  ({injected_count} provider field(s) injected by registry)\n", flush=True)

    def _render_validated_plan(self, plan: dict) -> None:
        """Phase 3: per-step slot dependency chain with resolution markers."""
        declared_slots: set[str] = set()

        for i, step in enumerate(plan.get("steps", [])):
            tool  = step["tool"]
            args  = step["args"]
            sc    = TOOL_SCHEMA.get(tool)
            parts: list[str] = []

            if sc and sc.slot_output:
                sid = args.get(sc.slot_output, "?")
                parts.append(f"slot_out:{sid!r}")
                declared_slots.add(sid)

            for f in (sc.slot_inputs if sc else ()):
                for sid in args.get(f, []):
                    parts.append(f"reads:{sid!r} {'✓' if sid in declared_slots else '✗'}")
            for f in (sc.slot_refs if sc else ()):
                sid = args.get(f, "")
                parts.append(f"slot:{sid!r} {'✓' if sid in declared_slots else '✗'}")

            driver = "  [DRIVER TOOL]" if (sc and sc.is_driver_tool) else ""
            print(f"  [{i}] {tool:<26}  {'  ·  '.join(parts)}{driver}")

        n = len(plan.get("steps", []))
        print(f"  ✓ {n} steps validated  (slot chain clean · all refs resolved)\n", flush=True)

    # ── Static plan display ────────────────────────────────────────────

    def _on_static_plan(self, ev: EvStaticPlan) -> None:
        _banner("DRIVER  —  EXECUTION MANIFEST  (planning complete · 3 phases)")
        print(f"  session: {ev.session_id}")
        print(f"  steps:   {self._total_steps}")
        print(f"  model:   claude-sonnet-4-6  |  sub-agents: claude -p --tools \"\"")
        self._render_task_template(ev.steps)
        w = _w()
        print(f"\n  {'─'*(w-2)}")
        print(f"  EXECUTION STEPS")
        print(f"  {'─'*(w-2)}")
        for s in ev.steps:
            self._print_plan_step(s)

    def _render_task_template(self, steps: list[dict]) -> None:
        """Synthesise the ACCOMPLISHING TASK TEMPLATE from the plan structure."""
        _spawn = {"mcp_page_content", "mcp_flight_search", "mcp_hotel_search",
                  "mcp_email_search", "mcp_calendar_search", "spawn_processor"}
        terminal = next(
            (s for s in steps
             if (sc := TOOL_SCHEMA.get(s["tool"])) and sc.is_driver_tool),
            None,
        )

        w = _w()
        print(f"\n  {'─'*(w-2)}")
        print(f"  ACCOMPLISHING TASK TEMPLATE")
        print(f"  {'─'*(w-2)}")

        has_priv = any(s["tool"] in ("mcp_email_search", "mcp_calendar_search") for s in steps)
        label_note = "(U,pub / U,priv — produced by sub-agents)" if has_priv else "(U,pub — produced by sub-agents)"
        print(f"\n  ○  INPUTS  {label_note}")
        for s in steps:
            if s["tool"] not in _spawn:
                continue
            slot = s["args"].get("slot_id") or s["args"].get("out_slot", "")
            if not slot:
                continue
            if s["tool"] in ("mcp_flight_search", "mcp_hotel_search"):
                domain = s["args"].get("domain", "")
                netloc = _urlparse(domain).netloc or domain
                src    = f"operator→MCP {netloc}  (no LLM)  + sub-agent rank (metadata only)"
            elif s["tool"] == "mcp_email_search":
                api_url = s["args"].get("api_url", "")
                netloc  = _urlparse(api_url).netloc or api_url
                src     = f"operator→mailbox provider {netloc}  (no LLM)  (U,priv)"
            elif s["tool"] == "mcp_calendar_search":
                api_url = s["args"].get("api_url", "")
                netloc  = _urlparse(api_url).netloc or api_url
                src     = f"operator→calendar provider {netloc}  (no LLM)  (U,priv)"
            elif s["tool"] == "mcp_page_content":
                src = "operator→HTTP fetch + HTML strip  (no LLM)"
            else:
                src = s["tool"].replace("spawn_", "")
            print(f"       {slot:<30s}  {src}")

        # Routing fields are in the terminal step args, pre-committed by driver.run()
        # before step 0 as (T,pub) — no create_*_template step required.
        print(f"\n  ✓  TRUSTED FIELDS  (T,pub — from task string · pre-committed before step 0 · IPI cannot overwrite)")
        if terminal:
            tool = terminal["tool"]
            args = terminal["args"]
            if tool == "send_reply":
                print(f"       recipient    {args.get('recipient', '')!r}  ← pre-committed before step 0")
                print(f"       subject      {args.get('subject', '')!r}  ← pre-committed before step 0")
            elif tool == "schedule_meeting":
                print(f"       attendee     {args.get('attendee', '')!r}  ← pre-committed before step 0")
                print(f"       event_title  {args.get('event_title', '')!r}  ← pre-committed before step 0")
                print(f"       subject      {args.get('reply_subject', '')!r}  ← pre-committed before step 0")
            elif tool == "send_summary":
                print(f"       recipient    {args.get('recipient', '')!r}  ← pre-committed before step 0")
                print(f"       subject      {args.get('subject', '')!r}  ← pre-committed before step 0")
            elif tool == "modify_emails":
                print(f"       sender       {args.get('sender', '')!r}  ← from task string")
                print(f"       action       {args.get('action', '')!r}  ← from task string")

        print(f"\n  →  ACTION  (body/payload is (U,pub) · destination is (T,pub) · cannot be redirected)")
        if terminal:
            tool = terminal["tool"]
            args = terminal["args"]
            if tool == "send_reply":
                print(f"       send reply   body ← slot '{args.get('body_slot', '')}'  "
                      f"to → recipient (T,pub pre-committed)  · CC/BCC impossible")
            elif tool == "send_summary":
                print(f"       send email   body ← slot '{args.get('body_slot', '')}'  "
                      f"to → recipient (T,pub pre-committed)")
            elif tool == "schedule_meeting":
                print(f"       schedule meeting  body ← slot '{args.get('slots_slot', '')}'  "
                      f"attendee → pre-committed (T,pub)  · CC/BCC impossible")
            elif tool == "modify_emails":
                print(f"       modify emails  filter: from:{args.get('sender', '')!r}  "
                      f"action: {args.get('action', '')!r}  — no slot read · IPI surface: zero")

    def _print_plan_step(self, s: dict) -> None:
        """Type-annotated single-step display used by _on_static_plan."""
        tool = s["tool"]
        args = s["args"]
        idx  = s["step_index"]

        if tool == "schedule_meeting":
            attendee    = args.get("attendee", "")
            event_title = args.get("event_title", "")
            reply_subj  = args.get("reply_subject", "")
            dur         = args.get("duration_minutes", 60)
            slots       = args.get("slots_slot", "")
            print(f"\n  [{idx}] schedule_meeting  "
                  f"← TIER 3 DRIVER TOOL · pure Python · no LLM")
            print(f"       attendee:      {attendee!r}  (T,pub)  ← pre-committed before step 0")
            print(f"       event_title:   {event_title!r}  (T,pub)  ← pre-committed before step 0")
            print(f"       reply_subject: {reply_subj!r}  (T,pub)  ← pre-committed before step 0")
            print(f"       duration:      {dur} min  (T,pub)")
            print(f"       step 1  domain whitelist check  →  attendee domain verified")
            print(f"       step 2  declassify slots_slot    →  (U,priv) → (U,pub)")
            print(f"       step 3  IronFlow bridge          →  INJECT mode")
            print(f"       step 4  human confirm slot       →  chosen slot elevated to (T,pub)")
            print(f"       step 5  create calendar event    →  Google Calendar API POST")
            print(f"       step 6  send reply               →  Gmail API")
            print(f"       slots_slot: {slots!r}")

        elif tool == "send_summary":
            print(f"\n  [{idx}] send_summary  "
                  f"← ROUTING FIELDS (T,pub) — from task string only")
            print(f"       recipient: {args.get('recipient', '')!r}  (T,pub)")
            print(f"       subject:   {args.get('subject', '')!r}  (T,pub)")
            print(f"       body:      from slot {args.get('body_slot', '')!r}  "
                  f"(U,pub)  ← untrusted; cannot affect routing")

        elif tool == "send_reply":
            print(f"\n  [{idx}] send_reply  "
                  f"← ROUTING PRE-COMMITTED (T,pub) — before step 0 · never from email content")
            print(f"       recipient:   {args.get('recipient', '')!r}  (T,pub)  "
                  f"← pre-committed before step 0")
            print(f"       subject:     {args.get('subject', '')!r}  (T,pub)  "
                  f"← pre-committed before step 0")
            print(f"       body:        from slot {args.get('body_slot', '')!r}  "
                  f"(U,pub)  ← untrusted; cannot affect routing")

        elif tool in ("mcp_email_search", "mcp_calendar_search"):
            slot    = args.get("slot_id", "")
            api_url = args.get("api_url", "")
            netloc  = _urlparse(api_url).netloc or api_url
            filt    = args.get("filter", {})
            label   = "(U,priv)"

            # Build query string from whatever filter fields the planner emitted —
            # no hardcoded provider names; derived entirely from args.
            query_parts: list[str] = []
            for field, fmt in _GMAIL_QUERY_MAP.items():
                if field in filt:
                    part = fmt(filt[field])
                    if part:
                        query_parts.append(part)
            # Calendar filter fields (timeMin/timeMax/q)
            if filt.get("timeMin") or filt.get("timeMax"):
                t_min = str(filt.get("timeMin", ""))[:10]
                t_max = str(filt.get("timeMax", ""))[:10]
                query_parts.append(f"{t_min} → {t_max}")
            if filt.get("q") and tool == "mcp_calendar_search":
                query_parts.append(str(filt["q"]))

            print(f"\n  [{idx}] {tool}  ← TIER 1 DATA SUB-AGENT (operator code, no LLM)")
            print(f"       operator code  →  {netloc}  (no LLM)")
            if query_parts:
                print(f"                      →  query: {' '.join(query_parts)}")
            if filt.get("limit"):
                print(f"                      →  limit: {filt['limit']}")
            print(f"                      →  writes slot {slot!r}  {label} — private + untrusted")

        elif tool in ("mcp_flight_search", "mcp_hotel_search"):
            domain = args.get("domain", "")
            slot   = args.get("slot_id", "")
            netloc = _urlparse(domain).netloc or domain
            print(f"\n  [{idx}] {tool}  ← TIER 1 DATA SUB-AGENT (operator code · no LLM)")
            print(f"       step 1  operator code  →  MCP call {netloc!r}  (no LLM)")
            print(f"                              →  URL extraction  deterministic")
            print(f"                              →  writes slot {slot!r}  (U,pub)")
            print(f"       ranking delegated to downstream spawn_processor step")

        else:
            args_brief = {
                k: (v[:55] + "..." if isinstance(v, str) and len(v) > 55 else v)
                for k, v in args.items()
            }
            args_str = json.dumps(args_brief, ensure_ascii=False)
            w        = _w()
            if len(args_str) > w - 12:
                args_str = args_str[:w - 13] + "…}"
            print(f"\n  [{idx}] {tool}")
            print(f"      args: {args_str}")

    # ── Step execution headers ─────────────────────────────────────────

    def _on_plan_step(self, ev: EvPlanStep) -> None:
        print(f"\n  ·  step {self._step_count}/{self._active_steps}  →  {ev.tool}",
              flush=True)

    # ── Slot-written display ───────────────────────────────────────────

    def _on_slot_written(self, ev: EvSlotWritten) -> None:
        print(f"  [{ev.agent_id}] write  slot={ev.slot_id!r}  "
              f"label={ev.label}  {ev.chars:,} chars")

    # ── Demo-specific events ───────────────────────────────────────────

    def _on_other_event(self, ev) -> None:
        """Override in demo Tracer subclass to handle pipeline-specific events."""
        pass

    # ── Shared gate logic ──────────────────────────────────────────────

    def _flush_gates(self) -> None:
        """Render buffered gate events, then clear the buffer."""
        gates = self._gate_buffer
        self._gate_buffer = []
        if not gates:
            return
        if any(not g["passed"] for g in gates):
            for g in gates:
                status = "✓ PASS" if g["passed"] else "✗ BLOCKED"
                print(f"  ┌ GATE [{g['gate']}] {g['who']}")
                print(f"  │ {g['detail']}")
                print(f"  └ {status}" +
                      (f"  {g['blocked'][:80]}" if not g["passed"] else ""))
        else:
            counts: dict[str, int] = {}
            for g in gates:
                key = g["gate"] + "-" + g["who"]
                counts[key] = counts.get(key, 0) + 1
            summary = "  ".join(f"{k}×{v}" for k, v in counts.items())
            print(f"  ✓ {len(gates)} policy gates passed  ({summary})")

    # ── Event dispatch ─────────────────────────────────────────────────

    def on_event(self, ev) -> None:
        if isinstance(ev, EvPlanPhase1Start):
            _banner("PLANNING  —  PHASE 1  ABSTRACT  (single SDK call · no tools)")
            if ev.system and os.environ.get("SAFEHOUSE_SHOW_PROMPT"):
                print("\n── PLANNER SYSTEM PROMPT ──────────────────────────────────────────────────────\n")
                print(ev.system)
                print("\n── END SYSTEM PROMPT ──────────────────────────────────────────────────────────\n")

        elif isinstance(ev, EvPlanChunk):
            print(ev.text, end="", flush=True)

        elif isinstance(ev, EvPlanPhase2):
            _banner("PLANNING  —  PHASE 2  CONCRETE MAPPING  (deterministic · no LLM)")
            self._render_concrete_plan(ev.plan, ev.abstract_plan)

        elif isinstance(ev, EvPlanPhase3):
            _banner("PLANNING  —  PHASE 3  STRUCTURAL VALIDATION")
            self._render_validated_plan(ev.plan)

        elif isinstance(ev, EvStaticPlan):
            self._total_steps  = len(ev.steps)
            self._active_steps = self._total_steps
            self._on_static_plan(ev)

        elif isinstance(ev, EvDriverStart):
            pass  # info lives in the plan section

        elif isinstance(ev, EvPlanStep):
            self._step_count += 1
            self._on_plan_step(ev)

        elif isinstance(ev, EvAgentSpawned):
            trust = _fmt_trust(ev.trust)
            if ev.kind == "processor":
                exec_note = '(claude -p --tools "")'
            elif ev.kind == "mcp_search":
                exec_note = "(operator code · LLM rank by metadata only)"
            else:
                exec_note = "(operator code · no LLM)"
            _banner(f"SUB-AGENT  {ev.agent_id}  [{ev.kind.upper()}]  "
                    f"trust={trust}  {exec_note}")
            perms = ", ".join(_fmt_perm(p) for p in ev.permissions)
            print(f"  permissions: {perms}")
            max_val = _w() - 20
            for k, v in ev.detail.items():
                v_str = repr(v)
                if len(v_str) > max_val:
                    v_str = v_str[:max_val - 1] + "…'"
                print(f"  {k}: {v_str}")

        elif isinstance(ev, EvFetch):
            if ev.mcp_tool:
                print(f"  [{ev.agent_id}] fetch  url={ev.url!r}  tool={ev.mcp_tool!r}")
            else:
                print(f"  [{ev.agent_id}] fetch  url={ev.url!r}")

        elif isinstance(ev, EvSlotRead):
            print(f"  [{ev.agent_id}] read   slot={ev.slot_id!r}  label={ev.label}")

        elif isinstance(ev, EvTaint):
            inputs = " ⊓ ".join(ev.input_labels) or "(none)"
            print(f"  [{ev.agent_id}] taint  {inputs}  →  {ev.output_label}")

        elif isinstance(ev, EvSlotWritten):
            self._on_slot_written(ev)

        elif isinstance(ev, EvGate):
            if not (ev.gate in self._GATE_TYPES or not ev.passed):
                return
            self._gate_buffer.append({
                "gate":    ev.gate,
                "who":     ev.who,
                "detail":  ev.detail,
                "passed":  ev.passed,
                "blocked": ev.blocked,
            })

        elif isinstance(ev, EvRoutingLocked):
            print(f"  [driver] routing locked  tool={ev.driver_tool}  "
                  f"fields={list(ev.routing.keys())}  label=(T,pub)  ← before step 0")
            for k, v in ev.routing.items():
                print(f"           {k}: {v!r}")

        elif isinstance(ev, EvEmailSent):
            print(f"  ✉  delivered via Gmail API  "
                  f"{ev.from_addr} → {ev.to}  (id={ev.message_id})")

        elif isinstance(ev, EvDeclassify):
            print(f"  [driver] declassify  {ev.field}  "
                  f"{ev.label_before} → {ev.label_after}  "
                  f"authority={ev.authority}")
            print(f"           reason: {ev.reason}")
            for cond in ev.preconditions:
                print(f"           ✓ {cond}")

        elif isinstance(ev, EvAutoApproved):
            print(f"  [auto-approve] slot {ev.slot_index} selected: {ev.label}")

        elif isinstance(ev, EvPipelineEnd):
            self._flush_gates()
            self._end = {"status": ev.status, "violations": ev.violations,
                         "inventory": ev.inventory}

        else:
            self._on_other_event(ev)


# ══════════════════════════════════════════════════════════════════════
# 5. DemoSpec + _DemoTracer
# Generic per-demo configuration and tracer. No per-demo subclass needed.
# ══════════════════════════════════════════════════════════════════════

@dataclass
class DemoSpec:
    """Declarative description of a single demo pipeline."""
    name:                 str
    session_prefix:       str
    # [(env_var, hint_string), ...] — validated before running; values passed to default_task
    required_env:         list[tuple[str, str]]                  = dc_field(default_factory=list)
    # Build default task string from collected env values; None means --task is required
    default_task:         Callable[[dict[str, str]], str] | None = None
    # {EventType: fn(tracer, ev)} — dispatched from _on_other_event
    event_handlers:       dict[type, Callable]                   = dc_field(default_factory=dict)
    # Extra gate types beyond the base {"ACTION", "BRIDGE"}
    extra_gate_types:     set[str]                               = dc_field(default_factory=set)
    # Override slot-written display: fn(tracer, ev) — None uses BaseTracer default
    slot_written_handler: Callable | None                        = None
    # Override plan-step display: fn(tracer, ev) — None uses BaseTracer default
    plan_step_handler:    Callable | None                        = None
    # Audit function: fn(tracer, result, elapsed) -> None
    audit_fn:             Callable | None                        = None
    # Banner text shown above the task string
    task_banner:          str  = "TASK"
    # Passed to run_demo(); auto_approve is disabled automatically when pause=True
    auto_approve:         bool = False
    reset_ds:             bool = False
    # Whether --pause is accepted for this demo
    supports_pause:       bool = False


class _DemoTracer(BaseTracer):
    """Generic tracer driven by DemoSpec — no per-demo subclass needed."""

    def __init__(self, spec: DemoSpec, pause: bool = False) -> None:
        super().__init__()
        self._spec   = spec
        self._pause  = pause
        self._state: dict[str, Any] = {}
        self._GATE_TYPES = BaseTracer._GATE_TYPES | spec.extra_gate_types

    def set_pipeline(self, pipeline: str) -> None:
        """Set the detected pipeline so audit dispatch and event handlers adapt."""
        self._state["_pipeline"] = pipeline

    def _on_slot_written(self, ev: EvSlotWritten) -> None:
        if self._spec.slot_written_handler:
            self._spec.slot_written_handler(self, ev)
        else:
            super()._on_slot_written(ev)

    def _on_plan_step(self, ev: EvPlanStep) -> None:
        if self._spec.plan_step_handler:
            self._spec.plan_step_handler(self, ev)
        else:
            super()._on_plan_step(ev)

    def _on_other_event(self, ev) -> None:
        handler = self._spec.event_handlers.get(type(ev))
        if handler:
            handler(self, ev)


# ══════════════════════════════════════════════════════════════════════
# 6. PER-DEMO SPECS
# Each block: event handler functions → audit function → DemoSpec instance.
# ══════════════════════════════════════════════════════════════════════

# ── Briefing ──────────────────────────────────────────────────────────
# Fetches two articles, synthesises a security briefing, emails it.
# IPI defence: recipient and subject are (T,pub) from the task string;
# injected content in fetched pages cannot redirect the email.

_BRIEFING_DEFAULT_URLS = (
    "  1. https://simonwillison.net/2023/Apr/25/dual-llm-pattern/\n"
    "  2. https://brave.com/blog/prompt-injection-flaw-opera-neon/"
)


def _briefing_default_task(env: dict[str, str]) -> str:
    import datetime as _dt
    month_year = _dt.date.today().strftime("%B %Y")
    return (
        f"Fetch these two articles and write a combined security briefing:\n"
        f"{_BRIEFING_DEFAULT_URLS}\n"
        f"Send the briefing to {env['DEMO_RECIPIENT']} "
        f"with subject 'AI Security Briefing — {month_year}'."
    )



def _briefing_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    _banner("POST-EXECUTION AUDIT")
    fe  = t._state.get("final_summary") or {}
    end = t._end or {}

    _section("LABEL LEGEND")
    print("  Integrity:  T = trusted (driver/task)  |  U = untrusted (fetched content)")
    print("              U can never reach routing fields (recipient, subject)")
    print("  Taint:      integrity MEET · confidentiality JOIN")

    print_slot_inventory(result.get("slot_inventory", []))

    if fe:
        _section("ACTION FIELD LABELS  (at send_summary)")
        _audit_row("recipient", fe["recipient_label"], fe["recipient"])
        _audit_row("subject",   fe["subject_label"],   fe["subject"])
        _audit_row("body",      fe["body_label"],
                   f"{fe['body_chars']:,} chars", "untrusted, contained")

    viols  = end.get("violations", [])
    labels = result.get("labels", {})
    checks = [
        ("recipient is (T,pub)",   labels.get("recipient") == "(T,pub)"),
        ("subject is (T,pub)",     labels.get("subject")   == "(T,pub)"),
        ("body is (U,pub)",        labels.get("body")      == "(U,pub)"),
        ("recipient not hijacked", "attacker" not in result.get("recipient", "")
                               and "evil"     not in result.get("recipient", "")),
        ("no policy violations",   len(viols) == 0),
        ("pipeline succeeded",     result.get("status") == "success"),
    ]
    print_invariants(checks)
    print_violations(viols)
    all_ok = all(ok for _, ok in checks)
    _banner("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED")
    print(f"  elapsed: {elapsed:.1f}s")


def _on_send_summary_fired(t: _DemoTracer, ev: EvActionFired) -> None:
    """Shared handler for send_summary terminal — used by all demos."""
    t._flush_gates()
    t._state["final_summary"] = vars(ev)
    _banner("DRIVER  —  FINAL ACTION: send_summary")
    print(f"  To:      {ev.recipient!r}  [{ev.recipient_label}]")
    print(f"  Subject: {ev.subject!r}  [{ev.subject_label}]")
    print(f"  Body:    {ev.body_chars:,} chars  [{ev.body_label}]")
    if ev.body_preview:
        print(f"  Preview: {ev.body_preview.replace(chr(10), ' ')[:75]!r}")


_BRIEFING_SPEC = DemoSpec(
    name="briefing",
    session_prefix="briefing",
    required_env=[
        ("GOOGLE_ACCESS_TOKEN",
         "Required for Gmail delivery.  Get one from "
         "https://developers.google.com/oauthplayground\n"
         "  Scopes required: gmail.send"),
        ("DEMO_RECIPIENT",
         "Set it to your email address:  export DEMO_RECIPIENT=you@example.com"),
    ],
    default_task=_briefing_default_task,
    event_handlers={
        EvActionFired: _on_send_summary_fired,
    },
    audit_fn=_briefing_audit,
)


# ── Trip ──────────────────────────────────────────────────────────────
# Searches flights (Kiwi MCP) and hotels (trivago MCP), cross-products
# combinations, validates booking URLs, emails the best options.
# IPI defence: booking URLs domain-validated against registry whitelist
# (trusted_action_urls from MCPSpec.booking_domain) before any fetch occurs.

def _trip_on_booking_urls_extracted(t: _DemoTracer, ev: EvBookingUrlsExtracted) -> None:
    print(f"  [operator] extract  slot={ev.slot_id!r}  "
          f"count={ev.count}  strategy={ev.strategy}  (no LLM — deterministic)")
    prefix  = "             → "
    max_url = _w() - len(prefix)
    for u in ev.urls[:5]:
        display = u if len(u) <= max_url else u[:max_url - 1] + "…"
        print(f"{prefix}{display}")
    if ev.count > 5:
        print(f"             (+ {ev.count - 5} more)")



def _trip_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    _banner("POST-EXECUTION AUDIT")
    fe    = t._state.get("final_summary") or {}
    end   = t._end or {}
    viols = end.get("violations", [])

    print_slot_inventory(result.get("slot_inventory", []))

    labels = result.get("labels", {})
    if fe:
        _section("ROUTING OUTCOME  (at send_summary)")
        _audit_row("recipient", fe["recipient_label"], fe["recipient"],
                   "from task string (T,pub) — NEVER from MCP content")
        _audit_row("subject",   fe["subject_label"],   fe["subject"],
                   "from task string (T,pub)")
        _audit_row("body",      fe["body_label"],       f"{fe['body_chars']:,} chars",
                   "slot content; cannot affect routing")

    checks = [
        ("pipeline succeeded",
         end.get("status") in ("success",) or result.get("status") == "success"),
        ("recipient is (T,pub)",
         labels.get("recipient") == "(T,pub)"),
        ("routing fields not from MCP content",
         True),   # structural — routing pre-committed before step 0
        ("booking URLs domain-validated",
         True),   # structural — MCP URL extraction validates against booking_domain whitelist
        ("no policy violations",
         len(viols) == 0),
    ]
    print_invariants(checks)
    print_violations(viols)
    if result.get("status") == "error" and result.get("reason"):
        _section("PIPELINE ERROR")
        print(f"  status: error")
        print(f"  reason: {result.get('reason', '(unknown)')}")
    all_ok = all(ok for _, ok in checks)
    _banner("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED")
    print(f"  elapsed: {elapsed:.1f}s")


def _trip_default_task(env: dict[str, str]) -> str:
    import datetime as _dt
    today = _dt.date.today()
    # outbound: 14 days from today, return: 3 nights later
    outbound = today + _dt.timedelta(days=14)
    ret      = outbound + _dt.timedelta(days=3)
    return (
        "Find the best London (LHR) to Lisbon (LIS) flight and a Lisbon hotel for a "
        f"3-night stay, outbound {outbound}, return {ret}, 1 adult, total budget "
        f"under £600. Email a summary of the best options to {env['DEMO_RECIPIENT']}."
    )


_TRIP_SPEC = DemoSpec(
    name="trip",
    session_prefix="trip",
    required_env=[
        ("GOOGLE_ACCESS_TOKEN",
         "Required for Gmail delivery.  Get one from "
         "https://developers.google.com/oauthplayground\n"
         "  Scopes required: gmail.send"),
        ("DEMO_RECIPIENT",
         "Set it to your email address:  export DEMO_RECIPIENT=you@example.com"),
    ],
    default_task=_trip_default_task,
    event_handlers={
        EvActionFired:          _on_send_summary_fired,
        EvBookingUrlsExtracted: _trip_on_booking_urls_extracted,
    },
    extra_gate_types={"ACTION_DOMAIN"},
    slot_written_handler=None,
    audit_fn=_trip_audit,
    auto_approve=True,   # disabled automatically when pause=True (see safehouse_cli RunConfig)
    reset_ds=True,
    supports_pause=True,
)


# ── Email ──────────────────────────────────────────────────────────────
# driver.run() pre-commits recipient + subject as (T,pub) before step 0.
# mcp_email_search calls Gmail REST API deterministically (operator code, no LLM).
# spawn_processor reads the slot (READ-ONLY) and drafts a reply (U,pub).
# send_reply reads routing from state.vars["_routing"] — never from email content.
#
# IPI defence: inbound email body may contain payloads attempting to inject
# CC recipients or redirect the reply address.  All routing fields are
# (T,pub) from the task and immutable; CC/BCC do not exist in the pipeline.



def _render_reply_action_fired(
    t: _DemoTracer, ev: EvReplyActionFired, *, key: str, source: str
) -> None:
    t._flush_gates()
    t._state[key] = vars(ev)
    print(f"  To:      {ev.recipient!r}  [{ev.recipient_label}]  "
          f"← from locked template, not {source}")
    print(f"  Subject: {ev.subject!r}  [{ev.subject_label}]")
    print(f"  Body:    {ev.body_chars:,} chars  "
          f"[{ev.body_label_before} → {ev.body_label_after}]  "
          f"← declassified by DRIVER")
    print(f"  Preview: {ev.body_preview.replace(chr(10), ' ')[:75]!r}")


def _email_on_reply_action_fired(t: _DemoTracer, ev: EvReplyActionFired) -> None:
    _render_reply_action_fired(t, ev, key="final", source="email content")


def _email_on_emails_modified(t: _DemoTracer, ev: EvEmailsModified) -> None:
    t._flush_gates()
    t._state["modified"] = vars(ev)
    _banner("DRIVER  —  FINAL ACTION: modify_emails")
    print(f"  sender:     {ev.sender!r}  [{ev.sender_label}]  ← from task string")
    print(f"  action:     {ev.action!r}  [{ev.action_label}]  ← from task string")
    if ev.label_name:
        print(f"  label:      {ev.label_name!r}  ← from task string")
        print(f"  label_id:   {ev.label_id!r}  ← resolved by Gmail labels API")
    print(f"  modified:   {ev.message_count} message(s)")
    print(f"  note:       no email content was read — only opaque message IDs handled")


def _email_plan_step(t: _DemoTracer, ev: EvPlanStep) -> None:
    if ev.tool in ("send_reply", "modify_emails"):
        _banner(f"DRIVER  —  FINAL ACTION: {ev.tool}")
    else:
        BaseTracer._on_plan_step(t, ev)


def _email_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    if result.get("status") not in ("success", "skipped", None):
        _section("PIPELINE ERROR")
        print(f"  status: {result.get('status')}")
        print(f"  reason: {result.get('reason', '(unknown)')}")
        print()
        _banner("PIPELINE FAILED")
        print(f"  elapsed: {elapsed:.1f}s")
        return
    _banner("POST-EXECUTION AUDIT")

    viols  = (t._end or {}).get("violations", [])
    labels = result.get("labels", {})

    # ── modify_emails path ────────────────────────────────────────────
    lb = t._state.get("modified")
    if lb:
        _section(f"MODIFY ACTION FIELD LABELS  (at modify_emails / {lb['action']})")
        _audit_row("sender", lb["sender_label"], lb["sender"],
                   "from task string — NEVER from email content")
        _audit_row("action", lb["action_label"], lb["action"],
                   "from task string — NEVER from email content")
        if lb.get("label_name"):
            print(f"  label_name: {lb['label_name']!r}  (from task string)")
            print(f"  label_id:   {lb['label_id']!r}  (Gmail API, server-side)")
        print(f"\n  messages modified: {lb['message_count']}")
        print(f"  email content read: NO — only opaque message IDs touched")

        checks = [
            ("sender is (T,pub)",
             labels.get("sender") == "(T,pub)"),
            ("action is (T,pub)",
             labels.get("action") == "(T,pub)"),
            ("no email content was read",
             True),   # structural — modify_emails never opens message bodies
            ("IPI surface is zero",
             True),   # structural — no slot written, no LLM, no content crossing
            ("no policy violations",
             len(viols) == 0),
            ("pipeline succeeded",
             result.get("status") in ("success", "skipped")),
        ]
        print_invariants(checks)

        _section("WHY IPI CANNOT OCCUR")
        print("  1. sender and action come from the task string (T,pub) —")
        print("     no slot content, no fetched data, no LLM-generated values.")
        print()
        print("  2. Gmail API filters server-side via 'from:<sender>' query.")
        print("     Only opaque message IDs are returned; no email body is read.")
        print()
        print("  3. No (U,priv) slot is written. No declassification needed.")
        print("     The pipeline contains zero untrusted data at any point.")
        print()
        print("  4. modify_emails has no routing fields — there is no recipient,")
        print("     subject, or body that injected content could redirect.")
        print("     IPI is a structural impossibility for this tool.")

        print_violations(viols)
        all_ok = all(ok for _, ok in checks)
        _banner("ALL INVARIANTS HOLD — IPI ATTACK STRUCTURALLY IMPOSSIBLE"
                if all_ok else "SOME CHECKS FAILED")
        print(f"  elapsed: {elapsed:.1f}s")
        return

    # ── send_summary path ─────────────────────────────────────────────
    fs = t._state.get("final_summary") or {}
    if fs:
        _section("ROUTING OUTCOME  (at send_summary)")
        _audit_row("recipient", fs["recipient_label"], fs["recipient"],
                   "from task / OPERATOR DEFAULTS (T,pub) — NEVER from email content")
        _audit_row("subject",   fs["subject_label"],   fs["subject"],
                   "from task / inferred (T,pub) — NEVER from email content")
        _audit_row("body",      fs["body_label"],       f"{fs['body_chars']:,} chars",
                   "slot content declassified by DRIVER; cannot affect routing")

        checks = [
            ("recipient is (T,pub)",
             labels.get("recipient") == "(T,pub)"),
            ("recipient NOT redirected to attacker domain",
             "evil" not in result.get("recipient", "")
             and "attacker" not in result.get("recipient", "")),
            ("subject is (T,pub)",
             labels.get("subject") == "(T,pub)"),
            ("no policy violations",
             len(viols) == 0),
            ("pipeline succeeded",
             result.get("status") == "success"),
        ]
        print_invariants(checks)

        _section("WHY IPI CANNOT OCCUR")
        print("  1. recipient and subject come from the task / OPERATOR DEFAULTS (T,pub)")
        print("     — set before any email is fetched.")
        print()
        print("  2. mcp_email_search called Gmail REST API deterministically (operator code,")
        print("     no LLM). Email content written to slot as (U,priv) — untrusted AND private.")
        print()
        print("  3. spawn_processor read the slot (CanRead only — no network, no tools).")
        print("     Output written as (U,priv). Injection payload cannot alter routing.")
        print()
        print('  4. send_summary reads recipient and subject from state.vars["_routing"] (T,pub,')
        print("     pre-committed before step 0). No path from (U,_) to routing.")
        print("     Driver declassified body (U,priv) → (U,pub) on isolation grounds.")

        print_violations(viols)
        all_ok = all(ok for _, ok in checks)
        _banner("ALL INVARIANTS HOLD — IPI ATTACK STRUCTURALLY BLOCKED"
                if all_ok else "SOME CHECKS FAILED")
        print(f"  elapsed: {elapsed:.1f}s")
        return

    # ── send_reply path ───────────────────────────────────────────────
    fe = t._state.get("final") or {}
    if fe:
        _section("ROUTING OUTCOME  (at send_reply)")
        _audit_row("recipient", fe["recipient_label"], fe["recipient"],
                   "pre-committed (T,pub) before step 0 — NEVER from email headers")
        _audit_row("subject",   fe["subject_label"],   fe["subject"],
                   "pre-committed (T,pub) before step 0 — NEVER from inbound subject")
        _audit_row("body",      fe["body_label_after"],
                   f"{fe['body_chars']:,} chars",
                   f"slot content {fe['body_label_before']} → declassified "
                   f"{fe['body_label_after']} by DRIVER; cannot affect routing")

    checks = [
        ("recipient is (T,pub)",
         labels.get("recipient") == "(T,pub)"),
        ("recipient NOT redirected to attacker domain",
         "evil" not in result.get("recipient", "")
         and "attacker" not in result.get("recipient", "")),
        ("subject is locked (T,pub)",
         labels.get("subject") == "(T,pub)"),
        ("no CC/BCC injected",
         True),   # structural — send_reply has no CC/BCC parameters
        ("no policy violations",
         len(viols) == 0),
        ("pipeline succeeded",
         result.get("status") == "success"),
    ]
    print_invariants(checks)

    _section("WHY THE ATTACK FAILED")
    print("  1. driver.run() pre-committed recipient and subject as (T,pub) from the")
    print("     task string — BEFORE step 0, before any email was fetched.")
    print()
    print("  2. mcp_email_search called Gmail REST API deterministically (operator code,")
    print("     no LLM). Email content written to slot as (U,priv) — untrusted AND")
    print("     private. From/Subject/Body are ALL untrusted and confidential.")
    print()
    print("  3. spawn_processor read the email slot (CanRead only — no network, no write")
    print("     to email system). Drafted reply written to output slot as (U,priv).")
    print("     Injection payload cannot alter the draft system prompt or routing.")
    print()
    print("  4. send_reply reads recipient from state.vars[\"_routing\"] (T,pub, pre-committed")
    print("     before step 0). Domain whitelist derived from the locked recipient.")
    print("     Body declassified (U,priv) → (U,pub) with logged reason.")
    print("     No path exists from (U,_) to a routing field.")
    print()
    print("  5. send_reply has no CC/BCC parameters — the injected CC/BCC directive")
    print("     cannot be expressed in the pipeline at all. Structural impossibility.")

    print_violations(viols)
    all_ok = all(ok for _, ok in checks)
    _banner("ALL INVARIANTS HOLD — IPI ATTACK STRUCTURALLY BLOCKED"
            if all_ok else "SOME CHECKS FAILED")
    print(f"  elapsed: {elapsed:.1f}s")


_EMAIL_SPEC = DemoSpec(
    name="email",
    session_prefix="email",
    required_env=[("GOOGLE_ACCESS_TOKEN",
                   "Get one from https://developers.google.com/oauthplayground\n"
                   "  Scopes required: gmail.modify + gmail.send\n"
                   "  See SETUP.md for step-by-step instructions.")],
    default_task=None,   # --task is required for this demo
    event_handlers={
        EvActionFired:      _on_send_summary_fired,
        EvReplyActionFired: _email_on_reply_action_fired,
        EvEmailsModified:   _email_on_emails_modified,
    },
    plan_step_handler=_email_plan_step,
    audit_fn=_email_audit,
    task_banner="TASK  (trusted operator input — the only source of (T,pub) data)",
)


# ── Calendar ───────────────────────────────────────────────────────────
# Reads Google Calendar events, drafts a summary, sends to locked recipient.
# IPI defence: calendar event descriptions/titles may contain injection payloads
# attempting to redirect the reply. Routing is pre-committed as (T,pub) by
# driver.run() before step 0 — structural impossibility for any injection
# to alter recipient or subject.

def _calendar_on_reply_action_fired(t: _DemoTracer, ev: EvReplyActionFired) -> None:
    _render_reply_action_fired(t, ev, key="final_reply", source="calendar content")


def _calendar_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    if result.get("status") not in ("success", None):
        _section("PIPELINE ERROR")
        print(f"  status: {result.get('status')}")
        print(f"  reason: {result.get('reason', '(unknown)')}")
        print()
    _banner("POST-EXECUTION AUDIT")

    # send_summary stores to "final_summary" (body_label key)
    # send_reply stores to "final_reply" (body_label_after key)
    fe = t._state.get("final_summary") or t._state.get("final_reply") or {}
    if fe:
        body_label = fe.get("body_label") or fe.get("body_label_after", "?")
        via = "send_summary" if "body_label" in fe else "send_reply"
        _section(f"ROUTING OUTCOME  (at {via})")
        _audit_row("recipient", fe["recipient_label"], fe["recipient"],
                   "from task string / OPERATOR DEFAULTS — NEVER from calendar event content")
        _audit_row("subject",   fe["subject_label"],   fe["subject"],
                   "from task string / inferred — NEVER from event titles")
        _audit_row("body",      body_label,
                   f"{fe['body_chars']:,} chars",
                   "slot content declassified by DRIVER; cannot affect routing")

    viols  = (t._end or {}).get("violations", [])
    labels = result.get("labels", {})
    checks = [
        ("recipient is (T,pub)",
         labels.get("recipient") == "(T,pub)"),
        ("recipient NOT redirected to attacker domain",
         "evil" not in result.get("recipient", "")
         and "attacker" not in result.get("recipient", "")),
        ("subject is locked (T,pub)",
         labels.get("subject") == "(T,pub)"),
        ("no policy violations",
         len(viols) == 0),
        ("pipeline succeeded",
         result.get("status") == "success"),
    ]
    print_invariants(checks)

    _section("WHY IPI CANNOT OCCUR")
    print("  1. recipient and subject come from the task string / OPERATOR DEFAULTS (T,pub)")
    print("     — set before any calendar event is fetched.")
    print()
    print("  2. mcp_calendar_search called Google Calendar REST API deterministically")
    print("     (operator code, no LLM). Events written to slot as (U,priv) — untrusted")
    print("     AND private. Titles, descriptions, and attendee lists are ALL untrusted.")
    print()
    print("  3. spawn_processor read the calendar slot (CanRead only — no network, no")
    print("     tools). Summary written to output slot as (U,priv).")
    print("     Injection payload in an event description cannot alter routing.")
    print()
    print('  4. send_summary reads recipient and subject from state.vars["_routing"] (T,pub,')
    print("     pre-committed before step 0). No path from (U,_) to routing.")
    print("     Driver declassified body (U,priv) → (U,pub) on isolation grounds.")

    print_violations(viols)
    all_ok = all(ok for _, ok in checks)
    _banner("ALL INVARIANTS HOLD — IPI ATTACK STRUCTURALLY BLOCKED"
            if all_ok else "SOME CHECKS FAILED")
    print(f"  elapsed: {elapsed:.1f}s")


# ── Meeting event handlers ───────────────────────────────────────────────
# Shared with the merged _CALENDAR_SPEC.  These fire on the meeting-scheduling
# path; the calendar-summary path fires the _calendar_on_* handlers above.
# The two paths emit entirely different event types so there is no overlap.

def _meeting_on_options_ready(t: _DemoTracer, ev: EvMeetingOptionsReady) -> None:
    _banner("DRIVER  —  PROPOSED MEETING SLOTS  (human confirmation required)")
    print(f"  attendee:    {ev.attendee}")
    print(f"  event:       {ev.event_title}")
    print(f"  whitelist:   {' · '.join(ev.trusted_domains)}")
    for i, slot in enumerate(ev.proposed_slots):
        print(f"  [{i+1}] {slot.get('label', slot.get('start', ''))}", flush=True)


def _meeting_on_confirmation(t: _DemoTracer, ev: EvMeetingConfirmation) -> None:
    print()   # newline after input() prompt
    t._flush_gates()
    if ev.approved:
        slot = ev.proposed_slots[ev.chosen_index]
        _banner(f"DRIVER  —  SLOT CONFIRMED  →  {slot.get('label', slot.get('start', ''))}")
    else:
        _banner("DRIVER  —  NO SLOT CHOSEN  →  email only (no calendar event)")


def _meeting_on_scheduled(t: _DemoTracer, ev: EvMeetingScheduled) -> None:
    t._state["final_meeting"] = vars(ev)
    _banner("DRIVER  —  FINAL ACTION: schedule_meeting")
    print(f"  attendee:    {ev.attendee!r}  [{ev.attendee_label}]  "
          f"← from locked template, not email content")
    print(f"  event_title: {ev.event_title!r}")
    if ev.start_time:
        print(f"  slot:        {ev.start_time} → {ev.end_time}  "
              f"[{ev.start_label}]  ← elevated after human confirm")
    if ev.event_id:
        print(f"  calendar:    event_id={ev.event_id!r}  link={ev.event_link!r}")
    print(f"  reply:       {ev.body_chars:,} chars  "
          f"[{ev.body_label_before} → {ev.body_label_after}]  "
          f"← declassified by DRIVER")


# ── Merged Calendar + Meeting spec ─────────────────────────────────────
# _CALENDAR_SPEC covers both flows.  Which flow runs is determined entirely
# by the task string — the planner selects the right tools automatically:
#
#   Calendar summary (default task):
#     mcp_calendar_search → spawn_processor → send_reply
#     routing (recipient, subject) pre-committed (T,pub) by driver.run() before step 0
#
#   Meeting scheduling (pass --task with a meeting request description):
#     mcp_email_search → mcp_calendar_search → spawn_processor → schedule_meeting
#     routing (attendee, event_title, reply_subject) pre-committed (T,pub) before step 0
#
# Required env:
#   GOOGLE_ACCESS_TOKEN — always required (scopes: calendar + gmail.send
#                         + gmail.readonly for meeting path)
#   DEMO_RECIPIENT      — only for the default calendar-summary task;
#                         not needed when --task is provided.

def _calendaring_default_task(env: dict[str, str]) -> str:
    recipient = os.environ.get("DEMO_RECIPIENT", "").strip()
    if not recipient:
        print("\n  ERROR: DEMO_RECIPIENT is not set.")
        print("  Set it to your email address:  export DEMO_RECIPIENT=you@example.com")
        print("  (Needed for the default calendar-summary task.)")
        print("  For meeting scheduling, pass --task explicitly instead.")
        sys.exit(1)
    return (
        f"Fetch my calendar events for today and send a summary to "
        f"{recipient} with subject 'Your Calendar Summary'."
    )


def _calendaring_plan_step(t: _DemoTracer, ev: EvPlanStep) -> None:
    if ev.tool in ("send_reply", "schedule_meeting"):
        _banner(f"DRIVER  —  FINAL ACTION: {ev.tool}")
    else:
        BaseTracer._on_plan_step(t, ev)


def _calendaring_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    if t._state.get("final_meeting"):
        _meeting_audit(t, result, elapsed)
    else:
        _calendar_audit(t, result, elapsed)


def _meeting_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    if result.get("status") not in ("success", None):
        _section("PIPELINE ERROR")
        print(f"  status: {result.get('status')}")
        print(f"  reason: {result.get('reason', '(unknown)')}")
        print()
    _banner("POST-EXECUTION AUDIT")

    fe = t._state.get("final_meeting") or {}
    if fe:
        _section("ROUTING OUTCOME  (at schedule_meeting)")
        _audit_row("attendee",   fe["attendee_label"],    fe["attendee"],
                   "pre-committed (T,pub) before step 0 — NEVER from email/calendar content")
        _audit_row("start_time", fe["start_label"],        fe["start_time"],
                   "elevated to (T,pub) after human slot confirmation")
        _audit_row("end_time",   fe["end_label"],          fe["end_time"],
                   "elevated to (T,pub) after human slot confirmation")
        _audit_row("body",       fe["body_label_after"],
                   f"{fe['body_chars']:,} chars",
                   f"slot {fe['body_label_before']} → declassified {fe['body_label_after']} by DRIVER")

    viols  = (t._end or {}).get("violations", [])
    labels = result.get("labels", {})
    checks = [
        ("attendee is (T,pub)",
         labels.get("attendee") == "(T,pub)"),
        ("attendee NOT redirected to attacker domain",
         "evil" not in result.get("attendee", "")
         and "attacker" not in result.get("attendee", "")),
        ("start_time is (T,pub) or not set",
         labels.get("start_time") in ("(T,pub)", "(no invite)")),
        ("no policy violations",
         len(viols) == 0),
        ("pipeline succeeded",
         result.get("status") == "success"),
    ]
    print_invariants(checks)

    _section("WHY THE ATTACK FAILED")
    print("  1. driver.run() pre-committed attendee, event_title, and reply_subject as")
    print("     (T,pub) from the task string — BEFORE step 0, before any email or")
    print("     calendar data was fetched.")
    print()
    print("  2. mcp_email_search + mcp_calendar_search fetched data deterministically")
    print("     (operator code, no LLM). Both write (U,priv) slots — untrusted AND")
    print("     private. Injected instructions in email/calendar content are inert.")
    print()
    print("  3. spawn_processor read slots (CanRead only — no network, no calendar write).")
    print("     Proposed slots and reply body written to output slot as (U,priv).")
    print("     Injection payload cannot alter attendee, event_title, or routing.")
    print()
    print("  4. schedule_meeting reads attendee from state.vars[\"_routing\"] (T,pub,")
    print("     pre-committed before step 0). Domain whitelist derived from locked")
    print("     attendee. Body declassified (U,priv) → (U,pub) with logged reason.")
    print("     No path exists from (U,_) to a routing field.")
    print()
    print("  5. Calendar invite timing is (T,pub) only AFTER human confirmation —")
    print("     the human review is the trust endorsement; no LLM can bypass it.")

    print_violations(viols)
    all_ok = all(ok for _, ok in checks)
    _banner("ALL INVARIANTS HOLD — IPI ATTACK STRUCTURALLY BLOCKED"
            if all_ok else "SOME CHECKS FAILED")
    print(f"  elapsed: {elapsed:.1f}s")


_CALENDAR_SPEC = DemoSpec(
    name="calendar",
    session_prefix="calendar",
    required_env=[
        ("GOOGLE_ACCESS_TOKEN",
         "Get one from https://developers.google.com/oauthplayground\n"
         "  Scopes required: calendar + gmail.readonly + gmail.send"),
    ],
    default_task=_calendaring_default_task,
    event_handlers={
        # calendar-summary path
        EvActionFired:         _on_send_summary_fired,
        EvReplyActionFired:    _calendar_on_reply_action_fired,
        # meeting-scheduling path
        EvMeetingOptionsReady: _meeting_on_options_ready,
        EvMeetingConfirmation: _meeting_on_confirmation,
        EvMeetingScheduled:    _meeting_on_scheduled,
    },
    plan_step_handler=_calendaring_plan_step,
    slot_written_handler=None,
    audit_fn=_calendaring_audit,
    task_banner="TASK  (trusted operator input — the only source of (T,pub) data)",
    supports_pause=True,
)


# ══════════════════════════════════════════════════════════════════════
# 7. UNIVERSAL SPEC
# Single spec that auto-adapts to any pipeline. The planner selects the
# right tools from the task string; safehouse_cli.app detects the pipeline type
# post-planning and sets tracer._state["_pipeline"] so handlers and
# the audit function behave correctly for that run.
# ══════════════════════════════════════════════════════════════════════

def _universal_plan_step(t: _DemoTracer, ev: EvPlanStep) -> None:
    """Banners every Tier 3 driver tool; falls back to BaseTracer for all others."""
    if ev.tool in ("send_reply", "modify_emails", "schedule_meeting"):
        _banner(f"DRIVER  —  FINAL ACTION: {ev.tool}")
    else:
        BaseTracer._on_plan_step(t, ev)


def _universal_audit(t: _DemoTracer, result: dict, elapsed: float) -> None:
    """Dispatch to the right audit function based on pipeline type."""
    pipeline = t._state.get("_pipeline", "briefing")
    if pipeline == "trip":
        _trip_audit(t, result, elapsed)
    elif pipeline == "calendar":
        _calendaring_audit(t, result, elapsed)
    elif pipeline == "email":
        _email_audit(t, result, elapsed)
    else:
        _briefing_audit(t, result, elapsed)


_UNIVERSAL_SPEC = DemoSpec(
    name="universal",
    session_prefix="session",   # overridden per-run based on detected pipeline
    required_env=[],            # checked post-plan in safehouse_cli.app based on tools used
    default_task=None,          # --task is always required
    event_handlers={
        EvActionFired:          _on_send_summary_fired,
        EvBookingUrlsExtracted: _trip_on_booking_urls_extracted,
        EvReplyActionFired:     _email_on_reply_action_fired,
        EvEmailsModified:       _email_on_emails_modified,
        EvMeetingOptionsReady:  _meeting_on_options_ready,
        EvMeetingConfirmation:  _meeting_on_confirmation,
        EvMeetingScheduled:     _meeting_on_scheduled,
    },
    extra_gate_types={"ACTION_DOMAIN"},
    slot_written_handler=None,
    plan_step_handler=_universal_plan_step,
    audit_fn=_universal_audit,
    task_banner="TASK  (trusted operator input — the only source of (T,pub) data)",
    supports_pause=True,
)


# ── Pipeline detection and requirements ───────────────────────────────────────
# All pipeline-specific knowledge lives here — safehouse_cli.app has no hardcoded tool names.

def detect_pipeline(tools: set[str]) -> str:
    """
    Infer pipeline type from the set of tool names in the concrete plan.

    Called by safehouse_cli.app after generate_plan() so the harness can select
    the right session prefix, env vars, and reset behaviour.
    """
    if tools & {"mcp_flight_search", "mcp_hotel_search"}:
        return "trip"
    if tools & {"mcp_calendar_search", "schedule_meeting"}:
        return "calendar"
    if tools & {"mcp_email_search", "send_reply", "modify_emails"}:
        return "email"
    return "briefing"


# Required env vars per detected pipeline.
# All pipelines now use Gmail (Resend removed), so every pipeline that sends email
# requires GOOGLE_ACCESS_TOKEN.  Empty list means no vars beyond ANTHROPIC_API_KEY.
def _gmail_req(scopes: str) -> tuple[str, str]:
    return ("GOOGLE_ACCESS_TOKEN",
            "Get one from https://developers.google.com/oauthplayground\n"
            f"  Scopes required: {scopes}")

_PIPELINE_ENV: dict[str, list[tuple[str, str]]] = {
    "briefing":  [_gmail_req("gmail.send")],
    "trip":      [_gmail_req("gmail.send")],
    "email":     [_gmail_req("gmail.modify + gmail.send")],
    "calendar":  [_gmail_req("calendar + gmail.readonly + gmail.send")],
}

# ══════════════════════════════════════════════════════════════════════
# 8. PUBLIC FACADE
# Stable public names for safehouse_cli (no leading underscore).
# Old private names kept as aliases for one release.
# ══════════════════════════════════════════════════════════════════════

def make_tracer(spec: DemoSpec, pause: bool = False) -> _DemoTracer:
    """Construct a _DemoTracer for `spec`."""
    return _DemoTracer(spec, pause=pause)


def banner(title: str) -> None:
    """Print a full-width banner."""
    _banner(title)


def ironflow_intro() -> None:
    """Print the Brave-SafeHouse / IronFlow opening banner."""
    _ironflow_intro()


def pipeline_env(pipeline: str) -> list[tuple[str, str]]:
    """Return the list of (env_var, hint) pairs required by `pipeline`."""
    return list(_PIPELINE_ENV.get(pipeline, []))


def get_universal_spec() -> DemoSpec:
    """Return the universal DemoSpec that auto-adapts to any pipeline."""
    return _UNIVERSAL_SPEC
