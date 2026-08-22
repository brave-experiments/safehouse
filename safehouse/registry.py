"""
safehouse/registry.py — Capability registry and concrete provider lookup.

Four layers, all defined here — ToolRegistry is the single source of truth for
every tool that appears in the planner prompt:

  Layer 0 (prompt schema):  ArgSpec / CatalogSpec — declarative arg descriptors
                            rendered into the TOOL CATALOG section of the prompt.
  Layer 1 (capability):     Capability + MCPSpec — abstract capability type with
                            label policy fixed at the type level; mapped to a
                            swappable concrete provider at planning time.
  Layer 2 (rendering):      _mcp_to_catalog / _catalog_entry — pure functions that
                            convert provider specs into rendered prompt strings.
                            No rendering logic lives in data classes.
  Layer 3 (registry):       ToolRegistry — MCPSpecs (fetchers) and CatalogSpecs
                            (processors, driver tools, utility tools).

The abstract planner sees only capability_summary() and tool_catalog() — never
provider domains, MCP tool names, or raw parameter schemas.  Adding a new provider
requires only a new MCPSpec in _MCP_SPECS; the planner prompt updates automatically.

Key security invariant:
  Label policy is attached to the Capability type, not the MCPSpec.
  CAPABILITY_LABEL is the single source of truth for label strings — they are
  derived from it at render time and never duplicated in description text.
  All providers of the same capability produce the same label regardless of which
  provider the mapper selects.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal
from .labels import Capability, CAPABILITY_LABEL


# ── Prompt schema types ────────────────────────────────────────────────────────
#
# ArgSpec / CatalogSpec describe the *abstract* plan args shown in the TOOL CATALOG
# section of the planner prompt.  They are the single source of truth for that section.

@dataclass(frozen=True)
class ArgSpec:
    name:        str
    type:        str          # shown in prompt: "str" | "list[str]" | "dict" | etc.
    required:    bool = True
    description: str  = ""    # shown after em-dash: "name* (type — description)"


_Category = Literal["fetcher", "processor", "terminal_auto", "terminal_confirmed", "utility"]

@dataclass(frozen=True)
class CatalogSpec:
    name:        str
    category:    _Category     # must match a key in _CATALOG_CATEGORY_HEADERS
    description: str           # one-line shown in TOOL CATALOG
    args:        tuple[ArgSpec, ...] = ()


# ── Capability metadata ────────────────────────────────────────────────────────

# One-line capability descriptions injected into the planner prompt.
# Text only — no label strings.  Labels are appended at render time from
# CAPABILITY_LABEL so they can never drift out of sync.
CAPABILITY_DESCRIPTION: dict[Capability, str] = {
    Capability.WEB_FETCH:     "Fetch a public URL via HTTP and return cleaned page text",
    Capability.FLIGHT_SEARCH: "Search available flights by route and date",
    Capability.HOTEL_SEARCH:  "Search available hotels by city and dates",
    Capability.EMAIL_READ:    "Read emails from a registered mailbox, filtered by sender/date",
    Capability.CALENDAR_READ: "Read calendar events for a user or account",
    # Capability-level line: the providers differ enough that each overrides it
    # with MCPSpec.description, so this stays deliberately broad.
    Capability.GITHUB_READ:   "Read GitHub issues and pull requests — one item with its "
                              "comments, many by predicate, or a pull request diff",
}


# ── Credential requirements ────────────────────────────────────────────────────
#
# Which tools need which provider credential. Declared here, beside the tools, so
# the CLI preflight and tracer.detect_pipeline read one source: a tool listed in
# one place but not the other either runs with no credential check or reports
# under the wrong pipeline banner.

GITHUB_TOOLS: frozenset[str] = frozenset({
    "mcp_github_issue_read", "mcp_github_issue_search", "mcp_github_issue_list",
    "mcp_github_pr_read", "mcp_github_pr_search",
    "add_comment", "submit_pr_review",
})

# The requirement belongs to the TOOL, not the pipeline label: a github pipeline
# ending in send_summary needs Gmail even though the github env list does not
# mention GOOGLE_ACCESS_TOKEN.
GOOGLE_TOOLS: frozenset[str] = frozenset({
    "mcp_email_search", "mcp_calendar_search",
    "send_summary", "send_reply", "schedule_meeting",
    "modify_emails", "create_calendar_event",
})

# Search AND the terminal booking tool: a plan can theoretically book without a
# search step (offer_slot from some other fetcher), and preflight must still fire.
DUFFEL_TOOLS:  frozenset[str] = frozenset({"mcp_flight_search", "book_flight"})
LITEAPI_TOOLS: frozenset[str] = frozenset({"mcp_hotel_search", "book_hotel"})


# ── Concrete provider spec ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class MCPSpec:
    """
    Concrete implementation details for one provider of a Capability.

    Attributes:
        name           — unique registry key (e.g. "mcp_email_search", "mcp_flight_search")
        capability     — which Capability this provider implements
        tool_type      — "rest" (direct HTTP) or "mcp" (MCP protocol)
        domain         — provider base URL; used as api_url for REST tools and
                         as domain for MCP tools.
                         Use "*" for WEB_FETCH (URL comes from task, not registry).
        mcp_tool       — MCP tool name to call (mcp tool_type only)
        param_map      — declarative field rename: {abstract_name: provider_name}.
                         Keys are the abstract param names the planner uses;
                         values are the provider-specific names the MCP server expects.
                         Unmapped names pass through unchanged.
        booking_domain   — booking URL auto-added to manifest trusted_action_urls (mcp tool_type only)
        location_tool    — optional pre-lookup MCP tool for location resolution
        date_fmt         — strftime format string for date params (default "" = ISO YYYY-MM-DD).
                           Set to e.g. "%d/%m/%Y" when the provider requires dd/mm/yyyy.
                           Any param value that looks like YYYY-MM-DD is converted automatically.
        value_maps       — per-field value translation after param_map rename.
                           {provider_field_name: {abstract_value: provider_value}}.
                           e.g. {"cabinClass": {"economy": "M", "business": "C"}}.
        filter_description — override the default filter arg description for REST tools;
                             if empty, the email-style default is used
        description        — override CAPABILITY_DESCRIPTION for this provider's TOOL
                             CATALOG line. Set it when providers of the same capability
                             do materially different things.
    """
    name:               str
    capability:         Capability
    tool_type:          Literal["rest", "mcp"]
    domain:             str
    mcp_tool:           str                        = ""
    param_map:          dict[str, str]             = field(default_factory=dict)
    booking_domain:     str                        = ""
    location_tool:      str                        = ""
    date_fmt:           str                        = ""
    value_maps:         dict[str, dict[str, str]]  = field(default_factory=dict)
    filter_description: str                        = ""
    description:        str                        = ""


# ── Rendering layer ────────────────────────────────────────────────────────────
#
# Pure functions: MCPSpec → CatalogSpec → rendered string.
# No rendering logic in data classes.

# Default filter description for REST sub-agents that don't supply their own.
# Describes the two usage patterns for mcp_email_search; mcp_calendar_search overrides this.
_DEFAULT_FILTER_DESCRIPTION = (
    "Use q (Gmail search syntax) as the primary filter field — it is fully general. "
    "Examples: q='from:alice@example.com' (received from), q='to:alice@example.com' (sent to), "
    "q='from:alice@example.com in:sent' (your sent mail to alice), "
    "q='subject:invoice has:attachment'. "
    "Set limit=1 for the latest message; limit=5–10 to surface candidates for a processor. "
    "Named shorthand fields (from, subject_contains, is_unread, has_attachment, "
    "after_date, before_date, label) are also accepted and appended to q — "
    "use q directly when the task implies sent mail or any query not covered by the named fields. "
    "Exception: send_reply plans must set filter.from to the reply recipient (not only q)."
)

_CATALOG_CATEGORY_HEADERS: dict[str, str] = {
    "fetcher":            "TIER 1 — DATA SUB-AGENTS",
    "processor":          "TIER 2 — PROCESSOR SUB-AGENTS",
    "terminal_auto":      "TIER 3 — DRIVER TOOLS (automated — fire immediately, no confirmation)",
    "terminal_confirmed": "TIER 3 — DRIVER TOOLS (confirmed — pause for human approval before acting)",
    "utility":            "UTILITY",
}


def _spec_text(spec: MCPSpec) -> str:
    """Per-provider description, falling back to the capability default.

    Shared by both renderers: an override added to one spec must read the same
    way in REGISTERED CAPABILITIES and in TOOL CATALOG.
    """
    return spec.description or CAPABILITY_DESCRIPTION[spec.capability]


def _mcp_to_catalog(spec: MCPSpec) -> CatalogSpec:
    """
    Convert an MCPSpec to a CatalogSpec for TOOL CATALOG rendering.

    Three structural patterns based on domain and tool_type:
      domain == "*"       → url fetcher   (mcp_page_content)
      tool_type == "rest" → filter-based  (mcp_email_search, mcp_calendar_search)
      tool_type == "mcp"  → params dict   (mcp_flight_search, mcp_hotel_search,
                                           mcp_github_* — REST, same arg shape)

    Description combines CAPABILITY_DESCRIPTION (text) and CAPABILITY_LABEL (label string).
    Both are single sources of truth; never duplicated here.
    """
    label       = str(CAPABILITY_LABEL[spec.capability])
    description = f"{_spec_text(spec)}; writes {label} slot."

    if spec.domain == "*":
        args: tuple[ArgSpec, ...] = (
            ArgSpec("url",     "str",
                    description="canonical https:// URL from task text or inferred from task context"),
            ArgSpec("slot_id", "str"),
        )
    elif spec.tool_type == "rest":
        args = (
            ArgSpec("filter",  "dict", required=False,
                    description=spec.filter_description or _DEFAULT_FILTER_DESCRIPTION),
            ArgSpec("slot_id", "str"),
        )
    else:  # tool_type == "mcp"
        args = (
            ArgSpec("params",  "dict",
                    description="keys and values: see REGISTERED CAPABILITIES"),
            ArgSpec("slot_id", "str"),
        )

    return CatalogSpec(
        name        = spec.name,
        category    = "fetcher",
        description = description,
        args        = args,
    )


def _catalog_entry(spec: CatalogSpec) -> str:
    left       = f"  {spec.name:<{_CATALOG_NAME_W}}  "
    args_start = " " * len(left) + "args: "
    cont       = " " * len(args_start)

    lines = [left + spec.description]
    if not spec.args:
        return lines[0]

    arg_strs = [
        f"{a.name}{'*' if a.required else ''} ({a.type}{f' — {a.description}' if a.description else ''})"
        for a in spec.args
    ]
    for i, s in enumerate(arg_strs):
        prefix = args_start if i == 0 else cont
        sep    = "," if i < len(arg_strs) - 1 else ""
        lines.append(prefix + s + sep)

    return "\n".join(lines)


# ── Registry ──────────────────────────────────────────────────────────────────

class ToolRegistry:
    """
    Single source of truth for ALL pipeline tools.

    Tier 1 data fetchers (MCPSpec) are capability-gated and provider-swappable;
    registered via register(). Non-fetcher pipeline tools (CatalogSpec) are
    always-available mechanics; registered via register_catalog().

    The abstract planner sees capability_summary(), build_patterns_section(),
    and tool_catalog() — never provider domains, MCP tool names, or raw parameter schemas.
    The concrete mapper calls find(capability) to resolve an MCPSpec.
    """

    def __init__(self) -> None:
        self._specs:         dict[str, MCPSpec]  = {}
        self._catalog_specs: list[CatalogSpec]   = []

    @classmethod
    def from_specs(
        cls,
        mcp_specs:     list[MCPSpec],
        catalog_specs: list[CatalogSpec],
    ) -> "ToolRegistry":
        """Construct a registry from declarative spec lists."""
        registry = cls()
        for spec in mcp_specs:
            registry.register(spec)
        for spec in catalog_specs:
            registry.register_catalog(spec)
        return registry

    def register(self, spec: MCPSpec) -> None:
        """Register a Tier 1 data fetcher (capability-gated, provider-swappable)."""
        self._specs[spec.name] = spec

    def register_catalog(self, spec: CatalogSpec) -> None:
        """Register a non-fetcher pipeline tool (Tier 2 processor, Tier 3 driver tool, utility)."""
        self._catalog_specs.append(spec)

    def find(self, capability: Capability) -> MCPSpec | None:
        """Return the first registered provider for the given capability, or None."""
        for spec in self._specs.values():
            if spec.capability == capability:
                return spec
        return None

    def find_by_name(self, name: str) -> MCPSpec | None:
        """Return the registered provider with the given name, or None."""
        return self._specs.get(name)

    def all_specs(self) -> list[MCPSpec]:
        """Return all registered MCPSpecs in insertion order."""
        return list(self._specs.values())

    def all_catalog_specs(self) -> list[CatalogSpec]:
        """
        Return CatalogSpecs for ALL registered tools in prompt order:
          1. Fetchers (TIER 1) — derived from MCPSpec via _mcp_to_catalog()
          2. Pipeline tools   — registered via register_catalog()
        """
        return [_mcp_to_catalog(s) for s in self._specs.values()] + self._catalog_specs

    def tool_catalog(self) -> str:
        """
        Generates the TOOL CATALOG section injected into the Phase 1 planner prompt.

        Lists every registered tool — Tier 1 data sub-agents, Tier 2 processor sub-agents,
        Tier 3 driver tools, and utility tools — grouped by category.
        Fills the {tool_catalog} placeholder in the prompt template.
        Single source of truth for tool arg schemas visible to the abstract planner.
        """
        groups: dict[str, list[CatalogSpec]] = {}
        for spec in self.all_catalog_specs():
            groups.setdefault(spec.category, []).append(spec)

        sections = []
        for cat, tools in groups.items():
            header = _CATALOG_CATEGORY_HEADERS.get(cat, cat.upper())
            body   = "\n\n".join(_catalog_entry(t) for t in tools)
            sections.append(f"{header}\n\n{body}")

        return "\n\n".join(sections)

    def capability_summary(self) -> str:
        """
        Generates the REGISTERED CAPABILITIES section injected into the Phase 1 planner prompt.

        Covers all three tiers:
          Tier 1 — Data sub-agents (MCPSpecs): every registered fetcher, including
                   multiple tools that share a Capability (GitHub read/search/list/PR).
                   Never includes provider domains, MCP tool names, or raw schemas.
          Tier 2 — Processor sub-agents (CatalogSpecs, category="processor"): name + description.
          Tier 3 — Driver tools (CatalogSpecs, category="terminal_auto/confirmed"): name + description + [auto/confirmed].

        Full arg schemas for all tools are in tool_catalog() / TOOL CATALOG below.
        """
        # Tier 1 — every registered fetcher. Sharing a Capability (GITHUB_READ) does
        # not make two tools interchangeable: list/search/read/PR each have their
        # own params and must appear, or the planner only sees the first one.
        tier1: list[str] = []
        for spec in self._specs.values():
            cap = spec.capability
            label = str(CAPABILITY_LABEL[cap])
            text = _spec_text(spec)
            if spec.param_map:
                params = ", ".join(spec.param_map)
            else:
                params = ", ".join(
                    a.name for a in _mcp_to_catalog(spec).args
                    if a.name not in ("slot_id", "system_prompt")
                ) or "—"
            tier1.append(
                f"  {spec.name:<{_CATALOG_NAME_W}}  {text}  →  {label}\n"
                f"  {'':{_CATALOG_NAME_W}}  params: {params}"
            )

        # Tier 2 and Tier 3 — single pass over catalog specs
        tier2: list[str] = []
        tier3: list[str] = []
        for spec in self._catalog_specs:
            if spec.category == "processor":
                tier2.append(f"  {spec.name:<{_CATALOG_NAME_W}}  {spec.description}")
            elif spec.category in ("terminal_auto", "terminal_confirmed"):
                tag = "[auto]" if spec.category == "terminal_auto" else "[confirmed]"
                tier3.append(f"  {spec.name:<{_CATALOG_NAME_W}}  {spec.description}  {tag}")

        sections: list[str] = []
        if tier1:
            sections.append("TIER 1 — DATA SUB-AGENTS\n\n" + "\n".join(tier1))
        if tier2:
            sections.append("TIER 2 — PROCESSOR SUB-AGENTS\n\n" + "\n".join(tier2))
        if tier3:
            sections.append("TIER 3 — DRIVER TOOLS\n\n" + "\n".join(tier3))
        return "\n\n".join(sections) if sections else "  (no capabilities registered)"


# ── Default registry (declarative) ────────────────────────────────────────────

_MCP_SPECS: list[MCPSpec] = [

    MCPSpec(
        name       = "mcp_page_content",
        capability = Capability.WEB_FETCH,
        tool_type  = "rest",
        domain     = "*",        # URL comes from task text, not registry
    ),

    MCPSpec(
        name       = "mcp_email_search",
        capability = Capability.EMAIL_READ,
        tool_type  = "rest",
        domain     = "https://gmail.googleapis.com/gmail/v1",
    ),

    MCPSpec(
        name               = "mcp_calendar_search",
        capability         = Capability.CALENDAR_READ,
        tool_type          = "rest",
        domain             = "https://www.googleapis.com/calendar/v3",
        filter_description = (
            "Always set timeMin + timeMax covering the relevant window. "
            "Do NOT set q — event titles are unpredictable; fetch the full window and let spawn_processor filter. "
            "timeMin: <ISO8601>; timeMax: <ISO8601>; "
            "calendarId: <add only if task names a specific calendar, default 'primary'>; "
            "maxResults: <int, default 10>"
        ),
    ),

    MCPSpec(
        name           = "mcp_flight_search",
        capability     = Capability.FLIGHT_SEARCH,
        tool_type      = "mcp",
        domain         = "https://api.duffel.com/air",
        mcp_tool       = "offer_requests",
        param_map      = {"date": "departure_date"},
    ),

    MCPSpec(
        name           = "mcp_hotel_search",
        capability     = Capability.HOTEL_SEARCH,
        tool_type      = "mcp",
        domain         = "https://api.liteapi.travel/v3.0",
        mcp_tool       = "hotels/rates",
        param_map      = {
            "check_in":   "checkin",
            "check_out":  "checkout",
        },
    ),

    # GitHub issues via REST (authenticated). tool_type stays "mcp" so the
    # concrete-mapping (params → search_params) is reused; the DRIVER handler
    # routes to run_github_issue_read (REST), not an MCP call — same pattern as
    # the Duffel/LiteAPI entries above. Issue bodies and comments are the
    # injection surface, so each item is provenance-filtered before it is written.
    MCPSpec(
        name           = "mcp_github_issue_read",
        capability     = Capability.GITHUB_READ,
        description    = ("Read ONE GitHub issue or pull request named by number, with its "
                          "comments. Use mcp_github_pr_read instead when the task needs the diff"),
        tool_type      = "mcp",
        domain         = "https://api.github.com",
        mcp_tool       = "issues",
        # Identity mapping: GitHub needs no field rename, but param_map keys are
        # what capability_summary() renders as the accepted `params` for the
        # planner — declaring them here is what stops the prompt printing the
        # useless "params: params" fallback.
        param_map      = {"repo": "repo", "issue_number": "issue_number"},
    ),

    # Same provider, same capability — but resolves ONE issue from a task-derived
    # predicate instead of requiring the number up front. Selection is operator
    # code over provider metadata with the provenance floor applied, and the
    # resolved number reaches add_comment via state.vars as (T,pub).
    MCPSpec(
        name           = "mcp_github_issue_search",
        capability     = Capability.GITHUB_READ,
        description    = ("Resolve ONE GitHub issue from a predicate (state, labels, "
                          "title_contains, author, select), then read it and its comments. "
                          "Publishes the resolved issue number for add_comment"),
        tool_type      = "mcp",
        domain         = "https://api.github.com",
        mcp_tool       = "issues/list",
        param_map      = {
            "repo": "repo", "issue_number": "issue_number", "state": "state",
            "labels": "labels", "title_contains": "title_contains",
            "author": "author", "select": "select",
        },
    ),

    # Report-only listing: MANY items, and it publishes no routing, so nothing it
    # returns can select the target of a write. That is what makes a broad query
    # safe here where issue_search deliberately resolves exactly one item.
    MCPSpec(
        name           = "mcp_github_issue_list",
        capability     = Capability.GITHUB_READ,
        description    = ("List MANY GitHub issues and/or pull requests matching a predicate "
                          "(state, labels, assignee, creator, mentioned, kind). Metadata plus a "
                          "short body excerpt per item; no comments. Report-only — publishes no "
                          "routing, so it cannot select the target of a write"),
        tool_type      = "mcp",
        domain         = "https://api.github.com",
        mcp_tool       = "issues/list",
        param_map      = {
            "repo": "repo", "state": "state", "labels": "labels",
            "assignee": "assignee", "creator": "creator", "mentioned": "mentioned",
            "kind": "kind", "sort": "sort", "direction": "direction", "limit": "limit",
        },
    ),

    # One pull request plus its changed files. Publishes the head SHA as (T,pub)
    # so submit_pr_review binds to the commit actually reviewed.
    MCPSpec(
        name           = "mcp_github_pr_read",
        capability     = Capability.GITHUB_READ,
        description    = ("Read ONE pull request named by number, with its changed files and "
                          "diff. Required before submit_pr_review — it publishes the head SHA "
                          "that binds the review to the reviewed commit"),
        tool_type      = "mcp",
        domain         = "https://api.github.com",
        mcp_tool       = "pulls",
        param_map      = {"repo": "repo", "pull_number": "pull_number"},
    ),

    # Same provider, same capability — resolves ONE pull request from a
    # task-derived predicate. Publishes both the number and the head SHA, so
    # submit_pr_review gets its target and its commit binding from one
    # deterministic resolution.
    MCPSpec(
        name           = "mcp_github_pr_search",
        capability     = Capability.GITHUB_READ,
        description    = ("Resolve ONE pull request from a predicate (state, base, head, author, "
                          "title_contains, select), then read it with its diff. Drafts excluded "
                          "unless include_drafts. Publishes the resolved number and head SHA"),
        tool_type      = "mcp",
        domain         = "https://api.github.com",
        mcp_tool       = "pulls/list",
        param_map      = {
            "repo": "repo", "pull_number": "pull_number", "state": "state",
            "base": "base", "head": "head", "author": "author",
            "title_contains": "title_contains", "select": "select",
            "include_drafts": "include_drafts",
        },
    ),

]

_CATALOG_SPECS: list[CatalogSpec] = [

    CatalogSpec(
        name        = "spawn_processor",
        category    = "processor",
        description = "Synthesise or transform across slots; output taint = inputs' taint.",
        args        = (
            ArgSpec("reads",       "list[str]", description="slot_ids from earlier steps"),
            ArgSpec("out_slot",    "str"),
            ArgSpec("instruction", "str",       description="specify exact output format and any ranking or selection criteria"),
        ),
    ),

    CatalogSpec(
        name        = "send_summary",
        category    = "terminal_auto",
        description = "Send new email; body from slot. Routing (recipient, subject) pre-committed (T,pub) — never derived from slot content. recipient may be a list for multi-recipient sends.",
        args        = (
            ArgSpec("recipient", "str | list[str]", description="verbatim email(s), each must contain @; list sends to multiple recipients"),
            ArgSpec("subject",   "str",             description="verbatim or inferred from task context"),
            ArgSpec("body_slot", "str"),
            ArgSpec("delivery",  "str", required=False, description="combined (default — one message) | separate (one message per recipient)"),
        ),
    ),

    CatalogSpec(
        name        = "send_reply",
        category    = "terminal_auto",
        description = "Reply to fetched email thread; body from slot. Routing (recipient, subject) pre-committed (T,pub) — never derived from slot content. Exactly one recipient.",
        args        = (
            ArgSpec("recipient", "str", description="verbatim sender email, must contain @"),
            ArgSpec("subject",   "str", description="verbatim or inferred from task context"),
            ArgSpec("body_slot", "str"),
        ),
    ),

    CatalogSpec(
        name        = "schedule_meeting",
        category    = "terminal_confirmed",
        description = "Propose calendar slots, confirm with human, create event, send reply. Routing (attendee, title, subject) pre-committed (T,pub) — never derived from slot content. attendee may be a list.",
        args        = (
            ArgSpec("attendee",         "str | list[str]", description="verbatim email(s) from task, each must contain @"),
            ArgSpec("event_title",      "str",             description="verbatim from task; if absent use a short generic title (e.g. Meeting) — never invent a name from an email local-part"),
            ArgSpec("reply_subject",    "str",             description="verbatim or short inferred subject (e.g. Re: Meeting Request)"),
            ArgSpec("slots_slot",       "str",             description="slot written by spawn_processor with proposed_slots JSON"),
        ),
    ),

    CatalogSpec(
        name        = "modify_emails",
        category    = "terminal_auto",
        description = "Apply bulk Gmail action to every message from a sender. Sender and action are (T,pub) from task — no slot content read.",
        args        = (
            ArgSpec("sender",     "str", description="verbatim sender name or email from task (Gmail from: filter accepts both)"),
            ArgSpec("action",     "str", description="add_label | remove_label | archive | mark_read | mark_unread | star | unstar"),
            ArgSpec("label_name", "str", required=False, description="verbatim Gmail label name — required for add_label and remove_label only"),
        ),
    ),

    CatalogSpec(
        name        = "add_comment",
        category    = "terminal_confirmed",
        description = "Post a comment on a GitHub issue OR pull request (one endpoint serves both). Routing (repo, and issue_number when named in the task) is (T,pub) — never derived from fetched issue content. Body comes from a slot.",
        args        = (
            ArgSpec("repo",         "str", description="'owner/name' verbatim from task, e.g. 'octocat/Hello-World'"),
            ArgSpec("issue_number", "int", required=False,
                    description="issue or PR number from task; omit when mcp_github_issue_search resolves it"),
            ArgSpec("body_slot",    "str"),
        ),
    ),

    CatalogSpec(
        name        = "submit_pr_review",
        category    = "terminal_confirmed",
        description = "Submit a review on a GitHub pull request. event is COMMENT or REQUEST_CHANGES only — APPROVE is not offered, because an approving review can satisfy branch protection and unblock an automated merge. Routing (repo, and pull_number/event when named in the task) is (T,pub). The reviewed commit is bound automatically from mcp_github_pr_read, which must run first. Body comes from a slot.",
        args        = (
            ArgSpec("repo",        "str", description="'owner/name' verbatim from task"),
            ArgSpec("pull_number", "int", required=False,
                    description="pull request number from task; omit when mcp_github_pr_search resolves it"),
            ArgSpec("event",       "str", required=False,
                    description="COMMENT (default; leaves a review without blocking) or REQUEST_CHANGES (blocks the PR)"),
            ArgSpec("body_slot",   "str"),
        ),
    ),

    CatalogSpec(
        name        = "create_calendar_event",
        category    = "terminal_confirmed",
        description = "Add a personal block to the operator's OWN calendar — no attendee, no email thread, no meeting request. Use this (NOT schedule_meeting) for 'add this to my calendar' tasks. event_title/start/end are (T,pub) from the task text, converted to ISO8601 — never derived from a slot.",
        args        = (
            ArgSpec("event_title", "str", description="short title from task context, e.g. 'Trip to Madrid'"),
            ArgSpec("start",       "str", description="tz-aware ISO8601 datetime, e.g. 2026-10-11T00:00:00+01:00"),
            ArgSpec("end",         "str", description="tz-aware ISO8601 datetime, must be after start"),
        ),
    ),

    CatalogSpec(
        name        = "book_flight",
        category    = "terminal_confirmed",
        description = "Book the flight offer chosen by spawn_processor (Duffel), paid from the operator's prepaid Duffel balance, after human confirmation. provider is (T,pub); the amount is re-validated against Duffel and human-endorsed. Passenger details and the spend ceiling come from operator config, never the task or a slot.",
        args        = (
            ArgSpec("provider",   "str", description="booking provider — must be 'duffel'"),
            ArgSpec("offer_slot", "str", description="slot written by spawn_processor holding the chosen offer as {offer_id, total_amount, total_currency}"),
        ),
    ),

    CatalogSpec(
        name        = "book_hotel",
        category    = "terminal_confirmed",
        description = "Book the hotel offer chosen by spawn_processor (LiteAPI), paid from the operator's prepaid LiteAPI wallet, after human confirmation. provider is (T,pub); the amount is re-validated via LiteAPI prebook and human-endorsed. Guest details and the spend ceiling come from operator config, never the task or a slot.",
        args        = (
            ArgSpec("provider",   "str", description="booking provider — must be 'liteapi'"),
            ArgSpec("offer_slot", "str", description="slot written by spawn_processor holding the chosen offer as {offer_id, amount, currency}"),
        ),
    ),

]

# Column width for rendered tool names. Derived rather than pinned: a longer tool
# name would otherwise silently push the description column out of alignment.
_CATALOG_NAME_W = max(len(s.name) for s in _MCP_SPECS + _CATALOG_SPECS) + 3

DEFAULT_REGISTRY = ToolRegistry.from_specs(_MCP_SPECS, _CATALOG_SPECS)
