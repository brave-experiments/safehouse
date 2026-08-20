"""
permissions.py — Permission model.

Permissions are granted by the driver at spawn time and are immutable.
Sub-agents cannot grant permissions to themselves or to others — enforced
by the subprocess boundary: Tier 1 and Tier 2 sub-agents run inside an
isolated `claude -p` process that holds no Python reference to AgentSpec
or IronFlow. See safehouse/runner.py for the spawn boundary.

Slot access control is structural, not token-based:
  Tier 1 fetchers receive a single-use SlotWriter fixed to one output slot.
  Tier 2 processors receive a SlotReader scoped to their declared input slots
  and a SlotWriter for their single output slot. The scoped view enforces data
  minimisation — a processor cannot read slots outside its declared inputs even
  if those slots exist in the same store.

AgentSpec is the immutable contract for one agent invocation.
Factories produce correct specs; IronFlow enforces them.
"""

from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlsplit
from .labels import Label, I, Capability, CAPABILITY_LABEL


# ── Permission primitives ─────────────────────────────────────────────

@dataclass(frozen=True)
class CanNetwork:
    url_prefix: str
    def __str__(self) -> str: return f"NET({self.url_prefix})"

    def __post_init__(self) -> None:
        # A schemeless prefix like "example.com/x" parses to empty scheme+netloc
        # and would degrade permits() to a path-only match — a silently mis-scoped grant.
        p = urlsplit(self.url_prefix)
        if not p.scheme or not p.netloc:
            raise ValueError(
                f"CanNetwork prefix must be absolute (scheme + host): {self.url_prefix!r}"
            )
        # A prefix with '..' segments would create a silently unmatchable grant: permits()
        # rejects any incoming URL containing '..', so the prefix could never be satisfied.
        prefix_segs = [s for s in p.path.split("/") if s]
        if ".." in prefix_segs:
            raise ValueError(
                f"CanNetwork prefix must not contain '..' path segments: {self.url_prefix!r}"
            )

    def permits(self, url: str) -> bool:
        """
        Returns True iff `url` is permitted by this CanNetwork grant.

        Enforcement:
          - URL scheme must match the prefix scheme exactly.
          - URL host is compared case-insensitively (RFC 3986 §3.2.2).
          - URL path is matched segment-by-segment, not as a raw string.
            '/v1/mail' does NOT match '/v1/mail-admin' because the
            segments differ at the point of divergence.
          - URLs containing un-normalized '..' segments are rejected.

        Uses urlsplit (params/fragment-free). The CVE-2023-24329 fix that
        strips leading C0 control characters and spaces lives in the shared
        parser, so it applies to both urlsplit and urlparse; the >=3.12 floor
        (see pyproject) guarantees it. The prefix is validated absolute at
        construction (__post_init__), so permits() need not re-check it.
        """
        try:
            u = urlsplit(url)
            p = urlsplit(self.url_prefix)
        except ValueError:
            return False

        if u.scheme != p.scheme:
            return False
        if u.netloc.lower() != p.netloc.lower():
            return False

        # Segment-aware path prefix check: split both paths on '/' and
        # verify every segment of the grant prefix matches exactly.
        u_segs = [s for s in u.path.split("/") if s]
        p_segs = [s for s in p.path.split("/") if s]
        # Reject un-normalized dot-segments: httpx resolves '..' after this
        # gate approves, so a match would authorize a different path than fetched.
        if ".." in u_segs:
            return False
        return u_segs[:len(p_segs)] == p_segs

@dataclass(frozen=True)
class CanCallTool:
    tool_id: str
    def __str__(self) -> str: return f"TOOL({self.tool_id})"

@dataclass(frozen=True)
class CanSpawn:
    def __str__(self) -> str: return "SPAWN"


Permission = CanNetwork | CanCallTool | CanSpawn


# ── Agent spec ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentSpec:
    id:            str
    trust_level:   I               # used in trace events (EvAgentSpawned); not a security gate
    perms:         frozenset[Permission]
    max_label:     Label           # ceiling on labels this agent may read (enforced at SlotReader construction)
    system_prompt: str            = ""

    # ── Permission queries ────────────────────────────────────────────

    def can_network(self, url: str) -> bool:
        return any(isinstance(p, CanNetwork) and p.permits(url)
                   for p in self.perms)

    def can_call_tool(self, tool_id: str) -> bool:
        return any(isinstance(p, CanCallTool) and p.tool_id == tool_id
                   for p in self.perms)

    def can_spawn(self) -> bool:
        return any(isinstance(p, CanSpawn) for p in self.perms)


# ── Factories ─────────────────────────────────────────────────────────

def fetcher_spec(agent_id: str, capability: Capability, *, url: str = "", mcp_domain: str = "") -> AgentSpec:
    """
    Tier 1 deterministic data fetcher.
    Network access is scoped to the provided URL or MCP domain; pass exactly one.
    Slot access is structural: the driver passes a single-use SlotWriter fixed to one output slot.
    All fetchers run at I.U regardless of capability.
    """
    if url and mcp_domain:
        raise ValueError(f"fetcher_spec: pass url OR mcp_domain, not both (url={url!r}, mcp_domain={mcp_domain!r})")
    if not url and not mcp_domain:
        raise ValueError("fetcher_spec: one of url or mcp_domain must be non-empty")
    return AgentSpec(
        id          = agent_id,
        trust_level = I.U,
        perms       = frozenset([CanNetwork(url_prefix=url or mcp_domain)]),
        max_label   = CAPABILITY_LABEL[capability],
    )


def processor_spec(agent_id: str, out_label: Label, instruction: str,
                   max_label: Label | None = None) -> AgentSpec:
    """
    Tier 2 LLM processor sub-agent.
    No network, no tool calls, no spawning.
    Slot access is structural: the driver mints a SlotReader scoped to the declared
    input slots and a SlotWriter fixed to the output slot — no permission tokens.

    max_label defaults to out_label. Pass Label.U_priv() explicitly when the
    processor reads private slots whose label exceeds the computed output label.
    """
    return AgentSpec(
        id            = agent_id,
        trust_level   = I.U,
        perms         = frozenset(),
        max_label     = max_label if max_label is not None else out_label,
        system_prompt = instruction,
    )


def driver_spec() -> AgentSpec:
    """
    Driver.
    Has SPAWN and tool permissions for the agentic loop tools.
    No slot read access — driver reads store directly for terminal actions only,
    always through IronFlow bridge gates (apply_bridge_field / before_action).
    """
    return AgentSpec(
        id          = "driver",
        trust_level = I.T,
        perms       = frozenset([
            CanSpawn(),
            # Tier 1 — Data Sub-Agents
            CanCallTool("mcp_page_content"),
            CanCallTool("mcp_email_search"),
            CanCallTool("mcp_calendar_search"),
            CanCallTool("mcp_flight_search"),
            CanCallTool("mcp_hotel_search"),
            # Tier 2 — Processor Sub-Agents
            CanCallTool("spawn_processor"),
            # Tier 3 — Driver Tools
            CanCallTool("send_summary"),
            CanCallTool("send_reply"),
            CanCallTool("schedule_meeting"),
            CanCallTool("modify_emails"),
            CanCallTool("book_flight"),
            CanCallTool("book_hotel"),
            CanCallTool("mcp_github_issue_read"),
            CanCallTool("mcp_github_issue_search"),
            CanCallTool("mcp_github_issue_list"),
            CanCallTool("mcp_github_pr_read"),
            CanCallTool("mcp_github_pr_search"),
            CanCallTool("create_calendar_event"),
            CanCallTool("add_comment"),
            CanCallTool("submit_pr_review"),
        ]),
        max_label   = Label.T_priv(),
    )
