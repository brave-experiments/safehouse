"""
tests/test_github_pr.py — issue listing, PR reading, and PR review.

Three properties these tools must hold, none of which the issue/comment tests cover:

  1. A listing that was emptied by the integrity floor must stay distinguishable
     from a listing that genuinely matched nothing. The single-issue path can
     raise; a list cannot, so it reports `withheld` instead.
  2. An open PR's diff is a proposal, not reviewed code. `diff_vetted` says so
     regardless of how well-standing its author is.
  3. A review must bind to the commit that was actually read, and must never be
     able to approve.

No API key and no network — the HTTP transport is stubbed.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

import safehouse.driver as driver_mod
import safehouse.runner as runner_mod
import safehouse.trace as _trace
from safehouse.driver import run as driver_run
from safehouse.ironflow_policy import IronFlow
from safehouse.labels import Capability
from safehouse.permissions import fetcher_spec
from safehouse.slots import SlotStore
from safehouse.trace import Tracer

REPO = "octocat/Hello-World"
BASE = "https://api.github.com"
SHA  = "0123456789abcdef0123456789abcdef01234567"


def _item(number, *, assoc="MEMBER", login="octocat", pr=False, merged=False, title="T"):
    item = {
        "number": number, "title": title, "body": "body words here",
        "state": "open", "author_association": assoc,
        "user": {"login": login}, "labels": [{"name": "bug"}],
        "comments": 2, "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
    }
    if pr:
        item["pull_request"] = {"merged_at": "2026-01-03T00:00:00Z" if merged else None}
    return item


PR = {
    "number": 42, "title": "Add retry", "body": "Adds a retry.", "state": "open",
    "author_association": "MEMBER", "user": {"login": "octocat"},
    "draft": False, "merged": False, "merged_at": None,
    "head": {"ref": "feature", "sha": SHA}, "base": {"ref": "main"},
    "additions": 10, "deletions": 2, "changed_files": 1,
}
FILES = [{"filename": "a.py", "status": "modified",
          "additions": 10, "deletions": 2, "patch": "@@ -1 +1 @@\n-old\n+new"}]


class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code, self.text = payload, status, ""

    def json(self):
        return self._p


class _Client:
    """Stub transport. Class attributes let each test reshape the payloads."""

    listed: list = []
    listed_prs: list = []
    pr: dict = dict(PR)
    files: list = list(FILES)
    posted: list = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None, params=None):
        page = (params or {}).get("page", 1)
        if url.endswith("/files"):
            return _Resp(_Client.files if page == 1 else [])
        if url.endswith("/pulls"):
            return _Resp(_Client.listed_prs)
        if "/pulls/" in url:
            # Echo the requested number so a search-selected PR reads back as itself.
            num = int(url.rsplit("/", 1)[-1])
            return _Resp({**_Client.pr, "number": num})
        if url.endswith("/issues"):
            return _Resp(_Client.listed)
        return _Resp({})

    async def post(self, url, headers=None, json=None):
        _Client.posted.append({"url": url, **(json or {})})
        return _Resp({"id": 777, "html_url": f"https://github.com/{REPO}/pull/42#r777"}, 200)


@pytest.fixture(autouse=True)
def _stub(monkeypatch):
    _Client.listed = [_item(1), _item(2, pr=True)]
    _Client.listed_prs = []
    _Client.pr     = dict(PR)
    _Client.files  = list(FILES)
    _Client.posted = []
    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    monkeypatch.setattr(driver_mod.httpx, "AsyncClient", _Client, raising=False)
    monkeypatch.setattr(runner_mod.httpx, "AsyncClient", _Client, raising=False)


def _fetch(fn, params, *, floor="", blocked=frozenset()):
    """Run a Tier-1 fetcher directly and return (return_value, parsed_slot)."""
    store = SlotStore()
    store.create("out")
    spec   = fetcher_spec("t", Capability.GITHUB_READ, mcp_domain=BASE)
    policy = IronFlow(store)
    writer = store.writer_for("out", spec.max_label, agent_id="t")
    _trace.set_tracer(Tracer())
    rv = asyncio.run(fn(spec, BASE, params, writer, policy,
                        github_token="fake-pat", min_integrity=floor,
                        blocked_users=blocked))
    return rv, json.loads(store.read("out").value)


# ══════════════════════════════════════════════════════════════════════
# 1. mcp_github_issue_list — report-only
# ══════════════════════════════════════════════════════════════════════

def test_list_projects_issues_and_prs():
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO})
    assert out["listed"] == 2
    assert [i["number"] for i in out["items"]] == [1, 2]
    assert [i["is_pull_request"] for i in out["items"]] == [False, True]


@pytest.mark.parametrize("kind,expected", [("issue", [1]), ("pr", [2]), ("all", [1, 2])])
def test_kind_splits_issues_from_pull_requests(kind, expected):
    """GitHub's issues endpoint returns PRs too — splitting them is a projection
    concern, not a second request."""
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO, "kind": kind})
    assert [i["number"] for i in out["items"]] == expected


def test_below_floor_items_are_withheld_and_counted():
    _Client.listed = [_item(1, assoc="MEMBER"), _item(2, assoc="NONE", login="drive-by")]
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO}, floor="approved")
    assert [i["number"] for i in out["items"]] == [1]
    assert out["withheld"] == 1 and out["listed"] == 1


def test_an_emptied_list_is_not_an_empty_list():
    """The many-item analogue of the fail-closed rule: a list the floor emptied
    must not read as 'nothing matched'. A processor told only `items: []` would
    report 'you have no open issues' as though that were a fact."""
    _Client.listed = [_item(1, assoc="NONE"), _item(2, assoc="NONE")]
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO}, floor="approved")
    assert out["items"] == []
    assert out["withheld"] == 2, "an all-filtered list must still report what it dropped"
    assert out["considered"] == 2


def test_blocklist_applies_to_listings():
    _Client.listed = [_item(1, login="spam-bot", assoc="OWNER")]
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO},
                    blocked=frozenset({"spam-bot"}))
    assert out["items"] == [] and out["withheld"] == 1


def test_limit_is_capped_at_the_ceiling():
    _Client.listed = [_item(n) for n in range(200)]
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO, "limit": 999})
    assert len(out["items"]) == runner_mod._GITHUB_LIST_MAX_ITEMS
    assert out["considered"] == 200


def test_body_excerpt_is_bounded():
    _Client.listed = [_item(1)]
    _Client.listed[0]["body"] = " ".join(["word"] * 500)
    _, out = _fetch(runner_mod.run_github_issue_list, {"repo": REPO})
    item = out["items"][0]
    assert len(item["body_excerpt"].split()) == runner_mod._GITHUB_EXCERPT_WORDS
    assert item["body_truncated"] is True


@pytest.mark.parametrize("params", [
    {"state": "bogus"}, {"kind": "bogus"}, {"sort": "bogus"},
    {"direction": "sideways"}, {"limit": "many"},
])
def test_invalid_predicate_values_are_rejected(params):
    with pytest.raises(RuntimeError):
        _fetch(runner_mod.run_github_issue_list, {"repo": REPO, **params})


def test_listing_publishes_no_routing(monkeypatch):
    """The structural reason a broad many-item query is safe: nothing it returns
    can select the target of a write.

    Asserted by recording every set_var during the run, not by inspecting the
    slot: the risk is a routing value reaching state.vars, which slot content
    would not reveal.
    """
    from safehouse.plan_types import PlanState

    published: list[str] = []
    original = PlanState.set_var

    def _spy(self, key, lval, **kw):
        published.append(key)
        return original(self, key, lval, **kw)

    monkeypatch.setattr(PlanState, "set_var", _spy)

    async def _fake_processor(reads, reader, writer, **kw):
        writer.write("3 open PRs assigned to you.")

    sent: list = []

    async def _fake_send(to, subject, body, google_token, state, *, body_slot=""):
        sent.append({"to": to, "subject": subject, "body": body})

    monkeypatch.setattr(driver_mod, "run_processor", _fake_processor)
    monkeypatch.setattr(driver_mod, "_gmail_send", _fake_send)

    # The flagship report-only flow: list many items, summarise, email the digest.
    plan = {"steps": [
        {"tool": "mcp_github_issue_list", "args": {
            "slot_id": "items", "capability": "GITHUB_READ", "domain": BASE,
            "mcp_tool": "issues/list", "search_params": {"repo": REPO, "kind": "pr"}}},
        {"tool": "spawn_processor", "args": {
            "reads": ["items"], "out_slot": "digest", "instruction": "Summarise."}},
        {"tool": "send_summary", "args": {
            "recipient": "dev@example.com", "subject": "Your PRs", "body_slot": "digest"}},
    ]}
    store = SlotStore()
    _trace.set_tracer(Tracer())
    result = asyncio.run(driver_run(
        "email me my PRs on octocat/Hello-World to dev@example.com", plan, store,
        IronFlow(store), github_token="fake-pat", google_token="fake-google"))
    assert result.get("status") == "success", result
    assert store.is_written("items") and sent
    assert [k for k in published if k != "_routing"] == [], (
        f"mcp_github_issue_list published {published} — it must publish no routing, "
        f"or its results could select the target of a write")


def test_pr_read_publishes_only_the_head_sha(monkeypatch):
    """The counterpart: pr_read *does* publish, and exactly one value."""
    from safehouse.plan_types import PlanState

    published: list[str] = []
    original = PlanState.set_var

    def _spy(self, key, lval, **kw):
        published.append(key)
        assert str(lval.label) == "(T,pub)", "state.vars accepts nothing weaker"
        return original(self, key, lval, **kw)

    monkeypatch.setattr(PlanState, "set_var", _spy)

    result, _ = _run_review(monkeypatch, _review_plan())
    assert result.get("status") == "success", result
    assert [k for k in published if k != "_routing"] == [
        driver_mod._GITHUB_PR_SHA_VAR, driver_mod._GITHUB_PR_NUM_VAR]


# ══════════════════════════════════════════════════════════════════════
# 2. mcp_github_pr_read
# ══════════════════════════════════════════════════════════════════════

def test_pr_read_returns_head_sha_and_projects_files():
    (sha, num), out = _fetch(runner_mod.run_github_pr_read,
                             {"repo": REPO, "pull_number": 42})
    assert sha == SHA and out["head_sha"] == SHA and num == 42
    assert out["base_ref"] == "main" and out["head_ref"] == "feature"
    assert out["files"][0]["filename"] == "a.py"
    assert "patch" in out["files"][0]


def test_open_pr_diff_is_unvetted_even_from_an_owner():
    """Author standing does not review a diff. An open PR is a proposal whoever
    wrote it — the distinction the vetting axis exists to make."""
    _Client.pr = {**PR, "author_association": "OWNER"}
    _, out = _fetch(runner_mod.run_github_pr_read, {"repo": REPO, "pull_number": 42})
    assert out["diff_vetted"] is False
    assert out["integrity"] == "approved"      # author standing, not "merged"


def test_merged_pr_is_vetted():
    _Client.pr = {**PR, "merged": True, "merged_at": "2026-01-03T00:00:00Z"}
    _, out = _fetch(runner_mod.run_github_pr_read, {"repo": REPO, "pull_number": 42})
    assert out["diff_vetted"] is True and out["integrity"] == "merged"


def test_below_floor_pr_raises_rather_than_blanking():
    _Client.pr = {**PR, "author_association": "NONE"}
    with pytest.raises(RuntimeError, match="below the configured floor"):
        _fetch(runner_mod.run_github_pr_read, {"repo": REPO, "pull_number": 42},
               floor="approved")


def test_missing_head_sha_raises():
    """Without a SHA a review cannot be bound to reviewed code, so refuse the read
    rather than let submit_pr_review fall back to whatever HEAD is later."""
    _Client.pr = {**PR, "head": {"ref": "feature"}}
    with pytest.raises(RuntimeError, match="no head SHA"):
        _fetch(runner_mod.run_github_pr_read, {"repo": REPO, "pull_number": 42})


def test_oversized_patches_are_dropped_whole():
    """A half-patch reads as a complete change that simply does not apply."""
    _Client.files = [
        {"filename": "big.py", "status": "modified", "additions": 1, "deletions": 0,
         "patch": " ".join(["+line"] * 20000)},
        {"filename": "small.py", "status": "modified", "additions": 1, "deletions": 0,
         "patch": "@@ +1 @@\n+ok"},
    ]
    _, out = _fetch(runner_mod.run_github_pr_read, {"repo": REPO, "pull_number": 42})
    big, small = out["files"]
    assert big.get("patch_omitted") is True and "patch" not in big
    assert small["patch"].endswith("+ok"), "a small patch after a dropped one still fits"
    assert out["patches_omitted"] == 1 and out["files_truncated"] is True


def test_pr_read_requires_an_integer_number():
    with pytest.raises(RuntimeError, match="integer pull_number"):
        _fetch(runner_mod.run_github_pr_read, {"repo": REPO, "pull_number": "latest"})


# ══════════════════════════════════════════════════════════════════════
# 3. submit_pr_review
# ══════════════════════════════════════════════════════════════════════

def _review_plan(event="COMMENT", *, with_pr_read=True):
    steps = []
    if with_pr_read:
        steps.append({"tool": "mcp_github_pr_read", "args": {
            "slot_id": "pr", "capability": "GITHUB_READ", "domain": BASE,
            "mcp_tool": "pulls", "search_params": {"repo": REPO, "pull_number": 42}}})
    steps.append({"tool": "spawn_processor", "args": {
        "reads": ["pr"] if with_pr_read else [], "out_slot": "review",
        "instruction": "Review it."}})
    args = {"repo": REPO, "pull_number": 42, "body_slot": "review"}
    if event is not None:
        args["event"] = event
    steps.append({"tool": "submit_pr_review", "args": args})
    return {"steps": steps}


def _run_review(monkeypatch, plan, *, confirm=1, floor=""):
    async def _fake_processor(reads, reader, writer, *, system_prompt="", agent_id="",
                              timeout=300, api_key=None):
        writer.write("Looks good, one nit on error handling.")

    async def _confirm(_slots):
        return confirm

    monkeypatch.setattr(driver_mod, "run_processor", _fake_processor)
    store = SlotStore()
    _trace.set_tracer(Tracer())
    try:
        return asyncio.run(driver_run(
            f"review {REPO} pull 42", plan, store, IronFlow(store),
            github_token="fake-pat", min_github_integrity=floor,
            confirm_slot=_confirm)), store
    finally:
        _trace.set_tracer(Tracer())


def test_review_posts_and_binds_the_reviewed_commit(monkeypatch):
    result, _ = _run_review(monkeypatch, _review_plan())
    assert result.get("status") == "success", result
    assert result["review_id"] == "777" and result["event"] == "COMMENT"
    assert len(_Client.posted) == 1
    sent = _Client.posted[0]
    assert sent["url"].endswith(f"/repos/{REPO}/pulls/42/reviews")
    assert sent["commit_id"] == SHA, "review must bind to the SHA that was read"
    assert sent["event"] == "COMMENT"
    assert sent["body"] == "Looks good, one nit on error handling."


def test_request_changes_is_allowed(monkeypatch):
    result, _ = _run_review(monkeypatch, _review_plan("REQUEST_CHANGES"))
    assert result.get("status") == "success", result
    assert _Client.posted[0]["event"] == "REQUEST_CHANGES"


def test_approve_is_rejected_by_the_driver(monkeypatch):
    """APPROVE can satisfy branch protection and unblock an automated merge, so
    the write surface stays monotonic. Checked in the handler as well as the
    planner enum — the driver must not depend on plan validation having run."""
    result, _ = _run_review(monkeypatch, _review_plan("APPROVE"))
    assert result.get("status") != "success"
    assert "APPROVE" in result.get("reason", "")
    assert _Client.posted == []


def test_event_defaults_to_the_non_blocking_verdict(monkeypatch):
    result, _ = _run_review(monkeypatch, _review_plan(None))
    assert result.get("status") == "success", result
    assert _Client.posted[0]["event"] == "COMMENT"


def test_review_without_a_pr_read_is_refused(monkeypatch):
    """No head SHA in state means nothing pins the review to reviewed code."""
    plan = _review_plan(with_pr_read=False)
    plan["steps"][0]["args"]["reads"] = []
    store = SlotStore()

    async def _fake_processor(reads, reader, writer, **kw):
        writer.write("Review text.")

    async def _confirm(_slots):
        return 1

    monkeypatch.setattr(driver_mod, "run_processor", _fake_processor)
    _trace.set_tracer(Tracer())
    result = asyncio.run(driver_run(
        f"review {REPO} pull 42", plan, store, IronFlow(store),
        github_token="fake-pat", confirm_slot=_confirm))
    assert result.get("status") != "success"
    assert "mcp_github_pr_read" in result.get("reason", "")
    assert _Client.posted == []


def test_declining_the_prompt_submits_nothing(monkeypatch):
    result, _ = _run_review(monkeypatch, _review_plan(), confirm=0)
    assert result.get("status") != "success"
    assert _Client.posted == []


def test_approve_is_absent_from_the_planner_enum():
    from safehouse.planner import TOOL_SCHEMA
    events = TOOL_SCHEMA["submit_pr_review"].literal_fields["event"]
    assert events == frozenset({"COMMENT", "REQUEST_CHANGES"})
    assert "APPROVE" not in events


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


def test_reviewing_a_different_pr_than_was_read_is_refused(monkeypatch):
    """The plan reads #42 but reviews #99: the review would carry a commit from
    another pull request. Both numbers are task-derived, so this is a planning
    error — caught here rather than as an opaque 422 on a write path."""
    plan = _review_plan()
    plan["steps"][-1]["args"]["pull_number"] = 99
    result, _ = _run_review(monkeypatch, plan)
    assert result.get("status") != "success"
    assert "#99" in result.get("reason", "") and "#42" in result.get("reason", "")
    assert _Client.posted == []


# ══════════════════════════════════════════════════════════════════════
# 4. mcp_github_pr_search — predicate → one PR
# ══════════════════════════════════════════════════════════════════════

def _pr(number, *, assoc="MEMBER", login="octocat", draft=False, title="Add retry"):
    return {"number": number, "title": title, "author_association": assoc,
            "user": {"login": login}, "draft": draft, "state": "open"}


def test_search_selects_latest_and_reads_it():
    _Client.listed_prs = [_pr(9), _pr(4)]
    (sha, num), out = _fetch(runner_mod.run_github_pr_search,
                             {"repo": REPO, "select": "latest"})
    assert num == 9 and sha == SHA
    assert out["number"] == 9, "the selected PR is the one actually read"


def test_explicit_number_short_circuits_the_predicate():
    _Client.listed_prs = []          # list would find nothing
    (sha, num), out = _fetch(runner_mod.run_github_pr_search,
                             {"repo": REPO, "pull_number": 42})
    assert num == 42 and sha == SHA


def test_drafts_are_excluded_by_default():
    """A draft is explicitly not ready for review, so selecting one by predicate
    would target work its author has said is unfinished."""
    _Client.listed_prs = [_pr(9, draft=True), _pr(4)]
    (_, num), _out = _fetch(runner_mod.run_github_pr_search, {"repo": REPO})
    assert num == 4


def test_drafts_can_be_opted_into():
    _Client.listed_prs = [_pr(9, draft=True), _pr(4)]
    (_, num), _out = _fetch(runner_mod.run_github_pr_search,
                            {"repo": REPO, "include_drafts": True})
    assert num == 9


def test_floor_applies_during_selection():
    """An untrusted account must not capture the review by opening a PR."""
    _Client.listed_prs = [_pr(9, assoc="NONE", login="drive-by"), _pr(4, assoc="MEMBER")]
    (_, num), _out = _fetch(runner_mod.run_github_pr_search, {"repo": REPO},
                            floor="approved")
    assert num == 4, "below-floor PR must not be selectable"


def test_author_and_title_predicates_match_locally():
    _Client.listed_prs = [_pr(9, title="Fix flaky test"), _pr(4, title="Add retry")]
    (_, num), _out = _fetch(runner_mod.run_github_pr_search,
                            {"repo": REPO, "title_contains": "flaky"})
    assert num == 9
    _Client.listed_prs = [_pr(9, login="alice"), _pr(4, login="bob")]
    (_, num), _out = _fetch(runner_mod.run_github_pr_search,
                            {"repo": REPO, "author": "bob"})
    assert num == 4


def test_empty_result_explains_why():
    """At a floor of 'approved' on a public repo an empty result is routine;
    'no PR matched' alone reads as a broken tool rather than a policy outcome."""
    _Client.listed_prs = [_pr(9, assoc="NONE"), _pr(4, draft=True)]
    with pytest.raises(RuntimeError) as exc:
        _fetch(runner_mod.run_github_pr_search, {"repo": REPO}, floor="approved")
    msg = str(exc.value)
    assert "2 considered" in msg and "draft" in msg and "approved" in msg


def test_search_publishes_number_and_sha(monkeypatch):
    from safehouse.plan_types import PlanState
    published: list[str] = []
    original = PlanState.set_var

    def _spy(self, key, lval, **kw):
        published.append(key)
        assert str(lval.label) == "(T,pub)"
        return original(self, key, lval, **kw)

    monkeypatch.setattr(PlanState, "set_var", _spy)
    _Client.listed_prs = [_pr(9)]
    result, _ = _run_review(monkeypatch, _search_review_plan())
    assert result.get("status") == "success", result
    assert [k for k in published if k != "_routing"] == [
        driver_mod._GITHUB_PR_SHA_VAR, driver_mod._GITHUB_PR_NUM_VAR]


def _search_review_plan(event="COMMENT"):
    """Review pipeline where the PR is resolved by predicate, not named."""
    args = {"repo": REPO, "body_slot": "review"}
    if event is not None:
        args["event"] = event
    return {"steps": [
        {"tool": "mcp_github_pr_search", "args": {
            "slot_id": "pr", "capability": "GITHUB_READ", "domain": BASE,
            "mcp_tool": "pulls/list",
            "search_params": {"repo": REPO, "select": "latest"}}},
        {"tool": "spawn_processor", "args": {
            "reads": ["pr"], "out_slot": "review", "instruction": "Review it."}},
        {"tool": "submit_pr_review", "args": args},
    ]}


def test_review_via_search_records_the_weaker_provenance(monkeypatch):
    """A resolved target is (T,pub) but discovered mid-run, so the audit must not
    report it as precommitted-before-observation."""
    _Client.listed_prs = [_pr(9)]
    result, _ = _run_review(monkeypatch, _search_review_plan())
    assert result.get("status") == "success", result
    assert result["pull_number"] == 9
    assert result["target_source"] == "search"
    assert _Client.posted[0]["commit_id"] == SHA


def test_review_with_a_named_target_records_the_stronger_provenance(monkeypatch):
    result, _ = _run_review(monkeypatch, _review_plan())
    assert result["target_source"] == "task"


def test_request_changes_via_search_still_requires_confirmation(monkeypatch):
    """The blocking verdict on a predicate-resolved target is the weakest
    combination available, so the human prompt is the load-bearing control."""
    _Client.listed_prs = [_pr(9)]
    result, _ = _run_review(monkeypatch, _search_review_plan("REQUEST_CHANGES"),
                            confirm=0)
    assert result.get("status") != "success"
    assert _Client.posted == []


# ══════════════════════════════════════════════════════════════════════
# 5. Plan-time guards
# ══════════════════════════════════════════════════════════════════════

def _plan_for_validation(params=None, *, reader="search", pull_number=None, read_num=42):
    steps = []
    if reader == "search":
        steps.append({"tool": "mcp_github_pr_search", "args": {
            "domain": BASE, "mcp_tool": "pulls/list", "slot_id": "pr",
            "search_params": params or {}}})
    elif reader == "read":
        sp = {"repo": REPO}
        if read_num is not None:
            sp["pull_number"] = read_num
        steps.append({"tool": "mcp_github_pr_read", "args": {
            "domain": BASE, "mcp_tool": "pulls", "slot_id": "pr", "search_params": sp}})
    else:
        # A reader that resolves no pull number at all.
        steps.append({"tool": "mcp_github_issue_list", "args": {
            "domain": BASE, "mcp_tool": "issues/list", "slot_id": "pr",
            "search_params": {"repo": REPO}}})
    steps.append({"tool": "spawn_processor", "args": {
        "reads": ["pr"], "out_slot": "rb", "instruction": "Review it."}})
    args = {"repo": REPO, "body_slot": "rb"}
    if pull_number is not None:
        args["pull_number"] = pull_number
    steps.append({"tool": "submit_pr_review", "args": args})
    return {"steps": steps}


def _validate(plan, task=None):
    from safehouse.planner import _validate_plan
    _validate_plan(plan, task=task or f"review {REPO} pull 42", operator_context="")


def test_review_requires_the_predicate_to_narrow_to_one_pr():
    """A bare repo/state predicate means 'some pull request'. The review would land
    on whichever sorted first — and REQUEST_CHANGES blocks whatever it lands on.

    Enforced at plan time because the planner's own reluctance to guess a target is
    model judgement, not reproducible.
    """
    from safehouse.planner import PlanValidationError
    with pytest.raises(PlanValidationError, match="narrow to one pull request"):
        _validate(_plan_for_validation({"repo": REPO, "state": "closed"}))


@pytest.mark.parametrize("selector", [
    {"select": "latest"}, {"title_contains": "retry"},
    {"author": "octocat"}, {"pull_number": 42},
])
def test_any_narrowing_selector_is_accepted(selector):
    _validate(_plan_for_validation({"repo": REPO, **selector}))


def test_pr_read_pins_the_target_without_a_selector():
    """pr_read always carries an explicit number, so it pins the target on its own —
    the rule must not forbid a plan that is already fully specified."""
    _validate(_plan_for_validation(reader="read"))


def test_review_with_nothing_resolving_a_target_is_rejected():
    from safehouse.planner import PlanValidationError
    with pytest.raises(PlanValidationError, match="nothing resolves one"):
        _validate(_plan_for_validation(reader="none"))


def test_read_only_listing_is_not_subject_to_the_selector_rule():
    """The asymmetry is deliberate: a broad listing is cheap to get wrong, a review
    is not. mcp_github_issue_list with a bare predicate stays legal."""
    _validate({"steps": [
        {"tool": "mcp_github_issue_list", "args": {
            "domain": BASE, "mcp_tool": "issues/list", "slot_id": "items",
            "search_params": {"repo": REPO, "state": "closed"}}},
        {"tool": "spawn_processor", "args": {
            "reads": ["items"], "out_slot": "d", "instruction": "Summarise."}},
        {"tool": "send_summary", "args": {
            "recipient": "dev@example.com", "subject": "PRs", "body_slot": "d"}},
    ]}, task=f"summarise closed PRs on {REPO} and email dev@example.com")


def test_each_github_read_tool_has_its_own_catalog_line():
    """One capability, providers that do materially different things. A shared
    line would tell the planner that a listing tool 'reads one issue and its
    comments', which is how a listing ends up used as a reader."""
    from safehouse.registry import DEFAULT_REGISTRY, _mcp_to_catalog
    from safehouse.labels import Capability

    lines = {
        spec.name: _mcp_to_catalog(spec).description
        for spec in DEFAULT_REGISTRY._specs.values()
        if spec.capability is Capability.GITHUB_READ
    }
    assert len(lines) >= 5
    assert len(set(lines.values())) == len(lines), (
        f"GITHUB_READ providers sharing a catalog description: {lines}")
    assert "MANY" in lines["mcp_github_issue_list"]
    assert "diff" in lines["mcp_github_pr_read"]
    assert "predicate" in lines["mcp_github_pr_search"]
