"""
tests/test_ironflow_gates.py — Focused gate-level tests for IronFlow.

Covers the six auditor-specified invariants (T1–T6):

  T1 — _require emits EvGate(passed=False) before raising IronFlowViolation
  T2 — declassify logs to _declassify_log, not _audit; clean() stays True
  T3 — ROUTING with integrity=U → INTEGRITY_GATE / "IPI BLOCKED"
  T4 — ROUTING with (T,priv) → CONFINEMENT / "ROUTING CONFIDENTIALITY" (C8)
  T5 — CONTENT with confidentiality=priv → CONFINEMENT / "EXFILTRATION BLOCKED"
  T6 — Unknown role → ValueError, no audit entry, no IronFlowViolation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from safehouse.labels import Label, LVal
from safehouse.slots import SlotStore
from safehouse.ironflow_policy import IronFlow, IronFlowViolation, Principle, Role
from safehouse.plan_types import PlanState
from safehouse import trace as _trace
from safehouse.trace import Tracer


T_pub  = Label.T_pub()
T_priv = Label.T_priv()
U_pub  = Label.U_pub()
U_priv = Label.U_priv()


class _CapturingTracer(Tracer):
    """Tracer that records all emitted events for assertion."""
    def __init__(self):
        self.events: list = []

    def on_event(self, event) -> None:
        self.events.append(event)

    def gate_events(self) -> list[_trace.EvGate]:
        return [e for e in self.events if isinstance(e, _trace.EvGate)]


_NULL = Tracer()   # base class on_event is a no-op — safe reset target


@pytest.fixture(autouse=True)
def _reset_tracer():
    """Ensure each test starts and ends with a no-op tracer."""
    _trace.set_tracer(_NULL)
    yield
    _trace.set_tracer(_NULL)


def _precommitted_slot(
    value: str, label: Label, slot_id: str = "body", *, sources: set[str] | None = None,
    transform: str | None = None,
):
    store = SlotStore()
    policy = IronFlow(store)
    state = PlanState()
    state.set_var("_routing", LVal({"recipient": "safe@example.com"}, T_pub))
    src = sources if sources is not None else {slot_id}
    xf = transform if transform is not None else ("opaque" if src else None)
    policy.precommit_routing(state, sources=src, transform=xf)
    store.create(slot_id)
    store.write(slot_id, value, label)
    return store, policy, state


# ── T1 — _require emits EvGate(passed=False) before raising ───────────────────

class TestRequireEmitsBeforeRaising:
    def test_require_emits_failed_gate_event_before_exception(self):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation):
            policy.before_action("send_summary", "recipient",
                                 LVal("x@bad.com", U_pub), Role.ROUTING)
        gate_events = tracer.gate_events()
        # At least one failed gate event must have been emitted
        failed = [e for e in gate_events if not e.passed]
        assert failed, "No failed EvGate emitted before IronFlowViolation"
        assert failed[0].blocked is not None

    def test_require_violation_is_in_audit_log(self):
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation):
            policy.before_action("send_summary", "recipient",
                                 LVal("x@bad.com", U_pub), Role.ROUTING)
        assert len(policy.violations()) == 1
        assert not policy.clean()

    @pytest.mark.parametrize("operation", ["precommit", "declassify"])
    def test_new_confinement_denials_emit_failed_gate(self, operation):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        policy = IronFlow(SlotStore())

        with pytest.raises(IronFlowViolation):
            if operation == "precommit":
                policy.precommit_routing(PlanState(), sources=set())
            else:
                policy.declassify_slot("body", state=PlanState(), reason="test")

        failed = [event for event in tracer.gate_events() if not event.passed]
        assert failed[-1].gate in {"PRECOMMIT", "DECLASSIFY"}
        assert failed[-1].blocked


# ── T2 — declassify goes to _declassify_log, not _audit ───────────────────────

class TestDeclassifyDoesNotPollutAudit:
    def test_declassify_does_not_add_to_violations(self):
        _, policy, state = _precommitted_slot("email body", U_priv)
        policy.declassify_slot("body", state=state, reason="routing pre-committed")
        assert policy.violations() == [], "declassify must not add to violations"
        assert policy.clean()

    def test_declassify_appears_in_declassify_log(self):
        _, policy, state = _precommitted_slot("email body", U_priv)
        policy.declassify_slot("body", state=state, reason="routing pre-committed")
        log = policy.declassify_log()
        assert len(log) == 1
        assert "body" in log[0]
        assert "routing pre-committed" in log[0]

    def test_declassify_event_contains_checked_evidence(self):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        _, policy, state = _precommitted_slot("email body", U_priv)
        policy.declassify_slot("body", state=state, reason="send to locked recipient")

        event = next(e for e in tracer.events if isinstance(e, _trace.EvDeclassify))
        assert event.field == "body"
        assert event.authority == "DRIVER"
        assert any("before every sub-agent spawn" in p for p in event.preconditions)
        assert any("write-once slot 'body'" in p for p in event.preconditions)
        assert any("listed in precommit release sources" in p for p in event.preconditions)

    def test_declassify_lowers_confidentiality_only(self):
        _, policy, state = _precommitted_slot("secret", U_priv)
        result = policy.declassify_slot("body", state=state, reason="test")
        assert result.label == U_pub          # integrity unchanged (U), priv→pub
        assert result.value == "secret"

    def test_declassify_already_public_is_idempotent(self):
        """Declassify on already-public data is a no-op on the label (C7)."""
        _, policy, state = _precommitted_slot("public body", U_pub)
        result = policy.declassify_slot("body", state=state, reason="public no-op")
        assert result.label == U_pub          # no change
        assert policy.clean()

    def test_public_noop_is_not_logged_as_declassification(self):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        _, policy, state = _precommitted_slot("public body", U_pub)
        result = policy.declassify_slot("body", state=state, reason="public")
        assert result.label == U_pub
        assert policy.declassify_log() == []
        assert not any(isinstance(e, _trace.EvDeclassify) for e in tracer.events)

    def test_declassify_empty_reason_raises(self):
        _, policy, state = _precommitted_slot("x", U_priv)
        with pytest.raises(ValueError, match="reason must be non-empty"):
            policy.declassify_slot("body", state=state, reason="")

    def test_declassify_requires_routing_precommit(self):
        store = SlotStore()
        store.create("body")
        store.write("body", "secret", U_priv)
        policy = IronFlow(store)
        with pytest.raises(IronFlowViolation, match="not bound"):
            policy.declassify_slot("body", state=PlanState(), reason="test")

    def test_declassify_requires_written_slot(self):
        store = SlotStore()
        policy = IronFlow(store)
        state = PlanState()
        state.set_var("_routing", LVal({"recipient": "safe@example.com"}, T_pub))
        policy.precommit_routing(state, sources={"body"}, transform="opaque")
        store.create("body")
        with pytest.raises(IronFlowViolation, match="missing or unwritten"):
            policy.declassify_slot("body", state=state, reason="test")

    def test_precommit_requires_routing_var(self):
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation, match="must be \\(T,pub\\)"):
            policy.precommit_routing(PlanState(), sources=set())

    def test_precommit_is_one_shot(self):
        policy = IronFlow(SlotStore())
        state = PlanState()
        state.set_var("_routing", LVal({"recipient": "safe@example.com"}, T_pub))
        policy.precommit_routing(state, sources={"body"}, transform="opaque")
        with pytest.raises(IronFlowViolation, match="already precommitted"):
            policy.precommit_routing(state, sources={"body"}, transform="opaque")

    def test_precommit_rejects_empty_routing(self):
        policy = IronFlow(SlotStore())
        state = PlanState()
        state.set_var("_routing", LVal({}, T_pub))
        with pytest.raises(IronFlowViolation, match="non-empty mapping"):
            policy.precommit_routing(state, sources=set())

    def test_precommit_allows_empty_sources(self):
        """Routing-only tools (modify_emails) precommit with no release slots."""
        policy = IronFlow(SlotStore())
        state = PlanState()
        state.set_var("_routing", LVal({"sender": "a@corp.com", "action": "archive"}, T_pub))
        policy.precommit_routing(state, sources=set())
        assert policy._sources == frozenset()
        assert policy.release_transform() is None

    def test_precommit_requires_transform_when_sources_nonempty(self):
        policy = IronFlow(SlotStore())
        state = PlanState()
        state.set_var("_routing", LVal({"recipient": "safe@example.com"}, T_pub))
        with pytest.raises(IronFlowViolation, match="transform id"):
            policy.precommit_routing(state, sources={"body"})

    def test_precommit_rejects_transform_when_sources_empty(self):
        policy = IronFlow(SlotStore())
        state = PlanState()
        state.set_var("_routing", LVal({"sender": "a@corp.com", "action": "archive"}, T_pub))
        with pytest.raises(IronFlowViolation, match="transform=None"):
            policy.precommit_routing(state, sources=set(), transform="opaque")

    def test_declassify_rejects_slot_not_in_sources(self):
        store, policy, state = _precommitted_slot("secret", U_priv, sources={"body"})
        store.create("email_raw")
        store.write("email_raw", "should not release", U_priv)
        with pytest.raises(IronFlowViolation, match="not in this run's release sources"):
            policy.declassify_slot("email_raw", state=state, reason="test")
        assert store.read("email_raw").label == U_priv
        assert store.read("body").label == U_priv

    def test_declassify_rejects_different_plan_state(self):
        store, policy, _ = _precommitted_slot("secret", U_priv)
        other = PlanState()
        other.set_var(
            "_routing",
            LVal({"recipient": "attacker@example.com"}, T_pub),
        )
        with pytest.raises(IronFlowViolation, match="not bound"):
            policy.declassify_slot("body", state=other, reason="test")
        assert store.read("body").label == U_priv


# ── T3 — ROUTING with integrity=U → INTEGRITY_GATE / "IPI BLOCKED" ────────────

class TestRoutingIntegrityGate:
    def test_U_pub_routing_raises_integrity_gate(self):
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation, match="IPI BLOCKED") as exc_info:
            policy.before_action("send_summary", "recipient",
                                 LVal("x@corp.com", U_pub), Role.ROUTING)
        assert exc_info.value.principle is Principle.INTEGRITY_GATE

    def test_U_priv_routing_raises_integrity_gate(self):
        """U takes priority over priv — integrity is checked first."""
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation, match="IPI BLOCKED") as exc_info:
            policy.before_action("send_summary", "recipient",
                                 LVal("x@corp.com", U_priv), Role.ROUTING)
        assert exc_info.value.principle is Principle.INTEGRITY_GATE

    def test_T_pub_routing_passes(self):
        policy = IronFlow(SlotStore())
        policy.before_action("send_summary", "recipient",
                             LVal("alice@corp.com", T_pub), Role.ROUTING)
        assert policy.clean()


# ── T4 — ROUTING with (T,priv) → CONFINEMENT / "ROUTING CONFIDENTIALITY" ──────

class TestRoutingConfidentialityGate:
    def test_T_priv_routing_raises_confinement(self):
        """(T,priv) passes integrity but fails confidentiality (C8)."""
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation,
                           match="ROUTING CONFIDENTIALITY") as exc_info:
            policy.before_action("send_summary", "recipient",
                                 LVal("alice@corp.com", T_priv), Role.ROUTING)
        assert exc_info.value.principle is Principle.CONFINEMENT

    def test_T_priv_routing_emits_failed_gate(self):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation, match="ROUTING CONFIDENTIALITY"):
            policy.before_action("send_summary", "recipient",
                                 LVal("alice@corp.com", T_priv), Role.ROUTING)
        failed = [e for e in tracer.gate_events() if not e.passed]
        assert any("ROUTING CONFIDENTIALITY" in (e.blocked or "") for e in failed)

    def test_plain_string_role_accepted(self):
        """before_action accepts plain strings as well as Role members."""
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation, match="ROUTING CONFIDENTIALITY"):
            policy.before_action("send_summary", "recipient",
                                 LVal("alice@corp.com", T_priv), "ROUTING")


# ── T5 — CONTENT with priv → CONFINEMENT / "EXFILTRATION BLOCKED" ─────────────

class TestContentConfinementGate:
    def test_priv_content_raises_confinement(self):
        policy = IronFlow(SlotStore())
        with pytest.raises(IronFlowViolation,
                           match="EXFILTRATION BLOCKED") as exc_info:
            policy.before_action("send_summary", "body",
                                 LVal("private text", U_priv), Role.CONTENT)
        assert exc_info.value.principle is Principle.CONFINEMENT

    def test_U_pub_content_passes(self):
        policy = IronFlow(SlotStore())
        policy.before_action("send_summary", "body",
                             LVal("public summary", U_pub), Role.CONTENT)
        assert policy.clean()

    def test_T_pub_content_passes(self):
        policy = IronFlow(SlotStore())
        policy.before_action("send_summary", "body",
                             LVal("trusted public", T_pub), Role.CONTENT)
        assert policy.clean()


# ── T6 — Unknown role → ValueError, no audit, no IronFlowViolation ────────────

class TestUnknownRoleIsValueError:
    def test_unknown_role_raises_value_error_not_violation(self):
        policy = IronFlow(SlotStore())
        with pytest.raises(ValueError, match="unknown role"):
            policy.before_action("send_summary", "field",
                                 LVal("x", T_pub), "BOGUS_ROLE")

    def test_unknown_role_does_not_add_to_audit(self):
        """ValueError is a programmer error — must not appear in the security audit log."""
        policy = IronFlow(SlotStore())
        try:
            policy.before_action("send_summary", "field",
                                 LVal("x", T_pub), "BOGUS_ROLE")
        except ValueError:
            pass
        assert policy.violations() == []
        assert policy.clean()
