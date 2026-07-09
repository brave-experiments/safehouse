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
from safehouse.labels import Label, LVal, I, C
from safehouse.slots import SlotStore
from safehouse.ironflow_policy import IronFlow, IronFlowViolation, Principle, Role
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


# ── T2 — declassify goes to _declassify_log, not _audit ───────────────────────

class TestDeclassifyDoesNotPollutAudit:
    def test_declassify_does_not_add_to_violations(self):
        policy = IronFlow(SlotStore())
        lval = LVal("email body", U_priv)
        policy.declassify(lval, field="body", reason="routing pre-committed")
        assert policy.violations() == [], "declassify must not add to violations"
        assert policy.clean()

    def test_declassify_appears_in_declassify_log(self):
        policy = IronFlow(SlotStore())
        lval = LVal("email body", U_priv)
        policy.declassify(lval, field="body", reason="routing pre-committed")
        log = policy.declassify_log()
        assert len(log) == 1
        assert "body" in log[0]
        assert "routing pre-committed" in log[0]

    def test_declassify_lowers_confidentiality_only(self):
        policy = IronFlow(SlotStore())
        lval = LVal("secret", U_priv)
        result = policy.declassify(lval, field="body", reason="test")
        assert result.label == U_pub          # integrity unchanged (U), priv→pub
        assert result.value == "secret"

    def test_declassify_already_public_is_idempotent(self):
        """Declassify on already-public data is a no-op on the label (C7)."""
        policy = IronFlow(SlotStore())
        lval = LVal("public body", U_pub)
        result = policy.declassify(lval, field="body", reason="uniform audit")
        assert result.label == U_pub          # no change
        assert policy.clean()

    def test_declassify_empty_reason_raises(self):
        policy = IronFlow(SlotStore())
        with pytest.raises(ValueError, match="reason must be non-empty"):
            policy.declassify(LVal("x", U_priv), field="body", reason="")


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
