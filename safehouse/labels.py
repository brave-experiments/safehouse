"""
labels.py — Information-flow label lattice  L = I × C

  I ∈ {T, U}         integrity:       T = trusted, U = untrusted
  C ∈ {pub, priv}    confidentiality: pub ⊑ priv (pub is less sensitive)

Lattice ordering (⊑):  (U,pub) ⊑ (U,priv) ⊑ (T,priv)
                        (U,pub) ⊑ (T,pub)  ⊑ (T,priv)
The two middle elements (U,priv) and (T,pub) are incomparable.

Taint propagation — one function, two axes, opposite directions:

  taint_all(inputs) — the only operation used to compute output labels.

    Integrity axis:       MEET  — one untrusted input makes the output untrusted.
                          Rationale: an LLM processing trusted data is still an
                          untrusted processor; one bad input corrupts the chain.

    Confidentiality axis: JOIN  — one private input makes the output private.
                          Rationale: a processor reading private email produces
                          private output regardless of other inputs.

    Empty inputs → (T, pub): no inputs means no taint.

Ordering (⊑) is used for label bound checks (structural, not via gate methods):
  label ceiling  slot_label ⊑ agent.max_label   (enforced at SlotReader construction)
  label floor    actual_label ⊑ max_label        (enforced by driver-minted SlotWriter label)


"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering
from typing import Iterable, Any


# ── Integrity axis ────────────────────────────────────────────────────
@total_ordering
class I(Enum):
    T = "T"   # trusted
    U = "U"   # untrusted

    def meet(self, other: "I") -> "I":
        """Lattice meet (⊓). U is bottom: meet(T, U) = U."""
        return I.U if (self == I.U or other == I.U) else I.T

    def __le__(self, other: object) -> bool:   # self ⊑ other
        if not isinstance(other, I):
            return NotImplemented
        return self == I.U or other == I.T



# ── Confidentiality axis ──────────────────────────────────────────────
@total_ordering
class C(Enum):
    pub  = "pub"
    priv = "priv"

    def join(self, other: "C") -> "C":
        """Lattice join (⊔). priv is top: join(pub, priv) = priv."""
        return C.priv if (self == C.priv or other == C.priv) else C.pub

    def __le__(self, other: object) -> bool:   # self ⊑ other
        if not isinstance(other, C):
            return NotImplemented
        return self == C.pub or other == C.priv


# ── Combined label ────────────────────────────────────────────────────
@dataclass(frozen=True)
class Label:
    """
    Product label L = I × C.

    """
    integrity:       I
    confidentiality: C

    # ── Convenience constructors ──
    @staticmethod
    def T_pub()  -> "Label": return Label(I.T, C.pub)
    @staticmethod
    def T_priv() -> "Label": return Label(I.T, C.priv)
    @staticmethod
    def U_pub()  -> "Label": return Label(I.U, C.pub)
    @staticmethod
    def U_priv() -> "Label": return Label(I.U, C.priv)

    # ⊑ ordering
    def __le__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return (self.integrity <= other.integrity and
                self.confidentiality <= other.confidentiality)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return other <= self

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return self <= other and self != other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return other < self

    def __str__(self) -> str:
        return f"({self.integrity.value},{self.confidentiality.value})"

    def __repr__(self) -> str:
        return f"Label{self}"


def taint_all(labels: Iterable[Label]) -> Label:
    """
    Taint propagation over a computation's inputs.

    Integrity axis:       MEET  — any U input makes the output U.
    Confidentiality axis: JOIN  — any priv input makes the output priv.
    Empty collection:     (T, pub) — no inputs → output is fully trusted and public.

    Use this whenever computing the output label of a computation from its inputs.
    """
    integrity       = I.T    # identity for meet: start maximally trusted
    confidentiality = C.pub  # identity for join: start maximally public
    empty = True
    for lbl in labels:
        integrity       = integrity.meet(lbl.integrity)
        confidentiality = confidentiality.join(lbl.confidentiality)
        empty = False
    if empty:
        return Label.T_pub()
    return Label(integrity, confidentiality)


# ── Labelled value ────────────────────────────────────────────────────
@dataclass(frozen=True)
class LVal:
    """
    A value paired with its provenance label.
    The label lives here — NOT inside the value.
    LLMs never see the label; only IronFlow does.
    """
    value: Any
    label: Label

    def __str__(self) -> str:
        if self.label.confidentiality == C.priv:
            preview = "<private: redacted>"
        else:
            preview = repr(self.value)[:60]
        return f"LVal({preview}, {self.label})"


# ── Capability taxonomy and label policy ──────────────────────────────
#
# Capability classifies what kind of data source an agent fetches from.
# CAPABILITY_LABEL is the single source of truth for the label each
# capability type produces — all providers of the same capability produce
# the same label, regardless of which MCPSpec the planner selects.
# Defined here (not in registry.py) because this is label policy, not
# provider config.

class Capability(Enum):
    # Public capabilities → label (U, pub)
    # Fetched from public services; content is untrusted but not private.
    WEB_FETCH      = "WEB_FETCH"
    FLIGHT_SEARCH  = "FLIGHT_SEARCH"
    HOTEL_SEARCH   = "HOTEL_SEARCH"

    # Private capabilities → label (U, priv)
    # Content is both untrusted (external) and private (confidential).
    # Cannot cross the IronFlow bridge without explicit driver declassification.
    EMAIL_READ     = "EMAIL_READ"
    CALENDAR_READ  = "CALENDAR_READ"


CAPABILITY_LABEL: dict[Capability, Label] = {
    Capability.WEB_FETCH:     Label.U_pub(),
    Capability.FLIGHT_SEARCH: Label.U_pub(),
    Capability.HOTEL_SEARCH:  Label.U_pub(),
    Capability.EMAIL_READ:    Label.U_priv(),
    Capability.CALENDAR_READ: Label.U_priv(),
}


