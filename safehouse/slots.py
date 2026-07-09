"""
slots.py — Write-once labelled slot store + capability facets.

Two privilege layers:
  Subprocess boundary — Tier 2 LLM has no Python references; nothing here is
                        load-bearing against a malicious model.
  In-process          — runner code receives SlotReader/SlotWriter facets, never
                        the store directly. Slot access control is structural:
                          SlotWriter is fixed to one output slot and one label.
                          SlotReader exposes only the declared input slots; reads
                          outside that set raise KeyError without any gate call.
                        Enforced by tests/test_slot_capabilities.py::TestRunnerDiscipline.

Immutability: values are str only (deeply immutable by type); write-once is
derived from LVal presence — no flag to desync; labels are fixed by the driver
at mint time, never by the writing code.

DRIVER TRANSPORT PATH — the driver reads store.read() directly for terminal
actions, always through IronFlow bridge gates (apply_bridge_field / before_action).
Facets are for runner code only.
"""

from __future__ import annotations

from .labels import Label, LVal
from . import trace as _trace


class SlotStore:
    """
    Session-scoped, write-once store. DRIVER-PRIVILEGED: only driver.run()
    constructs this; sub-agent code receives SlotReader / SlotWriter facets.
    Thread-safe for reads; writes are sequential (one sub-agent per slot).
    """

    def __init__(self) -> None:
        # slot_id -> None (created, unwritten) | LVal (written, immutable)
        self._slots: dict[str, LVal | None] = {}

    # ── Lifecycle (driver only) ───────────────────────────────────────

    def create(self, slot_id: str) -> None:
        if slot_id in self._slots:
            raise ValueError(f"Slot '{slot_id}' already exists.")
        self._slots[slot_id] = None

    def write(self, slot_id: str, value: str, label: Label) -> None:
        """Write-once. Values are str only — deep immutability by type."""
        if not isinstance(value, str):
            raise TypeError(
                f"Slot '{slot_id}': slot values must be str "
                f"(got {type(value).__name__}); store structured data as JSON text."
            )
        self._require(slot_id)
        if self._slots[slot_id] is not None:
            raise RuntimeError(f"Write-once violation: slot '{slot_id}' already written.")
        self._slots[slot_id] = LVal(value, label)

    # ── Access ────────────────────────────────────────────────────────

    def read(self, slot_id: str) -> LVal:
        self._require(slot_id, must_be_written=True)
        return self._slots[slot_id]  # type: ignore[return-value]  # guarded above

    def label_of(self, slot_id: str) -> Label:
        self._require(slot_id, must_be_written=True)
        return self._slots[slot_id].label  # type: ignore[union-attr]  # guarded above

    def exists(self, slot_id: str) -> bool:
        """True if the slot has been created (written or not)."""
        return slot_id in self._slots

    def is_written(self, slot_id: str) -> bool:
        return self._slots.get(slot_id) is not None

    # ── Facet minting (driver only) ───────────────────────────────────

    def reader_for(self, slot_ids: list[str], *,
                   agent_id: str, max_label: Label) -> "SlotReader":
        """
        Mint a scoped read capability for agent_id covering exactly slot_ids.

        Checks label ceiling at construction: every slot's label must be ≤ max_label.
        A slot whose label exceeds max_label cannot be placed in any scoped view for
        this agent — the error surfaces here, not at read time.
        """
        for sid in slot_ids:
            if not self.is_written(sid):
                continue  # label unknown until written; error surfaces at read time
            slot_label = self.label_of(sid)
            if not (slot_label <= max_label):
                raise ValueError(
                    f"LABEL CEILING — agent '{agent_id}' max_label={max_label} "
                    f"but slot '{sid}' label={slot_label}. "
                    f"Cannot include this slot in the scoped view."
                )
        return SlotReader(self, frozenset(slot_ids), agent_id=agent_id)

    def writer_for(self, slot_id: str, label: Label, *,
                   agent_id: str) -> "SlotWriter":
        """Mint a single-use write capability. Label is fixed here by the driver — never by the writer."""
        return SlotWriter(self, slot_id, label, agent_id=agent_id)

    # ── Driver-safe inventory (metadata only) ─────────────────────────

    def inventory(self) -> list[dict]:
        """Slot metadata — id, written, label string. NEVER slot contents."""
        return [
            {
                "id":      sid,
                "written": lval is not None,
                "label":   str(lval.label) if lval is not None else None,
            }
            for sid, lval in self._slots.items()
        ]

    # ── Helpers ───────────────────────────────────────────────────────

    def _require(self, slot_id: str, must_be_written: bool = False) -> None:
        if slot_id not in self._slots:
            raise KeyError(f"Slot '{slot_id}' does not exist.")
        if must_be_written and self._slots[slot_id] is None:
            raise RuntimeError(f"Slot '{slot_id}' has not been written yet.")


# ── Capability facets ─────────────────────────────────────────────────


class SlotReader:
    """
    Scoped read capability for one agent over a declared set of slots.
    The ONLY read path handed to sub-agent runner code.

    Slot access is structural: reads outside _allowed raise KeyError
    without any gate call. Label ceiling is verified at construction by
    SlotStore.reader_for() — not repeated per read.
    """

    __slots__ = ("_store", "_allowed", "_agent_id")

    def __init__(self, store: SlotStore, allowed: frozenset[str], *,
                 agent_id: str) -> None:
        self._store    = store
        self._allowed  = allowed
        self._agent_id = agent_id

    def read(self, slot_id: str) -> LVal:
        if slot_id not in self._allowed:
            raise KeyError(
                f"Slot '{slot_id}' is not in the scoped view for agent '{self._agent_id}'."
            )
        lval = self._store.read(slot_id)
        _trace.emit(_trace.EvSlotRead(
            agent_id=self._agent_id, slot_id=slot_id, label=str(lval.label),
        ))
        return lval


class SlotWriter:
    """
    Single-use write capability for exactly one slot with a driver-fixed label.
    Store write and trace are atomic — the only write path handed to runner code.
    """

    __slots__ = ("_store", "_slot_id", "_label", "_agent_id", "_used")

    def __init__(self, store: SlotStore, slot_id: str, label: Label, *,
                 agent_id: str) -> None:
        self._store    = store
        self._slot_id  = slot_id
        self._label    = label
        self._agent_id = agent_id
        self._used     = False

    @property
    def slot_id(self) -> str:
        return self._slot_id

    @property
    def label(self) -> Label:
        return self._label

    def write(self, content: str) -> None:
        if self._used:
            raise RuntimeError(
                f"SlotWriter for '{self._slot_id}' already used; "
                f"writers are single-use by design."
            )
        self._store.write(self._slot_id, content, self._label)
        self._used = True
        _trace.emit(_trace.EvSlotWritten(
            agent_id=self._agent_id, slot_id=self._slot_id,
            label=str(self._label), chars=len(content),
        ))
