"""
tests/test_slot_capabilities.py — SlotReader / SlotWriter capability facets.

Three sections:
  S1 — SlotWriter: single-use, str-only, store+trace atomically (no gate call)
  S2 — SlotReader: structural scoping + label ceiling at construction + trace
  S3 — Discipline: runner.py must not call store/policy APIs directly
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from safehouse.labels import Label, LVal, I, C
from safehouse.slots import SlotStore
from safehouse.ironflow_policy import IronFlow
from safehouse import trace as _trace
from safehouse.trace import Tracer


T_pub  = Label.T_pub()
T_priv = Label.T_priv()
U_pub  = Label.U_pub()
U_priv = Label.U_priv()


class _CapturingTracer(Tracer):
    def __init__(self) -> None:
        self.events: list = []

    def on_event(self, event) -> None:
        self.events.append(event)


_NULL = Tracer()


@pytest.fixture(autouse=True)
def _reset_tracer():
    _trace.set_tracer(_NULL)
    yield
    _trace.set_tracer(_NULL)


def _make_writer(slot_id: str = "out", label: Label = U_pub):
    """Helper: store with one created slot and a writer for it."""
    store = SlotStore()
    store.create(slot_id)
    writer = store.writer_for(slot_id, label, agent_id="fetch_agent")
    return store, writer


def _make_reader(slot_id: str = "src", content: str = "hello",
                 slot_label: Label = U_pub, max_label: Label = U_pub):
    """Helper: store with one written slot and a scoped reader for it."""
    store = SlotStore()
    store.create(slot_id)
    store.write(slot_id, content, slot_label)
    store.create("out")
    reader = store.reader_for([slot_id], agent_id="proc_agent", max_label=max_label)
    return store, reader


# ── S1 — SlotWriter ───────────────────────────────────────────────────

class TestSlotWriter:
    def test_write_stores_content(self):
        store, writer = _make_writer()
        writer.write("hello world")
        assert store.read("out").value == "hello world"

    def test_write_stamps_label(self):
        store, writer = _make_writer(label=U_pub)
        writer.write("content")
        assert store.read("out").label == U_pub

    def test_slot_id_property(self):
        _, writer = _make_writer(slot_id="myslot")
        assert writer.slot_id == "myslot"

    def test_label_property(self):
        _, writer = _make_writer(label=U_pub)
        assert writer.label == U_pub

    def test_write_emits_ev_slot_written(self):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        _, writer = _make_writer()
        writer.write("data")
        written = [e for e in tracer.events if isinstance(e, _trace.EvSlotWritten)]
        assert len(written) == 1
        assert written[0].slot_id == "out"
        assert written[0].chars == 4

    def test_write_is_single_use(self):
        _, writer = _make_writer()
        writer.write("first")
        with pytest.raises(RuntimeError, match="already used"):
            writer.write("second")

    def test_write_rejects_non_str(self):
        store, _ = _make_writer()
        with pytest.raises(TypeError):
            store.write("out", 42, U_pub)  # type: ignore[arg-type]


# ── S2 — SlotReader ───────────────────────────────────────────────────

class TestSlotReader:
    def test_read_returns_lval(self):
        _, reader = _make_reader(content="world")
        lval = reader.read("src")
        assert lval.value == "world"
        assert lval.label == U_pub

    def test_read_emits_ev_slot_read(self):
        tracer = _CapturingTracer()
        _trace.set_tracer(tracer)
        _, reader = _make_reader()
        reader.read("src")
        read_events = [e for e in tracer.events if isinstance(e, _trace.EvSlotRead)]
        assert len(read_events) == 1
        assert read_events[0].slot_id == "src"

    def test_read_outside_scope_raises(self):
        """Reading a slot not in the scoped view raises KeyError."""
        store = SlotStore()
        store.create("a"); store.write("a", "data", U_pub)
        store.create("b"); store.write("b", "secret", U_pub)
        reader = store.reader_for(["a"], agent_id="proc", max_label=U_pub)
        lval = reader.read("a")
        assert lval.value == "data"
        with pytest.raises(KeyError, match="not in the scoped view"):
            reader.read("b")

    def test_label_ceiling_at_construction(self):
        """reader_for raises ValueError if any slot's label exceeds max_label."""
        store = SlotStore()
        store.create("priv"); store.write("priv", "secret", U_priv)
        with pytest.raises(ValueError, match="LABEL CEILING"):
            store.reader_for(["priv"], agent_id="proc", max_label=U_pub)

    def test_read_unwritten_slot_raises(self):
        store = SlotStore()
        store.create("pending")
        reader = store.reader_for(["pending"], agent_id="proc", max_label=U_pub)
        with pytest.raises(RuntimeError, match="not been written"):
            reader.read("pending")


# ── S3 — Discipline: runner.py must not bypass facets ─────────────────

class TestRunnerDiscipline:
    """runner.py must not call store/policy APIs directly — only via facets."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        runner_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "safehouse", "runner.py",
        )
        with open(runner_path) as f:
            self._src = f.read()

    def test_no_store_write(self):
        assert "store.write(" not in self._src, \
            "runner.py must not call store.write() directly — use writer.write()"

    def test_no_store_read(self):
        assert "store.read(" not in self._src, \
            "runner.py must not call store.read() directly — use reader.read()"

    def test_no_before_write(self):
        assert "before_write(" not in self._src, \
            "runner.py must not call policy.before_write() directly — handled by SlotWriter"

    def test_no_before_read(self):
        assert "before_read(" not in self._src, \
            "runner.py must not call policy.before_read() directly — handled by SlotReader"

    def test_no_ds_save(self):
        assert "_ds.save(" not in self._src, \
            "runner.py must not call _ds.save() — data_slots has been eliminated"

    def test_run_mcp_search_no_bare_slot_id(self):
        """run_mcp_search no longer takes slot_id; verify no stale references remain."""
        import ast
        tree = ast.parse(self._src)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_mcp_search":
                params = {a.arg for a in node.args.args}
                assert "slot_id" not in params, \
                    "run_mcp_search must not have slot_id parameter"
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and child.id == "slot_id":
                        raise AssertionError(
                            f"run_mcp_search references bare 'slot_id' at line {child.lineno} "
                            f"— use writer.slot_id instead"
                        )
