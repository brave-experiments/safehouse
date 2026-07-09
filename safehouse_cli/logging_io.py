"""
logging_io.py — Session identity, structured JSONL trace, and TeeStream.

Design notes:
  - Session id is the single correlation key: same id in EvStaticPlan,
    both filenames, and RunResult. Replaces the timestamp filename (1-second
    resolution → silent clobber; no log↔trace correlation).
  - JsonlTraceSink is SENSITIVE: planner events include the full system prompt
    and operator context (may contain personal emails). Never print jsonl_path
    contents to stdout under --json.
  - TeeStream teeing both stdout AND stderr captures tracebacks (the most
    important failure content) which the old _Tee missed entirely.
  - Streams are restored via contextlib.ExitStack so restoration survives
    exceptions and KeyboardInterrupt.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from safehouse.trace import Tracer, Event


# ── Session ───────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class Session:
    """
    Immutable identity for one pipeline run.

    id           — used as filename prefix and in EvStaticPlan.session_id
    jsonl_path   — structured event log (one JSON line per event); SENSITIVE
    transcript_path — human-readable stdout+stderr tee
    """
    id:               str
    jsonl_path:       Path
    transcript_path:  Path

    @classmethod
    def new(cls, results_dir: Path, prefix: str = "sess") -> "Session":
        """Create a new session with a unique id under results_dir."""
        results_dir.mkdir(parents=True, exist_ok=True)
        sid = f"{prefix}_{uuid.uuid4().hex[:12]}"
        return cls(
            id              = sid,
            jsonl_path      = results_dir / f"{sid}.jsonl",
            transcript_path = results_dir / f"{sid}.txt",
        )

    def rename_prefix(self, new_prefix: str) -> "Session":
        """Return a new Session whose id uses new_prefix, keeping the same hex suffix."""
        hex_suffix = self.id.split("_", 1)[-1]
        new_id = f"{new_prefix}_{hex_suffix}"
        results_dir = self.jsonl_path.parent
        return Session(
            id              = new_id,
            jsonl_path      = results_dir / f"{new_id}.jsonl",
            transcript_path = results_dir / f"{new_id}.txt",
        )


# ── JsonlTraceSink ────────────────────────────────────────────────────


def _event_to_dict(event: Event) -> dict:
    """Convert an event dataclass to a JSON-serialisable dict."""
    try:
        d = dataclasses.asdict(event)
    except TypeError:
        # Fallback for non-dataclass events (shouldn't happen in practice).
        d = vars(event) if hasattr(event, "__dict__") else {"repr": repr(event)}

    # Make frozensets serialisable.
    def _convert(obj):
        if isinstance(obj, frozenset):
            return sorted(str(x) for x in obj)
        if isinstance(obj, set):
            return sorted(str(x) for x in obj)
        return obj

    def _walk(obj):
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_walk(v) for v in obj]
        return _convert(obj)

    return _walk(d)


class JsonlTraceSink(Tracer):
    """
    Trace sink that writes every event as one JSON line to a file.

    Lines are flushed immediately (buffering=1 on the file handle) so partial
    traces are durable on crash or KeyboardInterrupt.

    SENSITIVE: this file may contain the full planner system prompt, operator
    context, and personal email addresses. Never expose its contents to stdout.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fh = path.open("w", buffering=1, encoding="utf-8")

    def on_event(self, event: Event) -> None:
        line = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "event": type(event).__name__,
            **_event_to_dict(event),
        }
        try:
            self._fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        except Exception:
            pass  # never let a logging failure crash the pipeline

    def rename(self, new_path: Path) -> None:
        """Close the current file, rename it on disk, reopen at the new path."""
        try:
            self._fh.close()
        except Exception:
            pass
        try:
            self._path.rename(new_path)
        except Exception:
            pass
        self._path = new_path
        try:
            self._fh = new_path.open("a", buffering=1, encoding="utf-8")
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ── TeeStream ─────────────────────────────────────────────────────────


class TeeStream(io.TextIOBase):
    """
    A text stream that writes to both the original stream and a log file.

    Fixes two issues with the old _Tee:
      1. _Tee was not a proper io.TextIOBase subclass — fileno/encoding/writable
         were missing, breaking subprocess and readline consumers.
      2. _Tee only teed stdout; stderr (tracebacks, the most important failure
         content) went uncaptured.

    Usage via tee_streams() context manager below — never install manually.
    """

    def __init__(self, original: io.TextIOBase, log: io.TextIOBase) -> None:
        self._orig = original
        self._log  = log

    def write(self, data: str) -> int:
        self._orig.write(data)
        self._log.write(data)
        return len(data)

    def flush(self) -> None:
        self._orig.flush()
        self._log.flush()

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        try:
            return self._orig.isatty()
        except Exception:
            return False

    def fileno(self) -> int:
        return self._orig.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self._orig, "encoding", "utf-8")

    @property
    def errors(self) -> str | None:
        return getattr(self._orig, "errors", None)

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False


@contextlib.contextmanager
def tee_streams(path: Path):
    """
    Context manager: tee both sys.stdout and sys.stderr to `path`.

    Streams are always restored on exit, even after exceptions or
    KeyboardInterrupt, via contextlib.ExitStack.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        log = stack.enter_context(path.open("w", buffering=1, encoding="utf-8"))

        orig_out = sys.stdout
        orig_err = sys.stderr
        sys.stdout = TeeStream(orig_out, log)
        sys.stderr = TeeStream(orig_err, log)
        stack.callback(setattr, sys, "stdout", orig_out)
        stack.callback(setattr, sys, "stderr", orig_err)

        yield
