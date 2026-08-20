"""
tests/test_credential_isolation.py — invariant #6, the ambient-environment half.

Invariant #6 says credentials are resolved in the CLI layer and passed into core
as explicit parameters. Two structural consequences follow, and neither was
covered by a test:

  1. Nothing writes a credential into `os.environ`. A process-wide environment is
     inherited by anything spawned later and readable by any code in the process,
     so writing a secret there re-creates the ambient channel that passing
     parameters was meant to remove.

  2. Nothing under `safehouse/` reads the environment at all. Credential
     resolution is the CLI's job; if core can fall back to an env var, a caller
     that forgets to thread a key still works locally and the parameter stops
     being load-bearing.

Both are asserted on the AST rather than on source text, so the prose in a
docstring explaining why we don't do something cannot trip them — and cannot
satisfy them either.

These are whole-directory sweeps, not spot checks: the failure they guard
against is a *new* module quietly reintroducing the pattern.
"""
import ast
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

REPO = Path(__file__).resolve().parent.parent
CORE = REPO / "safehouse"
CLI  = REPO / "safehouse_cli"

# Mutating an environment through any of these is equivalent to assigning to it.
_ENV_MUTATORS = {"update", "setdefault", "pop", "clear", "putenv", "unsetenv"}


def _sources(*roots: Path) -> list[tuple[Path, ast.Module]]:
    """Every first-party module under `roots`, parsed. Build artefacts excluded."""
    out = []
    for root in roots:
        paths = sorted(root.rglob("*.py")) if root.is_dir() else [root]
        for path in paths:
            if "__pycache__" in path.parts or "build" in path.parts:
                continue
            out.append((path, ast.parse(path.read_text(), filename=str(path))))
    assert out, f"no modules found under {roots} — the sweep would vacuously pass"
    return out


def _is_environ(node: ast.AST) -> bool:
    """True for `os.environ` / `environ` / `os.environb`, however imported."""
    if isinstance(node, ast.Attribute):
        return node.attr in ("environ", "environb")
    if isinstance(node, ast.Name):
        return node.id in ("environ", "environb")
    return False


def _env_writes(tree: ast.Module) -> list[tuple[int, str]]:
    """Locate every statement that mutates a process environment."""
    hits: list[tuple[int, str]] = []

    def targets(node):
        if isinstance(node, ast.Assign):    return node.targets
        if isinstance(node, (ast.AugAssign, ast.AnnAssign)): return [node.target]
        if isinstance(node, ast.Delete):    return node.targets
        return []

    for node in ast.walk(tree):
        # os.environ[...] = / += / del os.environ[...] / os.environ = ...
        for tgt in targets(node):
            if isinstance(tgt, ast.Subscript) and _is_environ(tgt.value):
                hits.append((node.lineno, "assignment into os.environ"))
            elif _is_environ(tgt):
                hits.append((node.lineno, "rebinding os.environ"))

        # os.environ.update(...) / os.putenv(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _ENV_MUTATORS:
                base = node.func.value
                if _is_environ(base) or (isinstance(base, ast.Name) and base.id == "os"):
                    if node.func.attr in ("putenv", "unsetenv") or _is_environ(base):
                        hits.append((node.lineno, f"os.environ.{node.func.attr}()"))
    return hits


def test_nothing_writes_a_credential_into_the_environment():
    """A resolved key must stay a parameter — never be materialized into env.

    This regressed once: the CLI wrote the resolved Anthropic key back to
    ANTHROPIC_API_KEY so the old Tier-2 subprocess would inherit it. When the
    processor moved in-process the write became pure residue, contradicting the
    invariant while every other test still passed.
    """
    offenders = [
        f"{path.relative_to(REPO)}:{line} — {what}"
        for path, tree in _sources(CORE, CLI, REPO / "tracer.py")
        for line, what in _env_writes(tree)
    ]
    assert not offenders, (
        "credentials must be passed as parameters, never written to the "
        "process environment (CLAUDE.md invariant #6):\n  " + "\n  ".join(offenders)
    )


def test_core_never_reads_the_environment():
    """`safehouse/` takes credentials as parameters and has no env fallback.

    Scoped to core on purpose: `safehouse_cli/settings.py` *must* read the
    environment — that is where resolution belongs — and tracer.py reads one
    non-secret display flag.
    """
    offenders = []
    for path, tree in _sources(CORE):
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("environ", "environb", "getenv"):
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} — os.{node.attr}")
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if alias.name in ("environ", "environb", "getenv"):
                        offenders.append(
                            f"{path.relative_to(REPO)}:{node.lineno} — from os import {alias.name}")
    assert not offenders, (
        "safehouse/ must not read the environment; resolve credentials in "
        "safehouse_cli/settings.py and pass them in explicitly:\n  " + "\n  ".join(offenders)
    )


def test_neither_model_call_site_accepts_a_missing_key(monkeypatch):
    """The planner and the processor each construct a provider client. Left with
    api_key=None the SDK resolves one from the environment itself — below this
    package, so the AST sweeps above cannot see it and the "resolved in the CLI
    layer" invariant would hold only when a key happened to be threaded.

    The processor's half is asserted in tests/test_subagent_isolation.py; this
    covers the planner so the pair cannot drift apart.
    """
    from safehouse.planner import _get_client

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-AMBIENT")
    with pytest.raises(RuntimeError, match="explicit API key"):
        _get_client(None)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
