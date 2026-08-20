"""
secrets.py — Per-run credential containment.

Invariant #6 says a credential must never appear in a slot, label, task string,
trace payload, or Tier 1/2 sub-agent input. Until now that held *by construction*:
credentials go in request headers, and fetchers write projections of provider data
rather than raw responses. Nothing enforced it.

By-construction is the right primary defence, but it is a property of every
current fetcher rather than of the architecture — a new fetcher that writes a
provider error into its output slot ("(fetch failed: %s)") breaks it silently, and
several providers echo the rejected credential in a 401 body. This module makes
the property structural at the two boundaries that matter.

Why those two boundaries behave differently:

  Slot write  → DENY.    Slot content flows onward: the Tier-2 processor reads it
                         and a Tier-3 action can release it to the world. A
                         credential there is an exfiltration path, and it is a bug
                         in our code rather than data worth salvaging. Redacting
                         would let a mangled slot continue down the pipeline.

  Trace emit  → REDACT.  A trace event is terminal output; it feeds the display
                         and the session transcript, and does not flow into an
                         action. It is also most likely to carry a credential
                         precisely when we are already handling a provider
                         failure — so denying would convert a clean error into a
                         confusing crash and destroy the audit record of it.

What this is not: an adversarial evasion boundary. It catches a credential that
*our own code* or *a provider's error body* put where it should not be — the
encodings registered are the ones that actually occur in that path (a raw echo,
a JSON error payload, a base64url MIME blob, a URL parameter). It would not stop
a party who could choose an arbitrary encoding to slip a value past a substring
scan; nothing short of not holding the secret can. The real guarantee remains
by-construction — credentials travel in headers and fetchers write projections —
and this is the net under it.

The registry holds plaintext because substring matching requires it. That is not
a new exposure: the process necessarily holds these values already (ProviderConfig
does). It is `__repr__`-suppressed so it cannot leak itself into an f-string,
a traceback frame, or a trace payload.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Mapping
from urllib.parse import quote

# Below this length a needle is more likely to collide with ordinary text than to
# identify a credential. Every real provider token is far longer; a value shorter
# than this is not registered at all rather than risking a false positive that
# would deny a legitimate slot write.
_MIN_NEEDLE = 12


class SecretLeak(RuntimeError):
    """A registered credential was found in data crossing a boundary.

    The message names the credential and never contains its value — otherwise
    the exception text, which is printed and written to the transcript, would
    become the leak it reports.
    """


def _b64_cores(raw: bytes) -> set[str]:
    """Base64 fragments that match whatever byte offset the secret sits at.

    Needed because `send_reply` base64url-encodes the whole MIME message before
    handing it to Gmail, so a credential inside one is invisible to a raw scan.

    Base64 maps each 3 input bytes to 4 output characters, so a secret's encoding
    depends on its offset mod 3. For each of the three alignments, take the
    largest slice of the secret that lands on whole 3-byte group boundaries:
    every group strictly inside the secret encodes to the same 4 characters no
    matter what surrounds it, whereas the partial groups at either end mix in
    neighbouring bytes. Encoding a whole number of groups also means no '='
    padding, which only ever appears at the true end of a blob.
    """
    cores: set[str] = set()
    for offset in (0, 1, 2):
        start = (3 - offset) % 3                  # first byte of the first whole group
        span  = ((len(raw) - start) // 3) * 3     # whole groups only
        if span < 9:                              # < 12 encoded chars
            continue
        chunk = raw[start:start + span]
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            cores.add(encode(chunk).decode("ascii"))
    return cores


class SecretRegistry:
    """The credential values for one run, plus the encodings they can appear in.

    Construct once per run from the resolved credentials. Empty is legitimate and
    means every scan is a no-op — a unit test building a bare SlotStore is not
    forced to supply credentials it does not have.
    """

    __slots__ = ("_needles",)

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._needles: dict[str, str] = {}   # needle -> credential name
        for name, value in (values or {}).items():
            self.register(name, value)

    def register(self, name: str, value: str | None) -> None:
        """Register one credential under a reportable name.

        Unset and implausibly short values are skipped: an empty string would
        match every text, and a short one invites collisions.
        """
        if not value or len(value) < _MIN_NEEDLE:
            return
        variants = {
            value,                          # header value, config file, plain echo
            quote(value, safe=""),          # percent-encoded into a URL
            json.dumps(value)[1:-1],        # escaped inside a JSON body
        }
        variants |= _b64_cores(value.encode("utf-8", errors="surrogatepass"))
        for needle in variants:
            if len(needle) >= _MIN_NEEDLE:
                # setdefault: if two credentials share an encoding, the first
                # name wins — either is a correct report.
                self._needles.setdefault(needle, name)

    def __bool__(self) -> bool:
        return bool(self._needles)

    def find(self, text: str) -> str | None:
        """Name of the first credential found in `text`, or None."""
        for needle, name in self._needles.items():
            if needle in text:
                return name
        return None

    def redact(self, text: str) -> str:
        """Replace every occurrence with a named marker, preserving the context."""
        for needle, name in self._needles.items():
            if needle in text:
                text = text.replace(needle, f"[REDACTED:{name}]")
        return text

    def scrub(self, value):
        """Redact recursively through containers, dataclasses and strings.

        Rebuilds rather than mutating: the caller still holds the original object,
        and silently rewriting it would make the redaction observable to code that
        merely passed data through.
        """
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self.scrub(v) for v in value)
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return dataclasses.replace(value, **{
                f.name: self.scrub(getattr(value, f.name))
                for f in dataclasses.fields(value) if f.init
            })
        return value

    # The registry is passed into the store and the tracer, both of which appear
    # in reprs and tracebacks. Suppressing here means no accidental interpolation
    # can print the values it holds.
    def __repr__(self) -> str:
        return f"<SecretRegistry {len(self._needles)} needles>"

    __str__ = __repr__
