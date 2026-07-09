"""
tests/test_permissions.py — CanNetwork.permits() security properties.

Covers all enforcement rules stated in the docstring plus regression guards
for the two security findings applied in this pass:
  F1 — traversal escape via un-normalized '..' segments
  F2 — schemeless CanNetwork construction raises ValueError
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from safehouse.permissions import CanNetwork


GRANT = CanNetwork("https://api.example.com/v1/users/me")


class TestPermitsBasic:
    def test_exact_match(self):
        assert GRANT.permits("https://api.example.com/v1/users/me")

    def test_deeper_subpath_allowed(self):
        assert GRANT.permits("https://api.example.com/v1/users/me/messages")

    def test_deeper_subpath_with_query(self):
        assert GRANT.permits("https://api.example.com/v1/users/me/messages?q=foo")

    def test_path_divergence_blocked(self):
        # '/v1/users/mail' shares no suffix with '/v1/users/me'
        assert not GRANT.permits("https://api.example.com/v1/users/mail")

    def test_segment_prefix_not_string_prefix(self):
        # '/v1/users/me-admin' starts with '/v1/users/me' as a string
        # but 'me-admin' != 'me' at the diverging segment.
        assert not GRANT.permits("https://api.example.com/v1/users/me-admin")


class TestPermitsScheme:
    def test_scheme_downgrade_blocked(self):
        assert not GRANT.permits("http://api.example.com/v1/users/me")

    def test_scheme_mismatch_blocked(self):
        assert not GRANT.permits("ftp://api.example.com/v1/users/me")


class TestPermitsHost:
    def test_subdomain_confusion_blocked(self):
        # 'api.example.com' is NOT a subpath of 'example.com'
        grant = CanNetwork("https://example.com/page")
        assert not grant.permits("https://api.example.com/page")

    def test_host_case_insensitive(self):
        grant = CanNetwork("https://Example.COM/page")
        assert grant.permits("https://example.com/page")
        assert grant.permits("https://EXAMPLE.COM/page")

    def test_userinfo_trick_blocked(self):
        # 'https://api.example.com@evil.com/...' — netloc is 'evil.com'
        assert not GRANT.permits("https://api.example.com@evil.com/v1/users/me")


class TestPermitsTraversal:
    """Finding 1 regression guard — '..' escape must be rejected."""

    def test_traversal_escape_blocked(self):
        # httpx normalizes /v1/users/me/../../../admin → /admin after gate approval
        assert not GRANT.permits("https://api.example.com/v1/users/me/../../../admin")

    def test_traversal_mid_path_blocked(self):
        assert not GRANT.permits("https://api.example.com/v1/../v1/users/me")

    def test_traversal_at_root_blocked(self):
        assert not GRANT.permits("https://api.example.com/../etc/passwd")

    def test_single_dot_segment_allowed(self):
        # '.' is a harmless current-dir no-op, dropped by the 'if s' filter;
        # it does not change the resolved path, so it must not be rejected.
        assert GRANT.permits("https://api.example.com/v1/users/me/./messages")


class TestCanNetworkConstruction:
    """Finding 2 regression guard — schemeless grants must raise at construction."""

    def test_absolute_url_ok(self):
        CanNetwork("https://example.com/path")  # must not raise

    def test_schemeless_raises(self):
        with pytest.raises(ValueError, match="absolute"):
            CanNetwork("example.com/path")

    def test_path_only_raises(self):
        with pytest.raises(ValueError, match="absolute"):
            CanNetwork("/v1/users/me")

    def test_scheme_only_raises(self):
        with pytest.raises(ValueError, match="absolute"):
            CanNetwork("https://")

    def test_hashable_and_dedupes_in_frozenset(self):
        a = CanNetwork("https://example.com/a")
        b = CanNetwork("https://example.com/a")
        c = CanNetwork("https://example.com/b")
        assert len({a, b, c}) == 2
        assert len(frozenset([a, b, c])) == 2
