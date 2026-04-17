"""Tests for idalib_server integration helpers."""

import os
import sys

from ..framework import test

try:
    from ida_pro_mcp import idalib_server
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import idalib_server  # type: ignore
    finally:
        sys.path.remove(_parent)


@test()
def test_idalib_list_returns_empty_when_no_sessions():
    """idalib_list should return count=0 when no sessions are open."""
    original_get_session_manager = idalib_server.get_session_manager

    class _FakeManager:
        def list_sessions(self):
            return []

    idalib_server.get_session_manager = lambda: _FakeManager()
    try:
        result = idalib_server.idalib_list()
        assert result["count"] == 0
        assert result["sessions"] == []
    finally:
        idalib_server.get_session_manager = original_get_session_manager
