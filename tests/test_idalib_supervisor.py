"""idalib supervisor tests that do not require IDA/idalib."""

import sys
from pathlib import Path

from ida_pro_mcp import idalib_supervisor as supmod


class _FakeProcess:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _DeadProcess(_FakeProcess):
    returncode = 1


class _FakeSupervisor(supmod.IdalibSupervisor):
    def __init__(self):
        super().__init__(supmod.McpServer("test"), max_workers=4)
        self.forwarded: list[dict] = []
        self.opened: list[tuple[str, dict]] = []

    def _spawn_worker(self):
        return supmod.WorkerSession(
            session_id="__schema__",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=1,
            process=_FakeProcess(),
        )

    def _worker_rpc(self, worker, payload, *, timeout=None):
        method = payload.get("method")
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": "decompile",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"addr": {"type": "string"}},
                                "required": ["addr"],
                            },
                        },
                        {"name": "idalib_open", "inputSchema": {"type": "object"}},
                        {"name": "list_instances", "inputSchema": {"type": "object"}},
                        {"name": "select_instance", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resources": []}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resourceTemplates": []}}
        self.forwarded.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    def call_worker_tool(self, worker, name, arguments=None):
        if name == "idalib_open":
            assert arguments is not None
            self.opened.append((name, arguments))
            return {
                "success": True,
                "session": {
                    "session_id": arguments["session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
            }
        return {"ok": True, "error": None}


class _TransportMcp:
    def __init__(self, session_id="stdio:default"):
        self.session_id = session_id

    def get_current_transport_session_id(self):
        return self.session_id


def _patch_discovery(*, instances, probe):
    old_discover = supmod._discovery.discover_instances
    old_probe = supmod._discovery.probe_instance
    supmod._discovery.discover_instances = lambda: instances
    supmod._discovery.probe_instance = lambda *_args, **_kwargs: probe

    def restore():
        supmod._discovery.discover_instances = old_discover
        supmod._discovery.probe_instance = old_probe

    return restore


def test_supervisor_import_does_not_import_ida_modules():
    assert "idapro" not in sys.modules
    assert "idaapi" not in sys.modules


def test_worker_rpc_default_has_no_socket_timeout(monkeypatch):
    class _FakeResponse:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'

    class _FakeConnection:
        instances = []

        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            type(self).instances.append(self)

        def request(self, method, path, body, headers):
            pass

        def getresponse(self):
            return _FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(supmod.http.client, "HTTPConnection", _FakeConnection)
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="",
        filename="",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, timeout=2.0)

    assert _FakeConnection.instances[0].timeout is None
    assert _FakeConnection.instances[1].timeout == 2.0


def test_worker_tools_inject_database_and_filter_management_tools():
    sup = _FakeSupervisor()
    tools = sup.worker_tools()
    names = [tool["name"] for tool in tools]
    assert names == ["decompile"]
    schema = tools[0]["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" not in schema.get("required", [])


def test_tool_error_result_omits_structured_content():
    result = supmod._call_tool_result({"error": "no database"}, is_error=True)
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_supervisor_blocks_gui_plugin_routing_tools():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "select_instance", "arguments": {"port": 13337}},
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        text = result["result"]["content"][0]["text"]
        assert "GUI-plugin routing tool" in text
        assert not supmod.supervisor.forwarded
    finally:
        supmod.supervisor = old_supervisor


def test_open_session_reuses_schema_worker_and_binds_context(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.worker_tools()  # creates the idle/schema worker
    session = sup.open_session(str(sample), session_id="sample", context_id="ctx")
    assert session.session_id == "sample"
    assert sup.context_bindings["ctx"] == "sample"
    assert sup.opened[0][1]["session_id"] == "sample"


def test_resolve_session_accepts_session_id_filename_and_context(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample", context_id="ctx")
    sup.mcp = _TransportMcp()
    sup.context_bindings[supmod.SHARED_FALLBACK_CONTEXT_ID] = "sample"

    assert sup.resolve_session("sample").session_id == "sample"
    assert sup.resolve_session("sample.bin").session_id == "sample"
    assert sup.resolve_session(None).session_id == "sample"


def test_open_session_uses_matching_gui_instance(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
        assert session.backend == "gui"
        assert session.host == "127.0.0.1"
        assert session.port == 31337
        assert session.pid == 999
        assert sup.resolve_session(str(sample)).session_id == "gui"
        assert sup.resolve_session(str(idb)).session_id == "gui"
        assert sup.opened == []
    finally:
        restore()


def test_open_session_removes_stale_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()), "ctx")
        session = sup.open_session(str(sample), session_id="new", context_id="ctx")
        assert session.session_id == "new"
        assert "stale" not in sup.sessions
        assert sup.context_bindings["ctx"] == "new"
    finally:
        restore()


def test_open_session_ignores_dead_workers_for_max_worker_limit(tmp_path):
    stale_path = tmp_path / "stale.bin"
    new_path = tmp_path / "new.bin"
    stale_path.write_bytes(b"stale")
    new_path.write_bytes(b"new")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        sup.max_workers = 1
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(stale_path.resolve()),
            filename="stale.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(stale_path.resolve()), "ctx")

        session = sup.open_session(str(new_path), session_id="new", context_id="ctx")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
        assert sup.context_bindings["ctx"] == "new"
    finally:
        restore()


def test_open_session_race_discards_losing_worker_for_existing_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample))
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
        assert sup.opened[0][1]["session_id"] != "winner"
    finally:
        restore()


def test_open_session_race_rejects_different_requested_session_id(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(sample), session_id="loser")
        except ValueError as e:
            assert "already open as session 'winner'" in str(e)
        else:
            raise AssertionError("expected ValueError")
        assert set(sup.sessions) == {"winner"}
    finally:
        restore()


def test_open_session_race_rejects_duplicate_session_id_for_different_path(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id=arguments["session_id"],
                    input_path=str(first.resolve()),
                    filename="first.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(first.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(second), session_id="shared")
        except ValueError as e:
            assert "Session already exists: shared" in str(e)
        else:
            raise AssertionError("expected ValueError")

        assert set(sup.sessions) == {"shared"}
        assert sup.sessions["shared"].input_path == str(first.resolve())
        assert sup.path_to_session.get(sup._path_key(str(second.resolve()))) is None
        assert sup.spawned[0].process.returncode == 0
    finally:
        restore()


def test_closed_gui_session_reopens_headless(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(idb.resolve())
    finally:
        restore()


def test_closed_gui_session_falls_back_to_requested_binary_if_idb_is_stale(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
        assert session.backend == "gui"
        idb.unlink()
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(sample.resolve())
    finally:
        restore()


def test_closed_gui_session_does_not_reappear_if_closed_during_headless_fallback(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                self.close_session(arguments["session_id"])
            return result

    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False

        try:
            sup.resolve_session("gui")
        except RuntimeError as e:
            assert "was closed or replaced" in str(e)
        else:
            raise AssertionError("expected RuntimeError")

        assert "gui" not in sup.sessions
        assert sup.spawned[-1].process.returncode == 0
    finally:
        restore()


# ---------------------------------------------------------------------------
# Bearer-token agent isolation + --bearer-contexts mode
# ---------------------------------------------------------------------------


class _BearerMcp:
    """McpServer stand-in that lets tests dial Bearer/transport state."""

    def __init__(self, agent_id="anonymous", session_id=None):
        self._agent = agent_id
        self._session = session_id

    def get_current_agent_id(self):
        return self._agent

    def get_current_transport_session_id(self):
        return self._session


def test_bearer_token_helper_hashes_consistently():
    # Import via the same path-trick the supervisor uses so we don't
    # trigger ida_mcp/__init__.py (which would import idaapi).
    pkg_dir = Path(supmod.__file__).resolve().parent / "ida_mcp"
    sys.path.insert(0, str(pkg_dir))
    try:
        from zeromcp.mcp import (  # type: ignore[import-not-found]
            ANONYMOUS_AGENT_ID,
            _agent_id_from_auth_header,
        )
    finally:
        sys.path.remove(str(pkg_dir))

    assert _agent_id_from_auth_header(None) == ANONYMOUS_AGENT_ID
    assert _agent_id_from_auth_header("") == ANONYMOUS_AGENT_ID
    assert _agent_id_from_auth_header("Bearer ") == ANONYMOUS_AGENT_ID
    assert _agent_id_from_auth_header("Basic abc") == ANONYMOUS_AGENT_ID

    a1 = _agent_id_from_auth_header("Bearer alpha")
    a2 = _agent_id_from_auth_header("Bearer alpha")
    b = _agent_id_from_auth_header("Bearer beta")
    assert a1 == a2
    assert a1 != b
    assert a1.startswith("agent_")


def test_resolve_context_id_no_flags_no_bearer_returns_shared_fallback():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    assert sup.resolve_context_id() == supmod.SHARED_FALLBACK_CONTEXT_ID


def test_resolve_context_id_uses_bearer_when_header_present_even_without_flag():
    sup = supmod.IdalibSupervisor(_BearerMcp(agent_id="agent_alice"))
    assert sup.resolve_context_id() == "bearer:agent_alice"


def test_resolve_context_id_bearer_contexts_flag_requires_header():
    sup = supmod.IdalibSupervisor(_BearerMcp(), bearer_contexts=True)
    try:
        sup.resolve_context_id()
    except RuntimeError as e:
        assert "Authorization: Bearer" in str(e)
    else:
        raise AssertionError("expected RuntimeError")


def test_resolve_context_id_isolated_uses_transport_session_when_no_bearer():
    sup = supmod.IdalibSupervisor(
        _BearerMcp(session_id="http:abc"), isolated_contexts=True
    )
    assert sup.resolve_context_id() == "http:abc"


def test_resolve_context_id_bearer_wins_over_isolated_when_both_set():
    sup = supmod.IdalibSupervisor(
        _BearerMcp(agent_id="agent_alice", session_id="http:abc"),
        isolated_contexts=True,
        bearer_contexts=True,
    )
    assert sup.resolve_context_id() == "bearer:agent_alice"


def test_context_fields_surfaces_bearer_state_without_leaking_agent_id():
    """The hashed Bearer token must not appear in responses — neither
    as a dedicated ``agent_id`` field nor embedded in ``context_id``.
    """
    mcp = _BearerMcp(agent_id="agent_alice", session_id="http:abc")
    sup = supmod.IdalibSupervisor(mcp, bearer_contexts=True)
    raw_context_id = sup.resolve_context_id()
    fields = sup.context_fields(raw_context_id)
    # Internally the supervisor still keys by the hash for isolation.
    assert raw_context_id == "bearer:agent_alice"
    # The public response masks the hash to just the mode marker.
    assert fields["context_id"] == "bearer"
    assert "agent_id" not in fields
    assert "agent_alice" not in str(fields), (
        f"Bearer hash leaked into response: {fields}"
    )
    assert fields["bearer_contexts"] is True


def test_context_fields_passes_non_bearer_context_ids_through():
    """Non-Bearer context_ids are either already-known to the caller
    (transport Mcp-Session-Id) or non-sensitive — keep them as-is."""
    # MCP transport session
    mcp = _BearerMcp(session_id="http:user-known-session")
    sup = supmod.IdalibSupervisor(mcp, isolated_contexts=True)
    fields = sup.context_fields(sup.resolve_context_id())
    assert fields["context_id"] == "http:user-known-session"
    # Shared fallback
    sup2 = supmod.IdalibSupervisor(_BearerMcp())
    fields2 = sup2.context_fields(sup2.resolve_context_id())
    assert fields2["context_id"] == supmod.SHARED_FALLBACK_CONTEXT_ID


# ---------------------------------------------------------------------------
# Refcount-aware close + auto-save before terminate
# ---------------------------------------------------------------------------


def _make_saving_sup():
    """A FakeSupervisor whose save call is captured for assertions."""

    class _SavingFakeSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.save_calls: list[tuple[str, str]] = []

        def call_worker_tool(self, worker, name, arguments=None):
            if name in {"idalib_save", "idb_save"}:
                self.save_calls.append((name, (arguments or {}).get("path", "")))
                return {"ok": True, "path": "/tmp/x.i64"}
            return super().call_worker_tool(worker, name, arguments)

    return _SavingFakeSupervisor()


def test_release_session_with_other_refs_keeps_worker_alive(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="shared", context_id="ctxA")
    sup.bind_context("ctxB", "shared")

    outcome = sup.release_session("shared", "ctxA")
    assert outcome == {
        "success": True,
        "released": True,
        "terminated": False,
        "remaining_refs": 1,
        "saved": True,
        "save_error": None,
    }
    assert "shared" in sup.sessions
    assert sup.context_bindings == {"ctxB": "shared"}
    assert sup.save_calls == [("idalib_save", "")]


def test_release_session_last_ref_saves_then_terminates(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="solo", context_id="ctxA")

    outcome = sup.release_session("solo", "ctxA")
    assert outcome["terminated"] is True
    assert outcome["saved"] is True
    assert outcome["remaining_refs"] == 0
    assert "solo" not in sup.sessions
    assert sup.context_bindings == {}
    # idalib_save fired before the worker was terminated.
    assert sup.save_calls == [("idalib_save", "")]


def test_release_session_from_unbound_context_is_noop(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="shared", context_id="ctxA")

    outcome = sup.release_session("shared", "ctxB")
    assert outcome["released"] is False
    assert outcome["terminated"] is False
    # No save happened — only bound contexts trigger saves.
    assert sup.save_calls == []
    assert "shared" in sup.sessions


def test_release_session_unknown_id_returns_error():
    sup = _make_saving_sup()
    outcome = sup.release_session("ghost", "ctxA")
    assert outcome == {
        "success": False,
        "released": False,
        "terminated": False,
        "error": "Session not found: ghost",
    }


def test_concurrent_release_from_two_agents_terminates_exactly_once(tmp_path):
    """A and B both hold the same session and call release_session at
    the same time. Exactly one must observe is_last (and terminate the
    worker); the other must observe a non-terminating release with
    remaining_refs == 1.

    Race anchor: step-1 pop is under self._lock, so the two pops
    serialize. Whichever pops first computes remaining=1; the second
    computes remaining=0 and runs the terminate path.
    """
    import threading as _threading

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="shared", context_id="ctxA")
    sup.bind_context("ctxB", "shared")
    assert "shared" in sup.sessions
    assert set(sup.context_bindings) == {"ctxA", "ctxB"}

    # Slow the save so both threads have time to enter step 2.
    barrier = _threading.Barrier(2, timeout=2.0)
    original_save = sup._save_session_idb

    def slow_save(session):
        try:
            barrier.wait()
        except _threading.BrokenBarrierError:
            pass
        return original_save(session)

    sup._save_session_idb = slow_save

    outcomes: dict[str, dict] = {}

    def release(ctx: str):
        outcomes[ctx] = sup.release_session("shared", ctx)

    ta = _threading.Thread(target=release, args=("ctxA",))
    tb = _threading.Thread(target=release, args=("ctxB",))
    ta.start()
    tb.start()
    ta.join(timeout=5.0)
    tb.join(timeout=5.0)
    assert not ta.is_alive() and not tb.is_alive()

    # Exactly one observed is_last (terminated=True) — never both.
    terminated = [c for c, r in outcomes.items() if r["terminated"]]
    not_terminated = [c for c, r in outcomes.items() if not r["terminated"]]
    assert len(terminated) == 1, f"expected exactly one terminator, got {terminated}"
    assert len(not_terminated) == 1
    # The non-terminator's snapshot saw exactly one remaining ref (the
    # other agent that hadn't entered step 1 yet).
    other = outcomes[not_terminated[0]]
    assert other["released"] is True
    assert other["remaining_refs"] == 1
    # The terminator's save MUST succeed (it's the one that has to hit
    # disk before terminate). The non-terminator's save can race
    # against the terminator's terminate (instant in this fake fixture,
    # real HTTP I/O in production), so we only assert the terminator
    # got persisted — the non-terminator's outcome is best-effort.
    assert outcomes[terminated[0]]["saved"] is True
    # End state: worker gone, no bindings left.
    assert "shared" not in sup.sessions
    assert sup.context_bindings == {}


def test_release_session_concurrent_open_keeps_worker_alive(tmp_path):
    """Race: A is the last holder and starts save; B opens during the save
    and adds a ref. A's post-save recheck must SKIP the terminate.
    """
    import threading as _threading

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="solo", context_id="ctxA")

    save_started = _threading.Event()
    save_can_finish = _threading.Event()

    original_save = sup._save_session_idb

    def slow_save(session):
        save_started.set()
        save_can_finish.wait(timeout=5.0)
        return original_save(session)

    sup._save_session_idb = slow_save

    result_holder: dict = {}

    def do_release():
        result_holder["r"] = sup.release_session("solo", "ctxA")

    t = _threading.Thread(target=do_release)
    t.start()
    assert save_started.wait(timeout=2.0)

    # While ctxA's save is in flight, ctxB joins the (still alive) session.
    sup.open_session(str(sample), session_id="solo", context_id="ctxB")

    save_can_finish.set()
    t.join(timeout=3.0)
    assert not t.is_alive()
    outcome = result_holder["r"]
    assert outcome["released"] is True
    assert outcome["terminated"] is False  # B's ref kept it alive
    assert outcome["remaining_refs"] == 1
    assert "solo" in sup.sessions
    assert sup.context_bindings == {"ctxB": "solo"}


# ---------------------------------------------------------------------------
# Pending-open early-return + idalib_list_pending
# ---------------------------------------------------------------------------


class _SlowFakeSupervisor(_FakeSupervisor):
    """FakeSupervisor whose call_worker_tool blocks for spawn_delay seconds."""

    def __init__(self, spawn_delay=0.5):
        super().__init__()
        self.spawn_delay = spawn_delay
        self.spawn_starts: list[float] = []
        self._spawn_count = 0
        self._spawn_lock = __import__("threading").Lock()

    def call_worker_tool(self, worker, name, arguments=None):
        if name == "idalib_open":
            import time as _time
            with self._spawn_lock:
                self._spawn_count += 1
                self.spawn_starts.append(_time.monotonic())
            _time.sleep(self.spawn_delay)
            return super().call_worker_tool(worker, name, arguments)
        return super().call_worker_tool(worker, name, arguments)


def test_open_session_returns_opening_when_wait_timeout_elapses(tmp_path):
    import time
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=1.0)

    t0 = time.monotonic()
    result = sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.1)
    elapsed = time.monotonic() - t0
    assert isinstance(result, dict), f"expected pending dict, got {type(result)}"
    assert result["status"] == "opening"
    assert result["filename"] == "slow.bin"
    assert elapsed < 0.9, f"wait_timeout not honoured ({elapsed:.2f}s)"
    # list_open_pending lists it for ctxA but not for ctxB
    assert len(sup.list_pending("ctxA")) == 1
    assert sup.list_pending("ctxB") == []

    # Wait for the spawn to actually finish.
    import time as _time
    for _ in range(40):
        if "ctxA" in sup.context_bindings:
            break
        _time.sleep(0.05)
    assert "ctxA" in sup.context_bindings


def test_open_session_concurrent_same_path_coalesces_into_one_spawn(tmp_path):
    import threading as _threading
    sample = tmp_path / "shared.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.4)

    results: list = []
    results_lock = _threading.Lock()

    def open_one(ctx):
        r = sup.open_session(str(sample), context_id=ctx, wait_timeout=2.0)
        with results_lock:
            results.append((ctx, r))

    threads = [
        _threading.Thread(target=open_one, args=(f"ctx{i}",)) for i in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive()

    # Exactly one underlying spawn.
    assert sup._spawn_count == 1, f"expected 1 spawn, got {sup._spawn_count}"
    # All four results are the same WorkerSession.
    sessions = [r for _, r in results if not isinstance(r, dict)]
    assert len(sessions) == 4
    assert {s.session_id for s in sessions} == {sessions[0].session_id}
    # Every context bound to that session.
    assert all(
        sup.context_bindings.get(f"ctx{i}") == sessions[0].session_id
        for i in range(4)
    )


def test_list_pending_isolated_per_context(tmp_path):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)

    # ctxA requests, ctxB doesn't
    pending = sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    assert isinstance(pending, dict)

    assert len(sup.list_pending("ctxA")) == 1
    assert sup.list_pending("ctxB") == []
    assert sup.list_pending("ctxC") == []

    # ctxB joins the same pending → both contexts see it
    sup.open_session(str(sample), context_id="ctxB", wait_timeout=0.05)
    assert len(sup.list_pending("ctxA")) == 1
    assert len(sup.list_pending("ctxB")) == 1
    assert sup.list_pending("ctxC") == []


def test_resolve_session_for_pending_session_id_gives_helpful_error(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)

    pending = sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    assert isinstance(pending, dict)
    try:
        sup.resolve_session(pending["session_id"])
    except RuntimeError as e:
        assert "still opening" in str(e)
        assert pending["session_id"] in str(e)
    else:
        raise AssertionError("expected RuntimeError")


def test_open_session_wait_timeout_none_blocks_until_ready(tmp_path):
    import time
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.3)

    t0 = time.monotonic()
    result = sup.open_session(
        str(sample), context_id="ctxA", wait_timeout=None
    )
    elapsed = time.monotonic() - t0
    # We blocked through the entire spawn (wait_timeout=None means wait forever).
    assert not isinstance(result, dict)
    assert result.session_id is not None
    assert elapsed >= 0.25


# ---------------------------------------------------------------------------
# Multi-threaded HTTP server + supervisor lock discipline
# ---------------------------------------------------------------------------


def test_mcp_server_serve_always_uses_threading_http_server():
    """Both background=True and background=False must give a threaded server.

    Single-threaded HTTPServer at the supervisor would serialise every
    request, so a long-running tool call from one agent would stall
    every other agent — defeating the multi-agent isolation work.
    """
    from http.server import ThreadingHTTPServer

    for background in (True, False):
        srv = supmod.McpServer(f"test-{background}")
        srv.serve(host="127.0.0.1", port=0, background=True)
        try:
            assert isinstance(srv._http_server, ThreadingHTTPServer), (
                f"serve(background={background}) selected "
                f"{type(srv._http_server).__name__} instead of ThreadingHTTPServer"
            )
        finally:
            srv.stop()


def test_bind_context_blocks_while_supervisor_lock_is_held():
    """A concurrent bind_context() must serialise on self._lock so that
    release_session()'s recheck-then-terminate window is consistent.
    """
    import threading as _threading
    import time as _time

    sup = supmod.IdalibSupervisor(_BearerMcp())

    lock_held = _threading.Event()
    finish_holding = _threading.Event()

    def hold_lock():
        with sup._lock:
            lock_held.set()
            finish_holding.wait(timeout=2.0)

    holder = _threading.Thread(target=hold_lock)
    holder.start()
    assert lock_held.wait(timeout=1.0)

    bind_done = _threading.Event()

    def try_bind():
        sup.bind_context("ctxA", "sess1")
        bind_done.set()

    binder = _threading.Thread(target=try_bind)
    binder.start()
    # Give the binder enough time to attempt and block.
    _time.sleep(0.1)
    assert not bind_done.is_set(), "bind_context did not block on the supervisor lock"

    # Release the holder; binder should now make progress.
    finish_holding.set()
    holder.join(timeout=2.0)
    binder.join(timeout=2.0)
    assert bind_done.is_set()
    assert sup.context_bindings == {"ctxA": "sess1"}


def test_unbind_context_blocks_while_supervisor_lock_is_held():
    import threading as _threading
    import time as _time

    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "sess1")

    lock_held = _threading.Event()
    finish_holding = _threading.Event()

    def hold_lock():
        with sup._lock:
            lock_held.set()
            finish_holding.wait(timeout=2.0)

    holder = _threading.Thread(target=hold_lock)
    holder.start()
    assert lock_held.wait(timeout=1.0)

    unbind_result: list[bool] = []

    def try_unbind():
        unbind_result.append(sup.unbind_context("ctxA"))

    unbinder = _threading.Thread(target=try_unbind)
    unbinder.start()
    _time.sleep(0.1)
    assert not unbind_result, "unbind_context did not block on the supervisor lock"

    finish_holding.set()
    holder.join(timeout=2.0)
    unbinder.join(timeout=2.0)
    assert unbind_result == [True]
    assert sup.context_bindings == {}


def test_concurrent_forward_to_same_session_runs_in_parallel(tmp_path):
    """Two tool calls to the SAME session must run in parallel at the
    supervisor — serialisation should happen at the worker (via
    @idasync / execute_sync), not at the supervisor layer.
    """
    import threading as _threading
    import time as _time

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _SlowForward(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.concurrent_peak = 0
            self._active = 0
            self._peak_lock = _threading.Lock()

        def _worker_rpc(self, worker, payload, *, timeout=None):
            method = payload.get("method")
            # tools/list and resources/list pre-cache during open_session
            # via _FakeSupervisor.worker_tools(); we only care about the
            # forwarded tool calls.
            if method in {"tools/list", "resources/list", "resources/templates/list"}:
                return super()._worker_rpc(worker, payload, timeout=timeout)
            with self._peak_lock:
                self._active += 1
                self.concurrent_peak = max(self.concurrent_peak, self._active)
            _time.sleep(0.2)
            with self._peak_lock:
                self._active -= 1
            return super()._worker_rpc(worker, payload, timeout=timeout)

    sup = _SlowForward()
    sup.open_session(str(sample), session_id="shared", context_id="ctx")
    target = sup.sessions["shared"]

    def call(i: int):
        sup.forward_raw(target, {
            "jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "decompile", "arguments": {"addr": "0x0"}},
        })

    threads = [_threading.Thread(target=call, args=(i,)) for i in range(4)]
    t0 = _time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3.0)
        assert not t.is_alive()
    elapsed = _time.monotonic() - t0

    # If forward_raw serialised on a supervisor lock, elapsed ≈ 4 × 0.2 = 0.8s.
    # With true parallelism it should be ~0.2-0.4s.
    assert elapsed < 0.7, f"forward_raw was serialised at supervisor (took {elapsed:.2f}s)"
    assert sup.concurrent_peak >= 2, (
        f"never observed >=2 concurrent forwards (peak={sup.concurrent_peak})"
    )


def test_concurrent_iteration_and_bind_does_not_raise(tmp_path):
    """Hammer context_bindings to make sure dict iteration under the
    lock never collides with a bind/unbind that bypassed it.
    """
    import threading as _threading
    import time as _time

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="shared", context_id="seed")

    stop = _threading.Event()
    errors: list[Exception] = []

    def reader():
        while not stop.is_set():
            try:
                # list_sessions iterates context_bindings under the lock.
                sup.list_sessions(supmod.SHARED_FALLBACK_CONTEXT_ID)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

    def writer():
        ctr = 0
        while not stop.is_set():
            sup.bind_context(f"ctx{ctr % 16}", "shared")
            sup.unbind_context(f"ctx{(ctr - 1) % 16}")
            ctr += 1

    readers = [_threading.Thread(target=reader) for _ in range(4)]
    writers = [_threading.Thread(target=writer) for _ in range(4)]
    for t in readers + writers:
        t.start()
    _time.sleep(0.3)
    stop.set()
    for t in readers + writers:
        t.join(timeout=2.0)
    assert not errors, f"hammer test raised: {errors[:3]}"
