"""Tests for IDASessionManager — pending-open + multi-agent semantics.

Workers are simulated with a FakeWorker that writes ``WORKER_READY``
(and optional follow-on lines) to an OS pipe.  This lets us exercise
the real reader/finalise/proxy code paths without spawning idalib
subprocesses and keeps the tests cross-platform.
"""

import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot spec {name} from {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_HERE = Path(__file__).resolve()
_FRAMEWORK_PATH = _HERE.parent.parent / "framework.py"
_SESSION_MANAGER_PATH = _HERE.parent.parent.parent / "idalib_session_manager.py"

try:
    from .. import framework as fw  # in-IDA path
    from ... import idalib_session_manager as ism
except ImportError:
    fw = _load_module("ida_mcp_test_framework_standalone", _FRAMEWORK_PATH)
    ism = _load_module(
        "ida_pro_mcp_idalib_session_manager_standalone", _SESSION_MANAGER_PATH
    )


# ---------------------------------------------------------------------------
# Fake worker plumbing
# ---------------------------------------------------------------------------


class _FakeStdin:
    """Stand-in for proc.stdin.  Optionally records writes for assertions."""

    def __init__(self):
        self.writes: list[bytes] = []
        self._lock = threading.Lock()

    def write(self, data):
        with self._lock:
            self.writes.append(bytes(data))
        return len(data)

    def flush(self):
        pass

    def close(self):
        pass


class _FakeStdout:
    """File-like wrapper around the read end of an OS pipe."""

    def __init__(self, fd: int):
        self._fd = fd
        self._closed = False

    def readline(self) -> bytes:
        if self._closed:
            return b""
        buf = b""
        while True:
            try:
                chunk = os.read(self._fd, 1)
            except OSError:
                self._closed = True
                return buf
            if not chunk:
                self._closed = True
                return buf
            buf += chunk
            if chunk == b"\n":
                return buf

    def close(self):
        if not self._closed:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._closed = True


class _FakeWorker:
    """subprocess.Popen-like object whose stdout emits configurable lines.

    Parameters:
        ready_after: seconds before WORKER_READY is written.
        write_error: if set, an ERROR sentinel is written instead of READY.
        never_ready: nothing is written until kill() closes the pipe.
        rpc_response: stored response (or callable returning response) for
            every JSON-RPC request — used to drive proxy_jsonrpc tests.
    """

    _pid_counter = 90000

    def __init__(
        self,
        *,
        ready_after: float = 0.0,
        write_error: str | None = None,
        never_ready: bool = False,
        rpc_response=None,
    ):
        self._read_fd, self._write_fd = os.pipe()
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(self._read_fd)
        _FakeWorker._pid_counter += 1
        self.pid = _FakeWorker._pid_counter
        self._returncode: int | None = None
        self._never_ready = never_ready
        self._rpc_response = rpc_response
        self._write_lock = threading.Lock()

        if never_ready:
            return

        def writer() -> None:
            time.sleep(ready_after)
            try:
                if write_error is not None:
                    line = f"{ism._ERROR_SENTINEL}:{write_error}\n"
                else:
                    line = f"{ism._READY_SENTINEL}\n"
                with self._write_lock:
                    os.write(self._write_fd, line.encode())
            except OSError:
                pass

        threading.Thread(target=writer, daemon=True).start()

        # Install the RPC echo thread that responds to every line written
        # to stdin with the configured response.  This only kicks in after
        # WORKER_READY has been delivered, mimicking the real worker.
        if rpc_response is not None:
            threading.Thread(
                target=self._serve_rpc, daemon=True, name=f"rpc-{self.pid}"
            ).start()

    def _serve_rpc(self) -> None:
        time.sleep(0.05)
        served = 0
        while not self._closed_write():
            # Poll the stdin write log for new requests.
            with self.stdin._lock:
                pending = self.stdin.writes[served:]
            for req_bytes in pending:
                served += 1
                resp = self._rpc_response
                if callable(resp):
                    body = resp(req_bytes)
                else:
                    body = resp
                if isinstance(body, dict):
                    body = json.dumps(body).encode() + b"\n"
                try:
                    with self._write_lock:
                        os.write(self._write_fd, body)
                except OSError:
                    return
            time.sleep(0.01)

    def _closed_write(self) -> bool:
        return self._returncode is not None

    def poll(self):
        return self._returncode

    @property
    def returncode(self):
        return self._returncode

    def kill(self):
        if self._returncode is None:
            self._returncode = -9
        try:
            os.close(self._write_fd)
        except OSError:
            pass

    def terminate(self):
        self.kill()

    def wait(self, timeout=None):
        return self._returncode if self._returncode is not None else 0


# ---------------------------------------------------------------------------
# Manager factory + binary stubs
# ---------------------------------------------------------------------------


def _make_manager(spawn_factory):
    mgr = ism.IDASessionManager()
    mgr._start_worker_process = spawn_factory  # type: ignore[assignment]
    return mgr


def _existing_file() -> Path:
    here = Path(__file__).resolve()
    assert here.exists()
    return here


def _ok_save_response(_req: bytes) -> bytes:
    """Reply with a successful tools/call result for save_database."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "structuredContent": {"saved": True, "idb_path": "/tmp/x.i64"},
                "content": [{"type": "text", "text": "{\"saved\": true}"}],
                "isError": False,
            },
        }
    ).encode() + b"\n"


# ---------------------------------------------------------------------------
# Single-agent tests (regression for prior pending-open commit)
# ---------------------------------------------------------------------------


@fw.test()
def test_open_returns_ready_when_worker_signals_ready():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.0))
    try:
        result = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        assert result["status"] == "ready", result
        session = result["session"]
        assert session["filename"] == path.name
        assert session["alive"] is True
        assert mgr.list_pending("agent-a") == []
        assert len(mgr.list_sessions("agent-a")) == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_returns_opening_when_wait_timeout_elapses():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=2.0))
    try:
        t0 = time.monotonic()
        result = mgr.open_binary(
            "agent-a", path, wait_timeout=0.2, spawn_timeout=10.0
        )
        elapsed = time.monotonic() - t0
        assert result["status"] == "opening", result
        assert elapsed < 1.5, f"wait_timeout not honoured: {elapsed:.2f}s"
        assert result["filename"] == path.name
        assert mgr.list_sessions("agent-a") == []
        pendings = mgr.list_pending("agent-a")
        assert len(pendings) == 1
        assert pendings[0]["session_id"] == result["session_id"]
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if mgr.list_sessions("agent-a"):
                break
            time.sleep(0.05)
        assert mgr.list_sessions("agent-a"), "worker never finalised after wait_timeout"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_duplicate_open_during_pending_returns_opening_status():
    path = _existing_file()
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=2.0)

    mgr = _make_manager(spawn)
    try:
        first = mgr.open_binary("agent-a", path, wait_timeout=0.2)
        second = mgr.open_binary("agent-a", path, wait_timeout=0.2)
        assert first["status"] == "opening"
        assert second["status"] == "opening"
        assert first["session_id"] == second["session_id"]
        assert spawn_count["n"] == 1, f"duplicate spawn: {spawn_count['n']}"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_list_sessions_excludes_pending_then_includes_after_ready():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.4))
    try:
        result = mgr.open_binary("agent-a", path, wait_timeout=0.1)
        assert result["status"] == "opening", result
        assert mgr.list_sessions("agent-a") == []
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if mgr.list_sessions("agent-a"):
                break
            time.sleep(0.05)
        sessions = mgr.list_sessions("agent-a")
        assert len(sessions) == 1
        assert sessions[0]["filename"] == path.name
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_after_ready_returns_existing_session():
    path = _existing_file()
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.0)

    mgr = _make_manager(spawn)
    try:
        first = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        second = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        assert first["status"] == "ready"
        assert second["status"] == "ready"
        assert first["session"]["session_id"] == second["session"]["session_id"]
        assert spawn_count["n"] == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_spawn_failure_surfaces_to_all_waiters_and_clears_pending():
    path = _existing_file()
    mgr = _make_manager(
        lambda _p: _FakeWorker(ready_after=0.0, write_error="open_database failed")
    )
    try:
        try:
            mgr.open_binary("agent-a", path, wait_timeout=2.0)
        except RuntimeError as e:
            assert "open_database failed" in str(e)
        else:
            assert False, "expected RuntimeError"
        spawn_count = {"n": 0}

        def spawn(_p):
            spawn_count["n"] += 1
            return _FakeWorker(ready_after=0.0)

        mgr._start_worker_process = spawn  # type: ignore[assignment]
        result = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        assert result["status"] == "ready"
        assert spawn_count["n"] == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_proxy_jsonrpc_for_pending_session_id_gives_helpful_error():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=5.0))
    try:
        result = mgr.open_binary("agent-a", path, wait_timeout=0.1)
        assert result["status"] == "opening"
        try:
            mgr.proxy_jsonrpc("agent-a", result["session_id"], "tools/list", {})
        except RuntimeError as e:
            assert "still opening" in str(e), str(e)
        else:
            assert False, "expected RuntimeError"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_concurrent_opens_for_same_path_coalesce_to_one_spawn():
    path = _existing_file()
    spawn_count = {"n": 0}
    spawn_lock = threading.Lock()

    def spawn(_p):
        with spawn_lock:
            spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.3)

    mgr = _make_manager(spawn)
    results: list[dict] = []
    results_lock = threading.Lock()

    def worker():
        r = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        with results_lock:
            results.append(r)

    try:
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), "open_binary hung"
        assert spawn_count["n"] == 1, f"spawned {spawn_count['n']} workers"
        assert len(results) == 8
        assert all(r["status"] == "ready" for r in results)
        ids = {r["session"]["session_id"] for r in results}
        assert len(ids) == 1, ids
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_for_different_paths_does_not_block_on_pending_other_path():
    path_a = _existing_file()
    path_b = Path(ism.__file__).resolve()
    if path_a.resolve() == path_b:
        path_b = Path(fw.__file__).resolve()
    assert path_a.resolve() != path_b

    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=3.0))
    try:
        t0 = time.monotonic()
        result_a = mgr.open_binary("agent-a", path_a, wait_timeout=0.1)
        result_b = mgr.open_binary("agent-a", path_b, wait_timeout=0.1)
        elapsed = time.monotonic() - t0
        assert result_a["status"] == "opening"
        assert result_b["status"] == "opening"
        assert elapsed < 1.5, f"opens serialised on each other: {elapsed:.2f}s"
        assert result_a["session_id"] != result_b["session_id"]
        assert len(mgr.list_pending("agent-a")) == 2
        assert mgr.list_sessions("agent-a") == []
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_list_pending_returns_status_dicts_for_in_flight_opens():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=2.0))
    try:
        result = mgr.open_binary("agent-a", path, wait_timeout=0.1)
        assert result["status"] == "opening"
        pending = mgr.list_pending("agent-a")
        assert len(pending) == 1
        entry = pending[0]
        assert entry["session_id"] == result["session_id"]
        assert entry["filename"] == path.name
        assert entry["elapsed_seconds"] >= 0.1
        assert "started_at" in entry and "pid" in entry
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_two_callers_to_same_session_serialise_on_worker_io_lock():
    """Same-session tool calls must serialise so JSON-RPC responses don't interleave."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.0))
    try:
        result = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        assert result["status"] == "ready"
        session_id = result["session"]["session_id"]
        worker = mgr._workers[result["session"]["input_path"]]

        active = threading.Event()
        overlap = threading.Event()
        active_count = [0]
        count_lock = threading.Lock()

        class _SerialStdin:
            def write(self, data):
                with count_lock:
                    active_count[0] += 1
                    if active_count[0] > 1:
                        overlap.set()
                active.set()
                return len(data)

            def flush(self):
                pass

            def close(self):
                pass

        class _SerialStdout:
            def readline(self):
                time.sleep(0.2)
                with count_lock:
                    active_count[0] -= 1
                return b'{"jsonrpc":"2.0","id":1,"result":{}}\n'

        worker.process.stdin = _SerialStdin()
        worker.process.stdout = _SerialStdout()

        def call():
            mgr.proxy_jsonrpc("agent-a", session_id, "tools/call", {})

        threads = [threading.Thread(target=call) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)
            assert not t.is_alive()
        assert active.is_set()
        assert not overlap.is_set(), "I/O overlapped — worker lock did not serialise"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_missing_file_raises_file_not_found():
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.0)

    mgr = _make_manager(spawn)
    try:
        try:
            mgr.open_binary("agent-a", "Z:/this/path/does/not/exist.bin")
        except FileNotFoundError:
            pass
        else:
            assert False
        assert spawn_count["n"] == 0
    finally:
        mgr.close_all_sessions()


# ---------------------------------------------------------------------------
# Multi-agent tests
# ---------------------------------------------------------------------------


@fw.test()
def test_two_agents_open_same_path_share_worker_but_get_distinct_session_ids():
    """Same binary, two agents → 1 worker, 2 distinct session IDs."""
    path = _existing_file()
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.0)

    mgr = _make_manager(spawn)
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        b = mgr.open_binary("agent-b", path, wait_timeout=2.0)
        assert a["status"] == "ready" and b["status"] == "ready"
        assert a["session"]["session_id"] != b["session"]["session_id"]
        assert spawn_count["n"] == 1, "second agent should reuse the worker"
        # Each agent only sees their own session.
        assert [s["session_id"] for s in mgr.list_sessions("agent-a")] == [a["session"]["session_id"]]
        assert [s["session_id"] for s in mgr.list_sessions("agent-b")] == [b["session"]["session_id"]]
        # Manager state: one worker with two refs.
        resolved = a["session"]["input_path"]
        worker = mgr._workers[resolved]
        assert len(worker.refs) == 2
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_agent_cannot_use_other_agents_session_id():
    """Even if agent-b knows agent-a's session_id, proxy_jsonrpc must reject it."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.0))
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        sid = a["session"]["session_id"]
        try:
            mgr.proxy_jsonrpc("agent-b", sid, "tools/list", {})
        except ValueError as e:
            assert "Session not found for this agent" in str(e), str(e)
        else:
            assert False, "expected ValueError"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_agent_cannot_close_other_agents_session():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.0))
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        sid = a["session"]["session_id"]
        outcome = mgr.close_session("agent-b", sid)
        assert outcome["success"] is False
        # agent-a still has the session.
        assert len(mgr.list_sessions("agent-a")) == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_close_with_refs_does_not_terminate_worker():
    """When other agents still hold the binary, close only drops this agent's view."""
    path = _existing_file()

    def spawn(_p):
        return _FakeWorker(ready_after=0.0, rpc_response=_ok_save_response)

    mgr = _make_manager(spawn)
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        b = mgr.open_binary("agent-b", path, wait_timeout=2.0)
        resolved = a["session"]["input_path"]
        worker = mgr._workers[resolved]

        outcome = mgr.close_session("agent-a", a["session"]["session_id"])
        assert outcome["success"] is True
        assert outcome["terminated"] is False
        assert outcome["remaining_refs"] == 1
        assert outcome["saved"] is True  # save was called before decrement
        assert mgr._workers.get(resolved) is worker, "worker must stay alive"
        assert mgr.list_sessions("agent-a") == []
        assert len(mgr.list_sessions("agent-b")) == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_close_last_ref_saves_then_terminates():
    """Last ref → save .i64, then terminate worker."""
    path = _existing_file()

    def spawn(_p):
        return _FakeWorker(ready_after=0.0, rpc_response=_ok_save_response)

    mgr = _make_manager(spawn)
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        resolved = a["session"]["input_path"]
        proc = mgr._workers[resolved].process

        outcome = mgr.close_session("agent-a", a["session"]["session_id"])
        assert outcome["success"] is True
        assert outcome["saved"] is True
        assert outcome["terminated"] is True
        # Worker is no longer registered.
        assert resolved not in mgr._workers
        # The save request was emitted before the kill.
        save_seen = any(
            b"save_database" in req for req in proc.stdin.writes
        )
        assert save_seen, "save_database was not invoked before terminate"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_pending_open_shared_between_two_agents():
    """Two agents calling open(same path) on a slow spawn must coalesce."""
    path = _existing_file()
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.6)

    mgr = _make_manager(spawn)
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=0.1)
        b = mgr.open_binary("agent-b", path, wait_timeout=0.1)
        assert a["status"] == "opening"
        assert b["status"] == "opening"
        assert a["session_id"] != b["session_id"], "each agent gets its own ID"
        assert spawn_count["n"] == 1, f"spawned {spawn_count['n']} workers"
        # Wait for ready, both agents should see their session live.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            sa = mgr.list_sessions("agent-a")
            sb = mgr.list_sessions("agent-b")
            if sa and sb:
                break
            time.sleep(0.05)
        assert mgr.list_sessions("agent-a"), "agent-a session never materialised"
        assert mgr.list_sessions("agent-b"), "agent-b session never materialised"
        # And the worker has both refs.
        resolved = mgr.list_sessions("agent-a")[0]["input_path"]
        worker = mgr._workers[resolved]
        assert len(worker.refs) == 2
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_concurrent_close_and_open_for_same_path_keeps_worker_alive():
    """While agent-a is closing (refs would drop to 0), agent-b opens — must reuse."""
    path = _existing_file()

    def spawn(_p):
        return _FakeWorker(ready_after=0.0, rpc_response=_ok_save_response)

    mgr = _make_manager(spawn)
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        resolved = a["session"]["input_path"]
        worker = mgr._workers[resolved]

        # Slow down save_database so we can race open against it.
        def slow_save(req: bytes) -> bytes:
            time.sleep(0.3)
            return _ok_save_response(req)

        worker.process._rpc_response = slow_save  # type: ignore[attr-defined]

        a_close_done = threading.Event()
        b_open_done = threading.Event()
        b_result: dict = {}

        def close_a():
            try:
                mgr.close_session("agent-a", a["session"]["session_id"])
            finally:
                a_close_done.set()

        def open_b():
            try:
                b_result["r"] = mgr.open_binary("agent-b", path, wait_timeout=2.0)
            finally:
                b_open_done.set()

        ta = threading.Thread(target=close_a)
        ta.start()
        time.sleep(0.05)  # let close start saving
        tb = threading.Thread(target=open_b)
        tb.start()

        ta.join(timeout=3.0)
        tb.join(timeout=3.0)
        assert a_close_done.is_set()
        assert b_open_done.is_set()
        assert b_result["r"]["status"] == "ready"
        # Worker must still be alive — agent-b's open arrived before the
        # final decrement and added a ref.
        assert resolved in mgr._workers
        live = mgr._workers[resolved]
        assert live.alive, "worker was terminated despite an open ref"
        assert len(live.refs) == 1
        only_ref = next(iter(live.refs))
        assert only_ref[0] == "agent-b"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_same_agent_close_then_open_during_save_yields_fresh_session():
    """Same agent's open() racing with their own close() must return a new sid.

    Without the in-lock pop of agent_sessions[sid], the racing open could
    return the dying session_id.  We assert the second open gets a fresh
    ID and the worker survives.
    """
    path = _existing_file()

    def spawn(_p):
        # Slow save lets the racing open land while close is mid-flight.
        def slow_save(req: bytes) -> bytes:
            time.sleep(0.3)
            return _ok_save_response(req)
        return _FakeWorker(ready_after=0.0, rpc_response=slow_save)

    mgr = _make_manager(spawn)
    try:
        a = mgr.open_binary("agent-a", path, wait_timeout=2.0)
        first_sid = a["session"]["session_id"]
        resolved = a["session"]["input_path"]

        result_holder: dict = {}

        def close_a():
            mgr.close_session("agent-a", first_sid)

        def open_a_again():
            time.sleep(0.05)
            result_holder["r"] = mgr.open_binary("agent-a", path, wait_timeout=2.0)

        tc = threading.Thread(target=close_a)
        to = threading.Thread(target=open_a_again)
        tc.start()
        to.start()
        tc.join(timeout=3.0)
        to.join(timeout=3.0)
        assert not tc.is_alive() and not to.is_alive()

        second = result_holder["r"]
        assert second["status"] == "ready"
        new_sid = second["session"]["session_id"]
        assert new_sid != first_sid, "second open must mint a fresh sid"
        # Worker survived because the racing open added a ref before
        # close's refcount check ran.
        assert resolved in mgr._workers
        assert mgr._workers[resolved].alive
        # Agent's view contains the new sid only.
        sids = [s["session_id"] for s in mgr.list_sessions("agent-a")]
        assert sids == [new_sid]
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_list_pending_isolated_per_agent():
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=5.0))
    try:
        mgr.open_binary("agent-a", path, wait_timeout=0.1)
        # agent-b never asked, must see nothing.
        assert mgr.list_pending("agent-b") == []
        assert len(mgr.list_pending("agent-a")) == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_agent_id_from_bearer_helper_is_stable_hash():
    """Same Bearer token → same agent_id; different tokens → different agent_ids.

    The helper lives in zeromcp/mcp.py which uses relative imports we
    can't satisfy under the standalone loader, so we exercise it via the
    real package import path (works when running under ``ida-mcp-test``)
    or skip otherwise.
    """
    try:
        from ...zeromcp.mcp import _agent_id_from_auth_header as helper
    except ImportError:
        fw.skip_test("mcp module not importable standalone")
        return

    assert helper(None) == "anonymous"
    assert helper("") == "anonymous"
    assert helper("Bearer ") == "anonymous"
    assert helper("NotBearer foo") == "anonymous"

    one = helper("Bearer alpha")
    two = helper("Bearer alpha")
    other = helper("Bearer beta")
    assert one == two
    assert one != other
    assert one.startswith("agent_")
    assert one != "anonymous"
