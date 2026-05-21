"""Tests for IDASessionManager pending-open semantics.

Workers are simulated with a FakeWorker that writes ``WORKER_READY``
to an OS pipe after a configurable delay.  This lets us exercise the
real reader/finalise code paths without spawning idalib subprocesses,
and keeps the tests cross-platform.
"""

import importlib.util
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


# Load `framework` and `idalib_session_manager` WITHOUT going through the
# ida_mcp package __init__ (which imports ``idaapi``).  This keeps the test
# runnable under plain pytest, in addition to the in-IDA ``ida-mcp-test``
# runner that discovers it via ``@fw.test``.
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
    """Stand-in for proc.stdin — accepts writes, discards them."""

    def write(self, _data):
        return len(_data)

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
                chunk = os.read(self._fd, 4096)
            except OSError:
                self._closed = True
                return buf
            if not chunk:
                self._closed = True
                return buf
            buf += chunk
            if b"\n" in buf:
                line, _rest = buf.split(b"\n", 1)
                # Push the remainder back: easiest is to keep a small buffer.
                # We don't actually need partial reads for these tests because
                # _FakeWorker writes one full sentinel line at a time.
                return line + b"\n"

    def close(self):
        if not self._closed:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._closed = True


class _FakeWorker:
    """subprocess.Popen-like object whose stdout emits one sentinel."""

    _pid_counter = 90000

    def __init__(
        self,
        *,
        ready_after: float = 0.0,
        write_error: str | None = None,
        never_ready: bool = False,
    ):
        self._read_fd, self._write_fd = os.pipe()
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(self._read_fd)
        _FakeWorker._pid_counter += 1
        self.pid = _FakeWorker._pid_counter
        self._returncode: int | None = None
        self._never_ready = never_ready

        if never_ready:
            return  # nothing will be written; tests rely on kill() / timeout

        def writer() -> None:
            time.sleep(ready_after)
            try:
                if write_error is not None:
                    line = f"{ism._ERROR_SENTINEL}:{write_error}\n"
                else:
                    line = f"{ism._READY_SENTINEL}\n"
                os.write(self._write_fd, line.encode())
            except OSError:
                pass

        threading.Thread(target=writer, daemon=True).start()

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
# Manager factory + binary stub
# ---------------------------------------------------------------------------


def _make_manager(spawn_factory):
    """Build an IDASessionManager whose _start_worker_process is fake."""

    mgr = ism.IDASessionManager()
    mgr._start_worker_process = spawn_factory  # type: ignore[assignment]
    return mgr


def _existing_file() -> Path:
    """Return a path that exists.  Any file under the project works."""

    here = Path(__file__).resolve()
    assert here.exists()
    return here


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@fw.test()
def test_open_returns_ready_when_worker_signals_ready():
    """Fast worker should produce a 'ready' status before wait_timeout."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.0))
    try:
        result = mgr.open_binary(path, wait_timeout=2.0)
        assert result["status"] == "ready", result
        session = result["session"]
        assert session["filename"] == path.name
        assert session["alive"] is True
        assert mgr.list_pending() == []
        assert len(mgr.list_sessions()) == 1
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_returns_opening_when_wait_timeout_elapses():
    """Slow worker should produce an 'opening' status without killing it."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=2.0))
    try:
        t0 = time.monotonic()
        result = mgr.open_binary(path, wait_timeout=0.2, spawn_timeout=10.0)
        elapsed = time.monotonic() - t0
        assert result["status"] == "opening", result
        assert elapsed < 1.5, f"wait_timeout not honoured: {elapsed:.2f}s"
        assert result["filename"] == path.name
        # list_sessions must hide pending opens
        assert mgr.list_sessions() == []
        # but list_pending shows it
        pendings = mgr.list_pending()
        assert len(pendings) == 1
        assert pendings[0]["session_id"] == result["session_id"]
        # Worker is NOT killed — wait for it to actually become ready
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if mgr.list_sessions():
                break
            time.sleep(0.05)
        assert mgr.list_sessions(), "worker never finalised after wait_timeout"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_duplicate_open_during_pending_returns_opening_status():
    """A second open() for the same path must NOT raise — returns 'opening'."""
    path = _existing_file()
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=2.0)

    mgr = _make_manager(spawn)
    try:
        first = mgr.open_binary(path, wait_timeout=0.2)
        second = mgr.open_binary(path, wait_timeout=0.2)
        assert first["status"] == "opening"
        assert second["status"] == "opening"
        assert first["session_id"] == second["session_id"], "session_id should coalesce"
        assert spawn_count["n"] == 1, f"duplicate spawn: {spawn_count['n']}"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_list_sessions_excludes_pending_then_includes_after_ready():
    """list_sessions must hide the binary until WORKER_READY arrives."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.4))
    try:
        result = mgr.open_binary(path, wait_timeout=0.1)
        assert result["status"] == "opening", result
        assert mgr.list_sessions() == [], "pending must not appear in list_sessions"

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if mgr.list_sessions():
                break
            time.sleep(0.05)
        sessions = mgr.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["filename"] == path.name
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_after_ready_returns_existing_session():
    """Calling open() again after the worker is live reuses the session."""
    path = _existing_file()
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.0)

    mgr = _make_manager(spawn)
    try:
        first = mgr.open_binary(path, wait_timeout=2.0)
        second = mgr.open_binary(path, wait_timeout=2.0)
        assert first["status"] == "ready"
        assert second["status"] == "ready"
        assert first["session"]["session_id"] == second["session"]["session_id"]
        assert spawn_count["n"] == 1, "second open must not respawn"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_spawn_failure_surfaces_to_all_waiters_and_clears_pending():
    """Worker error → both initial caller and subsequent caller see the error."""
    path = _existing_file()
    mgr = _make_manager(
        lambda _p: _FakeWorker(ready_after=0.0, write_error="open_database failed")
    )
    try:
        try:
            mgr.open_binary(path, wait_timeout=2.0)
        except RuntimeError as e:
            assert "open_database failed" in str(e)
        else:
            assert False, "expected RuntimeError"

        # Pending was cleared — a fresh open spawns again.
        spawn_count = {"n": 0}

        def spawn(_p):
            spawn_count["n"] += 1
            return _FakeWorker(ready_after=0.0)

        mgr._start_worker_process = spawn  # type: ignore[assignment]
        result = mgr.open_binary(path, wait_timeout=2.0)
        assert result["status"] == "ready"
        assert spawn_count["n"] == 1, "retry must spawn a fresh worker"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_proxy_jsonrpc_for_pending_session_id_gives_helpful_error():
    """Tool calls against a still-opening session_id must explain why."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=5.0))
    try:
        result = mgr.open_binary(path, wait_timeout=0.1)
        assert result["status"] == "opening"
        try:
            mgr.proxy_jsonrpc(result["session_id"], "tools/list", {})
        except RuntimeError as e:
            assert "still opening" in str(e), str(e)
        else:
            assert False, "expected RuntimeError"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_concurrent_opens_for_same_path_coalesce_to_one_spawn():
    """N parallel open() calls must spawn exactly one worker."""
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
        r = mgr.open_binary(path, wait_timeout=2.0)
        with results_lock:
            results.append(r)

    try:
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), "open_binary hung in a worker thread"
        assert spawn_count["n"] == 1, f"spawned {spawn_count['n']} workers"
        assert len(results) == 8
        assert all(r["status"] == "ready" for r in results)
        # All callers should observe the same session id.
        ids = {r["session"]["session_id"] for r in results}
        assert len(ids) == 1, ids
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_for_different_paths_does_not_block_on_pending_other_path():
    """A pending open for A must not block a concurrent open for B.

    Both calls use a short wait_timeout — if open(B) ever waited for
    open(A) to become ready, total elapsed would exceed the slow
    ready_after.  Instead, both return 'opening' quickly.
    """
    path_a = _existing_file()
    path_b = Path(ism.__file__).resolve()
    if path_a.resolve() == path_b:
        path_b = Path(fw.__file__).resolve()
    assert path_a.resolve() != path_b

    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=3.0))
    try:
        t0 = time.monotonic()
        result_a = mgr.open_binary(path_a, wait_timeout=0.1)
        result_b = mgr.open_binary(path_b, wait_timeout=0.1)
        elapsed = time.monotonic() - t0
        assert result_a["status"] == "opening"
        assert result_b["status"] == "opening"
        assert elapsed < 1.5, f"opens serialised on each other: {elapsed:.2f}s"
        assert result_a["session_id"] != result_b["session_id"]
        assert len(mgr.list_pending()) == 2
        assert mgr.list_sessions() == []
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_list_pending_returns_status_dicts_for_in_flight_opens():
    """list_pending must surface all current pending opens with their elapsed times."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=2.0))
    try:
        result = mgr.open_binary(path, wait_timeout=0.1)
        assert result["status"] == "opening"
        pending = mgr.list_pending()
        assert len(pending) == 1
        entry = pending[0]
        assert entry["session_id"] == result["session_id"]
        assert entry["filename"] == path.name
        assert entry["elapsed_seconds"] >= 0.1
        assert "started_at" in entry and "pid" in entry
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_two_callers_to_same_session_serialise_on_session_lock():
    """Same-session tool calls must serialise so JSON-RPC responses don't interleave."""
    path = _existing_file()
    mgr = _make_manager(lambda _p: _FakeWorker(ready_after=0.0))
    try:
        result = mgr.open_binary(path, wait_timeout=2.0)
        assert result["status"] == "ready"
        session_id = result["session"]["session_id"]
        session = mgr.get_session(session_id)

        # Replace process stdin/stdout with a pair of objects that
        # observe the lock-ordering at the I/O boundary.
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

        session.process.stdin = _SerialStdin()
        session.process.stdout = _SerialStdout()

        def call():
            mgr.proxy_jsonrpc(session_id, "tools/call", {})

        threads = [threading.Thread(target=call) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)
            assert not t.is_alive(), "proxy_jsonrpc hung"

        assert active.is_set(), "no calls reached the worker"
        assert not overlap.is_set(), "I/O overlapped — session lock did not serialise"
    finally:
        mgr.close_all_sessions()


@fw.test()
def test_open_missing_file_raises_file_not_found():
    """Non-existent path is rejected synchronously, no worker spawned."""
    spawn_count = {"n": 0}

    def spawn(_p):
        spawn_count["n"] += 1
        return _FakeWorker(ready_after=0.0)

    mgr = _make_manager(spawn)
    try:
        try:
            mgr.open_binary("Z:/this/path/does/not/exist.bin")
        except FileNotFoundError:
            pass
        else:
            assert False, "expected FileNotFoundError"
        assert spawn_count["n"] == 0
    finally:
        mgr.close_all_sessions()
