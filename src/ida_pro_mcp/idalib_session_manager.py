"""IDALib Session Manager — multi-process worker management via stdio IPC.

Each binary runs in its own idalib worker subprocess.  Communication uses
line-delimited JSON-RPC over stdin/stdout pipes (no network ports).  A
per-worker lock serialises requests so multiple agents can safely share
the same session manager.

Opens are split into two phases:

* The caller of :meth:`open_binary` blocks for at most ``wait_timeout``
  seconds.  If the worker becomes ready in that window, ``open_binary``
  returns ``{"status": "ready", "session": ...}``.
* Otherwise it returns ``{"status": "opening", ...}``; a background
  thread keeps reading the worker's stdout until either ``WORKER_READY``
  arrives (at which point the session is published) or ``spawn_timeout``
  elapses (at which point the worker is killed and the slot freed).

Concurrent ``open_binary`` calls for the same path coalesce onto a
single worker, so duplicate spawns are impossible even when the HTTP
server dispatches requests on multiple threads.
"""

import atexit
import json
import logging
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_WORKER_SCRIPT = str(Path(__file__).parent / "idalib_worker.py")
_READY_SENTINEL = "WORKER_READY"
_ERROR_SENTINEL = "WORKER_ERROR"

_DEFAULT_WAIT_TIMEOUT = 10.0  # seconds before open_binary returns "opening"
_DEFAULT_SPAWN_TIMEOUT = 3600.0  # hard limit on background spawn (1 hour)


@dataclass
class IDAWorkerSession:
    """Represents a worker subprocess serving one IDA database."""

    session_id: str
    input_path: Path
    process: subprocess.Popen
    _lock: threading.Lock = field(default_factory=threading.Lock)
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "alive": self.alive,
            "pid": self.process.pid,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class PendingOpen:
    """A worker subprocess that has been spawned but is not yet ready."""

    resolved_path: str
    session_id: str
    process: subprocess.Popen
    started_at: datetime
    ready_event: threading.Event
    error: Optional[str] = None  # set when spawn fails; ready_event is also set

    @property
    def elapsed_seconds(self) -> float:
        return (datetime.now() - self.started_at).total_seconds()

    def to_status_dict(self) -> dict:
        return {
            "status": "opening",
            "session_id": self.session_id,
            "resolved_path": self.resolved_path,
            "filename": Path(self.resolved_path).name,
            "started_at": self.started_at.isoformat(),
            "elapsed_seconds": self.elapsed_seconds,
            "pid": self.process.pid,
        }


class IDASessionManager:
    """Manages idalib worker subprocesses communicating via stdio."""

    def __init__(self):
        self._sessions: Dict[str, IDAWorkerSession] = {}
        # resolved-path → in-flight spawn.  Holding ``_lock`` makes the
        # check-and-insert atomic, which is what prevents duplicate spawns.
        self._pending: Dict[str, PendingOpen] = {}
        self._lock = threading.RLock()
        logger.info("IDASessionManager initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def open_binary(
        self,
        input_path: Path | str,
        wait_timeout: float = _DEFAULT_WAIT_TIMEOUT,
        spawn_timeout: float = _DEFAULT_SPAWN_TIMEOUT,
    ) -> dict:
        """Open a worker for *input_path* and return its status.

        Returns one of:

        * ``{"status": "ready", "session": <session dict>}`` — worker is
          live and the session ID is valid for tool calls.
        * ``{"status": "opening", "session_id": ..., "elapsed_seconds": ..., ...}``
          — the worker is still being spawned.  The same dict shape can
          be obtained from subsequent ``open_binary`` calls for the same
          path; the returned ``session_id`` is *not yet* usable for
          ``proxy_jsonrpc`` until ``status`` becomes ``"ready"``.

        Raises ``FileNotFoundError`` if the path doesn't exist, and
        ``RuntimeError`` if the worker spawn failed.  Failed pendings are
        removed from the in-flight set immediately, so a fresh
        ``open_binary`` call will start a new spawn.
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        resolved = str(input_path.resolve())

        with self._lock:
            # Re-use a live session for the same binary.
            for sid, session in list(self._sessions.items()):
                if str(session.input_path.resolve()) == resolved:
                    if session.alive:
                        session.last_accessed = datetime.now()
                        return {"status": "ready", "session": session.to_dict()}
                    # Stale session — drop it and fall through to spawn.
                    logger.warning("Stale session %s, re-spawning", sid)
                    self._sessions.pop(sid)
                    break

            pending = self._pending.get(resolved)
            if pending is None:
                pending = self._begin_spawn(input_path, resolved, spawn_timeout)

        # Wait OUTSIDE the manager lock so other paths (and concurrent
        # callers for the same path) aren't blocked.  The pending object
        # lives until _finalise_pending() decides its fate.
        pending.ready_event.wait(timeout=wait_timeout)

        with self._lock:
            session = self._sessions.get(pending.session_id)
            if session is not None:
                session.last_accessed = datetime.now()
                return {"status": "ready", "session": session.to_dict()}
            if pending.error:
                # All waiters on this pending see the same error.  The
                # entry has already been removed from _pending by
                # _finalise_pending, so a fresh open call will retry.
                raise RuntimeError(pending.error)
            return pending.to_status_dict()

    def close_session(self, session_id: str) -> bool:
        """Terminate a live session.  Returns ``False`` for unknown IDs.

        Pending sessions (still spawning) are intentionally not affected
        here — wait for them to finish or fail naturally.
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        # Wait for any in-flight I/O to finish before terminating.
        with session._lock:
            self._terminate_worker(session)
        logger.info("Session closed: %s", session_id)
        return True

    def proxy_jsonrpc(self, session_id: str, method: str, params: dict) -> dict:
        """Send a JSON-RPC request to a worker and return the parsed response."""
        # Acquire session._lock while still holding self._lock so that
        # close_session cannot terminate the worker in the gap.
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                # Friendlier error if the caller is using a session_id
                # that's still being spawned.
                pending = next(
                    (p for p in self._pending.values() if p.session_id == session_id),
                    None,
                )
                if pending is not None:
                    raise RuntimeError(
                        f"Session {session_id} is still opening "
                        f"(elapsed={pending.elapsed_seconds:.1f}s). "
                        f"Call idalib_open again to wait for it to be ready."
                    )
                raise ValueError(f"Session not found: {session_id}")
            if not session.alive:
                raise RuntimeError(
                    f"Worker for session {session_id} is dead (pid {session.process.pid}). "
                    "Close and re-open the binary."
                )
            session.last_accessed = datetime.now()
            session._lock.acquire()

        # self._lock is released — other sessions can proceed.
        # session._lock is held — close_session will block on _terminate_worker
        # because we hold the I/O lock.
        try:
            request_line = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode() + b"\n"
            try:
                session.process.stdin.write(request_line)
                session.process.stdin.flush()
                response_line = session.process.stdout.readline()
            except (BrokenPipeError, OSError) as e:
                raise RuntimeError(
                    f"Worker pipe broken for session {session_id}: {e}"
                ) from e
        finally:
            session._lock.release()

        if not response_line:
            raise RuntimeError(
                f"Worker for session {session_id} closed unexpectedly"
            )
        return json.loads(response_line)

    def get_session(self, session_id: str) -> Optional[IDAWorkerSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict]:
        """Return only sessions whose worker is ready for tool calls.

        Pending opens are deliberately excluded — they appear here only
        after ``WORKER_READY`` is received.
        """
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    def list_pending(self) -> list[dict]:
        """Return status entries for in-flight opens (mainly for debugging)."""
        with self._lock:
            return [p.to_status_dict() for p in self._pending.values()]

    def close_all_sessions(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            pendings = list(self._pending.values())
            # Don't clear _pending here — _finalise_pending() will remove
            # entries as monitor threads exit, and we want the kill to
            # propagate via EOF detection.
        for session in sessions:
            with session._lock:
                self._terminate_worker(session)
        for pending in pendings:
            self._kill_process(pending.process)
        logger.info("All sessions closed")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _begin_spawn(
        self, input_path: Path, resolved: str, spawn_timeout: float
    ) -> PendingOpen:
        """Spawn a worker process and register the pending entry.

        Called with ``self._lock`` held.
        """
        session_id = str(uuid.uuid4())[:8]
        process = self._start_worker_process(input_path)
        pending = PendingOpen(
            resolved_path=resolved,
            session_id=session_id,
            process=process,
            started_at=datetime.now(),
            ready_event=threading.Event(),
        )
        self._pending[resolved] = pending

        monitor = threading.Thread(
            target=self._monitor_spawn,
            args=(pending, spawn_timeout),
            daemon=True,
            name=f"idalib-spawn-{session_id}",
        )
        monitor.start()
        return pending

    def _start_worker_process(self, input_path: Path) -> subprocess.Popen:
        """Spawn the worker subprocess.  Overridable for tests."""
        cmd = [sys.executable, _WORKER_SCRIPT, str(input_path)]
        logger.info("Spawning worker: %s", " ".join(cmd))
        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit parent stderr → journal / terminal
        )

    def _monitor_spawn(self, pending: PendingOpen, timeout: float) -> None:
        """Background thread: wait for WORKER_READY (cross-platform).

        A nested reader thread does the blocking ``readline()`` (so it
        works on Windows, where ``select`` doesn't accept pipe FDs), and
        an Event lets us bound the wait by ``timeout``.
        """
        proc = pending.process
        result: list[tuple[bool, Optional[str]]] = []
        done = threading.Event()

        def reader() -> None:
            try:
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        result.append(
                            (False, f"Worker stdout closed (returncode={proc.poll()})")
                        )
                        done.set()
                        return
                    text = line.decode(errors="replace").strip()
                    if text == _READY_SENTINEL:
                        result.append((True, None))
                        done.set()
                        return
                    if text.startswith(_ERROR_SENTINEL):
                        err = (
                            text.split(":", 1)[1]
                            if ":" in text
                            else "Worker reported error"
                        )
                        result.append((False, err))
                        done.set()
                        return
                    # Other lines (debug logs etc.) are ignored.
            except Exception as e:  # noqa: BLE001 — propagate as spawn error
                result.append((False, f"Reader thread crashed: {e}"))
                done.set()

        threading.Thread(
            target=reader,
            daemon=True,
            name=f"idalib-reader-{pending.session_id}",
        ).start()

        if done.wait(timeout=timeout):
            ok, err = result[0]
            if ok:
                self._finalise_pending(pending, ok=True)
            else:
                self._kill_process(proc)
                self._finalise_pending(pending, error=err)
            return

        # Hard spawn timeout — kill the worker so the reader thread
        # unblocks via EOF, then surface the failure to any waiter.
        self._kill_process(proc)
        self._finalise_pending(
            pending, error=f"Worker did not become ready within {timeout}s"
        )

    def _finalise_pending(
        self,
        pending: PendingOpen,
        *,
        ok: bool = False,
        error: Optional[str] = None,
    ) -> None:
        """Move a pending entry to either _sessions or the error slot.

        If the pending entry has been displaced (e.g. by
        ``close_all_sessions`` clearing state) we do NOT promote it to
        a session — instead the worker is killed and the failure is
        surfaced to waiters.  This keeps ``_sessions`` consistent with
        ``_pending``: every live session went through a real spawn that
        nobody else cancelled.

        The ``ready_event`` is set last so any waiter observes a
        consistent view of either ``_sessions`` or ``pending.error``.
        """
        promoted = False
        with self._lock:
            existing = self._pending.get(pending.resolved_path)
            owned = existing is pending
            if owned:
                self._pending.pop(pending.resolved_path)

            if owned and ok:
                session = IDAWorkerSession(
                    session_id=pending.session_id,
                    input_path=Path(pending.resolved_path),
                    process=pending.process,
                )
                self._sessions[pending.session_id] = session
                promoted = True
                logger.info(
                    "Session %s ready: %s (pid %d)",
                    pending.session_id,
                    session.input_path.name,
                    pending.process.pid,
                )
            elif not owned:
                # Another path displaced this pending — most likely a
                # reset.  Discard the worker so we don't leak a dead-end
                # subprocess, and surface a clear error to waiters.
                pending.error = "Spawn cancelled (pending entry was displaced)"
                logger.warning(
                    "Pending for %s was displaced; discarding worker",
                    pending.resolved_path,
                )
            else:
                pending.error = error or "unknown error"
                logger.warning(
                    "Spawn failed for %s: %s",
                    pending.resolved_path,
                    pending.error,
                )

        if not promoted:
            self._kill_process(pending.process)

        # Signal waiters AFTER releasing the lock so they observe
        # _sessions / pending.error in the correct state.
        pending.ready_event.set()

    @staticmethod
    def _kill_process(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.kill()
        except Exception as e:  # noqa: BLE001 — best-effort cleanup
            logger.warning("Failed to kill worker pid %d: %s", proc.pid, e)

    @staticmethod
    def _terminate_worker(session: IDAWorkerSession) -> None:
        proc = session.process
        if proc.poll() is not None:
            return
        logger.info(
            "Terminating worker pid %d (session %s)", proc.pid, session.session_id
        )
        # Close stdin to signal the worker's stdio loop to exit.
        try:
            proc.stdin.close()
        except OSError:
            pass
        # Then send SIGTERM for the graceful close_database() handler.
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            logger.warning("Worker pid %d did not exit, killing", proc.pid)
            proc.kill()


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------

_session_manager: Optional[IDASessionManager] = None
_session_manager_lock = threading.Lock()


def _cleanup_at_exit() -> None:
    if _session_manager is not None:
        _session_manager.close_all_sessions()


atexit.register(_cleanup_at_exit)


def get_session_manager() -> IDASessionManager:
    global _session_manager
    if _session_manager is None:
        with _session_manager_lock:
            if _session_manager is None:
                _session_manager = IDASessionManager()
    return _session_manager
