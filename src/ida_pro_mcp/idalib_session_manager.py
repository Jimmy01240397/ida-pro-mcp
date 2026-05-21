"""IDALib Session Manager — multi-agent, multi-process worker management.

Workers vs. agent sessions
--------------------------

Each binary on disk maps to *at most one* worker subprocess
(``IDAWorker``).  Multiple agents that open the same path are handed
*distinct* agent-scoped session IDs that all reference that single
worker.  This means:

* Spawning IDA happens once per binary, no matter how many agents are
  attached.  The expensive auto-analysis cost is amortised.
* Each agent sees an isolated session list (``idalib_list`` only
  returns their own session IDs).  Cross-agent session-ID guessing
  doesn't help because the manager validates ``(agent_id, session_id)``
  pairs on every call.
* Closing a session saves the database (``.i64``) first and then drops
  this agent's reference.  The worker is terminated only when the last
  agent releases the binary, so other agents keep working without
  interruption.

Pending-open semantics from the prior commit still apply: ``open`` may
return ``{status: "opening", ...}`` after ``wait_timeout``, agents
calling ``open`` again coalesce onto the same pending entry, and
``list_sessions`` hides pending workers.

Concurrency model
-----------------

* ``self._lock`` (``RLock``) protects all in-memory maps:
  ``_workers``, ``_agent_sessions``, ``_pending``.  All check-then-mutate
  sequences run under it.
* Each worker has its own ``io_lock`` serialising stdin/stdout JSON-RPC
  with the subprocess — multiple agents on the same worker queue up,
  multiple workers proceed in parallel.
* ``_finalise_pending`` uses an identity check (``existing is pending``)
  so a displaced pending (e.g. after ``close_all_sessions``) kills its
  worker instead of getting promoted into a phantom session.
* Save-then-decrement on close is split: the save runs under the
  worker's ``io_lock``, the refcount mutation runs under ``self._lock``,
  and only when refs become empty does the manager remove the worker.
  A concurrent ``open`` of the same path during this window simply adds
  itself to ``worker.refs`` before the close re-acquires the lock, which
  keeps the worker alive — no leaked workers, no terminated-then-reused
  workers.
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
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_WORKER_SCRIPT = str(Path(__file__).parent / "idalib_worker.py")
_READY_SENTINEL = "WORKER_READY"
_ERROR_SENTINEL = "WORKER_ERROR"

_DEFAULT_WAIT_TIMEOUT = 10.0  # seconds before open returns "opening"
_DEFAULT_SPAWN_TIMEOUT = 3600.0  # hard limit on background spawn (1 hour)
_DEFAULT_SAVE_TIMEOUT = 600.0  # ceiling on the save_database JSON-RPC call


@dataclass
class IDAWorker:
    """Worker subprocess serving one binary, shared across agents."""

    resolved_path: str
    process: subprocess.Popen
    created_at: datetime = field(default_factory=datetime.now)
    io_lock: threading.Lock = field(default_factory=threading.Lock)
    # Every (agent_id, agent_session_id) currently holding a reference.
    refs: set[Tuple[str, str]] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def alive(self) -> bool:
        return self.process.poll() is None


@dataclass
class AgentSession:
    """Per-agent view of an open binary."""

    agent_id: str
    session_id: str  # short, unique within agent_id
    resolved_path: str
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": self.resolved_path,
            "filename": Path(self.resolved_path).name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
        }


@dataclass
class PendingOpen:
    """A worker subprocess that has been spawned but is not yet ready."""

    resolved_path: str
    process: subprocess.Popen
    started_at: datetime
    ready_event: threading.Event
    # agent_id → agent_session_id allocated for that waiter.  When the
    # worker becomes ready every entry here is materialised into an
    # AgentSession and the worker.refs set.
    refs: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def elapsed_seconds(self) -> float:
        return (datetime.now() - self.started_at).total_seconds()

    def status_dict_for_agent(self, session_id: str) -> dict:
        return {
            "status": "opening",
            "session_id": session_id,
            "resolved_path": self.resolved_path,
            "filename": Path(self.resolved_path).name,
            "started_at": self.started_at.isoformat(),
            "elapsed_seconds": self.elapsed_seconds,
            "pid": self.process.pid,
        }


class IDASessionManager:
    """Multi-agent session manager."""

    def __init__(self):
        self._workers: Dict[str, IDAWorker] = {}  # resolved_path → worker
        self._agent_sessions: Dict[str, Dict[str, AgentSession]] = {}
        self._pending: Dict[str, PendingOpen] = {}
        self._lock = threading.RLock()
        logger.info("IDASessionManager initialised (multi-agent mode)")

    # ------------------------------------------------------------------
    # Open
    # ------------------------------------------------------------------

    def open_binary(
        self,
        agent_id: str,
        input_path: Path | str,
        wait_timeout: float = _DEFAULT_WAIT_TIMEOUT,
        spawn_timeout: float = _DEFAULT_SPAWN_TIMEOUT,
    ) -> dict:
        """Open *input_path* for *agent_id*.

        Returns one of:

        * ``{"status": "ready", "session": <agent session dict>}`` — the
          worker is live and the returned ``session_id`` is usable for
          tool calls right away.
        * ``{"status": "opening", "session_id": ..., ...}`` — the worker
          is still being spawned.  Subsequent ``open_binary`` calls from
          the *same* agent for the same path return the same
          ``session_id``; calls from *other* agents get their own
          ``session_id`` but share the same underlying spawn.
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        resolved = str(input_path.resolve())

        with self._lock:
            # Re-use a live worker for the same binary.
            worker = self._workers.get(resolved)
            if worker is not None and worker.alive:
                existing = self._find_agent_session_for_path(agent_id, resolved)
                if existing is None:
                    existing = self._mint_agent_session(agent_id, resolved)
                    worker.refs.add((agent_id, existing.session_id))
                existing.last_accessed = datetime.now()
                return {
                    "status": "ready",
                    "session": self._session_to_dict(existing, worker),
                }

            if worker is not None and not worker.alive:
                logger.warning(
                    "Stale worker for %s (pid %d), re-spawning",
                    resolved,
                    worker.process.pid,
                )
                self._drop_worker(worker)

            # Re-use or start a pending spawn.
            pending = self._pending.get(resolved)
            if pending is None:
                pending = self._begin_spawn(input_path, resolved, spawn_timeout)
            # Allocate (or re-use) this agent's session id on the pending.
            if agent_id in pending.refs:
                agent_session_id = pending.refs[agent_id]
            else:
                agent_session_id = self._allocate_session_id(agent_id)
                pending.refs[agent_id] = agent_session_id

        # Wait OUTSIDE the manager lock.
        pending.ready_event.wait(timeout=wait_timeout)

        with self._lock:
            # Did the worker materialise?
            session = self._agent_sessions.get(agent_id, {}).get(agent_session_id)
            if session is not None:
                worker = self._workers.get(session.resolved_path)
                if worker is not None and worker.alive:
                    session.last_accessed = datetime.now()
                    return {
                        "status": "ready",
                        "session": self._session_to_dict(session, worker),
                    }

            if pending.error and pending.refs.get(agent_id) == agent_session_id:
                raise RuntimeError(pending.error)

            return pending.status_dict_for_agent(agent_session_id)

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close_session(self, agent_id: str, session_id: str) -> dict:
        """Drop *agent_id*'s reference to *session_id*.

        Saves the database first.  If the agent was the last holder of
        the underlying worker, terminates it.  Returns a status dict
        describing what happened.
        """
        # Step 1 — atomically remove this agent's view of the session so
        # a concurrent open(same path) from the same agent doesn't see
        # the dying session_id.  worker.refs still holds (agent, sid) so
        # the worker isn't seen as ref-free yet; other agents opening the
        # binary during our save will simply add another ref and keep it
        # alive.
        with self._lock:
            session = self._agent_sessions.get(agent_id, {}).pop(session_id, None)
            if session is None:
                # Maybe the agent is closing a still-pending session?
                pending = self._find_pending_for_agent_session(agent_id, session_id)
                if pending is not None:
                    pending.refs.pop(agent_id, None)
                    return {
                        "success": True,
                        "saved": False,
                        "terminated": False,
                        "message": "Cancelled pending open for this agent.",
                    }
                return {
                    "success": False,
                    "error": f"Session not found for this agent: {session_id}",
                }
            resolved = session.resolved_path
            worker = self._workers.get(resolved)

        if worker is None:
            return {
                "success": True,
                "saved": False,
                "terminated": False,
                "message": "Session removed (worker was already gone).",
            }

        # Step 2 — save outside the global lock so other agents can keep
        # using the worker (any tool call from them will queue on
        # worker.io_lock just like our save does).
        saved, save_error = self._save_database(worker)

        # Step 3 — drop our refcount and decide whether to terminate.
        # If another agent opened the binary while we were saving,
        # worker.refs now contains their (agent, sid) and we leave the
        # worker alive.
        with self._lock:
            worker.refs.discard((agent_id, session_id))
            if worker.refs:
                return {
                    "success": True,
                    "saved": saved,
                    "save_error": save_error,
                    "terminated": False,
                    "remaining_refs": len(worker.refs),
                    "message": (
                        f"Session removed; {len(worker.refs)} other agent session(s) "
                        f"still attached to this binary."
                    ),
                }
            # Last ref — drop the worker from the map under the lock so
            # any concurrent open sees "no worker" and starts a fresh
            # spawn instead of attaching to a dying one.
            self._workers.pop(resolved, None)

        # Step 4 — terminate outside the global lock, holding io_lock so
        # any concurrent proxy_jsonrpc finishes before we kill the pipe.
        with worker.io_lock:
            self._terminate_worker(worker)
        logger.info("Worker %s terminated (last agent released)", resolved)
        return {
            "success": True,
            "saved": saved,
            "save_error": save_error,
            "terminated": True,
            "message": "Database saved and worker terminated.",
        }

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_sessions(self, agent_id: str) -> list[dict]:
        """Return live sessions visible to *agent_id* only."""
        with self._lock:
            sessions = self._agent_sessions.get(agent_id, {}).values()
            return [
                self._session_to_dict(s, self._workers.get(s.resolved_path))
                for s in sessions
            ]

    @staticmethod
    def _session_to_dict(
        session: "AgentSession", worker: Optional["IDAWorker"]
    ) -> dict:
        d = session.to_dict()
        d["alive"] = worker is not None and worker.alive
        d["pid"] = worker.process.pid if worker is not None else None
        d["metadata"] = dict(worker.metadata) if worker is not None else {}
        return d

    def list_pending(self, agent_id: str) -> list[dict]:
        """Return pending opens this *agent_id* has requested."""
        with self._lock:
            out = []
            for pending in self._pending.values():
                agent_session_id = pending.refs.get(agent_id)
                if agent_session_id is None:
                    continue
                out.append(pending.status_dict_for_agent(agent_session_id))
            return out

    # ------------------------------------------------------------------
    # Tool dispatch
    # ------------------------------------------------------------------

    def proxy_jsonrpc(
        self, agent_id: str, session_id: str, method: str, params: dict
    ) -> dict:
        """Forward a JSON-RPC call to the worker behind ``(agent_id, session_id)``.

        Other agents' session IDs are rejected — even if guessed — so
        agent A can't drive a session that belongs to agent B.
        """
        with self._lock:
            session = self._agent_sessions.get(agent_id, {}).get(session_id)
            if session is None:
                pending = self._find_pending_for_agent_session(agent_id, session_id)
                if pending is not None:
                    raise RuntimeError(
                        f"Session {session_id} is still opening "
                        f"(elapsed={pending.elapsed_seconds:.1f}s). "
                        f"Call idalib_open again to wait for it to be ready."
                    )
                raise ValueError(f"Session not found for this agent: {session_id}")
            worker = self._workers.get(session.resolved_path)
            if worker is None or not worker.alive:
                raise RuntimeError(
                    f"Worker for {session.resolved_path} is no longer alive. "
                    "Close and re-open the binary."
                )
            session.last_accessed = datetime.now()
            worker.io_lock.acquire()

        # Outside self._lock; holding worker.io_lock — close that
        # involves termination will block on it.
        try:
            return self._call_worker_locked(worker, method, params)
        finally:
            worker.io_lock.release()

    # ------------------------------------------------------------------
    # Internal: worker I/O
    # ------------------------------------------------------------------

    def _call_worker_locked(
        self, worker: IDAWorker, method: str, params: dict
    ) -> dict:
        """Send one JSON-RPC request.  Must be called with worker.io_lock held."""
        request_line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode() + b"\n"
        try:
            worker.process.stdin.write(request_line)
            worker.process.stdin.flush()
            response_line = worker.process.stdout.readline()
        except (BrokenPipeError, OSError) as e:
            raise RuntimeError(
                f"Worker pipe broken for {worker.resolved_path}: {e}"
            ) from e
        if not response_line:
            raise RuntimeError(
                f"Worker for {worker.resolved_path} closed unexpectedly"
            )
        return json.loads(response_line)

    def _save_database(self, worker: IDAWorker) -> tuple[bool, Optional[str]]:
        """Call save_database on *worker*.  Returns (success, error_message)."""
        if not worker.alive:
            return False, "Worker is not alive"
        with worker.io_lock:
            try:
                response = self._call_worker_locked(
                    worker,
                    "tools/call",
                    {"name": "save_database", "arguments": {}},
                )
            except Exception as e:  # noqa: BLE001 — surface as save error
                logger.warning("save_database failed for %s: %s", worker.resolved_path, e)
                return False, str(e)
        if "error" in response:
            msg = response["error"].get("message", str(response["error"]))
            logger.warning("save_database error for %s: %s", worker.resolved_path, msg)
            return False, msg
        result = response.get("result", {})
        if isinstance(result, dict) and result.get("isError"):
            text = ""
            for c in result.get("content", []):
                if isinstance(c, dict) and c.get("type") == "text":
                    text = c.get("text", "")
                    break
            logger.warning("save_database returned isError for %s: %s", worker.resolved_path, text)
            return False, text or "save_database returned isError"
        return True, None

    # ------------------------------------------------------------------
    # Internal: lookup helpers
    # ------------------------------------------------------------------

    def _find_agent_session_for_path(
        self, agent_id: str, resolved: str
    ) -> Optional[AgentSession]:
        for s in self._agent_sessions.get(agent_id, {}).values():
            if s.resolved_path == resolved:
                return s
        return None

    def _find_pending_for_agent_session(
        self, agent_id: str, session_id: str
    ) -> Optional[PendingOpen]:
        for pending in self._pending.values():
            if pending.refs.get(agent_id) == session_id:
                return pending
        return None

    def _allocate_session_id(self, agent_id: str) -> str:
        """Mint a short ID unique within *agent_id*."""
        existing = self._agent_sessions.get(agent_id, {})
        pending_ids = {
            sid for p in self._pending.values()
            if (sid := p.refs.get(agent_id)) is not None
        }
        for _ in range(64):
            candidate = uuid.uuid4().hex[:8]
            if candidate not in existing and candidate not in pending_ids:
                return candidate
        # Extremely unlikely, but fall back to full UUID rather than loop forever.
        return uuid.uuid4().hex

    def _mint_agent_session(self, agent_id: str, resolved: str) -> AgentSession:
        session_id = self._allocate_session_id(agent_id)
        session = AgentSession(
            agent_id=agent_id,
            session_id=session_id,
            resolved_path=resolved,
        )
        self._agent_sessions.setdefault(agent_id, {})[session_id] = session
        return session

    # ------------------------------------------------------------------
    # Internal: spawn lifecycle
    # ------------------------------------------------------------------

    def _begin_spawn(
        self, input_path: Path, resolved: str, spawn_timeout: float
    ) -> PendingOpen:
        """Spawn a worker process and register the pending entry.

        Called with ``self._lock`` held.
        """
        process = self._start_worker_process(input_path)
        pending = PendingOpen(
            resolved_path=resolved,
            process=process,
            started_at=datetime.now(),
            ready_event=threading.Event(),
        )
        self._pending[resolved] = pending

        monitor = threading.Thread(
            target=self._monitor_spawn,
            args=(pending, spawn_timeout),
            daemon=True,
            name=f"idalib-spawn-{resolved}",
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
            stderr=None,
        )

    def _monitor_spawn(self, pending: PendingOpen, timeout: float) -> None:
        """Background thread: wait for WORKER_READY (cross-platform)."""
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
            except Exception as e:  # noqa: BLE001
                result.append((False, f"Reader thread crashed: {e}"))
                done.set()

        threading.Thread(
            target=reader,
            daemon=True,
            name=f"idalib-reader-{pending.resolved_path}",
        ).start()

        if done.wait(timeout=timeout):
            ok, err = result[0]
            if ok:
                self._finalise_pending(pending, ok=True)
            else:
                self._kill_process(proc)
                self._finalise_pending(pending, error=err)
            return

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
        """Promote a pending entry to a worker (or surface failure to waiters).

        Materialises every agent waiting on the pending into an
        AgentSession + worker.refs entry, so callers wake up with their
        session ready to use.  Identity-checks ``_pending[path] is pending``
        before promoting so displaced pendings (e.g. after
        ``close_all_sessions``) get their workers killed instead of
        leaking into ``_workers``.
        """
        promoted = False
        with self._lock:
            existing = self._pending.get(pending.resolved_path)
            owned = existing is pending
            if owned:
                self._pending.pop(pending.resolved_path)

            if owned and ok:
                worker = IDAWorker(
                    resolved_path=pending.resolved_path,
                    process=pending.process,
                )
                self._workers[pending.resolved_path] = worker
                for agent_id, agent_session_id in pending.refs.items():
                    session = AgentSession(
                        agent_id=agent_id,
                        session_id=agent_session_id,
                        resolved_path=pending.resolved_path,
                    )
                    self._agent_sessions.setdefault(agent_id, {})[agent_session_id] = session
                    worker.refs.add((agent_id, agent_session_id))
                promoted = True
                logger.info(
                    "Worker ready: %s (pid %d, %d agent ref(s))",
                    Path(pending.resolved_path).name,
                    pending.process.pid,
                    len(worker.refs),
                )
            elif not owned:
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

        pending.ready_event.set()

    # ------------------------------------------------------------------
    # Internal: termination
    # ------------------------------------------------------------------

    def _drop_worker(self, worker: IDAWorker) -> None:
        """Remove a worker from _workers and from every agent's session map."""
        self._workers.pop(worker.resolved_path, None)
        for agent_id, agent_session_id in list(worker.refs):
            sessions = self._agent_sessions.get(agent_id, {})
            sessions.pop(agent_session_id, None)
        worker.refs.clear()

    @staticmethod
    def _kill_process(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.kill()
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to kill worker pid %d: %s", proc.pid, e)

    @staticmethod
    def _terminate_worker(worker: IDAWorker) -> None:
        proc = worker.process
        if proc.poll() is not None:
            return
        logger.info(
            "Terminating worker pid %d (%s)", proc.pid, worker.resolved_path
        )
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            logger.warning("Worker pid %d did not exit, killing", proc.pid)
            proc.kill()

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def close_all_sessions(self) -> None:
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
            self._agent_sessions.clear()
            pendings = list(self._pending.values())
        for worker in workers:
            with worker.io_lock:
                self._terminate_worker(worker)
        for pending in pendings:
            self._kill_process(pending.process)
        logger.info("All sessions closed")


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
