"""IDALib Session Manager — multi-process worker management via stdio IPC.

Each binary runs in its own idalib worker subprocess.  Communication uses
line-delimited JSON-RPC over stdin/stdout pipes (no network ports).  A
per-worker lock serialises requests so multiple agents can safely share
the same session manager.
"""

import json
import logging
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_WORKER_SCRIPT = str(Path(__file__).parent / "idalib_worker.py")
_READY_SENTINEL = "WORKER_READY"
_ERROR_SENTINEL = "WORKER_ERROR"


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


class IDASessionManager:
    """Manages idalib worker subprocesses communicating via stdio.

    * ``open_binary()`` spawns a worker, waits for it to be ready, and
      returns its ``session_id``.
    * ``proxy_jsonrpc(session_id, method, params)`` sends a JSON-RPC
      request to the worker via stdin and reads the response from stdout.
    * ``close_session(session_id)`` terminates the worker.
    """

    def __init__(self):
        self._sessions: Dict[str, IDAWorkerSession] = {}
        self._lock = threading.RLock()
        logger.info("IDASessionManager initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def open_binary(
        self,
        input_path: Path | str,
        timeout: float = 120.0,
    ) -> str:
        """Spawn a worker for *input_path* and return the session ID."""
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            # Re-use existing session for the same binary
            for sid, session in self._sessions.items():
                if session.input_path.resolve() == input_path.resolve():
                    if session.alive:
                        logger.info("Binary already open in session %s", sid)
                        session.last_accessed = datetime.now()
                        return sid
                    else:
                        logger.warning("Stale session %s, re-spawning", sid)
                        self._sessions.pop(sid)
                        break

            session_id = str(uuid.uuid4())[:8]

        # Spawn outside the lock to avoid blocking other operations.
        worker = self._spawn_worker(input_path, timeout)

        with self._lock:
            session = IDAWorkerSession(
                session_id=session_id,
                input_path=input_path,
                process=worker,
            )
            self._sessions[session_id] = session

        logger.info(
            "Session %s ready: %s (pid %d)",
            session_id,
            input_path.name,
            worker.pid,
        )
        return session_id

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        self._terminate_worker(session)
        logger.info("Session closed: %s", session_id)
        return True

    def proxy_jsonrpc(self, session_id: str, method: str, params: dict) -> dict:
        """Send a JSON-RPC request to a worker and return the parsed response."""
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")
        if not session.alive:
            raise RuntimeError(
                f"Worker for session {session_id} is dead (pid {session.process.pid}). "
                "Close and re-open the binary."
            )
        session.last_accessed = datetime.now()

        request_line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode() + b"\n"

        with session._lock:
            try:
                session.process.stdin.write(request_line)
                session.process.stdin.flush()
                response_line = session.process.stdout.readline()
            except (BrokenPipeError, OSError) as e:
                raise RuntimeError(
                    f"Worker pipe broken for session {session_id}: {e}"
                ) from e

        if not response_line:
            raise RuntimeError(
                f"Worker for session {session_id} closed unexpectedly"
            )
        return json.loads(response_line)

    def get_session(self, session_id: str) -> Optional[IDAWorkerSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    def close_all_sessions(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            self._terminate_worker(session)
        logger.info("All sessions closed")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _spawn_worker(self, input_path: Path, timeout: float) -> subprocess.Popen:
        cmd = [sys.executable, _WORKER_SCRIPT, str(input_path)]
        logger.info("Spawning worker: %s", " ".join(cmd))

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit parent stderr → journal / terminal
        )

        # Wait for the WORKER_READY sentinel on stdout.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"Worker exited with code {proc.returncode} for {input_path}"
                )

            line = proc.stdout.readline().decode().strip()
            if line == _READY_SENTINEL:
                return proc
            if line.startswith(_ERROR_SENTINEL):
                proc.kill()
                raise RuntimeError(line.split(":", 1)[1])

            time.sleep(0.2)

        proc.kill()
        raise RuntimeError(
            f"Worker did not become ready within {timeout}s for {input_path}"
        )

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


def get_session_manager() -> IDASessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = IDASessionManager()
    return _session_manager
