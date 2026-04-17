"""IDALib Worker — single-binary MCP server process.

Each worker opens exactly one binary in its own idalib runtime and serves
all analysis tools over stdio (line-delimited JSON-RPC).  The main
``idalib_server`` process spawns workers and communicates via stdin/stdout
pipes.

Usage (spawned by session manager, not invoked directly)::

    python idalib_worker.py <input_path> [--verbose]
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

# idapro must go first to initialise idalib before any ida_* import.
import idapro

_READY_SENTINEL = "WORKER_READY"
_ERROR_SENTINEL = "WORKER_ERROR"


def main() -> None:
    parser = argparse.ArgumentParser(description="idalib single-binary MCP worker")
    parser.add_argument("input_path", type=str, help="Path to the binary to analyse")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Logging goes to stderr (stdout is reserved for JSON-RPC IPC).
    if args.verbose:
        idapro.enable_console_messages(True)
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    else:
        idapro.enable_console_messages(False)
        logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    logger = logging.getLogger(__name__)

    input_path = Path(args.input_path)
    if not input_path.exists():
        # Error sentinel on stdout so the parent can detect it.
        sys.stdout.write(f"{_ERROR_SENTINEL}:File not found: {input_path}\n")
        sys.stdout.flush()
        sys.exit(1)

    logger.info("Opening database: %s", input_path)
    if idapro.open_database(str(input_path), run_auto_analysis=True):
        sys.stdout.write(
            f"{_ERROR_SENTINEL}:Failed to open database: {input_path}\n"
        )
        sys.stdout.flush()
        sys.exit(1)

    import ida_auto

    ida_auto.auto_wait()
    logger.info("Auto-analysis completed for %s", input_path.name)

    # Import MCP modules — registers all analysis tools with MCP_SERVER.
    from ida_pro_mcp.ida_mcp import MCP_SERVER

    # Save the real stdout for JSON-RPC IPC, then redirect sys.stdout
    # to stderr so that any print() / log inside MCP dispatch does not
    # corrupt the IPC pipe.
    ipc_stdout = sys.stdout.buffer
    sys.stdout = sys.stderr

    # Tell the parent we are ready (on the IPC pipe, before entering
    # the stdio loop).
    ipc_stdout.write(f"{_READY_SENTINEL}\n".encode())
    ipc_stdout.flush()

    def _graceful_shutdown(signum, frame):
        logger.info("Received signal %d, closing database …", signum)
        idapro.close_database()
        logger.info("Database closed.")
        os._exit(0)

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    try:
        MCP_SERVER.stdio(stdin=sys.stdin.buffer, stdout=ipc_stdout)
    finally:
        idapro.close_database()


if __name__ == "__main__":
    main()
