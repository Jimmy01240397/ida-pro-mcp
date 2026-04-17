"""IDALib MCP Server — multi-process session router.

The main process never opens an IDA database.  Instead it spawns one
worker subprocess per binary (via :mod:`idalib_session_manager`) and
routes every tool / resource call to the correct worker based on the
``session_id`` argument.  Workers communicate via stdio (stdin/stdout
pipes), not network ports.

Management tools (``idalib_open``, ``idalib_close``, ``idalib_list``)
are handled locally.  All other tools are proxied to the worker that owns
the requested session.
"""

import argparse
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# idapro must be imported first to initialise idalib so that the
# ida_pro_mcp.ida_mcp package (which imports idaapi, idc, …) can load.
import idapro

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.profile import apply_profile, load_profile
from ida_pro_mcp.ida_mcp.rpc import tool
from ida_pro_mcp.idalib_session_manager import get_session_manager


# -----------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------

class IdalibSessionInfo(TypedDict):
    session_id: str
    input_path: str
    filename: str
    alive: bool
    pid: int
    created_at: str
    last_accessed: str
    metadata: dict[str, Any]


class IdalibOpenResult(TypedDict, total=False):
    success: bool
    session: IdalibSessionInfo
    message: str
    error: str


class IdalibCloseResult(TypedDict, total=False):
    success: bool
    message: str
    error: str


class IdalibListResult(TypedDict, total=False):
    sessions: list[IdalibSessionInfo]
    count: int
    error: str


logger = logging.getLogger(__name__)

# Tools handled by the main process — not proxied to workers.
IDALIB_MANAGEMENT_TOOLS = {"idalib_open", "idalib_close", "idalib_list"}

# Tools that don't touch any IDA database — handled locally, no session_id needed.
_SESSION_FREE_TOOLS = IDALIB_MANAGEMENT_TOOLS | {
    "int_convert",
    "list_instances",
    "select_instance",
    "open_file",
}

# JSON-Schema snippet injected into every proxied tool.
_SESSION_ID_SCHEMA = {
    "type": "string",
    "description": (
        "Session ID identifying which IDA database to operate on "
        "(from idalib_open / idalib_list)"
    ),
}


# -----------------------------------------------------------------------
# Proxy helper
# -----------------------------------------------------------------------

def _proxy_to_worker(session_id: str, method: str, params: dict) -> dict:
    """Send a JSON-RPC request to a worker via stdio and return the
    MCP result envelope (e.g. ``{content, structuredContent, isError}``)."""
    manager = get_session_manager()
    response = manager.proxy_jsonrpc(session_id, method, params)
    if "error" in response:
        err = response["error"]
        return {
            "content": [{"type": "text", "text": err.get("message", str(err))}],
            "isError": True,
        }
    return response.get("result", {})


# -----------------------------------------------------------------------
# Dispatch hooks
# -----------------------------------------------------------------------

def _install_session_hooks() -> None:
    """Wrap MCP dispatch so every non-management call is proxied to the
    correct worker subprocess based on ``session_id``.
    """
    if getattr(MCP_SERVER, "_idalib_session_hooks_installed", False):
        return

    # -- tools/call ----------------------------------------------------
    original_tools_call = MCP_SERVER.registry.methods["tools/call"]

    def tools_call_with_session(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        if name in _SESSION_FREE_TOOLS:
            return original_tools_call(name, arguments, _meta)

        if arguments is None:
            arguments = {}

        session_id = arguments.pop("session_id", None)
        if not session_id:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Missing required parameter 'session_id'. "
                            "Use idalib_list to see available sessions."
                        ),
                    }
                ],
                "isError": True,
            }

        try:
            return _proxy_to_worker(
                session_id, "tools/call",
                {"name": name, "arguments": arguments},
            )
        except Exception as e:
            return {
                "content": [{"type": "text", "text": str(e)}],
                "isError": True,
            }

    MCP_SERVER.registry.methods["tools/call"] = tools_call_with_session

    # -- tools/list ----------------------------------------------------
    original_tools_list = MCP_SERVER.registry.methods["tools/list"]

    def tools_list_with_session(_meta: Optional[dict] = None) -> dict:
        result = original_tools_list(_meta)
        for tool_schema in result.get("tools", []):
            if tool_schema.get("name") in _SESSION_FREE_TOOLS:
                continue
            input_schema = tool_schema.get("inputSchema", {})
            props = input_schema.setdefault("properties", {})
            required = input_schema.setdefault("required", [])
            if "session_id" not in props:
                props["session_id"] = _SESSION_ID_SCHEMA
            if "session_id" not in required:
                required.append("session_id")
        return result

    MCP_SERVER.registry.methods["tools/list"] = tools_list_with_session

    # -- resources/read ------------------------------------------------
    original_resources_read = MCP_SERVER.registry.methods["resources/read"]

    def resources_read_with_session(
        uri: str, _meta: Optional[dict] = None
    ) -> dict:
        parsed = urlparse(uri)
        qs = parse_qs(parsed.query)
        session_id = qs.pop("session", [None])[0]

        if not session_id:
            manager = get_session_manager()
            sessions = manager.list_sessions()
            if len(sessions) == 1:
                session_id = sessions[0]["session_id"]
            else:
                return {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "error": (
                                        "Missing ?session=<id> in resource URI. "
                                        "Use idalib_list to see available sessions."
                                    )
                                },
                                indent=2,
                            ),
                        }
                    ],
                    "isError": True,
                }

        clean_qs = urlencode(qs, doseq=True) if qs else ""
        clean_uri = urlunparse(parsed._replace(query=clean_qs))

        try:
            return _proxy_to_worker(
                session_id, "resources/read", {"uri": clean_uri}
            )
        except Exception as e:
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps({"error": str(e)}, indent=2),
                    }
                ],
                "isError": True,
            }

    MCP_SERVER.registry.methods["resources/read"] = resources_read_with_session

    setattr(MCP_SERVER, "_idalib_session_hooks_installed", True)


# -----------------------------------------------------------------------
# Management tools (handled locally, not proxied)
# -----------------------------------------------------------------------

@tool
def idalib_open(
    input_path: Annotated[str, "Path to the binary file to analyse"],
) -> IdalibOpenResult:
    """Open a binary in a new worker process. Returns the session_id for subsequent calls."""
    try:
        manager = get_session_manager()
        opened_id = manager.open_binary(Path(input_path))
        session = manager.get_session(opened_id)
        return {
            "success": True,
            "session": session.to_dict(),
            "message": f"Binary opened: {session.input_path.name} (session_id={opened_id})",
        }
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idalib_close(
    session_id: Annotated[str, "Session ID to close"],
) -> IdalibCloseResult:
    """Close an idalib session (terminates the worker process)."""
    try:
        manager = get_session_manager()
        if manager.close_session(session_id):
            return {"success": True, "message": f"Session closed: {session_id}"}
        return {"success": False, "error": f"Session not found: {session_id}"}
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


@tool
def idalib_list() -> IdalibListResult:
    """List all open idalib sessions and their worker status."""
    try:
        manager = get_session_manager()
        sessions = manager.list_sessions()
        return {"sessions": sessions, "count": len(sessions)}
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port (default: 8745)"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions"
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Restrict exposed tools to those listed in a profile file "
            "(one name per line, # for comments). idalib_* management tools "
            "are always kept."
        ),
    )
    parser.add_argument(
        "input_path", type=Path, nargs="?",
        help="Optional initial binary to open on startup.",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    session_manager = get_session_manager()

    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")
        logger.info("Opening initial binary: %s", args.input_path)
        sid = session_manager.open_binary(args.input_path)
        logger.info("Initial session ready: %s", sid)
    else:
        logger.info(
            "No initial binary. Use idalib_open() to load binaries dynamically."
        )

    def cleanup_and_exit(signum, frame):
        logger.info("Shutting down — closing all sessions …")
        session_manager.close_all_sessions()
        logger.info("All sessions closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # Gate unsafe tools: remove them from the registry unless --unsafe is set.
    if not args.unsafe:
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    if args.profile is not None:
        try:
            whitelist = load_profile(args.profile)
        except (OSError, UnicodeDecodeError) as e:
            raise SystemExit(f"Failed to read profile '{args.profile}': {e}")
        kept, unknown = apply_profile(
            MCP_SERVER.tools.methods,
            whitelist,
            protected=IDALIB_MANAGEMENT_TOOLS,
        )
        if unknown:
            logger.warning(
                "Profile references unknown tool(s) (ignored): %s", ", ".join(unknown)
            )
        logger.info(
            "Profile applied: %d whitelisted + %d management tool(s) active",
            len(kept),
            len(IDALIB_MANAGEMENT_TOOLS),
        )

    _install_session_hooks()

    MCP_SERVER.serve(host=args.host, port=args.port, background=False)


if __name__ == "__main__":
    main()
