# NOTE: Vendored from zeromcp 1.3.0
# Local additions on top of vendored upstream: ANONYMOUS_AGENT_ID +
# _agent_id_from_auth_header re-exports for the Bearer-based agent
# isolation layer used by IdalibSupervisor.

from .mcp import (
    ANONYMOUS_AGENT_ID,
    EXTERNAL_BASE_HEADER,
    McpRpcRegistry,
    McpToolError,
    McpServer,
    McpHttpRequestHandler,
    _agent_id_from_auth_header,
    get_current_request_external_base_url,
    set_current_request_external_base_url,
)

__all__ = [
    "ANONYMOUS_AGENT_ID",
    "EXTERNAL_BASE_HEADER",
    "McpRpcRegistry",
    "McpToolError",
    "McpServer",
    "McpHttpRequestHandler",
    "_agent_id_from_auth_header",
    "get_current_request_external_base_url",
    "set_current_request_external_base_url",
]
