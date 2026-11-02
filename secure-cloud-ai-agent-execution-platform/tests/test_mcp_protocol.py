from __future__ import annotations

import pytest

from secure_agent.stdio_mcp_server import (
    MCPProtocolError,
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_META_KEY,
    handle_request,
)


def request(method: str, params: dict, request_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def test_server_discover_advertises_stateless_protocol(gateway, issue_agent_token):
    response = handle_request(gateway, issue_agent_token(), request("server/discover", {}))
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == 30_000
    assert result["cacheScope"] == "private"
    assert PROTOCOL_VERSION in result["protocolVersions"]
    assert result["serverInfo"]["name"] == "secure-agent-mcp-gateway"


def test_tools_list_requires_version_metadata(gateway, issue_agent_token):
    with pytest.raises(MCPProtocolError, match="protocol version"):
        handle_request(gateway, issue_agent_token(), request("tools/list", {}))


def test_tools_list_returns_cacheable_identity_filtered_result(gateway, issue_agent_token):
    token = issue_agent_token()
    params = {"_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION}}
    response = handle_request(gateway, token, request("tools/list", params))
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["cacheScope"] == "private"
    assert "read_workspace_file" in {tool["name"] for tool in result["tools"]}
    assert "propose_patch" not in {tool["name"] for tool in result["tools"]}


def test_tools_call_executes_only_gateway_authorized_tool(gateway, issue_agent_token):
    token = issue_agent_token()
    params = {
        "_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION},
        "name": "read_workspace_file",
        "arguments": {"path": "src/hello.py"},
    }
    response = handle_request(gateway, token, request("tools/call", params))
    assert response["result"]["resultType"] == "complete"
    assert response["result"]["isError"] is False


def test_tools_call_unknown_tool_is_returned_as_tool_error(gateway, issue_agent_token):
    token = issue_agent_token()
    params = {
        "_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION},
        "name": "run_shell",
        "arguments": {"command": "id"},
    }
    response = handle_request(gateway, token, request("tools/call", params))
    assert response["result"]["isError"] is True


def test_unknown_method_returns_json_rpc_method_not_found(gateway, issue_agent_token):
    params = {"_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION}}
    response = handle_request(gateway, issue_agent_token(), request("initialize", params))
    assert response["error"]["code"] == -32601


def test_requests_do_not_require_initialize_or_session_state(gateway, issue_agent_token):
    token = issue_agent_token()
    params = {"_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION}}
    # A fresh request can be handled without initialize/initialized state.
    response = handle_request(gateway, token, request("tools/list", params, request_id=21))
    assert response["id"] == 21
    assert response["result"]["resultType"] == "complete"
