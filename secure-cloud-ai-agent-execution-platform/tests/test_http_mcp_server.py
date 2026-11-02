from __future__ import annotations

from fastapi.testclient import TestClient

from secure_agent.http_mcp_server import create_app
from secure_agent.stdio_mcp_server import PROTOCOL_VERSION, PROTOCOL_VERSION_META_KEY


def test_discovery_is_available_without_bearer(gateway):
    client = TestClient(create_app(gateway))
    response = client.post(
        "/mcp",
        headers={"Mcp-Method": "server/discover"},
        json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
    )
    assert response.status_code == 200
    assert response.json()["result"]["resultType"] == "complete"


def test_tools_list_requires_bearer(gateway, issue_agent_token):
    client = TestClient(create_app(gateway))
    response = client.post(
        "/mcp",
        headers={
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/list",
        },
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION}},
        },
    )
    assert response.status_code == 401


def test_tools_list_requires_protocol_version_and_returns_cache_hints(gateway, issue_agent_token):
    client = TestClient(create_app(gateway))
    token = issue_agent_token()
    response = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/list",
        },
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {"_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION}},
        },
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == 30_000
    assert result["cacheScope"] == "private"


def test_tools_call_requires_matching_mcp_name_header(gateway, issue_agent_token):
    client = TestClient(create_app(gateway))
    token = issue_agent_token()
    response = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "run_shell",
        },
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION},
                "name": "read_workspace_file",
                "arguments": {"path": "src/hello.py"},
            },
        },
    )
    assert response.status_code == 400


def test_tools_call_accepts_matching_identity_and_tool_headers(gateway, issue_agent_token):
    client = TestClient(create_app(gateway))
    token = issue_agent_token()
    response = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "read_workspace_file",
        },
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "_meta": {PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION},
                "name": "read_workspace_file",
                "arguments": {"path": "src/hello.py"},
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["result"]["isError"] is False


def test_http_rejects_wrong_protocol_version(gateway, issue_agent_token):
    client = TestClient(create_app(gateway))
    token = issue_agent_token()
    response = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": "2025-11-25",
            "Mcp-Method": "tools/list",
        },
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/list",
            "params": {"_meta": {PROTOCOL_VERSION_META_KEY: "2025-11-25"}},
        },
    )
    assert response.status_code == 400
