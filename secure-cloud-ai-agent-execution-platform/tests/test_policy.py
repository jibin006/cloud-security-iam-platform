import pytest

from secure_agent.identity import AgentIdentity
from secure_agent.policy import AuthorizationError, ToolPolicy


def identity(roles=frozenset({"agent"}), scopes=frozenset({"workspace:read"})):
    return AgentIdentity(
        issuer="issuer",
        subject="agent-1",
        audience="gateway",
        scopes=scopes,
        roles=roles,
        issued_at=1,
        expires_at=2,
        token_id="id-1",
    )


def test_policy_authorizes_matching_role_scope_and_arguments(policy):
    policy.authorize(identity(), "read_workspace_file", {"path": "src/hello.py"})


def test_policy_denies_unregistered_tool(policy):
    with pytest.raises(AuthorizationError, match="not registered"):
        policy.authorize(identity(), "run_shell", {})


def test_policy_denies_missing_role(policy):
    with pytest.raises(AuthorizationError, match="Role"):
        policy.authorize(identity(roles=frozenset({"viewer"})), "read_workspace_file", {"path": "src/hello.py"})


def test_policy_denies_missing_scope(policy):
    with pytest.raises(AuthorizationError, match="scope"):
        policy.authorize(identity(scopes=frozenset()), "read_workspace_file", {"path": "src/hello.py"})


def test_policy_denies_unexpected_arguments(policy):
    with pytest.raises(AuthorizationError, match="Unexpected"):
        policy.authorize(identity(), "read_workspace_file", {"path": "src/hello.py", "command": "id"})


def test_policy_denies_missing_required_arguments(policy):
    with pytest.raises(AuthorizationError, match="Missing"):
        policy.authorize(identity(), "read_workspace_file", {})


def test_policy_rejects_non_object_arguments(policy):
    with pytest.raises(AuthorizationError, match="JSON object"):
        policy.authorize(identity(), "read_workspace_file", ["src/hello.py"])
