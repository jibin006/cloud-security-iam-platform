from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from secure_agent.workspace import Workspace, WorkspaceDenied


def test_read_from_allowed_root(workspace):
    assert workspace.read_file("src/hello.py") == "print('hello')\n"


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "/etc/passwd",
        "src/../../etc/passwd",
        "policies/tool-policy.json",
        ".env",
        "src/.env.production",
        ".github/workflows/ci.yml",
        "infra/main.tf",
        "k8s/deployment.yaml",
        "tests/../src/hello.py",
    ],
)
def test_forbidden_paths_are_rejected(workspace, path):
    with pytest.raises(WorkspaceDenied):
        workspace.read_file(path)


def test_write_only_under_src_and_precondition_must_match(workspace, tmp_path):
    target = tmp_path / "src" / "hello.py"
    expected = hashlib.sha256(target.read_bytes()).hexdigest()
    new_hash = workspace.propose_patch("src/hello.py", "print('updated')\n", expected)
    assert new_hash == hashlib.sha256(b"print('updated')\n").hexdigest()
    assert target.read_text(encoding="utf-8") == "print('updated')\n"


def test_patch_with_stale_precondition_is_rejected(workspace):
    with pytest.raises(WorkspaceDenied, match="precondition"):
        workspace.propose_patch("src/hello.py", "malicious", "0" * 64)


def test_patch_cannot_write_docs_or_policy(workspace):
    with pytest.raises(WorkspaceDenied):
        workspace.propose_patch("docs/design.md", "changed", "0" * 64)
    with pytest.raises(WorkspaceDenied):
        workspace.propose_patch("policies/tool-policy.json", "{}", "0" * 64)


def test_symlink_escape_is_rejected(workspace, tmp_path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("secret", encoding="utf-8")
    link = tmp_path / "src" / "escape.txt"
    link.symlink_to(outside)
    with pytest.raises(WorkspaceDenied, match="escapes"):
        workspace.read_file("src/escape.txt")


def test_patch_refuses_symlinked_target(workspace, tmp_path):
    original = tmp_path / "src" / "hello.py"
    original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    alias = tmp_path / "src" / "alias.py"
    alias.symlink_to(original)
    with pytest.raises(WorkspaceDenied):
        workspace.propose_patch("src/alias.py", "print('no')", original_hash)
