"""Filesystem capability boundary with traversal and symlink checks."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path, PurePosixPath


class WorkspaceDenied(PermissionError):
    """Raised when a path or filesystem operation is outside workspace policy."""


class Workspace:
    def __init__(
        self,
        root: str | Path,
        *,
        read_roots: tuple[str, ...] = ("src", "docs", "tests"),
        write_roots: tuple[str, ...] = ("src",),
        max_file_bytes: int = 128_000,
    ) -> None:
        candidate = Path(root)
        candidate.mkdir(parents=True, exist_ok=True)
        self.root = candidate.resolve(strict=True)
        self.read_roots = read_roots
        self.write_roots = write_roots
        self.max_file_bytes = max_file_bytes
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")

    @staticmethod
    def _validate_relative_path(relative_path: str) -> PurePosixPath:
        if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
            raise WorkspaceDenied("A non-empty relative path is required")
        normalized = relative_path.replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise WorkspaceDenied("Absolute paths and traversal segments are not allowed")
        if ":" in path.parts[0]:
            raise WorkspaceDenied("Drive-qualified paths are not allowed")
        if any(part in {".git", ".github", "__pycache__"} for part in path.parts):
            raise WorkspaceDenied("Protected repository metadata is not accessible")
        if any(part == ".env" or part.startswith(".env.") for part in path.parts):
            raise WorkspaceDenied("Environment and secret files are not accessible")
        return path

    def _resolve(self, relative_path: str, roots: tuple[str, ...]) -> Path:
        path = self._validate_relative_path(relative_path)
        if not path.parts or path.parts[0] not in roots:
            raise WorkspaceDenied(f"Path is outside approved roots: {relative_path}")
        target = (self.root / Path(*path.parts)).resolve(strict=False)
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise WorkspaceDenied("Resolved path escapes workspace root") from exc
        if any(part in {"infra", "k8s", "policies", "config", "supply-chain"} for part in path.parts):
            raise WorkspaceDenied("Security and deployment configuration is protected")
        return target

    def read_file(self, relative_path: str) -> str:
        target = self._resolve(relative_path, self.read_roots)
        if not target.is_file():
            raise WorkspaceDenied("Requested workspace file does not exist")
        if target.stat().st_size > self.max_file_bytes:
            raise WorkspaceDenied("File exceeds the configured read limit")
        return target.read_text(encoding="utf-8")

    def propose_patch(self, relative_path: str, content: str, expected_sha256: str) -> str:
        target = self._resolve(relative_path, self.write_roots)
        if not target.is_file():
            raise WorkspaceDenied("Patches must target an existing source file")
        encoded = content.encode("utf-8")
        if len(encoded) > self.max_file_bytes:
            raise WorkspaceDenied("Patch exceeds the configured size limit")
        current = target.read_bytes()
        current_hash = hashlib.sha256(current).hexdigest()
        if current_hash != expected_sha256:
            raise WorkspaceDenied("Patch precondition failed: source file changed")
        parent = target.parent.resolve(strict=True)
        try:
            parent.relative_to(self.root)
        except ValueError as exc:
            raise WorkspaceDenied("Resolved parent escapes workspace root") from exc
        fd, temporary_name = tempfile.mkstemp(prefix=".agent-patch-", dir=parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            if target.is_symlink() or target.resolve(strict=False).parent != parent:
                raise WorkspaceDenied("Target changed during patch operation")
            os.replace(temporary_name, target)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return hashlib.sha256(encoded).hexdigest()
