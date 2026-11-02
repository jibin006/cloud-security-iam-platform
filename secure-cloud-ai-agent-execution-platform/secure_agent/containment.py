"""Agent suspension control for the local platform reference implementation."""

from __future__ import annotations

from .audit import AuditLog


class ContainmentController:
    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit
        self._suspended: dict[str, str] = {}

    def suspend(self, subject: str, reason: str, request_id: str) -> None:
        if not subject or not reason:
            raise ValueError("subject and reason are required")
        self._suspended[subject] = reason
        self._audit.append(
            subject=subject,
            action="agent.suspend",
            decision="deny",
            detail=reason,
            request_id=request_id,
        )

    def resume(self, subject: str, *, approver: str, request_id: str) -> None:
        if not approver:
            raise ValueError("An approver identity is required")
        if subject in self._suspended:
            del self._suspended[subject]
        self._audit.append(
            subject=subject,
            action="agent.resume",
            decision="allow",
            detail=f"resumed_by={approver}",
            request_id=request_id,
        )

    def is_suspended(self, subject: str) -> bool:
        return subject in self._suspended

    def reason(self, subject: str) -> str | None:
        return self._suspended.get(subject)
