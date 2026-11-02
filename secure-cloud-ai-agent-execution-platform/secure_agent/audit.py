"""Hash-linked audit events; export to independently managed storage in production."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

GENESIS_HASH = "0" * 64


class AuditIntegrityError(ValueError):
    """Raised when an audit record is missing, reordered, or modified."""


class AuditLog:
    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock

    @staticmethod
    def _canonical(value: dict) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def append(
        self,
        *,
        subject: str,
        action: str,
        decision: str,
        detail: str,
        request_id: str,
    ) -> dict:
        existing = self.verify()
        previous_hash = existing[-1]["hash"] if existing else GENESIS_HASH
        payload = {
            "sequence": len(existing) + 1,
            "timestamp": self._clock().astimezone(timezone.utc).isoformat(),
            "subject": subject,
            "action": action,
            "decision": decision,
            "detail": detail,
            "request_id": request_id,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(self._canonical(payload)).hexdigest()
        record = {**payload, "hash": event_hash}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def verify(self) -> list[dict]:
        if not self.path.exists():
            return []
        records: list[dict] = []
        expected_previous = GENESIS_HASH
        with self.path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditIntegrityError(f"Invalid audit JSON at line {line_number}") from exc
                if not isinstance(record, dict) or "hash" not in record:
                    raise AuditIntegrityError(f"Malformed audit record at line {line_number}")
                supplied_hash = record.pop("hash")
                if record.get("sequence") != line_number:
                    raise AuditIntegrityError(f"Audit sequence gap at line {line_number}")
                if record.get("previous_hash") != expected_previous:
                    raise AuditIntegrityError(f"Audit chain link mismatch at line {line_number}")
                expected_hash = hashlib.sha256(self._canonical(record)).hexdigest()
                if not isinstance(supplied_hash, str) or not hmac.compare_digest(supplied_hash, expected_hash):
                    raise AuditIntegrityError(f"Audit hash mismatch at line {line_number}")
                record["hash"] = supplied_hash
                records.append(record)
                expected_previous = supplied_hash
        return records
