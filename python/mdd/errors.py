"""Exceptions. One class per ABI status, plus the engine code on every instance."""
from __future__ import annotations

from typing import Any


class MddError(Exception):
    """A failed call or a failed query.

    `status` is the stable ABI status (None for a query that failed after the call
    itself succeeded), `code` the exact engine code such as ``QUOTA_EXCEEDED``.
    """

    status: int | None = None

    def __init__(self, message: str, *, status: int | None = None, code: str = "",
                 stage: str = "", retryable: bool = False, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        if status is not None:
            self.status = status
        self.code = code
        self.stage = stage
        self.retryable = retryable
        self.details = details or {}

    def __str__(self) -> str:
        where = f" [{self.stage}]" if self.stage else ""
        return f"{self.code or type(self).__name__}{where}: {self.message}"


class InvalidArgument(MddError): status = 1
class InvalidHandle(MddError): status = 2
class Closed(MddError): status = 3
class Busy(MddError): status = 4
class OutstandingBatch(MddError): status = 5
class Cancelled(MddError): status = 6
class DeadlineExceeded(MddError): status = 7
class QuotaExceeded(MddError): status = 8
class Unsupported(MddError): status = 9
class IncompleteFacts(MddError): status = 10
class InvalidInput(MddError): status = 11
class AbiMismatch(MddError): status = 12
class InternalFault(MddError): status = 13


class WorkerLost(MddError):
    """The worker process went away before a request's answer was complete. Raised by
    `mdd.worker.Worker`, never by the in-process library; carries no ABI status."""


class WorkerProtocol(MddError):
    """The worker sent something that is not the line protocol. It is ended."""


_BY_STATUS = {cls.status: cls for cls in (
    InvalidArgument, InvalidHandle, Closed, Busy, OutstandingBatch, Cancelled,
    DeadlineExceeded, QuotaExceeded, Unsupported, IncompleteFacts, InvalidInput,
    AbiMismatch, InternalFault)}

# The same classes, reached from the engine code of a terminal envelope.
_BY_CODE = {
    "INVALID_ARGUMENT": InvalidArgument, "INVALID_CURSOR": InvalidArgument,
    "AMBIGUOUS_ENTITY": InvalidArgument,
    "SNAPSHOT_CLOSED": Closed, "CANCELLED": Cancelled,
    "DEADLINE_EXCEEDED": DeadlineExceeded, "QUOTA_EXCEEDED": QuotaExceeded,
    "UNSUPPORTED_CAPABILITY": Unsupported, "UNSUPPORTED_QUERY": Unsupported,
    "INCOMPLETE_FACTS": IncompleteFacts,
    "INVALID_INPUT": InvalidInput, "PARTIAL_INPUT": InvalidInput, "SOURCE_CHANGED": InvalidInput,
    "WORKER_LOST": WorkerLost,
}


def from_status(status: int, info: dict[str, Any]) -> MddError:
    cls = _BY_STATUS.get(status, MddError)
    return cls(info.get("message", "call failed"), status=status, code=info.get("code", ""),
               stage=info.get("stage", ""), retryable=bool(info.get("retryable")),
               details=info.get("details") or {})


def from_terminal(error: dict[str, Any]) -> MddError:
    """The exception for the error carried by a failure terminal."""
    cls = _BY_CODE.get(error.get("code", ""), MddError)
    return cls(error.get("message", "query failed"), code=error.get("code", ""),
               stage=error.get("stage", ""), retryable=bool(error.get("retryable")),
               details=error.get("details") or {})
