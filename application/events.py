"""
Application Events, Status, Errors and Cancellation

Shared vocabulary the controller uses to talk to any presentation layer.
The CLI consumes these through a simple listener; the GUI forwards them
to Qt signals. Neither interface inspects core internals directly.
"""

import threading
from dataclasses import dataclass, field
from typing import Any, Dict


# ---- Event types (controller -> presentation) ----
class EventType:
    SCAN_STARTED = "scan_started"
    PHASE_CHANGED = "phase_changed"
    PROGRESS = "progress_changed"
    PORT_RESULT = "port_result"
    SERVICE_RESULT = "service_result"
    METRICS = "metrics_updated"
    WARNING = "warning"
    ERROR = "error"
    SCAN_FINISHED = "scan_finished"
    SCAN_CANCELLED = "scan_cancelled"


# ---- Scan phases ----
class Phase:
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"


# ---- Scan status (a finished scan's outcome) ----
class ScanStatus:
    RUNNING = "Running"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"
    FAILED = "Failed"
    PARTIAL = "Partial"


# ---- Error categories carried by ERROR events (exc.category) ----
class ErrorCategory:
    CONFIGURATION = "configuration"
    RESOLUTION = "resolution"
    RUNTIME = "runtime"


class TCPraxError(Exception):
    """Base for expected TCPrax errors, tagged with an ErrorCategory."""

    category = ErrorCategory.RUNTIME

    def __init__(self, message: str, category: "str | None" = None):
        super().__init__(message)
        if category is not None:
            self.category = category


class ScanConfigurationError(TCPraxError):
    category = ErrorCategory.CONFIGURATION


class TargetResolutionError(TCPraxError):
    category = ErrorCategory.RESOLUTION


@dataclass
class ScanEvent:
    """One progress/lifecycle event emitted by the controller."""
    type: str
    data: Dict[str, Any] = field(default_factory=dict)


class CancelToken:
    """
    Thread-safe cooperative cancellation flag.

    The controller/scheduler checks is_cancelled() between units of work;
    setting it does not kill running work, so in-flight probes finish and
    partial results are preserved.
    """

    def __init__(self):
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def reset(self) -> None:
        self._event.clear()
