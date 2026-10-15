"""
Scan Controller - the Application API

The single orchestration path both interfaces use. Given a validated
ScanConfiguration it resolves the target, runs the chosen scan engine
(streaming progress and honouring cancellation), optionally runs service
detection, computes metrics, and returns a structured ScanReport.

It contains no presentation logic and no file I/O: callers (CLI adapter,
GUI controller) format and persist the report themselves via the shared
report package. It emits progress through an optional `on_event` callback
so the GUI stays responsive; the CLI passes a quiet listener.
"""

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from core.connect_scan import connect_scan
from core.syn_scan import syn_scan
from report.formatter import build_metrics
from service.detect import detect_services

from .events import (CancelToken, ErrorCategory, EventType, Phase, ScanEvent,
                     ScanStatus, TargetResolutionError, TCPraxError)
from .scan_configuration import ScanConfiguration, ScanType

# Emit a PROGRESS event at most once per this many completed ports, so a
# large scan does not flood the listener. PORT_RESULT is
# still emitted for every port for streaming displays.
_PROGRESS_EVERY = 20

EventCallback = Callable[[ScanEvent], None]


@dataclass
class ScanReport:
    """Structured outcome of a scan run."""
    config: ScanConfiguration
    target_ip: str
    meta: Dict
    results: List[Dict] = field(default_factory=list)
    metrics: Dict = field(default_factory=dict)
    status: str = ScanStatus.COMPLETED
    duration: float = 0.0
    error: Optional[str] = None


def resolve_host(target: str) -> str:
    """
    Resolves a hostname or IPv4 string to an IPv4 address.

    Raises:
        TargetResolutionError if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise TargetResolutionError(
            "Hostname could not be resolved.") from exc


def _scan_type_label(config: ScanConfiguration) -> str:
    return ("TCP Connect Scan (-sT)" if config.scan_type == ScanType.CONNECT
            else "TCP SYN Scan (-sS)")


def run_scan(config: ScanConfiguration,
             on_event: Optional[EventCallback] = None,
             cancel_token: Optional[CancelToken] = None) -> ScanReport:
    """
    Runs a scan described by `config` and returns a ScanReport.

    Parameters:
        config: A ScanConfiguration (validated here if not already)
        on_event: Optional callback receiving ScanEvent progress/lifecycle
        cancel_token: Optional cooperative cancellation token

    Raises:
        ScanConfigurationError: invalid configuration (pre-flight)
        TargetResolutionError: target could not be resolved (pre-flight)

    Runtime errors during scanning are captured into the report
    (status FAILED) rather than raised, so a partial result is preserved.
    """

    def emit(event_type: str, **data) -> None:
        if on_event is not None:
            on_event(ScanEvent(event_type, data))

    # ---- Pre-flight (may raise; these are caller-visible) ----
    config.validate()
    ports = config.resolved_ports()
    workers = config.effective_workers(len(ports))
    target_ip = resolve_host(config.target)

    meta = {
        "target": config.target,
        "resolved_ip": target_ip,
        "scan_type": _scan_type_label(config),
        "threads": workers,
        "total_ports": len(ports),
        "service_detection": config.service_detection,
        "retries": config.retries,
    }

    report = ScanReport(config=config, target_ip=target_ip, meta=meta)
    total = len(ports)
    processed = 0
    started = time.perf_counter()

    emit(EventType.SCAN_STARTED, meta=meta)

    def on_port_result(result: Dict) -> None:
        nonlocal processed
        processed += 1
        emit(EventType.PORT_RESULT, result=result)
        if processed % _PROGRESS_EVERY == 0 or processed == total:
            emit(EventType.PROGRESS, processed=processed, total=total,
                 phase=Phase.PORT_SCAN)

    should_cancel = cancel_token.is_cancelled if cancel_token else None

    try:
        # ---- Phase 1: port scan ----
        emit(EventType.PHASE_CHANGED, phase=Phase.PORT_SCAN, total=total)

        engine = connect_scan if config.scan_type == ScanType.CONNECT \
            else syn_scan
        results = engine(target_ip, ports, workers=workers,
                         retries=config.retries, on_result=on_port_result,
                         should_cancel=should_cancel)
        report.results = results

        cancelled = bool(cancel_token and cancel_token.is_cancelled())

        # ---- Phase 2: service detection (OPEN ports only) ----
        if config.service_detection and not cancelled:
            open_ports = [r for r in results if r["state"] == "OPEN"]
            if open_ports:
                sd_total = len(open_ports)
                emit(EventType.PHASE_CHANGED,
                     phase=Phase.SERVICE_DETECTION, total=sd_total)
                _run_service_detection(target_ip, results, emit, sd_total)

        report.duration = time.perf_counter() - started
        report.metrics = build_metrics(results, report.duration)
        emit(EventType.METRICS, metrics=report.metrics)

        if cancelled:
            report.status = ScanStatus.CANCELLED
            emit(EventType.SCAN_CANCELLED, report_status=report.status)
        else:
            report.status = ScanStatus.COMPLETED
            emit(EventType.SCAN_FINISHED, report_status=report.status)

    except TCPraxError as exc:
        report.duration = time.perf_counter() - started
        report.status = ScanStatus.FAILED
        report.error = str(exc)
        report.metrics = build_metrics(report.results, report.duration)
        emit(EventType.ERROR, category=exc.category, message=str(exc))
        emit(EventType.SCAN_FINISHED, report_status=report.status)
    except Exception as exc:  # noqa: BLE001 - surfaced, not swallowed
        report.duration = time.perf_counter() - started
        report.status = ScanStatus.FAILED
        report.error = str(exc)
        report.metrics = build_metrics(report.results, report.duration)
        emit(EventType.ERROR, category=ErrorCategory.RUNTIME,
             message=str(exc))
        emit(EventType.SCAN_FINISHED, report_status=report.status)

    return report


def _run_service_detection(target_ip: str, results: List[Dict],
                           emit: Callable, total: int) -> None:
    """
    Runs -sV detection, emitting a SERVICE_RESULT for each identified port
    and a PROGRESS event on the service-detection scale (0..total).

    Detection runs concurrently, so the completion counter is guarded by a
    lock; PROGRESS is throttled the same way the port-scan phase is. The
    open-port count (`total`) is the denominator here - not the port-scan
    total - so the progress fraction stays correct once this phase starts.
    """
    progress_lock = threading.Lock()
    completed = 0

    def detector(ip: str, port: int) -> dict:
        nonlocal completed
        from service.banner import discover_service_result
        info = discover_service_result(ip, port)
        emit(EventType.SERVICE_RESULT, port=port, info=info)
        with progress_lock:
            completed += 1
            current = completed
        if current % _PROGRESS_EVERY == 0 or current == total:
            emit(EventType.PROGRESS, processed=current, total=total,
                 phase=Phase.SERVICE_DETECTION)
        return info

    detect_services(target_ip, results, detector=detector)
