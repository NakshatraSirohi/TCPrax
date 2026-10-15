"""
GUI Scan Controller

The bridge between QML and the application layer. It holds the scan
configuration as Qt properties (bound from the UI), builds a
ScanConfiguration, and runs it through application.run_scan on a worker
thread so the UI never blocks. Progress events from the (worker-thread)
callback are re-emitted as Qt signals; because the controller lives on
the GUI thread, auto-connected internal signals marshal safely onto it.

No scanning, parsing or service logic lives here - only presentation
wiring around the shared application API.
"""

import threading
from datetime import datetime

from PySide6.QtCore import Property, QObject, Signal, Slot

from application.events import (CancelToken, EventType, ScanConfigurationError,
                                ScanStatus, TargetResolutionError)
from application.scan_configuration import ScanConfiguration
from application.scan_controller import run_scan
from gui.models.result_model import ResultTableModel


class ScanController(QObject):
    """Exposes scan configuration, control and progress to QML."""

    # ---- public (QML-facing) signals ----
    runningChanged = Signal()
    statusChanged = Signal()
    metaChanged = Signal()
    configChanged = Signal()
    scanStarted = Signal()
    phaseChanged = Signal(str, int)
    progressChanged = Signal(int, int, str)
    metricsUpdated = Signal(object)
    scanFinished = Signal(str)
    errorOccurred = Signal(str, str)
    logAdded = Signal(str, str)          # level, message
    historyChanged = Signal()

    # ---- internal (worker-thread -> GUI-thread) signals ----
    _evStarted = Signal(object)
    _evPhase = Signal(str, int)
    _evProgress = Signal(int, int, str)
    _evPort = Signal(object)
    _evService = Signal(int, object)
    _evMetrics = Signal(object)
    _evError = Signal(str, str)
    _evFinished = Signal(str)

    def __init__(self, model: ResultTableModel, runner=run_scan,
                 background: bool = True, parent=None):
        super().__init__(parent)
        self._model = model
        self._runner = runner
        self._background = background

        self._token = None
        self._thread = None
        self._running = False
        self._status = "Idle"
        self._meta = {}
        self._metrics = {}
        self._last_report = None
        self._history = []
        self._active_config = None

        # Configuration (bound from QML). threads==0 means "automatic".
        self._target = ""
        self._scan_type = "connect"
        self._port_mode = "custom"
        self._ports = "1-1000"
        self._top_ports = 100
        self._threads = 0
        self._service_detection = False
        self._retries = 0
        self._output_enabled = False
        self._output_path = ""

        # Marshal worker-thread events onto the GUI thread (AutoConnection:
        # direct when synchronous, queued when on a worker thread).
        self._evStarted.connect(self._on_started)
        self._evPhase.connect(self._on_phase)
        self._evProgress.connect(self._on_progress)
        self._evPort.connect(self._on_port)
        self._evService.connect(self._on_service)
        self._evMetrics.connect(self._on_metrics)
        self._evError.connect(self._on_error)
        self._evFinished.connect(self._on_finished)

    # ---- configuration properties ----
    def _get_target(self):
        return self._target

    def _set_target(self, v):
        if v != self._target:
            self._target = v
            self.configChanged.emit()

    target = Property(str, _get_target, _set_target, notify=configChanged)

    def _get_scan_type(self):
        return self._scan_type

    def _set_scan_type(self, v):
        if v != self._scan_type:
            self._scan_type = v
            self.configChanged.emit()

    scanType = Property(str, _get_scan_type, _set_scan_type,
                        notify=configChanged)

    def _get_port_mode(self):
        return self._port_mode

    def _set_port_mode(self, v):
        if v != self._port_mode:
            self._port_mode = v
            self.configChanged.emit()

    portMode = Property(str, _get_port_mode, _set_port_mode,
                        notify=configChanged)

    def _get_ports(self):
        return self._ports

    def _set_ports(self, v):
        if v != self._ports:
            self._ports = v
            self.configChanged.emit()

    ports = Property(str, _get_ports, _set_ports, notify=configChanged)

    def _get_top_ports(self):
        return self._top_ports

    def _set_top_ports(self, v):
        if v != self._top_ports:
            self._top_ports = int(v)
            self.configChanged.emit()

    topPorts = Property(int, _get_top_ports, _set_top_ports,
                        notify=configChanged)

    def _get_threads(self):
        return self._threads

    def _set_threads(self, v):
        if v != self._threads:
            self._threads = int(v)
            self.configChanged.emit()

    threads = Property(int, _get_threads, _set_threads, notify=configChanged)

    def _get_service_detection(self):
        return self._service_detection

    def _set_service_detection(self, v):
        if v != self._service_detection:
            self._service_detection = bool(v)
            self.configChanged.emit()

    serviceDetection = Property(bool, _get_service_detection,
                                _set_service_detection, notify=configChanged)

    def _get_retries(self):
        return self._retries

    def _set_retries(self, v):
        if v != self._retries:
            self._retries = int(v)
            self.configChanged.emit()

    retries = Property(int, _get_retries, _set_retries, notify=configChanged)

    def _get_output_enabled(self):
        return self._output_enabled

    def _set_output_enabled(self, v):
        if v != self._output_enabled:
            self._output_enabled = bool(v)
            self.configChanged.emit()

    outputEnabled = Property(bool, _get_output_enabled, _set_output_enabled,
                             notify=configChanged)

    def _get_output_path(self):
        return self._output_path

    def _set_output_path(self, v):
        if v != self._output_path:
            self._output_path = v
            self.configChanged.emit()

    outputPath = Property(str, _get_output_path, _set_output_path,
                          notify=configChanged)

    # ---- read-only state ----
    @Property(bool, notify=runningChanged)
    def running(self):
        return self._running

    @Property(str, notify=statusChanged)
    def status(self):
        return self._status

    # QVariantMap (not `object`): a dict exposed as `object` reaches QML as
    # an opaque PyObject wrapper whose members all read as undefined.
    @Property("QVariantMap", notify=metaChanged)
    def meta(self):
        return self._meta

    @Property("QVariantMap", notify=metricsUpdated)
    def metrics(self):
        return self._metrics

    # ---- control ----
    def build_config(self) -> ScanConfiguration:
        """Builds a ScanConfiguration from the current properties."""
        top = self._top_ports if self._port_mode == "top" else None
        ports = self._ports if self._port_mode == "custom" else None
        threads = self._threads if self._threads and self._threads > 0 \
            else None
        output = self._output_path if (self._output_enabled
                                       and self._output_path.strip()) else None
        return ScanConfiguration(
            target=self._target.strip(), scan_type=self._scan_type,
            ports=ports, top_ports=top, threads=threads,
            service_detection=self._service_detection, retries=self._retries,
            output_path=output)

    @Slot()
    def start(self):
        """Validates the configuration and launches a scan."""
        if self._running:
            self.errorOccurred.emit("configuration",
                                    "A scan is already running.")
            return

        config = self.build_config()
        try:
            config.validate()
        except ScanConfigurationError as exc:
            self.errorOccurred.emit(exc.category, str(exc))
            return

        self._model.clear()
        self._active_config = config
        self._token = CancelToken()
        self._set_running(True)
        self._set_status(ScanStatus.RUNNING)

        if self._background:
            self._thread = threading.Thread(target=self._run,
                                            args=(config,), daemon=True)
            self._thread.start()
        else:
            self._run(config)

    @Slot()
    def cancel(self):
        """Requests cooperative cancellation of the running scan."""
        if self._token is not None:
            self._token.cancel()

    @Slot(result=int)
    def portCount(self):
        """Number of ports the current selection resolves to (-1 if invalid)."""
        try:
            return len(self.build_config().resolved_ports())
        except Exception:  # noqa: BLE001 - invalid selection -> sentinel
            return -1

    @Slot(result="QVariantList")
    def serviceSummary(self):
        """Aggregated detected services for the Services page."""
        return self._model.service_summary()

    @Slot(result="QVariantList")
    def history(self):
        """Previous scan records (most recent first) for the History page."""
        return list(self._history)

    @Slot(str, result=bool)
    def saveReport(self, path: str) -> bool:
        """Writes the last completed scan report to `path`."""
        from report.formatter import format_text_report
        from report.writer import ReportWriteError, write_report

        if self._last_report is None:
            self.errorOccurred.emit("output", "No scan results to save.")
            return False
        report = self._last_report
        try:
            write_report(path, format_text_report(report.meta,
                                                  report.results,
                                                  report.metrics))
        except ReportWriteError as exc:
            self.errorOccurred.emit("output", str(exc))
            return False
        return True

    def shutdown(self):
        """Cancels and joins the worker thread (called on app close)."""
        self.cancel()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    # ---- worker ----
    def _run(self, config: ScanConfiguration):
        try:
            self._last_report = self._runner(config,
                                            on_event=self._emit_event,
                                            cancel_token=self._token)
        except (ScanConfigurationError, TargetResolutionError) as exc:
            self._evError.emit(exc.category, str(exc))
            self._evFinished.emit(ScanStatus.FAILED)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI/logs
            self._evError.emit("runtime", str(exc))
            self._evFinished.emit(ScanStatus.FAILED)

    def _emit_event(self, event):
        t, d = event.type, event.data
        if t == EventType.SCAN_STARTED:
            self._evStarted.emit(d.get("meta", {}))
        elif t == EventType.PHASE_CHANGED:
            self._evPhase.emit(d.get("phase", ""), int(d.get("total", 0)))
        elif t == EventType.PROGRESS:
            self._evProgress.emit(int(d.get("processed", 0)),
                                  int(d.get("total", 0)),
                                  d.get("phase", ""))
        elif t == EventType.PORT_RESULT:
            self._evPort.emit(d.get("result", {}))
        elif t == EventType.SERVICE_RESULT:
            self._evService.emit(int(d.get("port", 0)), d.get("info", {}))
        elif t == EventType.METRICS:
            self._evMetrics.emit(d.get("metrics", {}))
        elif t == EventType.ERROR:
            self._evError.emit(d.get("category", ""), d.get("message", ""))
        elif t in (EventType.SCAN_FINISHED, EventType.SCAN_CANCELLED):
            self._evFinished.emit(d.get("report_status", ScanStatus.COMPLETED))

    # ---- GUI-thread slots ----
    def _log(self, level, message):
        self.logAdded.emit(level, message)

    @Slot(object)
    def _on_started(self, meta):
        self._meta = meta
        self.metaChanged.emit()
        self.scanStarted.emit()
        self._log("INFO", f"Scan started: {meta.get('target', '')} "
                          f"({meta.get('scan_type', '')})")

    @Slot(str, int)
    def _on_phase(self, phase, total):
        self.phaseChanged.emit(phase, total)
        self._log("INFO", f"Phase: {phase} ({total})")

    @Slot(int, int, str)
    def _on_progress(self, processed, total, phase):
        self.progressChanged.emit(processed, total, phase)

    @Slot(object)
    def _on_port(self, result):
        self._model.add_result(result)

    @Slot(int, object)
    def _on_service(self, port, info):
        self._model.update_service(port, info)

    @Slot(object)
    def _on_metrics(self, metrics):
        self._metrics = metrics
        self.metricsUpdated.emit(metrics)

    @Slot(str, str)
    def _on_error(self, category, message):
        self.errorOccurred.emit(category, message)
        self._log("ERROR", f"[{category}] {message}")

    @Slot(str)
    def _on_finished(self, status):
        self._set_running(False)
        self._set_status(status)
        self._record_history(status)
        self.scanFinished.emit(status)
        self._log("INFO", f"Scan {status}")

    def _record_history(self, status):
        counts = (self._metrics or {}).get("state_counts", {})
        cfg = self._active_config
        snapshot = {}
        if cfg is not None:
            snapshot = {
                "target": cfg.target, "scanType": cfg.scan_type,
                "portMode": cfg.port_mode, "ports": cfg.ports or "",
                "topPorts": cfg.top_ports or 100,
                "threads": cfg.threads or 0,
                "serviceDetection": cfg.service_detection,
                "retries": cfg.retries,
            }
        self._history.insert(0, {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self._meta.get("target", ""),
            "scanType": self._meta.get("scan_type", ""),
            "ports": self._meta.get("total_ports", 0),
            "status": status,
            "duration": round((self._metrics or {}).get("total_time", 0.0), 3),
            "open": counts.get("OPEN", 0),
            "closed": counts.get("CLOSED", 0),
            "filtered": counts.get("FILTERED", 0),
            "config": snapshot,
        })
        self.historyChanged.emit()

    @Slot("QVariant")
    def applyConfig(self, cfg) -> None:
        """Applies a stored history config snapshot back onto the controls."""
        if not cfg:
            return
        self.target = cfg.get("target", "")
        self.scanType = cfg.get("scanType", "connect")
        self.portMode = cfg.get("portMode", "custom")
        self.ports = cfg.get("ports", "") or "1-1000"
        self.topPorts = int(cfg.get("topPorts", 100))
        self.threads = int(cfg.get("threads", 0))
        self.serviceDetection = bool(cfg.get("serviceDetection", False))
        self.retries = int(cfg.get("retries", 0))

    # ---- internal setters ----
    def _set_running(self, value):
        if value != self._running:
            self._running = value
            self.runningChanged.emit()

    def _set_status(self, value):
        if value != self._status:
            self._status = value
            self.statusChanged.emit()
