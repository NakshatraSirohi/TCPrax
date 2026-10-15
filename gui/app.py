"""
GUI Application Bootstrap

Creates the Qt application, wires the theme, result models and scan
controller to QML as context properties, and loads Main.qml.

This module is imported lazily by main.run_gui, so the CLI never pays for
PySide6. `create_engine` is factored out so tests can build the engine
headlessly (offscreen) without entering the event loop.
"""

import os
import sys

from PySide6.QtGui import QGuiApplication
from PySide6.QtCore import QUrl
from PySide6.QtQml import QQmlApplicationEngine

from gui.controllers.scan_controller import ScanController
from gui.models.result_model import ResultFilterProxy, ResultTableModel
from gui.theme.theme_manager import ThemeManager
from version import APP_NAME, __version__

QML_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qml")
MAIN_QML = os.path.join(QML_DIR, "Main.qml")


def _database_info() -> dict:
    """Read-only service-database facts for the Services page."""
    try:
        from service.common_services import COMMON_SERVICES
        from service.database import get_engine
        from service.nmap_fingerprints import NMAP_FINGERPRINTS
        engine = get_engine()
        return {
            "commonServices": len(COMMON_SERVICES),
            "fingerprints": len(engine),
            "nmapFingerprints": len(NMAP_FINGERPRINTS),
            "tls": "Available",
            "version": __version__,
        }
    except Exception as exc:  # noqa: BLE001 - shown as unavailable in UI
        return {"commonServices": 0, "fingerprints": 0,
                "nmapFingerprints": 0, "tls": "Unknown",
                "version": __version__, "error": str(exc)}


def create_engine(background: bool = True):
    """
    Builds the QML engine with all context objects wired.

    Returns (engine, controller, keepalive) where keepalive holds the
    Python objects that must outlive this function.
    """
    theme = ThemeManager(mode="system")
    model = ResultTableModel()
    proxy = ResultFilterProxy()
    proxy.setSourceModel(model)
    controller = ScanController(model, background=background)

    engine = QQmlApplicationEngine()
    ctx = engine.rootContext()
    ctx.setContextProperty("Theme", theme)
    ctx.setContextProperty("scan", controller)
    ctx.setContextProperty("resultsModel", proxy)
    ctx.setContextProperty("resultsSource", model)
    ctx.setContextProperty("dbInfo", _database_info())
    ctx.setContextProperty("appName", APP_NAME)
    ctx.setContextProperty("appVersion", __version__)

    engine.load(QUrl.fromLocalFile(MAIN_QML))

    keepalive = (theme, model, proxy, controller)
    return engine, controller, keepalive


def run_gui(argv=None) -> int:
    """Launches the GUI event loop. Returns the process exit code."""
    app = QGuiApplication.instance() or QGuiApplication(argv or sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)

    engine, controller, _keep = create_engine(background=True)
    if not engine.rootObjects():
        print("Error: failed to load the GUI (QML errors above).",
              file=sys.stderr)
        return 1

    app.aboutToQuit.connect(controller.shutdown)
    return app.exec()
