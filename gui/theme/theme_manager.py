"""
Theme Manager

Central, semantic theme for the GUI. QML binds to these colour
properties (Theme.background, Theme.accent, ...) rather than hard-coding
colours, so light/dark/system switching updates the whole UI at once.

Modes:
    system - follow the OS colour scheme (falls back to dark)
    light  - force light palette
    dark   - force dark palette
"""

from PySide6.QtCore import Property, QObject, Qt, Signal
from PySide6.QtGui import QGuiApplication

# Semantic palettes. Keys match the properties exposed to QML.
_DARK = {
    "background": "#0f1115",
    "surface": "#171a21",
    "surfaceVariant": "#1f2430",
    "text": "#e6e9ef",
    "secondaryText": "#9aa4b2",
    "border": "#2a2f3a",
    "accent": "#4c8dff",
    "success": "#3fb950",
    "warning": "#d29922",
    "error": "#f85149",
}

_LIGHT = {
    "background": "#f6f7f9",
    "surface": "#ffffff",
    "surfaceVariant": "#eef1f5",
    "text": "#1b1f27",
    "secondaryText": "#5b6472",
    "border": "#d6dae1",
    "accent": "#2f6fed",
    "success": "#1a7f37",
    "warning": "#9a6700",
    "error": "#cf222e",
}

_MODES = ("system", "light", "dark")


class ThemeManager(QObject):
    """Exposes semantic theme colours and the current mode to QML."""

    changed = Signal()
    modeChanged = Signal()

    def __init__(self, mode: str = "system", parent=None):
        super().__init__(parent)
        self._mode = mode if mode in _MODES else "system"

    # ---- palette resolution ----
    def _palette(self) -> dict:
        if self._mode == "light":
            return _LIGHT
        if self._mode == "dark":
            return _DARK
        # system
        try:
            scheme = QGuiApplication.styleHints().colorScheme()
            if scheme == Qt.ColorScheme.Light:
                return _LIGHT
        except Exception:
            pass
        return _DARK

    def _color(self, key: str) -> str:
        return self._palette()[key]

    # ---- mode ----
    def get_mode(self) -> str:
        return self._mode

    def set_mode(self, value: str) -> None:
        if value not in _MODES or value == self._mode:
            return
        self._mode = value
        self.modeChanged.emit()
        self.changed.emit()

    mode = Property(str, get_mode, set_mode, notify=modeChanged)

    @Property(bool, notify=changed)
    def isDark(self) -> bool:
        return self._palette() is _DARK

    # ---- semantic colours ----
    @Property(str, notify=changed)
    def background(self) -> str:
        return self._color("background")

    @Property(str, notify=changed)
    def surface(self) -> str:
        return self._color("surface")

    @Property(str, notify=changed)
    def surfaceVariant(self) -> str:
        return self._color("surfaceVariant")

    @Property(str, notify=changed)
    def text(self) -> str:
        return self._color("text")

    @Property(str, notify=changed)
    def secondaryText(self) -> str:
        return self._color("secondaryText")

    @Property(str, notify=changed)
    def border(self) -> str:
        return self._color("border")

    @Property(str, notify=changed)
    def accent(self) -> str:
        return self._color("accent")

    @Property(str, notify=changed)
    def success(self) -> str:
        return self._color("success")

    @Property(str, notify=changed)
    def warning(self) -> str:
        return self._color("warning")

    @Property(str, notify=changed)
    def error(self) -> str:
        return self._color("error")

    def refresh_system(self) -> None:
        """Re-emit change when following the system scheme and it flips."""
        if self._mode == "system":
            self.changed.emit()
