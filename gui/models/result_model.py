"""
Result Table Model

Efficient table model for scan results, backed by QAbstractTableModel so
a QML TableView can render tens of thousands of rows without one object
per port. Results (and later their service info) are appended
incrementally as the scan streams them.

A ResultFilterProxy provides search / state / service filtering and
sorting over the same data, without copying the result set.
"""

from typing import Dict, List, Optional

from PySide6.QtCore import (Property, QAbstractTableModel, QModelIndex,
                            QSortFilterProxyModel, Qt, Signal, Slot)

# Columns
COL_PORT = 0
COL_PROTOCOL = 1
COL_STATE = 2
COL_SERVICE = 3
COL_PRODUCT = 4
COL_VERSION = 5
_HEADERS = ["Port", "Protocol", "State", "Service", "Product", "Version"]

# Custom roles so QML delegates can style/inspect a row regardless of
# which column cell they are rendering.
ROLE_ROW_STATE = Qt.UserRole + 1
ROLE_ROW_CONFIDENCE = Qt.UserRole + 2
ROLE_ROW_PORT = Qt.UserRole + 3
ROLE_ROW_DETECTION = Qt.UserRole + 4


def _service_fields(result: Dict) -> Dict:
    """Extracts (service, product, version) display strings from a result."""
    info = result.get("service_info")
    if isinstance(info, dict):
        return {
            "service": info.get("service") or "",
            "product": info.get("product") or "",
            "version": info.get("version") or "",
            "confidence": info.get("confidence") or "",
            "detection": info.get("detection_source") or "",
        }
    # No structured info: fall back to any plain "service" display string.
    return {
        "service": result.get("service", "") if "service" in result else "",
        "product": "",
        "version": "",
        "confidence": "",
        "detection": "",
    }


class ResultTableModel(QAbstractTableModel):
    """Holds scan result rows for display."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict] = []
        self._port_to_row: Dict[int, int] = {}

    # ---- Qt model interface ----
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(_HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None

        row = self._rows[index.row()]

        if role == ROLE_ROW_STATE:
            return row.get("state", "")
        if role == ROLE_ROW_PORT:
            return row.get("port")

        fields = _service_fields(row)
        if role == ROLE_ROW_CONFIDENCE:
            return fields["confidence"]
        if role == ROLE_ROW_DETECTION:
            return fields["detection"]

        if role == Qt.DisplayRole:
            col = index.column()
            if col == COL_PORT:
                return str(row.get("port", ""))
            if col == COL_PROTOCOL:
                return "tcp"
            if col == COL_STATE:
                return row.get("state", "")
            if col == COL_SERVICE:
                return fields["service"]
            if col == COL_PRODUCT:
                return fields["product"]
            if col == COL_VERSION:
                return fields["version"]
        return None

    def roleNames(self):
        return {
            Qt.DisplayRole: b"display",
            ROLE_ROW_STATE: b"rowState",
            ROLE_ROW_CONFIDENCE: b"rowConfidence",
            ROLE_ROW_PORT: b"rowPort",
            ROLE_ROW_DETECTION: b"rowDetection",
        }

    # ---- mutation ----
    def set_results(self, results: List[Dict]) -> None:
        """Replaces all rows (used for batch/History loads)."""
        self.beginResetModel()
        self._rows = list(results)
        self._reindex()
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows = []
        self._port_to_row = {}
        self.endResetModel()

    def add_result(self, result: Dict) -> None:
        """Appends one streamed result."""
        pos = len(self._rows)
        self.beginInsertRows(QModelIndex(), pos, pos)
        self._rows.append(dict(result))
        self._port_to_row[result.get("port")] = pos
        self.endInsertRows()

    def update_service(self, port: int, info: Dict) -> None:
        """Attaches structured service info to the row for `port`."""
        row = self._port_to_row.get(port)
        if row is None:
            return
        self._rows[row]["service_info"] = info
        top = self.index(row, COL_SERVICE)
        bottom = self.index(row, COL_VERSION)
        self.dataChanged.emit(top, bottom,
                              [Qt.DisplayRole, ROLE_ROW_CONFIDENCE,
                               ROLE_ROW_DETECTION])

    def _reindex(self) -> None:
        self._port_to_row = {
            r.get("port"): i for i, r in enumerate(self._rows)
        }

    # ---- helpers for detail panel / services page ----
    def result_at(self, row: int) -> Optional[Dict]:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def service_summary(self) -> List[Dict]:
        """
        Aggregates identified services for the Services page:
        one row per (service, product, version) with an occurrence count.
        """
        counts: Dict[tuple, int] = {}
        for row in self._rows:
            if row.get("state") != "OPEN":
                continue
            fields = _service_fields(row)
            service = fields["service"]
            if not service or service == "unknown":
                continue
            key = (service, fields["product"], fields["version"])
            counts[key] = counts.get(key, 0) + 1

        summary = [{"service": s, "product": p, "version": v,
                    "occurrences": n} for (s, p, v), n in counts.items()]
        summary.sort(key=lambda e: (-e["occurrences"], e["service"]))
        return summary


class ResultFilterProxy(QSortFilterProxyModel):
    """Search / state / service filtering and sorting over ResultTableModel."""

    countChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._search = ""
        self._state = "All"
        self._service = "All"
        self._count = 0
        self.setDynamicSortFilter(True)

        # rowCount() is a method, so QML can't bind to it; mirror it as a
        # notifying property. Filter changes arrive as layoutChanged (from
        # invalidate()), streamed rows as rowsInserted, clears as modelReset.
        for sig in (self.rowsInserted, self.rowsRemoved, self.modelReset,
                    self.layoutChanged):
            sig.connect(self._update_count)

    # ---- visible row count (bindable from QML) ----
    def _update_count(self, *_args) -> None:
        count = self.rowCount()
        if count != self._count:
            self._count = count
            self.countChanged.emit()

    @Property(int, notify=countChanged)
    def count(self) -> int:
        return self._count

    # ---- filter controls (callable from QML) ----
    @Slot(str)
    def set_search(self, text: str) -> None:
        self._search = (text or "").strip().lower()
        self.invalidate()

    @Slot(str)
    def set_state_filter(self, state: str) -> None:
        self._state = state or "All"
        self.invalidate()

    @Slot(str)
    def set_service_filter(self, mode: str) -> None:
        self._service = mode or "All"
        self.invalidate()

    @Slot(int, int)
    def sortBy(self, column: int, order: int) -> None:
        self.sort(column, Qt.SortOrder(order))

    # ---- filtering ----
    def filterAcceptsRow(self, source_row, source_parent) -> bool:
        model = self.sourceModel()
        if model is None:
            return True
        row = model.result_at(source_row)
        if row is None:
            return False

        if self._state != "All" and row.get("state") != self._state:
            return False

        fields = _service_fields(row)
        if self._service == "Detected":
            if not fields["service"] or fields["service"] == "unknown":
                return False
        elif self._service == "Unknown":
            if fields["service"] and fields["service"] != "unknown":
                return False

        if self._search:
            haystack = " ".join([
                str(row.get("port", "")), row.get("state", ""),
                fields["service"], fields["product"], fields["version"],
            ]).lower()
            if self._search not in haystack:
                return False

        return True

    def lessThan(self, left, right) -> bool:
        model = self.sourceModel()
        # Port column sorts numerically; everything else as text.
        if left.column() == COL_PORT:
            lp = model.result_at(left.row())
            rp = model.result_at(right.row())
            return (lp.get("port", 0) or 0) < (rp.get("port", 0) or 0)
        return super().lessThan(left, right)
