import QtQuick
import QtQuick.Layouts

Card {
    id: root
    title: "Progress"

    property string phase: ""
    property int processed: 0
    property int total: 0
    property int openCount: 0
    property int closedCount: 0
    property int filteredCount: 0
    property real elapsed: 0
    property double startMs: 0

    readonly property real fraction: total > 0 ? processed / total : 0
    readonly property real rate: elapsed > 0 ? processed / elapsed : 0
    readonly property string phaseLabel:
        phase === "service_detection" ? "Service detection" :
        phase === "port_scan" ? "Port scanning" : "Preparing"

    function resetCounts() {
        processed = 0; total = 0; openCount = 0; closedCount = 0
        filteredCount = 0; elapsed = 0; startMs = Date.now()
    }

    Connections {
        target: scan
        function onScanStarted() { root.resetCounts() }
        function onPhaseChanged(p, t) {
            // A new phase resets the counter so the numerator and
            // denominator always belong to the same phase: the port scan
            // measures against the total port count, service detection
            // against the (smaller) open-port count.
            root.phase = p
            root.processed = 0
            if (t > 0) root.total = t
        }
        function onProgressChanged(pr, t, p) {
            root.processed = pr; if (t > 0) root.total = t; root.phase = p
        }
    }

    Connections {
        target: resultsSource
        function onRowsInserted(parent, first, last) {
            for (var r = first; r <= last; r++) {
                var st = resultsSource.data(resultsSource.index(r, 2))
                if (st === "OPEN") root.openCount++
                else if (st === "CLOSED") root.closedCount++
                else if (st === "FILTERED") root.filteredCount++
            }
        }
        function onModelReset() {
            root.openCount = 0; root.closedCount = 0; root.filteredCount = 0
        }
    }

    Timer {
        running: scan.running
        interval: 250; repeat: true
        onTriggered: root.elapsed = (Date.now() - root.startMs) / 1000
    }

    // ---- content ----
    RowLayout {
        Layout.fillWidth: true
        Text {
            text: root.phaseLabel
            color: Theme.text
            font.pixelSize: 14
            font.bold: true
            Layout.fillWidth: true
        }
        Text {
            text: root.total > 0
                  ? Math.round(Math.max(0, Math.min(1, root.fraction)) * 100) + "%"
                  : ""
            color: Theme.accent
            font.pixelSize: 14
            font.bold: true
        }
    }

    // progress bar
    Rectangle {
        Layout.fillWidth: true
        height: 8
        radius: 4
        color: Theme.surfaceVariant
        Rectangle {
            width: parent.width * Math.max(0, Math.min(1, root.fraction))
            height: parent.height
            radius: 4
            color: Theme.accent
            Behavior on width { NumberAnimation { duration: 150 } }
        }
    }

    Text {
        text: root.total > 0 ? (root.processed + " / " + root.total + " ports")
                             : (root.processed + " ports")
        color: Theme.secondaryText
        font.pixelSize: 12
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: 18
        Text { text: "Open " + root.openCount; color: Theme.success; font.pixelSize: 12 }
        Text { text: "Closed " + root.closedCount; color: Theme.secondaryText; font.pixelSize: 12 }
        Text { text: "Filtered " + root.filteredCount; color: Theme.warning; font.pixelSize: 12 }
        Item { Layout.fillWidth: true }
        Text {
            text: root.rate > 0 ? root.rate.toFixed(1) + " ports/sec" : ""
            color: Theme.secondaryText
            font.pixelSize: 12
        }
    }

    RowLayout {
        Layout.fillWidth: true
        Text {
            text: "Elapsed " + root.elapsed.toFixed(1) + "s"
            color: Theme.secondaryText
            font.pixelSize: 11
            Layout.fillWidth: true
        }
        Text {
            // No fake ETA.
            text: (root.rate > 0 && root.total > 0)
                  ? ("ETA " + Math.max(0, Math.round((root.total - root.processed) / root.rate)) + "s")
                  : "ETA: Calculating..."
            color: Theme.secondaryText
            font.pixelSize: 11
        }
    }
}
