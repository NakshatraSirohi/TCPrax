import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "components"
import "pages"

ApplicationWindow {
    id: win
    visible: true
    width: 1120
    height: 740
    minimumWidth: 560
    minimumHeight: 460
    title: appName + " " + appVersion
    color: Theme.background

    property int pageIndex: 0
    readonly property bool compact: width < 820

    // ---- keyboard shortcuts ----
    Shortcut { sequence: "Ctrl+N"; onActivated: win.pageIndex = 1 }
    Shortcut { sequence: "Ctrl+Return"; onActivated: if (!scan.running) scan.start() }
    Shortcut { sequence: "Ctrl+F"; onActivated: win.pageIndex = 2 }
    Shortcut { sequence: "Ctrl+,"; onActivated: win.pageIndex = 6 }
    Shortcut { sequence: "Escape"; onActivated: if (scan.running) scan.cancel() }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        Sidebar {
            id: sidebar
            Layout.fillHeight: true
            Layout.preferredWidth: win.compact ? 68 : 212
            compact: win.compact
            currentIndex: win.pageIndex
            statusText: scan.status
            running: scan.running
            onNavigate: (i) => win.pageIndex = i
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.background

            StackLayout {
                anchors.fill: parent
                currentIndex: win.pageIndex
                Dashboard { onGoScan: win.pageIndex = 1; onGoResults: win.pageIndex = 2 }
                ScanPage { onGoResults: win.pageIndex = 2 }
                ResultsPage {}
                ServicesPage {}
                HistoryPage { onRequestScanPage: win.pageIndex = 1 }
                LogsPage {}
                SettingsPage {}
            }
        }
    }

    // ---- transient error toast ----
    Rectangle {
        id: toast
        property string message: ""
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 24
        width: Math.min(560, parent.width - 48)
        height: msg.implicitHeight + 24
        radius: 8
        color: Theme.surfaceVariant
        border.color: Theme.error
        border.width: 1
        opacity: 0
        visible: opacity > 0
        z: 100

        Text {
            id: msg
            anchors.fill: parent
            anchors.margins: 12
            text: toast.message
            color: Theme.text
            wrapMode: Text.WordWrap
            font.pixelSize: 13
        }

        Behavior on opacity { NumberAnimation { duration: 180 } }
        Timer { id: hideTimer; interval: 4500; onTriggered: toast.opacity = 0 }
        function show(m) { message = m; opacity = 1; hideTimer.restart() }
    }

    Connections {
        target: scan
        function onErrorOccurred(category, message) {
            toast.show("✕  " + message)
        }
    }
}
