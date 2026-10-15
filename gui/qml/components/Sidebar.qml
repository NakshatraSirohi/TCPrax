import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property int currentIndex: 0
    property bool compact: false
    property string statusText: "Idle"
    property bool running: false
    signal navigate(int index)

    color: Theme.surface
    border.color: Theme.border
    border.width: 1

    readonly property var items: [
        { label: "Dashboard", glyph: "■" },
        { label: "Scan",      glyph: "▶" },
        { label: "Results",   glyph: "≣" },
        { label: "Services",  glyph: "⚑" },
        { label: "History",   glyph: "↺" },
        { label: "Logs",      glyph: "⌗" },
        { label: "Settings",  glyph: "⚙" }
    ]

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 16
        anchors.bottomMargin: 12
        spacing: 4

        // Header: app name + status dot
        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 12
            Layout.bottomMargin: 12
            spacing: 8
            Rectangle {
                width: 9; height: 9; radius: 5
                color: root.running ? Theme.warning : Theme.success
            }
            Text {
                visible: !root.compact
                text: appName
                color: Theme.text
                font.pixelSize: 16
                font.bold: true
                Layout.fillWidth: true
            }
        }

        Repeater {
            model: root.items
            NavButton {
                label: modelData.label
                glyph: modelData.glyph
                compact: root.compact
                active: index === root.currentIndex
                onClicked: root.navigate(index)
            }
        }

        Item { Layout.fillHeight: true }

        // Footer: status + version
        Text {
            visible: !root.compact
            Layout.leftMargin: 16
            text: root.statusText
            color: root.running ? Theme.warning : Theme.secondaryText
            font.pixelSize: 11
        }
        Text {
            Layout.leftMargin: 16
            text: root.compact ? "v" : ("v" + appVersion)
            color: Theme.secondaryText
            font.pixelSize: 11
        }
    }
}
