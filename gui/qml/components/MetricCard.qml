import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string label: ""
    property string value: "-"
    property color accent: Theme.text

    Layout.fillWidth: true
    implicitHeight: 66
    radius: 8
    color: Theme.surfaceVariant
    border.color: Theme.border
    border.width: 1

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 2
        Text {
            text: root.value
            color: root.accent
            font.pixelSize: 22
            font.bold: true
        }
        Text {
            text: root.label
            color: Theme.secondaryText
            font.pixelSize: 11
        }
    }
}
