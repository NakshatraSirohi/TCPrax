import QtQuick

// State indicator that always shows the state text (never colour-only),
// for accessibility.
Rectangle {
    id: root
    property string state: ""
    implicitWidth: label.implicitWidth + 16
    implicitHeight: 20
    radius: 10
    color: Qt.rgba(badgeColor.r, badgeColor.g, badgeColor.b, 0.15)
    border.width: 1
    border.color: badgeColor

    readonly property color badgeColor: {
        switch (root.state) {
        case "OPEN": return Theme.success
        case "CLOSED": return Theme.secondaryText
        case "FILTERED": return Theme.warning
        case "ERROR": return Theme.error
        default: return Theme.accent   // OTHER / anything else
        }
    }

    Text {
        id: label
        anchors.centerIn: parent
        text: root.state
        color: root.badgeColor
        font.pixelSize: 10
        font.bold: true
    }
}
