import QtQuick
import QtQuick.Layouts

Item {
    id: root
    property string label: ""
    property string glyph: ""
    property bool active: false
    property bool compact: false
    signal clicked()

    implicitHeight: 40
    Layout.fillWidth: true

    Rectangle {
        anchors.fill: parent
        anchors.leftMargin: 8
        anchors.rightMargin: 8
        radius: 6
        color: root.active ? Theme.surfaceVariant
                           : (hover.hovered ? Theme.surfaceVariant : "transparent")
        opacity: root.active ? 1.0 : (hover.hovered ? 0.6 : 1.0)

        Rectangle {   // active accent bar
            width: 3; height: parent.height * 0.5
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left
            radius: 2
            color: Theme.accent
            visible: root.active
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 12
            spacing: 10

            Text {
                text: root.glyph
                color: root.active ? Theme.accent : Theme.secondaryText
                font.pixelSize: 15
                font.bold: root.active
                Layout.preferredWidth: 18
                horizontalAlignment: Text.AlignHCenter
            }
            Text {
                visible: !root.compact
                text: root.label
                color: root.active ? Theme.text : Theme.secondaryText
                font.pixelSize: 13
                font.bold: root.active
                Layout.fillWidth: true
                elide: Text.ElideRight
            }
        }

        HoverHandler { id: hover }
        TapHandler { onTapped: root.clicked() }
    }

    Accessible.role: Accessible.Button
    Accessible.name: label
}
