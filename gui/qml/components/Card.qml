import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string title: ""
    default property alias content: body.data

    Layout.fillWidth: true
    implicitHeight: layout.implicitHeight + 28
    radius: 10
    color: Theme.surface
    border.color: Theme.border
    border.width: 1

    ColumnLayout {
        id: layout
        anchors.fill: parent
        anchors.margins: 14
        spacing: 10

        Text {
            visible: root.title.length > 0
            text: root.title
            color: Theme.secondaryText
            font.pixelSize: 12
            font.bold: true
            font.capitalization: Font.AllUppercase
        }

        ColumnLayout {
            id: body
            Layout.fillWidth: true
            spacing: 10
        }
    }
}
