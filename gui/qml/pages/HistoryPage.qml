import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: page
    signal requestScanPage()
    property var records: []

    function refresh() { records = scan.history() }
    Component.onCompleted: refresh()
    Connections { target: scan; function onHistoryChanged() { page.refresh() } }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        Text {
            text: "History"
            color: Theme.text
            font.pixelSize: 22
            font.bold: true
        }

        Text {
            visible: page.records.length === 0
            text: "No scans yet."
            color: Theme.secondaryText
            font.pixelSize: 13
        }

        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: 8
            model: page.records
            ScrollBar.vertical: ScrollBar {}

            delegate: Rectangle {
                width: ListView.view.width
                implicitHeight: 66
                radius: 8
                color: Theme.surface
                border.color: Theme.border

                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 14

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        RowLayout {
                            spacing: 8
                            Text { text: modelData.target; color: Theme.text; font.pixelSize: 14; font.bold: true }
                            StateBadge {
                                state: modelData.status === "Completed" ? "OPEN"
                                       : modelData.status === "Cancelled" ? "FILTERED"
                                       : modelData.status === "Failed" ? "ERROR" : "OTHER"
                            }
                            Text { text: modelData.status; color: Theme.secondaryText; font.pixelSize: 11 }
                        }
                        Text {
                            text: modelData.timestamp + "  ·  " + modelData.scanType
                                  + "  ·  " + modelData.ports + " ports  ·  "
                                  + modelData.duration + "s"
                            color: Theme.secondaryText
                            font.pixelSize: 11
                        }
                        Text {
                            text: "Open " + modelData.open + "   Closed " + modelData.closed
                                  + "   Filtered " + modelData.filtered
                            color: Theme.secondaryText
                            font.pixelSize: 11
                        }
                    }

                    Button {
                        text: "Re-run"
                        enabled: !scan.running && modelData.config && modelData.config.target
                        onClicked: {
                            scan.applyConfig(modelData.config)
                            page.requestScanPage()
                        }
                    }
                }
            }
        }
    }
}
