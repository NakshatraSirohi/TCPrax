import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: page
    property int selectedRow: -1

    function cell(row, col) {
        if (row < 0) return ""
        var v = resultsModel.data(resultsModel.index(row, col))
        return v === undefined || v === null ? "" : v
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        Text {
            text: "Results"
            color: Theme.text
            font.pixelSize: 22
            font.bold: true
        }

        // ---- filter bar ----
        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            TextField {
                Layout.fillWidth: true
                placeholderText: "Search port, service, product…"
                color: Theme.text
                placeholderTextColor: Theme.secondaryText
                onTextChanged: resultsModel.set_search(text)
                background: Rectangle {
                    radius: 6; color: Theme.surfaceVariant; border.color: Theme.border
                }
            }
            ComboBox {
                model: ["All", "OPEN", "CLOSED", "FILTERED", "OTHER", "ERROR"]
                onActivated: resultsModel.set_state_filter(currentText)
            }
            ComboBox {
                model: ["All", "Detected", "Unknown"]
                onActivated: resultsModel.set_service_filter(currentText)
            }
        }

        // ---- table ----
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: Theme.surface
            border.color: Theme.border

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 1
                spacing: 0

                HorizontalHeaderView {
                    id: header
                    Layout.fillWidth: true
                    syncView: table
                    clip: true
                    delegate: Rectangle {
                        implicitHeight: 30
                        color: Theme.surfaceVariant
                        Text {
                            anchors.fill: parent
                            anchors.leftMargin: 8
                            verticalAlignment: Text.AlignVCenter
                            text: display
                            color: Theme.secondaryText
                            font.pixelSize: 11
                            font.bold: true
                        }
                        TapHandler {
                            onTapped: resultsModel.sortBy(column, Qt.AscendingOrder)
                        }
                    }
                }

                TableView {
                    id: table
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    model: resultsModel
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: ScrollBar {}

                    columnWidthProvider: function (column) {
                        var narrow = page.width < 720
                        switch (column) {
                        case 0: return 70               // Port
                        case 1: return narrow ? 0 : 70  // Protocol
                        case 2: return 96               // State
                        case 3: return Math.max(120, page.width - (narrow ? 366 : 600))
                        case 4: return narrow ? 0 : 150 // Product
                        case 5: return narrow ? 0 : 120 // Version
                        }
                        return 100
                    }
                    rowHeightProvider: function () { return 30 }

                    delegate: Rectangle {
                        required property int row
                        required property int column
                        required property string display
                        required property string rowState
                        implicitHeight: 30
                        color: row === page.selectedRow ? Theme.surfaceVariant
                               : (row % 2 ? Theme.surface : Theme.background)

                        Loader {
                            anchors.fill: parent
                            anchors.leftMargin: 8
                            anchors.rightMargin: 8
                            sourceComponent: column === 2 ? badgeCell : textCell
                            property string cellText: display
                            property string cellState: rowState
                        }
                        TapHandler { onTapped: page.selectedRow = row }
                    }
                }
            }
        }

        // ---- detail panel ----
        Rectangle {
            Layout.fillWidth: true
            visible: page.selectedRow >= 0
            implicitHeight: 96
            radius: 8
            color: Theme.surface
            border.color: Theme.border

            GridLayout {
                anchors.fill: parent
                anchors.margins: 12
                columns: page.width < 720 ? 3 : 6
                columnSpacing: 20
                rowSpacing: 6
                Repeater {
                    model: [
                        { k: "Port", c: 0 }, { k: "Protocol", c: 1 },
                        { k: "State", c: 2 }, { k: "Service", c: 3 },
                        { k: "Product", c: 4 }, { k: "Version", c: 5 }
                    ]
                    ColumnLayout {
                        spacing: 1
                        Text { text: modelData.k; color: Theme.secondaryText; font.pixelSize: 10 }
                        Text {
                            text: page.cell(page.selectedRow, modelData.c) || "—"
                            color: Theme.text; font.pixelSize: 13
                        }
                    }
                }
            }
        }

        Text {
            text: resultsModel.count + " rows"
            color: Theme.secondaryText
            font.pixelSize: 11
        }
    }

    Component {
        id: textCell
        Text {
            verticalAlignment: Text.AlignVCenter
            text: parent.cellText
            color: Theme.text
            font.pixelSize: 12
            elide: Text.ElideRight
        }
    }
    Component {
        id: badgeCell
        Item {
            id: badgeRoot
            // This Item is the loaded component's root, so its parent is
            // the Loader that carries the cell data. StateBadge.parent is
            // this Item (not the Loader), so reach cellState via badgeRoot.
            StateBadge {
                anchors.verticalCenter: parent.verticalCenter
                state: badgeRoot.parent ? badgeRoot.parent.cellState : ""
            }
        }
    }
}
