import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: page
    property var services: []

    function refresh() { services = scan.serviceSummary() }
    Component.onCompleted: refresh()
    Connections { target: scan; function onScanFinished(s) { page.refresh() } }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth
        clip: true

        ColumnLayout {
            width: page.width
            ColumnLayout {
                Layout.fillWidth: true
                Layout.margins: 20
                spacing: 16

                Text {
                    text: "Services"
                    color: Theme.text
                    font.pixelSize: 22
                    font.bold: true
                }

                // ---- Detected services ----
                Card {
                    title: "Detected Services"

                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Service"; color: Theme.secondaryText; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 140 }
                        Text { text: "Product"; color: Theme.secondaryText; font.pixelSize: 11; font.bold: true; Layout.fillWidth: true }
                        Text { text: "Version"; color: Theme.secondaryText; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 100 }
                        Text { text: "Count"; color: Theme.secondaryText; font.pixelSize: 11; font.bold: true; Layout.preferredWidth: 50 }
                    }
                    Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }

                    Text {
                        visible: page.services.length === 0
                        text: "No services detected yet. Run a scan with service detection enabled."
                        color: Theme.secondaryText; font.pixelSize: 12
                    }

                    Repeater {
                        model: page.services
                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: modelData.service; color: Theme.text; font.pixelSize: 13; Layout.preferredWidth: 140 }
                            Text { text: modelData.product || "—"; color: Theme.secondaryText; font.pixelSize: 13; Layout.fillWidth: true; elide: Text.ElideRight }
                            Text { text: modelData.version || "—"; color: Theme.secondaryText; font.pixelSize: 13; Layout.preferredWidth: 100 }
                            Text { text: "" + modelData.occurrences; color: Theme.accent; font.pixelSize: 13; Layout.preferredWidth: 50 }
                        }
                    }
                }

                // ---- Database info ----
                Card {
                    title: "TCPrax Service Database"
                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        columnSpacing: 20
                        rowSpacing: 6
                        Text { text: "Common services"; color: Theme.secondaryText; font.pixelSize: 12 }
                        Text { text: "" + dbInfo.commonServices; color: Theme.text; font.pixelSize: 12 }
                        Text { text: "Fingerprints loaded"; color: Theme.secondaryText; font.pixelSize: 12 }
                        Text { text: "" + dbInfo.fingerprints; color: Theme.text; font.pixelSize: 12 }
                        Text { text: "Nmap-derived fingerprints"; color: Theme.secondaryText; font.pixelSize: 12 }
                        Text { text: "" + dbInfo.nmapFingerprints; color: Theme.text; font.pixelSize: 12 }
                        Text { text: "TLS detection"; color: Theme.secondaryText; font.pixelSize: 12 }
                        Text { text: dbInfo.tls; color: Theme.success; font.pixelSize: 12 }
                        Text { text: "Database version"; color: Theme.secondaryText; font.pixelSize: 12 }
                        Text { text: dbInfo.version; color: Theme.text; font.pixelSize: 12 }
                    }
                }
            }
        }
    }
}
