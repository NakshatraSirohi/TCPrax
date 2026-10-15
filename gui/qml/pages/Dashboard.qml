import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: page
    signal goScan()
    signal goResults()

    function count(key) {
        var m = scan.metrics
        if (!m || !m.state_counts) return "0"
        return "" + (m.state_counts[key] || 0)
    }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth
        clip: true

        ColumnLayout {
            width: page.width
            spacing: 16

            ColumnLayout {
                Layout.fillWidth: true
                Layout.margins: 20
                spacing: 16

                Text {
                    text: "Dashboard"
                    color: Theme.text
                    font.pixelSize: 22
                    font.bold: true
                }

                // ---- Quick scan ----
                Card {
                    title: "Quick Scan"

                    GridLayout {
                        Layout.fillWidth: true
                        columns: page.width < 700 ? 1 : 2
                        columnSpacing: 14
                        rowSpacing: 10

                        ColumnLayout {
                            Layout.fillWidth: true
                            Text { text: "Target"; color: Theme.secondaryText; font.pixelSize: 12 }
                            TextField {
                                Layout.fillWidth: true
                                enabled: !scan.running
                                text: scan.target
                                placeholderText: "example.com or 192.168.1.1"
                                color: Theme.text
                                placeholderTextColor: Theme.secondaryText
                                onTextEdited: scan.target = text
                                background: Rectangle {
                                    radius: 6; color: Theme.surfaceVariant
                                    border.color: Theme.border
                                }
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            Text { text: "Ports"; color: Theme.secondaryText; font.pixelSize: 12 }
                            TextField {
                                id: portsField
                                Layout.fillWidth: true
                                enabled: !scan.running && scan.portMode === "custom"
                                readOnly: scan.portMode !== "custom"
                                placeholderText: "1-1000, 8080"
                                color: Theme.text
                                placeholderTextColor: Theme.secondaryText
                                onTextEdited: if (scan.portMode === "custom") scan.ports = text
                                background: Rectangle {
                                    radius: 6; color: Theme.surfaceVariant
                                    border.color: Theme.border
                                }

                                // Reflect the shared config: the custom string
                                // in custom mode, or the top-ports selection
                                // when the Advanced page switched modes. Resync
                                // on every config change so this quick field
                                // never goes stale (a user edit would otherwise
                                // break a plain `text:` binding).
                                function syncFromConfig() {
                                    text = scan.portMode === "top"
                                        ? ("Top " + scan.topPorts + " ports")
                                        : scan.ports
                                }
                                Component.onCompleted: syncFromConfig()
                                Connections {
                                    target: scan
                                    function onConfigChanged() {
                                        portsField.syncFromConfig()
                                    }
                                }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 12

                        ComboBox {
                            enabled: !scan.running
                            model: ["TCP Connect", "TCP SYN"]
                            currentIndex: scan.scanType === "syn" ? 1 : 0
                            onActivated: scan.scanType = (currentIndex === 1 ? "syn" : "connect")
                        }

                        Item { Layout.fillWidth: true }

                        Button {
                            text: "Advanced →"
                            flat: true
                            onClicked: page.goScan()
                        }

                        Button {
                            text: scan.running ? "Scanning…" : "Start Scan"
                            enabled: !scan.running
                            onClicked: scan.start()
                        }
                    }
                }

                // ---- Progress (while running) ----
                ProgressPanel { visible: scan.running }

                // ---- Last scan metrics ----
                Text {
                    text: "Last Scan"
                    color: Theme.secondaryText
                    font.pixelSize: 12
                    font.bold: true
                    font.capitalization: Font.AllUppercase
                }
                GridLayout {
                    Layout.fillWidth: true
                    columns: page.width < 700 ? 2 : 3
                    columnSpacing: 12
                    rowSpacing: 12
                    MetricCard { label: "Status"; value: scan.status; accent: Theme.accent }
                    MetricCard {
                        label: "Duration"
                        value: (scan.metrics && scan.metrics.total_time
                                ? scan.metrics.total_time.toFixed(2) : "0") + "s"
                    }
                    MetricCard {
                        label: "Rate"
                        value: (scan.metrics && scan.metrics.scan_rate
                                ? scan.metrics.scan_rate.toFixed(0) : "0") + "/s"
                    }
                    MetricCard { label: "Open"; value: page.count("OPEN"); accent: Theme.success }
                    MetricCard { label: "Closed"; value: page.count("CLOSED") }
                    MetricCard { label: "Filtered"; value: page.count("FILTERED"); accent: Theme.warning }
                }

                Button {
                    text: "View Results →"
                    flat: true
                    onClicked: page.goResults()
                }
            }
        }
    }
}
