import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import "../components"

Item {
    id: page
    signal goResults()

    property int selCount: -1
    function refreshCount() { selCount = scan.portCount() }
    Component.onCompleted: refreshCount()
    Connections { target: scan; function onConfigChanged() { page.refreshCount() } }

    function themedField(parentText) { return parentText }

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

                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        text: "Scan"
                        color: Theme.text
                        font.pixelSize: 22
                        font.bold: true
                        Layout.fillWidth: true
                    }
                    Button {
                        text: "Cancel"
                        visible: scan.running
                        onClicked: scan.cancel()
                    }
                    Button {
                        text: scan.running ? "Running…" : "Start Scan"
                        enabled: !scan.running
                        onClicked: scan.start()
                    }
                }

                ProgressPanel { visible: scan.running }

                // ---- Target ----
                Card {
                    title: "Target"
                    TextField {
                        Layout.fillWidth: true
                        enabled: !scan.running
                        text: scan.target
                        placeholderText: "hostname or IPv4 address"
                        color: Theme.text
                        placeholderTextColor: Theme.secondaryText
                        onTextEdited: scan.target = text
                        background: Rectangle {
                            radius: 6; color: Theme.surfaceVariant
                            border.color: Theme.border
                        }
                    }
                }

                // ---- Port Selection ----
                Card {
                    title: "Port Selection"
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 20
                        RadioButton {
                            text: "Custom ports"
                            enabled: !scan.running
                            checked: scan.portMode === "custom"
                            onToggled: if (checked) { scan.portMode = "custom"; page.refreshCount() }
                            contentItem: Text {
                                text: parent.text; color: Theme.text
                                leftPadding: parent.indicator.width + 6
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                        RadioButton {
                            text: "Top ports"
                            enabled: !scan.running
                            checked: scan.portMode === "top"
                            onToggled: if (checked) { scan.portMode = "top"; page.refreshCount() }
                            contentItem: Text {
                                text: parent.text; color: Theme.text
                                leftPadding: parent.indicator.width + 6
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                    }
                    TextField {
                        Layout.fillWidth: true
                        enabled: !scan.running && scan.portMode === "custom"
                        opacity: enabled ? 1 : 0.5
                        text: scan.ports
                        placeholderText: "80; 1-1000; 22,80,443; 1-20,40-75"
                        color: Theme.text
                        placeholderTextColor: Theme.secondaryText
                        onTextEdited: { scan.ports = text; page.refreshCount() }
                        background: Rectangle {
                            radius: 6; color: Theme.surfaceVariant
                            border.color: Theme.border
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        enabled: !scan.running && scan.portMode === "top"
                        opacity: enabled ? 1 : 0.5
                        Text { text: "Top N:"; color: Theme.secondaryText; font.pixelSize: 12 }
                        SpinBox {
                            from: 1; to: 1000; editable: true
                            value: scan.topPorts
                            onValueModified: { scan.topPorts = value; page.refreshCount() }
                        }
                    }
                    Text {
                        text: page.selCount >= 0
                              ? (page.selCount + " ports selected")
                              : "✕ Invalid port selection"
                        color: page.selCount >= 0 ? Theme.secondaryText : Theme.error
                        font.pixelSize: 12
                    }
                }

                // ---- Scan Method ----
                Card {
                    title: "Scan Method"
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 12
                        Repeater {
                            model: [
                                { id: "connect", name: "TCP Connect (-sT)", note: "No special privileges" },
                                { id: "syn", name: "TCP SYN (-sS)", note: "Requires root / raw sockets" }
                            ]
                            Rectangle {
                                Layout.fillWidth: true
                                implicitHeight: 62
                                radius: 8
                                color: scan.scanType === modelData.id ? Theme.surfaceVariant : Theme.surface
                                border.color: scan.scanType === modelData.id ? Theme.accent : Theme.border
                                border.width: scan.scanType === modelData.id ? 2 : 1
                                opacity: scan.running ? 0.6 : 1
                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 2
                                    Text { text: modelData.name; color: Theme.text; font.pixelSize: 13; font.bold: true }
                                    Text { text: modelData.note; color: Theme.secondaryText; font.pixelSize: 11 }
                                }
                                TapHandler {
                                    enabled: !scan.running
                                    onTapped: scan.scanType = modelData.id
                                }
                            }
                        }
                    }
                }

                // ---- Performance ----
                Card {
                    title: "Performance"
                    CheckBox {
                        text: "Automatic thread count"
                        enabled: !scan.running
                        checked: scan.threads === 0
                        onToggled: scan.threads = checked ? 0 : 20
                        contentItem: Text {
                            text: parent.text; color: Theme.text
                            leftPadding: parent.indicator.width + 6
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        enabled: !scan.running && scan.threads !== 0
                        opacity: enabled ? 1 : 0.5
                        Slider {
                            Layout.fillWidth: true
                            from: 1; to: 300; stepSize: 1
                            value: scan.threads === 0 ? 20 : scan.threads
                            onMoved: scan.threads = Math.round(value)
                        }
                        SpinBox {
                            from: 1; to: 300; editable: true
                            value: scan.threads === 0 ? 20 : scan.threads
                            onValueModified: scan.threads = value
                        }
                    }
                    Text {
                        text: "1-300 threads. Automatic sizes to the port count."
                        color: Theme.secondaryText; font.pixelSize: 11
                    }
                }

                // ---- Reliability ----
                Card {
                    title: "Reliability"
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Retries:"; color: Theme.secondaryText; font.pixelSize: 12 }
                        SpinBox {
                            from: 0; to: 10; editable: true
                            enabled: !scan.running
                            value: scan.retries
                            onValueModified: scan.retries = value
                        }
                        Text {
                            text: "Additional attempts for uncertain (FILTERED/OTHER) ports."
                            color: Theme.secondaryText; font.pixelSize: 11
                            Layout.fillWidth: true; wrapMode: Text.WordWrap
                        }
                    }
                }

                // ---- Service Detection ----
                Card {
                    title: "Service Detection"
                    CheckBox {
                        text: "Service / version detection (-sV)"
                        enabled: !scan.running
                        checked: scan.serviceDetection
                        onToggled: scan.serviceDetection = checked
                        contentItem: Text {
                            text: parent.text; color: Theme.text
                            leftPadding: parent.indicator.width + 6
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    Text {
                        text: scan.serviceDetection
                              ? "Banners, protocol probes, TLS and fingerprint matching on open ports."
                              : "Enable to identify services on open ports."
                        color: Theme.secondaryText; font.pixelSize: 11
                        Layout.fillWidth: true; wrapMode: Text.WordWrap
                    }
                }

                // ---- Output ----
                Card {
                    title: "Output"
                    CheckBox {
                        text: "Save report to file"
                        enabled: !scan.running
                        checked: scan.outputEnabled
                        onToggled: scan.outputEnabled = checked
                        contentItem: Text {
                            text: parent.text; color: Theme.text
                            leftPadding: parent.indicator.width + 6
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        enabled: !scan.running && scan.outputEnabled
                        opacity: enabled ? 1 : 0.5
                        TextField {
                            Layout.fillWidth: true
                            text: scan.outputPath
                            placeholderText: "path/to/scan.txt"
                            color: Theme.text
                            placeholderTextColor: Theme.secondaryText
                            onTextEdited: scan.outputPath = text
                            background: Rectangle {
                                radius: 6; color: Theme.surfaceVariant
                                border.color: Theme.border
                            }
                        }
                        Button { text: "Browse"; onClicked: saveDialog.open() }
                    }
                }

                // ---- Advanced ----
                Card {
                    title: "Advanced"
                    Text {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: Theme.secondaryText
                        font.pixelSize: 11
                        text: "Concurrency is chosen adaptively when Automatic is on, "
                              + "bounded to 300 workers. SYN scans require root privileges; "
                              + "if unavailable, ports are reported as ERROR."
                    }
                }
            }
        }
    }

    FileDialog {
        id: saveDialog
        title: "Save report as"
        fileMode: FileDialog.SaveFile
        nameFilters: ["Text files (*.txt)", "All files (*)"]
        onAccepted: {
            scan.outputEnabled = true
            scan.outputPath = selectedFile.toString().replace("file://", "")
        }
    }
}
