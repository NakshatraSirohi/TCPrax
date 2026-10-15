import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: page

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
                    text: "Settings"
                    color: Theme.text
                    font.pixelSize: 22
                    font.bold: true
                }

                // ---- Appearance ----
                Card {
                    title: "Appearance"
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Theme"; color: Theme.text; font.pixelSize: 13; Layout.preferredWidth: 120 }
                        ComboBox {
                            model: ["System", "Light", "Dark"]
                            currentIndex: Theme.mode === "light" ? 1
                                          : Theme.mode === "dark" ? 2 : 0
                            onActivated: Theme.mode = ["system", "light", "dark"][currentIndex]
                        }
                    }
                }

                // ---- Defaults (apply to the next scan) ----
                Card {
                    title: "Defaults"
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Scan type"; color: Theme.text; font.pixelSize: 13; Layout.preferredWidth: 120 }
                        ComboBox {
                            model: ["TCP Connect", "TCP SYN"]
                            currentIndex: scan.scanType === "syn" ? 1 : 0
                            onActivated: scan.scanType = currentIndex === 1 ? "syn" : "connect"
                        }
                    }
                    CheckBox {
                        text: "Automatic thread count"
                        checked: scan.threads === 0
                        onToggled: scan.threads = checked ? 0 : 20
                        contentItem: Text {
                            text: parent.text; color: Theme.text
                            leftPadding: parent.indicator.width + 6
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    CheckBox {
                        text: "Service detection by default"
                        checked: scan.serviceDetection
                        onToggled: scan.serviceDetection = checked
                        contentItem: Text {
                            text: parent.text; color: Theme.text
                            leftPadding: parent.indicator.width + 6
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Default retries"; color: Theme.text; font.pixelSize: 13; Layout.preferredWidth: 120 }
                        SpinBox {
                            from: 0; to: 10; editable: true
                            value: scan.retries
                            onValueModified: scan.retries = value
                        }
                    }
                }

                // ---- About ----
                Card {
                    title: "About"
                    Text { text: appName + " " + appVersion; color: Theme.text; font.pixelSize: 14; font.bold: true }
                    Text {
                        text: "Modular TCP reconnaissance framework. CLI and GUI share one scan engine."
                        color: Theme.secondaryText; font.pixelSize: 12
                        Layout.fillWidth: true; wrapMode: Text.WordWrap
                    }
                    Text {
                        text: dbInfo.fingerprints + " fingerprints · "
                              + dbInfo.commonServices + " common services"
                        color: Theme.secondaryText; font.pixelSize: 11
                    }
                }
            }
        }
    }
}
