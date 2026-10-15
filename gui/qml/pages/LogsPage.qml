import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: page
    property var all: []
    property string levelFilter: "All"
    property string search: ""

    function view() {
        var out = []
        for (var i = 0; i < all.length; i++) {
            var e = all[i]
            if (levelFilter !== "All" && e.level !== levelFilter) continue
            if (search.length > 0 &&
                e.message.toLowerCase().indexOf(search.toLowerCase()) < 0) continue
            out.push(e)
        }
        return out
    }
    property var filtered: []
    function refresh() { filtered = view() }

    Connections {
        target: scan
        function onLogAdded(level, message) {
            var d = new Date()
            var ts = Qt.formatTime(d, "hh:mm:ss")
            page.all = [{ level: level, message: message, time: ts }].concat(page.all)
            page.refresh()
        }
    }

    function levelColor(level) {
        switch (level) {
        case "ERROR": return Theme.error
        case "WARNING": return Theme.warning
        case "DEBUG": return Theme.secondaryText
        default: return Theme.accent
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        Text {
            text: "Logs"
            color: Theme.text
            font.pixelSize: 22
            font.bold: true
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10
            ComboBox {
                model: ["All", "INFO", "WARNING", "ERROR", "DEBUG"]
                onActivated: { page.levelFilter = currentText; page.refresh() }
            }
            TextField {
                Layout.fillWidth: true
                placeholderText: "Search logs…"
                color: Theme.text
                placeholderTextColor: Theme.secondaryText
                onTextChanged: { page.search = text; page.refresh() }
                background: Rectangle { radius: 6; color: Theme.surfaceVariant; border.color: Theme.border }
            }
            Button {
                text: "Clear"
                onClicked: { page.all = []; page.refresh() }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: 8
            color: Theme.surface
            border.color: Theme.border

            ListView {
                anchors.fill: parent
                anchors.margins: 8
                clip: true
                model: page.filtered
                ScrollBar.vertical: ScrollBar {}
                delegate: RowLayout {
                    width: ListView.view.width
                    spacing: 10
                    Text { text: modelData.time; color: Theme.secondaryText; font.pixelSize: 11; font.family: "monospace" }
                    Text {
                        text: modelData.level
                        color: page.levelColor(modelData.level)
                        font.pixelSize: 11; font.bold: true
                        Layout.preferredWidth: 62
                    }
                    Text {
                        text: modelData.message
                        color: Theme.text; font.pixelSize: 12
                        Layout.fillWidth: true; wrapMode: Text.WordWrap
                    }
                }
            }
        }
    }
}
