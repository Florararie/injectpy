import os
import sys
import psutil
import ctypes
from ctypes import wintypes
from injectpy import Injector, InjectionResult
from PySide6.QtCore import Qt, QTimer, QSettings
from PySide6.QtGui import QIcon, QPixmap, QImage, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QFileDialog, QLabel, QCheckBox, QSpinBox, QLineEdit, QListWidget,
    QDialog, QDialogButtonBox, QMessageBox, QListWidgetItem
)



PROCESS_REFRESH_INTERVAL_MS = 1500
PROCESS_CHECK_INTERVAL_MS = 2000
SETTINGS_ORG = "FloryTools"
SETTINGS_APP = "InjectpyGUI"



def get_process_icon(exe_path: str) -> QIcon:
    shell32 = ctypes.windll.shell32
    user32 = ctypes.windll.user32

    def hicon_to_qicon(hicon):
        if not hicon:
            return None
        try:
            img = QImage.fromHICON(hicon)
            if not img.isNull():
                return QIcon(QPixmap.fromImage(img))
            return None
        finally:
            user32.DestroyIcon(hicon)

    def try_extract_icon(path, index=0):
        try:
            hicon_large = wintypes.HICON()
            hicon_small = wintypes.HICON()
            res = shell32.ExtractIconExW(
                path, index,
                ctypes.byref(hicon_large),
                ctypes.byref(hicon_small),
                1
            )
            if res > 0:
                return hicon_to_qicon(hicon_large.value)
        except Exception:
            pass
        return None

    icon = try_extract_icon(exe_path)
    if icon:
        return icon

    return try_extract_icon("C:\\Windows\\System32\\shell32.dll", 2) or QIcon()



class ProcessPickerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Process")
        self.resize(350, 500)

        self.proc_map = {}
        self.proc_details = {}
        self.filtered = []

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter by name or PID...")
        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.accept)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.search_edit)
        layout.addWidget(self.list_widget)
        layout.addWidget(button_box)

        self.search_edit.textChanged.connect(self.filter_processes)
        self.search_edit.setFocus()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_processes)
        self.timer.start(PROCESS_REFRESH_INTERVAL_MS)
        self.load_processes()


    def load_processes(self):
        current_filter = self.search_edit.text().lower().strip()

        self.proc_map.clear()
        processes = []
        for proc in psutil.process_iter(attrs=["name", "pid", "exe"]):
            try:
                name = proc.info.get("name")
                pid = proc.info.get("pid")
                exe = proc.info.get("exe")
                if name and pid:
                    display = f"{name} ({pid})"
                    processes.append((display, pid, exe))
                    self.proc_map[display] = pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        processes.sort(key=lambda x: x[0].lower())
        self.filtered = [p[0] for p in processes]
        self.proc_details = {p[0]: (p[1], p[2]) for p in processes}
        self.filter_processes(current_filter)


    def filter_processes(self, text):
        text = text.lower().strip()
        if not text:
            self.filtered = list(self.proc_map.keys())
        else:
            self.filtered = [item for item in self.proc_map.keys() if text in item.lower()]
        self.update_list()


    def update_list(self):
        current_selection = self.list_widget.currentItem().text() if self.list_widget.currentItem() else None

        self.list_widget.clear()
        for display in self.filtered:
            item = QListWidgetItem(display)
            pid, exe = self.proc_details.get(display, (None, None))
            if exe:
                icon = get_process_icon(exe)
                if icon:
                    item.setIcon(icon)
            self.list_widget.addItem(item)

        if current_selection and current_selection in self.filtered:
            matches = self.list_widget.findItems(current_selection, Qt.MatchExactly)
            if matches:
                self.list_widget.setCurrentItem(matches[0])


    def selected_process(self):
        item = self.list_widget.currentItem()
        if item:
            display = item.text()
            return self.proc_details.get(display, (None, None)), display
        return (None, None), None



class InjectorGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Injectpy GUI - Flory <3")
        self.setFixedSize(400, 150)
        self.setAcceptDrops(True)

        self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
        main_layout = QVBoxLayout(self)

        dll_layout = QHBoxLayout()
        self.dll_edit = QLineEdit()
        dll_btn = QPushButton("...")
        dll_btn.setToolTip("Open file dialog")
        dll_btn.clicked.connect(self.select_dll)
        dll_layout.addWidget(QLabel("DLL:"))
        dll_layout.addWidget(self.dll_edit)
        dll_layout.addWidget(dll_btn)
        main_layout.addLayout(dll_layout)

        proc_layout = QHBoxLayout()
        proc_layout.addWidget(QLabel("Process:"))

        self.proc_icon = QLabel()
        self.proc_icon.setFixedSize(16, 16)
        proc_layout.addWidget(self.proc_icon)
        self.proc_label = QLabel("<No process selected>")
        proc_layout.addWidget(self.proc_label, 1)
        select_btn = QPushButton("...")
        select_btn.setToolTip("Select a running process")
        select_btn.clicked.connect(self.open_process_picker)
        proc_layout.addWidget(select_btn)
        main_layout.addLayout(proc_layout)

        self.selected_pid = None
        self.selected_display = None
        self.selected_exe = None

        options_layout = QHBoxLayout()
        self.force_check = QCheckBox("Force Inject")
        self.force_check.setToolTip("If enabled, the DLL will be ejected first if it is already loaded before attempting to inject again.")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(0, 60000)
        self.timeout_spin.setValue(5000)
        self.timeout_spin.setPrefix("Timeout (ms): ")
        self.infinite_check = QCheckBox("Infinite")
        self.infinite_check.toggled.connect(self.toggle_infinite_timeout)
        options_layout.addWidget(self.force_check)
        options_layout.addWidget(self.timeout_spin)
        options_layout.addWidget(self.infinite_check)
        main_layout.addLayout(options_layout)

        btn_layout = QHBoxLayout()
        self.inject_btn = QPushButton("Inject")
        self.inject_btn.setToolTip("Inject DLL into chosen process")
        self.eject_btn = QPushButton("Eject")
        self.eject_btn.setToolTip("Eject DLL from chosen process")
        btn_layout.addWidget(self.inject_btn)
        btn_layout.addWidget(self.eject_btn)
        main_layout.addLayout(btn_layout)

        self.injector = Injector(verbose=True)
        self.inject_btn.clicked.connect(lambda: self.handle_dll_action("inject"))
        self.eject_btn.clicked.connect(lambda: self.handle_dll_action("eject"))
        self.update_button_states()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_process_alive)
        self.timer.start(PROCESS_CHECK_INTERVAL_MS)
        self.restore_settings()


    def toggle_infinite_timeout(self, checked):
        self.timeout_spin.setEnabled(not checked)


    def open_process_picker(self):
        dialog = ProcessPickerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            (pid, exe), display = dialog.selected_process()
            if pid:
                self.selected_pid = pid
                self.selected_display = display
                self.selected_exe = exe
                self.proc_label.setText(display)

                icon = get_process_icon(exe) if exe else QIcon()
                if not icon.isNull():
                    self.proc_icon.setPixmap(icon.pixmap(16, 16))
                else:
                    self.proc_icon.clear()
        self.update_button_states()


    def select_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select DLL File", "", "Dynamic Link Library (*.dll)")
        if path:
            self.dll_edit.setText(path)


    def handle_dll_action(self, action: str):
        dll_path = self.dll_edit.text().strip()
        pid = self.selected_pid

        if not pid or not psutil.pid_exists(pid):
            QMessageBox.critical(self, "Error", "Please select a valid running process.")
            return

        if not dll_path or not dll_path.lower().endswith(".dll") or not os.path.exists(dll_path):
            QMessageBox.critical(self, "Error", "Please select a valid DLL file.")
            return

        timeout = 0xFFFFFFFF if self.infinite_check.isChecked() else self.timeout_spin.value()
        force = self.force_check.isChecked()

        try:
            if action == "inject":
                result = self.injector.inject(pid, dll_path, timeout=timeout, force=force)
                success_msg = f"DLL injected into {self.selected_display}"
                fail_msg = f"Injection failed: {{}}"
            elif action == "eject":
                module_name = os.path.basename(dll_path)
                result = self.injector.eject(pid, module_name, timeout=timeout)
                success_msg = f"DLL ejected from {self.selected_display}"
                fail_msg = f"Ejection failed: {{}}"
            else:
                QMessageBox.critical(self, "Error", f"Unknown action: {action}")
                return

            if result == InjectionResult.SUCCESS:
                QMessageBox.information(self, "Success", success_msg)
            else:
                QMessageBox.critical(self, "Error", fail_msg.format(result.value))

        except Exception as e:
            QMessageBox.critical(self, "Error", f"{action.capitalize()} error: {e}")


    def check_process_alive(self):
        if self.selected_pid and not psutil.pid_exists(self.selected_pid):
            self.selected_pid = None
            self.selected_display = None
            self.proc_label.setText("<No process selected>")
            self.proc_icon.clear()
        self.update_button_states()


    def update_button_states(self):
        has_process = self.selected_pid is not None
        self.inject_btn.setEnabled(has_process)
        self.eject_btn.setEnabled(has_process)


    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()


    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            self.dll_edit.setText(path)


    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)


    def save_settings(self):
        self.settings.setValue("dll_path", self.dll_edit.text())
        self.settings.setValue("timeout", self.timeout_spin.value())
        self.settings.setValue("infinite", self.infinite_check.isChecked())
        self.settings.setValue("force", self.force_check.isChecked())


    def restore_settings(self):
        dll_path = self.settings.value("dll_path", "")
        timeout = int(self.settings.value("timeout", 5000))
        infinite = self.settings.value("infinite", False, type=bool)
        force = self.settings.value("force", False, type=bool)

        self.dll_edit.setText(dll_path)
        self.timeout_spin.setValue(timeout)
        self.infinite_check.setChecked(infinite)
        self.force_check.setChecked(force)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = InjectorGUI()
    window.show()
    sys.exit(app.exec())
