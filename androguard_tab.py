import pickle
import os
import shutil
import subprocess
import sys
import webbrowser
import requests
import zipfile
import tempfile
import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit,
    QFileDialog, QTabWidget, QTreeWidget, QTreeWidgetItem, QGroupBox, QMessageBox, QProgressBar, QMenu, QDialog, QSplitter, QProgressDialog
)
from PyQt6.QtCore import QObject, pyqtSignal, QThread, Qt
from PyQt6.QtGui import QFont, QPainter, QColor
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from lxml import etree

JADX_TOOLS_DIR = os.path.join(os.getcwd(), "tools", "jadx")

class Overlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.spinner = QProgressBar(self)
        self.spinner.setRange(0, 0) # Indeterminate
        self.spinner.setTextVisible(False)
        self.spinner.setStyleSheet("QProgressBar { border: none; background-color: transparent; } QProgressBar::chunk { background-color: #007acc; }")

        self.label = QLabel("Analyzing APK...", self)
        self.label.setStyleSheet("background-color: transparent; color: white; font-size: 16px;")

        layout.addWidget(self.spinner)
        layout.addWidget(self.label)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor(0, 0, 0, 180))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRect(self.rect())

class CFGDialog(QDialog):
    def __init__(self, g, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Control Flow Graph")
        layout = QVBoxLayout(self)
        fig, ax = plt.subplots()
        nx.draw(g, ax=ax, with_labels=True)
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)

class JadxInstaller(QObject):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)

    def run(self):
        try:
            self.progress.emit(0, "Finding latest JADX release...")
            api_url = "https://api.github.com/repos/skylot/jadx/releases/latest"
            response = requests.get(api_url, timeout=15)
            response.raise_for_status()
            release_data = response.json()
            
            download_url = None
            for asset in release_data.get('assets', []):
                if asset['name'].endswith(".zip"):
                    download_url = asset['browser_download_url']
                    break
            
            if not download_url:
                raise FileNotFoundError("Could not find a suitable release for JADX.")

            self.progress.emit(10, f"Downloading from {download_url}...")
            zip_path = os.path.join(tempfile.gettempdir(), "jadx.zip")
            with requests.get(download_url, stream=True, timeout=300) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                with open(zip_path, "wb") as f:
                    downloaded = 0
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = 10 + int((downloaded / total_size) * 80)
                            self.progress.emit(percent, f"Downloading... {downloaded // 1024} KB / {total_size // 1024} KB")

            self.progress.emit(90, "Installing JADX...")
            tools_dir = JADX_TOOLS_DIR
            if os.path.exists(tools_dir):
                shutil.rmtree(tools_dir)
            os.makedirs(tools_dir)

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tools_dir)

            os.remove(zip_path)

            # Find the executable
            jadx_executable = "jadx-gui.bat" if sys.platform == "win32" else "jadx-gui"
            final_path = os.path.join(tools_dir, "bin", jadx_executable)
            if not os.path.exists(final_path):
                # The structure might be different, search for it
                for root, dirs, files in os.walk(tools_dir):
                    if jadx_executable in files:
                        final_path = os.path.join(root, jadx_executable)
                        break
            
            if not os.path.exists(final_path):
                raise FileNotFoundError("Could not find jadx-gui executable after extraction.")

            self.progress.emit(100, "Installation complete.")
            self.finished.emit(final_path)

        except requests.exceptions.RequestException as e:
            self.error.emit(f"Network error during JADX download: {e}")
        except FileNotFoundError as e:
            self.error.emit(f"File not found error during JADX installation: {e}")
        except zipfile.BadZipFile as e:
            self.error.emit(f"Bad zip file error during JADX extraction: {e}")
        except Exception as e:
            self.error.emit(f"An unexpected error occurred during JADX installation: {e}")


class AndroguardWorker(QObject):
    """
    Worker to run Androguard analysis in a background thread.
    """
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, apk_path):
        super().__init__()
        self.apk_path = apk_path

    def run(self):
        try:
            from androguard import misc
        except ImportError as e:
            self.error.emit(f"Failed to import androguard: {e}. Please ensure it is installed correctly.")
            return

        try:
            a, d, dx = misc.AnalyzeAPK(self.apk_path)
            self.finished.emit((a, d, dx))
        except Exception as e:
            self.error.emit(f"Androguard analysis failed: {e}")

class AndroguardTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.apk_path = None
        self.apk = None
        self.dvm = None
        self.analysis = None
        self.tabs_populated = []
        self.init_ui()

        self.overlay = Overlay(self)
        self.overlay.hide()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Top section for APK selection
        selection_group = QGroupBox("APK Selection")
        selection_layout = QHBoxLayout()
        self.apk_path_edit = QLineEdit()
        self.apk_path_edit.setPlaceholderText("Select an APK file to analyze...")
        self.apk_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_apk)
        analyze_btn = QPushButton("Decompile with Androguard")
        analyze_btn.clicked.connect(self.start_analysis)
        jadx_btn = QPushButton("Decompile with JADX")
        jadx_btn.clicked.connect(self.decompile_with_jadx)
        selection_layout.addWidget(self.apk_path_edit)
        selection_layout.addWidget(browse_btn)
        selection_layout.addWidget(analyze_btn)
        selection_layout.addWidget(jadx_btn)

        save_btn = QPushButton("Save Analysis")
        save_btn.clicked.connect(self.save_analysis)
        load_btn = QPushButton("Load Analysis")
        load_btn.clicked.connect(self.load_analysis)
        selection_layout.addWidget(save_btn)
        selection_layout.addWidget(load_btn)

        selection_group.setLayout(selection_layout)
        layout.addWidget(selection_group)

        # Results section with tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.currentChanged.connect(self.tab_changed)
        layout.addWidget(self.results_tabs)

        self.setLayout(layout)

    def browse_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk);;All Files (*)")
        if file_path:
            self.apk_path = file_path
            self.apk_path_edit.setText(file_path)

    def start_analysis(self):
        if not self.apk_path:
            QMessageBox.warning(self, "No APK Selected", "Please select an APK file first.")
            return

        self.overlay.show()
        self.overlay.raise_()
            
        self.results_tabs.clear()
        self.worker = AndroguardWorker(self.apk_path)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.analysis_finished)
        self.worker.error.connect(self.analysis_error)
        self.thread.start()

    def analysis_finished(self, result):
        self.overlay.hide()
        self.apk, self.dvm, self.analysis = result
        self.populate_results()
        self.thread.quit()

    def analysis_error(self, error_message):
        self.overlay.hide()
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.thread.quit()

    def save_analysis(self):
        if not self.analysis:
            QMessageBox.warning(self, "No Analysis", "Please analyze an APK first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Analysis File", "", "Androguard Analysis Files (*.ag);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    pickle.dump((self.apk, self.dvm, self.analysis), f)
                QMessageBox.information(self, "Analysis Saved", f"Analysis saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save analysis: {e}")

    def load_analysis(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Analysis File", "", "Androguard Analysis Files (*.ag);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    self.apk, self.dvm, self.analysis = pickle.load(f)
                
                self.apk_path_edit.setText(f"Loaded from {file_path}")
                self.populate_results()
                QMessageBox.information(self, "Analysis Loaded", f"Analysis loaded from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load analysis: {e}")

    def populate_results(self):
        self.results_tabs.clear()
        self.tabs_populated = [False] * 14

        self.results_tabs.addTab(QWidget(), "General")
        self.results_tabs.addTab(QWidget(), "Permissions")
        self.results_tabs.addTab(QWidget(), "Activities")
        self.results_tabs.addTab(QWidget(), "Services")
        self.results_tabs.addTab(QWidget(), "Receivers")
        self.results_tabs.addTab(QWidget(), "Providers")
        self.results_tabs.addTab(QWidget(), "Classes")
        self.results_tabs.addTab(QWidget(), "Methods")
        self.results_tabs.addTab(QWidget(), "Strings")
        self.results_tabs.addTab(QWidget(), "Manifest")
        self.results_tabs.addTab(QWidget(), "Certificates")
        self.results_tabs.addTab(QWidget(), "Libraries")
        self.results_tabs.addTab(QWidget(), "Resources")
        self.results_tabs.addTab(QWidget(), "Xposed Hooks")

        # Populate the first tab immediately
        self.tab_changed(0)

    def tab_changed(self, index):
        if self.tabs_populated[index]:
            return

        if index == 0:
            self.populate_general_tab()
        elif index == 1:
            self.populate_permissions_tab()
        elif index == 2:
            self.populate_activities_tab()
        elif index == 3:
            self.populate_services_tab()
        elif index == 4:
            self.populate_receivers_tab()
        elif index == 5:
            self.populate_providers_tab()
        elif index == 6:
            self.populate_classes_tab()
        elif index == 7:
            self.populate_methods_tab()
        elif index == 8:
            self.populate_strings_tab()
        elif index == 9:
            self.populate_manifest_tab()
        elif index == 10:
            self.populate_certificates_tab()
        elif index == 11:
            self.populate_libraries_tab()
        elif index == 12:
            self.populate_resources_tab()
        elif index == 13:
            self.populate_xposed_hooks_tab()

        self.tabs_populated[index] = True

    def populate_general_tab(self):
        tab = self.results_tabs.widget(0)
        layout = QVBoxLayout(tab)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier New", 10))
        general_info = f'''
Package: {self.apk.get_package()}\nVersion Name: {self.apk.get_androidversion_name()}\nVersion Code: {self.apk.get_androidversion_code()}\nMin SDK: {self.apk.get_min_sdk_version()}\nMax SDK: {self.apk.get_max_sdk_version()}\nTarget SDK: {self.apk.get_target_sdk_version()}\nEffective Target SDK: {self.apk.get_effective_target_sdk_version()}\n        '''
        text_edit.setText(general_info)
        layout.addWidget(text_edit)

    def populate_permissions_tab(self):
        tab = self.results_tabs.widget(1)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Permission"])
        for perm in self.apk.get_permissions():
            QTreeWidgetItem(tree, [perm])
        layout.addWidget(tree)

    def populate_activities_tab(self):
        tab = self.results_tabs.widget(2)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Activity"])
        for act in self.apk.get_activities():
            QTreeWidgetItem(tree, [act])
        layout.addWidget(tree)

    def populate_services_tab(self):
        tab = self.results_tabs.widget(3)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Service"])
        for serv in self.apk.get_services():
            QTreeWidgetItem(tree, [serv])
        layout.addWidget(tree)

    def populate_receivers_tab(self):
        tab = self.results_tabs.widget(4)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Receiver"])
        for rec in self.apk.get_receivers():
            QTreeWidgetItem(tree, [rec])
        layout.addWidget(tree)

    def populate_providers_tab(self):
        tab = self.results_tabs.widget(5)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Provider"])
        for prov in self.apk.get_providers():
            QTreeWidgetItem(tree, [prov])
        layout.addWidget(tree)

    def populate_classes_tab(self):
        tab = self.results_tabs.widget(6)
        layout = QVBoxLayout(tab)
        search = QLineEdit()
        search.setPlaceholderText("Search classes...")
        layout.addWidget(search)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Class Name"])
        search.textChanged.connect(lambda text: self.filter_tree(tree, text))
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self.show_class_context_menu)
        for cls in self.analysis.get_classes():
            QTreeWidgetItem(tree, [cls.name])
        layout.addWidget(tree)

    def populate_methods_tab(self):
        tab = self.results_tabs.widget(7)
        layout = QVBoxLayout(tab)
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        search = QLineEdit()
        search.setPlaceholderText("Search methods...")
        layout.insertWidget(0, search)

        tree = QTreeWidget()
        tree.setHeaderLabels(["Class", "Method", "Descriptor"])
        search.textChanged.connect(lambda text: self.filter_tree(tree, text))
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self.show_method_context_menu)

        self.method_code_view = QTextEdit()
        self.method_code_view.setReadOnly(True)
        self.method_code_view.setFont(QFont("Courier New", 10))

        splitter.addWidget(tree)
        splitter.addWidget(self.method_code_view)

        tree.itemSelectionChanged.connect(self.show_method_code)

        for meth in self.analysis.get_methods():
            QTreeWidgetItem(tree, [meth.class_name, meth.name, meth.descriptor])

    def populate_strings_tab(self):
        tab = self.results_tabs.widget(8)
        layout = QVBoxLayout(tab)
        search = QLineEdit()
        search.setPlaceholderText("Search strings...")
        layout.addWidget(search)
        tree = QTreeWidget()
        tree.setHeaderLabels(["String"])
        search.textChanged.connect(lambda text: self.filter_tree(tree, text))
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self.show_string_context_menu)
        for s in self.analysis.get_strings():
            QTreeWidgetItem(tree, [s.get_value()])
        layout.addWidget(tree)

    def populate_manifest_tab(self):
        tab = self.results_tabs.widget(9)
        layout = QVBoxLayout(tab)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier New", 10))
        text_edit.setText(etree.tostring(self.apk.get_android_manifest_xml(), pretty_print=True).decode())
        layout.addWidget(text_edit)

    def populate_certificates_tab(self):
        tab = self.results_tabs.widget(10)
        layout = QVBoxLayout(tab)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier New", 10))
        cert_info = ""
        for cert in self.apk.get_certificates():
            cert_info += f"Issuer: {cert.issuer.human_friendly}\n"
            cert_info += f"Subject: {cert.subject.human_friendly}\n"
            cert_info += f"Serial Number: {cert.serial_number}\n"
            cert_info += f"Valid From: {cert.not_valid_before}\n"
            cert_info += f"Valid To: {cert.not_valid_after}\n"
            cert_info += f"Signature Algorithm: {cert.signature_algo}\n"
            cert_info += f"Fingerprint (SHA1): {cert.sha1_fingerprint}\n\n"
        text_edit.setText(cert_info)
        layout.addWidget(text_edit)

    def populate_libraries_tab(self):
        tab = self.results_tabs.widget(11)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Library"])
        for lib in self.apk.get_libraries():
            QTreeWidgetItem(tree, [lib])
        layout.addWidget(tree)

    def populate_resources_tab(self):
        tab = self.results_tabs.widget(12)
        layout = QVBoxLayout(tab)
        tree = QTreeWidget()
        tree.setHeaderLabels(["Package", "Type", "Name", "Value"])
        arsc = self.apk.get_android_resources()
        if arsc:
            for package_name in arsc.get_packages_names():
                package_item = QTreeWidgetItem(tree, [package_name])
                for locale in arsc.get_locales(package_name):
                    # FIXME: we should show the locale in the GUI
                    if locale != "default":
                        continue
                    for type_name in arsc.get_types_names(package_name, locale=locale):
                        type_item = QTreeWidgetItem(package_item, [type_name])
                        try:
                            for res in arsc.get_resources(package_name, type_name, locale=locale):
                                QTreeWidgetItem(type_item, ["", "", res.get_name(), res.get_value()])
                        except KeyError:
                            # this happens if the type is empty
                            pass
        layout.addWidget(tree)

    def populate_xposed_hooks_tab(self):
        tab = self.results_tabs.widget(13)
        layout = QVBoxLayout(tab)
        
        # Xposed Module Management
        module_group = QGroupBox("Xposed Module Management")
        module_layout = QVBoxLayout()
        
        self.module_list_widget = QTreeWidget()
        self.module_list_widget.setHeaderLabels(["Module Name", "Package Name", "Version", "Status"])
        self.module_list_widget.setSortingEnabled(True)
        self.module_list_widget.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        
        refresh_modules_btn = QPushButton("Refresh Modules")
        refresh_modules_btn.clicked.connect(self.refresh_xposed_modules)
        
        module_layout.addWidget(refresh_modules_btn)
        module_layout.addWidget(self.module_list_widget)
        module_group.setLayout(module_layout)
        
        # Xposed Log Viewer
        log_group = QGroupBox("Xposed Log Viewer")
        log_layout = QVBoxLayout()
        
        self.xposed_log_output = QTextEdit()
        self.xposed_log_output.setReadOnly(True)
        self.xposed_log_output.setFont(QFont("Courier New", 10))
        
        log_controls_layout = QHBoxLayout()
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_xposed_log)
        
        save_log_btn = QPushButton("Save Log")
        save_log_btn.clicked.connect(self.save_xposed_log)
        
        log_controls_layout.addWidget(clear_log_btn)
        log_controls_layout.addWidget(save_log_btn)
        
        log_layout.addWidget(self.xposed_log_output)
        log_layout.addLayout(log_controls_layout)
        log_group.setLayout(log_layout)
        
        layout.addWidget(module_group)
        layout.addWidget(log_group)
        
        self.refresh_xposed_modules() # Initial load
        self.load_xposed_log() # Initial load of log



    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.overlay.resize(self.size())

    def show_class_context_menu(self, position):
        current_widget = self.results_tabs.currentWidget()
        if not current_widget:
            return
        item = current_widget.findChild(QTreeWidget).itemAt(position)
        if not item:
            return

        menu = QMenu()
        find_xrefs_action = menu.addAction("Find XREFs")
        find_xrefs_action.triggered.connect(lambda: self.find_class_xrefs(item.text(0)))
        menu.exec(self.results_tabs.currentWidget().findChild(QTreeWidget).viewport().mapToGlobal(position))

    def find_class_xrefs(self, class_name):
        if not self.analysis:
            return

        xrefs_tab = QWidget()
        xrefs_layout = QVBoxLayout(xrefs_tab)
        xrefs_tree = QTreeWidget()
        xrefs_tree.setHeaderLabels(["From Class", "From Method", "Offset"])
        xrefs_layout.addWidget(xrefs_tree)

        cls = None
        for c in self.analysis.get_classes():
            if c.name == class_name:
                cls = c
                break
        if not cls:
            return

        for caller, refs in cls.get_xref_from().items():
            for ref_kind, ref_method, ref_offset in refs:
                QTreeWidgetItem(xrefs_tree, [caller.name, ref_method.name, str(ref_offset)])

        self.results_tabs.addTab(xrefs_tab, f"XREFs to {class_name}")
        self.tabs_populated.append(True)
        self.results_tabs.setCurrentWidget(xrefs_tab)

    def show_method_context_menu(self, position):
        current_widget = self.results_tabs.currentWidget()
        if not current_widget:
            return
        item = current_widget.findChild(QTreeWidget).itemAt(position)
        if not item:
            return

        menu = QMenu()
        find_xrefs_action = menu.addAction("Find XREFs")
        find_xrefs_action.triggered.connect(lambda: self.find_method_xrefs(item.text(0), item.text(1), item.text(2)))
        view_cfg_action = menu.addAction("View CFG")
        view_cfg_action.triggered.connect(lambda: self.view_method_cfg(item.text(0), item.text(1), item.text(2)))
        menu.exec(self.results_tabs.currentWidget().findChild(QTreeWidget).viewport().mapToGlobal(position))

    def view_method_cfg(self, class_name, method_name, descriptor):
        if not self.analysis:
            return

        cls = None
        for c in self.analysis.get_classes():
            if c.name == class_name:
                cls = c
                break
        if not cls:
            return

        meth = None
        for m in cls.get_methods():
            if m.name == method_name and m.descriptor == descriptor:
                meth = m
                break
        
        if not meth:
            return

        g = nx.DiGraph()
        if meth.get_basic_blocks():
            for block in meth.get_basic_blocks().gets():
                g.add_node(block.get_name())
                for _, _, child_block in block.get_next():
                    if child_block:
                        g.add_edge(block.get_name(), child_block.get_name())
        if not g:
            QMessageBox.information(self, "CFG", "Could not generate CFG for this method.")
            return

        dialog = CFGDialog(g, self)
        dialog.exec()

    def _get_instruction_offset(self, ins):
        for attr in ['get_idx', 'get_offset', 'get_address']:
            if hasattr(ins, attr):
                return getattr(ins, attr)()
        return 0

    def show_method_code(self):
        selected_items = self.results_tabs.currentWidget().findChild(QTreeWidget).selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        class_name = item.text(0)
        method_name = item.text(1)
        descriptor = item.text(2)

        meth = self.analysis.get_method_by_name(class_name, method_name, descriptor)
        if not meth:
            return

        code = ""
        if meth.get_instructions():
            for ins in meth.get_instructions():
                offset = self._get_instruction_offset(ins)
                
                code += f"{offset:08x}  {ins.get_name()} {ins.get_output()}\n"

        self.method_code_view.setText(code)

    def find_method_xrefs(self, class_name, method_name, descriptor):
        if not self.analysis:
            return

        xrefs_tab = QWidget()
        xrefs_layout = QVBoxLayout(xrefs_tab)
        xrefs_tree = QTreeWidget()
        xrefs_tree.setHeaderLabels(["From Class", "From Method", "Offset"])
        xrefs_layout.addWidget(xrefs_tree)

        cls = None
        for c in self.analysis.get_classes():
            if c.name == class_name:
                cls = c
                break
        if not cls:
            return

        meth = None
        for m in cls.get_methods():
            if m.name == method_name and m.descriptor == descriptor:
                meth = m
                break
        
        if not meth:
            return

        for from_class, from_method, offset in meth.get_xref_from():
            QTreeWidgetItem(xrefs_tree, [from_class.name, from_method.name, str(offset)])

        self.results_tabs.addTab(xrefs_tab, f"XREFs to {method_name}")
        self.tabs_populated.append(True)
        self.results_tabs.setCurrentWidget(xrefs_tab)

    def show_string_context_menu(self, position):
        current_widget = self.results_tabs.currentWidget()
        if not current_widget:
            return
        item = current_widget.findChild(QTreeWidget).itemAt(position)
        if not item:
            return

        menu = QMenu()
        find_xrefs_action = menu.addAction("Find XREFs")
        find_xrefs_action.triggered.connect(lambda: self.find_string_xrefs(item.text(0)))
        menu.exec(self.results_tabs.currentWidget().findChild(QTreeWidget).viewport().mapToGlobal(position))

    def find_string_xrefs(self, string_value):
        if not self.analysis:
            return

        xrefs_tab = QWidget()
        xrefs_layout = QVBoxLayout(xrefs_tab)
        xrefs_tree = QTreeWidget()
        xrefs_tree.setHeaderLabels(["From Class", "From Method"])
        xrefs_layout.addWidget(xrefs_tree)

        for s in self.analysis.get_strings():
            if s.get_value() == string_value:
                for from_class, from_method in s.get_xref_from():
                    QTreeWidgetItem(xrefs_tree, [from_class.name, from_method.name])
                break

        self.results_tabs.addTab(xrefs_tab, f'XREFs to "{string_value}"')
        self.tabs_populated.append(True)
        self.results_tabs.setCurrentWidget(xrefs_tab)

    def filter_tree(self, tree, text):
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            item.setHidden(text.lower() not in item.text(0).lower())

    def _check_xposed_manager_installed(self):
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "No Device", "Please connect a device first.")
            return False

        return_code, output = self.device_manager.execute_adb_command("shell pm list packages org.meowcat.edxposed.manager")
        if return_code != 0 or "package:org.meowcat.edxposed.manager" not in output:
            QMessageBox.information(self, "Xposed Not Found", "Xposed Framework or Manager not detected on device.")
            return False
        return True

    def refresh_xposed_modules(self):
        self.module_list_widget.clear()
        if not self._check_xposed_manager_installed():
            return

    def _get_active_xposed_modules(self):
        active_modules = set()
        return_code, output = self.device_manager.execute_adb_command('shell su -c \'grep -E "^I.*XposedBridge: Loading module" /data/xposed/debug.log\' ')
        
        if return_code == 0 and output:
            for line in output.splitlines():
                match = re.search(r"Loading module (.+)", line)
                if match:
                    active_modules.add(match.group(1).strip())
        else:
            QMessageBox.information(self, "Xposed Modules", "Could not retrieve active Xposed modules. Ensure Xposed is installed and you have root access.")
        return active_modules

    def _get_installed_packages_info(self, active_modules):
        packages_info = []
        return_code, all_packages_output = self.device_manager.execute_adb_command("shell pm list packages -f")
        if return_code == 0 and all_packages_output:
            for line in all_packages_output.splitlines():
                match = re.match(r"package:(.+?)=(.+)", line)
                if match:
                    apk_path = match.group(1)
                    package_name = match.group(2)
                    
                    status = "Active" if package_name in active_modules else "Inactive/Not Xposed"
                    
                    version_name = "Unknown"
                    return_code_info, info_output = self.device_manager.execute_adb_command(f"shell dumpsys package {package_name}")
                    if return_code_info == 0:
                        version_match = re.search(r"versionName=([^\\s]+)", info_output)
                        if version_match:
                            version_name = version_match.group(1).strip('"')
                    packages_info.append((package_name, version_name, status))
        return packages_info

    def refresh_xposed_modules(self):
        self.module_list_widget.clear()
        if not self._check_xposed_manager_installed():
            return

        active_modules = self._get_active_xposed_modules()
        packages_info = self._get_installed_packages_info(active_modules)

        for package_name, version_name, status in packages_info:
            QTreeWidgetItem(self.module_list_widget, [package_name, package_name, version_name, status])

    def clear_xposed_log(self):
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "No Device", "Please connect a device first.")
            return
        
        confirm = QMessageBox.question(self, "Clear Xposed Log", "Are you sure you want to clear the Xposed log?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            return_code, output = self.device_manager.execute_adb_command("shell su -c 'echo > /data/xposed/debug.log'")
            if return_code == 0:
                self.xposed_log_output.clear()
                QMessageBox.information(self, "Success", "Xposed log cleared.")
            else:
                QMessageBox.warning(self, "Error", f"Failed to clear Xposed log: {output}")

    def save_xposed_log(self):
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "No Device", "Please connect a device first.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Xposed Log", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            return_code, output = self.device_manager.execute_adb_command("shell su -c 'cat /data/xposed/debug.log'")
            if return_code == 0:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(output)
                    QMessageBox.information(self, "Success", f"Xposed log saved to {file_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to save log to file: {e}")
            else:
                QMessageBox.warning(self, "Error", f"Failed to retrieve Xposed log from device: {output}")

    def load_xposed_log(self):
        if not self.device_manager.current_device:
            return
        
        return_code, output = self.device_manager.execute_adb_command("shell su -c 'cat /data/xposed/debug.log'")
        if return_code == 0:
            self.xposed_log_output.setText(output)
        else:
            self.xposed_log_output.setText(f"Failed to load Xposed log: {output}")


    def decompile_with_jadx(self):
        if not self.apk_path:
            QMessageBox.warning(self, "No APK Selected", "Please select an APK file first.")
            return

        jadx_path = shutil.which("jadx-gui") or shutil.which("jadx-gui.bat")
        if not jadx_path:
            tools_dir = JADX_TOOLS_DIR
            if sys.platform == "win32":
                jadx_path = os.path.join(tools_dir, "bin", "jadx-gui.bat")
            else:
                jadx_path = os.path.join(tools_dir, "bin", "jadx-gui")

        if not os.path.exists(jadx_path):
            reply = QMessageBox.question(self, "JADX Not Found",
                                         "JADX GUI not found in your system\'s PATH or in the 'tools' folder.\n"
                                         "Would you like to download and install it now?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.install_jadx()
            return

        try:
            subprocess.Popen([jadx_path, self.apk_path])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start JADX GUI: {e}")

    def install_jadx(self):
        self.progress_dialog = QProgressDialog("Installing JADX...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("JADX Installation")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.show()

        self.jadx_installer = JadxInstaller()
        self.jadx_thread = QThread()
        self.jadx_installer.moveToThread(self.jadx_thread)
        self.jadx_thread.started.connect(self.jadx_installer.run)
        self.jadx_installer.finished.connect(self.jadx_install_finished)
        self.jadx_installer.error.connect(self.jadx_install_error)
        self.jadx_installer.progress.connect(self.update_progress)
        self.jadx_thread.start()

    def update_progress(self, value, text):
        self.progress_dialog.setValue(value)
        self.progress_dialog.setLabelText(text)

    def jadx_install_finished(self, jadx_path):
        self.progress_dialog.close()
        QMessageBox.information(self, "JADX Installed", f"JADX has been installed to {os.path.dirname(os.path.dirname(jadx_path))}")

        reply = QMessageBox.question(self, "Add to PATH", 
                                     "Do you want to add the JADX bin directory to your system's PATH? This will allow you to run JADX from the command line.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            jadx_bin_path = os.path.dirname(jadx_path)
            if sys.platform == "win32":
                # Use setx to permanently add to user's PATH
                subprocess.run(['setx', 'PATH', f"%PATH%;{jadx_bin_path}"], shell=True)
                QMessageBox.information(self, "PATH Updated", "JADX has been added to your PATH. Please restart the application for the changes to take effect.")
            else:
                # For Linux/macOS, we would need to modify shell profiles, which is more complex and risky.
                # For now, just inform the user.
                QMessageBox.information(self, "PATH Information", f"Please add the following directory to your system's PATH: {jadx_bin_path}")

        reply = QMessageBox.question(self, "Restart Application",
                                     "The application needs to be restarted to apply the changes. Do you want to restart now?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            os.execl(sys.executable, sys.executable, *sys.argv)
        else:
            self.decompile_with_jadx()

    def jadx_install_error(self, error_message):
        self.progress_dialog.close()
        QMessageBox.critical(self, "JADX Installation Failed", error_message)
