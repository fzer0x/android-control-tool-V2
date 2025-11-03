import sys
import os
import subprocess
import re
import time
import threading
import shlex
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QTextBrowser,
    QComboBox, QCheckBox, QGroupBox, QScrollArea, QFileDialog,
    QMessageBox, QProgressBar, QListWidget, QTreeWidget, QInputDialog, QProgressDialog, QProgressDialog,
    QTreeWidgetItem, QSplitter, QFrame, QMenu, QSystemTrayIcon, QGridLayout, QSpinBox, QStyle, QStyledItemDelegate, QDockWidget,
    QFormLayout, QStatusBar, QDialog)
from PyQt6.QtGui import (QIcon, QFont, QPixmap, QColor, QPalette, QAction, QTextDocument,
                         QTextCursor, QStandardItemModel, QStandardItem)
from PyQt6.QtCore import (Qt, QSize, QTimer, QProcess, QSettings, QThread,
                          pyqtSignal, QObject, QByteArray, QDateTime, QStandardPaths)
from tools.androguard_tab import AndroguardTab
from functools import partial
import webbrowser
import json
import zipfile
import tempfile
import requests
import shutil
import xml.etree.ElementTree as ET
from packaging import version
import traceback
import requests
import shutil
import zipfile
import tempfile

import logging
# Constants
VERSION = "2.1.0"
APP_NAME = "Android Control Tool"
DEVELOPER = "fzer0x"
SUPPORTED_ANDROID_VERSIONS = ["4.0", "5.0", "6.0", "7.0", "8.0", "9.0", "10", "11", "12", "13", "14", "15", "16"]
DEFAULT_ADB_PATH = "adb" if sys.platform != "win32" else "adb.exe"
DEFAULT_FASTBOOT_PATH = "fastboot" if sys.platform != "win32" else "fastboot.exe"

# Global settings with thread-safe access
settings = QSettings("AndroidToolMaster", "UACT")
settings_lock = threading.Lock()

def setup_logging():
    """Set up centralized logging to a file."""
    log_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, "android_control_tool.log")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, mode='w', encoding='utf-8'),
            logging.StreamHandler() # Also log to console for debugging
        ]
    )
    logging.info("Application started.")
    return log_file

def global_exception_hook(exctype, value, tb):
    """Global exception handler to log unhandled exceptions."""
    error_msg = "".join(traceback.format_exception(exctype, value, tb))
    logging.critical(f"Unhandled exception caught:\n{error_msg}")
    QMessageBox.critical(None, "Critical Error", f"A critical error occurred. Please check the log file for details.\n\n{error_msg}")
    sys.exit(1)

class Worker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(Exception)
    progress_update = pyqtSignal(int, str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(self, *self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(e)

class CopyableMessageBox(QMessageBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        # Finde das interne QTextEdit, um es ebenfalls auswählbar zu machen
        # Dies ist ein kleiner Workaround, da Qt das nicht direkt unterstützt.
        for child in self.findChildren(QTextEdit):
            child.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

    @staticmethod
    def critical(parent, title, text):
        msg = CopyableMessageBox(parent)
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle(title)
        msg.setText(text)
        return msg.exec()

    @staticmethod
    def warning(parent, title, text):
        msg = CopyableMessageBox(parent)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle(title)
        msg.setText(text)
        return msg.exec()

    @staticmethod
    def information(parent, title, text):
        msg = CopyableMessageBox(parent)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle(title)
        msg.setText(text)
        return msg.exec()

class CommandWorker(QObject):
    command_output = pyqtSignal(str)
    command_finished = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, str)

    def __init__(self):
        super().__init__()
        self.process = None
        self.is_running = False
        self.timeout = 30  # Default timeout in seconds
        self._command_queue = []
        self._queue_lock = threading.Lock()
        self._current_process = None
        
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.process_command_queue)
        self.process_timer.start(50)  # Check queue every 50ms

    def run_command(self, command, cwd=None, timeout=None):
        if isinstance(command, str):
            command = shlex.split(command) if sys.platform != "win32" else command
        
        with self._queue_lock:
            self._command_queue.append((command, cwd, timeout))
            
    def process_command_queue(self):
        if self._current_process is not None and self._current_process.state() != QProcess.NotRunning:
            return  # Still processing previous command
            
        with self._queue_lock:
            if not self._command_queue:
                return  # No commands to process
            command, cwd, timeout = self._command_queue.pop(0)
        
        self.is_running = True
        actual_timeout = timeout if timeout is not None else self.timeout
        
        try:
            self._current_process = QProcess()
            if cwd:
                self._current_process.setWorkingDirectory(cwd)
            self._current_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
            
            self._current_process.readyRead.connect(self._handle_output)
            self._current_process.finished.connect(self._handle_finished)
            
            timer = QTimer()
            timer.setSingleShot(True)
            timer.timeout.connect(lambda: self._handle_timeout(command, actual_timeout))
            timer.start(actual_timeout * 1000)
            
            if isinstance(command, list):
                program = command[0]
                args = command[1:]
            else:
                program = command
                args = []
                
                self._current_process.start(program, args)
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}\n{traceback.format_exc()}"
            self.command_output.emit(error_msg)
            self.command_finished.emit(-1, error_msg)

    def _handle_output(self):
        """Handle process output in real-time"""
        if self._current_process:
            data = self._current_process.readAll().data().decode(errors='replace')
            if data:
                self.command_output.emit(data.strip())

    def _handle_finished(self, exit_code, exit_status):
        """Handle process completion"""
        if self._current_process:
            self._handle_output()
            
            error = ""
            if exit_code != 0:
                error = self._current_process.readAllStandardError().data().decode(errors='replace').strip()
            
            self._current_process.deleteLater()
            self._current_process = None
            self.is_running = False
            
            self.command_finished.emit(exit_code, error)

    def _handle_timeout(self, command, timeout):
        """Handle command timeout"""
        if self._current_process and self._current_process.state() != QProcess.NotRunning:
            error_msg = f"Command timed out after {timeout} seconds"
            self.command_output.emit(error_msg)
            self.command_finished.emit(-2, error_msg)
            self.cleanup_process()

    def cleanup_process(self):
        """Clean up the current process"""
        if self._current_process:
            if self._current_process.state() != QProcess.NotRunning:
                self._current_process.kill()
                self._current_process.waitForFinished(2000)
            self._current_process.deleteLater()
            self._current_process = None
            self.is_running = False

    def stop(self):
        """Stop all command processing and cleanup"""
        self.is_running = False
        self.cleanup_process()

class DeviceManager(QObject):
    devices_updated = pyqtSignal(list)
    device_details_updated = pyqtSignal(dict)
    connection_status_changed = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        with settings_lock:
            self.adb_path = settings.value("adb_path", DEFAULT_ADB_PATH)
            self.fastboot_path = settings.value("fastboot_path", DEFAULT_FASTBOOT_PATH)
        self.connected_devices = []
        self.current_device = None
        self.device_details = {}
        self.device_initialized = False
        self.last_device_check = 0
        self.last_details_check = 0
        self.device_check_interval = 60000  # Check devices every 60 seconds
        self.details_check_interval = 58000  # Update details every 58 seconds
        
        self.is_updating_devices = False
        self.worker_thread = QThread()
        self.worker_thread.start()
        
        self.command_worker = CommandWorker()
        self.command_worker.moveToThread(self.worker_thread)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_updates)
        self.timer.start(1000)  # Timer ticks every second but checks intervals
        
        self.lock = threading.Lock()
        self.update_queue = []  # Queue for pending updates

        self.start_adb_server()

    def start_adb_server(self):
        """Starts the ADB server to ensure it's running and can prompt for authorization."""
        try:
            logging.info("Attempting to start ADB server...")
            subprocess.run([self.adb_path, "start-server"], capture_output=True, text=True, timeout=10, check=False)
            logging.info("ADB 'start-server' command issued.")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logging.error(f"Failed to start ADB server: {e}")

    def check_updates(self):
        """Check if we need to update devices or details based on intervals"""
        current_time = QDateTime.currentMSecsSinceEpoch()
        
        if current_time - self.last_device_check >= self.device_check_interval:
            if not self.is_updating_devices:
                self.update_devices()
            
        if self.current_device and current_time - self.last_details_check >= self.details_check_interval:
            self.last_details_check = current_time
            QTimer.singleShot(0, self.update_device_details)

    def update_devices(self):
        """Starts the device update process in a background thread."""
        if self.is_updating_devices:
            return

        self.is_updating_devices = True
        self.last_device_check = QDateTime.currentMSecsSinceEpoch()
        
        self.thread = QThread()
        self.worker = Worker(self._get_devices_sync)
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_devices_updated)
        self.worker.error.connect(self._on_update_error)
        
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        
        self.thread.start()

    def _get_devices_sync(self, worker_instance=None):
        """Synchronous part of device update, runs in a worker thread. Accepts optional worker instance."""
        adb_devices = []
        try:
            adb_output = subprocess.check_output([self.adb_path, "devices"], text=True, timeout=2)
            for line in adb_output.splitlines()[1:]:
                if "\t" in line:
                    device_id, status = line.strip().split("\t")
                    if status == "device":
                        model_name = "Unknown"
                        try:
                            model_output = subprocess.check_output(
                                [self.adb_path, "-s", device_id, "shell", "getprop", "ro.product.model"],
                                text=True, timeout=2, encoding='utf-8', errors='replace'
                            ).strip()
                            if model_output:
                                model_name = model_output
                        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                            pass # Ignore if model name can't be fetched
                        adb_devices.append({"id": device_id, "type": "adb", "status": status, "model": model_name})
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass  # Ignore errors, e.g. if adb is not running

        fastboot_devices = []
        try:
            fastboot_output = subprocess.check_output([self.fastboot_path, "devices"], text=True, timeout=2)
            for line in fastboot_output.splitlines():
                if "\t" in line:
                    device_id, _ = line.strip().split("\t")
                    fastboot_devices.append({"id": device_id, "type": "fastboot", "status": "fastboot"})
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass  # Ignore errors

        return adb_devices + fastboot_devices

    def _on_devices_updated(self, new_devices):
        """Handles the result from the background device scan."""
        self.connected_devices = new_devices
        self.devices_updated.emit(self.connected_devices)

        if self.connected_devices:
            self.connection_status_changed.emit(True)
            if not self.device_initialized or self.current_device not in [d["id"] for d in self.connected_devices]:
                self.device_initialized = True
                self.set_current_device(self.connected_devices[0]["id"])
        else:
            self.connection_status_changed.emit(False)
            self.current_device = None
            self.device_details = {}
            self.device_details_updated.emit({})
        
        self.is_updating_devices = False

    def _on_update_error(self, e):
        logging.error(f"Error updating devices: {e}\n{traceback.format_exc()}")
        self.is_updating_devices = False


    def set_current_device(self, device_id):
        with self.lock:
            self.current_device = device_id
            self.update_device_details()

    def update_device_details(self):
        """Update device details in background"""
        if not self.current_device:
             return
 
        details = {}
        device_type = next((d["type"] for d in self.connected_devices if d["id"] == self.current_device), None)

        if device_type == "adb":
            try:
                details["serial"] = self.current_device
                details["type"] = "adb"

                # Get all properties at once for efficiency.
                prop_output = subprocess.check_output(
                    [self.adb_path, "-s", self.current_device, "shell", "getprop"],
                    text=True, timeout=5, encoding='utf-8', errors='replace'
                ).strip()

                prop_dict = {}
                for line in prop_output.splitlines():
                    match = re.match(r'\[([^\]]+)\]: \[([^\]]*)\]', line)
                    if match:
                        key, value = match.groups()
                        prop_dict[key] = value

                details["model"] = prop_dict.get("ro.product.model", "Unbekannt")
                details["brand"] = prop_dict.get("ro.product.brand", "Unbekannt")
                details["android_version"] = prop_dict.get("ro.build.version.release", "Unbekannt")
                details["build_number"] = prop_dict.get("ro.build.display.id", "Unbekannt")
                details["build_id"] = prop_dict.get("ro.build.display.id", "Unknown") # Alias for build_number

                # Get root status using multiple methods for reliability.
                root_methods = [
                    ["su", "-c", "echo Root check"],
                    ["which", "su"],
                ]
                details["root"] = False
                for method_args in root_methods:
                    result = subprocess.run(
                        [self.adb_path, "-s", self.current_device, "shell"] + method_args,
                        capture_output=True, text=True, timeout=2, encoding='utf-8', errors='replace'
                    )
                    if result.returncode == 0:
                        details["root"] = True
                        break

                result = subprocess.run(
                    [self.adb_path, "-s", self.current_device, "get-state"],
                    capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
                )
                details["state"] = result.stdout.strip() or "unknown"

                result = subprocess.run(
                    [self.adb_path, "-s", self.current_device, "shell", "dumpsys", "battery"],
                    capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
                )
                battery_info = result.stdout.strip()
                details["battery_level"] = "Unbekannt"
                match = re.search(r"level:\s*(\d+)", battery_info)
                if match:
                    details["battery_level"] = f"{match.group(1)}%"

                result = subprocess.run(
                    [self.adb_path, "-s", self.current_device, "shell", "df", "/data"],
                    capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
                )
                storage_info = result.stdout.strip()
                if len(storage_info.splitlines()) > 1:
                    parts = storage_info.splitlines()[1].split()
                    if len(parts) >= 4:
                        try:
                            # df usually outputs in 1K-blocks. Convert to GB.
                            total_kb = int(parts[1])
                            used_kb = int(parts[2])
                            details["storage_total_gb"] = f"{total_kb / (1024*1024):.2f}"
                            details["storage_used_gb"] = f"{used_kb / (1024*1024):.2f}"
                            details["storage_percent"] = parts[4] if len(parts) >= 5 else f"{int(used_kb/total_kb*100)}%"
                        except (ValueError, IndexError, ZeroDivisionError):
                            pass  # Ignore parsing errors

            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.warning(f"Error getting device details for {self.current_device}: {e}")

        elif device_type == "fastboot":
            try:
                details["serial"] = self.current_device
                details["type"] = "fastboot"
                
                result = subprocess.run(
                    [self.fastboot_path, "-s", self.current_device, "getvar", "all"],
                    capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
                )
                # Fastboot getvar all sends output to stderr
                output = result.stderr.strip()
                for line in output.splitlines():
                    if ":" in line:
                        key_val_part = line.split(":", 1)
                        key = key_val_part[0].replace("(bootloader)", "").strip()
                        value = key_val_part[1].strip()
                        details[key] = value
                
                details["unlocked"] = details.get("unlocked", "no").lower() == "yes"

            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.warning(f"Error getting fastboot details for {self.current_device}: {e}")

        self.device_details = details
        self.device_details_updated.emit(details)

    def execute_adb_command(self, command, device_specific=True, timeout=30):
        if not self.current_device:
            return None, "No device selected #001"
        
        full_command = [self.adb_path]
        if device_specific:
            full_command.extend(["-s", self.current_device])
        
        if isinstance(command, str):
            full_command.extend(shlex.split(command))
        else:
            full_command.extend(command)
        
        try:
            result = subprocess.run(full_command, 
                                   capture_output=True, 
                                   text=True,
                                   encoding='utf-8', errors='replace',
                                   timeout=timeout)
            output = (result.stdout or "").strip() + "\n" + (result.stderr or "").strip()
            return result.returncode, output.strip()
        except subprocess.TimeoutExpired:
            return -1, "Command timed out"
        except Exception as e:
            return -1, f"Error executing ADB command: {str(e)}"

    def execute_fastboot_command(self, command, device_specific=True, timeout=30):
        if not self.current_device:
            return None, "No device selected #002"
        
        full_command = [self.fastboot_path]
        if device_specific:
            full_command.extend(["-s", self.current_device])
        
        if isinstance(command, str):
            full_command.extend(shlex.split(command))
        else:
            full_command.extend(command)
        
        try:
            result = subprocess.run(full_command, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=timeout,
                                  encoding='utf-8', errors='replace')
            return result.returncode, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return -1, "Command timed out"
        except Exception as e:
            return -1, f"Error executing Fastboot command: {str(e)}"

    def reboot_device(self, mode="system"):
        if not self.current_device:
            return False, "No device selected #003"
        
        device_type = next((d["type"] for d in self.connected_devices if d["id"] == self.current_device), None)
        
        if device_type == "adb":
            valid_modes = ["recovery", "bootloader", "sideload", "download"]
            cmd_list = ["reboot"]
            if mode.lower() in valid_modes:
                cmd_list.append(mode.lower())
            
            return_code, output = self.execute_adb_command(cmd_list)
            return return_code == 0, output
        elif device_type == "fastboot":
            valid_modes = ["recovery", "bootloader", "system"]
            cmd_list = ["reboot"]
            if mode.lower() in valid_modes:
                cmd_list = [f"reboot-{mode.lower()}"]
            
            return_code, output = self.execute_fastboot_command(cmd_list)
            return return_code == 0, output
        else:
            return False, "Unknown device type"

    def wait_for_disconnect(self, device_id, timeout=30):
        """Waits for a specific device to disconnect from ADB."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, timeout=5)
                if device_id not in result.stdout:
                    logging.info(f"Device {device_id} successfully disconnected.")
                    return True
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                # ADB server might be down during reboot, which is expected.
                pass
            time.sleep(1)
        logging.warning(f"Timeout waiting for device {device_id} to disconnect.")
        return False

    def wait_for_connect(self, timeout=60):
        """Waits for any device to connect via ADB."""
        start_time = time.time()
        logging.info("Waiting for a device to connect...")
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, timeout=5)
                lines = result.stdout.strip().splitlines()
                # Check if there is at least one device listed that is not offline
                for line in lines[1:]:
                    if "\t" in line and "offline" not in line:
                        device_id = line.split('\t')[0]
                        logging.info(f"Device {device_id} connected.")
                        return True
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass
            time.sleep(2)
        logging.warning("Timeout waiting for a device to connect.")
        return False

class FileManager(QObject):
    file_transfer_progress = pyqtSignal(int, str)
    file_operation_complete = pyqtSignal(bool, str)
    file_operation_started = pyqtSignal(str)
    
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()
        self.active_transfers = {}
    
    def push_file(self, local_path, remote_path):
        if not self.device_manager.current_device and not getattr(self.device_manager, "suppress_no_device_warning", False):
            QMessageBox.warning(None, "Error", "No device selected #004")
            return
        
        local_path = os.path.normpath(local_path)
        if not os.path.exists(local_path):
            self.file_operation_complete.emit(False, f"Local file does not exist: {local_path}")
            return
        
        transfer_id = f"push_{time.time()}"
        self.active_transfers[transfer_id] = {
            "type": "push",
            "local_path": local_path,
            "remote_path": remote_path,
            "cancelled": False
        }
        
        def run_push():
            try:
                self.file_operation_started.emit(f"Pushing {local_path} to {remote_path}")
                
                total_size = os.path.getsize(local_path)
                if total_size == 0:
                    total_size = 1  # Avoid division by zero
                
                remote_dir = os.path.dirname(remote_path.replace("\\", "/"))
                if remote_dir:
                    self.device_manager.execute_adb_command(["shell", "mkdir", "-p", remote_dir])
                
                command = [
                    self.device_manager.adb_path,
                    "-s", self.device_manager.current_device,
                    "push", local_path, remote_path
                ]
                
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                transferred = 0
                last_progress = 0
                start_time = time.time()
                
                while True:
                    if self.active_transfers.get(transfer_id, {}).get("cancelled", False):
                        process.terminate()
                        self.file_operation_complete.emit(False, "Transfer cancelled by user")
                        break
                    
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    
                    if output:
                        match = re.search(r'(\d+)%', output)
                        if match:
                            progress = int(match.group(1))
                            if progress != last_progress:
                                self.file_transfer_progress.emit(progress, f"Uploading: {progress}%")
                                last_progress = progress
                        else:
                            elapsed = time.time() - start_time
                            if elapsed > 0:
                                transferred = min(total_size, transferred + 1024)  # Simulate progress for commands that don't report it.
                                progress = min(99, int((transferred / total_size) * 100))
                                self.file_transfer_progress.emit(
                                    progress, 
                                    f"Uploading: {progress}%"
                                )
                
                return_code = process.poll()
                stderr_output = process.stderr.read()
                
                if return_code == 0:
                    self.file_operation_complete.emit(True, f"File transfer completed: {local_path} -> {remote_path}")
                else:
                    error_msg = f"File transfer failed: {stderr_output.strip()}" if stderr_output else "File transfer failed"
                    self.file_operation_complete.emit(False, error_msg)
            except Exception as e:
                error_msg = f"Error during file push: {str(e)}\n{traceback.format_exc()}"
                self.file_operation_complete.emit(False, error_msg)
            finally:
                self.active_transfers.pop(transfer_id, None)
        
        thread = threading.Thread(target=run_push, daemon=True)
        thread.start()
        return transfer_id
    
    def pull_file(self, remote_path, local_path):
        if not self.device_manager.current_device:
            self.file_operation_complete.emit(False, "No device selected #005")
            return
        
        local_path = os.path.normpath(local_path)
        if os.path.exists(local_path):
            self.file_operation_complete.emit(False, f"File already exists: {local_path}")
            return
        
        transfer_id = f"pull_{time.time()}"
        self.active_transfers[transfer_id] = {
            "type": "pull",
            "local_path": local_path,
            "remote_path": remote_path,
            "cancelled": False
        }
        
        def run_pull():
            try:
                self.file_operation_started.emit(f"Pulling {remote_path} to {local_path}")
                
                cleaned_path = remote_path.replace('\\', '/')
                size_cmd = ["shell", "stat", "-c", "%s", cleaned_path]

                return_code, size_output = self.device_manager.execute_adb_command(size_cmd)
                
                if return_code != 0:
                    self.file_operation_complete.emit(False, f"Failed to get remote file size: {size_output}")
                    return
                
                try:
                    total_size = int(size_output.strip())
                except ValueError:
                    total_size = 0
                
                if total_size == 0:
                    total_size = 1  # Avoid division by zero
                
                command = [
                    self.device_manager.adb_path,
                    "-s", self.device_manager.current_device,
                    "pull", remote_path, local_path
                ]
                
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                start_time = time.time()
                last_update = start_time
                last_size = 0
                
                while True:
                    if self.active_transfers.get(transfer_id, {}).get("cancelled", False):
                        process.terminate()
                        self.file_operation_complete.emit(False, "Transfer cancelled by user")
                        break
                    
                    if not os.path.exists(local_path):
                        time.sleep(0.1)
                        continue
                    
                    current_size = os.path.getsize(local_path)
                    now = time.time()
                    
                    if now - last_update > 0.5:
                        progress = min(99, int((current_size / total_size) * 100))
                        
                        transferred = current_size - last_size
                        elapsed = now - last_update
                        speed = transferred / elapsed if elapsed > 0 else 0
                        
                        remaining = (total_size - current_size) / speed if speed > 0 else 0
                        
                        self.file_transfer_progress.emit(
                            progress, 
                            f"Downloading: {progress}% ({(speed/1024):.1f} KB/s, {remaining:.1f}s remaining)"
                        )
                        
                        last_update = now
                        last_size = current_size
                    
                    if process.poll() is not None:
                        break
                    
                    time.sleep(0.1)
                
                return_code = process.poll()
                stderr_output = process.stderr.read()
                
                if return_code == 0:
                    if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                        self.file_operation_complete.emit(True, f"File transfer completed: {remote_path} -> {local_path}")
                    else:
                        self.file_operation_complete.emit(False, "File transfer failed: empty or missing file")
                else:
                    error_msg = f"File transfer failed: {stderr_output.strip()}" if stderr_output else "File transfer failed"
                    self.file_operation_complete.emit(False, error_msg)
                    
                    if os.path.exists(local_path):
                        try:
                            os.remove(local_path)
                        except:
                            pass
            except Exception as e:
                error_msg = f"Error during file pull: {str(e)}\n{traceback.format_exc()}"
                self.file_operation_complete.emit(False, error_msg)
                
                if os.path.exists(local_path):
                    try:
                        os.remove(local_path)
                    except:
                        pass
            finally:
                self.active_transfers.pop(transfer_id, None)
        
        thread = threading.Thread(target=run_pull, daemon=True)
        thread.start()
        return transfer_id
    
    def cancel_transfer(self, transfer_id):
        if transfer_id in self.active_transfers:
            self.active_transfers[transfer_id]["cancelled"] = True

class PackageManager(QObject):
    package_operation_complete = pyqtSignal(bool, str)
    package_list_updated = pyqtSignal(list)
    package_info_updated = pyqtSignal(dict)
    
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()
    
    def get_installed_packages(self, system_only=False, third_party_only=False, enabled_only=False, disabled_only=False):
        if not self.device_manager.current_device:
            self.package_operation_complete.emit(False, "No device selected #006")
            return False, "No device selected #006"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "pm", "list", "packages"]
            
            if system_only:
                command.append("-s")
            elif third_party_only:
                command.append("-3")
            
            if enabled_only:
                command.extend(["-e"])
            elif disabled_only:
                command.extend(["-d"])
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            packages = []
            
            for line in result.stdout.splitlines():
                if line.startswith("package:"):
                    package_name = line[8:].strip()
                    if package_name:
                        packages.append(package_name)
            
            self.package_list_updated.emit(packages)
            return True, "Package list retrieved"
        except subprocess.TimeoutExpired:
            error_msg = "Timeout while getting package list"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error getting package list: {str(e)}"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
    
    def get_package_info(self, package_name):
        if not self.device_manager.current_device:
            return False, "No device selected #007"
        
        if not package_name or not isinstance(package_name, str):
            return False, "Invalid package name"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "dumpsys", "package", package_name]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            output = result.stdout
            
            info = {
                "name": package_name,
                "version": "Unknown",
                "uid": "Unknown",
                "path": "Unknown",
                "enabled": True,
                "target_sdk": "Unknown",
                "min_sdk": "Unknown",
                "installer": "Unknown",
                "data_dir": "Unknown",
                "signature": "Unknown",
                "cpu_abi": "Unknown",
                "permissions": []
            }
            
            version_match = re.search(r"versionName=([^\s]+)", output)
            if version_match:
                info["version"] = version_match.group(1).strip('"\'')
            
            target_sdk_match = re.search(r"targetSdk=(\d+)", output)
            if target_sdk_match:
                info["target_sdk"] = target_sdk_match.group(1)

            min_sdk_match = re.search(r"minSdk=(\d+)", output)
            if min_sdk_match:
                info["min_sdk"] = min_sdk_match.group(1)

            installer_match = re.search(r"installerPackageName=([^\s]+)", output)
            if installer_match:
                info["installer"] = installer_match.group(1)

            data_dir_match = re.search(r"dataDir=([^\s]+)", output)
            if data_dir_match:
                info["data_dir"] = data_dir_match.group(1)

            uid_match = re.search(r"userId=(\d+)", output)
            if uid_match:
                info["uid"] = uid_match.group(1)
            
            path_match = re.search(r"codePath=([^\s]+)", output)
            if path_match:
                info["path"] = path_match.group(1).strip('"\'')
            
            enabled_match = re.search(r"enabled=(\d+)", output)
            if enabled_match:
                info["enabled"] = enabled_match.group(1) == "1"
            
            cpu_abi_match = re.search(r"primaryCpuAbi=([^\s]+)", output)
            if cpu_abi_match:
                info["cpu_abi"] = cpu_abi_match.group(1)

            # Signature parsing
            signatures_block_match = re.search(r"signatures:\[(.*?)\]", output, re.DOTALL)
            if signatures_block_match:
                sig_hash_match = re.search(r'([a-fA-F0-9]{8,})', signatures_block_match.group(1))
                if sig_hash_match:
                    info["signature"] = sig_hash_match.group(1)

            permissions_section = re.search(r"requested permissions:(.*?)install permissions:", output, re.DOTALL)
            if not permissions_section:
                permissions_section = re.search(r"requested permissions:(.*)", output, re.DOTALL)
            
            if permissions_section:
                permissions = re.findall(r"(\w+): granted=(\w+)", permissions_section.group(1))
                info["permissions"] = [f"{p[0]} ({'granted' if p[1] == 'true' else 'denied'})" for p in permissions]
            
            install_time_match = re.search(r"firstInstallTime=(\d+)", output)
            if install_time_match:
                try:
                    timestamp = int(install_time_match.group(1))
                    info["install_time"] = datetime.fromtimestamp(timestamp/1000).strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass
            
            update_time_match = re.search(r"lastUpdateTime=(\d+)", output)
            if update_time_match:
                try:
                    timestamp = int(update_time_match.group(1))
                    info["update_time"] = datetime.fromtimestamp(timestamp/1000).strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass
            
            size_match = re.search(r"codeSize=(\d+)", output)
            if size_match:
                try:
                    size_bytes = int(size_match.group(1))
                    info["size"] = self._format_size(size_bytes)
                except:
                    pass
            
            self.package_info_updated.emit(info)
            return True, info
        except subprocess.TimeoutExpired:
            return False, "Timeout while getting package info"
        except Exception as e:
            return False, f"Error getting package info: {str(e)}"
    
    def _format_size(self, size_bytes):
        """Format size in bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def install_package(self, apk_path, replace_existing=False, grant_all_permissions=False, test_only=False):
        if not self.device_manager.current_device:
            self.package_operation_complete.emit(False, "No device selected #008")
            return False, "No device selected #008"
        
        apk_path = os.path.normpath(apk_path)
        if not os.path.exists(apk_path):
            self.package_operation_complete.emit(False, "APK file does not exist")
            return False, "APK file does not exist"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "install"]
            
            if replace_existing:
                command.append("-r")
            
            if grant_all_permissions:
                command.append("-g")
            
            if test_only:
                command.append("-t")
            
            command.append(apk_path)
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            success = "Success" in result.stdout or "success" in result.stdout.lower()
            message = result.stdout.strip() or result.stderr.strip()
            
            self.package_operation_complete.emit(success, message)
            return success, message
        except subprocess.TimeoutExpired:
            error_msg = "Package installation timed out"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error installing package: {str(e)}"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
    
    def uninstall_package(self, package_name, keep_data=False):
        if not self.device_manager.current_device:
            self.package_operation_complete.emit(False, "No device selected #009")
            return False, "No device selected #009"
        
        if not package_name or not isinstance(package_name, str):
            self.package_operation_complete.emit(False, "Invalid package name")
            return False, "Invalid package name"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "uninstall"]
            
            if keep_data:
                command.append("-k")
            
            command.append(package_name)
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            success = "Success" in result.stdout or "success" in result.stdout.lower()
            message = result.stdout.strip() or result.stderr.strip()
            
            self.package_operation_complete.emit(success, message)
            return success, message
        except subprocess.TimeoutExpired:
            error_msg = "Package uninstallation timed out"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error uninstalling package: {str(e)}"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
    
    def clear_package_data(self, package_name):
        if not self.device_manager.current_device:
            self.package_operation_complete.emit(False, "No device selected #010")
            return False, "No device selected #010"
        
        if not package_name or not isinstance(package_name, str):
            self.package_operation_complete.emit(False, "Invalid package name")
            return False, "Invalid package name"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "pm", "clear", package_name]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            success = "Success" in result.stdout or "success" in result.stdout.lower()
            message = result.stdout.strip() or result.stderr.strip()
            
            self.package_operation_complete.emit(success, message)
            return success, message
        except subprocess.TimeoutExpired:
            error_msg = "Clear package data timed out"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error clearing package data: {str(e)}"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
    
    def enable_package(self, package_name):
        if not self.device_manager.current_device:
            self.package_operation_complete.emit(False, "No device selected #011")
            return False, "No device selected #011"
        
        if not package_name or not isinstance(package_name, str):
            self.package_operation_complete.emit(False, "Invalid package name")
            return False, "Invalid package name"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "pm", "enable", "--user", "0", package_name]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            success = result.returncode == 0
            message = result.stdout.strip() or result.stderr.strip() or ("Package enabled" if success else "Failed to enable package")
            
            self.package_operation_complete.emit(success, message)
            return success, message
        except subprocess.TimeoutExpired:
            error_msg = "Enable package timed out"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error enabling package: {str(e)}"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
    
    def disable_package(self, package_name):
        if not self.device_manager.current_device:
            self.package_operation_complete.emit(False, "No device selected #012")
            return False, "No device selected #012"
        
        if not package_name or not isinstance(package_name, str):
            self.package_operation_complete.emit(False, "Invalid package name")
            return False, "Invalid package name"
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "pm", "disable-user", "--user", "0", package_name]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            success = result.returncode == 0
            message = result.stdout.strip() or result.stderr.strip() or ("Package disabled" if success else "Failed to disable package")
            
            self.package_operation_complete.emit(success, message)
            return success, message
        except subprocess.TimeoutExpired:
            error_msg = "Disable package timed out"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error disabling package: {str(e)}"
            self.package_operation_complete.emit(False, error_msg)
            return False, error_msg

class BackupManager(QObject):
    backup_progress = pyqtSignal(int, str)
    backup_complete = pyqtSignal(bool, str)
    backup_started = pyqtSignal(str)
    
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()
    
    def create_backup(self, backup_path, include_apks=False, include_shared=False, include_system=False, all_apps=False, packages=None):
        if not self.device_manager.current_device:
            self.backup_complete.emit(False, "No device selected #013")
            return
        
        if not packages and not all_apps:
            self.backup_complete.emit(False, "No packages selected and 'all apps' not checked")
            return
        
        backup_path = os.path.normpath(backup_path)
        
        def run_backup():
            try:
                self.backup_started.emit("Starting backup...")
                
                command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "backup"]
                
                if include_apks:
                    command.append("-apk")
                
                if include_shared:
                    command.append("-shared")
                
                if include_system:
                    command.append("-system")
                
                if all_apps:
                    command.append("-all")
                elif packages:
                    command.append("-f")
                    command.append(backup_path)
                    command.extend(packages)
                
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    universal_newlines=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    
                    if output:
                        if "%" in output:
                            match = re.search(r'(\d+)%', output)
                            if match:
                                progress = int(match.group(1))
                                self.backup_progress.emit(progress, f"Backup progress: {progress}%")
                
                return_code = process.poll()
                stderr_output = process.stderr.read()
                
                if return_code == 0:
                    if os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
                        self.backup_complete.emit(True, "Backup completed successfully")
                    else:
                        self.backup_complete.emit(False, "Backup failed: empty or missing backup file")
                else:
                    error_msg = f"Backup failed: {stderr_output.strip()}" if stderr_output else "Backup failed"
                    self.backup_complete.emit(False, error_msg)
                    
                    if os.path.exists(backup_path):
                        try:
                            os.remove(backup_path)
                        except:
                            pass
            except Exception as e:
                error_msg = f"Error during backup: {str(e)}\n{traceback.format_exc()}"
                self.backup_complete.emit(False, error_msg)
                
                if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                    except:
                        pass
        
        thread = threading.Thread(target=run_backup, daemon=True)
        thread.start()
    
    def restore_backup(self, backup_path):
        if not self.device_manager.current_device:
            self.backup_complete.emit(False, "No device selected #014")
            return
        
        backup_path = os.path.normpath(backup_path)
        if not os.path.exists(backup_path):
            self.backup_complete.emit(False, "Backup file does not exist")
            return
        
        def run_restore():
            try:
                self.backup_started.emit("Starting restore...")
                
                command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "restore", backup_path]
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    universal_newlines=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    
                    if output:
                        if "%" in output:
                            match = re.search(r'(\d+)%', output)
                            if match:
                                progress = int(match.group(1))
                                self.backup_progress.emit(progress, f"Restore progress: {progress}%")
                
                return_code = process.poll()
                stderr_output = process.stderr.read()
                
                if return_code == 0:
                    self.backup_complete.emit(True, "Restore completed successfully")
                else:
                    error_msg = f"Restore failed: {stderr_output.strip()}" if stderr_output else "Restore failed"
                    self.backup_complete.emit(False, error_msg)
            except Exception as e:
                error_msg = f"Error during restore: {str(e)}\n{traceback.format_exc()}"
                self.backup_complete.emit(False, error_msg)
        
        thread = threading.Thread(target=run_restore, daemon=True)
        thread.start()

class LogcatManager(QObject):
    log_received = pyqtSignal(str)
    log_cleared = pyqtSignal(bool)
    log_started = pyqtSignal()
    log_stopped = pyqtSignal()
    
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.process = None
        self.is_running = False
        self.lock = threading.Lock()
        self.first_check_done = False
    
    def start_logcat(self, filters=None, clear_first=True):
        # If no current device, silently return False; UI should display a single warning
        if not self.device_manager.current_device:
            # mark that we've checked at least once
            self.first_check_done = True
            return False
        self.first_check_done = True
        
        if self.is_running:
            self.log_received.emit("Error: Logcat already running")
            return
        
        if clear_first:
            self.clear_logcat()
        
        def run_logcat():
            try:
                # Emit start signal before acquiring lock
                self.log_started.emit()
                
                with self.lock:
                    self.is_running = True
                    command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "logcat"]
                    
                    if filters:
                        command.extend(filters.split())
                    
                    self.process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        encoding='utf-8',
                        errors='replace'
                    )
                
                while True:
                    if not self.is_running:
                        break
                        
                    output = self.process.stdout.readline()
                    if output == '' and self.process.poll() is not None:
                        break
                    
                    if output:
                        self.log_received.emit(output.strip())
                
            except Exception as e:
                error_msg = f"Error in logcat: {str(e)}\n{traceback.format_exc()}"
                self.log_received.emit(error_msg)
            finally:
                with self.lock:
                    if self.is_running:  # Only reset if not already stopped
                        self.is_running = False
                        self.process = None
                self.log_stopped.emit()
        
        thread = threading.Thread(target=run_logcat, daemon=True)
        thread.start()
        return True
    
    def stop_logcat(self):
        with self.lock:
            if not self.is_running:
                return
                
            self.is_running = False
            if self.process:
                try:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=1)
                except Exception as e:
                    logging.error(f"Error stopping logcat: {str(e)}")
                finally:
                    self.process = None
        
        # Emit the signal outside the lock to avoid potential deadlocks
        self.log_stopped.emit()
    
    def clear_logcat(self):
        if not self.device_manager.current_device:
            self.log_cleared.emit(False)
            return
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "logcat", "-c"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            success = result.returncode == 0
            self.log_cleared.emit(success)
            return success
        except subprocess.TimeoutExpired:
            self.log_cleared.emit(False)
            return False
        except Exception as e:
            self.log_cleared.emit(False)
            return False
    
    def save_logcat(self, file_path, filters=None):
        if not self.device_manager.current_device:
            return False, "No device selected #015"
        
        file_path = os.path.normpath(file_path)
        
        try:
            command = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "logcat", "-d"]
            
            if filters:
                command.extend(filters.split())
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return False, result.stderr.strip()
            
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                return True, "Logcat saved successfully"
            except Exception as e:
                return False, f"Error saving file: {str(e)}"
        except subprocess.TimeoutExpired:
            return False, "Logcat save timed out"
        except Exception as e:
            return False, f"Error saving logcat: {str(e)}"

class DeviceControlTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.init_ui()
        
        self.device_manager.device_details_updated.connect(self.update_device_info)
        self.device_manager.connection_status_changed.connect(self.update_connection_status)
    
    def send_text_to_device(self):
        """Send text to device's current focused input field."""
        text = self.text_input.text()
        if not text:
            return
            
        # Use ADB input text command to send text.
        # No, we pass it as an argument to avoid shell injection
        cmd_list = ["shell", "input", "text", text]
        
        return_code, _ = self.device_manager.execute_adb_command(cmd_list)
        if return_code == 0:
            self.text_input.clear()
            CopyableMessageBox.information(self, "Success", "Text sent to device")
        else:
            CopyableMessageBox.warning(self, "Error", "Failed to send text to device")
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Device Info Group
        device_info_group = QGroupBox("Device Information")
        device_info_layout = QFormLayout()
        
        self.device_model_label = QLabel("Unbekannt")
        self.device_brand_label = QLabel("Unbekannt")
        self.android_version_label = QLabel("Unbekannt")
        self.build_number_label = QLabel("Unbekannt")
        self.root_status_label = QLabel("Unbekannt")
        self.battery_level_label = QLabel("Unbekannt")
        self.storage_info_label = QLabel("Unbekannt")
        self.storage_progress_bar = QProgressBar()
        self.storage_progress_bar.setTextVisible(False)
        self.storage_progress_bar.setMaximumHeight(10)
        
        device_info_layout.addRow("Modell:", self.device_model_label)
        device_info_layout.addRow("Marke:", self.device_brand_label)
        device_info_layout.addRow("Android Version:", self.android_version_label)
        device_info_layout.addRow("Build Number:", self.build_number_label)
        device_info_layout.addRow("Root Status:", self.root_status_label)
        device_info_layout.addRow("Battery Level:", self.battery_level_label)
        device_info_layout.addRow("Storage Info:", self.storage_info_label)
        device_info_layout.addRow("", self.storage_progress_bar)
        
        device_info_group.setLayout(device_info_layout)
        
        # Reboot Control Group
        reboot_group = QGroupBox("Device Control")
        reboot_layout = QHBoxLayout()
        
        self.reboot_system_btn = QPushButton("Reboot System")
        self.reboot_recovery_btn = QPushButton("Reboot Recovery")
        self.reboot_bootloader_btn = QPushButton("Reboot Bootloader")
        self.reboot_sideload_btn = QPushButton("Reboot Sideload")
        self.reboot_download_btn = QPushButton("Reboot Download")
        
        self.reboot_system_btn.clicked.connect(lambda: self.execute_reboot("system"))
        self.reboot_recovery_btn.clicked.connect(lambda: self.execute_reboot("recovery"))
        self.reboot_bootloader_btn.clicked.connect(lambda: self.execute_reboot("bootloader"))
        self.reboot_sideload_btn.clicked.connect(lambda: self.execute_reboot("sideload"))
        self.reboot_download_btn.clicked.connect(lambda: self.execute_reboot("download"))
        
        # --- Tooltips ---
        reboot_layout.addWidget(self.reboot_system_btn)
        reboot_layout.addWidget(self.reboot_recovery_btn)
        reboot_layout.addWidget(self.reboot_bootloader_btn)
        reboot_layout.addWidget(self.reboot_sideload_btn)
        reboot_layout.addWidget(self.reboot_download_btn)
        
        reboot_group.setLayout(reboot_layout)
        
        # Screen Recording Group
        screen_group = QGroupBox("Screen Recording")
        screen_layout = QVBoxLayout()
        
        recording_controls = QHBoxLayout()
        
        self.record_btn = QPushButton("🔴 Start Recording")
        self.record_btn.clicked.connect(self.toggle_screen_recording)
        
        self.recording_options_btn = QPushButton("⚙️ Recording Options")
        self.recording_options_btn.clicked.connect(self.show_recording_options)
        
        recording_controls.addWidget(self.record_btn)
        recording_controls.addWidget(self.recording_options_btn)
        
        self.recording_status = QLabel("Not recording")
        font = self.recording_status.font()
        font.setPointSize(10)
        self.recording_status.setFont(font)
        
        screen_layout.addLayout(recording_controls)
        screen_layout.addWidget(self.recording_status)
        
        screen_group.setLayout(screen_layout)
        
        # Store recording settings
        self.recording_settings = {
            'resolution': '720p',  # 720p, 1080p, native
            'bitrate': '4M',      # 2M, 4M, 8M
            'time_limit': 180,    # seconds, max 180
            'with_audio': False
        }
        self.is_recording = False
        self.recording_process = None
        self.is_finishing = False
        self.recording_pid = None
        self.finish_timer = None
        
        power_group = QGroupBox("Power Options")
        power_layout = QHBoxLayout()
        
        self.power_off_btn = QPushButton("🔌 Power Off")
        self.screen_on_btn = QPushButton("💡 Turn Screen On")
        self.screen_off_btn = QPushButton("🌑 Turn Screen Off")
        
        self.power_off_btn.clicked.connect(self.power_off_device)
        self.screen_on_btn.clicked.connect(self.turn_screen_on)
        self.screen_off_btn.clicked.connect(self.turn_screen_off)
        
        # --- Tooltips ---
        self.power_off_btn.setToolTip("Shuts down the device completely (requires adb).")
        self.screen_on_btn.setToolTip("Wakes the device and turns the screen on.")
        self.screen_off_btn.setToolTip("Turns the screen off (device stays on).")

        power_layout.addWidget(self.power_off_btn)
        power_layout.addWidget(self.screen_on_btn)
        power_layout.addWidget(self.screen_off_btn)
        
        power_group.setLayout(power_layout)
        
        input_group = QGroupBox("Input Keyboard")
        input_layout = QVBoxLayout()
        
        # Text Input
        text_input_layout = QFormLayout()
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText("Type text to send to device...")
        self.send_text_btn = QPushButton("Send Text")
        self.send_text_btn.clicked.connect(self.send_text_to_device)
        text_input_layout.addRow(self.text_input, self.send_text_btn)
        
        clipboard_layout = QHBoxLayout()
        self.get_clipboard_btn = QPushButton("Get from Device")
        self.set_clipboard_btn = QPushButton("Set from PC")
        clipboard_layout.addWidget(self.get_clipboard_btn)
        clipboard_layout.addWidget(self.set_clipboard_btn)
        
        self.get_clipboard_btn.clicked.connect(self.get_device_clipboard)
        self.set_clipboard_btn.clicked.connect(self.set_device_clipboard)
        
        # --- Tooltips ---
        self.text_input.setToolTip("Enter text here and click 'Send' to type it on the device.")
        self.send_text_btn.setToolTip("Sends the text from the input field to the device.")
        self.get_clipboard_btn.setToolTip("Copies the clipboard content from the device to your PC's clipboard.")
        self.set_clipboard_btn.setToolTip("Pastes your PC's clipboard content into the device's clipboard.")

        clipboard_group = QGroupBox("Clipboard [beta]")
        clipboard_group.setLayout(clipboard_layout)

        input_layout.addLayout(text_input_layout)
        input_layout.addWidget(clipboard_group)
        input_group.setLayout(input_layout)

        advanced_group = QGroupBox("Advanced Controls")
        advanced_layout = QVBoxLayout()
        
        root_layout = QHBoxLayout()
        self.root_check_btn = QPushButton("Check Root Access")
        self.root_grant_btn = QPushButton("Enable ADB Root")
        
        self.root_check_btn.clicked.connect(self.check_root_access)
        self.root_grant_btn.clicked.connect(self.grant_root_access)

        # --- Tooltips ---
        self.root_check_btn.setToolTip("Checks if the device has root (su) access.")
        self.root_grant_btn.setToolTip("Restarts adbd with root permissions (temporary). Requires unlocked bootloader and/or root.")

        root_layout.addWidget(self.root_check_btn)
        root_layout.addWidget(self.root_grant_btn)
        
        wifi_layout = QHBoxLayout()
        self.wifi_enable_btn = QPushButton("Enable ADB over Wi-Fi")
        self.wifi_disable_btn = QPushButton("Disable ADB over Wi-Fi")
        self.wifi_connect_btn = QPushButton("Connect via WiFi")
        
        self.wifi_enable_btn.clicked.connect(self.enable_adb_over_wifi)
        self.wifi_disable_btn.clicked.connect(self.disable_adb_over_wifi)
        self.wifi_connect_btn.clicked.connect(self.connect_via_wifi)
        
        # --- Tooltips ---
        self.wifi_enable_btn.setToolTip("Enables ADB over TCP/IP on port 5555. Requires USB connection first.")
        self.wifi_disable_btn.setToolTip("Disables ADB over TCP/IP and reverts to USB mode.")
        self.wifi_connect_btn.setToolTip("Attempts to connect to the device's current Wi-Fi IP address.")

        wifi_layout.addWidget(self.wifi_enable_btn)
        wifi_layout.addWidget(self.wifi_disable_btn)
        wifi_layout.addWidget(self.wifi_connect_btn)
        
        advanced_layout.addLayout(root_layout)
        advanced_layout.addLayout(wifi_layout)
        advanced_group.setLayout(advanced_layout)
        advanced_group.setVisible(True) # Re-enabled for visibility
        
        layout.addWidget(device_info_group)
        layout.addWidget(screen_group)
        layout.addWidget(input_group)
        layout.addWidget(reboot_group)
        layout.addWidget(power_group)
        layout.addWidget(advanced_group)
        layout.addStretch()
        
        self.setLayout(layout)

    def update_device_info(self, details):
        """Update device information labels with the provided details."""
        self.device_model_label.setText(details.get("model", "Unbekannt"))
        self.device_brand_label.setText(details.get("brand", "Unbekannt"))
        self.android_version_label.setText(details.get("android_version", "Unbekannt"))
        self.build_number_label.setText(details.get("build_number", "Unbekannt"))
        self.root_status_label.setText("Unbekannt")
        self.battery_level_label.setText("Unbekannt")
        self.storage_info_label.setText("Unbekannt")
        
        if not details:
            return
            
        root_status = details.get("root", False)
        self.root_status_label.setText("Ja" if root_status else "Nein")
        self.root_status_label.setStyleSheet(
            "color: green" if root_status else "color: red"
        )
        
        battery_level = details.get("battery_level")
        if battery_level is not None:
            self.battery_level_label.setText(str(battery_level))
        
        if all(k in details for k in ["storage_total_gb", "storage_used_gb", "storage_percent"]):
            storage_percent_str = details['storage_percent'].replace('%', '')
            try:
                storage_percent = int(storage_percent_str)
                self.storage_progress_bar.setValue(storage_percent)
                
                # Set color based on usage
                if storage_percent > 90:
                    self.storage_progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #e74c3c; }") # Red
                elif storage_percent > 75:
                    self.storage_progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #f1c40f; }") # Yellow
                else:
                    self.storage_progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #2ecc71; }") # Green

            except ValueError:
                self.storage_progress_bar.setValue(0)

            storage_text = f"Used: {details['storage_used_gb']} GB of {details['storage_total_gb']} GB ({details['storage_percent']})"
            self.storage_info_label.setText(storage_text)
        
    def show_recording_options(self):
        """Show dialog for screen recording options."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Recording Options")
        dialog.setMinimumWidth(300)
        
        layout = QFormLayout()
        
        resolution_combo = QComboBox()
        resolution_combo.addItems(["720p", "1080p", "native"])
        resolution_combo.setCurrentText(self.recording_settings['resolution'])
        layout.addRow("Resolution:", resolution_combo)
        
        bitrate_combo = QComboBox()
        bitrate_combo.addItems(["2M", "4M", "8M", "12M"])
        bitrate_combo.setCurrentText(self.recording_settings['bitrate'])
        layout.addRow("Bitrate:", bitrate_combo)
        
        time_limit_spin = QSpinBox()
        time_limit_spin.setRange(1, 180)  # 1 second to 3 minutes (adb screenrecord limit)
        time_limit_spin.setValue(self.recording_settings['time_limit'])
        time_limit_spin.setSuffix(" seconds")
        layout.addRow("Time Limit:", time_limit_spin)
        
        audio_check = QCheckBox()
        audio_check.setToolTip("Audio recording is only supported on Android 11+ and may not work on all devices.")
        audio_check.setChecked(self.recording_settings['with_audio'])
        layout.addRow("Record Audio:", audio_check)
        
        button_box = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        
        button_box.addWidget(save_btn)
        button_box.addWidget(cancel_btn)
        
        layout.addRow(button_box)
        dialog.setLayout(layout)
        
        save_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.recording_settings.update({
                'resolution': resolution_combo.currentText(),
                'bitrate': bitrate_combo.currentText(),
                'time_limit': time_limit_spin.value(),
                'with_audio': audio_check.isChecked()
            })
            
    def toggle_screen_recording(self):
        """Start or stop screen recording."""
        if not self.is_recording:
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Recording",
                os.path.join(os.path.expanduser("~"), f"screenrec_{int(time.time())}.mp4"),
                "MP4 Files (*.mp4)"
            )
            
            if not save_path:
                return
                
            device_path = f"/sdcard/screen_recording_{int(time.time())}.mp4"
            self.current_recording_info = {"device_path": device_path, "save_path": save_path}

            cmd_args = ["-s", self.device_manager.current_device, "shell", "screenrecord"]
            
            if self.recording_settings['resolution'] != 'native':
                width = "1920" if self.recording_settings['resolution'] == "1080p" else "1280"
                height = "1080" if self.recording_settings['resolution'] == "1080p" else "720"
                cmd_args.extend(["--size", f"{width}x{height}"])
                
            cmd_args.extend(["--bit-rate", self.recording_settings['bitrate']])
            cmd_args.extend(["--time-limit", str(self.recording_settings['time_limit'])])
            
            # if self.recording_settings['with_audio']: # Audio recording is complex and device-dependent.
            #     cmd_args.append("--audio-source internal")
            
            cmd_args.append(device_path)
            
            try:
                self.recording_process = QProcess()
                self.recording_process.finished.connect(self.finish_recording)
                self.recording_process.start(self.device_manager.adb_path, cmd_args)
                
                self.is_recording = True
                self.record_btn.setText("⏹️ Stop Recording")
                self.recording_status.setText("Recording in progress...")
                self.recording_status.setStyleSheet("color: red")
                self.recording_options_btn.setEnabled(False)

                QTimer.singleShot(1000, self.get_recording_pid)

            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to start recording: {str(e)}")
                self.is_recording = False
                
        else:
            if not self.is_recording or not self.recording_process:
                return

            self.recording_status.setText("Stopping recording...")
            QApplication.processEvents()

            if self.recording_pid:
                # Send SIGINT (Ctrl+C) to the process on the device to gracefully stop it.
                self.device_manager.execute_adb_command(f"shell kill -2 {self.recording_pid}")
                self.recording_pid = None
            
            # We use a failsafe timer to ensure finish_recording is called.
            if self.finish_timer:
                self.finish_timer.stop()
            self.finish_timer = QTimer()
            self.finish_timer.setSingleShot(True)
            self.finish_timer.timeout.connect(self.finish_recording)
            self.finish_timer.start(3000) # 3-second failsafe to allow file finalization

    def get_recording_pid(self):
        """Get the PID of the running screenrecord process."""
        return_code, output = self.device_manager.execute_adb_command("shell pidof screenrecord")
        if return_code == 0 and output.strip().isdigit():
            self.recording_pid = output.strip()

    def finish_recording(self):
        """Pull the recorded file from device and save it."""
        if self.is_finishing:
            return

        if hasattr(self, 'finish_timer') and self.finish_timer:
            self.finish_timer.stop()
            self.finish_timer = None

        device_path = self.current_recording_info["device_path"]
        save_path = self.current_recording_info["save_path"]

        self.recording_status.setText("Finishing up, pulling file...")
        QApplication.processEvents()  # Update UI

        self.is_finishing = True

        try:
            time.sleep(1.5)

            return_code, output = self.device_manager.execute_adb_command(f"pull \"{device_path}\" \"{save_path}\"")

            if return_code == 0 and os.path.exists(save_path) and os.path.getsize(save_path) > 0:
                self.device_manager.execute_adb_command(f"shell rm {device_path}")
                QMessageBox.information(self, "Success", f"Recording saved to {save_path}")
            else:
                QMessageBox.warning(self, "Error", f"Failed to save recording. Output: {output}")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error saving recording: {str(e)}")
            
        finally:
            self.reset_recording_ui()

    def reset_recording_ui(self):
        """Resets the recording UI to its initial state."""
        self.is_recording = False
        self.recording_process = None
        self.current_recording_info = None
        self.recording_pid = None
        self.record_btn.setText("🔴 Start Recording")
        self.is_finishing = False
        self.recording_status.setText("Not recording")
        self.recording_status.setStyleSheet("")
        self.recording_options_btn.setEnabled(True)

    def update_connection_status(self, connected):
        is_adb = False
        if connected and self.device_manager.current_device:
            device_type = next((d["type"] for d in self.device_manager.connected_devices if d["id"] == self.device_manager.current_device), None)
            if device_type == 'adb':
                is_adb = True

        for btn in [
            self.reboot_system_btn, self.reboot_recovery_btn, self.reboot_bootloader_btn,
            self.reboot_sideload_btn, self.reboot_download_btn, self.power_off_btn,
            self.screen_on_btn, self.screen_off_btn, self.root_check_btn, self.root_grant_btn,
            self.wifi_enable_btn,
            self.wifi_disable_btn, self.wifi_connect_btn, self.send_text_btn,
            self.get_clipboard_btn, self.set_clipboard_btn, self.record_btn, self.recording_options_btn
        ]:
            btn.setEnabled(is_adb)
        self.text_input.setEnabled(is_adb)

    def get_device_clipboard(self):
        """Get clipboard content from device, trying modern method first."""
        # Modern method (API 29+) - This is the most reliable.
        return_code, output = self.device_manager.execute_adb_command(["shell", "clipboard", "get-primary-clip"])
        if return_code == 0 and output.strip():
            text = output.strip()
            QApplication.clipboard().setText(text)
            CopyableMessageBox.information(self, "Success", f"Clipboard content copied to PC:\n{text}")
            return

        # Fallback to legacy method (less reliable)
        logging.info("Modern clipboard get failed, trying legacy method...")
        return_code, output = self.device_manager.execute_adb_command(["shell", "service", "call", "clipboard", "2"])
        if return_code == 0 and output:
            # The output is a Parcel object. We need to find the string data.
            # It's usually in the format: '...' (UTF-16-LE with nulls as dots)
            match = re.search(r"'(.*?)'\s*$", output, re.MULTILINE)
            if match:
                # The matched string is UTF-16LE, where null bytes are represented as dots.
                # We need to reconstruct the byte string.
                s16_le_with_dots = match.group(1)
                byte_string = b''
                i = 0
                while i < len(s16_le_with_dots):
                    char = s16_le_with_dots[i]
                    if i + 1 < len(s16_le_with_dots) and s16_le_with_dots[i+1] == '.':
                        byte_string += char.encode('utf-16-le')[0:1] # Get the first byte of the char
                        i += 2 # Skip char and dot
                    else:
                        # This case is less common but handles non-null-terminated chars
                        byte_string += char.encode('utf-16-le')
                        i += 1
                
                try:
                    text = byte_string.decode('utf-16-le')
                    QApplication.clipboard().setText(text)
                    CopyableMessageBox.information(self, "Success", f"Clipboard content copied to PC (legacy method):\n{text}")
                    return
                except UnicodeDecodeError as e:
                    CopyableMessageBox.warning(self, "Parsing Error", f"Could not decode legacy clipboard data: {e}")
                    return

        CopyableMessageBox.warning(self, "Error", "Failed to get device clipboard or it is empty. The legacy method may not be supported.")

    def set_device_clipboard(self):
        """Set device clipboard with content from PC."""
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        
        if not text:
            CopyableMessageBox.warning(self, "Error", "PC clipboard is empty")
            return
            
        # Modern method (API 29+)
        # Use exec-out and stdin to handle special characters safely
        try:
            proc = subprocess.Popen(
                [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "clipboard", "set-primary-clip"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            _, stderr = proc.communicate(input=text.encode('utf-8'), timeout=5)
            if proc.returncode == 0:
                CopyableMessageBox.information(self, "Success", "Clipboard content sent to device.")
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass # Fallback to legacy

        # Fallback to legacy method
        cmd_list = ["shell", "service", "call", "clipboard", "1", "i32", "1", "s16", text]
        return_code, _ = self.device_manager.execute_adb_command(cmd_list, timeout=10)
        
        if return_code == 0:
            CopyableMessageBox.information(self, "Success",
                "Clipboard content sent to device")
        else:
            CopyableMessageBox.warning(self, "Error",
                "Failed to set device clipboard")
    
    def execute_reboot(self, mode):
        confirm = QMessageBox.question(
            self, "Confirm Reboot", 
            f"Are you sure you want to reboot to {mode}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            success, output = self.device_manager.reboot_device(mode)
            if success:
                CopyableMessageBox.information(self, "Success", f"Device rebooting to {mode}")
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to reboot: {output}")
    
    def power_off_device(self):
        confirm = QMessageBox.question(
            self, "Confirm Power Off", 
            "Are you sure you want to power off the device?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            return_code, output = self.device_manager.execute_adb_command(["shell", "reboot", "-p"])
            if return_code == 0:
                CopyableMessageBox.information(self, "Success", "Device is powering off")
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to power off device: {output}")
    
    def turn_screen_on(self):
        return_code, output = self.device_manager.execute_adb_command(["shell", "input", "keyevent", "KEYCODE_POWER"])
        if return_code == 0:
            CopyableMessageBox.information(self, "Success", "Screen turned on")
        else:
            CopyableMessageBox.warning(self, "Error", f"Failed to turn screen on: {output}")
    
    def turn_screen_off(self):
        return_code, output = self.device_manager.execute_adb_command(["shell", "input", "keyevent", "KEYCODE_POWER"])
        if return_code == 0:
            CopyableMessageBox.information(self, "Success", "Screen turned off")
        else:
            CopyableMessageBox.warning(self, "Error", f"Failed to turn screen off: {output}")
    
    def check_root_access(self):
        return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "echo Root check"])
        if return_code == 0 and "Root check" in output:
            CopyableMessageBox.information(self, "Root Access", "Device has root access")
        else:
            CopyableMessageBox.warning(self, "Root Access", "Device does NOT have root access")
    
    def grant_root_access(self):
        confirm = QMessageBox.question(
            self, "Confirm Root Access", 
            "This will attempt to grant temporary root access. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            return_code, output = self.device_manager.execute_adb_command(["root"])
            if return_code == 0:
                CopyableMessageBox.information(self, "Success", "Temporary root access granted. Device may reboot.")
            else:
                CopyableMessageBox.warning(self, "Error", "Failed to grant root access")
    
    def enable_adb_over_wifi(self):
        confirm = QMessageBox.question(
            self, "Confirm ADB over WiFi", 
            "This will enable ADB over WiFi. Make sure your device is connected to the same network. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            return_code, output = self.device_manager.execute_adb_command(["shell", "setprop", "service.adb.tcp.port", "5555"])
            if return_code != 0:
                CopyableMessageBox.warning(self, "Error", "Failed to set ADB port")
                return
            
            self.device_manager.execute_adb_command(["shell", "stop", "adbd"])
            self.device_manager.execute_adb_command(["shell", "start", "adbd"])
            
            ip_commands = [
                "ip -f inet addr show wlan0",
                "ip -f inet addr show eth0",
                "ifconfig wlan0",
                "ifconfig eth0",
                "getprop dhcp.wlan0.ipaddress"
            ]
            
            ip_address = None
            for cmd in ip_commands:
                return_code, output = self.device_manager.execute_adb_command(["shell"] + shlex.split(cmd))
                if return_code == 0:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
                    if ip_match:
                        ip_address = ip_match.group(1)
                        break
            
            if ip_address:
                CopyableMessageBox.information(
                    self, "ADB over WiFi", 
                    f"ADB over WiFi enabled. Connect using:\n\nadb connect {ip_address}:5555"
                )
            else:
                CopyableMessageBox.information(
                    self, "ADB over WiFi", 
                    "ADB over WiFi enabled but couldn't determine IP address. "
                    "Make sure WiFi is connected on the device."
                )
    
    def disable_adb_over_wifi(self):
        confirm = QMessageBox.question(
            self, "Confirm Disable ADB over WiFi", 
            "This will disable ADB over WiFi. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            return_code, output = self.device_manager.execute_adb_command(["shell", "setprop", "service.adb.tcp.port", "-1"])
            if return_code != 0:
                CopyableMessageBox.warning(self, "Error", "Failed to disable ADB over WiFi")
                return
            
            self.device_manager.execute_adb_command(["shell", "stop", "adbd"])
            self.device_manager.execute_adb_command(["shell", "start", "adbd"])
            
            CopyableMessageBox.information(self, "Success", "ADB over WiFi disabled")
    
    def connect_via_wifi(self):
        ip_commands = [
            "ip -f inet addr show wlan0",
            "ip -f inet addr show eth0",
            "ifconfig wlan0",
            "ifconfig eth0",
            "getprop dhcp.wlan0.ipaddress"
        ]
        
        ip_address = None
        for cmd in ip_commands:
            return_code, output = self.device_manager.execute_adb_command(["shell"] + shlex.split(cmd))
            if return_code == 0:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
                if ip_match:
                    ip_address = ip_match.group(1)
                    break
        
        if ip_address:
            return_code, output = self.device_manager.execute_adb_command(["tcpip", "5555"], device_specific=True)
            if return_code != 0:
                CopyableMessageBox.warning(self, "Error", "Failed to set TCP/IP mode")
                return
            
            return_code, output = self.device_manager.execute_adb_command(["connect", f"{ip_address}:5555"], device_specific=False)
            
            if return_code == 0:
                CopyableMessageBox.information(self, "Success", f"Connected to {ip_address}:5555")
            else:
                CopyableMessageBox.warning(self, "Error", "Failed to connect")
        else:
            CopyableMessageBox.warning(self, "Error", "Could not determine device IP address. Make sure WiFi is connected.")

    def launch_camera(self):
        """Starts the default camera application on the device."""
        return_code, output = self.device_manager.execute_adb_command(["shell", "am", "start", "-a", "android.media.action.STILL_IMAGE_CAMERA"])
        if "Error" in output:
            CopyableMessageBox.warning(self, "Error", f"Failed to launch camera app: {output}")
        else:
            self.main_window.append_to_log("Camera app launched.")

    def take_picture(self):
        """Simulates pressing the camera shutter button."""
        self.main_window.append_to_log("Simulating shutter press...")
        # KEYCODE_CAMERA is often the shutter button.
        self.device_manager.execute_adb_command(["shell", "input", "keyevent", "KEYCODE_CAMERA"])

class FileExplorerTab(QWidget):
    def __init__(self, device_manager, file_manager):
        super().__init__()
        self.device_manager = device_manager
        self.file_manager = file_manager
        self.current_remote_path = "/storage/emulated/0"
        self.current_local_path = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DesktopLocation)

        # Add a dock widget for previews
        self.preview_dock = QDockWidget("Preview", self)
        self.preview_dock.setAllowedAreas(Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.LeftDockWidgetArea)
        self.preview_widget = QTextBrowser() # Use a more versatile widget
        self.preview_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_dock.setWidget(self.preview_widget)
        self.preview_dock.setVisible(False) # Initially hidden
        # We need to add this dock to the main window, not here. This will be handled in the main window.

        self.init_ui()
        self.thumbnail_loader = ThumbnailLoader(self.device_manager)
        
        self.file_manager.file_transfer_progress.connect(self.update_progress)
        self.file_manager.file_operation_complete.connect(self.file_operation_completed)
        self.file_manager.file_operation_started.connect(self.file_operation_started)
    
    def init_ui(self):
        main_layout = QHBoxLayout()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Remote (Device) File System
        remote_group = QGroupBox("Device File System")
        remote_layout = QVBoxLayout()
        
        # Remote Toolbar
        remote_toolbar = QHBoxLayout()
        self.remote_up_btn = QPushButton(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp), "")
        self.remote_up_btn.clicked.connect(self.remote_up)
        self.remote_path_edit = QLineEdit(self.current_remote_path)
        self.remote_path_edit.returnPressed.connect(self.navigate_remote)
        self.remote_bookmark_btn = QPushButton("🔖")
        self.remote_bookmark_btn.clicked.connect(self.manage_remote_bookmarks)
        remote_toolbar.addWidget(self.remote_up_btn)
        remote_toolbar.addWidget(self.remote_path_edit)
        remote_toolbar.addWidget(self.remote_bookmark_btn)
        
        self.remote_files_tree = QTreeWidget()
        self.remote_files_tree.setHeaderLabels(["Name", "Size", "Permissions", "Owner"])
        self.remote_files_tree.setDragDropMode(QTreeWidget.DragDropMode.DragDrop)
        self.remote_files_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.remote_files_tree.setColumnWidth(0, 250)
        self.remote_files_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.remote_files_tree.itemDoubleClicked.connect(self.remote_item_double_clicked)
        
        remote_btn_layout = QHBoxLayout()
        self.remote_refresh_btn = QPushButton("🔄 Refresh")
        self.remote_refresh_btn.clicked.connect(self.refresh_remote_directory)
        self.remote_pull_btn = QPushButton("⬇️ Pull")
        self.remote_pull_btn.clicked.connect(self.pull_file)
        self.remote_delete_btn = QPushButton("🗑️ Delete")
        self.remote_delete_btn.clicked.connect(self.delete_remote_file)
        self.remote_new_folder_btn = QPushButton("New Folder")
        self.remote_new_folder_btn.clicked.connect(self.create_remote_folder)
        
        remote_btn_layout.addWidget(self.remote_refresh_btn)
        remote_btn_layout.addWidget(self.remote_pull_btn)
        remote_btn_layout.addWidget(self.remote_delete_btn)
        remote_btn_layout.addWidget(self.remote_new_folder_btn)
        
        remote_layout.addLayout(remote_toolbar)
        remote_layout.addWidget(self.remote_files_tree)
        remote_layout.addLayout(remote_btn_layout)
        remote_group.setLayout(remote_layout)
        
        # Local File System
        local_group = QGroupBox("Local File System")
        local_layout = QVBoxLayout()
        
        # Local Toolbar
        local_toolbar = QHBoxLayout()
        self.local_up_btn = QPushButton(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp), "")
        self.local_up_btn.clicked.connect(self.local_up)
        self.local_path_edit = QLineEdit(self.current_local_path)
        self.local_path_edit.returnPressed.connect(self.navigate_local)
        self.local_bookmark_btn = QPushButton("🔖")
        self.local_bookmark_btn.clicked.connect(self.manage_local_bookmarks)
        local_toolbar.addWidget(self.local_up_btn)
        local_toolbar.addWidget(self.local_path_edit)
        local_toolbar.addWidget(self.local_bookmark_btn)
        
        self.local_files_tree = QTreeWidget()
        self.local_files_tree.setHeaderLabels(["Name", "Size", "Type", "Modified"])
        self.local_files_tree.setDragDropMode(QTreeWidget.DragDropMode.DragDrop)
        self.local_files_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.local_files_tree.setColumnWidth(0, 250)
        self.local_files_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.local_files_tree.itemDoubleClicked.connect(self.local_item_double_clicked)
        
        local_btn_layout = QHBoxLayout()
        self.local_refresh_btn = QPushButton("🔄 Refresh")
        self.local_refresh_btn.clicked.connect(self.refresh_local_directory)
        self.local_push_btn = QPushButton("⬆️ Push")
        self.local_push_btn.clicked.connect(self.push_file)
        self.local_delete_btn = QPushButton("🗑️ Delete")
        self.local_delete_btn.clicked.connect(self.delete_local_file)
        self.local_new_folder_btn = QPushButton("New Folder")
        self.local_new_folder_btn.clicked.connect(self.create_local_folder)
        
        local_btn_layout.addWidget(self.local_refresh_btn)
        local_btn_layout.addWidget(self.local_push_btn)
        local_btn_layout.addWidget(self.local_delete_btn)
        local_btn_layout.addWidget(self.local_new_folder_btn)
        
        local_layout.addLayout(local_toolbar)
        local_layout.addWidget(self.local_files_tree)
        local_layout.addLayout(local_btn_layout)
        local_group.setLayout(local_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        
        splitter.addWidget(remote_group)
        splitter.addWidget(local_group)
        
        main_layout.addWidget(splitter)
        
        overall_layout = QVBoxLayout()
        overall_layout.addLayout(main_layout)
        overall_layout.addWidget(self.progress_label)
        overall_layout.addWidget(self.progress_bar)
        
        self.setLayout(overall_layout)
        
        self.remote_files_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.remote_files_tree.customContextMenuRequested.connect(self.show_remote_context_menu)
        
        self.local_files_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.local_files_tree.customContextMenuRequested.connect(self.show_local_context_menu)

        # --- Tooltips ---
        self.remote_path_edit.setToolTip("Current directory on the Android device. Press Enter to navigate.")
        self.remote_up_btn.setToolTip("Go to parent directory.")
        self.remote_bookmark_btn.setToolTip("Manage and use bookmarks for remote directories.")
        self.remote_pull_btn.setToolTip("Download selected file(s)/folder(s) from device to PC.")
        self.remote_delete_btn.setToolTip("Delete selected file(s)/folder(s) on the device.")
        self.remote_new_folder_btn.setToolTip("Create a new folder in the current remote directory.")

        self.local_path_edit.setToolTip("Current directory on your PC. Press Enter to navigate.")
        self.local_up_btn.setToolTip("Go to parent directory.")
        self.local_bookmark_btn.setToolTip("Manage and use bookmarks for local directories.")
        self.local_push_btn.setToolTip("Upload selected file(s)/folder(s) from PC to the device.")
        self.local_delete_btn.setToolTip("Delete selected file(s)/folder(s) on your PC.")
        self.local_new_folder_btn.setToolTip("Create a new folder in the current local directory.")

        # Connect selection changed signals for preview
        self.remote_files_tree.itemSelectionChanged.connect(self.update_remote_preview)
        self.local_files_tree.itemSelectionChanged.connect(self.update_local_preview)

        self.setup_drag_drop()
    
    def refresh_remote_directory(self):
        if not self.device_manager.current_device:
            if not getattr(self.device_manager, "suppress_no_device_warning", False):
                QMessageBox.warning(self, "Error", "No device selected #016")
            return
        
        self.remote_files_tree.clear()
        if self.thumbnail_loader:
            self.thumbnail_loader.stop()
        
        try:
            return_code, output = self.device_manager.execute_adb_command(["shell", "ls", "-la", self.current_remote_path])
            
            if return_code != 0:
                CopyableMessageBox.warning(self, "Error", f"Failed to list directory: {output}")
                return
            
            image_files_to_load = []

            lines = output.splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 7:
                    permissions = parts[0]
                    owner = parts[2]
                    group = parts[3]
                    size = parts[4]
                    date = " ".join(parts[5:7])
                    name = " ".join(parts[7:])
                    
                    if name in [".", ".."]:
                        continue
                    
                    item = QTreeWidgetItem()
                    item.setText(0, name)
                    item.setText(1, size)
                    item.setText(2, permissions)
                    item.setText(3, f"{owner}/{group}")
                    
                    if permissions.startswith("d"):
                        item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                    else:
                        ext = os.path.splitext(name)[1].lower()
                        if ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp"]:
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                            remote_file_path = f"{self.current_remote_path}/{name}"
                            image_files_to_load.append((item, remote_file_path))
                        elif ext in [".mp3", ".wav", ".ogg"]:
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)) # Placeholder
                        elif ext in [".mp4", ".avi", ".mkv"]:
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)) # Placeholder
                        elif ext in [".txt", ".log", ".conf"]:
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)) # Placeholder
                        elif ext in [".apk"]:
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)) # Placeholder
                        else:
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                    
                    self.remote_files_tree.addTopLevelItem(item)
            
            if image_files_to_load:
                self.thumbnail_loader.load(image_files_to_load)

        except Exception as e:
            CopyableMessageBox.warning(self, "Error", f"Failed to refresh remote directory: {str(e)}")
    
    def refresh_local_directory(self):
        self.local_files_tree.clear()
        
        try:
            for entry in os.listdir(self.current_local_path):
                full_path = os.path.join(self.current_local_path, entry)
                try:
                    stat = os.stat(full_path)
                    
                    item = QTreeWidgetItem()
                    item.setText(0, entry)
                    
                    if os.path.isdir(full_path):
                        item.setText(1, "")
                        item.setText(2, "Folder")
                        item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                    else:
                        size = stat.st_size
                        item.setText(1, self.format_size(size))
                        
                        ext = os.path.splitext(entry)[1].lower()
                        if ext in [".jpg", ".jpeg", ".png", ".gif"]:
                            item.setText(2, "Image") # Placeholder
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                        elif ext in [".mp3", ".wav", ".ogg"]:
                            item.setText(2, "Audio")
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                        elif ext in [".mp4", ".avi", ".mkv"]:
                            item.setText(2, "Video")
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                        elif ext in [".txt", ".log", ".conf"]:
                            item.setText(2, "Text")
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                        elif ext in [".apk"]:
                            item.setText(2, "APK")
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                        else:
                            item.setText(2, ext[1:].upper() + " File" if ext else "File")
                            item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                    
                    item.setText(3, datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
                    self.local_files_tree.addTopLevelItem(item)
                except Exception as e:
                    logging.warning(f"Error processing local file {entry}: {str(e)}")
        except Exception as e:
            CopyableMessageBox.warning(self, "Error", f"Failed to refresh local directory: {str(e)}")
    
    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def navigate_remote(self):
        new_path = self.remote_path_edit.text().strip()
        if not new_path:
            return
        
        new_path = new_path.replace("\\", "/").replace("//", "/")
        if not new_path.startswith("/"):
            new_path = "/" + new_path
        
        self.current_remote_path = new_path
        self.remote_path_edit.setText(new_path)
        self.refresh_remote_directory()
    
    def navigate_local(self):
        new_path = self.local_path_edit.text().strip()
        if not new_path:
            return
        
        if os.path.isdir(new_path):
            self.current_local_path = os.path.abspath(new_path)
            self.local_path_edit.setText(self.current_local_path)
            self.refresh_local_directory()
        else:
            CopyableMessageBox.warning(self, "Error", "Invalid directory path")
            self.local_path_edit.setText(self.current_local_path)
    
    def remote_up(self):
        if self.current_remote_path == "/":
            return
        
        self.current_remote_path = os.path.dirname(self.current_remote_path.rstrip("/")) or "/"
        self.remote_path_edit.setText(self.current_remote_path)
        self.refresh_remote_directory()
    
    def local_up(self):
        parent = os.path.dirname(self.current_local_path)
        if parent != self.current_local_path:
            self.current_local_path = parent
            self.local_path_edit.setText(self.current_local_path)
            self.refresh_local_directory()
    
    def remote_item_double_clicked(self, item, column):
        name = item.text(0)
        if item.text(2).startswith("d"): # is directory
            new_path = os.path.join(self.current_remote_path, name).replace("\\", "/")
            self.current_remote_path = new_path
            self.remote_path_edit.setText(new_path)
            self.refresh_remote_directory()
    
    def local_item_double_clicked(self, item, column):
        name = item.text(0)
        full_path = os.path.join(self.current_local_path, name)
        
        if os.path.isdir(full_path):
            self.current_local_path = full_path
            self.local_path_edit.setText(full_path)
            self.refresh_local_directory()
    
    def pull_file(self):
        selected_items = self.remote_files_tree.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No file selected")
            return

        local_dir = QFileDialog.getExistingDirectory(self, "Select Destination Directory", self.current_local_path)
        if not local_dir:
            return

        for item in selected_items:
            remote_file = f"{self.current_remote_path}/{item.text(0)}"
            local_file = os.path.join(local_dir, item.text(0))
            self.file_manager.pull_file(remote_file, local_file)
    
    def push_file(self):
        selected_items = self.local_files_tree.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No file selected")
            return

        for item in selected_items:
            local_file = os.path.join(self.current_local_path, item.text(0))
            remote_file = f"{self.current_remote_path}/{item.text(0)}"
            self.file_manager.push_file(local_file, remote_file)
    
    def delete_remote_file(self):
        selected_items = self.remote_files_tree.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No file selected")
            return

        confirm = QMessageBox.question(
            self, "Confirm Delete", 
            f"Are you sure you want to delete {len(selected_items)} item(s) from the device?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            for item in selected_items:
                name = item.text(0)
                path = f"{self.current_remote_path}/{name}"
                is_dir = item.text(2).startswith("d")
                cmd_list = ["shell", "rm", "-r", path] if is_dir else ["shell", "rm", path]
                self.device_manager.execute_adb_command(cmd_list)
            CopyableMessageBox.information(self, "Success", f"Delete command sent for {len(selected_items)} items.")
            self.refresh_remote_directory()
    
    def delete_local_file(self):
        selected_items = self.local_files_tree.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No file selected")
            return

        confirm = QMessageBox.question(
            self, "Confirm Delete", 
            f"Are you sure you want to delete {len(selected_items)} item(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            for item in selected_items:
                name = item.text(0)
                path = os.path.join(self.current_local_path, name)
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                except Exception as e:
                    CopyableMessageBox.warning(self, "Error", f"Failed to delete {name}: {str(e)}")
            self.refresh_local_directory()
    
    def create_remote_folder(self):
        folder_name, ok = QInputDialog.getText(
            self, "New Folder", "Enter folder name:",
            QLineEdit.EchoMode.Normal
        )
        
        if ok and folder_name:
            folder_path = f"{self.current_remote_path}/{folder_name}"
            return_code, output = self.device_manager.execute_adb_command(["shell", "mkdir", "-p", folder_path])
            
            if return_code == 0:
                CopyableMessageBox.information(self, "Success", f"Folder created: {folder_path}")
                self.refresh_remote_directory()
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to create folder: {output}")
    
    def create_local_folder(self):
        folder_name, ok = QInputDialog.getText(
            self, "New Folder", "Enter folder name:",
            QLineEdit.EchoMode.Normal
        )
        
        if ok and folder_name:
            folder_path = os.path.join(self.current_local_path, folder_name)
            try:
                os.mkdir(folder_path)
                CopyableMessageBox.information(self, "Success", f"Folder created: {folder_path}")
                self.refresh_local_directory()
            except Exception as e:
                CopyableMessageBox.warning(self, "Error", f"Failed to create folder: {str(e)}")
    
    def update_progress(self, progress, message):
        self.progress_bar.setValue(progress)
        self.progress_label.setText(message)
    
    def file_operation_started(self, message):
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.progress_label.setText(message)
        self.progress_label.setVisible(True)
    
    def file_operation_completed(self, success, message):
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        if success:
            CopyableMessageBox.information(self, "Success", message)
            self.refresh_remote_directory()
            self.refresh_local_directory()
        else:
            CopyableMessageBox.warning(self, "Error", message)
    
    def show_remote_context_menu(self, position):
        item = self.remote_files_tree.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        
        name = item.text(0)
        path = f"{self.current_remote_path}/{name}"
        is_dir = item.text(2).startswith("d")
        
        if is_dir:
            open_action = menu.addAction("Open Directory")
            open_action.triggered.connect(lambda: self.remote_item_double_clicked(item, 0))
        else:
            open_action = menu.addAction("View File")
            open_action.triggered.connect(lambda: self.view_remote_file(path))
        
        pull_action = menu.addAction("Pull to Local")
        pull_action.triggered.connect(self.pull_file)
        
        if not is_dir and name.lower().endswith(('.txt', '.xml', '.prop', '.sh', '.log')):
            edit_action = menu.addAction("Edit File")
            edit_action.triggered.connect(lambda: self.edit_remote_text_file(path))
            menu.addAction(edit_action)
        menu.addSeparator()

        rename_action = menu.addAction("Rename")
        rename_action.triggered.connect(lambda: self.rename_remote_file(item))
        menu.addAction(rename_action)

        delete_action = menu.addAction("Delete")
        delete_action.triggered.connect(self.delete_remote_file)
        
        if not is_dir:
            prop_action = menu.addAction("Properties")
            prop_action.triggered.connect(lambda: self.show_remote_file_properties(item))
        else:
            # Add "Calculate Size" for directories
            calc_size_action = menu.addAction("Calculate Size")
            calc_size_action.triggered.connect(lambda: self.calculate_remote_folder_size(item))

        menu.addSeparator()
        
        menu.exec(self.remote_files_tree.viewport().mapToGlobal(position))
    
    def show_local_context_menu(self, position):
        item = self.local_files_tree.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        
        name = item.text(0)
        path = os.path.join(self.current_local_path, name)
        is_dir = item.text(2) == "Folder"
        
        if is_dir:
            open_action = menu.addAction("Open Directory")
            open_action.triggered.connect(lambda: self.local_item_double_clicked(item, 0))
        else:
            open_action = menu.addAction("Open File")
            open_action.triggered.connect(lambda: self.open_local_file(path))
        
        push_action = menu.addAction("Push to Device")
        push_action.triggered.connect(self.push_file)
        
        rename_action = menu.addAction("Rename")
        rename_action.triggered.connect(lambda: self.rename_local_file(item))
        menu.addAction(rename_action)

        delete_action = menu.addAction("Delete")
        delete_action.triggered.connect(self.delete_local_file)
        
        if not is_dir:
            prop_action = menu.addAction("Properties")
            prop_action.triggered.connect(lambda: self.show_local_file_properties(item))
        
        menu.exec(self.local_files_tree.viewport().mapToGlobal(position))
    
    def view_remote_file(self, path):
        # Use a secure temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.basename(path)) as tmp_file:
            temp_file_path = tmp_file.name

        # This is a simplified approach. A full solution would use signals to open after pull is complete.
        self.file_manager.pull_file(path, temp_file_path)
        QMessageBox.information(self, "File Ready", f"File pulled to temporary location:\n{temp_file_path}\nIt will be opened shortly if an association exists.")
        self.open_local_file(temp_file_path)
    
    def open_local_file(self, path):
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path])
            else:
                subprocess.run(["xdg-open", path])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open file: {str(e)}")
    
    def show_remote_file_properties(self, item):
        name = item.text(0)
        size = item.text(1)
        permissions = item.text(2)
        owner = item.text(3)
        path = f"{self.current_remote_path}/{name}"
        
        return_code, output = self.device_manager.execute_adb_command(["shell", "ls", "-ld", path]) # Use -d for directories
        details = output.strip() if return_code == 0 else "Could not get additional details"
        
        msg = QMessageBox()
        msg.setWindowTitle("File Properties")
        msg.setText(f"""
        <b>Name:</b> {name}<br>
        <b>Size:</b> {size}<br>
        <b>Permissions:</b> {permissions}<br>
        <b>Owner/Group:</b> {owner}<br>
        <b>Path:</b> {path}<br>
        <b>Details:</b><br>{details}
        """)
        msg.exec()

    def show_local_file_properties(self, item):
        name = item.text(0)
        size = item.text(1)
        file_type = item.text(2)
        modified = item.text(3)
        path = os.path.join(self.current_local_path, name)
        
        try:
            stat = os.stat(path)
            created = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
            accessed = datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S")
            permissions = oct(stat.st_mode)[-3:]
        except:
            created = "Unknown"
            accessed = "Unknown"
            permissions = "Unknown"
        
        msg = QMessageBox()
        msg.setWindowTitle("File Properties")
        msg.setText(f"""
        <b>Name:</b> {name}<br>
        <b>Size:</b> {size}<br>
        <b>Type:</b> {file_type}<br>
        <b>Modified:</b> {modified}<br>
        <b>Created:</b> {created}<br>
        <b>Accessed:</b> {accessed}<br>
        <b>Permissions:</b> {permissions}<br>
        <b>Path:</b> {path}
        """)
        msg.exec()

    def update_thumbnail_icon(self, item, icon):
        if item and self.remote_files_tree.indexOfTopLevelItem(item) != -1:
            item.setIcon(0, icon)

    def rename_remote_file(self, item):
        old_name = item.text(0)
        new_name, ok = QInputDialog.getText(self, "Rename Remote File", "New name:", text=old_name)
        if ok and new_name and new_name != old_name:
            old_path = f"{self.current_remote_path}/{old_name}"
            new_path = f"{self.current_remote_path}/{new_name}"
            return_code, output = self.device_manager.execute_adb_command(["shell", "mv", old_path, new_path])
            if return_code == 0:
                self.refresh_remote_directory()
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to rename: {output}")

    def rename_local_file(self, item):
        old_name = item.text(0)
        new_name, ok = QInputDialog.getText(self, "Rename Local File", "New name:", text=old_name)
        if ok and new_name and new_name != old_name:
            old_path = os.path.join(self.current_local_path, old_name)
            new_path = os.path.join(self.current_local_path, new_name)
            try:
                os.rename(old_path, new_path)
                self.refresh_local_directory()
            except Exception as e:
                CopyableMessageBox.warning(self, "Error", f"Failed to rename: {e}")

    def setup_drag_drop(self):
        self.local_files_tree.setDragEnabled(True)
        self.remote_files_tree.setAcceptDrops(True)

        self.remote_files_tree.setDragEnabled(True)
        self.local_files_tree.setAcceptDrops(True)

        # Override event handlers
        self.remote_files_tree.dragEnterEvent = self.remote_drag_enter_event
        self.remote_files_tree.dropEvent = self.remote_drop_event

        self.local_files_tree.dragEnterEvent = self.local_drag_enter_event
        self.local_files_tree.dropEvent = self.local_drop_event

    def remote_drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def remote_drop_event(self, event):
        for url in event.mimeData().urls():
            local_path = url.toLocalFile()
            if os.path.exists(local_path):
                remote_path = f"{self.current_remote_path}/{os.path.basename(local_path)}"
                self.file_manager.push_file(local_path, remote_path)

    def local_drag_enter_event(self, event):
        # A simple check to see if the drag originates from our remote tree
        if event.source() == self.remote_files_tree:
            event.acceptProposedAction()

    def local_drop_event(self, event):
        if event.source() == self.remote_files_tree:
            selected_items = self.remote_files_tree.selectedItems()
            for item in selected_items:
                remote_file = f"{self.current_remote_path}/{item.text(0)}"
                local_file = os.path.join(self.current_local_path, item.text(0))
                self.file_manager.pull_file(remote_file, local_file)

    def update_remote_preview(self):
        selected_items = self.remote_files_tree.selectedItems()
        if not selected_items:
            self.preview_dock.setVisible(False)
            return

        item = selected_items[0]
        filename = item.text(0)
        remote_path = f"{self.current_remote_path}/{filename}"
        is_dir = item.text(2).startswith("d")

        if is_dir:
            self.preview_dock.setVisible(False)
            return

        self.preview_dock.setVisible(True)
        self.preview_widget.clear()

        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            self.preview_widget.setText("Loading image preview...")
            # Use a worker to load image data to avoid freezing UI
            self.thread = QThread()
            self.worker = Worker(self._get_remote_image_data, remote_path)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.show_image_preview)
            self.thread.start()
        elif filename.lower().endswith(('.txt', '.xml', '.prop', '.sh', '.log')):
            self.preview_widget.setText("Loading text preview...")
            self.thread = QThread()
            self.worker = Worker(self.device_manager.execute_adb_command, ["shell", "cat", remote_path])
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.show_text_preview)
            self.thread.start()
        else:
            self.preview_dock.setVisible(False)

    def _get_remote_image_data(self, worker_instance, remote_path):
        return_code, output = self.device_manager.execute_adb_command(["exec-out", "cat", remote_path], capture_output=True)
        if return_code == 0:
            return output
        return None

    def show_image_preview(self, image_data):
        if image_data:
            pixmap = QPixmap()
            pixmap.loadFromData(image_data)
            if not pixmap.isNull():
                self.preview_widget.clear()
                doc = self.preview_widget.document()
                cursor = QTextCursor(doc)
                cursor.insertHtml(f'<img src="data:image/png;base64,{QByteArray(image_data).toBase64().data().decode()}" width="256">')
                self.preview_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
                return
        self.preview_widget.setText("Preview not available.")

    def show_text_preview(self, result):
        return_code, output = result
        if return_code == 0:
            self.preview_widget.setPlainText(output)
            self.preview_widget.setAlignment(Qt.AlignmentFlag.AlignLeft)
        else:
            self.preview_widget.setText("Preview not available.")

    def update_local_preview(self):
        selected_items = self.local_files_tree.selectedItems()
        if not selected_items:
            self.preview_dock.setVisible(False)
            return

        item = selected_items[0]
        filename = item.text(0)
        local_path = os.path.join(self.current_local_path, filename)

        if os.path.isdir(local_path):
            self.preview_dock.setVisible(False)
            return

        self.preview_dock.setVisible(True)
        self.preview_widget.clear()

        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            pixmap = QPixmap(local_path)
            if not pixmap.isNull():
                self.preview_widget.clear()
                # Convert to base64 to embed in HTML, works more reliably
                with open(local_path, "rb") as f:
                    image_data = f.read()
                doc = self.preview_widget.document()
                cursor = QTextCursor(doc)
                cursor.insertHtml(f'<img src="data:image/png;base64,{QByteArray(image_data).toBase64().data().decode()}" width="256">')
                self.preview_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            else:
                self.preview_widget.setText("Preview not available.")
        elif filename.lower().endswith(('.txt', '.xml', '.prop', '.sh', '.log')):
            try:
                with open(local_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read(1024 * 10) # Read up to 10KB
                    self.preview_widget.setPlainText(content)
                    self.preview_widget.setAlignment(Qt.AlignmentFlag.AlignLeft)
            except Exception as e:
                self.preview_widget.setText(f"Could not read file: {e}")
        else:
            self.preview_dock.setVisible(False)

    def edit_remote_text_file(self, remote_path):
        return_code, content = self.device_manager.execute_adb_command(["shell", "cat", remote_path])
        if return_code != 0:
            CopyableMessageBox.warning(self, "Error", f"Could not read file: {content}")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Editing {os.path.basename(remote_path)}")
        dialog.setMinimumSize(600, 500)
        layout = QVBoxLayout(dialog)
        editor = QTextEdit()
        editor.setPlainText(content)
        layout.addWidget(editor)
        save_btn = QPushButton("Save to Device")
        layout.addWidget(save_btn)

        def save_changes():
            new_content = editor.toPlainText().replace("'", "'\\''")
            # Use a here-document to safely write content
            cmd = f"shell \"echo '{new_content}' > {remote_path}\""
            code, out = self.device_manager.execute_adb_command(cmd)
            if code == 0:
                CopyableMessageBox.information(self, "Success", "File saved successfully.")
                dialog.accept()
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to save file: {out}")

        save_btn.clicked.connect(save_changes)
        dialog.exec()

    def manage_local_bookmarks(self):
        self.manage_bookmarks(local=True)

    def manage_remote_bookmarks(self):
        self.manage_bookmarks(local=False)

    def manage_bookmarks(self, local):
        setting_key = "local_bookmarks" if local else "remote_bookmarks"
        current_path = self.current_local_path if local else self.current_remote_path
        path_edit = self.local_path_edit if local else self.remote_path_edit
        refresh_func = self.refresh_local_directory if local else self.refresh_remote_directory

        with settings_lock:
            bookmarks = settings.value(setting_key, {}, type=dict)

        menu = QMenu(self)
        
        # Add current path
        add_action = menu.addAction(f"Add '{current_path}' to bookmarks")
        add_action.triggered.connect(lambda: self.add_bookmark(setting_key, current_path, bookmarks))
        menu.addSeparator()

        if not bookmarks:
            no_bookmarks_action = menu.addAction("No bookmarks yet")
            no_bookmarks_action.setEnabled(False)
        else:
            for name, path in bookmarks.items():
                action = menu.addAction(f"{name} ({path})")
                action.triggered.connect(lambda checked, p=path: self.navigate_to_bookmark(p, path_edit, refresh_func, local))

        menu.addSeparator()
        manage_action = menu.addAction("Manage Bookmarks...")
        manage_action.triggered.connect(lambda: self.open_bookmark_manager(setting_key, bookmarks))

        btn = self.local_bookmark_btn if local else self.remote_bookmark_btn
        menu.exec(btn.mapToGlobal(btn.rect().bottomLeft()))

    def add_bookmark(self, setting_key, path, bookmarks):
        name, ok = QInputDialog.getText(self, "Add Bookmark", "Enter a name for this bookmark:", text=os.path.basename(path) or path)
        if ok and name:
            bookmarks[name] = path
            with settings_lock:
                settings.setValue(setting_key, bookmarks)
            CopyableMessageBox.information(self, "Success", "Bookmark added.")

    def navigate_to_bookmark(self, path, path_edit, refresh_func, local):
        if local:
            self.current_local_path = path
        else:
            self.current_remote_path = path
        path_edit.setText(path)
        refresh_func()

    def open_bookmark_manager(self, setting_key, bookmarks):
        # This is a placeholder for a more advanced manager dialog.
        # For now, we'll just list them and allow deletion.
        items = list(bookmarks.keys())
        item, ok = QInputDialog.getItem(self, "Manage Bookmarks", "Select a bookmark to delete:", items, 0, False)
        if ok and item:
            del bookmarks[item]
            with settings_lock:
                settings.setValue(setting_key, bookmarks)
            CopyableMessageBox.information(self, "Success", "Bookmark deleted.")

class PackageManagerTab(QWidget):
    def __init__(self, device_manager, package_manager):
        super().__init__()
        self.device_manager = device_manager
        self.package_manager = package_manager
        self.init_ui()
        
        self.package_manager.package_list_updated.connect(self.update_package_list)
        self.package_manager.package_operation_complete.connect(self.package_operation_result)
        self.package_manager.package_info_updated.connect(self.update_package_info)
        self.active_workers = [] # Keep references to active workers/threads
        
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.timeout.connect(self.filter_packages)

    def force_stop_package(self):
        """Force stops the selected package."""
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "Please select a package to force stop")
            return
            
        package_name = selected_items[0].text().split()[0]
        confirm = QMessageBox.question(
            self, 
            "Confirm Force Stop", 
            f"Are you sure you want to force stop {package_name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            cmd_list = ["shell", "am", "force-stop", package_name]
            return_code, output = self.device_manager.execute_adb_command(cmd_list)
            
            if return_code == 0:
                CopyableMessageBox.information(self, "Success", f"Successfully force stopped {package_name}")
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to force stop {package_name}: {output}")

    def list_activities(self):
        """Lists all activities for the selected package."""
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "Please select a package to list activities")
            return
            
        package_name = selected_items[0].text().split()[0]
        # This is tricky to make safe with pipes. A full shell is invoked here.
        cmd_str = f"dumpsys package {package_name} | grep -A 10 Activity"
        return_code, output = self.device_manager.execute_adb_command(["shell", cmd_str])
        if return_code == 0 and output.strip():
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Activities for {package_name}")
            dialog.setMinimumWidth(600)
            dialog.setMinimumHeight(400)
            
            layout = QVBoxLayout()
            
            text_browser = QTextBrowser()
            text_browser.setPlainText(output)
            layout.addWidget(text_browser)
            
            dialog.setLayout(layout)
            dialog.exec()
        else:
            CopyableMessageBox.warning(self, "Error", f"No activities found for {package_name}")

    def start_activity(self):
        """Starts a specific activity from the selected package."""
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "Please select a package first")
            return
            
        package_name = selected_items[0].text().split()[0]
        
        # Get the activity name from user
        activity_name, ok = QInputDialog.getText(
            self,
            "Start Activity",
            "Enter activity name (e.g., .MainActivity or com.example.myapp.MainActivity):"
        )
        
        if ok and activity_name:
            # If activity doesn't have full package name, add it
            if not activity_name.startswith('.') and not activity_name.startswith(package_name):
                activity_name = '.' + activity_name
                
            if activity_name.startswith('.'):
                activity_name = package_name + activity_name
                
            cmd_list = ["shell", "am", "start", "-n", f"{package_name}/{activity_name}"]
            return_code, output = self.device_manager.execute_adb_command(cmd_list)
            
            if "Error" in output or return_code != 0:
                CopyableMessageBox.warning(self, "Error", f"Failed to start activity: {output}")
            else:
                CopyableMessageBox.information(self, "Success", f"Activity started: {activity_name}")
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Search and Filter Group
        search_filter_group = QGroupBox("Search & Filter Packages")
        search_filter_layout = QVBoxLayout()

        # Search Bar
        search_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search packages by name...")
        self.search_edit.textChanged.connect(self.on_search_text_changed)
        self.clear_search_btn = QPushButton("Clear")
        self.clear_search_btn.clicked.connect(self.search_edit.clear)
        search_layout.addWidget(QLabel("Search:"))
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(self.clear_search_btn)

        # Filter Checkboxes
        filter_checkbox_layout = QHBoxLayout()
        
        self.system_check = QCheckBox("System")
        self.third_party_check = QCheckBox("Third Party")
        self.enabled_check = QCheckBox("Enabled")
        self.disabled_check = QCheckBox("Disabled")

        # Connect checkboxes to refresh the list
        for checkbox in [self.system_check, self.third_party_check, self.enabled_check, self.disabled_check]:
            checkbox.stateChanged.connect(self.refresh_packages)

        filter_checkbox_layout.addWidget(self.system_check)
        filter_checkbox_layout.addWidget(self.third_party_check)
        filter_checkbox_layout.addWidget(self.enabled_check)
        filter_checkbox_layout.addWidget(self.disabled_check)
        filter_checkbox_layout.addStretch()

        search_filter_layout.addLayout(search_layout)
        search_filter_layout.addLayout(filter_checkbox_layout)
        search_filter_group.setLayout(search_filter_layout)
        
        # Package List Group
        package_group = QGroupBox("Packages")
        package_layout = QVBoxLayout()
        
        self.package_list = QListWidget()        
        
        # Action buttons for package management
        action_layout = QHBoxLayout()
        
        self.force_stop_btn = QPushButton("⛔ Force Stop")
        self.force_stop_btn.clicked.connect(self.force_stop_package)
        
        self.list_activities_btn = QPushButton("📋 List Activities")
        self.list_activities_btn.clicked.connect(self.list_activities)
        
        self.start_activity_btn = QPushButton("▶️ Start Activity")
        self.start_activity_btn.clicked.connect(self.start_activity)
        
        action_layout.addWidget(self.force_stop_btn)
        action_layout.addWidget(self.list_activities_btn)
        action_layout.addWidget(self.start_activity_btn)
        action_layout.addStretch()
        self.package_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        
        package_btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.install_btn = QPushButton("📦 Install APK [beta]")
        self.uninstall_btn = QPushButton("🗑️ Uninstall")
        self.clear_data_btn = QPushButton("🧹 Clear Data")
        self.enable_btn = QPushButton("▶️ Enable")
        self.disable_btn = QPushButton("⏸️ Disable")
        self.info_btn = QPushButton("Info")
        
        self.refresh_btn.clicked.connect(self.refresh_packages)
        self.install_btn.clicked.connect(self.install_package)
        self.uninstall_btn.clicked.connect(self.uninstall_package)
        self.clear_data_btn.clicked.connect(self.clear_package_data)
        self.enable_btn.clicked.connect(self.enable_package)
        self.disable_btn.clicked.connect(self.disable_package)
        self.info_btn.clicked.connect(self.show_package_info)

        # --- Tooltips ---        
        self.search_edit.setToolTip("Live search for packages by name.")
        self.system_check.setToolTip("Show only system applications.")
        self.third_party_check.setToolTip("Show only third-party (user-installed) applications.")
        self.install_btn.setToolTip("Install an APK file from your PC onto the device.")
        self.uninstall_btn.setToolTip("Uninstall the selected application(s).")
        self.clear_data_btn.setToolTip("Clear the application data and cache for the selected app(s).")
        self.enable_btn.setToolTip("Enable the selected disabled application(s).")
        self.disable_btn.setToolTip("Disable the selected application(s).")
        self.info_btn.setToolTip("Show detailed information about the selected application.")
        
        package_btn_layout.addWidget(self.refresh_btn)
        package_btn_layout.addWidget(self.install_btn)
        package_btn_layout.addWidget(self.uninstall_btn)
        package_btn_layout.addWidget(self.clear_data_btn)
        package_btn_layout.addWidget(self.enable_btn)
        package_btn_layout.addWidget(self.disable_btn)
        package_btn_layout.addWidget(self.info_btn)
        
        package_layout.addWidget(self.package_list)
        package_layout.addLayout(package_btn_layout)
        package_layout.addLayout(action_layout)
        package_group.setLayout(package_layout)
        
        # Package Info Group
        info_group = QGroupBox("Package Information")
        info_layout = QVBoxLayout()
        
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        
        info_layout.addWidget(self.info_text)
        info_group.setLayout(info_layout)
        
        layout.addWidget(search_filter_group)
        layout.addWidget(package_group)
        layout.addWidget(info_group)
        
        self.setLayout(layout)
        
        self.package_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.package_list.customContextMenuRequested.connect(self.show_package_context_menu)
        self.package_list.itemDoubleClicked.connect(self.show_package_info)
        self.package_list.itemSelectionChanged.connect(self.show_package_info)

    def showEvent(self, event):
        """When the tab is shown for the first time, refresh the package list."""
        super().showEvent(event)
        self.refresh_packages()
    
    def refresh_packages(self):
        system_only = self.system_check.isChecked()
        third_party_only = self.third_party_check.isChecked()
        enabled_only = self.enabled_check.isChecked()
        disabled_only = self.disabled_check.isChecked()
        
        self.package_manager.get_installed_packages(
            system_only=system_only,
            third_party_only=third_party_only,
            enabled_only=enabled_only,
            disabled_only=disabled_only
        )
    
    def update_package_list(self, packages):
        self.package_list.clear()
        self.package_list.addItems(packages)
        self.filter_packages()
    
    def on_search_text_changed(self, text):
        """Trigger search with a small delay to avoid lagging on fast typing."""
        self.search_timer.start(300) # 300ms delay

    def filter_packages(self):
        search_text = self.search_edit.text().lower()
        
        for i in range(self.package_list.count()):
            item = self.package_list.item(i)
            item.setHidden(search_text not in item.text().lower())
    
    def install_package(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select APK File", "", "APK Files (*.apk);;All Files (*)"
        )
        
        if file_path:
            # Analyze APK first
            cmd = f"aapt dump badging \"{file_path}\""
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = process.communicate()
            
            if process.returncode == 0:
                apk_info = self.parse_apk_info(output.decode('utf-8', errors='ignore'))
                
                # Show APK details dialog
                info_dialog = QDialog(self)
                info_dialog.setWindowTitle("APK Analysis")
                info_dialog.setMinimumWidth(500)
                
                layout = QVBoxLayout()
                
                # APK Information
                info_text = QTextEdit()
                info_text.setReadOnly(True)
                info_text.setHtml(f"""
                    <h3>APK Information:</h3>
                    <p><b>Package:</b> {apk_info['package']}</p>
                    <p><b>Version Name:</b> {apk_info['version_name']}</p>
                    <p><b>Version Code:</b> {apk_info['version_code']}</p>
                    <p><b>Min SDK:</b> {apk_info['min_sdk']}</p>
                    <p><b>Target SDK:</b> {apk_info['target_sdk']}</p>
                    <p><b>App Name:</b> {apk_info['app_name']}</p>
                    
                    <h3>Permissions:</h3>
                    <ul>
                    {"".join(f"<li>{p}</li>" for p in apk_info['permissions'])}
                    </ul>
                    
                    <h3>Features:</h3>
                    <ul>
                    {"".join(f"<li>{f}</li>" for f in apk_info['features'])}
                    </ul>
                """)
                layout.addWidget(info_text)
                
                options_group = QGroupBox("Installation Options")
                options_layout = QVBoxLayout()
                
                replace_existing = QCheckBox("Replace existing app")
                grant_permissions = QCheckBox("Grant all permissions")
                test_only = QCheckBox("Test only (don't actually install)")
                downgrade = QCheckBox("Allow downgrade")
                
                options_layout.addWidget(replace_existing)
                options_layout.addWidget(grant_permissions)
                options_layout.addWidget(test_only)
                options_layout.addWidget(downgrade)
                options_group.setLayout(options_layout)
                layout.addWidget(options_group)
                
                button_layout = QHBoxLayout()
                install_btn = QPushButton("Install")
                cancel_btn = QPushButton("Cancel")
                
                button_layout.addWidget(install_btn)
                button_layout.addWidget(cancel_btn)
                layout.addLayout(button_layout)
                
                info_dialog.setLayout(layout)

                # --- Tooltips for install options ---
                replace_existing.setToolTip("Reinstall the application, keeping its data.")
                grant_permissions.setToolTip("Grant all permissions declared in the app's manifest (Android 6.0+).")
                test_only.setToolTip("Mark the application as a test-only APK.")
                downgrade.setToolTip("Allow installing an older version of an app over a newer one (may not always work).")

                # --- Styling for the dialog ---
                info_dialog.setStyleSheet("""
                    QDialog { background-color: #3c3c3c; }
                    QGroupBox { background-color: #2b2b2b; }
                    QTextEdit { background-color: #2b2b2b; border: 1px solid #555; }
                """)
                install_btn.setStyleSheet("background-color: #007acc; color: white;")


                
                install_btn.clicked.connect(info_dialog.accept)
                cancel_btn.clicked.connect(info_dialog.reject)
                
                result = info_dialog.exec()
                
                if result == QDialog.DialogCode.Accepted:
                    args = []
                    if replace_existing.isChecked():
                        args.append("-r")
                    if grant_permissions.isChecked():
                        args.append("-g")
                    if test_only.isChecked():
                        args.append("-t")
                    if downgrade.isChecked():
                        args.append("-d") # Note: This is the same flag as test_only in some contexts, but `adb install` handles it.

                    self.run_long_operation(
                        self.package_manager.install_package,
                        "Installing APK...",
                        file_path,
                        *args
                    )

    def run_long_operation(self, function, title, *args):
        """Generic runner for long operations with a progress dialog."""
        progress = QProgressDialog(title, "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Operation in Progress")
        progress.show()
    
        thread = QThread()
        worker = Worker(function, *args)
        worker.moveToThread(thread)
    
        # Keep references
        self.active_workers.append((thread, worker))
    
        thread.started.connect(worker.run)
        worker.finished.connect(progress.close)
        worker.finished.connect(thread.quit)
        # Clean up when finished
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: self.active_workers.remove((thread, worker)))
    
        thread.start()

    def parse_apk_info(self, aapt_output):
        """Parse aapt dump output to extract APK information."""
        info = {
            'package': '',
            'version_name': '',
            'version_code': '',
            'min_sdk': '',
            'target_sdk': '',
            'app_name': '',
            'permissions': [],
            'features': []
        }
        
        for line in aapt_output.split('\n'):
            if line.startswith('package:'):
                matches = re.findall(r"name='([^']+)'.*versionCode='([^']+)'.*versionName='([^']+)'", line)
                if matches:
                    info['package'] = matches[0][0]
                    info['version_code'] = matches[0][1]
                    info['version_name'] = matches[0][2]
            elif line.startswith('sdkVersion:'):
                info['min_sdk'] = line.split("'")[1]
            elif line.startswith('targetSdkVersion:'):
                info['target_sdk'] = line.split("'")[1]
            elif line.startswith('application:'):
                matches = re.findall(r"label='([^']+)'", line)
                if matches:
                    info['app_name'] = matches[0]
            elif line.startswith('uses-permission:'):
                permission = re.findall(r"name='([^']+)'", line)
                if permission:
                    info['permissions'].append(permission[0])
            elif line.startswith('uses-feature:'):
                feature = re.findall(r"name='([^']+)'", line)
                if feature:
                    info['features'].append(feature[0])
                    
        return info
    
    def uninstall_package(self):
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No packages selected")
            return
        
        package_names = [item.text() for item in selected_items]
        
        confirm = QMessageBox.question(
            self, "Confirm Uninstall", 
            f"Are you sure you want to uninstall {len(package_names)} package(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            options = QMessageBox()
            options.setWindowTitle("Uninstall Options")
            options.setText("Select uninstall options:")
            
            keep_data = QCheckBox("Keep data and cache")
            
            layout = options.layout()
            if layout is not None:
                layout.addWidget(keep_data, 1, 0, 1, 2)
            
            options.addButton("Uninstall", QMessageBox.ButtonRole.AcceptRole)
            options.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
            
            options.exec()
            
            if options.clickedButton().text() == "Uninstall":
                self.run_long_operation(
                    self.uninstall_packages_worker,
                    "Uninstalling...", # This is the title for the progress dialog
                    package_names, keep_data.isChecked()
                )
    
    def clear_package_data(self):
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No packages selected")
            return
        
        package_names = [item.text() for item in selected_items]
        
        confirm = QMessageBox.question(
            self, "Confirm Clear Data", 
            f"Are you sure you want to clear data for {len(package_names)} package(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.run_long_operation(
                self.clear_packages_worker,
                "Clearing Data...", # Title
                package_names
            )
    
    def enable_package(self):
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No packages selected")
            return
        
        self.run_long_operation(
            self.enable_packages_worker,
            "Enabling Packages...", # Title
            [item.text() for item in selected_items]
        )
    
    def disable_package(self):
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            CopyableMessageBox.warning(self, "Error", "No packages selected")
            return
        
        self.run_long_operation(
            self.disable_packages_worker,
            "Disabling Packages...", # Title
            [item.text() for item in selected_items]
        )

    def uninstall_packages_worker(self, worker_instance, packages, keep_data):
        for package in packages:
            self.package_manager.uninstall_package(package, keep_data)
        return True # Return a value to prevent crash

    def clear_packages_worker(self, worker_instance, packages):
        for package in packages:
            self.package_manager.clear_package_data(package)
        return True # Return a value to prevent crash

    def enable_packages_worker(self, worker_instance, packages):
        for package in packages:
            self.package_manager.enable_package(package)
        return True # Return a value to prevent crash
    
    def show_package_info(self):
        selected_items = self.package_list.selectedItems()
        if not selected_items:
            # No need for a message box if nothing is selected, just return.
            return
        
        package_name = selected_items[0].text()
        self.package_manager.get_package_info(package_name)

    def disable_packages_worker(self, worker_instance, packages):
        for package in packages:
            self.package_manager.disable_package(package)
        return True # Return a value to prevent crash
    
    def update_package_info(self, info):
        info_text = f"""
        <b>Package Name:</b> {info['name']}<br>
        <b>Version:</b> {info['version']}<br>
        <b>Target SDK:</b> {info.get('target_sdk', 'Unknown')}<br>
        <b>Min SDK:</b> {info.get('min_sdk', 'Unknown')}<br>
        <hr>
        <b>UID:</b> {info['uid']}<br>
        <b>Path:</b> {info['path']}<br>
        <b>Data Path:</b> {info.get('data_dir', 'Unknown')}<br>
        <b>Status:</b> {'Enabled' if info['enabled'] else 'Disabled'}<br>
        <b>Installer:</b> {info.get('installer', 'Unknown')}<br>
        <b>CPU ABI:</b> {info.get('cpu_abi', 'Unknown')}<br>
        <hr>
        <b>Signature Hash:</b> {info.get('signature', 'Unknown')}<br>
        """
        
        if 'install_time' in info:
            info_text += f"<b>Installed:</b> {info['install_time']}<br>"
        
        if 'update_time' in info:
            info_text += f"<b>Updated:</b> {info['update_time']}<br>"
        
        if 'size' in info:
            info_text += f"<b>Size:</b> {info['size']}<br>"
        
        if info['permissions']:
            info_text += "<hr><b>Permissions:</b><br>"
            info_text += "<b>Permissions:</b><br>"
            for perm in info['permissions']:
                info_text += f"&nbsp;&nbsp;• {perm}<br>"
        
        self.info_text.setHtml(info_text)
    
    def package_operation_result(self, success, message):
        if success:
            CopyableMessageBox.information(self, "Success", message)
            self.refresh_packages()
        else:
            CopyableMessageBox.warning(self, "Error", message)
    
    def show_package_context_menu(self, position):
        item = self.package_list.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        
        info_action = menu.addAction("Show Info")
        info_action.triggered.connect(self.show_package_info)
        
        menu.addSeparator()
        
        enable_action = menu.addAction("Enable")
        enable_action.triggered.connect(self.enable_package)
        
        disable_action = menu.addAction("Disable")
        disable_action.triggered.connect(self.disable_package)
        
        menu.addSeparator()
        
        uninstall_action = menu.addAction("Uninstall")
        uninstall_action.triggered.connect(self.uninstall_package)
        
        clear_action = menu.addAction("Clear Data")
        clear_action.triggered.connect(self.clear_package_data)
        
        menu.exec(self.package_list.mapToGlobal(position))

class BackupRestoreTab(QWidget):
    def __init__(self, device_manager, backup_manager):
        super().__init__()
        self.device_manager = device_manager
        self.backup_manager = backup_manager
        self.init_ui()
        
        self.backup_manager.backup_progress.connect(self.update_progress)
        self.backup_manager.backup_complete.connect(self.backup_completed)
        self.backup_manager.backup_started.connect(self.backup_started)
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Backup Group
        backup_group = QGroupBox("Backup")
        backup_layout = QVBoxLayout()
        
        self.backup_path_edit = QLineEdit()
        self.backup_path_edit.setPlaceholderText("Select backup file path...")
        
        self.backup_browse_btn = QPushButton("Browse...")
        self.backup_browse_btn.clicked.connect(self.select_backup_path)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.backup_path_edit)
        path_layout.addWidget(self.backup_browse_btn)
        
        self.include_apks_check = QCheckBox("Include APKs")
        self.include_shared_check = QCheckBox("Include Shared Storage")
        self.include_system_check = QCheckBox("Include System Apps")
        self.all_apps_check = QCheckBox("Backup All Apps")
        
        self.backup_btn = QPushButton("Create Backup")
        self.backup_btn.clicked.connect(self.create_backup)
        
        backup_layout.addLayout(path_layout)
        backup_layout.addWidget(self.include_apks_check)
        backup_layout.addWidget(self.include_shared_check)
        backup_layout.addWidget(self.include_system_check)
        backup_layout.addWidget(self.all_apps_check)
        backup_layout.addWidget(self.backup_btn)
        backup_group.setLayout(backup_layout)
        
        # Restore Group
        restore_group = QGroupBox("Restore")
        restore_layout = QVBoxLayout()
        
        self.restore_path_edit = QLineEdit()
        self.restore_path_edit.setPlaceholderText("Select backup file to restore...")
        
        self.restore_browse_btn = QPushButton("Browse...")
        self.restore_browse_btn.clicked.connect(self.select_restore_path)
        
        restore_path_layout = QHBoxLayout()
        restore_path_layout.addWidget(self.restore_path_edit)
        restore_path_layout.addWidget(self.restore_browse_btn)
        
        self.restore_btn = QPushButton("Restore Backup")
        self.restore_btn.clicked.connect(self.restore_backup)
        
        restore_layout.addLayout(restore_path_layout)
        restore_layout.addWidget(self.restore_btn)
        restore_group.setLayout(restore_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        
        layout.addWidget(backup_group)
        layout.addWidget(restore_group)
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress_bar)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def select_backup_path(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Backup File", "", "AB Backup Files (*.ab);;All Files (*)"
        )
        
        if file_path:
            if not file_path.lower().endswith('.ab'):
                file_path += '.ab'
            self.backup_path_edit.setText(file_path)
    
    def select_restore_path(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Backup File", "", "AB Backup Files (*.ab);;All Files (*)"
        )
        
        if file_path:
            self.restore_path_edit.setText(file_path)
    
    def create_backup(self):
        backup_path = self.backup_path_edit.text()
        if not backup_path:
            CopyableMessageBox.warning(self, "Error", "Please select a backup file path")
            return
        
        if os.path.exists(backup_path):
            confirm = QMessageBox.question(
                self, "Confirm Overwrite", 
                f"The file '{backup_path}' already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm != QMessageBox.StandardButton.Yes:
                return
        
        include_apks = self.include_apks_check.isChecked()
        include_shared = self.include_shared_check.isChecked()
        include_system = self.include_system_check.isChecked()
        all_apps = self.all_apps_check.isChecked()
        
        self.backup_manager.create_backup(
            backup_path,
            include_apks=include_apks,
            include_shared=include_shared,
            include_system=include_system,
            all_apps=all_apps
        )
    
    def restore_backup(self):
        restore_path = self.restore_path_edit.text()
        if not restore_path:
            CopyableMessageBox.warning(self, "Error", "Please select a backup file to restore")
            return
        
        if not os.path.exists(restore_path):
            CopyableMessageBox.warning(self, "Error", "Backup file does not exist")
            return
        
        confirm = QMessageBox.question(
            self, "Confirm Restore", 
            "Restoring will overwrite existing data on the device. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.backup_manager.restore_backup(restore_path)
    
    def backup_started(self, message):
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.progress_label.setText(message)
        self.progress_label.setVisible(True)
    
    def update_progress(self, progress, message):
        self.progress_bar.setValue(progress)
        self.progress_label.setText(message)
    
    def backup_completed(self, success, message):
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        if success:
            CopyableMessageBox.information(self, "Success", message)
        else:
            CopyableMessageBox.warning(self, "Error", message)

class LogcatTab(QWidget):
    def __init__(self, device_manager, logcat_manager):
        super().__init__()
        self.device_manager = device_manager
        self.logcat_manager = logcat_manager
        self.init_ui()
        
        self.logcat_manager.log_received.connect(self.append_log)
        self.logcat_manager.log_cleared.connect(self.log_cleared)
        self.logcat_manager.log_started.connect(self.log_started)
        self.logcat_manager.log_stopped.connect(self.log_stopped)
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Filter Controls
        filter_group = QGroupBox("Logcat Filters")
        filter_layout = QHBoxLayout()
        
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["Verbose", "Debug", "Info", "Warning", "Error", "Fatal", "Silent"])
        self.priority_combo.setCurrentText("Verbose")
        
        self.device_manager.devices_updated.connect(self.on_devices_updated)
        
        self.tag_edit = QLineEdit()
        self.tag_edit.setPlaceholderText("Tag filter (optional)")
        
        self.pid_edit = QLineEdit()
        self.pid_edit.setPlaceholderText("PID filter (optional)")
        
        filter_layout.addWidget(QLabel("Priority:"))
        filter_layout.addWidget(self.priority_combo)
        filter_layout.addWidget(QLabel("Tag:"))
        filter_layout.addWidget(self.tag_edit)
        filter_layout.addWidget(QLabel("PID:"))
        filter_layout.addWidget(self.pid_edit)
        
        filter_group.setLayout(filter_layout)
        
        # Log Controls
        control_group = QGroupBox("Logcat Controls")
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear")
        self.save_btn = QPushButton("Save")
        
        self.start_btn.clicked.connect(self.start_logcat)
        self.stop_btn.clicked.connect(self.stop_logcat)
        self.clear_btn.clicked.connect(self.clear_logcat)
        self.save_btn.clicked.connect(self.save_logcat)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.save_btn)
        
        control_group.setLayout(control_layout)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        font = QFont("Consolas", 10)
        self.log_text.setFont(font)
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier New", 10))
        
        layout.addWidget(filter_group)
        layout.addWidget(control_group)
        layout.addWidget(self.log_text)
        
        self.setLayout(layout)
    
    def start_logcat(self):
        priority = self.priority_combo.currentText().lower()[0]
        tag = self.tag_edit.text().strip()
        pid = self.pid_edit.text().strip()
        
        filters = []
        
        if priority != 'v':
            filters.append(f"*:{priority}")
        
        if tag:
            filters.append(f"{tag}:{priority}")
        
        if pid:
            filters.append(f"--pid={pid}")
        
        if not self.device_manager.current_device:
            if not getattr(self.device_manager, "suppress_no_device_warning", False):
                CopyableMessageBox.warning(self, "Error", "No device selected #017")
            return

        started = self.logcat_manager.start_logcat(filters=" ".join(filters) if filters else None)
        if started is False:
            if not getattr(self.device_manager, "suppress_no_device_warning", False):
                CopyableMessageBox.warning(self, "Error", "No device selected #018")
    
    def stop_logcat(self):
        self.logcat_manager.stop_logcat()
    
    def clear_logcat(self):
        self.logcat_manager.clear_logcat()
    
    def save_logcat(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Logcat", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            priority = self.priority_combo.currentText().lower()[0]
            tag = self.tag_edit.text().strip()
            pid = self.pid_edit.text().strip()
            
            filters = []
            
            if priority != 'v':
                filters.append(f"*:{priority}")
            
            if tag:
                filters.append(f"{tag}:{priority}")
            
            if pid:
                filters.append(f"--pid={pid}")
            
            success, message = self.logcat_manager.save_logcat(file_path, filters=" ".join(filters) if filters else None)
            
            if success:
                CopyableMessageBox.information(self, "Success", "Logcat saved successfully")
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to save logcat: {message}")
    
    def append_log(self, log_line):
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        log_colors = {
            'V': QColor('#808080'),  # Grau für Verbose
            'D': QColor('#0000FF'),  # Blau für Debug
            'I': QColor('#008000'),  # Grün für Info
            'W': QColor('#FFA500'),  # Orange für Warning
            'E': QColor('#FF0000'),  # Rot für Error
            'F': QColor('#800080'),  # Violett für Fatal
            'Starting logcat...': QColor('#008000'),  # Grün für Start-Nachricht
            'Logcat stopped.': QColor('#0000FF'),    # Blau für Stop-Nachricht
        }
        
        format = self.log_text.currentCharFormat()
        format.setForeground(QColor('#000000'))
        
        if log_line in ['Starting logcat...', 'Logcat stopped.']:
            format.setForeground(log_colors[log_line])
            cursor.setCharFormat(format)
            cursor.insertText(log_line + "\n")
            self.log_text.setTextCursor(cursor)
            return
            
        try:
            # Extrahiere den Log-Level aus der Zeile
            parts = log_line.split()
            for part in parts:
                if len(part) == 1 and part in log_colors:  # Einzelner Buchstabe als Level
                    format.setForeground(log_colors[part])
                    break
                elif '/' in part:  # Suche in "D/TAG" Format
                    level = part.split('/')[0]
                    if level in log_colors:
                        format.setForeground(log_colors[level])
                        break
        except:
            pass
            
        cursor.setCharFormat(format)
        cursor.insertText(log_line + "\n")
        self.log_text.setTextCursor(cursor)
        self.log_text.ensureCursorVisible()
    
    def on_devices_updated(self, devices):
        has_device = len(devices) > 0
        self.start_btn.setEnabled(has_device)
        self.clear_btn.setEnabled(has_device)
        self.save_btn.setEnabled(has_device)
        
    def log_started(self):
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.log_text.clear()
        self.append_log("Starting logcat...")
        
    def log_cleared(self, success):
        if success:
            self.log_text.clear()
    
    def log_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.append_log("\nLogcat stopped.")

class AdvancedShellTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.command_history = []
        self.history_index = 0
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        input_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter shell command...")
        self.command_input.returnPressed.connect(self.execute_command)
        
        self.run_btn = QPushButton("▶️ Run")
        self.run_btn.clicked.connect(self.execute_command)
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(self.clear_output)
        
        input_layout.addWidget(self.command_input)
        input_layout.addWidget(self.run_btn)
        input_layout.addWidget(self.clear_btn)

        history_group = QGroupBox("Command History")
        history_layout = QVBoxLayout()
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.use_history_item)
        history_layout.addWidget(self.history_list)
        history_group.setLayout(history_layout)

        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextBrowser()
        self.output_text.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)

        quick_group = QGroupBox("Quick Commands")
        quick_layout = QGridLayout()
        
        quick_commands = [
            ("📱 Device Info", "getprop"),
            ("📊 Process List", "ps -A"),
            ("💾 Memory Info", "dumpsys meminfo"),
            ("🔋 Battery Info", "dumpsys battery"),
            ("📊 CPU Info", "cat /proc/cpuinfo"),
            ("💿 Disk Usage", "df -h"),
            ("📶 Network Info", "ifconfig"),
            ("⚡ Running Services", "service list"),
            ("🔝 Top Processes", "top -n 1"),
            ("🌐 Net Connections", "netstat -tuln"),
            ("📏 Screen Resolution", "wm size"),
            ("엑 Top Activity", "dumpsys activity top"),
        ]
        
        row = 0
        col = 0
        for label, cmd in quick_commands:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, cmd=cmd: self.run_quick_command(cmd))
            quick_layout.addWidget(btn, row, col)
            col += 1
            if col > 3:  # 4 buttons per row
                col = 0
                row += 1
        
        quick_group.setLayout(quick_layout)

        layout.addLayout(input_layout)
        layout.addWidget(quick_group)
        layout.addWidget(output_group)
        layout.addWidget(history_group)

        self.setLayout(layout)

    def execute_command(self):
        command = self.command_input.text().strip()
        if not command:
            return
            
        if not self.command_history or command != self.command_history[-1]:
            self.command_history.append(command)
            self.history_list.addItem(command)
            
        self.history_index = len(self.command_history)
        
        self.output_text.append(f"\n$ {command}\n")
        return_code, output = self.device_manager.execute_adb_command(["shell", command])
        
        color = "green" if return_code == 0 else "red"
        self.output_text.append(f'<pre><font color="{color}">{output}</font></pre>')
        
        self.command_input.clear()
        self.output_text.verticalScrollBar().setValue(
            self.output_text.verticalScrollBar().maximum()
        )

    def run_quick_command(self, command):
        self.command_input.setText(command)
        self.execute_command()

    def use_history_item(self, item):
        self.command_input.setText(item.text())
        self.command_input.setFocus()

    def clear_output(self):
        self.output_text.clear()

    def keyPressEvent(self, event):
        if self.command_input.hasFocus():
            if event.key() == Qt.Key.Key_Up and self.command_history:
                if self.history_index > 0:
                    self.history_index -= 1
                    self.command_input.setText(self.command_history[self.history_index])
            elif event.key() == Qt.Key.Key_Down and self.command_history:
                if self.history_index < len(self.command_history) - 1:
                    self.history_index += 1
                    self.command_input.setText(self.command_history[self.history_index])
                else:
                    self.history_index = len(self.command_history)
                    self.command_input.clear()
        super().keyPressEvent(event)

class XposedHookTab(QWidget):
    """Tab for real-time Xposed module hook injection and management."""

    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.hooks = {}  # Store active hooks
        self.init_ui()


    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()

        package_group = QGroupBox("Target Package")
        package_layout = QHBoxLayout()
        self.package_input = QLineEdit()
        self.package_input.setPlaceholderText("com.example.app")
        self.refresh_button = QPushButton("Refresh Packages")
        self.analyze_apk_button = QPushButton("Analyze APK (JADX)")
        self.analyze_apk_button.setToolTip(
            "Pulls the APK of the selected package and opens it in JADX-GUI for analysis.\n"
            "Requires JADX to be in your system's PATH or in the 'tools' folder."
        )
        self.analyze_apk_button.clicked.connect(self.analyze_apk_with_jadx)
        self.refresh_button.clicked.connect(self.refresh_packages)
        self.package_combobox = QComboBox()
        # Set stretch factors to give more space to the combobox
        package_layout.addWidget(self.package_input, 1)
        package_layout.addWidget(self.package_combobox, 3)
        package_layout.addWidget(self.refresh_button, 0)

        package_layout.addWidget(self.analyze_apk_button)
        package_group.setLayout(package_layout)
        layout.addWidget(package_group)

        # Hook Configuration
        hook_group = QGroupBox("Hook Configuration")
        hook_layout = QVBoxLayout()

        method_layout = QHBoxLayout()
        self.class_input = QLineEdit()
        self.class_input.setPlaceholderText("com.example.Class")
        self.method_input = QLineEdit()
        self.method_input.setPlaceholderText("methodName")
        method_layout.addWidget(QLabel("Class:"))
        method_layout.addWidget(self.class_input)
        method_layout.addWidget(QLabel("Method:"))
        method_layout.addWidget(self.method_input)
        hook_layout.addLayout(method_layout)

        # Advanced Hooking Options
        adv_options_layout = QHBoxLayout()
        self.hook_all_methods_check = QCheckBox("Hook all methods in class")
        self.hook_all_methods_check.setToolTip("If checked, ignores the method name and hooks all declared methods in the class.")
        self.hook_constructors_check = QCheckBox("Hook constructors")
        self.hook_constructors_check.setToolTip("If checked, hooks the constructors of the class instead of a specific method.")
        adv_options_layout.addWidget(self.hook_all_methods_check)
        adv_options_layout.addWidget(self.hook_constructors_check)
        hook_layout.addLayout(adv_options_layout)

        hook_type_layout = QHBoxLayout()
        self.hook_before = QCheckBox("Before Method")
        self.hook_after = QCheckBox("After Method")
        self.hook_replace = QCheckBox("Replace Method")
        self.hook_before.setChecked(True)
        self.hook_before.setToolTip("Executes your code before the original method runs.")
        self.hook_after.setToolTip("Executes your code after the original method runs.")
        self.hook_replace.setToolTip("Replaces the original method entirely with your code. Call param.setResult() to return a value.")
        hook_type_layout.addWidget(self.hook_before)
        hook_type_layout.addWidget(self.hook_after)
        hook_type_layout.addWidget(self.hook_replace)
        hook_layout.addLayout(hook_type_layout)

        # Templates and Snippets
        template_group = QGroupBox("Templates & Snippets")
        template_layout = QVBoxLayout()
        
        self.template_combo = QComboBox()
        self.template_combo.addItems(["-- Select a Template --", "Log Method Calls", "Change Return Value", "Bypass SSL Pinning (Common)"])
        self.template_combo.currentIndexChanged.connect(self.apply_template)
        
        snippet_layout = QHBoxLayout()
        self.log_args_btn = QPushButton("Log Arguments")
        self.log_args_btn.clicked.connect(lambda: self.insert_snippet("log_args"))
        self.log_return_btn = QPushButton("Log Return Value")
        self.log_return_btn.clicked.connect(lambda: self.insert_snippet("log_return"))
        self.log_stack_btn = QPushButton("Log Stack Trace")
        self.log_stack_btn.clicked.connect(lambda: self.insert_snippet("log_stack"))
        snippet_layout.addWidget(self.log_args_btn)
        snippet_layout.addWidget(self.log_return_btn)
        snippet_layout.addWidget(self.log_stack_btn)
        
        template_layout.addWidget(self.template_combo)
        template_layout.addLayout(snippet_layout)
        template_group.setLayout(template_layout)
        hook_layout.addWidget(template_group)

        hook_code_layout = QVBoxLayout()
        hook_code_layout.addWidget(QLabel("Hook Code:"))
        self.hook_code = QTextEdit()
        self.hook_code.setPlaceholderText("// Java code for the hook\nXposedBridge.log(\"Method called: \" + param.method.getName());\nparam.setResult(null);")
        hook_code_layout.addWidget(self.hook_code)
        hook_layout.addLayout(hook_code_layout)

        hook_group.setLayout(hook_layout)
        layout.addWidget(hook_group)

        active_hooks_group = QGroupBox("Active Hooks")
        active_hooks_layout = QVBoxLayout()
        self.hooks_list = QTreeWidget()
        self.hooks_list.setHeaderLabels(["Package", "Class", "Method", "Type"])
        self.hooks_list.itemDoubleClicked.connect(self.edit_hook)
        active_hooks_layout.addWidget(self.hooks_list)
        active_hooks_group.setLayout(active_hooks_layout)
        layout.addWidget(active_hooks_group)

        log_group = QGroupBox("Hook Log")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        button_layout = QHBoxLayout()
        self.inject_button = QPushButton("Inject Hook")
        self.inject_button.clicked.connect(self.inject_hook)
        self.remove_button = QPushButton("Remove Hook")
        self.remove_button.clicked.connect(self.remove_hook)
        self.clear_button = QPushButton("Clear All")
        self.clear_button.clicked.connect(self.clear_hooks)
        button_layout.addWidget(self.inject_button)
        button_layout.addWidget(self.remove_button)
        button_layout.addWidget(self.clear_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)


    def refresh_packages(self):
        """Refresh the list of installed packages."""
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "Error", "No device connected")
            return

        try:
            return_code, result = self.device_manager.execute_adb_command(["shell", "pm", "list", "packages"])
            packages = [line.split(":")[1] for line in result.splitlines() if line.startswith("package:")]
            self.package_combobox.clear()
            self.package_combobox.addItems(sorted(packages))
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get package list: {str(e)}")

    def inject_hook(self):
        """Inject a new Xposed hook."""
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "Error", "No device connected")
            return

        package = self.package_input.text().strip()
        if not package and self.package_combobox.currentText():
            package = self.package_combobox.currentText()

        if not package:
            CopyableMessageBox.warning(self, "Error", "Please enter or select a package name")
            return

        if not package:
            CopyableMessageBox.warning(self, "Error", "Please enter or select a package name")
            return

        class_name = self.class_input.text().strip()
        method_name = self.method_input.text().strip()
        hook_code = self.hook_code.toPlainText().strip()

        hook_all = self.hook_all_methods_check.isChecked()

        if not class_name or (not method_name and not hook_all) or not hook_code:
            CopyableMessageBox.warning(self, "Error", "Please fill in all hook details")
            return

        hook_type = "before"
        if self.hook_after.isChecked():
            hook_type = "after"
        elif self.hook_replace.isChecked():
            hook_type = "replace"

        try:
            hook_id = f"{package}_{class_name}_{method_name}_{hook_type}"
            
            hook_file = self.create_hook_file(
                package,
                class_name,
                method_name,
                hook_type,
                hook_code,
                self.hook_all_methods_check.isChecked(),
                self.hook_constructors_check.isChecked()
            )


            self.device_manager.execute_adb_command(["push", hook_file, "/data/local/tmp/"])
            
            self.device_manager.execute_adb_command(["shell", "am", "broadcast", "-a", "de.robv.android.xposed.installer.LOAD_PACKAGE", "-e", "package", package])
            
            # Add to active hooks list
            item = QTreeWidgetItem([package, class_name, method_name, hook_type])
            self.hooks_list.addTopLevelItem(item)
            self.hooks[hook_id] = {
                'package': package,
                'class': class_name,
                'method': method_name,
                'type': hook_type,
                'code': hook_code
            }

            self.log_text.append(f"[+] Successfully injected hook into {package}")
        except Exception as e:
            CopyableMessageBox.warning(self, "Error", f"Failed to inject hook: {str(e)}")

    def create_hook_file(self, package, class_name, method_name, hook_type, hook_code, hook_all, hook_constructors):
        """Create a temporary file containing the hook code."""
        try:
            hook_body = f"""
            @Override
            protected void {hook_type}HookedMethod(MethodHookParam param) throws Throwable {{
                {hook_code}
            }}
            """

            if hook_all:
                find_and_hook_logic = f"""
        final Class<?> clazz = XposedHelpers.findClass("{class_name}", lpparam.classLoader);
        for (java.lang.reflect.Method method : clazz.getDeclaredMethods()) {{
            XposedBridge.hookMethod(method, new XC_MethodHook() {{
                {hook_body}
            }});
        }}
        """
            elif hook_constructors:
                find_and_hook_logic = f"""
        XposedHelpers.findAndHookConstructor("{class_name}", lpparam.classLoader, new XC_MethodHook() {{
            {hook_body}
        }});
        """
            else:
                find_and_hook_logic = f"""
        XposedHelpers.findAndHookMethod("{class_name}",
            lpparam.classLoader,
            "{method_name}",
            new XC_MethodHook() {{
            {hook_body}
            }});
        """

            hook_template = f"""
import de.robv.android.xposed.*;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Hook_{package.replace(".", "_")} implements IXposedHookLoadPackage {{
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {{
        if (!lpparam.packageName.equals("{package}"))
            return;

        {find_and_hook_logic}
    }}
}}
"""
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.java', delete=False) as f:
                f.write(hook_template.encode())
                return f.name
        except Exception as e:
            raise Exception(f"Failed to create hook file: {str(e)}")

    def remove_hook(self):
        """Remove selected hook."""
        item = self.hooks_list.currentItem()
        if not item:
            CopyableMessageBox.warning(self, "Error", "Please select a hook to remove")
            return

        package = item.text(0)
        class_name = item.text(1)
        method_name = item.text(2)
        hook_type = item.text(3)
        hook_id = f"{package}_{class_name}_{method_name}_{hook_type}"

        try:
            self.device_manager.execute_adb_command(["shell", "am", "broadcast", "-a", "de.robv.android.xposed.installer.REMOVE_PACKAGE", "-e", "package", package])
            
            self.hooks_list.takeTopLevelItem(self.hooks_list.indexOfTopLevelItem(item))
            del self.hooks[hook_id]
            
            self.log_text.append(f"[-] Successfully removed hook from {package}")
        except Exception as e:
            CopyableMessageBox.warning(self, "Error", f"Failed to remove hook: {str(e)}")

    def clear_hooks(self):
        """Remove all active hooks."""
        if not self.hooks:
            return

        try:
            for hook_id, hook in self.hooks.items():
                self.device_manager.execute_adb_command(["shell", "am", "broadcast", "-a", "de.robv.android.xposed.installer.REMOVE_PACKAGE", "-e", "package", hook['package']])
            
            self.hooks.clear()
            self.hooks_list.clear()
            self.log_text.append("[*] Cleared all hooks")
        except Exception as e:
            CopyableMessageBox.warning(self, "Error", f"Failed to clear hooks: {str(e)}")

    def edit_hook(self, item):
        """Edit an existing hook."""
        package = item.text(0)
        class_name = item.text(1)
        method_name = item.text(2)
        hook_type = item.text(3)
        hook_id = f"{package}_{class_name}_{method_name}_{hook_type}"

        if hook_id in self.hooks:
            hook = self.hooks[hook_id]
            self.package_input.setText(hook['package'])
            self.class_input.setText(hook['class'])
            self.method_input.setText(hook['method'])
            self.hook_code.setText(hook['code'])
            
            self.hook_before.setChecked(hook['type'] == 'before')
            self.hook_after.setChecked(hook['type'] == 'after')
            self.hook_replace.setChecked(hook['type'] == 'replace')

    def apply_template(self, index):
        """Applies a selected code template to the editor."""
        template = self.template_combo.currentText()
        if index == 0: # "-- Select a Template --"
            return

        code = ""
        if template == "Log Method Calls":
            code = """
String methodName = param.method.getName();
XposedBridge.log(">>> Method call: " + methodName);

for (int i = 0; i < param.args.length; i++) {
    XposedBridge.log("  arg[" + i + "]: " + param.args[i]);
}
"""
        elif template == "Change Return Value":
            self.hook_after.setChecked(True)
            code = """
// Change the return value to something else
// Example: return true for a method that returns a boolean
param.setResult(true);
XposedBridge.log("Changed return value to: " + param.getResult());
"""
        elif template == "Bypass SSL Pinning (Common)":
            self.class_input.setText("javax.net.ssl.TrustManagerFactory")
            self.method_input.setText("getTrustManagers")
            self.hook_after.setChecked(True)
            code = """
XposedBridge.log("Bypassing SSL Pinning by replacing TrustManager...");
param.setResult(new javax.net.ssl.TrustManager[] {
    new javax.net.ssl.X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
    }
});
"""
        self.hook_code.setPlainText(code)
        self.template_combo.setCurrentIndex(0) # Reset combo box

    def insert_snippet(self, snippet_type):
        """Inserts a code snippet at the current cursor position."""
        cursor = self.hook_code.textCursor()
        code = ""
        if snippet_type == "log_args":
            code = """
for (int i = 0; i < param.args.length; i++) {
    XposedBridge.log("arg[" + i + "]: " + String.valueOf(param.args[i]));
}
"""
        elif snippet_type == "log_return":
            code = "XposedBridge.log(\"Return value: \" + String.valueOf(param.getResult()));"
        elif snippet_type == "log_stack":
            code = "XposedBridge.log(android.util.Log.getStackTraceString(new Throwable()));"

        cursor.insertText(code)

    def analyze_apk_with_jadx(self):
        """Pulls the APK and opens it with JADX GUI."""
        package = self.package_input.text().strip() or self.package_combobox.currentText()
        if not package:
            CopyableMessageBox.warning(self, "Error", "Please select a package to analyze.")
            return

        # Find JADX
        jadx_path = shutil.which("jadx-gui") or shutil.which("jadx-gui.bat")
        if not jadx_path:
            reply = QMessageBox.question(self, "JADX Not Found",
                                         "JADX GUI not found in your system's PATH.\n"
                                         "Would you like to download it now?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                webbrowser.open("https://github.com/skylot/jadx/releases")
            return

        # Pull APK
        self.log_text.append(f"Finding APK path for {package}...")
        code, path_output = self.device_manager.execute_adb_command(["shell", "pm", "path", package])
        if code != 0 or not path_output.startswith("package:"):
            CopyableMessageBox.warning(self, "Error", f"Could not find APK path for {package}.")
            return

        apk_path_on_device = path_output.replace("package:", "").strip()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            local_apk_path = os.path.join(tmpdir, f"{package}.apk")
            self.log_text.append(f"Pulling APK to {local_apk_path}...")
            pull_code, pull_output = self.device_manager.execute_adb_command(["pull", apk_path_on_device, local_apk_path])

            if pull_code == 0 and os.path.exists(local_apk_path):
                self.log_text.append("APK pulled successfully. Starting JADX GUI...")
                subprocess.Popen([jadx_path, local_apk_path])
            else:
                CopyableMessageBox.warning(self, "Error", f"Failed to pull APK: {pull_output}")

class MonkeyTesterTab(QWidget):
    """Tab for Monkey testing Android applications."""

    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()

        package_group = QGroupBox("Target Package")
        package_layout = QHBoxLayout()
        self.package_input = QLineEdit()
        self.package_input.setPlaceholderText("com.example.app")
        self.refresh_button = QPushButton("Refresh Packages")
        self.refresh_button.clicked.connect(self.refresh_packages)
        self.package_combobox = QComboBox()
        
        # Set stretch factors to give more space to the combobox
        package_layout.addWidget(self.package_input, 1)
        package_layout.addWidget(self.package_combobox, 2)
        package_layout.addWidget(self.refresh_button, 0)
        
        package_group.setLayout(package_layout)
        layout.addWidget(package_group)

        config_group = QGroupBox("Test Configuration")
        config_layout = QFormLayout()

        self.event_count = QSpinBox()
        self.event_count.setRange(1, 1000000)
        self.event_count.setValue(1000)
        config_layout.addRow("Event Count:", self.event_count)

        # Throttle (delay between events)
        self.throttle = QSpinBox()
        self.throttle.setRange(0, 1000)
        self.throttle.setValue(100)
        config_layout.addRow("Throttle (ms):", self.throttle)

        self.seed = QSpinBox()
        self.seed.setRange(-2147483648, 2147483647)
        self.seed.setValue(0)
        config_layout.addRow("Random Seed:", self.seed)

        self.touch_pct = QSpinBox()
        self.touch_pct.setRange(0, 100)
        self.touch_pct.setValue(25)
        config_layout.addRow("Touch %:", self.touch_pct)

        self.motion_pct = QSpinBox()
        self.motion_pct.setRange(0, 100)
        self.motion_pct.setValue(25)
        config_layout.addRow("Motion %:", self.motion_pct)

        self.nav_pct = QSpinBox()
        self.nav_pct.setRange(0, 100)
        self.nav_pct.setValue(25)
        config_layout.addRow("Nav Keys %:", self.nav_pct)

        self.system_pct = QSpinBox()
        self.system_pct.setRange(0, 100)
        self.system_pct.setValue(25)
        config_layout.addRow("System Keys %:", self.system_pct)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()

        self.ignore_crashes = QCheckBox("Ignore Crashes")
        self.ignore_timeouts = QCheckBox("Ignore Timeouts")
        self.ignore_security = QCheckBox("Ignore Security Exceptions")
        self.kill_process = QCheckBox("Kill Process at End")
        self.monitor_native = QCheckBox("Monitor Native Crashes")
        self.dbg_no_events = QCheckBox("Debug No Events")
        
        advanced_layout.addWidget(self.ignore_crashes)
        advanced_layout.addWidget(self.ignore_timeouts)
        advanced_layout.addWidget(self.ignore_security)
        advanced_layout.addWidget(self.kill_process)
        advanced_layout.addWidget(self.monitor_native)
        advanced_layout.addWidget(self.dbg_no_events)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Test")
        self.start_button.clicked.connect(self.start_monkey_test)
        self.stop_button = QPushButton("Stop Test")
        self.stop_button.clicked.connect(self.stop_monkey_test)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.monkey_process = None

    def refresh_packages(self):
        """Refresh the list of installed packages."""
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "Error", "No device connected")
            return

        try:
            return_code, result = self.device_manager.execute_adb_command(["shell", "pm", "list", "packages"])
            packages = [line.split(":")[1] for line in result.splitlines() if line.startswith("package:")]
            self.package_combobox.clear()
            self.package_combobox.addItems(sorted(packages))
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get package list: {str(e)}")

    def start_monkey_test(self):
        """Start the monkey test with current configuration."""
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "Error", "No device connected")
            return

        package = self.package_input.text().strip()
        if not package and self.package_combobox.currentText():
            package = self.package_combobox.currentText()

        if not package:
            CopyableMessageBox.warning(self, "Error", "Please enter or select a package name")
            return

        cmd = ["monkey", "-p", package]
        
        if self.seed.value() != 0:
            cmd.extend(["-s", str(self.seed.value())])
        if self.throttle.value() != 0:
            cmd.extend(["--throttle", str(self.throttle.value())])
        if self.ignore_crashes.isChecked():
            cmd.append("--ignore-crashes")
        if self.ignore_timeouts.isChecked():
            cmd.append("--ignore-timeouts")
        if self.ignore_security.isChecked():
            cmd.append("--ignore-security-exceptions")
        if self.kill_process.isChecked():
            cmd.append("--kill-process-after-error")
        if self.monitor_native.isChecked():
            cmd.append("--monitor-native-crashes")
        if self.dbg_no_events.isChecked():
            cmd.append("--dbg-no-events")

        if self.touch_pct.value() != 0:
            cmd.extend(["--pct-touch", str(self.touch_pct.value())])
        if self.motion_pct.value() != 0:
            cmd.extend(["--pct-motion", str(self.motion_pct.value())])
        if self.nav_pct.value() != 0:
            cmd.extend(["--pct-nav", str(self.nav_pct.value())])
        if self.system_pct.value() != 0:
            cmd.extend(["--pct-syskeys", str(self.system_pct.value())])

        cmd.append(str(self.event_count.value()))

        try:
            self.output_text.clear()
            self.monkey_process = QProcess()
            self.monkey_process.readyReadStandardOutput.connect(
                lambda: self.handle_output(self.monkey_process.readAllStandardOutput()))
            self.monkey_process.readyReadStandardError.connect(
                lambda: self.handle_output(self.monkey_process.readAllStandardError()))
            self.monkey_process.finished.connect(self.handle_finished)

            adb_path = "adb"  # Adjust if needed
            device_id = self.device_manager.current_device
            full_cmd = [adb_path, "-s", device_id, "shell"] + cmd
            
            self.monkey_process.start(full_cmd[0], full_cmd[1:])
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
        except Exception as e:
            CopyableMessageBox.warning(self, "Error", f"Failed to start monkey test: {str(e)}")

    def stop_monkey_test(self):
        """Stop the currently running monkey test."""
        if self.monkey_process and self.monkey_process.state() == QProcess.Running:
            self.monkey_process.kill()

    def handle_output(self, output):
        """Handle output from the monkey test process."""
        text = bytes(output).decode()
        self.output_text.append(text)
        
    def handle_finished(self, exit_code, exit_status):
        """Handle monkey test process completion."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.monkey_process = None

        if exit_code != 0:
            self.output_text.append(f"\nMonkey test failed with exit code {exit_code}")
        else:
            self.output_text.append("\nMonkey test completed successfully")

class DevicePropertiesTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.init_ui()
        self.refresh_properties()

    def init_ui(self):
        layout = QVBoxLayout()

        controls_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_properties)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by property or value...")
        self.search_input.textChanged.connect(self.filter_properties)
        
        self.export_btn = QPushButton("💾 Export")
        self.export_btn.clicked.connect(self.export_properties)
        
        controls_layout.addWidget(self.refresh_btn)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.search_input)
        controls_layout.addWidget(self.export_btn)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Property", "Value", "Description"])
        self.tree.setColumnWidth(0, 250)  # Property name
        self.tree.setColumnWidth(1, 300)  # Value
        self.tree.setColumnWidth(2, 400)  # Description
        self.tree.setAlternatingRowColors(True)
        font = self.tree.font()
        font.setPointSize(10)
        self.tree.setFont(font)

        self.categories = {
            "System": ["ro.build.", "ro.product.", "ro.system.", "ro.bootloader", "ro.hardware"],
            "Display": ["ro.sf.", "init.svc.surfaceflinger", "display.", "debug.sf."],
            "CPU/Memory": ["ro.boot.hardware", "ro.arch", "ro.dalvik.", "dalvik.", "ro.kernel."],
            "Security": ["ro.boot.secure", "ro.secure", "ro.debuggable", "persist.sys.usb.config"],
            "Network": ["dhcp.", "net.", "wifi.", "bluetooth.", "telephony."],
            "Storage": ["ro.crypto.", "vold.", "persist.sys.usb.", "sys.usb."],
            "Vendor": ["ro.vendor.", "vendor.", "persist.vendor."],
            "Other": []
        }

        layout.addLayout(controls_layout)
        layout.addWidget(self.tree)
        self.setLayout(layout)

    def refresh_properties(self):
        self.tree.clear()
        return_code, output = self.device_manager.execute_adb_command("shell getprop")
        if return_code != 0:
            self.tree.addTopLevelItem(QTreeWidgetItem(["Error", output, ""]))
            return

        properties = {}
        for line in output.splitlines():
            if not line.strip():
                continue
            
            match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line)
            if match:
                prop_name = match.group(1)
                prop_value = match.group(2)
                properties[prop_name] = prop_value

        category_items = {cat: QTreeWidgetItem([cat, "", ""]) for cat in self.categories}
        for cat_item in category_items.values():
            self.tree.addTopLevelItem(cat_item)
            cat_item.setExpanded(True)

        uncategorized = []
        for prop_name, prop_value in properties.items():
            categorized = False
            for cat_name, patterns in self.categories.items():
                if any(prop_name.startswith(pattern) for pattern in patterns):
                    item = QTreeWidgetItem([prop_name, prop_value, self.get_property_description(prop_name)])
                    category_items[cat_name].addChild(item)
                    categorized = True
                    break
            
            if not categorized:
                uncategorized.append((prop_name, prop_value))

        other_item = category_items["Other"]
        for prop_name, prop_value in sorted(uncategorized):
            item = QTreeWidgetItem([prop_name, prop_value, self.get_property_description(prop_name)])
            other_item.addChild(item)

    def filter_properties(self):
        filter_text = self.filter_input.text().lower()
        
        def filter_item(item):
            if not filter_text:
                return True
                
            for i in range(item.columnCount()):
                if filter_text in item.text(i).lower():
                    return True
                    
            for i in range(item.childCount()):
                if filter_item(item.child(i)):
                    return True
                    
            return False

        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            item.setHidden(not filter_item(item))
            
            # Show all children that match filter
            for j in range(item.childCount()):
                child = item.child(j)
                child.setHidden(not filter_item(child))

    def export_properties(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Properties",
            os.path.expanduser("~") + "/device_properties.txt",
            "Text Files (*.txt)"
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                for i in range(self.tree.topLevelItemCount()):
                    category = self.tree.topLevelItem(i)
                    f.write(f"\n[{category.text(0)}]\n")
                    
                    for j in range(category.childCount()):
                        prop = category.child(j)
                        f.write(f"{prop.text(0)} = {prop.text(1)}\n")
                        if prop.text(2):
                            f.write(f"# {prop.text(2)}\n")
            
            CopyableMessageBox.information(self, "Success", "Properties exported successfully!")

    def get_property_description(self, prop_name):
        """Return a description for common properties."""
        descriptions = {
            "ro.build.version.release": "Android version",
            "ro.build.version.sdk": "API level",
            "ro.product.model": "Device model name",
            "ro.product.manufacturer": "Device manufacturer",
            "ro.serialno": "Device serial number",
            "ro.build.fingerprint": "Build fingerprint",
            "ro.build.type": "Build type (user, eng, etc.)",
            "ro.secure": "Security status",
            "ro.debuggable": "Debug status",
            "ro.hardware": "Hardware platform",
            "ro.boot.hardware": "Boot hardware",
            "ro.revision": "Hardware revision",
            "ro.bootloader": "Bootloader version",
            "ro.build.date": "Build date",
            "ro.build.tags": "Build tags",
            "persist.sys.usb.config": "USB configuration",
            "ro.crypto.state": "Encryption status",
            "gsm.version.baseband": "Baseband version",
        }
        return descriptions.get(prop_name, "")

class FastbootTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()  # Thread safety for fastboot operations
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        flash_group = QGroupBox("Flash Options")
        flash_layout = QVBoxLayout()
        
        partition_group = QGroupBox("Partitions")
        partition_layout = QGridLayout()
        
        self.boot_check = QCheckBox("boot")
        self.system_check = QCheckBox("system")
        self.vendor_check = QCheckBox("vendor")
        self.recovery_check = QCheckBox("recovery")
        self.cache_check = QCheckBox("cache")
        self.userdata_check = QCheckBox("userdata")
        self.custom_part_edit = QLineEdit()
        self.custom_part_edit.setPlaceholderText("Custom partition")
        
        partition_layout.addWidget(self.boot_check, 0, 0)
        partition_layout.addWidget(self.system_check, 0, 1)
        partition_layout.addWidget(self.vendor_check, 0, 2)
        partition_layout.addWidget(self.recovery_check, 1, 0)
        partition_layout.addWidget(self.cache_check, 1, 1)
        partition_layout.addWidget(self.userdata_check, 1, 2)
        partition_layout.addWidget(QLabel("Custom:"), 2, 0)
        partition_layout.addWidget(self.custom_part_edit, 2, 1, 1, 2)
        
        partition_group.setLayout(partition_layout)
        
        image_group = QGroupBox("Image Files")
        image_layout = QVBoxLayout()
        
        self.boot_img_edit = QLineEdit()
        self.boot_img_edit.setPlaceholderText("boot.img path")
        self.boot_img_browse = QPushButton("Browse...")
        self.boot_img_browse.clicked.connect(lambda: self.browse_image(self.boot_img_edit))
        
        self.system_img_edit = QLineEdit()
        self.system_img_edit.setPlaceholderText("system.img path")
        self.system_img_browse = QPushButton("Browse...")
        self.system_img_browse.clicked.connect(lambda: self.browse_image(self.system_img_edit))
        
        self.vendor_img_edit = QLineEdit()
        self.vendor_img_edit.setPlaceholderText("vendor.img path")
        self.vendor_img_browse = QPushButton("Browse...")
        self.vendor_img_browse.clicked.connect(lambda: self.browse_image(self.vendor_img_edit))
        
        self.recovery_img_edit = QLineEdit()
        self.recovery_img_edit.setPlaceholderText("recovery.img path")
        self.recovery_img_browse = QPushButton("Browse...")
        self.recovery_img_browse.clicked.connect(lambda: self.browse_image(self.recovery_img_edit))
        
        self.cache_img_edit = QLineEdit()
        self.cache_img_edit.setPlaceholderText("cache.img path")
        self.cache_img_browse = QPushButton("Browse...")
        self.cache_img_browse.clicked.connect(lambda: self.browse_image(self.cache_img_edit))
        
        self.userdata_img_edit = QLineEdit()
        self.userdata_img_edit.setPlaceholderText("userdata.img path")
        self.userdata_img_browse = QPushButton("Browse...")
        self.userdata_img_browse.clicked.connect(lambda: self.browse_image(self.userdata_img_edit))
        
        self.custom_img_edit = QLineEdit()
        self.custom_img_edit.setPlaceholderText("Custom image path")
        self.custom_img_browse = QPushButton("Browse...")
        self.custom_img_browse.clicked.connect(lambda: self.browse_image(self.custom_img_edit))
        
        def add_image_row(label, edit, browse):
            row = QHBoxLayout()
            row.addWidget(QLabel(label))
            row.addWidget(edit)
            row.addWidget(browse)
            return row
        
        image_layout.addLayout(add_image_row("Boot:", self.boot_img_edit, self.boot_img_browse))
        image_layout.addLayout(add_image_row("System:", self.system_img_edit, self.system_img_browse))
        image_layout.addLayout(add_image_row("Vendor:", self.vendor_img_edit, self.vendor_img_browse))
        image_layout.addLayout(add_image_row("Recovery:", self.recovery_img_edit, self.recovery_img_browse))
        image_layout.addLayout(add_image_row("Cache:", self.cache_img_edit, self.cache_img_browse))
        image_layout.addLayout(add_image_row("Userdata:", self.userdata_img_edit, self.userdata_img_browse))
        image_layout.addLayout(add_image_row("Custom:", self.custom_img_edit, self.custom_img_browse))
        
        image_group.setLayout(image_layout)
        
        flash_btn_layout = QHBoxLayout()
        self.flash_selected_btn = QPushButton("Flash Selected")
        self.flash_selected_btn.clicked.connect(self.flash_selected)
        self.flash_all_btn = QPushButton("Flash All")
        self.flash_all_btn.clicked.connect(self.flash_all)
        
        flash_btn_layout.addWidget(self.flash_selected_btn)
        flash_btn_layout.addWidget(self.flash_all_btn)
        
        flash_layout.addWidget(partition_group)
        flash_layout.addWidget(image_group)
        flash_layout.addLayout(flash_btn_layout)
        flash_group.setLayout(flash_layout)
        
        advanced_group = QGroupBox("Advanced Fastboot Commands")
        advanced_layout = QVBoxLayout()
        
        unlock_layout = QHBoxLayout()
        self.unlock_btn = QPushButton("Unlock Bootloader")
        self.lock_btn = QPushButton("Lock Bootloader")
        self.unlock_critical_btn = QPushButton("Unlock Critical")
        self.lock_critical_btn = QPushButton("Lock Critical")
        
        self.unlock_btn.clicked.connect(lambda: self.execute_fastboot_command("flashing unlock"))
        self.lock_btn.clicked.connect(lambda: self.execute_fastboot_command("flashing lock"))
        self.unlock_critical_btn.clicked.connect(lambda: self.execute_fastboot_command("flashing unlock_critical"))
        self.lock_critical_btn.clicked.connect(lambda: self.execute_fastboot_command("flashing lock_critical"))
        
        unlock_layout.addWidget(self.unlock_btn)
        unlock_layout.addWidget(self.lock_btn)
        unlock_layout.addWidget(self.unlock_critical_btn)
        unlock_layout.addWidget(self.lock_critical_btn)
        
        other_layout = QHBoxLayout()
        self.erase_btn = QPushButton("Erase Partition")
        self.erase_btn.clicked.connect(self.erase_partition)
        
        self.format_btn = QPushButton("Format Partition")
        self.format_btn.clicked.connect(self.format_partition)
        
        self.boot_btn = QPushButton("Boot Image")
        self.boot_btn.clicked.connect(self.boot_image)
        
        self.set_active_btn = QPushButton("Set Active Slot")
        self.set_active_btn.clicked.connect(self.set_active_slot)
        
        other_layout.addWidget(self.erase_btn)
        other_layout.addWidget(self.format_btn)
        other_layout.addWidget(self.boot_btn)
        other_layout.addWidget(self.set_active_btn)
        
        advanced_layout.addLayout(unlock_layout)
        advanced_layout.addLayout(other_layout)
        advanced_group.setLayout(advanced_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        
        layout.addWidget(flash_group)
        layout.addWidget(advanced_group)
        layout.addWidget(self.output_text)
        
        self.setLayout(layout)

    def browse_image(self, target_edit):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image File", "", "Image Files (*.img);;All Files (*)"
        )
        
        if file_path:
            target_edit.setText(os.path.normpath(file_path))

    def flash_selected(self):
        with self.lock:  # Thread-safe operation
            partitions = []
            images = []
            
            if self.boot_check.isChecked() and self.boot_img_edit.text():
                partitions.append("boot")
                images.append(self.boot_img_edit.text())
            
            if self.system_check.isChecked() and self.system_img_edit.text():
                partitions.append("system")
                images.append(self.system_img_edit.text())
            
            if self.vendor_check.isChecked() and self.vendor_img_edit.text():
                partitions.append("vendor")
                images.append(self.vendor_img_edit.text())
            
            if self.recovery_check.isChecked() and self.recovery_img_edit.text():
                partitions.append("recovery")
                images.append(self.recovery_img_edit.text())
            
            if self.cache_check.isChecked() and self.cache_img_edit.text():
                partitions.append("cache")
                images.append(self.cache_img_edit.text())
            
            if self.userdata_check.isChecked() and self.userdata_img_edit.text():
                partitions.append("userdata")
                images.append(self.userdata_img_edit.text())
            
            custom_part = self.custom_part_edit.text().strip()
            custom_img = self.custom_img_edit.text().strip()
            if custom_part and custom_img:
                partitions.append(custom_part)
                images.append(custom_img)
            
            if not partitions:
                CopyableMessageBox.warning(self, "Error", "No partitions selected or image paths not specified")
                return
            
            confirm = QMessageBox.question(
                self, "Confirm Flash", 
                f"Are you sure you want to flash {len(partitions)} partition(s)? This cannot be undone!",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if confirm == QMessageBox.StandardButton.Yes:
                self.output_text.clear()
                
                for part, img in zip(partitions, images):
                    try:
                        self.append_output(f"Flashing {part} with {img}...")
                        cmd_list = ["flash", part, img]
                        return_code, output = self.device_manager.execute_fastboot_command(
                            cmd_list, timeout=300)
                        self.append_output(output)
                        
                        if return_code != 0:
                            self.append_output(f"Failed to flash {part}")
                            break
                        else:
                            self.append_output(f"Successfully flashed {part}")
                    except Exception as e:
                        self.append_output(f"Error flashing {part}: {str(e)}")
                        break
                
                self.append_output("Flash operation completed")

    def flash_all(self):
        with self.lock:  # Thread-safe operation
            partitions = ["boot", "system", "vendor", "recovery", "cache", "userdata"]
            images = [
                self.boot_img_edit.text(),
                self.system_img_edit.text(),
                self.vendor_img_edit.text(),
                self.recovery_img_edit.text(),
                self.cache_img_edit.text(),
                self.userdata_img_edit.text()
            ]
            
            for img in images:
                if not img:
                    CopyableMessageBox.warning(self, "Error", "All image paths must be specified for flash all")
                    return
            
            confirm = QMessageBox.question(
                self, "Confirm Flash All", 
                "Are you sure you want to flash ALL partitions? This will wipe your device!",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if confirm == QMessageBox.StandardButton.Yes:
                self.output_text.clear()
                
                for part, img in zip(partitions, images):
                    try:
                        self.append_output(f"Flashing {part} with {img}...")
                        cmd_list = ["flash", part, img]
                        return_code, output = self.device_manager.execute_fastboot_command(
                            cmd_list, timeout=300)
                        self.append_output(output)
                        
                        if return_code != 0:
                            self.append_output(f"Failed to flash {part}")
                            break
                        else:
                            self.append_output(f"Successfully flashed {part}")
                    except Exception as e:
                        self.append_output(f"Error flashing {part}: {str(e)}")
                        break
                
                self.append_output("Flash all operation completed")

    def execute_fastboot_command(self, command):
        if not self.device_manager.current_device:
            CopyableMessageBox.warning(self, "Error", "No device connected in fastboot mode")
            return
        
        confirm = QMessageBox.question(
            self, "Confirm Command", 
            f"Are you sure you want to execute: fastboot {command}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:  # Thread-safe operation
                self.output_text.clear()
                self.append_output(f"Executing: fastboot {command}")
                
                try:
                    return_code, output = self.device_manager.execute_fastboot_command(shlex.split(command), timeout=60)
                    self.append_output(output)
                    
                    if return_code == 0:
                        self.append_output("Command executed successfully")
                    else:
                        self.append_output("Command failed")
                except Exception as e:
                    self.append_output(f"Error executing command: {str(e)}")

    def erase_partition(self):
        partition, ok = QInputDialog.getText(
            self, "Erase Partition", "Enter partition to erase:"
        )
        
        if ok and partition:
            self.execute_fastboot_command(["erase", partition.strip()])

    def format_partition(self):
        partition, ok = QInputDialog.getText(
            self, "Format Partition", "Enter partition to format:"
        )
        
        if ok and partition:
            self.execute_fastboot_command(["format", partition.strip()])

    def boot_image(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Boot Image", "", "Image Files (*.img);;All Files (*)"
        )
        
        if file_path:
            self.execute_fastboot_command(["boot", os.path.normpath(file_path)])

    def set_active_slot(self):
        slot, ok = QInputDialog.getText(
            self, "Set Active Slot", "Enter slot (a or b):"
        )
        
        if ok and slot.lower() in ['a', 'b']:
            self.execute_fastboot_command([f"--set-active={slot.lower()}"])
        elif ok:
            CopyableMessageBox.warning(self, "Error", "Slot must be 'a' or 'b'")

    def append_output(self, text):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n")
        self.output_text.setTextCursor(cursor)
        self.output_text.ensureCursorVisible()

class RomModificationsTab(QWidget):
    """Tab for applying common ROM modifications on rooted devices."""

    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.init_ui()
        # Connect signals to read current settings when the tab is shown or device changes
        self.device_manager.device_details_updated.connect(self.read_all_current_settings)

    def showEvent(self, event):
        self.device_manager.device_details_updated.connect(self.read_current_animation_scales)

    def showEvent(self, event):
        self.read_current_animation_scales()

    def init_ui(self):
        layout = QVBoxLayout(self)
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # --- Main container for all modification widgets ---
        mods_container = QWidget()
        grid_layout = QGridLayout(mods_container)
        grid_layout.setSpacing(15)

        # --- Column 1: Visual & Display ---
        col1_widget = QWidget()
        col1_layout = QVBoxLayout(col1_widget)
        col1_layout.setSpacing(10)

        # Visual Mods
        visual_group = QGroupBox("Visual Modifications")
        visual_layout = QFormLayout(visual_group)
        # Boot Animation
        self.boot_anim_path = QLineEdit()
        self.boot_anim_path.setPlaceholderText("Path to bootanimation.zip")
        boot_anim_browse_btn = QPushButton("Browse...")
        boot_anim_browse_btn.clicked.connect(self.browse_boot_animation)
        apply_boot_anim_btn = QPushButton("Apply Boot Animation")
        apply_boot_anim_btn.clicked.connect(self.apply_boot_animation)
        visual_layout.addRow(self.boot_anim_path, boot_anim_browse_btn)
        visual_layout.addRow(apply_boot_anim_btn)
        # Font
        self.font_path = QLineEdit()
        self.font_path.setPlaceholderText("Path to font.ttf")
        font_browse_btn = QPushButton("Browse...")
        font_browse_btn.clicked.connect(self.browse_font)
        apply_font_btn = QPushButton("Apply System Font")
        apply_font_btn.clicked.connect(self.apply_font)
        visual_layout.addRow(self.font_path, font_browse_btn)
        visual_layout.addRow(apply_font_btn)
        col1_layout.addWidget(visual_group)

        # Display Tweaks
        display_group = QGroupBox("Display Tweaks")
        display_layout = QFormLayout(display_group)
        # DPI
        dpi_layout = QHBoxLayout()
        self.dpi_spinbox = QSpinBox()
        self.dpi_spinbox.setRange(120, 640); self.dpi_spinbox.setSingleStep(10); self.dpi_spinbox.setValue(320)
        apply_dpi_btn = QPushButton("Apply"); apply_dpi_btn.clicked.connect(self.apply_dpi)
        reset_dpi_btn = QPushButton("Reset"); reset_dpi_btn.clicked.connect(self.reset_dpi)
        dpi_layout.addWidget(self.dpi_spinbox); dpi_layout.addWidget(apply_dpi_btn); dpi_layout.addWidget(reset_dpi_btn)
        display_layout.addRow("Screen Density (DPI):", dpi_layout)
        # Animation Scales
        self.window_anim_combo = QComboBox(); self.transition_anim_combo = QComboBox(); self.animator_duration_combo = QComboBox()
        self.anim_scales_map = {"0.0x (Off)": "0.0", "0.5x": "0.5", "1.0x (Default)": "1.0", "1.5x": "1.5", "2.0x": "2.0"}
        for combo in [self.window_anim_combo, self.transition_anim_combo, self.animator_duration_combo]:
            combo.addItems(self.anim_scales_map.keys()); combo.setCurrentText("1.0x (Default)")
        apply_anim_btn = QPushButton("Apply Animation Scales"); apply_anim_btn.clicked.connect(self.apply_animation_scales)
        display_layout.addRow("Window Animation:", self.window_anim_combo)
        display_layout.addRow("Transition Animation:", self.transition_anim_combo)
        display_layout.addRow("Animator Duration:", self.animator_duration_combo)
        display_layout.addRow(apply_anim_btn)
        # Immersive Mode
        immersive_combo = QComboBox(); immersive_combo.addItems(["Disable", "Hide Status Bar", "Hide Navigation Bar", "Full Immersive"])
        immersive_combo.activated.connect(self.set_immersive_mode)
        display_layout.addRow("Immersive Mode:", immersive_combo)
        col1_layout.addWidget(display_group)
        col1_layout.addStretch()

        # --- Column 2: System & Network ---
        col2_widget = QWidget()
        col2_layout = QVBoxLayout(col2_widget)
        col2_layout.setSpacing(10)

        # System Tweaks
        system_group = QGroupBox("System Tweaks")
        system_layout = QFormLayout(system_group)
        # Hosts
        hosts_layout = QHBoxLayout()
        apply_hosts_btn = QPushButton("Block Ads"); apply_hosts_btn.clicked.connect(self.apply_adblock_hosts)
        restore_hosts_btn = QPushButton("Restore"); restore_hosts_btn.clicked.connect(self.restore_hosts)
        edit_hosts_btn = QPushButton("Edit"); edit_hosts_btn.clicked.connect(self.edit_hosts)
        hosts_layout.addWidget(apply_hosts_btn); hosts_layout.addWidget(restore_hosts_btn); hosts_layout.addWidget(edit_hosts_btn)
        system_layout.addRow("Hosts File:", hosts_layout)
        # SELinux
        selinux_layout = QHBoxLayout()
        permissive_btn = QPushButton("Permissive"); permissive_btn.clicked.connect(lambda: self.set_selinux_mode(0))
        enforcing_btn = QPushButton("Enforcing"); enforcing_btn.clicked.connect(lambda: self.set_selinux_mode(1))
        selinux_layout.addWidget(permissive_btn); selinux_layout.addWidget(enforcing_btn)
        system_layout.addRow("SELinux Mode:", selinux_layout)
        # Nav Bar
        nav_bar_layout = QHBoxLayout()
        enable_nav_btn = QPushButton("Enable"); enable_nav_btn.clicked.connect(lambda: self.toggle_nav_bar(True))
        disable_nav_btn = QPushButton("Disable"); disable_nav_btn.clicked.connect(lambda: self.toggle_nav_bar(False))
        nav_bar_layout.addWidget(enable_nav_btn); nav_bar_layout.addWidget(disable_nav_btn)
        system_layout.addRow("On-Screen Nav Bar:", nav_bar_layout)
        col2_layout.addWidget(system_group)

        # Network Tweaks
        network_group = QGroupBox("Network Tweaks")
        network_layout = QFormLayout(network_group)
        # DNS
        dns_combo = QComboBox(); dns_combo.addItems(["Default", "Cloudflare", "Google", "Quad9"])
        apply_dns_btn = QPushButton("Set Private DNS"); apply_dns_btn.clicked.connect(lambda: self.set_private_dns(dns_combo.currentText()))
        network_layout.addRow("Private DNS:", dns_combo)
        network_layout.addRow(apply_dns_btn)
        # TCP Congestion
        self.tcp_congestion_combo = QComboBox(); self.tcp_congestion_combo.addItems(["cubic", "reno", "bbr", "westwood"])
        apply_tcp_btn = QPushButton("Apply TCP Congestion"); apply_tcp_btn.clicked.connect(self.apply_tcp_congestion)
        network_layout.addRow("TCP Congestion:", self.tcp_congestion_combo)
        network_layout.addRow(apply_tcp_btn)
        col2_layout.addWidget(network_group)
        col2_layout.addStretch()

        # Add columns to grid
        grid_layout.addWidget(col1_widget, 0, 0)
        grid_layout.addWidget(col2_widget, 0, 1)

        # --- Output Log ---
        log_group = QGroupBox("Output Log")
        log_layout = QVBoxLayout(log_group)
        self.output_browser = QTextBrowser()
        self.output_browser.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.output_browser)

        main_splitter.addWidget(mods_container)
        main_splitter.addWidget(log_group)
        main_splitter.setSizes([450, 150]) # Give more space to mods
        layout.addWidget(main_splitter)

    def read_all_current_settings(self):
        """Reads all relevant settings from the device to update the UI."""
        if not self.device_manager.current_device:
            return

        settings_to_read = {
            "window_animation_scale": self.window_anim_combo,
            "transition_animation_scale": self.transition_anim_combo,
            "animator_duration_scale": self.animator_duration_combo
        }

        for setting, combo in settings_to_read.items():
            code, value = self.device_manager.execute_adb_command(["shell", "settings", "get", "global", setting])
            if code == 0 and value.strip():
                value_str = value.strip()
                for text, val in self.anim_scales_map.items():
                    if val == value_str:
                        combo.setCurrentText(text)
                        break

    def apply_animation_scales(self):
        if not self.device_manager.current_device:
            CopyableMessageBox.warning(self, "Error", "No device selected #019")
            return
        self.append_output("--- Applying Animation Scales ---", "yellow")
        
        scales_to_apply = {
            "window_animation_scale": self.anim_scales_map[self.window_anim_combo.currentText()],
            "transition_animation_scale": self.anim_scales_map[self.transition_anim_combo.currentText()],
            "animator_duration_scale": self.anim_scales_map[self.animator_duration_combo.currentText()]
        }

        all_successful = True
        for setting, value in scales_to_apply.items():
            code, out = self.device_manager.execute_adb_command(["shell", "settings", "put", "global", setting, value])
            if code == 0:
                self.append_output(f"Successfully set {setting} to {value}", "lime")
            else:
                self.append_output(f"Failed to set {setting}: {out}", "red")
                all_successful = False
        
    def read_current_animation_scales(self):
        """Reads current animation scales from the device and updates the UI."""
        # This method is kept for compatibility with showEvent, but the main logic
        # is now in read_all_current_settings.
        self.read_all_current_settings()

    def append_output(self, text, color="white"):
        self.output_browser.append(f'<font color="{color}">{text}</font>')

    def _run_root_operation(self, title, warning, operation_func, *args):
        if not self.device_manager.current_device:
            CopyableMessageBox.warning(self, "Error", "No device selected #020")
            return

        code, _ = self.device_manager.execute_adb_command(["shell", "su", "-c", "echo Root check"])
        if code != 0:
            CopyableMessageBox.warning(self, "Root Required", "This operation requires root access.")
            return

        confirm = QMessageBox.question(self, title, warning, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.append_output(f"--- Starting: {title} ---", "yellow")
        
        # Remount /system as RW
        self.append_output("Attempting to remount /system as read-write...")
        code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", "mount -o remount,rw /system"])
        if code != 0:
            self.append_output("Could not remount /system as RW. This might be expected on newer Android versions. Proceeding...", "orange")

        # Run the actual operation
        try:
            operation_func(*args)
        except Exception as e:
            self.append_output(f"An error occurred: {e}", "red")
            logging.error(f"ROM Mod error: {traceback.format_exc()}")

        self.append_output(f"--- Finished: {title} ---", "yellow")

    def browse_boot_animation(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select bootanimation.zip", "", "ZIP Files (*.zip)")
        if path:
            self.boot_anim_path.setText(path)

    def apply_boot_animation(self):
        path = self.boot_anim_path.text()
        if not path or not os.path.exists(path):
            CopyableMessageBox.warning(self, "Error", "Please select a valid bootanimation.zip file.")
            return
        
        def operation():
            self.device_manager.execute_adb_command(["push", path, "/data/local/tmp/bootanimation.zip"])
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", "mv /data/local/tmp/bootanimation.zip /system/media/bootanimation.zip && chmod 644 /system/media/bootanimation.zip"])
            if code == 0:
                self.append_output("Boot animation applied successfully. It will be visible on next reboot.", "lime")
            else:
                self.append_output(f"Failed to apply boot animation: {out}", "red")

        self._run_root_operation("Apply Boot Animation", "This will replace your current boot animation. Continue?", operation)

    def browse_font(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Font File", "", "Font Files (*.ttf)")
        if path:
            self.font_path.setText(path)

    def apply_font(self):
        # This is a simplified example. Real font changing is much more complex.
        self.append_output("Note: Changing system fonts is complex and device-dependent. This is a simplified example and may not work.", "orange")
        path = self.font_path.text()
        if not path or not os.path.exists(path):
            CopyableMessageBox.warning(self, "Error", "Please select a valid .ttf font file.")
            return

        def operation():
            self.device_manager.execute_adb_command(["shell", "su", "-c", "cp /system/fonts/Roboto-Regular.ttf /system/fonts/Roboto-Regular.ttf.bak"])
            self.device_manager.execute_adb_command(["push", path, "/data/local/tmp/newfont.ttf"])
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", "mv /data/local/tmp/newfont.ttf /system/fonts/Roboto-Regular.ttf && chmod 644 /system/fonts/Roboto-Regular.ttf"])
            if code == 0:
                self.append_output("Font applied. A full reboot is required to see changes.", "lime")
            else:
                self.append_output(f"Failed to apply font: {out}", "red")

        self._run_root_operation("Apply System Font", "This will replace the default system font (Roboto-Regular.ttf). This is risky. Continue?", operation)

    def apply_dpi(self):
        dpi = self.dpi_spinbox.value()
        def operation():
            code, out = self.device_manager.execute_adb_command(["shell", "wm", "density", str(dpi)])
            if code == 0:
                self.append_output(f"Screen density set to {dpi}. The UI will restart.", "lime")
            else:
                self.append_output(f"Failed to set DPI: {out}", "red")
        
        self._run_root_operation("Change Screen DPI", f"This will change the screen density to {dpi} and restart the UI. Continue?", operation)

    def reset_dpi(self):
        def operation():
            code, out = self.device_manager.execute_adb_command(["shell", "wm", "density", "reset"])
            if code == 0:
                self.append_output("Screen density reset to default. The UI will restart.", "lime")
            else:
                self.append_output(f"Failed to reset DPI: {out}", "red")

        self._run_root_operation("Reset Screen DPI", "This will reset the screen density to the device default and restart the UI. Continue?", operation)

    def apply_adblock_hosts(self):
        # URL for a well-known ad-blocking hosts file
        hosts_url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        
        def operation():
            try:
                self.append_output(f"Downloading hosts file from {hosts_url}...")
                response = requests.get(hosts_url, timeout=30)
                response.raise_for_status()
                
                with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp:
                    tmp.write(response.text)
                    tmp_path = tmp.name
                
                self.append_output("Backing up original hosts file to /system/etc/hosts.bak...")
                self.device_manager.execute_adb_command(["shell", "su", "-c", "cp /system/etc/hosts /system/etc/hosts.bak"])

                self.append_output("Pushing new hosts file...")
                self.device_manager.execute_adb_command(["push", tmp_path, "/data/local/tmp/hosts"])
                code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", "mv /data/local/tmp/hosts /system/etc/hosts && chmod 644 /system/etc/hosts"])

                if code == 0:
                    self.append_output("Ad-blocking hosts file applied successfully.", "lime")
                else:
                    self.append_output(f"Failed to apply hosts file: {out}", "red")
                
                os.remove(tmp_path)
            except Exception as e:
                self.append_output(f"An error occurred: {e}", "red")

        self._run_root_operation("Apply Ad-Block Hosts", "This will replace your device's hosts file to block ads. A backup will be created. Continue?", operation)

    def restore_hosts(self):
        def operation():
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", "if [ -f /system/etc/hosts.bak ]; then mv /system/etc/hosts.bak /system/etc/hosts; else echo 'Backup not found'; fi"])
            if code == 0 and "Backup not found" not in out:
                self.append_output("Original hosts file restored successfully.", "lime")
            else:
                self.append_output(f"Failed to restore hosts file: {out}", "red")

        self._run_root_operation("Restore Hosts", "This will restore the original hosts file from backup (/system/etc/hosts.bak). Continue?", operation)

    def edit_hosts(self):
        self.append_output("This feature is not yet implemented.", "orange")

    def toggle_nav_bar(self, enable):
        value = "0" if enable else "1"
        action = "Enable" if enable else "Disable"
        
        def operation():
            # This build.prop tweak is a classic method.
            # It might not work on all modern devices.
            self.append_output("Note: This is a build.prop tweak and may not work on all devices.", "orange")
            
            # Read, modify, and write back build.prop
            code, content = self.device_manager.execute_adb_command(["shell", "cat", "/system/build.prop"])
            if code != 0:
                self.append_output("Failed to read build.prop", "red")
                return

            new_content = []
            prop_found = False
            for line in content.splitlines():
                if line.strip().startswith("qemu.hw.mainkeys"):
                    new_content.append(f"qemu.hw.mainkeys={value}")
                    prop_found = True
                else:
                    new_content.append(line)
            
            if not prop_found:
                new_content.append(f"qemu.hw.mainkeys={value}")

            final_content = "\n".join(new_content)

            with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tmp:
                tmp.write(final_content)
                tmp_path = tmp.name

            self.device_manager.execute_adb_command(["push", tmp_path, "/data/local/tmp/build.prop"])
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", "mv /data/local/tmp/build.prop /system/build.prop && chmod 644 /system/build.prop"])
            
            if code == 0:
                self.append_output(f"On-screen navigation bar {action.lower()}d. A reboot is required.", "lime")
            else:
                self.append_output(f"Failed to modify build.prop: {out}", "red")
            
            os.remove(tmp_path)

        self._run_root_operation(f"{action} Navigation Bar", f"This will modify build.prop to {action.lower()} the on-screen navigation bar. A reboot is required. Continue?", operation)

    def set_immersive_mode(self, index):
        if not self.device_manager.current_device: return
        mode = ["null", "status", "navigation", "immersive.full"][index] # Maps to combo box items
        command = ["shell", "settings", "put", "global", "policy_control", mode]
        code, out = self.device_manager.execute_adb_command(command)
        if code == 0:
            self.append_output(f"Immersive mode set to: {mode}", "lime")
        else:
            self.append_output(f"Failed to set immersive mode: {out}", "red")

    def set_selinux_mode(self, mode):
        """Set SELinux mode. 0 for Permissive, 1 for Enforcing."""
        mode_str = "Permissive" if mode == 0 else "Enforcing"
        def operation():
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", f"setenforce {mode}"])
            if code == 0:
                self.append_output(f"SELinux mode set to {mode_str}", "lime")
            else:
                self.append_output(f"Failed to set SELinux mode: {out}", "red")
        self._run_root_operation(f"Set SELinux to {mode_str}", f"This will change the SELinux mode to {mode_str}. This can affect system security. Continue?", operation)

    def apply_io_scheduler(self):
        scheduler = self.io_scheduler_combo.currentText()
        def operation():
            # Find the correct sysfs path for the I/O scheduler
            cmd = "find /sys/block/ -name 'scheduler' -print -quit"
            code, path = self.device_manager.execute_adb_command(["shell", "su", "-c", cmd])
            if code != 0 or not path.strip():
                self.append_output("Could not find I/O scheduler path.", "red")
                return
            
            scheduler_path = path.strip()
            apply_cmd = f"echo {scheduler} > {scheduler_path}"
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", apply_cmd])
            if code == 0:
                self.append_output(f"I/O Scheduler set to '{scheduler}'.", "lime")
            else:
                self.append_output(f"Failed to set I/O Scheduler: {out}", "red")
        self._run_root_operation("Set I/O Scheduler", f"This will attempt to set the I/O scheduler to '{scheduler}'. This is an advanced tweak. Continue?", operation)

    def apply_tcp_congestion(self):
        algo = self.tcp_congestion_combo.currentText()
        def operation():
            cmd = f"echo {algo} > /proc/sys/net/ipv4/tcp_congestion_control"
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", cmd])
            if code == 0:
                self.append_output(f"TCP Congestion algorithm set to '{algo}'.", "lime")
            else:
                self.append_output(f"Failed to set TCP Congestion algorithm: {out}", "red")
        self._run_root_operation("Set TCP Congestion", f"This will set the TCP congestion algorithm to '{algo}'. This is an advanced network tweak. Continue?", operation)

    def force_peak_refresh_rate(self):
        if not self.device_manager.current_device: return
        cmd = ["shell", "settings", "put", "system", "peak_refresh_rate", "1.0"]
        code, out = self.device_manager.execute_adb_command(cmd)
        if code == 0:
            self.append_output("Attempted to force peak refresh rate. May require a reboot.", "lime")
        else:
            self.append_output(f"Failed to force peak refresh rate: {out}", "red")

    def hide_display_cutout(self):
        if not self.device_manager.current_device: return
        cmd = ["shell", "settings", "put", "secure", "display_cutout_mode", "1"]
        code, out = self.device_manager.execute_adb_command(cmd)
        if code == 0:
            self.append_output("Display cutout hidden. To revert, use 'adb shell settings put secure display_cutout_mode 0'.", "lime")
        else:
            self.append_output(f"Failed to hide display cutout: {out}", "red")

    def toggle_camera_shutter_sound(self):
        def operation():
            prop = "persist.sys.camera_shutter_sound"
            code, current_val = self.device_manager.execute_adb_command(["shell", "su", "-c", f"getprop {prop}"])
            new_val = "0" if current_val.strip() != "0" else "1"
            action = "Disabled" if new_val == "0" else "Enabled"
            
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", f"setprop {prop} {new_val}"])
            if code == 0:
                self.append_output(f"Camera shutter sound {action.lower()}.", "lime")
            else:
                self.append_output(f"Failed to toggle camera shutter sound: {out}", "red")
        self._run_root_operation("Toggle Camera Shutter Sound", "This will attempt to disable/enable the camera shutter sound. This may not work on all devices. Continue?", operation)

    def set_volume_steps(self):
        steps = self.volume_steps_spin.value()
        def operation():
            # This is a common build.prop tweak
            self.append_output("This modifies build.prop. A backup is not created by this specific function.", "orange")
            cmd = f"sed -i '/ro.config.media_vol_steps/d' /system/build.prop && echo 'ro.config.media_vol_steps={steps}' >> /system/build.prop"
            code, out = self.device_manager.execute_adb_command(["shell", "su", "-c", cmd])
            if code == 0:
                self.append_output(f"Volume steps set to {steps}. A reboot is required.", "lime")
            else:
                self.append_output(f"Failed to set volume steps: {out}", "red")
        self._run_root_operation("Set Volume Steps", f"This will set media volume steps to {steps} by modifying build.prop. A reboot is required. Continue?", operation)

    def set_private_dns(self, provider):
        if not self.device_manager.current_device: return
        provider_map = { "Default": "off", "Cloudflare": "one.one.one.one", "Google": "dns.google", "Quad9": "dns.quad9.net" }
        hostname = provider_map.get(provider, "off")
        mode = "hostname" if hostname != "off" else "off"

        self.device_manager.execute_adb_command(["shell", "settings", "put", "global", "private_dns_mode", mode])
        if mode == "hostname":
            self.device_manager.execute_adb_command(["shell", "settings", "put", "global", "private_dns_specifier", hostname])
        self.append_output(f"Private DNS set to {provider}", "lime")

    def _apply_build_prop_tweaks(self, title, warning, tweaks):
        def operation():
            for prop, value in tweaks.items():
                self.append_output(f"Setting {prop}={value}")
                cmd = f"sed -i '/{prop}/d' /system/build.prop && echo '{prop}={value}' >> /system/build.prop"
                self.device_manager.execute_adb_command(["shell", "su", "-c", cmd])
            self.append_output("Tweaks applied. A reboot is required.", "lime")
        self._run_root_operation(title, warning, operation)

    def apply_network_tweaks(self):
        tweaks = { "net.ipv4.tcp_ecn": "0", "net.ipv4.tcp_window_scaling": "1", "net.ipv4.tcp_syncookies": "1" }
        self._apply_build_prop_tweaks("Apply Network Tweaks", "This will apply common network performance tweaks to build.prop. A reboot is required. Continue?", tweaks)

    def apply_scrolling_tweaks(self):
        tweaks = { "ro.min.fling_velocity": "8000", "ro.max.fling_velocity": "12000" }
        self._apply_build_prop_tweaks("Apply Scrolling Tweaks", "This will apply common scrolling performance tweaks to build.prop. A reboot is required. Continue?", tweaks)

class SideloadTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()  # Thread safety for sideload operations
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        sideload_group = QGroupBox("Sideload")
        sideload_layout = QVBoxLayout()
        
        self.sideload_path_edit = QLineEdit()
        self.sideload_path_edit.setPlaceholderText("Select ZIP file to sideload...")
        
        self.sideload_browse_btn = QPushButton("Browse...")
        self.sideload_browse_btn.clicked.connect(self.select_sideload_file)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.sideload_path_edit)
        path_layout.addWidget(self.sideload_browse_btn)
        
        self.sideload_btn = QPushButton("Start Sideload")
        self.sideload_btn.clicked.connect(self.start_sideload)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        
        sideload_layout.addLayout(path_layout)
        sideload_layout.addWidget(self.sideload_btn)
        sideload_layout.addWidget(self.output_text)
        sideload_group.setLayout(sideload_layout)
        
        adb_sideload_group = QGroupBox("ADB Sideload")
        adb_sideload_layout = QVBoxLayout()
        
        self.adb_sideload_path_edit = QLineEdit()
        self.adb_sideload_path_edit.setPlaceholderText("Select ZIP file for ADB sideload...")
        
        self.adb_sideload_browse_btn = QPushButton("Browse...")
        self.adb_sideload_browse_btn.clicked.connect(self.select_adb_sideload_file)
        
        adb_path_layout = QHBoxLayout()
        adb_path_layout.addWidget(self.adb_sideload_path_edit)
        adb_path_layout.addWidget(self.adb_sideload_browse_btn)
        
        self.adb_sideload_btn = QPushButton("Start ADB Sideload")
        self.adb_sideload_btn.clicked.connect(self.start_adb_sideload)
        
        adb_sideload_layout.addLayout(adb_path_layout)
        adb_sideload_layout.addWidget(self.adb_sideload_btn)
        adb_sideload_group.setLayout(adb_sideload_layout)
        
        layout.addWidget(sideload_group)
        layout.addWidget(adb_sideload_group)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def select_sideload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select ZIP File", "", "ZIP Files (*.zip);;All Files (*)"
        )
        
        if file_path:
            self.sideload_path_edit.setText(os.path.normpath(file_path))
    
    def select_adb_sideload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select ZIP File", "", "ZIP Files (*.zip);;All Files (*)"
        )
        
        if file_path:
            self.adb_sideload_path_edit.setText(os.path.normpath(file_path))
    
    def start_sideload(self):
        file_path = self.sideload_path_edit.text()
        if not file_path:
            CopyableMessageBox.warning(self, "Error", "No file selected")
            return
        
        if not os.path.isfile(file_path):
            CopyableMessageBox.warning(self, "Error", "File does not exist")
            return
        
        confirm = QMessageBox.question(
            self, "Confirm Sideload", 
            "This will reboot your device to sideload mode and install the selected ZIP. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:  # Thread-safe operation
                self.output_text.clear()
                self.append_output("Rebooting to sideload mode...")
                
                try:
                    success, output = self.device_manager.reboot_device("sideload")
                    self.append_output(output)
                    
                    if not success:
                        self.append_output("Failed to reboot to sideload mode")
                        return
                    
                    self.append_output("Waiting for device to enter sideload mode...")
                    time.sleep(10)
                    
                    self.append_output(f"Sideloading {file_path}...")
                    cmd_list = ["sideload", file_path]
                    return_code, output = self.device_manager.execute_adb_command(
                        cmd_list, device_specific=True, timeout=600)
                    self.append_output(output)
                    
                    if return_code == 0:
                        self.append_output("Sideload completed successfully")
                    else:
                        self.append_output("Sideload failed")
                except Exception as e:
                    self.append_output(f"Error during sideload: {str(e)}")
    
    def start_adb_sideload(self):
        file_path = self.adb_sideload_path_edit.text()
        if not file_path:
            CopyableMessageBox.warning(self, "Error", "No file selected")
            return
        
        if not os.path.isfile(file_path):
            CopyableMessageBox.warning(self, "Error", "File does not exist")
            return
        
        confirm = QMessageBox.question(
            self, "Confirm ADB Sideload", 
            "This will install the selected ZIP using ADB sideload. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:  # Thread-safe operation
                self.output_text.clear()
                self.append_output(f"Sideloading {file_path}...")
                
                try:
                    cmd_list = ["sideload", file_path]
                    return_code, output = self.device_manager.execute_adb_command(
                        cmd_list, device_specific=True, timeout=600)
                    self.append_output(output)
                    
                    if return_code == 0:
                        self.append_output("ADB sideload completed successfully")
                    else:
                        self.append_output("ADB sideload failed")
                except Exception as e:
                    self.append_output(f"Error during ADB sideload: {str(e)}")
    
    def append_output(self, text):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n")
        self.output_text.setTextCursor(cursor)
        self.output_text.ensureCursorVisible()


class RootToolsTab(QWidget):
    # Signale für Worker-Threads
    progress_update = pyqtSignal(int, str)
    operation_finished = pyqtSignal(bool, str)

    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()  # Thread safety for root operations
        self.init_ui()
        self.progress_dialog = None

        # Initialisiere die Emulator-Liste beim Start
        QTimer.singleShot(500, self.refresh_emulators_list)

    def find_emulator_path(self):
        """Sucht nach der emulator.exe basierend auf dem ADB-Pfad."""
        # 1. Versuche, den Pfad aus den Einstellungen zu laden
        with settings_lock:
            sdk_path = settings.value("sdk_path", "")
        if sdk_path:
            emulator_path = os.path.join(sdk_path, "emulator", "emulator.exe" if sys.platform == "win32" else "emulator")
            if os.path.exists(emulator_path):
                return emulator_path

        # 2. Versuche, den Pfad relativ zu ADB zu finden
        try:
            adb_path = self.device_manager.adb_path
            if adb_path and adb_path != DEFAULT_ADB_PATH:
                sdk_root = os.path.dirname(os.path.dirname(os.path.abspath(adb_path)))
                emulator_path = os.path.join(sdk_root, "emulator", "emulator.exe" if sys.platform == "win32" else "emulator")
                if os.path.exists(emulator_path):
                    return emulator_path
        except Exception: pass

        # 3. Fallback auf System-PATH
        return shutil.which("emulator")
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        root_group = QGroupBox("Root Access")
        root_layout = QVBoxLayout()
        
        self.root_status_label = QLabel("Root status: Unknown")
        self.root_status_label.setStyleSheet("font-weight: bold;")
        
        self.check_root_btn = QPushButton("Check Root Access")
        self.check_root_btn.clicked.connect(self.check_root_access)
        
        self.grant_root_btn = QPushButton("Grant Temporary Root")
        self.grant_root_btn.clicked.connect(self.grant_temp_root)
        
        self.install_su_btn = QPushButton("Install SuperSU")
        self.install_su_btn.clicked.connect(self.install_supersu)
        
        self.root_emulator_btn = QPushButton("Root Emulator")
        self.root_emulator_btn.clicked.connect(self.root_emulator)
        
        self.remove_bloatware_btn = QPushButton("System-Apps entfernen")
        self.remove_bloatware_btn.clicked.connect(self.remove_bloatware)
        
        self.unroot_btn = QPushButton("Remove Root")
        self.unroot_btn.setVisible(False) # This is too risky and unreliable
        
        root_btn_layout = QHBoxLayout()
        root_btn_layout.addWidget(self.check_root_btn)
        root_btn_layout.addWidget(self.grant_root_btn)
        
        install_btn_layout = QHBoxLayout()
        install_btn_layout.addWidget(self.install_su_btn)
        install_btn_layout.addWidget(self.root_emulator_btn)
        install_btn_layout.addWidget(self.remove_bloatware_btn)
        
        root_layout.addWidget(self.root_status_label)
        root_layout.addLayout(root_btn_layout)
        root_layout.addLayout(install_btn_layout)
        root_layout.addWidget(self.unroot_btn)
        root_group.setLayout(root_layout)
        
        # --- Emulator Management Group ---
        emulator_group = QGroupBox("Emulator Management")
        emulator_layout = QVBoxLayout()

        emulator_controls_layout = QHBoxLayout()
        self.emulator_combo = QComboBox()
        self.emulator_combo.setToolTip("Liste der verfügbaren Android Virtual Devices (AVDs)")
        self.refresh_emulators_btn = QPushButton("Refresh")
        self.refresh_emulators_btn.setToolTip("Sucht erneut nach verfügbaren Emulatoren.")
        self.refresh_emulators_btn.clicked.connect(self.refresh_emulators_list)
        emulator_controls_layout.addWidget(self.emulator_combo)
        emulator_controls_layout.addWidget(self.refresh_emulators_btn)

        start_emulator_layout = QHBoxLayout()
        self.writable_system_check = QCheckBox("-writable-system")
        self.writable_system_check.setToolTip("Startet den Emulator mit einer beschreibbaren Systempartition (erforderlich für Root).")
        self.writable_system_check.setChecked(True)
        self.start_emulator_btn = QPushButton("Start Emulator")
        self.start_emulator_btn.clicked.connect(self.start_selected_emulator)
        start_emulator_layout.addWidget(self.writable_system_check)
        start_emulator_layout.addWidget(self.start_emulator_btn)

        emulator_layout.addLayout(emulator_controls_layout)
        emulator_layout.addLayout(start_emulator_layout)
        emulator_group.setLayout(emulator_layout)

        system_group = QGroupBox("System Modifications")
        system_layout = QVBoxLayout()
        
        self.mount_system_btn = QPushButton("Mount /system as RW")
        self.mount_system_btn.clicked.connect(self.mount_system_rw)

        self.remount_btn = QPushButton("Remount Partitions")
        self.remount_btn.clicked.connect(self.remount_partitions)
        
        self.build_prop_editor_btn = QPushButton("build.prop Editor [beta]")
        self.build_prop_editor_btn.clicked.connect(self.open_build_prop_editor)
        
        self.extract_boot_img_btn = QPushButton("Extract boot.img from payload.bin")
        self.extract_boot_img_btn.setToolTip("Extrahiert Images aus einer OTA payload.bin Datei, um das boot.img für Magisk zu erhalten.")
        self.extract_boot_img_btn.clicked.connect(self.extract_boot_image_from_payload)

        self.download_ota_btn = QPushButton("Download OTA ZIP")
        self.download_ota_btn.setToolTip("Lädt eine OTA-Update-ZIP-Datei herunter und extrahiert die payload.bin daraus.")
        self.download_ota_btn.clicked.connect(self.download_ota_zip)

        self.extract_device_boot_img_btn = QPushButton("Extract boot.img from Device")
        self.extract_device_boot_img_btn.setToolTip("Pulls the boot.img from a rooted device for patching with Magisk.")
        self.extract_device_boot_img_btn.clicked.connect(self.extract_boot_image_from_device)

        self.pull_system_btn = QPushButton("Pull File from /system")
        self.pull_system_btn.clicked.connect(self.pull_from_system)
        
        system_btn_layout = QHBoxLayout()
        system_btn_layout.addWidget(self.mount_system_btn)
        system_btn_layout.addWidget(self.remount_btn)
        
        system_file_layout = QHBoxLayout()
        system_file_layout.addWidget(self.build_prop_editor_btn)
        system_file_layout.addWidget(self.extract_boot_img_btn)
        system_file_layout.addWidget(self.download_ota_btn)
        system_file_layout.addWidget(self.extract_device_boot_img_btn)
        system_file_layout.addWidget(self.pull_system_btn)
        
        system_layout.addLayout(system_btn_layout)
        system_layout.addLayout(system_file_layout)
        system_group.setLayout(system_layout)
        
        advanced_group = QGroupBox("Advanced Root Commands")
        advanced_layout = QVBoxLayout()
        
        self.root_shell_btn = QPushButton("Open Root Shell")
        self.root_shell_btn.clicked.connect(self.open_root_shell)
        
        self.fix_permissions_btn = QPushButton("Fix Permissions")
        self.fix_permissions_btn.clicked.connect(self.fix_permissions)
        
        self.read_keybox_btn = QPushButton("Read KeyBox")
        self.read_keybox_btn.clicked.connect(self.read_keybox)
        
        # BusyBox Tools Group
        busybox_group = QGroupBox("BusyBox Tools")
        busybox_layout = QGridLayout()
        self.dmesg_btn = QPushButton("Kernel Log (dmesg)")
        self.dmesg_btn.clicked.connect(lambda: self.run_root_command("dmesg | tail -n 100", "Kernel Log"))
        self.ps_btn = QPushButton("Process List (ps)")
        self.ps_btn.clicked.connect(lambda: self.run_root_command("ps -ef", "Process List"))
        self.netstat_btn = QPushButton("Network Connections (netstat)")
        self.netstat_btn.clicked.connect(lambda: self.run_root_command("netstat -tuln", "Network Connections"))
        self.find_btn = QPushButton("Find File")
        self.find_btn.clicked.connect(self.find_file_with_busybox)
        busybox_layout.addWidget(self.dmesg_btn, 0, 0)
        busybox_layout.addWidget(self.ps_btn, 0, 1)
        busybox_layout.addWidget(self.netstat_btn, 1, 0)
        busybox_layout.addWidget(self.find_btn, 1, 1)
        busybox_group.setLayout(busybox_layout)

        self.install_busybox_btn = QPushButton("Install BusyBox")
        self.install_busybox_btn.clicked.connect(self.install_busybox)
        
        advanced_layout.addWidget(self.root_shell_btn)
        advanced_layout.addWidget(self.fix_permissions_btn)
        advanced_layout.addWidget(self.install_busybox_btn)
        advanced_layout.addWidget(self.read_keybox_btn)
        advanced_group.setLayout(advanced_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        
        output_controls_layout = QHBoxLayout()
        output_controls_layout.addStretch()
        self.clear_log_btn = QPushButton("Clear Log")
        self.clear_log_btn.setToolTip("Clears this log window.")
        self.clear_log_btn.clicked.connect(self.output_text.clear)
        output_controls_layout.addWidget(self.clear_log_btn)
        
        layout.addWidget(root_group)
        layout.addWidget(system_group)
        layout.addWidget(emulator_group)
        layout.addWidget(advanced_group)
        layout.addWidget(busybox_group)
        layout.addWidget(self.output_text)
        layout.addLayout(output_controls_layout)
        
        self.setLayout(layout)

        # Signale verbinden
        self.progress_update.connect(self.update_progress)
        self.operation_finished.connect(self.on_operation_finished)
    
    def check_root_access(self):
        """Prüft, ob Root-Zugriff besteht und aktualisiert das UI."""
        with self.lock:
            self.append_output("Checking root access...")
            try:
                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "echo Root check"])
                if return_code == 0 and "Root check" in output:
                    self.root_status_label.setText("Root status: Root access available")
                    self.root_status_label.setStyleSheet("color: #2ecc71; font-weight: bold;") # Grün
                    self.append_output("Device has root access.")
                    return True
                else:
                    self.root_status_label.setText("Root status: No root access")
                    self.root_status_label.setStyleSheet("color: #e74c3c; font-weight: bold;") # Rot
                    self.append_output("Device does NOT have root access.")
                    return False
            except Exception as e:
                self.append_output(f"Error checking root access: {e}")
                self.root_status_label.setText("Root status: Check failed")
                self.root_status_label.setStyleSheet("color: #f1c40f; font-weight: bold;") # Gelb
                return False

    def remove_bloatware(self):
        """Ermöglicht dem Benutzer, eine System-App auszuwählen und zu deinstallieren."""
        if not self.is_root():
            return

        self.append_output("Fetching system packages...")
        return_code, output = self.device_manager.execute_adb_command(["shell", "pm", "list", "packages", "-s"])
        if return_code != 0:
            CopyableMessageBox.warning(self, "Error", "Could not fetch system packages.")
            return

        packages = sorted([line.replace("package:", "").strip() for line in output.splitlines()])
        package, ok = QInputDialog.getItem(self, "Remove System App (Bloatware)", "Select a package to remove:", packages, 0, False)

        if ok and package:
            confirm = QMessageBox.question(
                self, "Confirm Removal",
                f"<b>WARNING:</b> This will permanently remove '<b>{package}</b>'.<br><br>"
                "Removing essential system apps can cause your device to malfunction or fail to boot. "
                "Only proceed if you know what you are doing.<br><br>"
                "Are you absolutely sure you want to continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm != QMessageBox.StandardButton.Yes:
                return

            self.append_output(f"Attempting to remove package: {package}")
            self.mount_system_rw() # Ensure /system is writable
            
            # Moderner Ansatz (Android 5.0+)
            return_code, output = self.device_manager.execute_adb_command(["shell", "pm", "uninstall", "--user", "0", package])
            
            # Fallback für ältere Systeme oder wenn der erste Befehl fehlschlägt
            if "Success" not in output:
                self.append_output("Modern uninstall failed, trying legacy method...")
                return_code, path_output = self.device_manager.execute_adb_command(["shell", "pm", "path", package])
                if return_code == 0 and path_output.startswith("package:"):
                    apk_path = path_output.replace("package:", "").strip()
                    self.append_output(f"Found APK at: {apk_path}. Removing...")
                    return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", f"rm -f {apk_path}"])
                else:
                    self.append_output("Could not determine APK path for legacy removal.")

            self.append_output(output)
            if "Success" in output or return_code == 0:
                self.append_output(f"Successfully removed {package}. A reboot is recommended.")
                CopyableMessageBox.information(self, "Success", f"Successfully removed {package}. A reboot is recommended.")
            else:
                self.append_output(f"Failed to remove {package}.")
                CopyableMessageBox.warning(self, "Error", f"Failed to remove {package}. Check the log for details.")

    def open_build_prop_editor(self):
        """Öffnet einen einfachen Editor für die build.prop-Datei."""
        if not self.is_root():
            return

        self.append_output("Reading /system/build.prop...")
        return_code, content = self.device_manager.execute_adb_command(["shell", "cat", "/system/build.prop"])

        if return_code != 0:
            self.append_output("Failed to read build.prop.")
            CopyableMessageBox.warning(self, "Error", "Could not read /system/build.prop.")
            return

        dialog = BuildPropEditorDialog(content, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_content = dialog.editor.toPlainText()
            if new_content != content:
                self.save_build_prop(new_content)
            else:
                self.append_output("No changes made to build.prop.")

    def save_build_prop(self, new_content):
        """Speichert den neuen Inhalt in die build.prop-Datei auf dem Gerät."""
        with self.lock:  # Thread-safe operation
            self.append_output("Checking root access...")
            try:
                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "echo Root check"])
                if return_code == 0 and "Root check" in output:
                    self.root_status_label.setText("Root status: Root access available")
                    self.root_status_label.setStyleSheet("color: #2ecc71; font-weight: bold;") # Grün
                    self.append_output("Device has root access")
                else:
                    self.root_status_label.setText("Root status: No root access")
                    self.root_status_label.setStyleSheet("color: #e74c3c; font-weight: bold;") # Rot
                    self.append_output("Device does NOT have root access")
            except Exception as e:
                self.append_output(f"Error checking root access: {str(e)}")
                self.root_status_label.setText("Root status: Check failed")
                self.root_status_label.setStyleSheet("color: #f1c40f; font-weight: bold;") # Gelb
    
    def grant_temp_root(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Attempting to grant temporary root access...")
            try:
                return_code, output = self.device_manager.execute_adb_command(["root"])
                self.append_output(output)
                
                if return_code == 0:
                    CopyableMessageBox.information(self, "Success", "Temporary root access granted. Device may reboot.")
                else:
                    QMessageBox.warning(self, "Error", f"Failed to grant temporary root access: {output}")
            except Exception as e:
                self.append_output(f"Error granting root access: {str(e)}")
    
    def install_supersu(self):
        with self.lock:  # Thread-safe operation
            return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "which su"])
            if return_code == 0 and "/su" in output:
                CopyableMessageBox.information(self, "Info", "SuperSU is already installed")
                return
            
            url = "https://supersu.com/download"
            self.append_output(f"Downloading SuperSU from {url}...")
            
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    temp_dir = tempfile.gettempdir()
                    zip_path = os.path.join(temp_dir, "supersu.zip")
                    
                    with open(zip_path, "wb") as f:
                        f.write(response.content)
                    
                    self.append_output("SuperSU downloaded, installing...")
                    
                    return_code, output = self.device_manager.execute_adb_command(["push", zip_path, "/sdcard/supersu.zip"])
                    self.append_output(output)
                    
                    if return_code != 0:
                        self.append_output("Failed to push SuperSU to device")
                        return
                    
                    success, output = self.device_manager.reboot_device("recovery")
                    self.append_output(output)
                    
                    if not success:
                        self.append_output("Failed to reboot to recovery")
                        return
                    
                    self.append_output("Waiting for device to enter recovery...")
                    time.sleep(10)
                    
                    return_code, output = self.device_manager.execute_adb_command(["shell", "twrp", "install", "/sdcard/supersu.zip"], device_specific=False)
                    self.append_output(output)
                    
                    if return_code == 0:
                        self.append_output("SuperSU installed successfully")
                    else:
                        self.append_output("Failed to install SuperSU")
                else:
                    self.append_output(f"Failed to download SuperSU: HTTP {response.status_code}")
            except Exception as e:
                self.append_output(f"Error installing SuperSU: {str(e)}")
            finally:
                if 'zip_path' in locals() and os.path.exists(zip_path): # type: ignore
                    try:
                        os.remove(zip_path) # type: ignore
                    except Exception:
                        pass
    
    def install_magisk(self):
        with self.lock:  # Thread-safe operation
            return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "which magisk"])
            if return_code == 0 and "/magisk" in output:
                CopyableMessageBox.information(self, "Info", "Magisk is already installed")
                return
            
            url = "https://github.com/topjohnwu/Magisk/releases/latest"
            self.append_output(f"Downloading Magisk from {url}...")
            
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    # NOTE: This is simplified. A real implementation would parse the releases page.
                    download_url = "https://github.com/topjohnwu/Magisk/releases/download/v23.0/Magisk-v23.0.apk"
                    
                    temp_dir = tempfile.gettempdir()
                    apk_path = os.path.join(temp_dir, "magisk.apk")
                    
                    with open(apk_path, "wb") as f:
                        f.write(requests.get(download_url).content)
                    
                    self.append_output("Magisk downloaded, installing...")
                    
                    return_code, output = self.device_manager.execute_adb_command(["install", apk_path])
                    self.append_output(output)
                    
                    if return_code == 0:
                        self.append_output("Magisk installed successfully")
                    else:
                        self.append_output("Failed to install Magisk")
                else:
                    self.append_output(f"Failed to download Magisk: HTTP {response.status_code}")
            except Exception as e:
                self.append_output(f"Error installing Magisk: {str(e)}")
            finally:
                if 'apk_path' in locals() and os.path.exists(apk_path): # type: ignore
                    try: # type: ignore
                        os.remove(apk_path) # type: ignore
                    except Exception:
                        pass
    
    def remove_root(self):
        confirm = QMessageBox.question(
            self, "Confirm Remove Root", 
            "This will attempt to remove root access from your device. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:  # Thread-safe operation
                self.append_output("Attempting to remove root access...")
                
                try:
                    self.device_manager.execute_adb_command(["shell", "su", "-c", "echo \"pm uninstall eu.chainfire.supersu\" > /cache/uninstall.sh'"])
                    self.device_manager.execute_adb_command(["shell", "su", "-c", "chmod 755 /cache/uninstall.sh"])
                    return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "/cache/uninstall.sh"])
                    self.append_output(output)
                    
                    return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "magisk --remove-modules"])
                    self.append_output(output)
                    
                    self.device_manager.execute_adb_command(["shell", "su", "-c", "rm -rf /system/bin/su /system/xbin/su /system/bin/.ext /system/etc/.installed_su_daemon"])
                    self.append_output(output)
                    
                    self.append_output("Root removal attempted. Reboot your device to complete the process.")
                except Exception as e:
                    self.append_output(f"Error removing root: {str(e)}")
    
    def mount_system_rw(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Mounting /system as read-write...")
            try:
                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "mount -o remount,rw /system"])
                self.append_output(output)
                
                if return_code == 0:
                    self.append_output("/system mounted as read-write")
                else:
                    self.append_output("Failed to mount /system as read-write. This is normal on newer Android versions with system-as-root.")
            except Exception as e:
                self.append_output(f"Error mounting /system: {str(e)}")
    
    def remount_partitions(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Remounting partitions...")
            try:
                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "mount -o remount,rw /"])
                self.append_output(output)
                
                if return_code == 0:
                    self.append_output("Partitions remounted successfully")
                else:
                    self.append_output("Failed to remount partitions")
            except Exception as e:
                self.append_output(f"Error remounting partitions: {str(e)}")
    
    def push_to_system(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Push", "", "All Files (*)"
        )
        
        if file_path:
            dest_path, ok = QInputDialog.getText(
                self, "Destination Path", "Enter destination path in /system:",
                QLineEdit.EchoMode.Normal, "/system/"
            )
            
            if ok and dest_path:
                with self.lock:  # Thread-safe operation
                    self.append_output(f"Pushing {file_path} to {dest_path}...")
                    try:
                        return_code, output = self.device_manager.execute_adb_command(["push", file_path, dest_path])
                        self.append_output(output)
                        
                        if return_code == 0:
                            self.append_output("File pushed successfully")
                            
                            perms, ok = QInputDialog.getText(
                                self, "Set Permissions", "Enter permissions (e.g. 644):",
                                QLineEdit.EchoMode.Normal, "644"
                            )
                            
                            if ok and perms:
                                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "chmod", perms, dest_path])
                                self.append_output(output)
                        else:
                            self.append_output("Failed to push file")
                    except Exception as e:
                        self.append_output(f"Error pushing file: {str(e)}")
    
    def pull_from_system(self):
        src_path, ok = QInputDialog.getText(
            self, "Source Path", "Enter file path in /system to pull:",
            QLineEdit.EchoMode.Normal, "/system/"
        )
        
        if ok and src_path:
            dest_path, _ = QFileDialog.getSaveFileName(
                self, "Save File", os.path.basename(src_path), "All Files (*)"
            )
            
            if dest_path:
                with self.lock:  # Thread-safe operation
                    self.append_output(f"Pulling {src_path} to {dest_path}...")
                    try:
                        return_code, output = self.device_manager.execute_adb_command(["pull", src_path, dest_path])
                        self.append_output(output)
                        
                        if return_code == 0:
                            self.append_output("File pulled successfully")
                        else:
                            self.append_output("Failed to pull file")
                    except Exception as e:
                        self.append_output(f"Error pulling file: {str(e)}")
    
    def read_keybox(self):
        if not self.is_root():
            return

        self.progress_dialog = QProgressDialog("Reading KeyBox...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("KeyBox Reader")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setAutoClose(True)
        self.progress_dialog.setAutoReset(True)
        self.progress_dialog.show()

        self.thread = QThread()
        # Pass 'self' to the worker so it can emit signals from the RootToolsTab instance
        self.worker = Worker(self._read_keybox_worker, self)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _read_keybox_worker(self, worker_instance, parent_self):
        """Worker function to read KeyBox data in the background."""
        parent_self.append_output("\n--- Attempting to read KeyBox ---")
        
        possible_dirs = [
            "/data/misc/keystore/user_0/",
            "/data/misc/user/0/keystore/",
            "/data/misc/keystore/",
            "/data/system/keystore/",
            "/data/keystore/",
        ]

        keybox_dir = None
        for i, d in enumerate(possible_dirs):
            progress = int((i / len(possible_dirs)) * 30) # 0-30% for initial search
            parent_self.progress_update.emit(progress, f"Checking: {d}")
            parent_self.append_output(f"Checking for directory: {d}")
            check_cmd = ["shell", "su", "-c", f"if [ -d {d} ]; then echo 'found'; fi"]
            return_code, output = parent_self.device_manager.execute_adb_command(check_cmd)
            if return_code == 0 and "found" in output:
                keybox_dir = d
                parent_self.append_output(f"Found keystore at: {keybox_dir}")
                break

        if not keybox_dir:
            parent_self.progress_update.emit(35, "Searching with 'find'...")
            parent_self.append_output("Standard directories not found. Using 'find' to locate keystore directory...")
            find_cmd = ["shell", "su", "-c", "find /data/misc /data/system -maxdepth 3 -type d -name 'keystore' -print -quit"]
            return_code, output = parent_self.device_manager.execute_adb_command(find_cmd)
            found_path = output.strip()
            if return_code == 0 and found_path and found_path.startswith('/'):
                keybox_dir = found_path + ("/" if not found_path.endswith("/") else "")
                parent_self.append_output(f"Dynamically found keystore at: {keybox_dir}")

        if not keybox_dir:
            parent_self.operation_finished.emit(False, "Could not find a valid KeyBox directory on this device.")
            return

        parent_self.progress_update.emit(40, "Listing key files...")
        list_cmd = ["shell", "su", "-c", f"ls -1 {keybox_dir}"]
        return_code, output = parent_self.device_manager.execute_adb_command(list_cmd)

        if return_code != 0 or not output.strip():
            parent_self.operation_finished.emit(False, f"Could not read KeyBox directory '{keybox_dir}'. It might be empty or inaccessible.")
            return

        key_files = [f for f in output.splitlines() if f.strip()]
        parent_self.append_output(f"Found {len(key_files)} key file(s). Reading content...")

        for i, filename in enumerate(key_files):
            progress = 40 + int((i / len(key_files)) * 60) # 40-100% for reading files
            parent_self.progress_update.emit(progress, f"Reading: {filename}")
            parent_self.append_output(f"\n[File: {filename}]")
            read_cmd = ["shell", "su", "-c", f"cat {keybox_dir}{filename} | xxd -p -c 256"]
            hex_code, hex_output = parent_self.device_manager.execute_adb_command(read_cmd)

            if hex_code == 0 and hex_output.strip():
                parent_self.append_output(hex_output.strip().replace("\n", ""))
            else:
                parent_self.append_output(f"  -> Could not read content of {filename}. It may be a directory or inaccessible.")
        
        parent_self.operation_finished.emit(True, "KeyBox reading finished.")

    def run_root_command(self, command, description):
        """Runs a generic root command and displays the output."""
        if not self.is_root():
            return

        self.append_output(f"\n--- Running: {description} ---")
        return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", command])
        if return_code == 0:
            self.append_output(output)
        else:
            self.append_output(f"Error executing command: {output}")
        self.append_output(f"--- {description} finished ---")

    def find_file_with_busybox(self):
        """Opens a dialog to find a file using busybox find."""
        if not self.is_root():
            return

        filename, ok = QInputDialog.getText(self, "Find File", "Enter filename (e.g., 'httpd.conf'):")
        if ok and filename:
            command = f"find / -name '{filename}'"
            self.run_root_command(command, f"Find '{filename}'")

    def open_root_shell(self):
        self.append_output("Opening root shell...")
        self.append_output("Type 'exit' to quit the shell")
        
        # Start a thread for the shell
        thread = threading.Thread(target=self.run_root_shell, daemon=True)
        thread.start()
    
    def run_root_shell(self):
        try:
            process = subprocess.Popen(
                [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "su"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            while True:
                command = input("root@android:# ")  # This won't work well with Qt, needs improvement
                if command.lower() == "exit":
                    break
                
                process.stdin.write(command + "\n")
                process.stdin.flush()
                
                output = process.stdout.readline()
                while output:
                    self.append_output(output.strip())
                    output = process.stdout.readline()
        except Exception as e:
            self.append_output(f"Shell error: {str(e)}")
        finally:
            if 'process' in locals():
                process.terminate()
    
    def fix_permissions(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Fixing permissions on /system...")
            try:
                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "find /system -type d -exec chmod 755 {} \\;"])
                self.append_output(output)
                
                return_code, output = self.device_manager.execute_adb_command(["shell", "su", "-c", "find /system -type f -exec chmod 644 {} \\;"])
                self.append_output(output)
                
                self.append_output("Permissions fixed")
            except Exception as e:
                self.append_output(f"Error fixing permissions: {str(e)}")
    
    def install_busybox(self):
        if not self.device_manager.current_device:
            CopyableMessageBox.warning(self, "Error", "No device selected #024")
            return

        self.progress_dialog = QProgressDialog("Installing BusyBox...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("BusyBox Installation")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setAutoClose(False)
        self.progress_dialog.setAutoReset(False)
        self.progress_dialog.show()

        self.thread = QThread()
        self.worker = Worker(self._install_busybox_worker, self)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _install_busybox_worker(self, worker_instance, parent_self):
        """Worker function to install BusyBox in the background."""
        temp_busybox_file_on_host = None
        try:
            parent_self.progress_update.emit(0, "Checking root access...")
            parent_self.append_output("--- Installing BusyBox ---")

            # 1. Check for root access
            return_code, _ = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", "echo Root check"], timeout=10)
            if return_code != 0:
                parent_self.operation_finished.emit(False, "Root access is required for this operation.")
                return

            # 2. Check if BusyBox is already installed
            parent_self.progress_update.emit(5, "Checking existing BusyBox installation...")
            return_code, _ = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", "busybox"], timeout=10)
            if return_code == 0:
                parent_self.operation_finished.emit(True, "BusyBox is already installed.")
                return

            # 3. Detect device architecture
            parent_self.progress_update.emit(10, "Detecting device architecture...")
            parent_self.append_output("Detecting device architecture...")
            return_code, output = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", "uname -m"], timeout=10)
            arch = output.strip().lower() if return_code == 0 else "arm"
            
            busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv7l"
            if 'arm64' in arch or 'aarch64' in arch:
                busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv8l"
            elif 'x86_64' in arch:
                busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64"
            elif 'x86' in arch or 'i686' in arch:
                busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-i686"

            # 4. Download BusyBox
            parent_self.progress_update.emit(20, f"Downloading BusyBox for {arch}...")
            parent_self.append_output(f"Downloading BusyBox for {arch} from {busybox_url}...")
            
            response = requests.get(busybox_url, stream=True, timeout=30)
            response.raise_for_status()
            
            temp_dir = tempfile.gettempdir()
            temp_busybox_file_on_host = os.path.join(temp_dir, "busybox")
            with open(temp_busybox_file_on_host, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # 5. Push BusyBox to device
            parent_self.progress_update.emit(40, "Pushing BusyBox to device...")
            device_tmp_path = "/data/local/tmp/busybox"
            parent_self.append_output(f"Pushing BusyBox to {device_tmp_path}...")
            return_code, output = parent_self.device_manager.execute_adb_command(["push", temp_busybox_file_on_host, device_tmp_path], timeout=60)
            if return_code != 0:
                parent_self.operation_finished.emit(False, f"Failed to push BusyBox to device: {output}")
                return

            # 6. Attempt system installation (remount /system first)
            parent_self.progress_update.emit(60, "Attempting system installation...")
            parent_self.append_output("Attempting to remount /system as read-write...")
            
            remount_success = False
            remount_commands = ["mount -o remount,rw /", "mount -o remount,rw /system"]
            for cmd in remount_commands:
                return_code, output = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=15)
                if return_code == 0 and ("remount succeeded" in output or "Read-only file system" not in output):
                    remount_success = True
                    break
            
            install_path = ""
            success = False
            if remount_success:
                parent_self.progress_update.emit(70, "Installing to /system/xbin...")
                parent_self.append_output("/system remounted as read-write. Proceeding with system installation.")
                install_path = "/system/xbin"
                commands = [
                    f"mkdir -p {install_path}",
                    f"mv {device_tmp_path} {install_path}/busybox",
                    f"chmod 755 {install_path}/busybox",
                    f"{install_path}/busybox --install -s {install_path}"
                ]
                for i, cmd in enumerate(commands):
                    parent_self.progress_update.emit(70 + i * 5, f"Executing: {cmd[:40]}...")
                    return_code, output = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=30)
                    parent_self.append_output(output)
                    if return_code != 0:
                        success = False
                        break
                    success = True
            else:
                parent_self.progress_update.emit(70, "Fallback: Installing to /data/local/bin...")
                parent_self.append_output("Failed to remount /system. Attempting fallback to /data/local/bin...")
                install_path = "/data/local/bin"
                commands = [
                    f"mkdir -p {install_path}",
                    f"mv {device_tmp_path} {install_path}/busybox",
                    f"chmod 755 {install_path}/busybox",
                    f"PATH=$PATH:{install_path} {install_path}/busybox --install -s {install_path}"
                ]
                for i, cmd in enumerate(commands):
                    parent_self.progress_update.emit(70 + i * 5, f"Executing: {cmd[:40]}...")
                    return_code, output = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=30)
                    parent_self.append_output(output)
                    if return_code != 0:
                        success = False
                        break
                    success = True
                
                if success:
                    parent_self.progress_update.emit(95, "Configuring shell PATH...")
                    parent_self.append_output("Attempting to automatically configure shell PATH for /data/local/bin...")
                    # This is a more robust way to add to PATH for /data/local/bin
                    # It creates a wrapper script for 'sh' that includes /data/local/bin in PATH
                    shell_wrapper_script_content = "#!/system/bin/sh\\nexport PATH=/data/local/bin:$PATH\\nexec /system/bin/sh \"$@\""
                    path_commands = [
                        f"echo -e '{shell_wrapper_script_content}' > /data/local/sh_wrapper",
                        "chmod 755 /data/local/sh_wrapper",
                        "mount -o remount,rw /", # Remount rootfs if needed for symlink
                        "mv /system/bin/sh /system/bin/sh_real", # Backup original sh
                        "ln -s /data/local/sh_wrapper /system/bin/sh" # Symlink to wrapper
                    ]
                    for cmd in path_commands:
                        return_code, output = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=15)
                        parent_self.append_output(output)
                        if return_code != 0:
                            parent_self.append_output(f"Warning: Failed to execute PATH configuration command: {cmd}")
                    parent_self.append_output("Shell PATH configured (may require reboot to take full effect).")

            # 7. Cleanup
            parent_self.progress_update.emit(98, "Cleaning up temporary files...")
            parent_self.device_manager.execute_adb_command(["shell", "rm", device_tmp_path])
            if temp_busybox_file_on_host and os.path.exists(temp_busybox_file_on_host):
                os.remove(temp_busybox_file_on_host)

            if success:
                parent_self.append_output("BusyBox installed successfully")
                parent_self.progress_update.emit(100, "Finished.")
                parent_self.operation_finished.emit(True, "BusyBox installed successfully!")
            else:
                parent_self.append_output("Failed to install BusyBox")
                parent_self.operation_finished.emit(False, "Failed to install BusyBox. Check the log for details.")

        except requests.exceptions.RequestException as e:
            parent_self.operation_finished.emit(False, f"Network error downloading BusyBox: {e}")
        except Exception as e:
            logging.error(f"BusyBox installation failed: {e}\n{traceback.format_exc()}")
            parent_self.operation_finished.emit(False, f"An unexpected error occurred: {e}")
        finally:
            if temp_busybox_file_on_host and os.path.exists(temp_busybox_file_on_host):
                try:
                    os.remove(temp_busybox_file_on_host)
                except Exception as e:
                    parent_self.append_output(f"Error cleaning up local temp file: {e}")

    def append_output(self, text):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n")
        self.output_text.setTextCursor(cursor)
        self.output_text.ensureCursorVisible()

    def setup_commandline_tools(self):
        """Startet den Download und die Einrichtung der Android SDK Command-line Tools."""
        self.progress_dialog = QProgressDialog("Starte Einrichtung...", "Abbrechen", 0, 100, self)
        self.progress_dialog.setWindowTitle("Einrichtung der Command-line Tools")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.show()

        self.thread = QThread()
        self.worker = Worker(self._commandline_tools_worker, self)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _commandline_tools_worker(self, worker_instance, parent_self):
        """Worker-Funktion zum Herunterladen und Extrahieren der Command-line Tools."""
        try:
            if sys.platform != "win32":
                parent_self.operation_finished.emit(False, "Die automatische Installation wird derzeit nur für Windows unterstützt.")
                return
            
            tools_dir = os.path.join(os.getcwd(), "tools")
            sdk_dir = os.path.join(tools_dir, "sdk")
            os.makedirs(sdk_dir, exist_ok=True)

            # 1. Download der Command-line Tools
            download_url = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
            parent_self.progress_update.emit(5, "Lade Command-line Tools herunter...")
            parent_self.append_output(f"Lade herunter von: {download_url}")

            zip_path = os.path.join(tempfile.gettempdir(), "commandlinetools.zip")
            with requests.get(download_url, stream=True, timeout=300) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                downloaded = 0
                with open(zip_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if parent_self.progress_dialog and parent_self.progress_dialog.wasCanceled(): raise InterruptedError("Download abgebrochen")
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = 5 + int((downloaded / total_size) * 40) # 5-45%
                            parent_self.progress_update.emit(progress, f"Download: {downloaded // 1024**2} MB / {total_size // 1024**2} MB")

            # 2. Entpacken und Ordnerstruktur korrigieren
            parent_self.progress_update.emit(50, "Extrahiere SDK-Manager...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Extrahiere in einen temporären Unterordner, um Namenskonflikte zu vermeiden
                temp_extract_dir = os.path.join(sdk_dir, "temp_extract")
                zip_ref.extractall(temp_extract_dir)
            
            # Korrekte Ordnerstruktur herstellen: sdk/cmdline-tools/latest
            # Der Inhalt des Zips ist in einem 'cmdline-tools' Ordner
            extracted_cmdline_tools_dir = os.path.join(temp_extract_dir, "cmdline-tools")
            target_dir = os.path.join(sdk_dir, "cmdline-tools", "latest")
            
            # Verschiebe den Inhalt des extrahierten 'cmdline-tools' Ordners in das 'latest' Verzeichnis
            if os.path.isdir(extracted_cmdline_tools_dir):
                shutil.copytree(extracted_cmdline_tools_dir, target_dir, dirs_exist_ok=True)
                shutil.rmtree(temp_extract_dir, ignore_errors=True) # Bereinige den temporären Extraktionsordner
            
            os.remove(zip_path)

            # NEU: Java-Prüfung und automatische Installation
            parent_self.progress_update.emit(55, "Suche nach Java (JDK)...")
            parent_self.append_output("Überprüfe auf Java (JDK) Installation...")
            java_home = None
            # 1. Prüfe, ob JAVA_HOME bereits gesetzt ist und gültig ist
            if os.environ.get("JAVA_HOME") and os.path.exists(os.path.join(os.environ.get("JAVA_HOME"), "bin", "java.exe")):
                java_home = os.environ.get("JAVA_HOME")
                parent_self.append_output(f"Gefundenes JAVA_HOME: {java_home}")
            
            # 2. Prüfe, ob 'java' im System-PATH ist
            if not java_home:
                java_exe_path = shutil.which("java")
                if java_exe_path:
                    # Versuche, JAVA_HOME aus dem Pfad abzuleiten
                    java_home = os.path.dirname(os.path.dirname(os.path.abspath(java_exe_path)))
                    parent_self.append_output(f"Gefundenes 'java' im PATH. Abgeleitetes JAVA_HOME: {java_home}")

            # 3. Prüfe auf lokale Installation
            local_jdk_path = os.path.join(tools_dir, "jdk")
            if not java_home and os.path.exists(os.path.join(local_jdk_path, "bin", "java.exe")):
                java_home = local_jdk_path
                parent_self.append_output(f"Gefundene lokale JDK-Installation: {java_home}")

            # 4. Wenn immer noch nicht gefunden, automatisch installieren
            if not java_home:
                parent_self.append_output("Keine Java-Installation gefunden. Starte automatische Installation von OpenJDK 17...")
                # URL für Eclipse Adoptium OpenJDK 17 (LTS) für Windows x64
                jdk_zip_url = "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse"
                jdk_zip_path = os.path.join(tempfile.gettempdir(), "openjdk.zip")

                parent_self.progress_update.emit(56, "Lade OpenJDK 17 herunter...")
                parent_self.append_output(f"Lade herunter von: {jdk_zip_url}")
                
                with requests.get(jdk_zip_url, stream=True, timeout=300) as r:
                    r.raise_for_status()
                    total_size = int(r.headers.get('content-length', 0))
                    downloaded = 0
                    with open(jdk_zip_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            if parent_self.progress_dialog and parent_self.progress_dialog.wasCanceled(): raise InterruptedError("Download abgebrochen")
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = 56 + int((downloaded / total_size) * 2) # Skaliert auf 56-58%
                                parent_self.progress_update.emit(progress, f"Download JDK: {downloaded // 1024**2} MB / {total_size // 1024**2} MB")
                
                parent_self.progress_update.emit(58, "Extrahiere OpenJDK...")
                parent_self.append_output("Extrahiere OpenJDK...")
                
                with zipfile.ZipFile(jdk_zip_path, 'r') as zip_ref:
                    temp_extract_path = os.path.join(tools_dir, "jdk_temp_extract")
                    os.makedirs(temp_extract_path, exist_ok=True)
                    zip_ref.extractall(temp_extract_path)
                
                extracted_folder_name = os.listdir(temp_extract_path)[0]
                extracted_folder_path = os.path.join(temp_extract_path, extracted_folder_name)

                if os.path.exists(local_jdk_path): shutil.rmtree(local_jdk_path)
                shutil.move(extracted_folder_path, local_jdk_path)
                
                shutil.rmtree(temp_extract_path); os.remove(jdk_zip_path)
                java_home = local_jdk_path
                parent_self.append_output(f"OpenJDK 17 erfolgreich installiert in: {java_home}")

            # 3. SDK-Manager ausführen, um Emulator und Platform-Tools zu installieren
            parent_self.progress_update.emit(60, "Akzeptiere SDK-Lizenzen...")
            sdkmanager_path = os.path.join(sdk_dir, "cmdline-tools", "latest", "bin", "sdkmanager.bat")
            
            # Umgebung für den Popen-Aufruf vorbereiten
            sdk_env = os.environ.copy()
            sdk_env["JAVA_HOME"] = java_home

            # Schritt 1: Lizenzen automatisch akzeptieren
            parent_self.append_output("Versuche, alle SDK-Lizenzen automatisch zu akzeptieren...")
            license_process = subprocess.Popen(
                [sdkmanager_path, "--licenses"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8',
                errors='replace',
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                env=sdk_env
            )
            try:
                # Sende genug 'y' um alle Lizenzen zu akzeptieren
                license_stdout, license_stderr = license_process.communicate(input='y\ny\ny\ny\ny\ny\ny\n', timeout=120)
                parent_self.append_output(license_stdout)
                if license_process.returncode != 0:
                    # Dies ist oft kein kritischer Fehler, nur eine Warnung ausgeben
                    parent_self.append_output(f"[WARNUNG] Lizenz-Akzeptierung meldet Exit-Code: {license_process.returncode}. Das ist oft unproblematisch.\n{license_stderr}")
                else:
                    parent_self.append_output("Lizenzen erfolgreich akzeptiert.")
            except subprocess.TimeoutExpired:
                license_process.kill()
                parent_self.append_output("[FEHLER] Timeout beim Akzeptieren der Lizenzen.")
                raise RuntimeError("SDK Manager timed out during license acceptance.")

            # Schritt 2: Komponenten installieren
            parent_self.progress_update.emit(70, "Installiere Emulator & Platform-Tools...")
            parent_self.append_output("Installiere 'emulator' und 'platform-tools'...")
            
            # Verwende Popen, um die Ausgabe in Echtzeit zu verarbeiten und den Fortschritt anzuzeigen
            process = subprocess.Popen(
                [sdkmanager_path, f"--sdk_root={sdk_dir}", "platform-tools", "emulator", "--channel=3"], # channel=3 for stable
                stdin=subprocess.DEVNULL, # Keine Eingabe mehr nötig, da Lizenzen akzeptiert sind
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding='utf-8',
                errors='replace',
                shell=False, # shell=True ist hier problematisch
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                env=sdk_env
            )
                
            
            # Echtzeit-Ausgabe für den Fortschritt verarbeiten
            while True:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    parent_self.append_output(line)
                
                    # Parse den Fortschritt aus der sdkmanager-Ausgabe
                    match = re.search(r'\[\s*(\d+)%\]', line)
                    if match:
                        sdk_progress = int(match.group(1))
                        # Skaliere den sdkmanager-Fortschritt auf den Bereich 70-95% des Gesamtvorgangs
                        total_progress = 70 + int(sdk_progress * 0.25)
                        parent_self.progress_update.emit(total_progress, f"Installiere SDK-Komponenten: {sdk_progress}%")
            
            if process.returncode != 0:
                raise RuntimeError(f"SDK Manager konnte die Komponenten nicht installieren (Exit-Code: {process.returncode}).")

            # 4. Pfad in den Einstellungen speichern
            parent_self.progress_update.emit(95, "Speichere Einstellungen...")
            with settings_lock:
                settings.setValue("sdk_path", sdk_dir)
            parent_self.operation_finished.emit(True, "Command-line Tools erfolgreich eingerichtet. Bitte klicken Sie erneut auf 'Refresh'.")

        except Exception as e:
            logging.error(f"Command-line tools setup failed: {e}\n{traceback.format_exc()}")
            parent_self.operation_finished.emit(False, f"Einrichtung fehlgeschlagen: {e}")

    def refresh_emulators_list(self):
        """Lädt die Liste der verfügbaren Emulatoren und füllt die ComboBox."""
        self.emulator_combo.clear()
        self.append_output("Suche nach verfügbaren Emulatoren...")
        
        emulator_path = self.find_emulator_path()
        if not emulator_path or not os.path.exists(emulator_path):
            self.append_output("[FEHLER] 'emulator' ausführbare Datei nicht gefunden.")
            
            # Biete automatische Installation an
            reply = QMessageBox.question(self, "Emulator-Tools nicht gefunden",
                                         "Die Android SDK Command-line Tools (emulator) wurden nicht gefunden.\n\n"
                                         "Möchten Sie versuchen, sie jetzt automatisch herunterzuladen und einzurichten?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.setup_commandline_tools()
            else:
                self.emulator_combo.addItem("Emulator-Tool nicht gefunden")
                self.emulator_combo.setEnabled(False)
                self.start_emulator_btn.setEnabled(False)
            return

        self.emulator_combo.setEnabled(True)
        self.start_emulator_btn.setEnabled(True)

        try:
            result = subprocess.run([emulator_path, "-list-avds"], capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace')
            if result.returncode == 0 and result.stdout.strip():
                avds = result.stdout.strip().splitlines()
                self.emulator_combo.addItems(avds)
                self.append_output(f"Gefunden: {', '.join(avds)}")
            else:
                self.append_output("Keine Emulatoren gefunden oder Fehler beim Auflisten.")
                self.emulator_combo.addItem("Keine AVDs gefunden")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.append_output(f"[FEHLER] Fehler beim Ausführen des Emulator-Befehls: {e}")

    def start_selected_emulator(self):
        """Startet den ausgewählten Emulator mit den gewählten Flags."""
        avd_name = self.emulator_combo.currentText()
        if not avd_name or "nicht gefunden" in avd_name or "Keine AVDs" in avd_name:
            CopyableMessageBox.warning(self, "Fehler", "Kein gültiger Emulator ausgewählt.")
            return

        emulator_path = self.find_emulator_path()
        if not emulator_path:
            CopyableMessageBox.warning(self, "Fehler", "'emulator' ausführbare Datei nicht gefunden.")
            return

        command = [emulator_path, "-avd", avd_name]
        if self.writable_system_check.isChecked():
            command.append("-writable-system")

        self.append_output(f"Starte Emulator: {' '.join(command)}")
        subprocess.Popen(command) # Startet den Prozess, ohne darauf zu warten

    def root_emulator(self):
        """Führt die Schritte zum Rooten eines Emulators aus."""
        if not self.device_manager.current_device:
            CopyableMessageBox.warning(self, "Fehler", "Kein Gerät ausgewählt.")
            return

        confirm = QMessageBox.question(
            self, "Emulator Rooten Bestätigen",
            "<b>Wichtige Voraussetzungen:</b>\n\n"
            "1. Verwenden Sie ein Emulator-Image <b>ohne 'Google Play'</b> (z.B. 'Google APIs' oder AOSP).\n"
            "2. Starten Sie den Emulator von der Kommandozeile mit dem Flag <b>-writable-system</b>.\n"
            "   (z.B. `emulator -avd Your_AVD_Name -writable-system`)\n\n"
            "Sind diese Bedingungen erfüllt?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.thread = QThread()
        self.worker = Worker(self._root_emulator_worker, self)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _ask_for_reboot(self):
        """Fragt den Benutzer im Hauptthread nach einem Neustart."""
        reply = QMessageBox.question(
            self, "Neustart Erforderlich",
            "Der erste 'remount'-Versuch ist wie erwartet fehlgeschlagen. Dies ist notwendig, um Android Verity zu deaktivieren.\n\n"
            "Soll das Tool den Emulator jetzt neu starten und den Vorgang automatisch wiederholen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.continue_root_after_reboot()
        else:
            self.operation_finished.emit(False, "Vorgang vom Benutzer abgebrochen.")

    def continue_root_after_reboot(self):
        """Setzt den Root-Vorgang nach Bestätigung des Neustarts fort."""
        self.thread = QThread()
        self.worker = Worker(self._reboot_and_retry_worker, self)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _root_emulator_worker(self, worker_instance, parent_self):
        """Führt den Root-Vorgang im Hintergrund aus, inklusive möglichem Neustart."""
        parent_self.append_output("--- Starte Emulator-Root-Vorgang (Versuch 1) ---")

        # Versuch 1
        remount_status = parent_self._attempt_remount(worker_instance)

        if remount_status == 'REBOOT_NEEDED':
            parent_self.append_output("\n[INFO] 'remount' ist fehlgeschlagen. Dies ist bei modernen Emulatoren normal.")
            parent_self.append_output("Ein Neustart ist erforderlich, um Verity zu deaktivieren.")
            # Frage im Hauptthread nach, anstatt direkt hier.
            QTimer.singleShot(0, parent_self._ask_for_reboot)
        elif remount_status == 'SUCCESS':
            parent_self.operation_finished.emit(True, "Emulator-Root-Vorgang erfolgreich abgeschlossen. Das System ist jetzt beschreibbar.")
        else:
            parent_self.operation_finished.emit(False, "Emulator-Root-Vorgang fehlgeschlagen. Bitte prüfen Sie die Logs.")

    def _reboot_and_retry_worker(self, worker_instance, parent_self):
        """Führt den Neustart und den zweiten Root-Versuch im Hintergrund durch."""
        parent_self.append_output("\n--- Starte Emulator neu und warte... ---")
        current_device_id = parent_self.device_manager.current_device
        parent_self.device_manager.execute_adb_command(["shell", "reboot"])
        parent_self.append_output("Warte auf Trennung des Geräts...")
        parent_self.device_manager.wait_for_disconnect(current_device_id, timeout=20)
        parent_self.append_output("Gerät getrennt. Warte auf Wiederverbindung...")
        parent_self.device_manager.wait_for_connect(timeout=60)
        parent_self.append_output("Warte 35 Sekunden, bis der Emulator vollständig hochgefahren ist...")
        time.sleep(35)

        # WICHTIG: Nach dem Neustart muss 'adb root' erneut ausgeführt werden.
        parent_self.append_output("Stelle sicher, dass ADB nach dem Neustart als Root läuft...")
        _, root_output = parent_self.device_manager.execute_adb_command(["root"])
        parent_self.append_output(root_output)

        # Prüfen, ob 'adb root' erfolgreich war
        if not ("restarting adbd as root" in root_output or "adbd is already running as root" in root_output):
            parent_self.append_output("Fehler: Konnte ADB nach Neustart nicht als Root starten.")
            parent_self.operation_finished.emit(False, "Emulator-Root-Vorgang nach Neustart fehlgeschlagen: ADB konnte nicht als Root gestartet werden.")
            return

        # Warte kurz, damit der adbd neu starten kann
        time.sleep(3)

        # NEU: Bei neueren Emulatoren (API 34+) ist es oft notwendig, den Remount-Dienst explizit neu zu starten.
        parent_self.append_output("Setze Remount-Dienst zurück (für moderne Emulatoren)...")
        _, remount_r_output = parent_self.device_manager.execute_adb_command(["shell", "remount", "-R"])
        parent_self.append_output(remount_r_output)

        parent_self.append_output("\n--- Starte Emulator-Root-Vorgang (Versuch 2) ---")
        remount_status = parent_self._attempt_remount(worker_instance)

        if remount_status == 'SUCCESS':
            parent_self.operation_finished.emit(True, "Emulator-Root-Vorgang erfolgreich abgeschlossen. Das System ist jetzt beschreibbar.")
        else:
            parent_self.operation_finished.emit(False, "Emulator-Root-Vorgang nach Neustart fehlgeschlagen. Bitte prüfen Sie die Logs.")

    def _attempt_remount(self, worker_instance):
        """Führt einen einzelnen 'adb root' und 'adb remount' Versuch durch und gibt den Status zurück."""
        # 1. adb root
        self.append_output("1. Versuche, ADB als Root neuzustarten...")
        root_return_code, root_output = self.device_manager.execute_adb_command(["root"])
        self.append_output(root_output)

        # Prüfen, ob 'adb root' erfolgreich war
        if not ("restarting adbd as root" in root_output or "adbd is already running as root" in root_output):
            self.append_output("Fehler: Konnte ADB nicht als Root starten. Ist der Bootloader entsperrt oder ist es ein non-Google-Play-Image?")
            return 'FAILURE'
        
        # Warte kurz, damit der adbd neu starten kann, falls er gerade neu gestartet wurde
        if "restarting adbd as root" in root_output:
            self.append_output("ADB startet neu... warte 3 Sekunden.")
            time.sleep(3)

        # 2. adb remount
        self.append_output("\n2. Versuche, Systempartition als beschreibbar einzubinden ('remount')...")
        remount_return_code, remount_output = self.device_manager.execute_adb_command(["remount"])
        self.append_output(remount_output)

        # Priorisiere expliziten Erfolg und erfolgreichen Return Code
        if remount_return_code == 0 and "remount succeeded" in remount_output:
            return 'SUCCESS'
        # Wenn Return Code ungleich 0 ist, aber die "Neustart erforderlich"-Meldung erscheint, ist es ein gültiger erster Schritt
        elif remount_return_code != 0 and ("overlayfs enabled. Now reboot your device" in remount_output or "No remountable partitions were found" in remount_output):
            return 'REBOOT_NEEDED'
        else:
            return 'FAILURE'

    def update_progress(self, value, text):
        if self.progress_dialog:
            if self.progress_dialog.wasCanceled():
                # Hier könnte man den Worker-Thread abbrechen
                return
            self.progress_dialog.setValue(value)
            self.progress_dialog.setLabelText(text)

    def on_operation_finished(self, success, message):
        self.append_output(f"\n--- {message} ---")
        if not success:
            CopyableMessageBox.warning(self, "Operation Failed", message)
        
        # Delay closing and setting to None to avoid race conditions with rapid progress updates
        def cleanup_dialog():
            if self.progress_dialog:
                self.progress_dialog.close()
                self.progress_dialog = None
        
        QTimer.singleShot(0, cleanup_dialog)

    def download_ota_zip(self):
        """Startet den Prozess zum Herunterladen einer OTA-ZIP und Extrahieren von payload.bin."""
        url, ok = QInputDialog.getText(self, "Download OTA ZIP", "Geben Sie die URL der OTA-Update-ZIP-Datei ein:")
        if not (ok and url.strip()):
            return

        output_dir = QFileDialog.getExistingDirectory(self, "Wählen Sie das Verzeichnis zum Speichern von payload.bin")
        if not output_dir:
            return

        self.progress_dialog = QProgressDialog("Download wird gestartet...", "Abbrechen", 0, 100, self)
        self.progress_dialog.setWindowTitle("OTA Download & Extraktion")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.show()

        self.thread = QThread()
        self.worker = Worker(self._download_and_extract_worker, self, url, output_dir)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _download_and_extract_worker(self, worker_instance, parent_self, url, output_dir):
        """Worker-Funktion zum Herunterladen und Extrahieren der OTA-ZIP."""
        zip_path = os.path.join(tempfile.gettempdir(), "ota_update.zip")
        try:
            # 1. Download der ZIP-Datei
            parent_self.append_output(f"--- Starte Download von {url} ---")
            parent_self.progress_update.emit(0, "Download wird gestartet...")
            
            with requests.get(url, stream=True, timeout=30) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                downloaded = 0
                with open(zip_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if parent_self.progress_dialog and parent_self.progress_dialog.wasCanceled():
                            raise InterruptedError("Download abgebrochen")
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = int((downloaded / total_size) * 80) # Download ist 80% des Prozesses
                            parent_self.progress_update.emit(progress, f"Download: {downloaded // 1024**2} MB / {total_size // 1024**2} MB")

            # 2. Extrahieren von payload.bin
            parent_self.append_output("\n--- Suche und extrahiere payload.bin ---")
            parent_self.progress_update.emit(85, "Extrahiere payload.bin...")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                if 'payload.bin' not in zip_ref.namelist():
                    raise FileNotFoundError("payload.bin nicht in der ZIP-Datei gefunden.")
                
                zip_ref.extract('payload.bin', output_dir)
                payload_final_path = os.path.join(output_dir, 'payload.bin')
                parent_self.append_output(f"payload.bin erfolgreich extrahiert nach: {payload_final_path}")

            parent_self.operation_finished.emit(True, f"Download und Extraktion erfolgreich!\n\npayload.bin wurde gespeichert in:\n{output_dir}")

        except Exception as e:
            logging.error(f"OTA download/extract failed: {e}\n{traceback.format_exc()}")
            parent_self.operation_finished.emit(False, f"Ein Fehler ist aufgetreten: {e}")
        finally:
            # Temporäre ZIP-Datei löschen
            if os.path.exists(zip_path):
                os.remove(zip_path)

    def extract_boot_image_from_payload(self):
        """Startet den Prozess zum Extrahieren von boot.img aus einer payload.bin."""
        payload_path, _ = QFileDialog.getOpenFileName(self, "Select payload.bin", "", "Payload Files (payload.bin)")
        if not payload_path:
            return

        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not output_dir:
            return

        self.progress_dialog = QProgressDialog("Preparing extraction...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Extracting Images")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.show()

        self.thread = QThread()
        self.worker = Worker(self._extract_payload_worker, self, payload_path, output_dir)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _extract_payload_worker(self, worker_instance, parent_self, payload_path, output_dir):
        """Worker-Funktion zum Extrahieren der payload.bin."""
        try:
            # 1. Finde oder lade payload-dumper-go
            parent_self.progress_update.emit(5, "Finding payload-dumper-go...")
            dumper_path = self._find_or_download_payload_dumper(parent_self)
            if not dumper_path:
                parent_self.operation_finished.emit(False, "payload-dumper-go could not be set up.")
                return

            # 2. Starte den Extraktionsprozess
            parent_self.progress_update.emit(20, "Starting extraction process...")
            parent_self.append_output(f"--- Starting extraction of {os.path.basename(payload_path)} ---")
            parent_self.append_output(f"Output directory: {output_dir}")

            command = [dumper_path, "-o", output_dir, payload_path]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    parent_self.append_output(line)
                    # Versuche, den Fortschritt aus der Ausgabe zu parsen
                    match = re.search(r'(\d+)/(\d+)', line)
                    if match:
                        current, total = int(match.group(1)), int(match.group(2))
                        progress = 20 + int((current / total) * 75) # Skaliere auf 20-95%
                        parent_self.progress_update.emit(progress, f"Extracting: {line}")

            process.wait()
            parent_self.progress_update.emit(98, "Finalizing...")

            # 3. Überprüfe das Ergebnis
            boot_img_path = os.path.join(output_dir, "boot.img")
            if os.path.exists(boot_img_path):
                parent_self.operation_finished.emit(True, f"Extraction successful!\nboot.img found at:\n{boot_img_path}")
            else:
                parent_self.operation_finished.emit(False, "Extraction finished, but boot.img was not found in the output directory.")

        except Exception as e:
            logging.error(f"Payload extraction failed: {e}\n{traceback.format_exc()}")
            parent_self.operation_finished.emit(False, f"An error occurred during extraction: {e}")

    def _find_or_download_payload_dumper(self, parent_self):
        """Findet payload-dumper-go oder lädt es herunter."""
        tools_dir = os.path.join(os.getcwd(), "tools")
        dumper_name = "payload-dumper-go.exe" if sys.platform == "win32" else "payload-dumper-go"
        dumper_path = os.path.join(tools_dir, dumper_name)

        if os.path.exists(dumper_path):
            parent_self.append_output("payload-dumper-go found.")
            return dumper_path

        if sys.platform != "win32":
            parent_self.append_output("Automatic download for non-Windows is not supported. Please install 'payload-dumper-go' manually in the 'tools' directory.")
            return None

        # Download für Windows
        parent_self.append_output("payload-dumper-go not found, attempting to download for Windows...")
        download_url = "https://github.com/ssut/payload-dumper-go/releases/download/1.2.2/payload-dumper-go_1.2.2_windows_amd64.zip"
        
        os.makedirs(tools_dir, exist_ok=True)
        zip_path = os.path.join(tools_dir, "dumper.zip")

        try:
            response = requests.get(download_url, stream=True, timeout=300)
            response.raise_for_status()
            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            parent_self.append_output("Download complete. Extracting...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extract("payload-dumper-go.exe", tools_dir)
            os.remove(zip_path)
            return dumper_path
        except Exception as e:
            parent_self.append_output(f"Download failed: {e}")
            return None

    def extract_boot_image_from_device(self):
        """Startet den Prozess zum Extrahieren von boot.img von einem gerooteten Gerät."""
        if not self.is_root():
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "Save boot.img", os.path.join(os.path.expanduser("~"), "boot.img"), "Image Files (*.img)")
        if not save_path:
            return

        self.progress_dialog = QProgressDialog("Starting extraction...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Extracting boot.img from Device")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.show()

        self.thread = QThread()
        self.worker = Worker(self._extract_boot_from_device_worker, self, save_path)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _extract_boot_from_device_worker(self, worker_instance, parent_self, save_path):
        """Worker-Funktion zum Extrahieren von boot.img vom Gerät."""
        device_temp_path = "/data/local/tmp/boot.img"
        try:
            # 1. Finde die aktive Boot-Partition
            parent_self.progress_update.emit(10, "Finding active boot partition...")
            parent_self.append_output("--- Finding active boot partition ---")
            return_code, slot_suffix = parent_self.device_manager.execute_adb_command(["shell", "getprop", "ro.boot.slot_suffix"])

            if return_code == 0 and slot_suffix.strip() in ["_a", "_b"]:
                slot = slot_suffix.strip()
                boot_partition = f"boot{slot}"
                parent_self.append_output(f"A/B device detected. Active slot: {slot}")
            else:
                boot_partition = "boot"
                parent_self.append_output("Non-A/B device detected.")

            # Versuche verschiedene Pfade für die Boot-Partition
            possible_paths = [f"/dev/block/by-name/{boot_partition}", f"/dev/block/bootdevice/by-name/{boot_partition}"]
            boot_block_path = None
            for path in possible_paths:
                check_code, _ = parent_self.device_manager.execute_adb_command(["shell", "su", "-c", f"test -e {path}"])
                if check_code == 0:
                    boot_block_path = path
                    break
            
            if not boot_block_path:
                parent_self.operation_finished.emit(False, f"Could not find boot partition block device for '{boot_partition}'.")
                return

            parent_self.append_output(f"Found boot partition at: {boot_block_path}")

            # 2. Dump der Partition mit 'dd'
            parent_self.progress_update.emit(30, "Dumping boot partition with 'dd'...")
            parent_self.append_output(f"Dumping {boot_block_path} to {device_temp_path}...")
            dd_cmd = ["shell", "su", "-c", f"dd if={boot_block_path} of={device_temp_path}"]
            return_code, output = parent_self.device_manager.execute_adb_command(dd_cmd, timeout=120)
            if return_code != 0:
                parent_self.operation_finished.emit(False, f"Failed to dump boot partition: {output}")
                return

            # 3. Pull der Imagedatei
            parent_self.progress_update.emit(70, "Pulling boot.img to PC...")
            parent_self.append_output(f"Pulling {device_temp_path} to PC...")
            return_code, output = parent_self.device_manager.execute_adb_command(["pull", device_temp_path, save_path], timeout=120)
            if return_code != 0:
                parent_self.operation_finished.emit(False, f"Failed to pull boot.img: {output}")
                return

            # 4. Cleanup
            parent_self.progress_update.emit(95, "Cleaning up temporary file...")
            parent_self.device_manager.execute_adb_command(["shell", "su", "-c", f"rm {device_temp_path}"])

            parent_self.operation_finished.emit(True, f"boot.img successfully extracted to:\n{save_path}")

        except Exception as e:
            logging.error(f"Boot image extraction from device failed: {e}\n{traceback.format_exc()}")
            parent_self.operation_finished.emit(False, f"An error occurred during extraction: {e}")
        finally:
            # Ensure cleanup is attempted even on failure
            parent_self.device_manager.execute_adb_command(["shell", "su", "-c", f"rm {device_temp_path}"])

    def is_root(self):
        """Checks for root and shows a message if not available."""
        self.append_output("Checking for root access...")
        return_code, _ = self.device_manager.execute_adb_command(["shell", "su", "-c", "echo Root check"])
        if return_code == 0:
            self.append_output("Root access confirmed.")
            return True
        else:
            self.append_output("Root access is required for this operation.")
            CopyableMessageBox.warning(self, "Root Required", "This operation requires root access, which was not detected.")
            return False

class BuildPropEditorDialog(QDialog):
    def __init__(self, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle("build.prop Editor")
        self.setMinimumSize(700, 600)
        
        layout = QVBoxLayout(self)
        
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setPlainText(content)
        layout.addWidget(self.editor)
        
        warning_label = QLabel("<b>Warning:</b> Incorrectly editing build.prop can cause your device to fail to boot.")
        warning_label.setStyleSheet("color: #e74c3c;")
        layout.addWidget(warning_label)

        button_box = QHBoxLayout()
        save_btn = QPushButton("Save and Reboot")
        cancel_btn = QPushButton("Cancel")
        button_box.addWidget(save_btn)
        button_box.addWidget(cancel_btn)
        layout.addLayout(button_box)

        save_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)

class RootToolsTab_OLD(QWidget):
    install_progress = pyqtSignal(int, str)
    install_finished = pyqtSignal(bool, str)

    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()  # Thread safety for root operations
        self.init_ui()
        self.progress_dialog = None
        self.is_installing_busybox = False

        self.install_progress.connect(self.update_install_progress)
        self.install_finished.connect(self.on_install_finished)
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        root_group = QGroupBox("Root Access")
        root_layout = QVBoxLayout()
        
        self.root_status_label = QLabel("Root status: Unknown")
        self.root_status_label.setStyleSheet("font-weight: bold;")
        
        self.check_root_btn = QPushButton("Check Root Access")
        self.check_root_btn.clicked.connect(self.check_root_access)
        
        self.grant_root_btn = QPushButton("Grant Temporary Root")
        self.grant_root_btn.clicked.connect(self.grant_temp_root)
        
        self.install_su_btn = QPushButton("Install SuperSU")
        self.install_su_btn.clicked.connect(self.install_supersu)
        
        self.root_emulator_btn = QPushButton("Root Emulator")
        self.root_emulator_btn.clicked.connect(self.root_emulator)
        
        self.remove_bloatware_btn = QPushButton("System-Apps entfernen")
        self.remove_bloatware_btn.clicked.connect(self.remove_bloatware)
        
        self.unroot_btn = QPushButton("Remove Root")
        self.unroot_btn.setVisible(False) # This is too risky and unreliable
        
        root_btn_layout = QHBoxLayout()
        root_btn_layout.addWidget(self.check_root_btn)
        root_btn_layout.addWidget(self.grant_root_btn)
        
        install_btn_layout = QHBoxLayout()
        install_btn_layout.addWidget(self.install_su_btn)
        install_btn_layout.addWidget(self.root_emulator_btn)
        install_btn_layout.addWidget(self.remove_bloatware_btn)
        
        root_layout.addWidget(self.root_status_label)
        root_layout.addLayout(root_btn_layout)
        root_layout.addLayout(install_btn_layout)
        root_layout.addWidget(self.unroot_btn)
        root_group.setLayout(root_layout)
        
        system_group = QGroupBox("System Modifications")
        system_layout = QVBoxLayout()
        
        self.mount_system_btn = QPushButton("Mount /system as RW")
        self.mount_system_btn.clicked.connect(self.mount_system_rw)
        
        self.remount_btn = QPushButton("Remount Partitions")
        self.remount_btn.clicked.connect(self.remount_partitions)
        
        self.push_system_btn = QPushButton("Push File to /system")
        self.push_system_btn.clicked.connect(self.push_to_system)
        
        self.pull_system_btn = QPushButton("Pull File from /system")
        self.pull_system_btn.clicked.connect(self.pull_from_system)
        
        system_btn_layout = QHBoxLayout()
        system_btn_layout.addWidget(self.mount_system_btn)
        system_btn_layout.addWidget(self.remount_btn)
        
        system_file_layout = QHBoxLayout()
        system_file_layout.addWidget(self.push_system_btn)
        system_file_layout.addWidget(self.pull_system_btn)
        
        system_layout.addLayout(system_btn_layout)
        system_layout.addLayout(system_file_layout)
        system_group.setLayout(system_layout)
        
        advanced_group = QGroupBox("Advanced Root Commands")
        advanced_layout = QVBoxLayout()
        
        self.fix_permissions_btn = QPushButton("Fix Permissions")
        self.fix_permissions_btn.clicked.connect(self.fix_permissions)
        
        self.install_busybox_btn = QPushButton("Install BusyBox")
        self.install_busybox_btn.clicked.connect(self.install_busybox)
        advanced_layout.addWidget(self.fix_permissions_btn)
        advanced_layout.addWidget(self.install_busybox_btn)
        advanced_group.setLayout(advanced_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        
        layout.addWidget(root_group)
        layout.addWidget(system_group)
        layout.addWidget(advanced_group)
        layout.addWidget(self.output_text)
        
        self.setLayout(layout)
    
    def check_root_access(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Checking root access...")
            try:
                root_checks = [
                    "su -c 'echo Root check'",
                    "which su",
                    "ls /system/xbin/su",
                    "ls /system/bin/su",
                    "ls /sbin/su",
                    "ls /system/su",
                    "ls /system/bin/.ext/su"
                ]
                
                root_found = False
                for check in root_checks:
                    return_code, output = self.device_manager.execute_adb_command(f"shell {check}", timeout=10)
                    if return_code == 0:
                        root_found = True
                        break
                
                if root_found:
                    self.root_status_label.setText("Root status: Root access available")
                    self.root_status_label.setStyleSheet("color: green; font-weight: bold;")
                    self.append_output("Device has root access")
                else:
                    self.root_status_label.setText("Root status: No root access")
                    self.root_status_label.setStyleSheet("color: red; font-weight: bold;")
                    self.append_output("Device does NOT have root access")
            except Exception as e:
                self.append_output(f"Error checking root access: {str(e)}")
                self.root_status_label.setText("Root status: Check failed")
                self.root_status_label.setStyleSheet("color: orange; font-weight: bold;")
    
    def grant_temp_root(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Attempting to grant temporary root access...")
            try:
                return_code, output = self.device_manager.execute_adb_command("root", timeout=15)
                self.append_output(output)
                
                if return_code == 0:
                    QMessageBox.information(self, "Success", "Temporary root access granted. Device may reboot.")
                    self.check_root_access()  # Update status
                else:
                    QMessageBox.warning(self, "Error", "Failed to grant temporary root access")
            except subprocess.TimeoutExpired:
                self.append_output("Timeout while granting root access")
                QMessageBox.warning(self, "Error", "Timeout while granting root access")
            except Exception as e:
                self.append_output(f"Error granting root access: {str(e)}")
                QMessageBox.warning(self, "Error", f"Failed to grant root: {str(e)}")
    
    def install_supersu(self):
        with self.lock:  # Thread-safe operation
            try:
                return_code, output = self.device_manager.execute_adb_command("shell su -c 'which su'", timeout=10)
                if return_code == 0 and "/su" in output:
                    CopyableMessageBox.information(self, "Info", "SuperSU is already installed")
                    return
                
                url = "https://supersu.com/download"
                self.append_output(f"Downloading SuperSU from {url}...")
                
                try:
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        temp_dir = tempfile.gettempdir()
                        zip_path = os.path.join(temp_dir, "supersu.zip")
                        
                        with open(zip_path, "wb") as f:
                            f.write(response.content)
                        
                        self.append_output("SuperSU downloaded, installing...")
                        
                        return_code, output = self.device_manager.execute_adb_command(
                            f"push {zip_path} /sdcard/supersu.zip", 
                            timeout=60
                        )
                        self.append_output(output)
                        
                        if return_code != 0:
                            self.append_output("Failed to push SuperSU to device")
                            QMessageBox.warning(self, "Error", "Failed to push SuperSU to device")
                            return
                        
                        success, output = self.device_manager.reboot_device("recovery")
                        self.append_output(output)
                        
                        if not success:
                            self.append_output("Failed to reboot to recovery")
                            QMessageBox.warning(self, "Error", "Failed to reboot to recovery")
                            return
                        
                        self.append_output("Waiting for device to enter recovery...")
                        time.sleep(15)  # Longer wait for recovery boot
                        
                        return_code, output = self.device_manager.execute_adb_command(
                            "shell twrp --version", 
                            device_specific=False,
                            timeout=10
                        )
                        
                        if return_code != 0:
                            self.append_output("TWRP not detected, trying default recovery")
                            return_code, output = self.device_manager.execute_adb_command(
                                "shell recovery --update_package=/sdcard/supersu.zip",
                                device_specific=False,
                                timeout=300
                            )
                        else:
                            return_code, output = self.device_manager.execute_adb_command(
                                "shell twrp install /sdcard/supersu.zip", 
                                device_specific=False,
                                timeout=300
                            )
                        
                        self.append_output(output)
                        
                        if return_code == 0:
                            self.append_output("SuperSU installed successfully")
                            CopyableMessageBox.information(self, "Success", "SuperSU installed successfully")
                        else:
                            self.append_output("Failed to install SuperSU")
                            QMessageBox.warning(self, "Error", "Failed to install SuperSU")
                    else:
                        self.append_output(f"Failed to download SuperSU: HTTP {response.status_code}")
                        QMessageBox.warning(self, "Error", f"Download failed: HTTP {response.status_code}")
                except requests.exceptions.RequestException as e:
                    self.append_output(f"Network error downloading SuperSU: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Download failed: {str(e)}")
                except Exception as e:
                    self.append_output(f"Error installing SuperSU: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Installation failed: {str(e)}")
                finally:
                    if 'zip_path' in locals() and os.path.exists(zip_path):
                        try:
                            os.remove(zip_path)
                        except Exception as e:
                            self.append_output(f"Error cleaning up temp file: {str(e)}")
            except Exception as e:
                self.append_output(f"Unexpected error: {str(e)}")
                QMessageBox.warning(self, "Error", f"Operation failed: {str(e)}")
    
    def install_magisk(self):
        with self.lock:  # Thread-safe operation
            try:
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'which magisk'", 
                    timeout=10
                )
                if return_code == 0 and "/magisk" in output:
                    CopyableMessageBox.information(self, "Info", "Magisk is already installed")
                    return
                
                self.append_output("Fetching latest Magisk release...")
                try:
                    api_url = "https://api.github.com/repos/topjohnwu/Magisk/releases/latest"
                    response = requests.get(api_url, timeout=15)
                    
                    if response.status_code == 200:
                        release_data = response.json()
                        download_url = None
                        
                        for asset in release_data.get('assets', []):
                            if asset['name'].lower().endswith('.apk'):
                                download_url = asset['browser_download_url']
                                break
                        
                        if not download_url:
                            raise Exception("No APK found in latest release")
                        
                        self.append_output(f"Downloading Magisk from {download_url}...")
                        
                        temp_dir = tempfile.gettempdir()
                        apk_path = os.path.join(temp_dir, "magisk.apk")
                        
                        with requests.get(download_url, stream=True, timeout=30) as r:
                            r.raise_for_status()
                            with open(apk_path, "wb") as f:
                                for chunk in r.iter_content(chunk_size=8192):
                                    f.write(chunk)
                        
                        self.append_output("Magisk downloaded, installing...")
                        
                        return_code, output = self.device_manager.execute_adb_command(
                            f"install {apk_path}", 
                            timeout=120
                        )
                        self.append_output(output)
                        
                        if return_code == 0:
                            self.append_output("Magisk installed successfully")
                            CopyableMessageBox.information(self, "Success", "Magisk installed successfully")
                        else:
                            self.append_output("Failed to install Magisk")
                            QMessageBox.warning(self, "Error", "Failed to install Magisk")
                    else:
                        self.append_output(f"Failed to fetch release info: HTTP {response.status_code}")
                        QMessageBox.warning(self, "Error", f"Failed to get release info: HTTP {response.status_code}")
                except requests.exceptions.RequestException as e:
                    self.append_output(f"Network error downloading Magisk: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Download failed: {str(e)}")
                except Exception as e:
                    self.append_output(f"Error installing Magisk: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Installation failed: {str(e)}")
                finally:
                    if 'apk_path' in locals() and os.path.exists(apk_path):
                        try:
                            os.remove(apk_path)
                        except Exception as e:
                            self.append_output(f"Error cleaning up temp file: {str(e)}")
            except Exception as e:
                self.append_output(f"Unexpected error: {str(e)}")
                QMessageBox.warning(self, "Error", f"Operation failed: {str(e)}")
    
    def remove_root(self):
        confirm = QMessageBox.question(
            self, "Confirm Remove Root", 
            "This will attempt to remove root access from your device. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:  # Thread-safe operation
                self.append_output("Attempting to remove root access...")
                try:
                    self.append_output("Attempting SuperSU uninstall...")
                    return_code, output = self.device_manager.execute_adb_command(
                        "shell su -c 'echo \"pm uninstall eu.chainfire.supersu\" > /cache/uninstall.sh'",
                        timeout=10
                    )
                    return_code, output = self.device_manager.execute_adb_command(
                        "shell su -c 'chmod 755 /cache/uninstall.sh'",
                        timeout=10
                    )
                    return_code, output = self.device_manager.execute_adb_command(
                        "shell su -c '/cache/uninstall.sh'",
                        timeout=30
                    )
                    self.append_output(output)
                    
                    self.append_output("Attempting Magisk uninstall...")
                    return_code, output = self.device_manager.execute_adb_command(
                        "shell su -c 'magisk --remove-modules'",
                        timeout=30
                    )
                    self.append_output(output)
                    
                    self.append_output("Removing su binaries...")
                    su_paths = [
                        "/system/bin/su",
                        "/system/xbin/su",
                        "/system/bin/.ext/su",
                        "/system/etc/.installed_su_daemon",
                        "/system/bin/.ext/.su",
                        "/system/xbin/daemonsu",
                        "/system/xbin/sugote",
                        "/system/xbin/supolicy",
                        "/system/xbin/ku.sud",
                        "/system/xbin/.suv",
                        "/system/etc/init.d/99SuperSUDaemon",
                        "/system/etc/.has_su_daemon"
                    ]
                    
                    for path in su_paths:
                        return_code, output = self.device_manager.execute_adb_command(
                            f"shell su -c 'rm -f {path}'",
                            timeout=10
                        )
                        if return_code == 0:
                            self.append_output(f"Removed {path}")
                    
                    self.append_output("Root removal attempted. Reboot your device to complete the process.")
                    CopyableMessageBox.information(
                        self, 
                        "Success", 
                        "Root removal attempted. Reboot your device to complete the process."
                    )
                    self.check_root_access()  # Update status
                except Exception as e:
                    self.append_output(f"Error removing root: {str(e)}")
                    QMessageBox.warning(self, "Error", f"Failed to remove root: {str(e)}")
    
    def mount_system_rw(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Mounting /system as read-write...")
            try:
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'echo Root check'",
                    timeout=10
                )
                if return_code != 0:
                    self.append_output("Root access required for this operation")
                    QMessageBox.warning(self, "Error", "Root access required")
                    return
                
                mount_commands = [
                    "mount -o remount,rw /system",
                    "mount -o rw,remount /system",
                    "mount -o remount,rw /",
                    "mount -o rw,remount /"
                ]
                
                success = False
                for cmd in mount_commands:
                    return_code, output = self.device_manager.execute_adb_command(
                        f"shell su -c '{cmd}'",
                        timeout=15
                    )
                    if return_code == 0:
                        success = True
                        break
                
                if success:
                    self.append_output("/system mounted as read-write")
                    CopyableMessageBox.information(self, "Success", "/system mounted as read-write")
                else:
                    self.append_output("Failed to mount /system as read-write")
                    QMessageBox.warning(self, "Error", "Failed to remount /system")
            except Exception as e:
                self.append_output(f"Error mounting /system: {str(e)}")
                CopyableMessageBox.warning(self, "Error", f"Failed to remount: {str(e)}")
    
    def remount_partitions(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Remounting partitions...")
            try:
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'echo Root check'",
                    timeout=10
                )
                if return_code != 0:
                    self.append_output("Root access required for this operation")
                    QMessageBox.warning(self, "Error", "Root access required")
                    return
                
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'mount -o remount,rw /'",
                    timeout=15
                )
                self.append_output(output)
                
                if return_code == 0:
                    self.append_output("Partitions remounted successfully")
                    CopyableMessageBox.information(self, "Success", "Partitions remounted successfully")
                else:
                    self.append_output("Failed to remount partitions")
                    QMessageBox.warning(self, "Error", "Failed to remount partitions")
            except Exception as e:
                self.append_output(f"Error remounting partitions: {str(e)}")
                CopyableMessageBox.warning(self, "Error", f"Failed to remount: {str(e)}")
    
    def push_to_system(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Push", "", "All Files (*)"
        )
        
        if file_path:
            file_path = os.path.normpath(file_path)
            dest_path, ok = QInputDialog.getText(
                self, "Destination Path", "Enter destination path in /system:",
                QLineEdit.EchoMode.Normal, "/system/"
            )
            
            if ok and dest_path:
                with self.lock:  # Thread-safe operation
                    self.append_output(f"Pushing {file_path} to {dest_path}...")
                    try:
                        return_code, output = self.device_manager.execute_adb_command(
                            "shell su -c 'mount -o remount,rw /system'",
                            timeout=15
                        )
                        if return_code != 0:
                            self.append_output("Failed to remount /system as RW")
                            QMessageBox.warning(self, "Error", "Failed to remount /system")
                            return
                        
                        dest_dir = os.path.dirname(dest_path)
                        if dest_dir:
                            return_code, output = self.device_manager.execute_adb_command(
                                f"shell su -c 'mkdir -p {dest_dir}'",
                                timeout=15
                            )
                            if return_code != 0:
                                self.append_output(f"Failed to create directory {dest_dir}")
                                QMessageBox.warning(self, "Error", "Failed to create directory")
                                return
                        
                        return_code, output = self.device_manager.execute_adb_command(
                            f"push {file_path} {dest_path}",
                            timeout=60
                        )
                        self.append_output(output)
                        
                        if return_code == 0:
                            self.append_output("File pushed successfully")
                            
                            perms, ok = QInputDialog.getText(
                                self, "Set Permissions", "Enter permissions (e.g. 644):",
                                QLineEdit.EchoMode.Normal, "644"
                            )
                            
                            if ok and perms:
                                try:
                                    int(perms, 8)  # Validate octal permissions
                                    return_code, output = self.device_manager.execute_adb_command(
                                        f"shell su -c 'chmod {perms} {dest_path}'",
                                        timeout=15
                                    )
                                    self.append_output(output)
                                    if return_code == 0:
                                        self.append_output(f"Permissions set to {perms}")
                                    else:
                                        self.append_output("Failed to set permissions")
                                except ValueError:
                                    self.append_output("Invalid permission value")
                            
                            QMessageBox.information(self, "Success", "File pushed successfully")
                        else:
                            self.append_output("Failed to push file")
                            QMessageBox.warning(self, "Error", "Failed to push file")
                    except Exception as e:
                        self.append_output(f"Error pushing file: {str(e)}")
                        QMessageBox.warning(self, "Error", f"Failed to push: {str(e)}")
    
    def pull_from_system(self):
        src_path, ok = QInputDialog.getText(
            self, "Source Path", "Enter file path in /system to pull:",
            QLineEdit.EchoMode.Normal, "/system/"
        )
        
        if ok and src_path:
            dest_path, _ = QFileDialog.getSaveFileName(
                self, "Save File", os.path.basename(src_path), "All Files (*)"
            )
            
            if dest_path:
                dest_path = os.path.normpath(dest_path)
                with self.lock:  # Thread-safe operation
                    self.append_output(f"Pulling {src_path} to {dest_path}...")
                    try:
                        return_code, output = self.device_manager.execute_adb_command(
                            f"pull {src_path} {dest_path}",
                            timeout=60
                        )
                        self.append_output(output)
                        
                        if return_code == 0:
                            self.append_output("File pulled successfully")
                            CopyableMessageBox.information(self, "Success", "File pulled successfully")
                        else:
                            self.append_output("Failed to pull file")
                            QMessageBox.warning(self, "Error", "Failed to pull file")
                    except Exception as e:
                        self.append_output(f"Error pulling file: {str(e)}")
                        CopyableMessageBox.warning(self, "Error", f"Failed to pull: {str(e)}")
    
    def open_root_shell(self):
        self.append_output("Opening root shell...")
        self.append_output("Type 'exit' to quit the shell")
        
        thread = threading.Thread(target=self.run_root_shell, daemon=True)
        thread.start()
    
    def run_root_shell(self):
        try:
            process = subprocess.Popen(
                [self.device_manager.adb_path, "-s", self.device_manager.current_device, "shell", "su"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            while True:
                try:
                    command = input("root@android:# ")  # This won't work well with Qt
                    if command.lower() == "exit":
                        break
                    
                    process.stdin.write(command + "\n")
                    process.stdin.flush()
                    
                    output = process.stdout.readline()
                    while output:
                        self.append_output(output.strip())
                        output = process.stdout.readline()
                except EOFError:
                    break
                except Exception as e:
                    self.append_output(f"Shell error: {str(e)}")
                    break
            
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        except Exception as e:
            self.append_output(f"Failed to start shell: {str(e)}")
    
    def fix_permissions(self):
        with self.lock:  # Thread-safe operation
            self.append_output("Fixing permissions on /system...")
            try:
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'echo Root check'",
                    timeout=10
                )
                if return_code != 0:
                    self.append_output("Root access required for this operation")
                    QMessageBox.warning(self, "Error", "Root access required")
                    return
                
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'find /system -type d -exec chmod 755 {} \\;'",
                    timeout=300
                )
                self.append_output("Directory permissions fixed")
                
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'find /system -type f -exec chmod 644 {} \\;'",
                    timeout=300
                )
                self.append_output("File permissions fixed")
                
                return_code, output = self.device_manager.execute_adb_command(
                    "shell su -c 'find /system/bin /system/xbin -type f -exec chmod 755 {} \\;'",
                    timeout=300
                )
                self.append_output("Executable permissions fixed")
                
                self.append_output("Permissions fixed successfully")
                CopyableMessageBox.information(self, "Success", "Permissions fixed successfully")
            except Exception as e:
                self.append_output(f"Error fixing permissions: {str(e)}")
                QMessageBox.warning(self, "Error", f"Failed to fix permissions: {str(e)}")
    
    def install_busybox(self):
        if self.is_installing_busybox:
            CopyableMessageBox.information(self, "In Progress", "A BusyBox installation is already in progress.")
            return

        self.is_installing_busybox = True
        self.progress_dialog = QProgressDialog("Installing BusyBox...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("BusyBox Installation")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setAutoClose(False)
        self.progress_dialog.setAutoReset(False)

        thread = threading.Thread(target=self._install_busybox_worker, daemon=True)
        thread.start()

    def update_install_progress(self, value, text):
        if self.progress_dialog and self.is_installing_busybox:
            self.progress_dialog.setValue(value)
            self.progress_dialog.setLabelText(text)

    def on_install_finished(self, success, message):
        self.is_installing_busybox = False
        if self.progress_dialog:
            self.progress_dialog.close()
        
        # Use a single shot timer to show the message box after the current event loop finishes.
        # This prevents a race condition where a final progress signal is processed
        # after the progress dialog is destroyed but before the modal message box is shown.
        def show_message():
            # Now it's safe to destroy the dialog and show the final message.
            self.progress_dialog = None
            if success:
                CopyableMessageBox.information(self, "Success", message)
            else:
                CopyableMessageBox.warning(self, "Error", message)

        QTimer.singleShot(0, show_message)

    def _install_busybox_worker(self):
        try:
            self.install_progress.emit(0, "Checking root and existing installation...")
            self.append_output("Installing BusyBox...")
            
            return_code, _ = self.device_manager.execute_adb_command("shell su -c 'echo Root check'", timeout=10)
            if return_code != 0:
                self.install_finished.emit(False, "Root access is required for this operation.")
                return

            return_code, _ = self.device_manager.execute_adb_command("shell su -c 'busybox'", timeout=10)
            if return_code == 0:
                self.install_finished.emit(True, "BusyBox is already installed.")
                return

            self.install_progress.emit(10, "Detecting device architecture...")
            self.append_output("Detecting device architecture...")
            return_code, output = self.device_manager.execute_adb_command("shell su -c 'uname -m'", timeout=10)
            arch = output.strip().lower() if return_code == 0 else "arm"
            
            busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv7l"
            if 'arm64' in arch or 'aarch64' in arch:
                busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv8l"
            elif 'x86_64' in arch:
                busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64"
            elif 'x86' in arch or 'i686' in arch:
                busybox_url = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-i686"

            self.install_progress.emit(20, f"Downloading BusyBox for {arch}...")
            self.append_output(f"Downloading BusyBox for {arch} from {busybox_url}...")
            
            response = requests.get(busybox_url, stream=True, timeout=30)
            response.raise_for_status()
            
            temp_dir = tempfile.gettempdir()
            busybox_path = os.path.join(temp_dir, "busybox")
            with open(busybox_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            self.install_progress.emit(40, "Pushing BusyBox to device...")
            self.append_output("Pushing BusyBox to /sdcard/busybox_temp...")
            return_code, output = self.device_manager.execute_adb_command(["push", busybox_path, "/sdcard/busybox_temp"], timeout=60)
            if return_code != 0:
                self.install_finished.emit(False, f"Failed to push BusyBox to device: {output}")
                return

            self.install_progress.emit(60, "Attempting system installation...")
            self.append_output("Attempting to install to /system/xbin...")
            
            remount_success = False
            remount_commands = ["mount -o remount,rw /", "mount -o remount,rw /system"]
            for cmd in remount_commands:
                if self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=15)[0] == 0:
                    remount_success = True
                    break

            success = False
            if remount_success:
                self.install_progress.emit(70, "Installing to /system/xbin...")
                self.append_output("/system remounted as read-write. Proceeding with system installation.")
                install_path = "/system/xbin"
                commands = [f"mkdir -p {install_path}", f"mv /sdcard/busybox_temp {install_path}/busybox", f"chmod 755 {install_path}/busybox", f"{install_path}/busybox --install -s {install_path}"]
                for i, cmd in enumerate(commands):
                    self.install_progress.emit(70 + i * 5, f"Executing: {cmd[:20]}...")
                    if self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=30)[0] != 0:
                        success = False; break
                    success = True
            else:
                self.install_progress.emit(70, "Fallback: Installing to /data/local/bin...")
                self.append_output("Failed to remount /system. Attempting fallback to /data/local/bin...")
                install_path = "/data/local/bin"
                commands = [f"mkdir -p {install_path}", f"mv /sdcard/busybox_temp {install_path}/busybox", f"chmod 755 {install_path}/busybox", f"PATH=$PATH:{install_path} {install_path}/busybox --install -s {install_path}"]
                for i, cmd in enumerate(commands):
                    self.install_progress.emit(70 + i * 5, f"Executing: {cmd[:20]}...")
                    if self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=30)[0] != 0:
                        success = False; break
                    success = True
                
                if success:
                    self.install_progress.emit(95, "Configuring shell PATH...")
                    self.append_output("Attempting to automatically configure shell PATH...")
                    shell_wrapper_script = f"echo -e '#!/system/bin/sh\\nexport PATH=/data/local/bin:$PATH\\nexec /system/bin/sh $@' > /data/local/sh_wrapper"
                    path_commands = [shell_wrapper_script, "chmod 755 /data/local/sh_wrapper", "mount -o remount,rw /", "mv /system/bin/sh /system/bin/sh_real", "ln -s /data/local/sh_wrapper /system/bin/sh"]
                    for cmd in path_commands:
                        self.device_manager.execute_adb_command(["shell", "su", "-c", cmd], timeout=15)
                    self.append_output("Shell PATH configured.")

            self.device_manager.execute_adb_command(["shell", "rm", "/sdcard/busybox_temp"])
            os.remove(busybox_path)

            if success:
                self.append_output("BusyBox installed successfully")
                self.install_progress.emit(100, "Finished.")
                self.install_finished.emit(True, "BusyBox installed successfully!")
            else:
                self.append_output("Failed to install BusyBox")
                self.install_finished.emit(False, "Failed to install BusyBox. Check the log for details.")

        except requests.exceptions.RequestException as e:
            self.install_finished.emit(False, f"Network error downloading BusyBox: {e}")
        except Exception as e:
            self.install_finished.emit(False, f"An unexpected error occurred: {e}")
    
    def append_output(self, text):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n")
        self.output_text.setTextCursor(cursor)
        self.output_text.ensureCursorVisible()

class ThumbnailLoader(QObject):
    thumbnail_ready = pyqtSignal(QTreeWidgetItem, QIcon)

    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.thread = QThread()
        self.moveToThread(self.thread)
        self.thread.start()
        self._is_running = False

    def load(self, items_to_load):
        self.stop() # Stop any previous loading
        self._is_running = True
        QTimer.singleShot(0, lambda: self._run(items_to_load))

    def stop(self):
        self._is_running = False

    def _run(self, items_to_load):
        for item, remote_path in items_to_load:
            if not self._is_running:
                break

            # Use exec-out to stream file content without saving it on device first
            cmd = [self.device_manager.adb_path, "-s", self.device_manager.current_device, "exec-out", "cat", remote_path]
            
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                image_data, _ = process.communicate(timeout=5)

                if process.returncode == 0 and image_data:
                    pixmap = QPixmap()
                    pixmap.loadFromData(image_data)
                    if not pixmap.isNull():
                        icon = QIcon(pixmap.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                        self.thumbnail_ready.emit(item, icon)
            except (subprocess.TimeoutExpired, Exception):
                continue # Silently fail for individual thumbnails

class ScreenMirrorTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.mirror_process = None
        self.init_ui()
        self.scrcpy_path = None

    def init_ui(self):
        layout = QVBoxLayout()
        
        controls_group = QGroupBox("Screen Mirroring (scrcpy)")
        controls_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶️ Start Mirroring")
        self.start_btn.clicked.connect(self.start_mirroring)
        
        self.stop_btn = QPushButton("⏹️ Stop Mirroring")
        self.stop_btn.clicked.connect(self.stop_mirroring)
        self.stop_btn.setEnabled(False)
        
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.stop_btn)
        controls_group.setLayout(controls_layout)
        
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_label = QLabel()
        self.status_label.setVisible(False)
        
        layout.addWidget(controls_group)
        layout.addWidget(log_group)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        self.setLayout(layout)

    def start_mirroring(self):
        if not self.device_manager.current_device:
            QMessageBox.warning(self, "Error", "No device selected #021")
            return

        if self.mirror_process and self.mirror_process.state() == QProcess.ProcessState.Running:
            QMessageBox.information(self, "Info", "Mirroring is already running.")
            return

        self.scrcpy_path = self.find_scrcpy_executable()
        if not self.scrcpy_path:
            self.prompt_for_scrcpy_install()
            return
        
        self.log_output.clear()
        self.log_output.append("Starting scrcpy...")
        
        self.mirror_process = QProcess()
        self.mirror_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.mirror_process.readyRead.connect(self.handle_output)
        self.mirror_process.finished.connect(self.handle_finished)
        
        cmd_args = ["--serial", self.device_manager.current_device]
        self.mirror_process.start(self.scrcpy_path, cmd_args)
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_mirroring(self):
        if self.mirror_process and self.mirror_process.state() != QProcess.ProcessState.NotRunning:
            self.mirror_process.terminate()
            self.log_output.append("\nStopping scrcpy...")

    def handle_output(self):
        if self.mirror_process:
            output = self.mirror_process.readAll().data().decode(errors='ignore')
            self.log_output.append(output.strip())

    def handle_finished(self):
        self.log_output.append("\nscrcpy process finished.")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.mirror_process = None

    def find_scrcpy_executable(self):
        """Finds the scrcpy executable, checking settings, PATH, and local tools folder."""
        with settings_lock:
            scrcpy_path = settings.value("scrcpy_path", "")
        if scrcpy_path and os.path.exists(scrcpy_path):
            return scrcpy_path

        local_path = os.path.join(os.getcwd(), "tools", "scrcpy", "scrcpy.exe")
        if os.path.exists(local_path):
            with settings_lock:
                settings.setValue("scrcpy_path", local_path)
            return local_path

        path_in_system = shutil.which("scrcpy")
        if path_in_system:
            with settings_lock:
                settings.setValue("scrcpy_path", path_in_system)
            return path_in_system

        return None

    def prompt_for_scrcpy_install(self):
        """Asks the user to download and install scrcpy."""
        reply = QMessageBox.question(self, "scrcpy Not Found",
                                     "scrcpy could not be found.\n\n"
                                     "Would you like to automatically download and install it?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.download_and_install_scrcpy()

    def download_and_install_scrcpy(self):
        """Handles the download and installation of scrcpy in a background thread."""
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Finding latest scrcpy release...")
        self.status_label.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.thread = QThread()
        self.worker = Worker(self._scrcpy_install_worker)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_install_finished)
        self.worker.error.connect(self._on_install_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _scrcpy_install_worker(self, worker_instance):
        """Worker function to download and unzip scrcpy. Accepts worker_instance argument."""
        api_url = "https://api.github.com/repos/Genymobile/scrcpy/releases/latest"
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        release_data = response.json()
        
        download_url = None
        for asset in release_data.get('assets', []):
            if asset['name'].startswith('scrcpy-win64'):
                download_url = asset['browser_download_url']
                break
        if not download_url:
            raise FileNotFoundError("Could not find a suitable Windows release for scrcpy.")

        self.status_label.setText(f"Downloading from {download_url}...")
        zip_path = os.path.join(tempfile.gettempdir(), "scrcpy.zip")
        with requests.get(download_url, stream=True, timeout=300) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            with open(zip_path, "wb") as f:
                downloaded = 0
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = int((downloaded / total_size) * 100)
                        self.progress_bar.setValue(progress)

        self.status_label.setText("Installing scrcpy...")
        tools_dir = os.path.join(os.getcwd(), "tools")
        install_dir = os.path.join(os.getcwd(), "tools", "scrcpy")

        if os.path.exists(install_dir):
            shutil.rmtree(install_dir)
        os.makedirs(install_dir)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(tools_dir)
            first_member = zip_ref.namelist()[0]
            extracted_folder_name = first_member.split('/')[0]
            extracted_folder_path = os.path.join(tools_dir, extracted_folder_name)
            
            # Move all files and folders from the extracted folder to the target install_dir
            for item_name in os.listdir(extracted_folder_path):
                s = os.path.join(extracted_folder_path, item_name)
                d = os.path.join(install_dir, item_name)
                shutil.move(s, d)
            os.rmdir(extracted_folder_path)

        os.remove(zip_path)
        return os.path.join(install_dir, "scrcpy.exe")

    def _on_install_finished(self, new_path):
        self.status_label.setText("scrcpy installed successfully!")
        self.progress_bar.setVisible(False)
        with settings_lock:
            settings.setValue("scrcpy_path", new_path)
        self.scrcpy_path = new_path
        self.start_btn.setEnabled(True)
        CopyableMessageBox.information(self, "Success", f"scrcpy has been installed to:\n{new_path}\n\nYou can now start mirroring.")

    def _on_install_error(self, e):
        self.status_label.setText(f"Error: {e}")
        self.progress_bar.setVisible(False)
        self.start_btn.setEnabled(True)
        QMessageBox.critical(self, "Installation Failed", f"Could not install scrcpy:\n{e}")

class RecoveryToolsTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        control_group = QGroupBox("Recovery Control")
        control_layout = QVBoxLayout()
        
        self.reboot_recovery_btn = QPushButton("Reboot to Recovery")
        self.reboot_recovery_btn.clicked.connect(lambda: self.device_manager.reboot_device("recovery"))
        
        self.reboot_bootloader_btn = QPushButton("Reboot to Bootloader")
        self.reboot_bootloader_btn.clicked.connect(lambda: self.device_manager.reboot_device("bootloader"))
        
        self.reboot_system_btn = QPushButton("Reboot to System")
        self.reboot_system_btn.clicked.connect(lambda: self.device_manager.reboot_device("system"))
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.reboot_recovery_btn)
        btn_layout.addWidget(self.reboot_bootloader_btn)
        btn_layout.addWidget(self.reboot_system_btn)
        
        control_layout.addLayout(btn_layout)
        control_group.setLayout(control_layout)
        
        twrp_group = QGroupBox("TWRP Recovery")
        twrp_layout = QVBoxLayout()
        
        self.install_zip_btn = QPushButton("Install ZIP")
        self.install_zip_btn.clicked.connect(self.install_twrp_zip)
        
        self.wipe_cache_btn = QPushButton("Wipe Cache")
        self.wipe_cache_btn.clicked.connect(lambda: self.execute_twrp_command("wipe cache"))
        
        self.wipe_dalvik_btn = QPushButton("Wipe Dalvik")
        self.wipe_dalvik_btn.clicked.connect(lambda: self.execute_twrp_command("wipe dalvik"))
        
        self.wipe_data_btn = QPushButton("Wipe Data")
        self.wipe_data_btn.clicked.connect(lambda: self.execute_twrp_command("wipe data"))
        
        self.backup_btn = QPushButton("Create Backup")
        self.backup_btn.clicked.connect(self.create_twrp_backup)
        
        self.restore_btn = QPushButton("Restore Backup")
        self.restore_btn.clicked.connect(self.restore_twrp_backup)
        
        twrp_btn_layout1 = QHBoxLayout()
        twrp_btn_layout1.addWidget(self.install_zip_btn)
        twrp_btn_layout1.addWidget(self.wipe_cache_btn)
        twrp_btn_layout1.addWidget(self.wipe_dalvik_btn)
        
        twrp_btn_layout2 = QHBoxLayout()
        twrp_btn_layout2.addWidget(self.wipe_data_btn)
        twrp_btn_layout2.addWidget(self.backup_btn)
        twrp_btn_layout2.addWidget(self.restore_btn)
        
        twrp_layout.addLayout(twrp_btn_layout1)
        twrp_layout.addLayout(twrp_btn_layout2)
        twrp_group.setLayout(twrp_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        
        layout.addWidget(control_group)
        layout.addWidget(twrp_group)
        layout.addWidget(self.output_text)
        
        self.setLayout(layout)
    
    def install_twrp_zip(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select ZIP File", "", "ZIP Files (*.zip);;All Files (*)"
        )
        
        if file_path:
            return_code, output = self.device_manager.execute_adb_command(f"push {file_path} /sdcard/tmp_install.zip")
            self.append_output(output)
            
            if return_code != 0:
                self.append_output("Failed to push ZIP to device")
                return
            
            success, output = self.device_manager.reboot_device("recovery")
            self.append_output(output)
            
            if not success:
                self.append_output("Failed to reboot to recovery")
                return
            
            self.append_output("Waiting for device to enter recovery...")
            time.sleep(10)
            
            return_code, output = self.device_manager.execute_adb_command("shell twrp install /sdcard/tmp_install.zip", device_specific=False)
            self.append_output(output)
            
            if return_code == 0:
                self.append_output("ZIP installed successfully")
            else:
                self.append_output("Failed to install ZIP")
    
    def execute_twrp_command(self, command):
        success, output = self.device_manager.reboot_device("recovery")
        self.append_output(output)
        
        if not success:
            self.append_output("Failed to reboot to recovery")
            return
        
        self.append_output("Waiting for device to enter recovery...")
        time.sleep(10)
        
        return_code, output = self.device_manager.execute_adb_command(f"shell twrp {command}", device_specific=False)
        self.append_output(output)
        
        if return_code == 0:
            self.append_output("Command executed successfully")
        else:
            self.append_output("Command failed")
    
    def create_twrp_backup(self):
        name, ok = QInputDialog.getText(
            self, "Backup Name", "Enter backup name:",
            QLineEdit.EchoMode.Normal, datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        
        if ok and name:
            success, output = self.device_manager.reboot_device("recovery")
            self.append_output(output)
            
            if not success:
                self.append_output("Failed to reboot to recovery")
                return
            
            self.append_output("Waiting for device to enter recovery...")
            time.sleep(10)
            
            return_code, output = self.device_manager.execute_adb_command(f"shell twrp backup {name}", device_specific=False)
            self.append_output(output)
            
            if return_code == 0:
                self.append_output("Backup created successfully")
            else:
                self.append_output("Failed to create backup")
    
    def restore_twrp_backup(self):
        name, ok = QInputDialog.getText(
            self, "Backup Name", "Enter backup name to restore:",
            QLineEdit.EchoMode.Normal
        )
        
        if ok and name:
            success, output = self.device_manager.reboot_device("recovery")
            self.append_output(output)
            
            if not success:
                self.append_output("Failed to reboot to recovery")
                return
            
            self.append_output("Waiting for device to enter recovery...")
            time.sleep(10)
            
            return_code, output = self.device_manager.execute_adb_command(f"shell twrp restore {name}", device_specific=False)
            self.append_output(output)
            
            if return_code == 0:
                self.append_output("Backup restored successfully")
            else:
                self.append_output("Failed to restore backup")
    
    def append_output(self, text):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n")
        self.output_text.setTextCursor(cursor)
        self.output_text.ensureCursorVisible()

class BootloaderRecoveryTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.lock = threading.Lock()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        self.output_browser = QTextBrowser()
        self.output_browser.setFont(QFont("Consolas", 10))
        self.output_browser.setStyleSheet("background-color: #1e1e1e; color: #dcdcdc;")

        # --- Fastboot Section ---
        fastboot_group = QGroupBox("Fastboot Mode")
        fastboot_layout = QVBoxLayout(fastboot_group)

        # Flash Options
        flash_group = QGroupBox("Flash Partitions")
        flash_layout = QGridLayout(flash_group)
        self.boot_check = QCheckBox("boot")
        self.system_check = QCheckBox("system")
        self.vendor_check = QCheckBox("vendor")
        self.recovery_check = QCheckBox("recovery")
        self.flash_selected_btn = QPushButton("Flash Selected")
        self.flash_selected_btn.clicked.connect(self.flash_selected)
        flash_layout.addWidget(self.boot_check, 0, 0)
        flash_layout.addWidget(self.system_check, 0, 1)
        flash_layout.addWidget(self.vendor_check, 0, 2)
        flash_layout.addWidget(self.recovery_check, 1, 0)
        flash_layout.addWidget(self.flash_selected_btn, 1, 1, 1, 2)

        # Advanced Fastboot Commands
        adv_fastboot_group = QGroupBox("Advanced Commands")
        adv_fastboot_layout = QGridLayout(adv_fastboot_group)
        self.unlock_btn = QPushButton("Unlock Bootloader")
        self.lock_btn = QPushButton("Lock Bootloader")
        self.erase_btn = QPushButton("Erase Partition")
        self.set_active_btn = QPushButton("Set Active Slot")
        self.unlock_btn.clicked.connect(lambda: self.execute_fastboot_command("flashing unlock"))
        self.lock_btn.clicked.connect(lambda: self.execute_fastboot_command("flashing lock"))
        self.erase_btn.clicked.connect(self.erase_partition)
        self.set_active_btn.clicked.connect(self.set_active_slot)
        adv_fastboot_layout.addWidget(self.unlock_btn, 0, 0)
        adv_fastboot_layout.addWidget(self.lock_btn, 0, 1)
        adv_fastboot_layout.addWidget(self.erase_btn, 1, 0)
        adv_fastboot_layout.addWidget(self.set_active_btn, 1, 1)

        # Magisk/Root Flash
        magisk_group = QGroupBox("Flash Magisk / Root")
        magisk_layout = QFormLayout(magisk_group)
        self.magisk_image_path_edit = QLineEdit()
        self.magisk_image_path_edit.setPlaceholderText("Path to patched boot.img or init_boot.img")
        self.magisk_image_browse_btn = QPushButton("Browse...")
        self.magisk_image_browse_btn.clicked.connect(self.select_magisk_image)
        
        self.magisk_partition_combo = QComboBox()
        self.magisk_partition_combo.addItems(["boot", "init_boot"])
        self.magisk_partition_combo.setEditable(True)
        self.magisk_partition_combo.setToolTip("Select or enter the partition to flash (usually 'boot' or 'init_boot').")

        self.flash_magisk_btn = QPushButton("⚡ Flash Patched Image")
        self.flash_magisk_btn.clicked.connect(self.flash_magisk_image)

        magisk_image_layout = QHBoxLayout()
        magisk_image_layout.addWidget(self.magisk_image_path_edit)
        magisk_image_layout.addWidget(self.magisk_image_browse_btn)
        magisk_layout.addRow("Image File:", magisk_image_layout)
        magisk_layout.addRow("Partition:", self.magisk_partition_combo)
        magisk_layout.addRow(self.flash_magisk_btn)

        fastboot_layout.addWidget(flash_group)
        fastboot_layout.addWidget(adv_fastboot_group)
        fastboot_layout.addWidget(magisk_group)

        # --- Recovery Section ---
        recovery_group = QGroupBox("Recovery Mode")
        recovery_layout = QVBoxLayout(recovery_group)

        # Sideload
        sideload_group = QGroupBox("ADB Sideload")
        sideload_layout = QHBoxLayout(sideload_group)
        self.sideload_path_edit = QLineEdit()
        self.sideload_path_edit.setPlaceholderText("Select ZIP file...")
        self.sideload_browse_btn = QPushButton("Browse...")
        self.sideload_browse_btn.clicked.connect(self.select_sideload_file)
        self.sideload_btn = QPushButton("Start Sideload")
        self.sideload_btn.clicked.connect(self.start_adb_sideload)
        sideload_layout.addWidget(self.sideload_path_edit)
        sideload_layout.addWidget(self.sideload_browse_btn)
        sideload_layout.addWidget(self.sideload_btn)

        # TWRP
        twrp_group = QGroupBox("TWRP Commands")
        twrp_layout = QGridLayout(twrp_group)
        self.install_zip_btn = QPushButton("Install ZIP")
        self.wipe_cache_btn = QPushButton("Wipe Cache")
        self.wipe_data_btn = QPushButton("Wipe Data")
        self.backup_btn = QPushButton("Create Backup")
        self.install_zip_btn.clicked.connect(self.install_twrp_zip)
        self.wipe_cache_btn.clicked.connect(lambda: self.execute_twrp_command("wipe cache"))
        self.wipe_data_btn.clicked.connect(lambda: self.execute_twrp_command("wipe data"))
        self.backup_btn.clicked.connect(self.create_twrp_backup)
        twrp_layout.addWidget(self.install_zip_btn, 0, 0)
        twrp_layout.addWidget(self.wipe_cache_btn, 0, 1)
        twrp_layout.addWidget(self.wipe_data_btn, 1, 0)
        twrp_layout.addWidget(self.backup_btn, 1, 1)

        recovery_layout.addWidget(sideload_group)
        recovery_layout.addWidget(twrp_group)

        # --- Main Layout ---
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(fastboot_group)
        top_splitter.addWidget(recovery_group)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(self.output_browser)
        main_splitter.setSizes([1, 1])

        layout.addWidget(main_splitter)

    def append_output(self, text):
        self.output_browser.append(text)
        self.output_browser.verticalScrollBar().setValue(self.output_browser.verticalScrollBar().maximum())

    # --- Fastboot Methods ---
    def flash_selected(self):
        # This is a simplified version. A full implementation would require file inputs.
        self.append_output("Flash Selected: This functionality needs to be fully implemented.")

    def execute_fastboot_command(self, command):
        if not self.device_manager.current_device:
            CopyableMessageBox.warning(self, "Error", "No device connected in fastboot mode")
            return
        
        confirm = QMessageBox.question(self, "Confirm Command", f"Execute: fastboot {command}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:
                self.append_output(f"Executing: fastboot {command}")
                return_code, output = self.device_manager.execute_fastboot_command(shlex.split(command), timeout=60)
                self.append_output(output)
                self.append_output("--- Done ---")

    def erase_partition(self):
        partition, ok = QInputDialog.getText(self, "Erase Partition", "Enter partition to erase:")
        if ok and partition:
            self.execute_fastboot_command(f"erase {partition.strip()}")

    def set_active_slot(self):
        slot, ok = QInputDialog.getItem(self, "Set Active Slot", "Select slot:", ["a", "b"], 0, False)
        if ok and slot:
            self.execute_fastboot_command(f"--set-active={slot}")

    def select_magisk_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Patched Image", "", "Image Files (*.img);;All Files (*)")
        if file_path:
            self.magisk_image_path_edit.setText(os.path.normpath(file_path))

    def flash_magisk_image(self):
        image_path = self.magisk_image_path_edit.text()
        partition = self.magisk_partition_combo.currentText()

        if not image_path or not os.path.isfile(image_path):
            CopyableMessageBox.warning(self, "Error", "Please select a valid image file.")
            return
        if not partition:
            CopyableMessageBox.warning(self, "Error", "Please specify a partition to flash.")
            return

        confirm = QMessageBox.question(self, "Confirm Magisk Flash",
                                     f"This will flash <b>{os.path.basename(image_path)}</b> to the <b>{partition}</b> partition.\n\n"
                                     "Flashing the wrong image can brick your device. Are you absolutely sure you want to continue?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            command = ["flash", partition, image_path]
            self.execute_fastboot_command(command, timeout=300)

    # --- Recovery/Sideload Methods ---
    def select_sideload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select ZIP File", "", "ZIP Files (*.zip)")
        if file_path:
            self.sideload_path_edit.setText(os.path.normpath(file_path))

    def start_adb_sideload(self):
        file_path = self.sideload_path_edit.text()
        if not file_path or not os.path.isfile(file_path):
            CopyableMessageBox.warning(self, "Error", "Please select a valid ZIP file.")
            return

        confirm = QMessageBox.question(self, "Confirm ADB Sideload",
                                     "This will install the selected ZIP using ADB sideload. The device must be in recovery mode. Continue?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:
                self.append_output(f"Sideloading {file_path}...")
                return_code, output = self.device_manager.execute_adb_command(["sideload", file_path], timeout=600)
                self.append_output(output)
                self.append_output("--- Sideload finished ---")

    def install_twrp_zip(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select ZIP File", "", "ZIP Files (*.zip)")
        if file_path:
            with self.lock:
                self.append_output("Pushing ZIP to /sdcard/twrp_install.zip...")
                self.device_manager.execute_adb_command(["push", file_path, "/sdcard/twrp_install.zip"])
                self.execute_twrp_command("install /sdcard/twrp_install.zip")

    def execute_twrp_command(self, command):
        confirm = QMessageBox.question(self, "Confirm TWRP Command", f"Execute: twrp {command}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            with self.lock:
                self.append_output(f"Executing TWRP command: {command}")
                return_code, output = self.device_manager.execute_adb_command(f"shell twrp {command}", device_specific=False)
                self.append_output(output)
                self.append_output("--- Done ---")

    def create_twrp_backup(self):
        name, ok = QInputDialog.getText(self, "Backup Name", "Enter backup name:",
                                      QLineEdit.EchoMode.Normal, datetime.now().strftime("%Y%m%d_%H%M%S"))
        if ok and name:
            self.execute_twrp_command(f"backup {name}")

class SettingsTab(QWidget):
    def __init__(self, device_manager):
        super().__init__()
        self.device_manager = device_manager
        self.init_ui()
        self.load_settings()
    
    def reset_settings(self):
        """Resets all settings to their default values."""
        confirm = QMessageBox.question(
            self, "Confirm Reset",
            "Are you sure you want to reset all settings to their default values? The application will need to be restarted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            settings.clear()
            self.load_settings() # Reload UI with default values
            CopyableMessageBox.information(self, "Success", "Settings have been reset. Please restart the application for all changes to take effect.")

    def reset_settings(self):
        """Resets all settings to their default values."""
        confirm = QMessageBox.question(
            self, "Confirm Reset",
            "Are you sure you want to reset all settings to their default values? The application will need to be restarted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            settings.clear()
            self.load_settings() # Reload UI with default values
            CopyableMessageBox.information(self, "Success", "Settings have been reset. Please restart the application for all changes to take effect.")

    def apply_settings(self):
        """Applies settings that can be changed live."""
        font_family = settings.value("font_family", "Segoe UI")
        font_size = int(settings.value("font_size", 10))
        font = QFont(font_family, font_size)
        QApplication.setFont(font)

        theme = settings.value("theme", "System Default")
        if theme == "Dark":
            try:
                from qdarktheme import setup_theme
                setup_theme("dark")
            except ImportError:
                pass
        elif theme == "Light":
            try:
                from qdarktheme import setup_theme
                setup_theme("light")
            except ImportError:
                pass
        else: # System Default
            QApplication.instance().setStyleSheet("") # Reset to default stylesheet
            self.parent().parent().apply_modern_dark_theme() # Re-apply the custom default if qdarktheme is not used

    def init_ui(self):
        layout = QVBoxLayout()
        
        path_group = QGroupBox("Path Settings")
        path_layout = QFormLayout()
        
        self.adb_path_edit = QLineEdit()
        self.adb_path_browse = QPushButton("Browse...")
        self.adb_path_browse.clicked.connect(lambda: self.browse_path(self.adb_path_edit))
        
        self.fastboot_path_edit = QLineEdit()
        self.fastboot_path_browse = QPushButton("Browse...")
        self.fastboot_path_browse.clicked.connect(lambda: self.browse_path(self.fastboot_path_edit))

        self.sdk_path_edit = QLineEdit()
        self.sdk_path_browse = QPushButton("Browse...")
        self.sdk_path_browse.setToolTip("Wählen Sie das Hauptverzeichnis Ihres Android SDKs (z.B. C:\\Users\\YourUser\\AppData\\Local\\Android\\Sdk).")
        self.sdk_path_browse.clicked.connect(lambda: self.browse_sdk_path(self.sdk_path_edit))

        self.scrcpy_path_edit = QLineEdit()
        self.scrcpy_path_browse = QPushButton("Browse...")
        self.scrcpy_path_browse.clicked.connect(lambda: self.browse_path(self.scrcpy_path_edit))
        
        path_layout.addRow("ADB Path:", self.create_path_row(self.adb_path_edit, self.adb_path_browse))
        path_layout.addRow("Fastboot Path:", self.create_path_row(self.fastboot_path_edit, self.fastboot_path_browse))
        
        path_layout.addRow("Android SDK Path:", self.create_path_row(self.sdk_path_edit, self.sdk_path_browse))
        path_group.setLayout(path_layout)
        
        ui_group = QGroupBox("UI Settings")
        ui_layout = QFormLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System Default", "Dark", "Light"])
        
        self.font_combo = QComboBox()
        self.font_combo.addItems(["Arial", "Courier New", "Times New Roman", "Verdana", "Segoe UI"])
        
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 20)
        self.font_size_spin.setValue(10)
        
        ui_layout.addRow("Theme:", self.theme_combo)
        ui_layout.addRow("Font Family:", self.font_combo)
        ui_layout.addRow("Font Size:", self.font_size_spin)
        
        ui_group.setLayout(ui_layout)
        
        # General Settings
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()
        self.check_updates_check = QCheckBox("Check for updates on startup")
        general_layout.addRow(self.check_updates_check)
        general_group.setLayout(general_layout)

        # Automatic Tool Setup
        setup_group = QGroupBox("Automatic Tool Setup")
        setup_layout = QVBoxLayout()

        setup_label = QLabel(
            "If ADB and Fastboot are not found or configured, this will automatically "
            "download the latest official Android SDK Platform-Tools from Google and set them up."
        )
        setup_label.setWordWrap(True)

        self.setup_tools_btn = QPushButton("Download & Setup SDK Platform-Tools")
        self.setup_tools_btn.clicked.connect(self.setup_sdk_tools)

        setup_layout.addWidget(setup_label)
        setup_layout.addWidget(self.setup_tools_btn)
        setup_group.setLayout(setup_layout)
        # File Explorer Settings
        explorer_group = QGroupBox("File Explorer Settings")
        explorer_layout = QFormLayout()
        self.show_hidden_files_check = QCheckBox("Show hidden files (dotfiles) on device")
        self.load_thumbnails_check = QCheckBox("Load thumbnails for remote images")
        explorer_layout.addRow(self.show_hidden_files_check)
        explorer_layout.addRow(self.load_thumbnails_check)
        explorer_group.setLayout(explorer_layout)

        # Logcat Settings
        logcat_group = QGroupBox("Logcat Settings")
        logcat_layout = QFormLayout()
        self.logcat_buffer_combo = QComboBox()
        self.logcat_buffer_combo.addItems(["256K", "1M", "4M", "16M", "64M (default)"])
        logcat_layout.addRow("Default Buffer Size:", self.logcat_buffer_combo)
        logcat_group.setLayout(logcat_layout)

        # Action Buttons
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("💾 Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.clicked.connect(self.reset_settings)
        
        button_layout.addWidget(self.save_btn)
        
        # Scroll Area for all settings
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.addWidget(general_group)
        scroll_layout.addWidget(setup_group)
        scroll_layout.addWidget(path_group)
        scroll_layout.addWidget(ui_group)
        scroll_layout.addWidget(explorer_group)
        scroll_layout.addWidget(logcat_group)
        scroll_area.setWidget(scroll_content)

        layout.addWidget(scroll_area)

        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.reset_btn)
        bottom_layout.addWidget(self.save_btn)
        layout.addLayout(bottom_layout)
        
        self.setLayout(layout)
    
    def create_path_row(self, edit, browse):
        row = QHBoxLayout()
        row.addWidget(edit)
        row.addWidget(browse)
        return row
    
    def browse_path(self, target_edit):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Executable", "", "Executable Files (*.exe);;All Files (*)"
        )
        
        if file_path:
            target_edit.setText(file_path)
    
    def browse_sdk_path(self, target_edit):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Android SDK Directory")
        if dir_path:
            target_edit.setText(dir_path)

    def load_settings(self):
        self.adb_path_edit.setText(settings.value("adb_path", DEFAULT_ADB_PATH))
        self.fastboot_path_edit.setText(settings.value("fastboot_path", DEFAULT_FASTBOOT_PATH))
        self.scrcpy_path_edit.setText(settings.value("scrcpy_path", ""))
        
        self.theme_combo.setCurrentText(settings.value("theme", "System Default"))
        self.font_combo.setCurrentText(settings.value("font_family", "Segoe UI"))
        self.font_size_spin.setValue(int(settings.value("font_size", 10)))
        self.sdk_path_edit.setText(settings.value("sdk_path", ""))

        # General settings
        self.check_updates_check.setChecked(settings.value("check_for_updates", True, type=bool))

        # File Explorer settings
        self.show_hidden_files_check.setChecked(settings.value("explorer_show_hidden", False, type=bool))
        self.load_thumbnails_check.setChecked(settings.value("explorer_load_thumbnails", True, type=bool))

        # Logcat settings
        self.logcat_buffer_combo.setCurrentText(settings.value("logcat_buffer_size", "64M (default)"))
    
    def save_settings(self):
        settings.setValue("adb_path", self.adb_path_edit.text())
        settings.setValue("fastboot_path", self.fastboot_path_edit.text())
        settings.setValue("scrcpy_path", self.scrcpy_path_edit.text())
        settings.setValue("sdk_path", self.sdk_path_edit.text())
        
        self.device_manager.adb_path = self.adb_path_edit.text()
        self.device_manager.fastboot_path = self.fastboot_path_edit.text()
        
        settings.setValue("theme", self.theme_combo.currentText())
        settings.setValue("font_family", self.font_combo.currentText())
        settings.setValue("font_size", self.font_size_spin.value())

        settings.setValue("check_for_updates", self.check_updates_check.isChecked())
        settings.setValue("explorer_show_hidden", self.show_hidden_files_check.isChecked())
        settings.setValue("explorer_load_thumbnails", self.load_thumbnails_check.isChecked())
        settings.setValue("logcat_buffer_size", self.logcat_buffer_combo.currentText())
        
        CopyableMessageBox.information(self, "Success", "Settings saved successfully")
        
        # Ask user to apply live settings
        if QMessageBox.question(self, "Apply Settings", "Some settings require a restart to take full effect. Please Restart the application now!", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.apply_settings()

    def setup_sdk_tools(self):
        confirm = QMessageBox.question(
            self, "Confirm Download",
            "This will download the latest Android SDK Platform-Tools (approx. 10-15 MB) from Google. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.progress_dialog = QProgressDialog("Starting setup...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("SDK Tools Setup")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.show()

        self.thread = QThread()
        self.worker = Worker(self._sdk_tools_worker)
        self.worker.moveToThread(self.thread)

        self.worker.progress_update.connect(self.update_progress)
        self.worker.finished.connect(self._on_setup_finished)
        self.worker.error.connect(self._on_setup_error)

        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def _sdk_tools_worker(self, worker_instance):
        """Worker function to download and extract platform tools."""
        # 1. Determine OS and URL
        if sys.platform == "win32":
            os_name = "windows"
        elif sys.platform == "linux":
            os_name = "linux"
        elif sys.platform == "darwin":
            os_name = "darwin"
        else:
            raise OSError("Unsupported operating system")

        url = f"https://dl.google.com/android/repository/platform-tools-latest-{os_name}.zip"
        worker_instance.progress_update.emit(5, f"Downloading from {url}...")

        # 2. Download the file
        zip_path = os.path.join(tempfile.gettempdir(), "platform-tools.zip")
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            with open(zip_path, "wb") as f:
                downloaded = 0
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = 5 + int((downloaded / total_size) * 75) # 5% to 80% for download
                        worker_instance.progress_update.emit(progress, f"Downloading... {downloaded // 1024} KB / {total_size // 1024} KB")

        # 3. Unzip the file
        worker_instance.progress_update.emit(85, "Extracting files...")
        tools_dir = os.path.join(os.getcwd(), "tools")
        if not os.path.exists(tools_dir):
            os.makedirs(tools_dir)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(tools_dir)

        os.remove(zip_path)
        worker_instance.progress_update.emit(100, "Setup complete.")
        return os.path.join(tools_dir, "platform-tools")

    def _on_setup_finished(self, platform_tools_path):
        self.progress_dialog.close()
        adb_exe = "adb.exe" if sys.platform == "win32" else "adb"
        fastboot_exe = "fastboot.exe" if sys.platform == "win32" else "fastboot"
        self.adb_path_edit.setText(os.path.join(platform_tools_path, adb_exe))
        self.fastboot_path_edit.setText(os.path.join(platform_tools_path, fastboot_exe))
        self.save_settings()
        CopyableMessageBox.information(self, "Success", "SDK Platform-Tools have been successfully set up.")

    def _on_setup_error(self, e):
        self.progress_dialog.close()
        CopyableMessageBox.critical(self, "Setup Failed", f"An error occurred during setup:\n{e}")

    def update_progress(self, value, text):
        if self.progress_dialog:
            self.progress_dialog.setValue(value)
            self.progress_dialog.setLabelText(text)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.device_manager = DeviceManager()
        self.device_manager.suppress_no_device_warning = True
        self.file_manager = FileManager(self.device_manager)
        self.package_manager = PackageManager(self.device_manager)
        self.backup_manager = BackupManager(self.device_manager)
        self.logcat_manager = LogcatManager(self.device_manager)
        
        self.init_ui()
        self.apply_modern_dark_theme()
        
        # Connect device manager signals
        self.device_manager.devices_updated.connect(self.update_device_list)
        self.device_manager.device_details_updated.connect(self.update_status_bar)
    
    def init_ui(self):
        self.setWindowTitle(f"{APP_NAME} v{VERSION}") # Set window title
        self.setGeometry(100, 100, 1600, 900) # Set window size
        def resource_path(relative_path):
            """ Get absolute path to resource, works for dev and for Nuitka/PyInstaller """
            try:
                # Nuitka/PyInstaller erstellen einen temporaeren Ordner und speichern den Pfad in _MEIPASS
                base_path = sys._MEIPASS
            except Exception:
                # Wenn _MEIPASS nicht existiert, sind wir im normalen Entwicklungsmodus
                base_path = os.path.abspath(".")
            return os.path.join(base_path, "resources", relative_path)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        toolbar = QHBoxLayout()
        
        self.device_combo = QComboBox()
        self.device_combo.currentIndexChanged.connect(self.device_selected)
        
        self.refresh_devices_btn = QPushButton("Refresh")
        self.refresh_devices_btn.clicked.connect(self.device_manager.update_devices)
        
        toolbar.addWidget(QLabel("Connected Devices:"))
        toolbar.addWidget(self.device_combo, 1)
        toolbar.addWidget(self.refresh_devices_btn)
        
        main_layout.addLayout(toolbar)
        
        self.tab_widget = QTabWidget()
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        # Add tabs
        self.tab_widget.addTab(DeviceControlTab(self.device_manager), "Device Control")
        self.tab_widget.addTab(FileExplorerTab(self.device_manager, self.file_manager), "File Explorer")
        self.tab_widget.addTab(PackageManagerTab(self.device_manager, self.package_manager), "Package Manager")
        self.tab_widget.addTab(BackupRestoreTab(self.device_manager, self.backup_manager), "Backup/Restore")
        self.tab_widget.addTab(LogcatTab(self.device_manager, self.logcat_manager), "Logcat")
        self.tab_widget.addTab(AdvancedShellTab(self.device_manager), "Shell")  # New Advanced Shell Tab
        self.tab_widget.addTab(DevicePropertiesTab(self.device_manager), "Device Properties")
        self.tab_widget.addTab(MonkeyTesterTab(self.device_manager), "Monkey Tester")
        self.tab_widget.addTab(ScreenMirrorTab(self.device_manager), "Screen Mirror")
        self.tab_widget.addTab(AndroguardTab(self.device_manager), "APK Analysis")
        self.tab_widget.addTab(XposedHookTab(self.device_manager), "Xposed Hook")
        self.tab_widget.addTab(RomModificationsTab(self.device_manager), "ROM Mods")
        self.tab_widget.addTab(RootToolsTab(self.device_manager), "Root Tools")
        self.tab_widget.addTab(BootloaderRecoveryTab(self.device_manager), "Bootloader/Recovery")
        self.tab_widget.addTab(SettingsTab(self.device_manager), "Settings")
        
        main_layout.addWidget(self.tab_widget)

        self.file_explorer_tab = self.tab_widget.widget(1)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.file_explorer_tab.preview_dock)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.device_status_label = QLabel("Kein Gerät verbunden")
        self.status_bar.addPermanentWidget(self.device_status_label)
        
        self.create_menu_bar()

    def check_admin_rights(self):
        """Prüft auf Administratorrechte und fordert diese bei Bedarf an (nur Windows)."""
        if sys.platform == "win32":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    reply = QMessageBox.question(self, "Administratorrechte empfohlen",
                                                 "Für einige erweiterte Funktionen (wie die automatische Treiber- oder Tool-Installation) werden Administratorrechte empfohlen.\n\n"
                                                 "Möchten Sie die Anwendung als Administrator neu starten?",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                        sys.exit(0)
            except (ImportError, AttributeError, Exception) as e:
                logging.warning(f"Could not check for admin rights: {e}")
    
    def create_menu_bar(self):
        menu_bar = self.menuBar()
        
        file_menu = menu_bar.addMenu("File")
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        tools_menu = menu_bar.addMenu("Tools")
        
        adb_shell_action = QAction("ADB Shell", self)
        adb_shell_action.triggered.connect(self.open_adb_shell)
        tools_menu.addAction(adb_shell_action)
        
        screenshot_action = QAction("Take Screenshot", self)
        screenshot_action.triggered.connect(self.take_screenshot)
        tools_menu.addAction(screenshot_action)
        
        help_menu = menu_bar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction("Discord", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)
    
    def showEvent(self, event):
        """Called when the window is shown for the first time."""
        super().showEvent(event)
        QTimer.singleShot(100, self.initial_device_scan)

    def on_tab_changed(self, index):
        """Called when the current tab is changed."""
        current_tab = self.tab_widget.widget(index)
        if isinstance(current_tab, PackageManagerTab):
            current_tab.refresh_packages()
        elif isinstance(current_tab, FileExplorerTab):
            current_tab.refresh_remote_directory()
            current_tab.refresh_local_directory()
        elif isinstance(current_tab, DevicePropertiesTab):
            current_tab.refresh_properties()


    def update_device_list(self, devices):
        self.device_combo.clear()
        
        for device in devices:
            if device.get("model") and device.get("type") == "adb":
                device_text = f"{device['model']} ({device['id']})"
            else:
                device_text = f"{device['id']} ({device['type'].upper()})"
            self.device_combo.addItem(device_text, device["id"])
        
        if not devices:
            self.device_status_label.setText("Kein Gerät verbunden")
    
    def device_selected(self, index):
        if index >= 0:
            device_id = self.device_combo.itemData(index)
            self.device_manager.set_current_device(device_id)
    
    def update_status_bar(self, details):
        if details:
            device_text = f"{details.get('model', 'Unbekannt')} | Android {details.get('android_version', 'Unbekannt')}"
            if details.get('type') == 'fastboot':
                device_text += " (Fastboot-Modus)"
            self.device_status_label.setText(device_text)
        
    def initial_device_scan(self):
        """Perform an initial synchronous device scan and refresh UI bindings."""
        try:
            # Trigger a device update and refresh details shortly after
            self.device_manager.update_devices()
            QTimer.singleShot(250, self.refresh_device_details)
        except Exception:
            # Fail silently — UI will update on the next timer tick in DeviceManager
            pass

    def refresh_device_details(self):
        """Refresh device details and ensure the device combo and status are in sync."""
        # Ensure the device combo shows the current device (if any)
        current = self.device_manager.current_device
        if current:
            # Update details on the manager (which emits device_details_updated)
            try:
                self.device_manager.update_device_details()
            except Exception:
                pass

            # Select the current device in the combo box if present
            for i in range(self.device_combo.count()):
                if self.device_combo.itemData(i) == current:
                    # block signal to avoid re-triggering selection handling
                    try:
                        self.device_combo.blockSignals(True)
                        self.device_combo.setCurrentIndex(i)
                    finally:
                        self.device_combo.blockSignals(False)
                    break
        else:
            # No current device — clear UI where appropriate
            self.device_status_label.setText("Kein Gerät verbunden")
        # initial scan finished — allow showing warnings from now on
        try:
            self.device_manager.suppress_no_device_warning = False
        except Exception:
            pass
    
    def open_adb_shell(self):
        if not self.device_manager.current_device:
            if not getattr(self.device_manager, "suppress_no_device_warning", False):
                QMessageBox.warning(self, "Error", "No device selected #022")
            return
        
        shell_dialog = QDialog(self)
        shell_dialog.setWindowTitle("ADB Shell")
        
        layout = QVBoxLayout()
        
        self.shell_output = QTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setFont(QFont("Courier New", 10))
        
        self.shell_input = QLineEdit()
        self.shell_input.returnPressed.connect(self.execute_shell_command)
        
        layout.addWidget(self.shell_output)
        layout.addWidget(self.shell_input)
        
        shell_dialog.setLayout(layout)
        shell_dialog.resize(600, 400)
        shell_dialog.exec()
    
    def execute_shell_command(self):
        command = self.shell_input.text()
        self.shell_input.clear()
        
        self.shell_output.append(f"$ {command}")
        
        return_code, output = self.device_manager.execute_adb_command(f"shell {command}")
        self.shell_output.append(output)
    
    def take_screenshot(self):
        if not self.device_manager.current_device:
            if not getattr(self.device_manager, "suppress_no_device_warning", False):
                QMessageBox.warning(self, "Error", "No device selected #023")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Screenshot", "screenshot.png", "PNG Files (*.png);;All Files (*)"
        )
        
        if file_path:
            if not file_path.lower().endswith('.png'):
                file_path += '.png'
            
            with open(file_path, "wb") as f:
                result = subprocess.run([self.device_manager.adb_path, "-s", self.device_manager.current_device, "exec-out", "screencap", "-p"], stdout=f)
            if result.returncode == 0:
                CopyableMessageBox.information(self, "Success", f"Screenshot saved to {file_path}")
            else:
                CopyableMessageBox.warning(self, "Error", "Failed to take screenshot.")
    
    def show_about(self):
        about_text = f"""
        <h1>{APP_NAME}</h1>
        <p>Version: {VERSION}</p>
        <p>Developer: {DEVELOPER}</p>
        <p>A comprehensive Android device management tool with ADB, Fastboot, and root capabilities.</p>
        <p>Supported Android versions: {', '.join(SUPPORTED_ANDROID_VERSIONS)}</p>
        """
        
        QMessageBox.about(self, "About", about_text)
    
    def show_documentation(self):
        webbrowser.open("https://discord.gg/dDzZkCj95D")

    def apply_modern_dark_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #dcdcdc;
                font-family: "Segoe UI", "Roboto", "Helvetica Neue", sans-serif;
                font-size: 10pt;
            }
            QToolTip {
                color: #000000; /* Black text */
                background-color: #ffffe1; /* Light yellow background */
                border: 1px solid #000000;
                border-radius: 2px;
            }
            QMainWindow, QDialog {
                background-color: #2b2b2b;
            }
            QGroupBox {
                background-color: #3c3c3c;
                border: 1px solid #555555;
                border-radius: 8px;
                margin-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 10px;
                background-color: #3c3c3c;
                color: #00aaff;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QTabBar::tab {
                background: #3c3c3c;
                border: 1px solid #555555;
                border-bottom: none;
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #007acc;
                color: white;
                border-color: #007acc;
            }
            QTabBar::tab:hover:!selected {
                background: #4a4a4a;
            }
            QPushButton {
                background-color: #555555;
                color: #dcdcdc;
                border: 1px solid #666666;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #6a6a6a;
                border-color: #007acc;
            }
            QPushButton:pressed {
                background-color: #4a4a4a;
            }
            QPushButton:disabled {
                background-color: #404040;
                color: #888888;
                border-color: #555555;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #2b2b2b;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 5px;
            }
            QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #007acc;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png); /* Needs an icon */
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 4px;
                text-align: center;
                color: #dcdcdc;
            }
            QProgressBar::chunk {
                background-color: #007acc;
                border-radius: 3px;
            }
            QTreeWidget, QListWidget {
                background-color: #3c3c3c;
                border: 1px solid #555555;
                border-radius: 4px;
            }
            QTreeWidget::item:hover, QListWidget::item:hover {
                background-color: #4a4a4a;
            }
            QTreeWidget::item:selected, QListWidget::item:selected {
                background-color: #007acc;
                color: white;
            }
            QHeaderView::section {
                background-color: #4a4a4a;
                color: #dcdcdc;
                padding: 4px;
                border: 1px solid #555555;
                font-weight: bold;
            }
            QScrollBar:vertical, QScrollBar:horizontal {
                border: none;
                background: #2b2b2b;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle {
                background: #555555;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:hover {
                background: #6a6a6a;
            }
            QScrollBar::add-line, QScrollBar::sub-line {
                height: 0px;
                width: 0px;
            }
            QMenu {
                background-color: #3c3c3c;
                border: 1px solid #555555;
            }
            QMenu::item:selected {
                background-color: #007acc;
            }
            QStatusBar {
                background-color: #3c3c3c;
            }
            QProgressDialog {
                background-color: #3c3c3c;
            }
            QDockWidget {
                titlebar-close-icon: url(close.png); /* Needs icons */
                titlebar-normal-icon: url(float.png);
                background-color: #3c3c3c;
            }
        """)

def check_and_install_java():
    """Checks for a valid Java installation and installs it if not found."""
    java_home = os.environ.get("JAVA_HOME")
    if java_home and os.path.exists(os.path.join(java_home, "bin", "java.exe")):
        return

    if shutil.which("java"):
        return

    local_jdk_path = os.path.join(os.getcwd(), "tools", "jdk")
    if os.path.exists(os.path.join(local_jdk_path, "bin", "java.exe")):
        os.environ["JAVA_HOME"] = local_jdk_path
        return

    reply = QMessageBox.question(None, "Java Not Found",
                                 "Java is not installed or configured correctly. This is required for some tools to work.\n\n"
                                 "Would you like to download and install OpenJDK now?",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    if reply != QMessageBox.StandardButton.Yes:
        return

    progress = QProgressDialog("Downloading OpenJDK...", "Cancel", 0, 100)
    progress.setWindowModality(Qt.WindowModality.WindowModal)
    progress.show()

    try:
        jdk_zip_url = "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse"
        jdk_zip_path = os.path.join(tempfile.gettempdir(), "openjdk.zip")

        with requests.get(jdk_zip_url, stream=True, timeout=300) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            downloaded = 0
            with open(jdk_zip_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if progress.wasCanceled():
                        return
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = int((downloaded / total_size) * 100)
                        progress.setValue(percent)

        progress.setLabelText("Installing OpenJDK...")
        with zipfile.ZipFile(jdk_zip_path, 'r') as zip_ref:
            temp_extract_path = os.path.join(os.getcwd(), "tools", "jdk_temp_extract")
            os.makedirs(temp_extract_path, exist_ok=True)
            zip_ref.extractall(temp_extract_path)
        
        extracted_folder_name = os.listdir(temp_extract_path)[0]
        extracted_folder_path = os.path.join(temp_extract_path, extracted_folder_name)

        if os.path.exists(local_jdk_path): shutil.rmtree(local_jdk_path)
        shutil.move(extracted_folder_path, local_jdk_path)
        
        shutil.rmtree(temp_extract_path)
        os.remove(jdk_zip_path)
        os.environ["JAVA_HOME"] = local_jdk_path

        QMessageBox.information(None, "Java Installed", f"OpenJDK has been installed to {local_jdk_path}")

    except Exception as e:
        QMessageBox.critical(None, "Java Installation Failed", f"An error occurred during Java installation: {e}")
    finally:
        progress.close()

def main():
    app = QApplication(sys.argv)
    check_and_install_java()
    log_file = setup_logging()
    sys.excepthook = global_exception_hook
    
    try:
        from qdarktheme import setup_theme
        setup_theme()
        logging.info("qdarktheme found and applied.")
    except ImportError:
        logging.info("qdarktheme not found, using default stylesheet.")

    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
