# Ultimate Android Control Tool (UACT)

A powerful Python GUI tool to manage and control Android devices via ADB and Fastboot.

## 🧩 Features

- Device detection (ADB / Fastboot)
- Reboot options (System, Recovery, Bootloader, Download)
- File Explorer (local ↔ device)
- APK installation and app management
- Logcat viewer
- Root Management
- Backup and restore
- ADB over WiFi
- Flash via Fastboot
- Install zip via Sideload
- Root Tools/Manegement
- Build.prop Viewer/Editor (need to update)

## 📸 Screenshot

![UACT Screenshot](docs/screenshot.png)

## 🖼️ Built with

- PyQt6

## 🧪 Supported Android Versions

Android 4.0 to 14

## 🚀 Installation

1. Make sure `adb` and `fastboot` are available in your system PATH.
2. Install Python 3.9+
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the tool:

```bash
python main.py
```
## Go to settings first and set phat to adb.exe and fastboot.exe !!!

## 📦 Requirements

```
PyQt6
requests
packaging
```

## 👤 Developer

**fzer0x**

## ⚠️ Note

This tool interacts directly with your Android device (Wifi/USB). USB debugging must be enabled and the ADB connection authorized on the device.

## 📜 License

[MIT License](LICENSE) – Free to use, modify, and distribute with conditions.
