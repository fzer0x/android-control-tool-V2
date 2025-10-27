@echo off
setlocal

REM =================================================================
REM  Run-Skript fuer Android Control Tool (Entwicklung)
REM  Richtet die Umgebung ein und startet die Anwendung.
REM
REM  Voraussetzungen:
REM  1. Python 3.8+ muss installiert und im System-PATH sein.
REM  2. Eine 'requirements.txt' Datei muss im selben Verzeichnis existieren.
REM =================================================================

echo [INFO] Starte Android Control Tool im Entwicklungsmodus...

REM --- Konfiguration ---
set SCRIPT_NAME=main.py
set VENV_DIR=venv

REM --- Python-Pruefung (bevorzugt die neueste Version ab 3.8) ---
echo [INFO] Suche nach einer kompatiblen Python-Installation (3.8+)...
set PYTHON_EXE=

REM --- Explizite Pruefung auf Python 3.11 ---
echo [INFO] Pruefe auf Python 3.11...
py -3.11 --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_EXE=py -3.11
    echo [INFO] Python 3.11 gefunden.
)

if not defined PYTHON_EXE (
    echo [WARN] Keine spezifische Python-Version via 'py' launcher gefunden. Versuche generisches 'python'.
    python --version >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_EXE=python
        echo [INFO] Generisches 'python' gefunden.
    ) else (
        echo [FEHLER] Python wurde nicht im PATH gefunden. Bitte installieren Sie Python 3.8+ und fuegen Sie es zum PATH hinzu.
        goto :error_exit
    )
)

echo [INFO] Verwende '%PYTHON_EXE%' zum Ausfuehren.

REM --- Virtuelle Umgebung einrichten ---
if not exist "%VENV_DIR%\" (
    echo [INFO] Erstelle virtuelle Umgebung in '%VENV_DIR%'...
    %PYTHON_EXE% -m venv %VENV_DIR%
    if %errorlevel% neq 0 (
        echo [FEHLER] Konnte die virtuelle Umgebung nicht erstellen.
        goto :error_exit
    )
)

REM --- Virtuelle Umgebung aktivieren ---
echo [INFO] Aktiviere virtuelle Umgebung...
call "%VENV_DIR%\Scripts\activate.bat"
if not defined VIRTUAL_ENV (
    echo [FEHLER] Konnte die virtuelle Umgebung nicht aktivieren.
    goto :error_exit
)

REM --- Abhaengigkeiten installieren ---
echo [INFO] Installiere Abhaengigkeiten aus requirements.txt...
pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [FEHLER] Installation der Abhaengigkeiten fehlgeschlagen. Pruefen Sie die Ausgabe oben auf Fehler.
    goto :error_exit
)

REM --- Auto-Update fuer main.py ---
echo [INFO] Versuche, die neueste 'main.py' von GitHub herunterzuladen...
set "MAIN_PY_URL=https://raw.githubusercontent.com/fzer0x/android-control-tool-V2/main/main.py"
set "TEMP_FILE=main.py.tmp"

REM Versuche es mit curl, das in modernen Windows-Versionen enthalten ist
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Verwende 'curl' fuer den Download.
    curl -L -s -f -o "%TEMP_FILE%" "%MAIN_PY_URL%"
    if %errorlevel% neq 0 (
        echo [WARN] Download mit curl fehlgeschlagen. Ueberspringe Update.
        if exist "%TEMP_FILE%" del "%TEMP_FILE%"
        goto :skip_update
    )
) else (
    echo [WARN] 'curl' nicht gefunden. Versuche es mit PowerShell.
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%MAIN_PY_URL%', '%TEMP_FILE%')"
    if %errorlevel% neq 0 (
        echo [WARN] Download mit PowerShell fehlgeschlagen. Ueberspringe Update.
        if exist "%TEMP_FILE%" del "%TEMP_FILE%"
        goto :skip_update
    )
)

REM Pruefe, ob die heruntergeladene Datei Inhalt hat
for %%A in ("%TEMP_FILE%") do if %%~zA equ 0 (
    echo [WARN] Heruntergeladene Datei ist leer. Ueberspringe Update.
    del "%TEMP_FILE%"
    goto :skip_update
)

echo [INFO] Download erfolgreich. Ersetze lokale 'main.py'.
move /Y "%TEMP_FILE%" "%SCRIPT_NAME%"

:skip_update
REM --- Anwendung starten ---
echo [INFO] Starte die Anwendung (%SCRIPT_NAME%)...
python %SCRIPT_NAME%

endlocal
echo.
echo [INFO] Anwendung wurde beendet.
pause
goto :eof

:error_exit
echo.
echo [FEHLER] Das Skript wurde aufgrund eines Fehlers abgebrochen.
pause
endlocal
