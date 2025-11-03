@echo off
setlocal

REM =================================================================
REM  Run-Skript fuer Android Control Tool (Entwicklung)
REM  Richtet die Umgebung ein, aktualisiert pip und startet die Anwendung.
REM =================================================================

echo [INFO] Starte Android Control Tool im Entwicklungsmodus...

REM --- Konfiguration ---
set SCRIPT_NAME=main.py
set VENV_DIR=venv
REM Optional: Pfad zu ADB hier definieren, falls nicht im PATH
set "ADB_PATH=C:\Android\platform-tools"

REM --- Python-Pruefung ---
echo [INFO] Suche nach einer kompatiblen Python-Installation (3.8+)...
set PYTHON_EXE=

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

REM --- PIP-Upgrade global ---
echo [INFO] Aktualisiere systemweites pip...
%PYTHON_EXE% -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo [WARN] Konnte systemweites pip nicht aktualisieren.
) else (
    echo [INFO] Systemweites pip erfolgreich aktualisiert.
)

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

REM --- PIP im venv updaten ---
echo [INFO] Aktualisiere pip innerhalb der virtuellen Umgebung...
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo [WARN] Konnte pip im venv nicht aktualisieren.
) else (
    echo [INFO] pip im venv erfolgreich aktualisiert.
)

REM --- Abhaengigkeiten installieren ---
echo [INFO] Installiere Abhaengigkeiten aus requirements.txt...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [FEHLER] Installation der Abhaengigkeiten fehlgeschlagen.
    goto :error_exit
)

REM --- ADB Pfad prüfen ---
echo [INFO] Pruefe auf ADB...
where adb >nul 2>&1
if %errorlevel% neq 0 (
    if exist "%ADB_PATH%\adb.exe" (
        echo [INFO] ADB im angegebenen Pfad gefunden: "%ADB_PATH%"
        set PATH=%PATH%;%ADB_PATH%
    ) else (
        echo [WARN] ADB wurde nicht gefunden. Bitte installieren Sie Android Platform-Tools oder passen Sie ADB_PATH an.
    )
) else (
    echo [INFO] ADB ist im PATH vorhanden.
)

REM --- Auto-Update fuer main.py ---
echo [INFO] Versuche, die neueste 'main.py' von GitHub herunterzuladen...
set "MAIN_PY_URL=https://raw.githubusercontent.com/fzer0x/android-control-tool-V2/main/main.py"
set "TEMP_FILE=main.py.tmp"

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
