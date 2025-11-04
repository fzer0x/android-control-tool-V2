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

REM =================================================================
REM --- Auto-Update fuer main.py und androguard_tab.py mit Hash-Vergleich ---
REM =================================================================
echo [INFO] Pruefe auf neueste Versionen von GitHub...

set "FILES_TO_UPDATE=main.py androguard_tab.py"

for %%F in (%FILES_TO_UPDATE%) do call :UPDATE_FILE %%F

goto :start_app

REM =================================================================
REM --- Unterprogramm: Datei aktualisieren ---
REM =================================================================
:UPDATE_FILE
set "FILE_NAME=%~1"
set "TEMP_FILE=%FILE_NAME%.tmp"
set "FILE_URL=https://raw.githubusercontent.com/fzer0x/android-control-tool-V2/main/%FILE_NAME%"

echo [INFO] Lade %FILE_NAME% von GitHub herunter...

REM --- Download ---
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    curl -L -s -f -o "%TEMP_FILE%" "%FILE_URL%" 2>nul
) else (
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%FILE_URL%', '%TEMP_FILE%')" 2>nul
)

if not exist "%TEMP_FILE%" (
    echo [WARN] Konnte %FILE_NAME% nicht herunterladen. Ueberspringe.
    goto :eof
)

for %%A in ("%TEMP_FILE%") do if %%~zA equ 0 (
    echo [WARN] Heruntergeladene Datei %FILE_NAME% ist leer. Ueberspringe Update.
    del "%TEMP_FILE%"
    goto :eof
)

REM --- Hash-Vergleich ---
set "OLD_HASH="
set "NEW_HASH="
if exist "%FILE_NAME%" (
    for /f "tokens=1" %%a in ('certutil -hashfile "%FILE_NAME%" SHA256 ^| find /i /v "SHA256" ^| findstr /r "^[0-9A-F]"') do set "OLD_HASH=%%a"
)
for /f "tokens=1" %%a in ('certutil -hashfile "%TEMP_FILE%" SHA256 ^| find /i /v "SHA256" ^| findstr /r "^[0-9A-F]"') do set "NEW_HASH=%%a"

if defined OLD_HASH if /i "%OLD_HASH%"=="%NEW_HASH%" (
    echo [INFO] %FILE_NAME% ist bereits aktuell.
    del "%TEMP_FILE%"
    goto :eof
)

echo [UPDATE] Neue Version von %FILE_NAME% gefunden. Ersetze Datei...
move /Y "%TEMP_FILE%" "%FILE_NAME%" >nul
echo [INFO] %FILE_NAME% erfolgreich aktualisiert.
goto :eof

REM =================================================================
REM --- Anwendung starten ---
REM =================================================================
:start_app
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
