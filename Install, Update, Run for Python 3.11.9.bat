@echo off
setlocal

REM =================================================================
REM  Run script for Android Control Tool (Development)
REM  Sets up the environment, updates pip, and starts the application.
REM =================================================================

echo [INFO] Starting Android Control Tool in development mode...

REM --- Configuration ---
set SCRIPT_NAME=main.py
set VENV_DIR=venv
REM Optional: define path to ADB here if it’s not in PATH
set "ADB_PATH=C:\Android\platform-tools"

REM --- Python check ---
echo [INFO] Searching for a compatible Python installation (3.8+)...
set PYTHON_EXE=

echo [INFO] Checking for Python 3.11...
py -3.11 --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_EXE=py -3.11
    echo [INFO] Found Python 3.11.
)

if not defined PYTHON_EXE (
    echo [WARN] No specific Python version found via 'py' launcher. Trying generic 'python'.
    python --version >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_EXE=python
        echo [INFO] Found generic 'python'.
    ) else (
        echo [ERROR] Python not found in PATH. Please install Python 3.8+ and add it to PATH.
        goto :error_exit
    )
)

echo [INFO] Using '%PYTHON_EXE%' for execution.

REM --- Global pip upgrade ---
echo [INFO] Updating system-wide pip...
%PYTHON_EXE% -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo [WARN] Could not update system-wide pip.
) else (
    echo [INFO] Successfully updated system-wide pip.
)

REM --- Setup virtual environment ---
if not exist "%VENV_DIR%\" (
    echo [INFO] Creating virtual environment in '%VENV_DIR%'...
    %PYTHON_EXE% -m venv %VENV_DIR%
    if %errorlevel% neq 0 (
        echo [ERROR] Could not create virtual environment.
        goto :error_exit
    )
)

REM --- Activate virtual environment ---
echo [INFO] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"
if not defined VIRTUAL_ENV (
    echo [ERROR] Could not activate virtual environment.
    goto :error_exit
)

REM =================================================================
REM --- Auto-update for main.py, androguard_tab.py, requirements.txt ---
REM =================================================================
echo [INFO] Checking for latest versions from GitHub...

set "FILES_TO_UPDATE=main.py androguard_tab.py requirements.txt"

for %%F in (%FILES_TO_UPDATE%) do call :UPDATE_FILE %%F

REM --- Update pip inside venv ---
echo [INFO] Updating pip inside virtual environment...
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo [WARN] Could not update pip in venv.
) else (
    echo [INFO] Successfully updated pip in venv.
)

REM --- Install dependencies ---
echo [INFO] Installing dependencies from requirements.txt...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    goto :error_exit
)

REM --- Check ADB path ---
echo [INFO] Checking for ADB...
where adb >nul 2>&1
if %errorlevel% neq 0 (
    if exist "%ADB_PATH%\adb.exe" (
        echo [INFO] Found ADB at specified path: "%ADB_PATH%"
        set PATH=%PATH%;%ADB_PATH%
    ) else (
        echo [WARN] ADB not found. Please install Android Platform-Tools manually or automatically in the Settings tab.
    )
) else (
    echo [INFO] ADB is present in PATH.
)

REM =================================================================
REM --- Start application ---
REM =================================================================
echo [INFO] Starting application (%SCRIPT_NAME%)...
python %SCRIPT_NAME%

endlocal
echo.
echo [INFO] Application has exited.
pause
goto :eof

REM =================================================================
REM --- Subroutine: Update file with hash comparison ---
REM =================================================================
:UPDATE_FILE
set "FILE_NAME=%~1"
set "TEMP_FILE=%FILE_NAME%.tmp"
set "FILE_URL=https://raw.githubusercontent.com/fzer0x/android-control-tool-V2/main/%FILE_NAME%"

echo [INFO] Downloading %FILE_NAME% from GitHub...

REM --- Download ---
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    curl -L -s -f -o "%TEMP_FILE%" "%FILE_URL%" 2>nul
) else (
    powershell -Command "(New-Object Net.WebClient).DownloadFile('%FILE_URL%', '%TEMP_FILE%')" 2>nul
)

if not exist "%TEMP_FILE%" (
    echo [WARN] Could not download %FILE_NAME%. Skipping.
    goto :eof
)

for %%A in ("%TEMP_FILE%") do if %%~zA equ 0 (
    echo [WARN] Downloaded file %FILE_NAME% is empty. Skipping update.
    del "%TEMP_FILE%"
    goto :eof
)

REM --- Hash comparison ---
set "OLD_HASH="
set "NEW_HASH="
if exist "%FILE_NAME%" (
    for /f "tokens=1" %%a in ('certutil -hashfile "%FILE_NAME%" SHA256 ^| find /i /v "SHA256" ^| findstr /r "^[0-9A-F]"') do set "OLD_HASH=%%a"
)
for /f "tokens=1" %%a in ('certutil -hashfile "%TEMP_FILE%" SHA256 ^| find /i /v "SHA256" ^| findstr /r "^[0-9A-F]"') do set "NEW_HASH=%%a"

if defined OLD_HASH if /i "%OLD_HASH%"=="%NEW_HASH%" (
    echo [INFO] %FILE_NAME% is already up to date.
    del "%TEMP_FILE%"
    goto :eof
)

echo [UPDATE] New version of %FILE_NAME% found. Replacing file...
move /Y "%TEMP_FILE%" "%FILE_NAME%" >nul
echo [INFO] Successfully updated %FILE_NAME%.
goto :eof

:error_exit
echo.
echo [ERROR] The script was aborted due to an error.
pause
endlocal
