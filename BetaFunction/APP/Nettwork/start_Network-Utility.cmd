@echo off
chcp 65001 >nul
title Windows Network Analyzer v1.0

echo ========================================
echo    Windows Network Analyzer Starter
echo ========================================
echo.

:find_python
echo [INFO] Searching for Python...
echo.

set PYTHON_CMD=

REM Check if python is in PATH
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
    goto :found_python
)

REM Check if py launcher is available
py --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    goto :found_python
)

REM Check if python3 is in PATH
python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python3
    goto :found_python
)

REM Check common Windows installation paths
if exist "C:\Python312\python.exe" (
    set PYTHON_CMD=C:\Python312\python.exe
    goto :found_python
)

if exist "C:\Python311\python.exe" (
    set PYTHON_CMD=C:\Python311\python.exe
    goto :found_python
)

if exist "C:\Python310\python.exe" (
    set PYTHON_CMD=C:\Python310\python.exe
    goto :found_python
)

if exist "C:\Python39\python.exe" (
    set PYTHON_CMD=C:\Python39\python.exe
    goto :found_python
)

if exist "C:\Python38\python.exe" (
    set PYTHON_CMD=C:\Python38\python.exe
    goto :found_python
)

if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
    goto :found_python
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe
    goto :found_python
)

if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python310\python.exe
    goto :found_python
)

if exist "%LOCALAPPDATA%\Programs\Python\Python39\python.exe" (
    set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python39\python.exe
    goto :found_python
)

if exist "%LOCALAPPDATA%\Programs\Python\Python38\python.exe" (
    set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python38\python.exe
    goto :found_python
)

if exist "%ProgramFiles%\Python312\python.exe" (
    set PYTHON_CMD=%ProgramFiles%\Python312\python.exe
    goto :found_python
)

if exist "%ProgramFiles%\Python311\python.exe" (
    set PYTHON_CMD=%ProgramFiles%\Python311\python.exe
    goto :found_python
)

if exist "%ProgramFiles(x86)%\Python312\python.exe" (
    set PYTHON_CMD=%ProgramFiles(x86)%\Python312\python.exe
    goto :found_python
)

if exist "%ProgramFiles(x86)%\Python311\python.exe" (
    set PYTHON_CMD=%ProgramFiles(x86)%\Python311\python.exe
    goto :found_python
)

REM Check for virtual environment
if exist "venv\Scripts\python.exe" (
    set PYTHON_CMD=venv\Scripts\python.exe
    goto :found_python
)

if exist ".venv\Scripts\python.exe" (
    set PYTHON_CMD=.venv\Scripts\python.exe
    goto :found_python
)

echo [ERROR] Python not found!
echo.
echo Please either:
echo 1. Install Python from https://www.python.org/
echo 2. Add Python to your PATH
echo 3. Or specify Python path manually
echo.
set /p manual_python="Enter path to python.exe (or press Enter to exit): "
if not "%manual_python%"=="" (
    if exist "%manual_python%" (
        set PYTHON_CMD=%manual_python%
        goto :found_python
    ) else (
        echo [ERROR] File not found: %manual_python%
        pause
        exit /b 1
    )
)
pause
exit /b 1

:found_python
echo [INFO] Python found: %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

:check_pip
echo [INFO] Checking pip...
%PYTHON_CMD% -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] pip not found!
    echo Attempting to install pip...

    %PYTHON_CMD% -m ensurepip --default-pip >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install pip!
        echo.
        echo Try manually: %PYTHON_CMD% -m ensurepip
        pause
        exit /b 1
    )
    echo [OK] pip installed
) else (
    echo [OK] pip available
)

echo.
echo [INFO] Upgrading pip to latest version...
%PYTHON_CMD% -m pip install --upgrade pip --quiet >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] pip upgraded
) else (
    echo [WARNING] Could not upgrade pip, continuing...
)

echo.
echo ========================================
echo Installing/Checking Windows Dependencies
echo ========================================
echo.

:install_deps
REM Windows-specific dependencies
set DEPENDENCIES=psutil colorama speedtest-cli requests python-nmap netaddr

for %%d in (%DEPENDENCIES%) do (
    echo Checking %%d...
    %PYTHON_CMD% -m pip show %%d >nul 2>&1
    if %%errorlevel%% neq 0 (
        echo [INSTALLING] %%d
        %PYTHON_CMD% -m pip install %%d --quiet
        if %%errorlevel%% equ 0 (
            echo [OK] %%d installed
        ) else (
            echo [WARNING] Issue installing %%d
        )
    ) else (
        echo [OK] %%d already installed
    )
    echo.
)

echo [INFO] Checking Windows networking tools...
where ipconfig >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Windows networking tools available
) else (
    echo [WARNING] Some Windows tools may be missing
)

echo.
echo ========================================
echo All dependencies checked!
echo Launching Windows Network Analyzer...
echo ========================================
echo.

:find_script
set SCRIPT_FILE=

REM Look for network analyzer script
if exist "windows_network_analyzer.py" (
    set SCRIPT_FILE=windows_network_analyzer.py
    goto :run_script
)

if exist "win_network_tools.py" (
    set SCRIPT_FILE=win_network_tools.py
    goto :run_script
)

if exist "network_utility.py" (
    set SCRIPT_FILE=network_utility.py
    goto :run_script
)

if exist "main.py" (
    set SCRIPT_FILE=main.py
    goto :run_script
)

if exist "Network_Multifunction.py" (
    set SCRIPT_FILE=Network_Multifunction.py
    goto :run_script
)

REM Search for any Python file in current directory
for %%f in (*.py) do (
    set SCRIPT_FILE=%%f
    goto :run_script
)

:run_script
if not defined SCRIPT_FILE (
    echo [ERROR] No Python files found!
    echo.
    dir *.py
    echo.
    pause
    exit /b 1
)

echo [INFO] Found script: %SCRIPT_FILE%
echo.

REM Offer admin rights for full functionality
echo Do you want to run with Administrator rights?
echo This is required for full network interface access.
echo.
choice /c YN /m "Run as Administrator? (Y/N): "
if %errorlevel% equ 1 (
    echo [INFO] Running with elevated privileges...

    REM Create temporary VBS script for admin launch
    echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\runasadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/k ""cd /d ""%CD%"" ^& ""%PYTHON_CMD%"" ""%SCRIPT_FILE%""", "", "runas", 1 >> "%TEMP%\runasadmin.vbs"

    wscript "%TEMP%\runasadmin.vbs"
    del "%TEMP%\runasadmin.vbs" >nul 2>&1

    echo [INFO] Launched in new window
    pause
    exit /b 0
)

echo [INFO] Running with current user rights...
echo.
%PYTHON_CMD% "%SCRIPT_FILE%"

set EXIT_CODE=%errorlevel%
if %EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] Script exited with error code: %EXIT_CODE%

    if %EXIT_CODE% equ 13 (
        echo [SUGGESTION] Administrator rights likely required!
        echo Run this batch file again and choose Administrator mode.
    )
)

echo.
pause
exit /b %EXIT_CODE%