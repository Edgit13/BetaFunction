@echo off
echo ========================================
echo Password Manager Starter
echo ========================================
echo.

REM Try to find Python in different locations
set PYTHON_CMD=

REM Check if python is in PATH
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
    goto :found_python
)

REM Check if py launcher is available (Windows Python Launcher)
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

REM Check common installation paths
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

REM Check if there's a venv in current directory
if exist "venv\Scripts\python.exe" (
    set PYTHON_CMD=venv\Scripts\python.exe
    goto :found_python
)

if exist ".venv\Scripts\python.exe" (
    set PYTHON_CMD=.venv\Scripts\python.exe
    goto :found_python
)

REM Python not found
echo [ERROR] Python is not installed or not found!
echo.
echo Please either:
echo 1. Install Python from https://www.python.org/
echo 2. Add Python to your PATH
echo 3. Edit this batch file and set PYTHON_PATH at line 100
echo    to your Python executable location
echo.
echo Example: set PYTHON_PATH=C:\Path\To\Your\python.exe
pause
exit /b 1

:found_python
echo [INFO] Python found: %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

REM Check if pip is available
%PYTHON_CMD% -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not installed!
    echo Installing pip...
    %PYTHON_CMD% -m ensurepip --default-pip
)

echo [INFO] pip is available
echo.

REM Upgrade pip to latest version
echo [INFO] Upgrading pip...
%PYTHON_CMD% -m pip install --upgrade pip --quiet

echo.
echo [INFO] Checking and installing required packages...
echo.

REM Check and install cryptography
echo Checking cryptography...
%PYTHON_CMD% -m pip show cryptography >nul 2>&1
if %errorlevel% neq 0 (
    echo [INSTALLING] cryptography
    %PYTHON_CMD% -m pip install cryptography
) else (
    echo [OK] cryptography is already installed
)

REM Check and install pyperclip
echo Checking pyperclip...
%PYTHON_CMD% -m pip show pyperclip >nul 2>&1
if %errorlevel% neq 0 (
    echo [INSTALLING] pyperclip
    %PYTHON_CMD% -m pip install pyperclip
) else (
    echo [OK] pyperclip is already installed
)

REM Check and install pywin32
echo Checking pywin32...
%PYTHON_CMD% -m pip show pywin32 >nul 2>&1
if %errorlevel% neq 0 (
    echo [INSTALLING] pywin32
    %PYTHON_CMD% -m pip install pywin32
) else (
    echo [OK] pywin32 is already installed
)

echo.
echo ========================================
echo All dependencies are installed!
echo Starting Password Manager...
echo ========================================
echo.

REM Find the Python file
set PYTHON_FILE=

REM Check for common names
if exist "password_manager.py" set PYTHON_FILE=password_manager.py
if exist "Password_Manager.py" set PYTHON_FILE=Password_Manager.py
if exist "passwordmanager.py" set PYTHON_FILE=passwordmanager.py
if exist "main.py" set PYTHON_FILE=main.py

REM If still not found, search in current directory
if not defined PYTHON_FILE (
    for %%f in (*.py) do (
        set PYTHON_FILE=%%f
        goto :found_file
    )
)

:found_file
if not defined PYTHON_FILE (
    echo [ERROR] No Python file found in current directory!
    echo.
    echo Please make sure the password manager Python file is in the same folder as this batch file.
    echo.
    echo Current directory: %CD%
    echo.
    pause
    exit /b 1
)

echo [INFO] Running: %PYTHON_FILE%
echo.

REM Run the password manager
%PYTHON_CMD% "%PYTHON_FILE%"

REM Pause if there was an error
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Password Manager closed with an error
    pause
)

exit /b 0

REM ===== MANUAL PYTHON PATH CONFIGURATION =====
REM If Python is still not found, uncomment the line below and set your Python path
REM set PYTHON_CMD=C:\Path\To\Your\python.exe