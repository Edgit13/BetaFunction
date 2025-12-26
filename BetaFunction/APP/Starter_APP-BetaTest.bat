@echo off
chcp 65001 >nul
title NAS_OS - Beta Function Launcher

echo ========================================
echo    NAS_OS Beta Function Launcher
echo ========================================
echo.

:menu
echo.
echo [1] Launch Network Utility (Windows)
echo [2] Launch Password Manager
echo [3] Check Python & Dependencies
echo [4] Help / Information
echo [5] Exit
echo.
set /p choice="Select option [1-5]: "

if "%choice%"=="1" goto network
if "%choice%"=="2" goto password
if "%choice%"=="3" goto check_python
if "%choice%"=="4" goto help
if "%choice%"=="5" goto exit

echo.
echo [ERROR] Invalid choice! Please select 1-5.
timeout /t 2 >nul
goto menu

:network
echo.
echo [INFO] Launching Windows Network Utility...
echo [DEBUG] Current directory: %CD%
echo.

REM Search for network utility in different folder names
if exist "Network\start_Network-Utility.cmd" (
    echo [INFO] Found folder: Network\
    cd Network
    call start_Network-Utility.cmd
    cd..
    goto menu
)

if exist "WinNetwork\start_Network-Utility.cmd" (
    echo [INFO] Found folder: WinNetwork\
    cd WinNetwork
    call start_Network-Utility.cmd
    cd..
    goto menu
)

if exist "NetworkTools\start_Network-Utility.cmd" (
    echo [INFO] Found folder: NetworkTools\
    cd NetworkTools
    call start_Network-Utility.cmd
    cd..
    goto menu
)

REM Search any folder for network utility
echo [INFO] Searching for network utility folder...
for /d %%i in (*) do (
    if exist "%%i\start_Network-Utility.cmd" (
        echo [INFO] Found in folder: %%i\
        cd "%%i"
        call start_Network-Utility.cmd
        cd..
        goto menu
    )
    if exist "%%i\win_network_analyzer.bat" (
        echo [INFO] Found in folder: %%i\
        cd "%%i"
        call win_network_analyzer.bat
        cd..
        goto menu
    )
    if exist "%%i\windows_network_tools.cmd" (
        echo [INFO] Found in folder: %%i\
        cd "%%i"
        call windows_network_tools.cmd
        cd..
        goto menu
    )
)

echo [ERROR] Could not find network utility!
echo.
echo Available folders in current directory:
dir /ad /b
echo.
set /p manual_folder="Enter folder name manually (or press Enter to cancel): "
if not "%manual_folder%"=="" (
    if exist "%manual_folder%\start_Network-Utility.cmd" (
        cd "%manual_folder%"
        call start_Network-Utility.cmd
        cd..
    ) else (
        echo [ERROR] start_Network-Utility.cmd not found in "%manual_folder%"
        pause
    )
)
goto menu

:password
echo.
echo [INFO] Launching Password Manager...
echo [DEBUG] Current directory: %CD%
echo.

REM Search for password manager
if exist "Password_Manager\start_password_manager.bat" (
    echo [INFO] Found folder: Password_Manager\
    cd Password_Manager
    call start_password_manager.bat
    cd..
    goto menu
)

if exist "PassManager\start_password_manager.bat" (
    echo [INFO] Found folder: PassManager\
    cd PassManager
    call start_password_manager.bat
    cd..
    goto menu
)

REM Search any folder for password manager
echo [INFO] Searching for password manager folder...
for /d %%i in (*) do (
    if exist "%%i\start_password_manager.bat" (
        echo [INFO] Found in folder: %%i\
        cd "%%i"
        call start_password_manager.bat
        cd..
        goto menu
    )
    if exist "%%i\passman.py" (
        echo [INFO] Found in folder: %%i\
        echo [INFO] Launching passman.py directly...
        cd "%%i"
        python passman.py
        cd..
        goto menu
    )
)

echo [ERROR] Password manager not found!
echo.
echo Available folders in current directory:
dir /ad /b
echo.
set /p manual_pass_folder="Enter password manager folder name: "
if not "%manual_pass_folder%"=="" (
    if exist "%manual_pass_folder%\start_password_manager.bat" (
        cd "%manual_pass_folder%"
        call start_password_manager.bat
        cd..
    ) else (
        echo [ERROR] start_password_manager.bat not found in "%manual_pass_folder%"
        pause
    )
)
goto menu

:check_python
echo.
echo [INFO] Checking Python & Dependencies...
echo [DEBUG] Current directory: %CD%
echo.

REM Check Python availability
set PYTHON_FOUND=0

python --version >nul 2>&1
if %errorlevel% equ 0 (
    python --version
    echo [OK] Python found in PATH (command: python)
    set PYTHON_FOUND=1
    set PYTHON_CMD=python
)

py --version >nul 2>&1
if %errorlevel% equ 0 (
    py --version
    echo [OK] Python found via py launcher (command: py)
    set PYTHON_FOUND=1
    if not defined PYTHON_CMD set PYTHON_CMD=py
)

python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    python3 --version
    echo [OK] Python found in PATH (command: python3)
    set PYTHON_FOUND=1
    if not defined PYTHON_CMD set PYTHON_CMD=python3
)

if %PYTHON_FOUND% equ 0 (
    echo [WARNING] Python not found!
    echo.
    echo [SUGGESTION] Please:
    echo 1. Install Python from https://www.python.org/
    echo 2. Restart system after installation
    echo 3. Add Python to PATH during installation
    pause
    goto menu
)

echo.
echo [INFO] Checking dependencies...
echo.

REM Check Python basic functionality
echo [TEST] Testing Python basic import...
%PYTHON_CMD% -c "import sys; print(f'Python version: {sys.version[:20]}...'); print(f'Platform: {sys.platform}')"
if %errorlevel% neq 0 (
    echo [ERROR] Problem with Python!
    pause
    goto menu
)

echo.
echo [INFO] Checking for Network Utility:
%PYTHON_CMD% -c "import psutil" 2>nul && echo [OK] psutil installed || echo [MISSING] psutil not installed
%PYTHON_CMD% -c "import colorama" 2>nul && echo [OK] colorama installed || echo [MISSING] colorama not installed
%PYTHON_CMD% -c "import speedtest" 2>nul && echo [OK] speedtest-cli installed || echo [MISSING] speedtest-cli not installed

echo.
echo [INFO] Checking for Password Manager:
%PYTHON_CMD% -c "import cryptography" 2>nul && echo [OK] cryptography installed || echo [MISSING] cryptography not installed
%PYTHON_CMD% -c "import pyperclip" 2>nul && echo [OK] pyperclip installed || echo [MISSING] pyperclip not installed

echo.
echo [INFO] Do you want to install missing dependencies?
choice /c YN /m "Install missing packages? (Y/N): "
if %errorlevel% equ 1 (
    echo.
    echo [INFO] Installing dependencies...

    %PYTHON_CMD% -c "import psutil" 2>nul || (
        echo [INSTALL] psutil...
        %PYTHON_CMD% -m pip install psutil --quiet
    )

    %PYTHON_CMD% -c "import colorama" 2>nul || (
        echo [INSTALL] colorama...
        %PYTHON_CMD% -m pip install colorama --quiet
    )

    %PYTHON_CMD% -c "import speedtest" 2>nul || (
        echo [INSTALL] speedtest-cli...
        %PYTHON_CMD% -m pip install speedtest-cli --quiet
    )

    %PYTHON_CMD% -c "import cryptography" 2>nul || (
        echo [INSTALL] cryptography...
        %PYTHON_CMD% -m pip install cryptography --quiet
    )

    %PYTHON_CMD% -c "import pyperclip" 2>nul || (
        echo [INSTALL] pyperclip...
        %PYTHON_CMD% -m pip install pyperclip --quiet
    )

    echo [OK] Dependencies installed!
)

echo.
pause
goto menu

:help
echo.
echo ========================================
echo         HELP / INFORMATION
echo ========================================
echo.
echo NAS_OS Beta Function Launcher v2.0
echo.
echo This launcher allows running various beta functions:
echo.
echo [1] Windows Network Utility
echo     - Network traffic analysis
echo     - Connection monitoring
echo     - Speed testing
echo     - Port scanning
echo     - Network diagnostics
echo.
echo [2] Password Manager
echo     - Secure password storage
echo     - AES-256 encryption
echo     - Password generation
echo     - Clipboard integration
echo.
echo [3] Python & Dependencies Check
echo     - Python version check
echo     - Required libraries check
echo     - Automatic package installation
echo.
echo [4] This help screen
echo.
echo [5] Exit launcher
echo.
echo Folder structure:
echo   Network Utility: Network\ or WinNetwork\
echo   Password Manager: Password_Manager\
echo.
echo Current directory: %CD%
echo.
pause
goto menu

:exit
echo.
echo ========================================
echo Thank you for using NAS_OS Beta Functions!
echo Have a great day!
echo ========================================
timeout /t 3 >nul
exit