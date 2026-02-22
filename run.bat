@echo off
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3 and add it to PATH.
    pause
    exit /b 1
)

python -c "import customtkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies. Try running: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

python McryptGUI.py
