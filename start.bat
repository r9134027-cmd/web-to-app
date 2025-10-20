@echo off
echo ====================================================================
echo    Advanced Domain Reconnaissance Desktop Application
echo ====================================================================
echo.
echo Starting application...
echo.

python run.py

if errorlevel 1 (
    echo.
    echo Error: Failed to start application
    echo.
    echo Please ensure Python is installed and in your PATH
    echo Try: python --version
    echo.
    pause
)
