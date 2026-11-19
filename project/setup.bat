@echo off
cd /d "%~dp0"
echo Creating a private Python environment in .venv ...
python -m venv .venv || (echo Python not found. Install Python 3.10+ from python.org and tick "Add python.exe to PATH". & pause & exit /b 1)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo.
echo Setup finished. Now double-click run_demo.bat
pause
