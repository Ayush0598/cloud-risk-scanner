@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python run_demo.py
start "" "reports\report.html"
pause
