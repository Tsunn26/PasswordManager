@echo off
REM cd /d "%~dp0.."
REM "%~dp0..\.venv\Scripts\python.exe" -u "%~dp0..\main.py"


cd /d "%~dp0.."
set PYTHONPATH=%CD%
"%~dp0..\venv\Scripts\python.exe" -u "%~dp0..\modules\handler.py"