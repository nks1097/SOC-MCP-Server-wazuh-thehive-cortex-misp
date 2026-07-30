@echo off
set PYTHONPATH=%~dp0
set FASTMCP_LOG_LEVEL=CRITICAL
cd /d "%~dp0"
"%~dp0\.venv\Scripts\python.exe" -m src.main
