@echo off
echo Starting MailGuard Python FastAPI Backend on port 8000...
cd /d "%~dp0backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
