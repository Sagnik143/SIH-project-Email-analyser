@echo off
echo ===================================================
echo   Starting MailGuard Platform (Full Stack)
echo ===================================================
echo.
echo 1. Starting Python FastAPI Backend on port 8000...
start "MailGuard Backend (FastAPI)" cmd /k "cd /d "%~dp0backend" && python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo 2. Starting React Vite Frontend on port 5173...
start "MailGuard Frontend (React)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ===================================================
echo  Platform is running!
echo  Frontend UI:  http://localhost:5173
echo  Backend Docs: http://localhost:8000/docs
echo ===================================================
echo.
