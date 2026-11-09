@echo off
title APIGuard Launcher
echo ========================================================
echo           Starting APIGuard Security Engine
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/2] Launching Backend Server on http://127.0.0.1:8000 ...
start "APIGuard Backend" cmd /k "python -m uvicorn apiguard.main:app --host 127.0.0.1 --port 8000 --app-dir backend"

echo [2/2] Launching Frontend Server on http://127.0.0.1:5173 ...
start "APIGuard Frontend" cmd /k "npm run dev --prefix frontend"

echo.
echo Waiting for servers to initialize...
timeout /t 3 /nobreak >nul

echo Opening browser at http://127.0.0.1:5173 ...
start http://127.0.0.1:5173

echo.
echo ========================================================
echo  APIGuard is running! Keep the two terminal windows open.
echo ========================================================
echo.
pause
