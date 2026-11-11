@echo off
title APIGuard Launcher
echo ========================================================
echo           Starting APIGuard Security Engine
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/2] Launching Backend Server on http://127.0.0.1:8000 ...
start "APIGuard Backend" cmd /k "python -m uvicorn apiguard.main:app --host 127.0.0.1 --port 8000 --app-dir backend"

echo [2/2] Launching Frontend Server on http://localhost:5173 ...
start "APIGuard Frontend" cmd /k "npm run dev --prefix frontend"

echo.
echo Waiting for servers to initialize (at least 8 seconds)...
powershell -Command "for ($i=0; $i -lt 16; $i++) { try { $r = Invoke-WebRequest -Uri 'http://localhost:5173' -UseBasicParsing -TimeoutSec 1; if ($r.StatusCode -eq 200) { break } } catch {}; Start-Sleep -Milliseconds 500 }; Start-Sleep -Seconds 2"

echo Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo.
echo ========================================================
echo  APIGuard is running! Keep the two terminal windows open.
echo ========================================================
echo.
pause
