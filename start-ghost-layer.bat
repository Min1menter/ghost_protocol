@echo off
REM Ghost Layer Startup Script - Handles port conflicts

echo === Ghost Layer Startup ===
echo Checking for existing instances...

REM Kill any existing processes on port 1420-1425
for /l %%i in (1420,1,1425) do (
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%%i') do (
        if %%a NEQ 0 (
            echo Killing process %%a using port %%i
            taskkill /PID %%a /F >nul 2>&1
        )
    )
)

REM Wait a moment for processes to terminate
timeout /t 2 >nul

echo Starting Ghost Layer...
npm run tauri dev

pause
