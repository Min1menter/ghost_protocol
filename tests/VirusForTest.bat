@echo off
title Ghost Layer - Parallel Test Runner
setlocal enabledelayedexpansion

echo Starting all tests with 1-second intervals...

set COUNT=0
for %%i in (*.ps1) do (
    set /a COUNT+=1
    echo Starting test !COUNT!: %%i
    
    :: Start each test minimized with 1-second delay between launches
    start /min powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File "%%i"
    
    :: 1-second delay before next launch
    timeout /t 1 /nobreak > nul
)

echo All %COUNT% tests launched!
exit