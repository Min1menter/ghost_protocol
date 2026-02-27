@echo off
REM Test Virus Simulation Batch File
REM This simulates virus-like behavior to test Ghost Layer detection

echo === Ghost Layer Virus Detection Test ===
echo Creating simulated virus behaviors...

REM Create test directory
if not exist "C:\Ghost_Secrets\virus_test" mkdir "C:\Ghost_Secrets\virus_test"

REM Test 1: Create self-replicating simulation
echo 1. Creating self-replicating virus simulation...
echo @echo off > C:\Ghost_Secrets\virus_test\self_replicating.bat
echo echo Replicating... >> C:\Ghost_Secrets\virus_test\self_replicating.bat
echo copy %%0 %%temp%%\virus_%%random%%.bat >> C:\Ghost_Secrets\virus_test\self_replicating.bat

REM Test 2: Create registry modification simulation
echo 2. Creating registry modification simulation...
echo Windows Registry Editor Version 5.00 > C:\Ghost_Secrets\virus_test\registry_hack.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run] >> C:\Ghost_Secrets\virus_test\registry_hack.reg
echo "SuspiciousProgram"="C:\Ghost_Secrets\virus_test\malware.exe" >> C:\Ghost_Secrets\virus_test\registry_hack.reg

REM Test 3: Create file encryption simulation (ransomware)
echo 3. Creating ransomware simulation...
echo @echo off > C:\Ghost_Secrets\virus_test\ransomware_sim.bat
echo echo Encrypting files... >> C:\Ghost_Secrets\virus_test\ransomware_sim.bat
echo dir /s /b C:\temp\*.txt >> C:\Ghost_Secrets\virus_test\ransomware_sim.bat

REM Test 4: Create network connection simulation
echo 4. Creating network connection simulation...
echo @echo off > C:\Ghost_Secrets\virus_test\network_bot.bat
echo echo Connecting to C2 server... >> C:\Ghost_Secrets\virus_test\network_bot.bat
echo ping -n 10 127.0.0.1 >> C:\Ghost_Secrets\virus_test\network_bot.bat

REM Test 5: Create suspicious executables
echo 5. Creating suspicious executable files...
echo MZ > C:\Ghost_Secrets\virus_test\trojan_horse.exe
echo. >> C:\Ghost_Secrets\virus_test\trojan_horse.exe
echo This is a dummy trojan file >> C:\Ghost_Secrets\virus_test\trojan_horse.exe

echo MZ > C:\Ghost_Secrets\virus_test\worm.exe
echo. >> C:\Ghost_Secrets\virus_test\worm.exe
echo This is a dummy worm file >> C:\Ghost_Secrets\virus_test\worm.exe

echo MZ > C:\Ghost_Secrets\virus_test\spyware.exe
echo. >> C:\Ghost_Secrets\virus_test\spyware.exe
echo This is a dummy spyware file >> C:\Ghost_Secrets\virus_test\spyware.exe

REM Test 6: Create process injection simulation
echo 6. Creating process injection simulation...
echo @echo off > C:\Ghost_Secrets\virus_test\process_inject.bat
echo echo Injecting into explorer.exe... >> C:\Ghost_Secrets\virus_test\process_inject.bat
echo tasklist /fi "imagename eq explorer.exe" >> C:\Ghost_Secrets\virus_test\process_inject.bat

REM Test 7: Start suspicious processes
echo 7. Starting suspicious processes...
start /B cmd /c "echo Suspicious activity & timeout /t 20 >nul"
start /B cmd /c "echo Virus simulation running & timeout /t 15 >nul"
start /B cmd /c "echo Malware payload active & timeout /t 25 >nul"

echo.
echo === Test Files Created ===
echo Test directory: C:\Ghost_Secrets\virus_test
echo Suspicious files created:
echo   - self_replicating.bat
echo   - registry_hack.reg
echo   - ransomware_sim.bat
echo   - network_bot.bat
echo   - trojan_horse.exe
echo   - worm.exe
echo   - spyware.exe
echo   - process_inject.bat
echo.
echo === Monitoring Ghost Layer Detection ===
echo Check the Ghost Layer dashboard for detected threats!
echo Expected detections:
echo   - Suspicious file creation
echo   - High entropy files
echo   - Suspicious process activity
echo   - Registry modification attempts
echo.
echo Test complete! Check Ghost Layer dashboard for results.
pause
