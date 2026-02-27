# RCE Detection Test Simulator - Fixed Version
# This script simulates RCE attack patterns to test if Ghost Layer detects it

Write-Host "=== Ghost Layer RCE Detection Test Suite ===" -ForegroundColor Green
Write-Host ""

# Test 1: Simulate Chrome spawning cmd.exe (RCE Attack)
Write-Host "Test 1: Simulating Chrome.exe spawning cmd.exe (RCE Attack)" -ForegroundColor Yellow
Write-Host "This should trigger RCE detection..."

# Create a more realistic simulation by starting a process that looks like chrome
$chromeProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c title FakeChromeProcess && echo Simulated Chrome process && timeout /t 5 > nul" -PassThru -WindowStyle Hidden
Write-Host "Fake Chrome PID: $($chromeProcess.Id)" -ForegroundColor Cyan

# Wait a moment, then simulate RCE attack by starting cmd.exe as a child
Start-Sleep -Seconds 1

# Use WMI to create a more realistic parent-child relationship
$cmdCommand = "cmd.exe /c echo Malicious cmd.exe spawned by Chrome && timeout /t 3 > nul && exit"
$cmdProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmdCommand" -PassThru

Write-Host "Malicious cmd PID: $($cmdProcess.Id)" -ForegroundColor Red
Write-Host "This should be detected as RCE exploit!" -ForegroundColor Red

# Test 2: Simulate Word spawning PowerShell (RCE Attack)
Write-Host ""
Write-Host "Test 2: Simulating WINWORD.exe spawning powershell.exe (RCE Attack)" -ForegroundColor Yellow

# Simulate Word process
$wordProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c title FakeWordProcess && echo Simulated Word process && timeout /t 5 > nul" -PassThru -WindowStyle Hidden
Write-Host "Fake Word PID: $($wordProcess.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 1

# Simulate PowerShell spawned by Word
$psCommand = "powershell.exe -Command Write-Host Malicious PowerShell spawned by Word; Start-Sleep 3; exit"
$psProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-Command $psCommand" -PassThru
Write-Host "Malicious PowerShell PID: $($psProcess.Id)" -ForegroundColor Red
Write-Host "This should be detected as RCE exploit!" -ForegroundColor Red

# Test 3: Normal process (should NOT trigger RCE)
Write-Host ""
Write-Host "Test 3: Normal process (should NOT trigger RCE)" -ForegroundColor Green

$normalProcess = Start-Process -FilePath "notepad.exe" -PassThru
Write-Host "Normal notepad.exe PID: $($normalProcess.Id)" -ForegroundColor Green
Write-Host "This should NOT trigger RCE detection" -ForegroundColor Green

# Test 4: Direct cmd.exe (should NOT trigger RCE)
Write-Host ""
Write-Host "Test 4: Direct cmd.exe launch (should NOT trigger RCE)" -ForegroundColor Green

$directCmd = Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Direct cmd launch && timeout /t 2 > nul && exit" -PassThru
Write-Host "Direct cmd PID: $($directCmd.Id)" -ForegroundColor Green
Write-Host "This should NOT trigger RCE detection (no browser parent)" -ForegroundColor Green

# Test 5: More realistic browser simulation
Write-Host ""
Write-Host "Test 5: Realistic browser simulation (should trigger RCE)" -ForegroundColor Yellow

# Start a process that simulates a browser more closely
$browserCommand = "powershell.exe -Command `$ps = Start-Process cmd.exe -ArgumentList '/c echo Browser simulation && timeout /t 4 > nul' -PassThru; Write-Host Browser PID: `$($ps.Id); Start-Sleep 5"
$browserSim = Start-Process -FilePath "powershell.exe" -ArgumentList "-Command $browserCommand" -PassThru
Write-Host "Browser simulator PID: $($browserSim.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 2

# Now spawn a shell from the "browser"
$cmd = "/c echo Shell spawned from browser simulation && timeout /t 3 > nul && exit"
$rceShell = Start-Process -FilePath "cmd.exe" -ArgumentList $cmd -PassThru
Write-Host "RCE Shell PID: $($rceShell.Id)" -ForegroundColor Red
Write-Host "This should trigger RCE detection!" -ForegroundColor Red

Write-Host ""
Write-Host "=== Test Simulation Complete ===" -ForegroundColor Green
Write-Host "Check your Ghost Layer dashboard for RCE alerts!" -ForegroundColor Cyan
Write-Host "Expected: 3 RCE alerts (Chrome->cmd, Word->PowerShell, Browser->cmd)" -ForegroundColor Yellow
Write-Host "Expected: 0 alerts for notepad.exe and direct cmd.exe" -ForegroundColor Green

# Cleanup test processes after 10 seconds
Start-Sleep -Seconds 10

Get-Process | Where-Object { $_.ProcessName -in @("cmd", "notepad", "powershell") } | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Test processes cleaned up." -ForegroundColor Gray
