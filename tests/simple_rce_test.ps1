# Simple RCE Test - Working Version
Write-Host "=== Simple RCE Test ===" -ForegroundColor Green

# Test 1: Browser simulation spawning cmd
Write-Host "Test 1: Browser simulation spawning cmd.exe" -ForegroundColor Yellow

# Create fake browser process
$fakeBrowser = Start-Process powershell -ArgumentList "-Command Write-Host 'Fake Browser'; Start-Sleep 15" -PassThru
Write-Host "Fake browser PID: $($fakeBrowser.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 2

# Spawn cmd.exe from fake browser
$cmdFromBrowser = Start-Process cmd -ArgumentList "/c echo Malicious cmd from fake browser && timeout /t 10" -PassThru
Write-Host "cmd.exe PID: $($cmdFromBrowser.Id)" -ForegroundColor Red
Write-Host "This should trigger RCE detection!" -ForegroundColor Red

# Test 2: Suspicious parent spawning PowerShell
Write-Host "`nTest 2: Suspicious parent spawning PowerShell" -ForegroundColor Yellow

$suspiciousParent = Start-Process powershell -ArgumentList "-Command Write-Host 'Suspicious Parent'; Start-Sleep 12" -PassThru
Write-Host "Suspicious parent PID: $($suspiciousParent.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 2

$shellFromSuspicious = Start-Process powershell -ArgumentList "-Command Write-Host 'Malicious shell from suspicious parent'; Start-Sleep 8" -PassThru
Write-Host "PowerShell PID: $($shellFromSuspicious.Id)" -ForegroundColor Red
Write-Host "This should trigger RCE detection!" -ForegroundColor Red

Write-Host "`nTest complete! Check Ghost Layer dashboard for RCE alerts." -ForegroundColor Green
Write-Host "Expected: 2 CRITICAL RCE alerts" -ForegroundColor Yellow

Start-Sleep -Seconds 8

# Cleanup
Get-Process | Where-Object { $_.ProcessName -like "*powershell*" } | Stop-Process -Force -ErrorAction SilentlyContinue
