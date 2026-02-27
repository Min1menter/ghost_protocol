# External Browser RCE Test - More realistic scenario
Write-Host "=== External Browser RCE Test ===" -ForegroundColor Green

# Method 1: Start browser with a different name to avoid whitelist
Write-Host "1. Starting browser with modified process name..." -ForegroundColor Yellow

# Start PowerShell first (this will be the "browser")
$parentProcess = Start-Process powershell -ArgumentList "-Command Write-Host 'Fake browser process'; Start-Sleep 30" -PassThru
Write-Host "Fake browser PID: $($parentProcess.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 2

# Now spawn shell from the "browser" context - this should trigger RCE detection
Write-Host "2. Spawning shell from fake browser context..." -ForegroundColor Red
$childProcess = Start-Process powershell -ArgumentList "-Command Write-Host 'Malicious shell from fake browser'; Start-Sleep 10" -PassThru
Write-Host "Shell PID: $($childProcess.Id)" -ForegroundColor Red

Write-Host "This should trigger RCE detection!" -ForegroundColor Yellow
Write-Host "Check Ghost Layer dashboard now..." -ForegroundColor Cyan

Start-Sleep -Seconds 5

# Method 2: Test with cmd.exe
Write-Host "`n3. Testing CMD shell spawn..." -ForegroundColor Yellow
$cmdChild = Start-Process cmd -ArgumentList "/c echo Malicious CMD from fake browser && timeout /t 8" -PassThru
Write-Host "CMD PID: $($cmdChild.Id)" -ForegroundColor Red

Write-Host "`nTest complete! Check Ghost Layer dashboard for RCE alerts." -ForegroundColor Green
