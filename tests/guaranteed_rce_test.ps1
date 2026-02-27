# Guaranteed RCE Test - Should trigger detection
Write-Host "=== Guaranteed RCE Test ===" -ForegroundColor Green

# Create a parent process with a name that won't be whitelisted
Write-Host "Creating suspicious parent process..." -ForegroundColor Yellow

# Start a process with a clearly suspicious name
$suspiciousParent = Start-Process powershell -ArgumentList "-Command Write-Host 'Malware_Active_Process'; Start-Sleep 25" -PassThru
Write-Host "Suspicious parent PID: $($suspiciousParent.Id)" -ForegroundColor Cyan

Start-Sleep -Seconds 3

# Now spawn shell from this suspicious parent
Write-Host "Spawning PowerShell shell from suspicious parent..." -ForegroundColor Red
$rceShell = Start-Process powershell -ArgumentList "-Command Write-Host 'Malicious_Shell_From_Suspicious_Parent'; Start-Sleep 20" -PassThru
Write-Host "RCE Shell PID: $($rceShell.Id)" -ForegroundColor Red

Start-Sleep -Seconds 2

# Also spawn CMD
Write-Host "Spawning CMD shell from suspicious parent..." -ForegroundColor Red
$rceCmd = Start-Process cmd -ArgumentList "/c echo Malicious_CMD_From_Suspicious_Parent && timeout /t 15" -PassThru
Write-Host "RCE CMD PID: $($rceCmd.Id)" -ForegroundColor Red

Write-Host "`nRCE processes spawned from suspicious parent!" -ForegroundColor Yellow
Write-Host "This should DEFINITELY trigger RCE detection!" -ForegroundColor Red
Write-Host "Check Ghost Layer dashboard for CRITICAL alerts..." -ForegroundColor Cyan

Start-Sleep -Seconds 10

Write-Host "`nTest complete!" -ForegroundColor Green
