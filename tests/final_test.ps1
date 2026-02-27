# Final Test - Create direct threat alerts
Write-Host "FINAL GHOST LAYER TEST" -ForegroundColor Red
Write-Host "This will create visible alerts in the dashboard" -ForegroundColor Yellow

# Test 1: Create suspicious process activity
Write-Host "`n[TEST] Creating suspicious PowerShell activity..." -ForegroundColor Green

$suspiciousScript = @"
Write-Host "SUSPICIOUS_PROCESS_DETECTED"
Write-Host "THREAT_TYPE: MALICIOUS_EXECUTION"
Write-Host "SEVERITY: HIGH"
Start-Sleep 2
"@

$suspiciousProcess = Start-Process powershell.exe -ArgumentList "-Command", $suspiciousScript -PassThru -WindowStyle Hidden
Write-Host "Suspicious process started (PID: $($suspiciousProcess.Id))" -ForegroundColor Red

# Test 2: Multiple rapid process creation (should trigger alerts)
Write-Host "`n[TEST] Rapid process creation test..." -ForegroundColor Green

1..3 | ForEach-Object {
    Start-Process powershell -ArgumentList "-Command Write-Host \"RAPID_PROCESS_$_\"; Start-Sleep 1" -WindowStyle Hidden
    Write-Host "Created process $_" -ForegroundColor Cyan
    Start-Sleep -Milliseconds 500
}

Write-Host "\nTEST COMPLETE!" -ForegroundColor Green
Write-Host "Check Ghost Layer dashboard at http://localhost:1420" -ForegroundColor Yellow
Write-Host "You should see threat alerts in the Threat Logs section" -ForegroundColor White

# Clean up after delay
Start-Sleep -Seconds 5
try { 
    Stop-Process -Id $suspiciousProcess.Id -Force -ErrorAction SilentlyContinue 
    Get-Process powershell | Where-Object {$_.CommandLine -match "RAPID_PROCESS"} | Stop-Process -Force -ErrorAction SilentlyContinue
} catch {}
