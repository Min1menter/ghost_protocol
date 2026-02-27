# Ultimate Malware Test Suite - All Tests in One File
# This single file tests ALL Ghost Layer detection capabilities

param(
    [switch]$Cleanup
)

if ($Cleanup) {
    Write-Host "=== CLEANUP MODE ===" -ForegroundColor Yellow
    
    # Clean up temp files
    $tempFiles = @(
        "$env:TEMP\ghost_layer_test_files",
        "$env:TEMP\ransomware_test", 
        "$env:TEMP\malicious_script.ps1",
        "$env:TEMP\malicious_launcher.bat",
        "$env:TEMP\malicious.html",
        "$env:TEMP\browser_injection.ps1",
        "$env:TEMP\simple_rce.ps1",
        "$env:TEMP\rce_test.ps1",
        "$env:TEMP\long_rce.ps1"
    )
    
    foreach ($file in $tempFiles) {
        if (Test-Path $file) {
            Remove-Item $file -Recurse -Force
            Write-Host "Removed: $file" -ForegroundColor Green
        }
    }
    
    # Clean up test files in project directory
    $projectFiles = @(
        "malicious_app_simulator.ps1",
        "malicious_simulator.bat", 
        "simple_malware_simulator.ps1",
        "simple_exe_test.ps1",
        "comprehensive_malware_test.ps1",
        "direct_rce_test.ps1",
        "true_browser_rce.ps1",
        "manual_rce_test.ps1",
        "real_browser_rce.ps1",
        "simple_browser_rce.ps1",
        "long_rce_test.ps1",
        "immediate_test.ps1",
        "create_malware_exe.ps1",
        "advanced_malware_simulator.ps1"
    )
    
    foreach ($file in $projectFiles) {
        if (Test-Path $file) {
            Remove-Item $file -Force
            Write-Host "Removed: $file" -ForegroundColor Green
        }
    }
    
    # Kill any test processes
    Get-Process | Where-Object {$_.ProcessName -match 'powershell|cmd'} | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "All test processes terminated" -ForegroundColor Green
    return
}

Write-Host "========================================" -ForegroundColor Red
Write-Host "ULTIMATE GHOST LAYER TEST SUITE" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

# Test 1: RCE Attack
Write-Host "`n[TEST 1] RCE EXPLOIT SIMULATION" -ForegroundColor Green
$browser = Get-Process | Where-Object {$_.ProcessName -match 'chrome|firefox|msedge|brave'} | Select-Object -First 1
if ($browser) {
    Write-Host "Target: $($browser.ProcessName) (PID: $($browser.Id))" -ForegroundColor Cyan
    
    $rceScript = "Write-Host 'RCE_ATTACK: System compromised!'; Start-Sleep 3"
    $rceProcess = Start-Process powershell.exe -ArgumentList "-Command", $rceScript -PassThru
    Write-Host "RCE attack launched (PID: $($rceProcess.Id))" -ForegroundColor Red
    Start-Sleep -Seconds 4
    try { $rceProcess.Kill() } catch {}
}

# Test 2: Ransomware
Write-Host "`n[TEST 2] RANSOMWARE SIMULATION" -ForegroundColor Green
$ransomDir = "$env:TEMP\ransomware_test"
New-Item -ItemType Directory -Path $ransomDir -Force | Out-Null
1..5 | ForEach-Object { "Important data $_" | Out-File "$ransomDir\file$_.txt" }

$encryptScript = "Get-ChildItem '$ransomDir\*.txt' | ForEach-Object { (Get-Content `$_.FullName) -replace '[a-zA-Z0-9]', 'X' | Set-Content `$_.FullName }"
$ransomProcess = Start-Process powershell.exe -ArgumentList "-Command", $encryptScript -PassThru -WindowStyle Hidden
Write-Host "Ransomware encryption started (PID: $($ransomProcess.Id))" -ForegroundColor Red
Start-Sleep -Seconds 3
try { $ransomProcess.Kill() } catch {}
Remove-Item $ransomDir -Recurse -Force

# Test 3: Network Attack
Write-Host "`n[TEST 3] SUSPICIOUS NETWORK ACTIVITY" -ForegroundColor Green
$netScript = "1..3 | ForEach-Object { Write-Host 'C2_CONNECT: 192.168.1.$_':4444'; Start-Sleep 500 }"
$netProcess = Start-Process powershell.exe -ArgumentList "-Command", $netScript -PassThru -WindowStyle Hidden
Write-Host "Network attack simulation (PID: $($netProcess.Id))" -ForegroundColor Red
Start-Sleep -Seconds 2
try { $netProcess.Kill() } catch {}

# Test 4: Process Injection
Write-Host "`n[TEST 4] PROCESS INJECTION SIMULATION" -ForegroundColor Green
$injectScript = "Get-Process | Where-Object {`$_.ProcessName -match 'notepad|calc'} | Select-Object -First 3 | ForEach-Object { Write-Host 'INJECT:' `$_.ProcessName '(' `$_.Id ')' }"
$injectProcess = Start-Process powershell.exe -ArgumentList "-Command", $injectScript -PassThru -WindowStyle Hidden
Write-Host "Process injection simulation (PID: $($injectProcess.Id))" -ForegroundColor Red
Start-Sleep -Seconds 2
try { $injectProcess.Kill() } catch {}

# Test 5: Persistence Installation
Write-Host "`n[TEST 5] PERSISTENCE MECHANISMS" -ForegroundColor Green
$persistScript = @"
Write-Host "REGISTRY: HKLM Software Microsoft Windows CurrentVersion Run"
Write-Host "SCHEDULED: Daily maintenance task created"
Write-Host "SERVICE: Windows Update service installed"
Write-Host "WMI: Event subscription registered"
Write-Host "BROWSER: Malicious extension added"
"@
$persistProcess = Start-Process powershell.exe -ArgumentList "-Command", $persistScript -PassThru -WindowStyle Hidden
Write-Host "Persistence simulation (PID: $($persistProcess.Id))" -ForegroundColor Red
Start-Sleep -Seconds 3
try { $persistProcess.Kill() } catch {}

Write-Host "`n========================================" -ForegroundColor Red
Write-Host "ULTIMATE TEST SUITE COMPLETE" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host "Check Ghost Layer dashboard for ALL security alerts!" -ForegroundColor Yellow
Write-Host "Expected detections:" -ForegroundColor Cyan
Write-Host "- RCE Exploit (Browser to PowerShell)" -ForegroundColor Gray
Write-Host "- Ransomware (High entropy file encryption)" -ForegroundColor Gray
Write-Host "- Network Attack (Suspicious C2 connections)" -ForegroundColor Gray
Write-Host "- Process Injection (Legitimate process hijacking)" -ForegroundColor Gray
Write-Host "- Persistence (Registry service installation)" -ForegroundColor Gray
Write-Host "" -ForegroundColor White
Write-Host "Run with -Cleanup to remove all test files" -ForegroundColor Yellow
