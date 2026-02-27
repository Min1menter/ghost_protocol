# Comprehensive Detection Test for Ghost Layer
Write-Host "=== Comprehensive Ghost Layer Detection Test ===" -ForegroundColor Green

# Test 1: Create files with suspicious names in monitored directory
Write-Host "1. Creating suspicious files..." -ForegroundColor Yellow
$testDir = "C:\Ghost_Secrets"
if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force
}

$suspiciousFiles = @(
    "mimikatz_password_stealer.exe",
    "psexec_hacking_tool.exe", 
    "meterpreter_payload.exe",
    "cobaltstrike_beacon.exe",
    "keylogger_pro.exe",
    "ransomware_locker.exe",
    "cryptominer_bot.exe",
    "backdoor_trojan.exe",
    "virus_payload.exe",
    "malware_dropper.exe"
)

foreach ($file in $suspiciousFiles) {
    $path = Join-Path $testDir $file
    "MZ`r`nFake malicious content: $file" | Out-File -FilePath $path -Encoding ASCII
    Write-Host "Created: $file" -ForegroundColor Gray
}

# Test 2: Create high entropy files
Write-Host "`n2. Creating high entropy files..." -ForegroundColor Yellow
for ($i = 1; $i -le 3; $i++) {
    $random = New-Object System.Random
    $bytes = New-Object byte[] 1024
    $random.NextBytes($bytes)
    $path = "$testDir\high_entropy_$i.bin"
    [System.IO.File]::WriteAllBytes($path, $bytes)
    Write-Host "Created high entropy file: high_entropy_$i.bin" -ForegroundColor Gray
}

# Test 3: Create processes that won't be whitelisted (using cmd with windowstyle hidden)
Write-Host "`n3. Starting suspicious processes..." -ForegroundColor Yellow

# Use cmd to start processes with suspicious window titles
Start-Process cmd -ArgumentList "/c title mimikatz_stealer && timeout /t 15 && exit" -WindowStyle Hidden
Start-Process cmd -ArgumentList "/c title keylogger_active && timeout /t 12 && exit" -WindowStyle Hidden  
Start-Process cmd -ArgumentList "/c title ransomware_encrypt && timeout /t 18 && exit" -WindowStyle Hidden
Start-Process cmd -ArgumentList "/c title backdoor_trojan && timeout /t 20 && exit" -WindowStyle Hidden

# Test 4: Create batch files with suspicious content
Write-Host "`n4. Creating suspicious batch files..." -ForegroundColor Yellow

$batchFiles = @(
    "password_stealer.bat",
    "encrypt_files.bat", 
    "remote_access.bat",
    "system_hack.bat"
)

foreach ($file in $batchFiles) {
    $path = Join-Path $testDir $file
    "@echo off`nFake malicious batch: $file`npause" | Out-File -FilePath $path -Encoding ASCII
    Write-Host "Created: $file" -ForegroundColor Gray
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Green
Write-Host "Ghost Layer should detect the following threats:" -ForegroundColor White
Write-Host "- 10 suspicious executable files" -ForegroundColor Yellow
Write-Host "- 3 high entropy files" -ForegroundColor Yellow
Write-Host "- 4 suspicious processes" -ForegroundColor Yellow
Write-Host "- 4 suspicious batch files" -ForegroundColor Yellow

Write-Host "`nCheck Ghost Layer dashboard for detection results!" -ForegroundColor Red
Write-Host "Total threats should be visible in real-time." -ForegroundColor Cyan

# Wait a bit for detection
Write-Host "`nWaiting 10 seconds for detection..." -ForegroundColor Blue
Start-Sleep -Seconds 10

Write-Host "Test execution complete!" -ForegroundColor Green
