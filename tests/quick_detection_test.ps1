# Quick Detection Test for Ghost Layer
Write-Host "=== Quick Ghost Layer Detection Test ===" -ForegroundColor Green

# Test 1: Create a process with a clearly suspicious name
Write-Host "Creating suspicious process..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-Command Write-Host 'mimikatz_password_stealer_active'; Start-Sleep 20" -WindowStyle Hidden

# Test 2: Create another suspicious process  
Write-Host "Creating another suspicious process..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-Command Write-Host 'cryptolocker_ransomware_running'; Start-Sleep 15" -WindowStyle Hidden

# Test 3: Create high entropy file in Ghost_Secrets directory
Write-Host "Creating high entropy file..." -ForegroundColor Yellow
$testDir = "C:\Ghost_Secrets"
if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force
}

$random = New-Object System.Random
$bytes = New-Object byte[] 512
$random.NextBytes($bytes)
[System.IO.File]::WriteAllBytes("$testDir\high_entropy_malware.bin", $bytes)

# Test 4: Create suspiciously named file
Write-Host "Creating suspicious file..." -ForegroundColor Yellow
"suspicious malware content" | Out-File "$testDir\keylogger_trojan.exe"

Write-Host "`nTest complete! Ghost Layer should detect:" -ForegroundColor Green
Write-Host "- Suspicious process: mimikatz_password_stealer_active" -ForegroundColor Cyan
Write-Host "- Suspicious process: cryptolocker_ransomware_running" -ForegroundColor Cyan  
Write-Host "- High entropy file: high_entropy_malware.bin" -ForegroundColor Cyan
Write-Host "- Suspicious file: keylogger_trojan.exe" -ForegroundColor Cyan

Write-Host "`nCheck Ghost Layer dashboard now!" -ForegroundColor Red
