# Simple Test - Creates one high-entropy file

Write-Host "Creating test threat file..." -ForegroundColor Yellow

# Generate 2KB of random data (high entropy)
$randomBytes = New-Object byte[] 2048
$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rng.GetBytes($randomBytes)

# Save to monitored directory
$testFile = "C:\Ghost_Secrets\test_malware.exe"
[System.IO.File]::WriteAllBytes($testFile, $randomBytes)

Write-Host "Test file created: $testFile" -ForegroundColor Green
Write-Host ""
Write-Host "Watch your Ghost Layer dashboard!" -ForegroundColor Cyan
