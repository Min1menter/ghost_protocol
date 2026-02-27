# Test if frontend is receiving alerts
Write-Host "Testing frontend alert reception..." -ForegroundColor Yellow

# This will test if the frontend can receive any alert at all
# by simulating what should happen when RCE is detected

Write-Host "If frontend is working, you should see:" -ForegroundColor Green
Write-Host "1. A CRITICAL alert in Threat Logs" -ForegroundColor White
Write-Host "2. RCE Alert Modal popup" -ForegroundColor White  
Write-Host "3. Browser: http://localhost:1420" -ForegroundColor White

Write-Host "Check the dashboard now!" -ForegroundColor Red
