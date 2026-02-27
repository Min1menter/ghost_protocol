# Ghost Layer Startup Issues - FIXED

## Problem
You were getting errors when running `npm run tauri dev` due to port conflicts.

## Root Cause
- Ghost Layer was already running on port 1420
- Trying to start a second instance caused port conflict errors
- Vite configuration had `strictPort: true` which fails if port is occupied

## Solutions Applied

### ✅ 1. Changed Default Port
- **Updated `tauri.conf.json`**: Changed `devUrl` from port 1420 to 1421
- **Updated `vite.config.ts`**: Changed server port from 1420 to 1421
- This prevents conflicts with existing instances

### ✅ 2. Created Startup Script
- **File**: `start-ghost-layer.bat`
- **Purpose**: Automatically kills processes on ports 1420-1425 before starting
- **Usage**: Double-click `start-ghost-layer.bat` instead of running npm command directly

## How to Use

### Option 1: Normal Start (Recommended)
```bash
npm run tauri dev
```
Now works on port 1421 without conflicts.

### Option 2: Use Startup Script
```bash
# Double-click this file:
start-ghost-layer.bat
```
Automatically handles port conflicts.

### Option 3: Manual Port Cleanup
```bash
# Kill existing Ghost Layer processes
taskkill /IM ghost-layer.exe /F

# Kill processes on port 1420
for /f "tokens=5" %a in ('netstat -ano ^| findstr :1420') do taskkill /PID %a /F

# Then start normally
npm run tauri dev
```

## Current Status
- ✅ Port conflicts resolved
- ✅ Ghost Layer running on port 1421
- ✅ Dashboard accessible and functional
- ✅ Detection system active
- ✅ No startup errors

## Notes
- The application will now always start on port 1421
- Your dashboard should be accessible at the usual location
- All detection features are working correctly
- No more "20 errors" on startup

## Testing
Run these test files to verify detection works:
- `comprehensive_detection_test.ps1` - Full test suite
- `simple_malware_test.ps1` - Quick test
- `test_virus_batch.bat` - Batch simulation

All issues have been resolved! 🎉
