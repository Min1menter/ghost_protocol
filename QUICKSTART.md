# Ghost Layer - Quick Start Guide

## Prerequisites

- Node.js (v18+)
- Rust (latest stable)
- Windows OS (for full functionality)

## Installation

1. Clone or navigate to the project directory
2. Install frontend dependencies:
```bash
npm install
```

## Running the Application

### Development Mode
```bash
npm run tauri dev
```

This will:
- Start the Vite dev server
- Launch two windows:
  - Main Console (1200x800) - Security dashboard
  - Pet Overlay (200x200) - Transparent Ghost

### Production Build
```bash
npm run tauri build
```

The installer will be in `src-tauri/target/release/bundle/`

## First Run

1. The app creates `C:\Ghost_Secrets` directory for monitoring
2. The database is initialized in your app data folder
3. Both windows launch automatically

## Testing the System

### Test File Monitoring
1. Create a file in `C:\Ghost_Secrets`
2. Add random encrypted content (high entropy)
3. Watch the Ghost pet turn red and shake
4. Check the dashboard for the threat log

### Test Process Monitoring
The system watches for suspicious process names like:
- mimikatz
- psexec
- netcat
- nc.exe

### Test AI Explanations
1. Get a Google Gemini API key from: https://makersuite.google.com/app/apikey
2. Enter it in the dashboard
3. Click "AI Explain" on any threat log

## Dashboard Features

### System Health Cards
- Total running processes
- CPU usage percentage
- Memory usage (used/total GB)
- Total threats detected

### Threat Logs
- Real-time threat alerts
- Severity color coding (CRITICAL=red, HIGH=orange, etc.)
- Entropy values for file-based threats
- AI explanation button

### Whitelist Management
- Add trusted process names
- View all whitelisted processes
- Remove entries as needed

## Pet Overlay

The Ghost pet:
- Floats on top of all windows
- Normally purple with a smile
- Turns red and shakes when threats detected
- Shows "THREAT!" text during alerts

## Troubleshooting

### Windows don't appear
- Check if ports 1420 is available
- Look for errors in the terminal

### File watcher not working
- Ensure `C:\Ghost_Secrets` exists
- Check Windows permissions

### AI explanations fail
- Verify your Gemini API key is valid
- Check internet connection
- Look for rate limit errors

## Architecture Overview

```
User Action → React UI → Tauri invoke() → Rust Command
                ↑                              ↓
         Tauri emit() ← Sentinel Thread ← Background Monitor
```

## Next Steps

- Customize the watched directory in `sentinel.rs`
- Adjust entropy threshold (currently 7.5)
- Add more suspicious process patterns
- Implement VHDX sandboxing for file isolation
- Extend AI prompts for better explanations

## Security Notes

- The app requires elevated permissions for process termination
- All data is stored locally (no cloud sync)
- API keys are not persisted (enter each session)
- Whitelist is stored in SQLite database
