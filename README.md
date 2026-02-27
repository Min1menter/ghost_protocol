# Ghost Layer - Industrial Grade Security Suite

A Rust-powered security suite that isolates users in a virtualized layer and uses AI to educate them on threats.

## Architecture

- **Sentinel (Rust)**: Background service for process monitoring, file-system tripwires, and entropy scanning
- **Console (React)**: Dual-window frontend with SaaS dashboard and animated Ghost pet overlay
- **Analyst (AI)**: Google Gemini integration for explainable security insights

## Features

- Real-time process monitoring with suspicious behavior detection
- File system watching with Shannon Entropy analysis for malware detection
- SQLite-based whitelist and event logging
- AI-powered threat explanations via Google Gemini API
- Transparent, always-on-top Ghost pet that alerts on threats
- Dark-mode SaaS dashboard with system health metrics

## Setup

1. Install dependencies:
```bash
npm install
```

2. Run in development mode:
```bash
npm run tauri dev
```

3. Build for production:
```bash
npm run tauri build
```

## Configuration

- The Sentinel monitors `C:\Ghost_Secrets` by default
- Database is stored in the app data directory
- To use AI explanations, enter your Google Gemini API key in the dashboard

## Usage

1. **Main Window**: View threat logs, manage whitelist, and monitor system health
2. **Pet Window**: A transparent overlay Ghost that shakes and turns red when threats are detected
3. **AI Explanations**: Click "AI Explain" on any threat log to get user-friendly security insights

## Security Features

- Shannon Entropy scanning (threshold: 7.5) to detect encrypted/packed malware
- Process name pattern matching for known hacking tools
- Safe Harbor logic for file isolation (foundation laid for VHDX sandboxing)
- No external IPC - single binary monolith architecture

## Tech Stack

- Rust (Core/Sentinel)
- Tauri 2.0 (Bridge)
- React + TypeScript (UI)
- Tailwind CSS (Styling)
- SQLite (Persistence)
- Google Gemini API (AI Analysis)

## Development Notes

- All Rust operations use `Result<T, E>` for safety
- No `unwrap()` calls in production code
- Ghost pet is an inline SVG (no external assets)
- Async/await for all I/O operations

## Features Added

- AI Explain: Get user-friendly security insights via Google Gemini API
- Add or remove any apps from the whitelist
- Add your folder and files as trusted
- Added engines folder for future engine implementations
- used mod.rs , rce_detector.rs for remote code execution detection