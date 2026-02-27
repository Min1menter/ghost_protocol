# Ghost Layer Architecture

## Directory Structure

```
ghost-layer/
├── src/                          # React Frontend
│   ├── components/
│   │   ├── Dashboard.tsx         # Main SaaS console UI
│   │   └── PetOverlay.tsx        # Transparent Ghost pet window
│   ├── App.tsx                   # Window routing logic
│   ├── App.css                   # Tailwind + custom animations
│   └── main.tsx                  # React entry point
│
├── src-tauri/                    # Rust Backend
│   ├── src/
│   │   ├── main.rs               # Binary entry point
│   │   ├── lib.rs                # App initialization & dual-window setup
│   │   ├── sentinel.rs           # Background monitoring service
│   │   ├── commands.rs           # Tauri command handlers
│   │   └── db.rs                 # SQLite persistence layer
│   ├── Cargo.toml                # Rust dependencies
│   └── tauri.conf.json           # Tauri configuration
│
└── README.md                     # Setup instructions
```

## Data Flow

### 1. Threat Detection Flow
```
File System Event → sentinel.rs (entropy scan) → emit("threat-alert") → 
  → Dashboard.tsx (log display) + PetOverlay.tsx (visual alert)
```

### 2. Process Monitoring Flow
```
sysinfo loop → pattern matching → emit("threat-alert") → Frontend
```

### 3. AI Explanation Flow
```
Dashboard.tsx → invoke("request_ai_explanation") → 
  → commands.rs → Google Gemini API → Response → Dashboard
```

### 4. Whitelist Management Flow
```
Dashboard.tsx → invoke("add_to_whitelist") → 
  → commands.rs → db.rs (SQLite) → Success
```

## Key Components

### Sentinel (sentinel.rs)
- **File Watcher**: Uses `notify` crate to monitor `C:\Ghost_Secrets`
- **Entropy Scanner**: Shannon Entropy calculation (threshold: 7.5)
- **Process Monitor**: 5-second polling loop with `sysinfo`
- **Threat Emission**: Sends alerts via Tauri event system

### Database (db.rs)
- **Tables**: `whitelist`, `event_logs`
- **Operations**: CRUD for whitelist, append-only logs
- **Thread Safety**: Mutex-wrapped SQLite connection

### Commands (commands.rs)
- `kill_process`: Terminate suspicious processes
- `get_logs`: Retrieve recent threat events
- `add_to_whitelist` / `remove_from_whitelist`: Manage trusted processes
- `request_ai_explanation`: Query Google Gemini for threat analysis
- `get_system_health`: CPU, memory, process count metrics

### Dashboard (Dashboard.tsx)
- Real-time system health cards
- Scrollable threat log with severity color coding
- Whitelist management interface
- AI explanation integration (requires API key)

### Pet Overlay (PetOverlay.tsx)
- Frameless, transparent window
- SVG Ghost with CSS animations
- Listens for "threat-alert" events
- Shake animation + red color on threat

## Security Principles

1. **No unwrap()**: All Rust operations return `Result<T, E>`
2. **Async I/O**: All network and file operations use tokio
3. **Single Binary**: No external IPC or Python dependencies
4. **Entropy Detection**: Identifies encrypted/packed malware
5. **Process Isolation**: Foundation for Safe Harbor sandboxing

## Future Enhancements

- VHDX-based file sandboxing
- Commit/Discard workflow for isolated files
- Machine learning-based anomaly detection
- Network traffic monitoring
- Kernel-level hooks for deeper protection
