Ghost Layer Security System - Function Documentation

This document provides comprehensive documentation of all functions in Ghost Layer security system, including their usage, parameters, and return values.

Table of Contents
- Rust Backend Functions
  - Main Application
  - Commands (Tauri IPC)
  - Sandbox Engine
  - RCE Detector Engine
  - Process Sentinel
- TypeScript Frontend Functions
  - Dashboard Component
  - Pet Overlay Component

---

Rust Backend Functions

 Main Application

 `run()`
**Location:** `src-tauri/src/lib.rs:16`
**Usage:** Main application entry point
**Parameters:** None
**Returns:** `()` (never returns on success)
**Description:** Initializes the Tauri application, sets up database, creates windows, and starts background monitoring services.

---

### Commands (Tauri IPC)

#### Process Management Commands

##### `kill_process(pid: u32)`
**Location:** `src-tauri/src/commands.rs:17`
**Usage:** Terminates a process by PID
**Parameters:** 
- `pid: u32` - Process ID to terminate
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if process not found or termination failed

##### `get_logs(db: State<'_, Arc<Database>>, limit: usize)`
**Location:** `src-tauri/src/commands.rs:35`
**Usage:** Retrieves recent security logs from database
**Parameters:**
- `db: Database state` - Database connection
- `limit: usize` - Maximum number of logs to retrieve
**Returns:** `Result<Vec<EventLog>, String>`
- `Ok(Vec<EventLog>)`: Array of log entries
- `Err(String)`: Database error message

#### Whitelist Management Commands

##### `add_to_whitelist(db: State<'_, Arc<Database>>, process_name: String)`
**Location:** `src-tauri/src/commands.rs:41`
**Usage:** Adds a process to the whitelist and trusted apps
**Parameters:**
- `db: Database state` - Database connection
- `process_name: String` - Name of process to whitelist
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if operation failed

##### `get_whitelist(db: State<'_, Arc<Database>>)`
**Location:** `src-tauri/src/commands.rs:132`
**Usage:** Retrieves all whitelisted processes
**Parameters:**
- `db: Database state` - Database connection
**Returns:** `Result<Vec<WhitelistEntry>, String>`
- `Ok(Vec<WhitelistEntry>)`: Array of whitelist entries
- `Err(String)`: Database error message

##### `remove_from_whitelist(db: State<'_, Arc<Database>>, id: i64, process_name: Option<String>)`
**Location:** `src-tauri/src/commands.rs:140`
**Usage:** Removes a process from whitelist and trusted apps
**Parameters:**
- `db: Database state` - Database connection
- `id: i64` - Database entry ID
- `process_name: Option<String>` - Optional process name for trusted apps removal
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if operation failed

#### AI Explanation Commands

##### `request_ai_explanation(log_text: String)`
**Location:** `src-tauri/src/commands.rs:175`
**Usage:** Requests AI-powered explanation of security events
**Parameters:**
- `log_text: String` - Security log text to analyze
**Returns:** `Result<AiExplanation, String>`
- `Ok(AiExplanation)`: Structured explanation with recommendations
- `Err(String)`: API or parsing error message

#### System Health Commands

##### `get_system_health()`
**Location:** `src-tauri/src/commands.rs:275`
**Usage:** Retrieves current system health metrics
**Parameters:** None
**Returns:** `Result<SystemHealth, String>`
- `Ok(SystemHealth)`: System health data structure
- `Err(String)`: Error message if system info unavailable

#### File Verification Commands

##### `check_file_hash(file_path: String)`
**Location:** `src-tauri/src/commands.rs:296`
**Usage:** Checks if a file is trusted based on hash verification
**Parameters:**
- `file_path: String` - Path to file to check
**Returns:** `Result<FileStatus, String>`
- `Ok(FileStatus)`: File trust status
- `Err(String)`: Error message if check failed

#### Trusted Application Management

##### `add_trusted_app(name: String, hash: String, path: Option<String>, description: Option<String>)`
**Location:** `src-tauri/src/commands.rs:306`
**Usage:** Adds a trusted application to whitelist
**Parameters:**
- `name: String` - Application name
- `hash: String` - File hash
- `path: Option<String>` - Optional file path
- `description: Option<String>` - Optional description
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if operation failed

##### `get_trusted_apps()`
**Location:** `src-tauri/src/commands.rs:378`
**Usage:** Retrieves all trusted applications
**Parameters:** None
**Returns:** `Result<Vec<TrustedApp>, String>`
- `Ok(Vec<TrustedApp>)`: Array of trusted applications
- `Err(String)`: Error message if retrieval failed

#### Trusted Folder Management

##### `add_trusted_folder(folder_path: String)`
**Location:** `src-tauri/src/commands.rs:336`
**Usage:** Adds a folder to trusted locations
**Parameters:**
- `folder_path: String` - Path to folder
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if operation failed

##### `get_trusted_folders()`
**Location:** `src-tauri/src/commands.rs:351`
**Usage:** Retrieves all trusted folders
**Parameters:** None
**Returns:** `Result<Vec<String>, String>`
- `Ok(Vec<String>)`: Array of trusted folder paths
- `Err(String)`: Error message if retrieval failed

##### `remove_trusted_folder(folder_path: String)`
**Location:** `src-tauri/src/commands.rs:360`
**Usage:** Removes a folder from trusted locations
**Parameters:**
- `folder_path: String` - Path to folder to remove
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if operation failed

#### Sandbox Management Commands

##### `migrate_process_to_sandbox(pid: u32, sentinel: State<'_, Arc<ProcessSentinel>>)`
**Location:** `src-tauri/src/commands.rs:405`
**Usage:** Migrates a process to a restricted sandbox environment
**Parameters:**
- `pid: u32` - Process ID to migrate
- `sentinel: ProcessSentinel state` - Process sentinel instance
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message
- `Err(String)`: Error message if migration failed

##### `get_sandbox_status(sentinel: State<'_, Arc<ProcessSentinel>>)`
**Location:** `src-tauri/src/commands.rs:420`
**Usage:** Retrieves current sandbox status and information
**Parameters:**
- `sentinel: ProcessSentinel state` - Process sentinel instance
**Returns:** `Result<SandboxStatus, String>`
- `Ok(SandboxStatus)`: Sandbox status information
- `Err(String)`: Error message if status retrieval failed

##### `update_process_risk_score(pid: u32, score_change: i32, sentinel: State<'_, Arc<ProcessSentinel>>)`
**Location:** `src-tauri/src/commands.rs:447`
**Usage:** Updates a process's risk score and applies restrictions based on thresholds
**Parameters:**
- `pid: u32` - Process ID
- `score_change: i32` - Change to apply to risk score
- `sentinel: ProcessSentinel state` - Process sentinel instance
**Returns:** `Result<String, String>`
- `Ok(String)`: Success message with new score and verdict
- `Err(String)`: Error message if update failed

##### `handle_threat_decision(alert_id: String, should_remove: bool, pid: Option<u32>, db: State<'_, Arc<Database>>)`
**Location:** `src-tauri/src/commands.rs:482`
**Usage:** Handles user decision on threat alerts (remove or ignore)
**Parameters:**
- `alert_id: String` - Alert identifier
- `should_remove: bool` - Whether to remove threat
- `pid: Option<u32>` - Optional process ID to terminate
- `db: Database state` - Database connection for logging
**Returns:** `Result<String, String>`
- `Ok(String)`: Action result message
- `Err(String)`: Error message if action failed

---

Sandbox Engine

Core Sandbox Management

new()
Location: src-tauri/src/engines/sandbox.rs:99
Usage: Creates a new SandboxManager instance
Parameters: None
Returns: SandboxManager
Description: Initializes sandbox manager with empty process and sandbox maps.

initialize(&mut self)
Location: src-tauri/src/engines/sandbox.rs:107
Usage: Initializes the sandbox system
Parameters: None
Returns: Result<()>
- Ok(()): Initialization successful
- Err(anyhow::Error): Initialization failed
Description: Sets up system monitoring and creates temporary directories.

create_job_object(&self)
Location: src-tauri/src/engines/sandbox.rs:121
Usage: Creates a new sandbox environment
Parameters: None
Returns: Result<SandboxHandle>
- Ok(SandboxHandle): New sandbox handle
- Err(anyhow::Error): Sandbox creation failed

Process Control

suspend_process(&self, process_id: u32)
Location: src-tauri/src/engines/sandbox.rs:136
Usage: Suspends a process for seamless migration
Parameters:
- process_id: u32 - Process ID to suspend
Returns: Result<()>
- Ok(()): Process suspended successfully
- Err(anyhow::Error): Suspension failed

resume_process(&self, process_id: u32)
Location: src-tauri/src/engines/sandbox.rs:167
Usage: Resumes a suspended process
Parameters:
- process_id: u32 - Process ID to resume
Returns: Result<()>
- Ok(()): Process resumed successfully
- Err(anyhow::Error): Resume failed

migrate_to_sandbox(&mut self, process_id: u32)
Location: src-tauri/src/engines/sandbox.rs:283
Usage: Migrates an existing process to sandbox without killing it
Parameters:
- process_id: u32 - Process ID to migrate
Returns: Result<()>
- Ok(()): Migration successful
- Err(anyhow::Error): Migration failed

Risk Management

update_risk_score(&self, process_id: u32, score_change: i32)
Location: src-tauri/src/engines/sandbox.rs:328
Usage: Updates process risk score and evaluates verdict
Parameters:
- process_id: u32 - Process ID
- score_change: i32 - Score change to apply
Returns: Result<(i32, String)>
- Ok((i32, String)): New score and verdict ("SAFE", "GREEN_ZONE", "YELLOW_ZONE", "RED_ZONE")
- Err(anyhow::Error): Update failed

Health Monitoring

monitor_sandbox_health(&self)
Location: src-tauri/src/engines/sandbox.rs:360
Usage: Monitors sandbox health and updates process status
Parameters: None
Returns: Result<()>
- Ok(()): Health check completed
- Err(anyhow::Error): Health check failed

recover_suspended_processes(&self)
Location: src-tauri/src/engines/sandbox.rs:414
Usage: Recovers processes that were suspended during migration
Parameters: None
Returns: Result<()>
- Ok(()): Recovery completed
- Err(anyhow::Error): Recovery failed

cleanup_inactive_sandboxes(&self)
Location: src-tauri/src/engines/sandbox.rs:456
Usage: Removes inactive sandboxes to free resources
Parameters: None
Returns: Result<()>
- Ok(()): Cleanup completed
- Err(anyhow::Error): Cleanup failed

---

RCE Detector Engine

Core Detection

new()
Location: src-tauri/src/engines/rce_detector.rs:46
Usage: Creates a new RCE detector instance
Parameters: None
Returns: RceDetector
Description: Initializes detector with default trusted browsers, document readers, and system shells.

with_database(db: Arc<Database>)
Location: src-tauri/src/engines/rce_detector.rs:80
Usage: Creates RCE detector with database integration
Parameters:
- db: Arc<Database> - Database connection
Returns: RceDetector

with_sentinel(self, sentinel: Arc<ProcessSentinel>)
Location: src-tauri/src/engines/rce_detector.rs:88
Usage: Adds process sentinel to detector
Parameters:
- sentinel: Arc<ProcessSentinel> - Process sentinel instance
Returns: RceDetector

Monitoring and Detection

start_monitoring(&self, app_handle: AppHandle)
Location: src-tauri/src/engines/rce_detector.rs:146
Usage: Starts continuous process monitoring for RCE detection
Parameters:
- app_handle: AppHandle - Tauri application handle
Returns: Result<(), Box<dyn std::error::Error + Send + Sync>>
- Ok(()): Monitoring started successfully
- Err(Box<dyn Error>): Failed to start monitoring

check_rce_exploit(&self, process_info: &ProcessInfo, sys: &System)
Location: src-tauri/src/engines/rce_detector.rs:304
Usage: Analyzes a process for RCE exploit patterns
Parameters:
- process_info: &ProcessInfo - Process information
- sys: &System - System information
Returns: Option<RceAlert>
- Some(RceAlert): RCE exploit detected
- None: No exploit detected

Helper Functions

is_legitimate_launcher(&self, parent_name: &str)
Location: src-tauri/src/engines/rce_detector.rs:94
Usage: Checks if parent process is a legitimate system launcher
Parameters:
- parent_name: &str - Parent process name
Returns: bool
- true: Process is legitimate launcher
- false: Process is suspicious

is_process_whitelisted(&self, process_name: &str)
Location: src-tauri/src/engines/rce_detector.rs:105
Usage: Checks if process is in whitelist
Parameters:
- process_name: &str - Process name to check
Returns: bool
- true: Process is whitelisted
- false: Process is not whitelisted

Public API

start_rce_detection_with_db(app_handle: tauri::AppHandle, db: Arc<Database>)
Location: src-tauri/src/engines/rce_detector.rs:419
Usage: Public function to start RCE detection with database
Parameters:
- app_handle: tauri::AppHandle - Tauri application handle
- db: Arc<Database> - Database connection
Returns: Result<(), Box<dyn std::error::Error + Send + Sync>>
- Ok(()): Detection started successfully
- Err(Box<dyn Error>): Failed to start detection

Process Sentinel

Note: Process Sentinel functions are located in src-tauri/src/engines/sentinel.rs and provide orchestration for sandbox migration and process lifecycle management.

TypeScript Frontend Functions

Dashboard Component

Core State Management

loadLogs()
Location: src/components/Dashboard.tsx (internal function)
Usage: Loads security logs from backend
Parameters: None
Returns: Promise<void>
Description: Calls invoke('get_logs') and updates component state.

loadHealth()
Location: src/components/Dashboard.tsx (internal function)
Usage: Loads system health metrics
Parameters: None
Returns: Promise<void>
Description: Calls invoke('get_system_health') and updates component state.

loadWhitelist()
Location: src/components/Dashboard.tsx (internal function)
Usage: Loads whitelist from backend
Parameters: None
Returns: Promise<void>
Description: Calls invoke('get_whitelist') and updates component state.

Event Handlers

handleAddToWhitelist()
Location: src/components/Dashboard.tsx (internal function)
Usage: Adds process to whitelist
Parameters: None (uses newProcess state)
Returns: Promise<void>
Description: Calls invoke('add_to_whitelist') with process name.

handleRemoveFromWhitelist(id: number, process_name: string)
Location: src/components/Dashboard.tsx (internal function)
Usage: Removes process from whitelist
Parameters:
- id: number - Database entry ID
- process_name: string - Process name
Returns: Promise<void>
Description: Calls invoke('remove_from_whitelist').

handleKillProcess(pid: number)
Location: src/components/Dashboard.tsx (internal function)
Usage: Kills a process by PID
Parameters:
- pid: number - Process ID to kill
Returns: Promise<void>
Description: Calls invoke('kill_process').

handleThreatDecision(shouldRemove: boolean)
Location: src/components/Dashboard.tsx (internal function)
Usage: Handles user decision on threat alerts
Parameters:
- shouldRemove: boolean - Whether to remove threat
Returns: Promise<void>
Description: Calls invoke('handle_threat_decision').

AI Integration

requestAiExplanation(log: EventLog)
Location: src/components/Dashboard.tsx (internal function)
Usage: Requests AI explanation for security event
Parameters:
- log: EventLog - Security log entry
Returns: Promise<void>
Description: Calls invoke('request_ai_explanation') and displays modal.

URL Risk Scoring

testURLScorer()
Location: src/components/Dashboard.tsx (internal function)
Usage: Tests URL risk scoring functionality
Parameters: None (uses urlInput state)
Returns: Promise<void>
Description: Uses URLRiskScorer class to analyze URL and display results.

Pet Overlay Component

Event Listeners

setupListener()
Location: src/components/PetOverlay.tsx:14
Usage: Sets up threat alert listener
Parameters: None
Returns: Promise<() => void> - Cleanup function
Description: Listens for "threat-alert" events and updates visual state.

State Management

useEffect()
Location: src/components/PetOverlay.tsx:8
Usage: Component lifecycle management
Parameters: None
Returns: void
Description: Sets up event listeners and cleanup on component mount/unmount.

---

Data Structures

Rust Structures

EventLog

pub struct EventLog {
    pub id: Option<i64>,
    pub threat_type: String,
    pub severity: String,
    pub target: String,
    pub timestamp: String,
    pub entropy: Option<f64>,
}

SystemHealth

pub struct SystemHealth {
    pub total_processes: usize,
    pub cpu_usage: f64,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
}

SandboxStatus

pub struct SandboxStatus {
    pub active_sandboxes: usize,
    pub sandboxed_processes: Vec<SandboxedProcessInfo>,
    pub total_processes: usize,
}

RceAlert

pub struct RceAlert {
    pub alert_type: String,
    pub parent_process: String,
    pub parent_pid: u32,
    pub child_process: String,
    pub child_pid: u32,
    pub timestamp: String,
    pub explanation: String,
    pub action_taken: String,
    pub severity: String,
}

TypeScript Interfaces

EventLog

interface EventLog {
  id?: number;
  threat_type: string;
  severity: string;
  target: string;
  timestamp: string;
  entropy?: number;
}

SystemHealth

interface SystemHealth {
  total_processes: number;
  cpu_usage: number;
  memory_used_gb: number;
  memory_total_gb: number;
}

AiExplanation

interface AiExplanation {
  original_log: string;
  explanation: string;
  recommendations: string[];
}

Error Handling

All functions return appropriate error types:
- Rust: Result<T, String> for Tauri commands, Result<T, anyhow::Error> for internal functions
- TypeScript: Promise rejections with error messages

Common error scenarios:
- Process not found
- Database connection failures
- Network API failures (AI explanations)
- File system permission errors
- Sandbox creation failures

Usage Examples

Rust Backend Example

// Kill a process
match invoke("kill_process", pid) {
    Ok(msg) => println!("Success: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}

// Get system health
let health: SystemHealth = invoke("get_system_health")?;
println!("CPU Usage: {}%", health.cpu_usage);

TypeScript Frontend Example

// Add process to whitelist
const addToWhitelist = async (processName: string) => {
  try {
    const result = await invoke('add_to_whitelist', { processName });
    console.log(result);
    await loadWhitelist(); // Refresh whitelist
  } catch (error) {
    console.error('Failed to add to whitelist:', error);
  }
};

// Handle threat decision
const handleThreat = async (alertId: string, shouldRemove: boolean, pid?: number) => {
  try {
    const result = await invoke('handle_threat_decision', {
      alertId,
      shouldRemove,
      pid
    });
    console.log(result);
  } catch (error) {
    console.error('Failed to handle threat:', error);
  }
};

Security Considerations

1. Process Isolation: All sandbox operations use proper process suspension/resumption
2. Input Validation: All user inputs are validated before processing
3. Error Information: Error messages don't expose sensitive system information
4. Resource Management: Proper cleanup of sandbox resources and processes
5. Database Security: SQL injection protection through parameterized queries

Performance Notes

- Monitoring Frequency: Process monitoring runs every 2 seconds
- Health Updates: System health updates every 5 seconds
- Memory Management: Regular cleanup of inactive sandboxes
- Async Operations: All I/O operations are non-blocking
- Resource Limits: Sandboxes have configurable memory and CPU limits

This documentation is automatically generated and should be kept in sync with code changes.
