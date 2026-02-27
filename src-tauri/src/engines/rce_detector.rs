use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use sysinfo::{Pid, System};
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use chrono::Utc;
use dotenv::dotenv;
use crate::db::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub parent_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct RceDetector {
    db: Option<Arc<Database>>,
    #[allow(dead_code)]
    trusted_browsers: Vec<String>,
    #[allow(dead_code)]
    trusted_document_readers: Vec<String>,
    #[allow(dead_code)]
    system_shells: Vec<String>,
    known_processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    #[allow(dead_code)]
    sentinel: Option<Arc<crate::engines::sentinel::ProcessSentinel>>,
}

impl RceDetector {
    pub fn new() -> Self {
        dotenv().ok();
        
        Self {
            db: None,
            trusted_browsers: vec![
                "chrome".to_string(),
                "firefox".to_string(),
                "msedge".to_string(),
                "brave".to_string(),
                "opera".to_string(),
                "safari".to_string(),
            ],
            trusted_document_readers: vec![
                "winword".to_string(),
                "excel".to_string(),
                "powerpnt".to_string(),
                "acrobat".to_string(),
                "wordpad".to_string(),
                "notepad".to_string(),
            ],
            system_shells: vec![
                "powershell".to_string(),
                "cmd".to_string(),
                "wscript".to_string(),
                "cscript".to_string(),
                "bash".to_string(),
                "sh".to_string(),
            ],
            known_processes: Arc::new(Mutex::new(HashMap::new())),
            sentinel: None,
        }
    }

    pub fn with_database(db: Arc<Database>) -> Self {
        Self {
            db: Some(db),
            ..Self::new()
        }
    }
    
    #[allow(dead_code)]
    pub fn with_sentinel(mut self, sentinel: Arc<crate::engines::sentinel::ProcessSentinel>) -> Self {
        self.sentinel = Some(sentinel);
        self
    }
    
    // Helper method to check if parent process is a legitimate launcher
    fn is_legitimate_launcher(&self, parent_name: &str) -> bool {
        let legitimate_launchers = vec![
            "explorer", "winlogon", "services", "svchost", "csrss", "smss",
            "wininit", "spoolsv", "lsass", "taskmgr", "regedit", "conhost", 
            "wsmprovhost", "system", "registry"
        ];
        
        legitimate_launchers.iter().any(|launcher| parent_name.contains(launcher))
    }
    
    // Helper method to check if process is whitelisted
    fn is_process_whitelisted(&self, process_name: &str) -> bool {
        // Common legitimate processes that should never be flagged
        let whitelisted_processes = vec![
            "explorer", "winlogon", "services", "svchost", "csrss", "smss",
            "wininit", "spoolsv", "lsass", "taskmgr", "regedit", 
            "powershell", "cmd", "conhost", "wsmprovhost", "system",
            "chrome", "firefox", "msedge", "brave", "opera",
            "winword", "excel", "powerpnt", "acrobat", "wordpad", "notepad",
            "dllhost", "runtimebroker", "sihost", "securityhealthsystray",
            "msfeedssync", "runtimebroker", "audiodg", "dwm", "windefend"
        ];
        
        let process_lower = process_name.to_lowercase();
        
        // First check built-in whitelist - be more permissive for system processes
        if whitelisted_processes.iter().any(|whitelisted| process_lower.contains(whitelisted)) {
            return true;
        }
        
        // Additional check for Windows system executables
        if process_lower.ends_with(".exe") {
            let base_name = process_lower.replace(".exe", "");
            if whitelisted_processes.iter().any(|whitelisted| base_name.contains(whitelisted)) {
                return true;
            }
        }
        
        // Check database whitelist if available
        if let Some(db) = &self.db {
            if let Ok(whitelist) = db.get_whitelist() {
                for entry in whitelist {
                    if process_lower.contains(&entry.process_name.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    async fn start_monitoring(&self, app_handle: AppHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!(" RCE Detector starting monitoring...");
        let app_handle = Arc::new(app_handle);
        let detector = self.clone();
        let known_processes = Arc::clone(&self.known_processes);

        tokio::spawn(async move {
            let mut sys = System::new_all();
            let mut last_check = std::time::Instant::now();
            
            // Initialize with all existing processes
            sys.refresh_all();
            {
                let mut known = known_processes.lock().await;
                for (pid, process) in sys.processes() {
                    let pid_u32 = pid.as_u32();
                    let process_info = ProcessInfo {
                        name: process.name().to_string_lossy().to_string(),
                        pid: pid_u32,
                        parent_pid: process.parent().map(|p| p.as_u32()),
                    };
                    known.insert(pid_u32, process_info);
                }
                println!(" Initialized with {} existing processes", sys.processes().len());
            }
            
            loop {
                sys.refresh_all();
                
                // Check for new processes every 2 seconds
                if last_check.elapsed().as_secs() >= 2 {
                    // First collect new processes
                    let mut new_processes = Vec::new();
                    {
                        let known = known_processes.lock().await;
                        
                        for (pid, process) in sys.processes() {
                            let pid_u32 = pid.as_u32();
                            
                            // Check if this is a new process
                            if !known.contains_key(&pid_u32) {
                                let process_info = ProcessInfo {
                                    name: process.name().to_string_lossy().to_string(),
                                    pid: pid_u32,
                                    parent_pid: process.parent().map(|p| p.as_u32()),
                                };
                                
                                // Log the parent-child relationship
                                if let Some(parent_pid) = process_info.parent_pid {
                                    let parent_name = match sys.process(Pid::from_u32(parent_pid)) {
                                        Some(p) => p.name().to_string_lossy().to_string(),
                                        None => "unknown".to_string(),
                                    };
                                    println!(" Parent-Child: {} ({}) → {} ({})", 
                                        parent_name, parent_pid, process_info.name, process_info.pid);
                                }
                                
                                new_processes.push(process_info);
                            }
                        }
                    }
                    
                    // Now process the new processes
                    for process_info in new_processes {
                        // Add to known processes
                        {
                            let mut known = known_processes.lock().await;
                            known.insert(process_info.pid, process_info.clone());
                        }
                        
                        // Check for RCE exploit
                        match detector.check_rce_exploit(&process_info, &sys).await {
                            Some(alert) => {
                                println!(" RCE Alert emitted: {:?}", alert);
            
                                let app_handle = Arc::clone(&app_handle);
            
                                // Log the threat
                                if let Err(e) = app_handle.emit("rce-alert", &alert) {
                                    eprintln!("Failed to emit rce-alert: {}", e);
                                }
                                println!(" RCE Alert emitted: {:?}", alert);
                                
                                // Also emit as general threat alert for frontend
                                if let Err(e) = app_handle.emit("threat-alert", &serde_json::json!({
                                    "id": None::<Option<i64>>,
                                    "threat_type": alert.alert_type,
                                    "severity": alert.severity,
                                    "target": format!("{} (PID: {}) -> {} (PID: {})", 
                                        alert.parent_process, alert.parent_pid, 
                                        alert.child_process, alert.child_pid),
                                    "timestamp": alert.timestamp,
                                    "entropy": None::<Option<f64>>,
                                    "additional_info": serde_json::json!({
                                        "parent_process_name": alert.parent_process,
                                        "child_process_name": alert.child_process,
                                    }),
                                })) {
                                    eprintln!("Failed to emit threat-alert: {}", e);
                                }
                                println!(" Threat alert sent to frontend");
                                
                                // Emit threat confirmation request for user decision
                                if let Err(e) = app_handle.emit("threat-confirmation-request", &serde_json::json!({
                                    "alert_id": format!("{}-{}", alert.alert_type, alert.child_pid),
                                    "alert_type": alert.alert_type,
                                    "parent_process": alert.parent_process,
                                    "parent_pid": alert.parent_pid,
                                    "child_process": alert.child_process,
                                    "child_pid": alert.child_pid,
                                    "timestamp": alert.timestamp,
                                    "explanation": alert.explanation,
                                    "severity": alert.severity,
                                    "action_required": "USER_DECISION",
                                    "message": format!("Threat detected: {} ({}) spawned by {} ({}). Do you want to remove this threat?", 
                                        alert.child_process, alert.child_pid, alert.parent_process, alert.parent_pid)
                                })) {
                                    eprintln!("Failed to emit threat-confirmation-request: {}", e);
                                }
                                println!(" Threat confirmation request sent to user");
                                
                                // Also emit as general threat alert for frontend display
                                if let Err(e) = app_handle.emit("threat-alert", &serde_json::json!({
                                    "id": None::<Option<i64>>,
                                    "threat_type": alert.alert_type,
                                    "severity": alert.severity,
                                    "target": format!("{} (PID: {}) -> {} (PID: {})", 
                                        alert.parent_process, alert.parent_pid, 
                                        alert.child_process, alert.child_pid),
                                    "timestamp": alert.timestamp,
                                    "entropy": None::<Option<f64>>,
                                    "additional_info": serde_json::json!({
                                        "parent_process_name": alert.parent_process,
                                        "child_process_name": alert.child_process,
                                        "requires_user_action": true,
                                        "alert_id": format!("{}-{}", alert.alert_type, alert.child_pid)
                                    }),
                                })) {
                                    eprintln!("Failed to emit threat-alert: {}", e);
                                }
                                println!(" Threat alert sent to frontend");
                            }
                            None => {
                                // No threat detected, continue monitoring
                            }
                        }
                    }
                    
                    last_check = std::time::Instant::now();
                }
                
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        });

        Ok(())
    }

    async fn check_rce_exploit(&self, process_info: &ProcessInfo, sys: &System) -> Option<RceAlert> {
        let child_name_lower = process_info.name.to_lowercase();
        
        println!(" DEBUG: Checking process: {} (PID: {})", process_info.name, process_info.pid);
        
        // 3. Detect suspicious process names (common malware patterns) - Check this AFTER whitelist!
        let suspicious_patterns = vec![
            "temp", "tmp", "cache", "download", "appdata", "malware", "virus",
            "trojan", "backdoor", "rootkit", "keylog", "bot", "miner",
            "crypt", "encrypt", "ransom", "lock", "decode", "inject",
            "hack", "crack", "exploit", "payload", "dropper", "loader",
        ];
        
        // Only check suspicious patterns if not whitelisted
        if !self.is_process_whitelisted(&process_info.name) {
            for pattern in suspicious_patterns {
                if child_name_lower.contains(pattern) {
                    println!(" DEBUG: Found suspicious pattern '{}' in process '{}'", pattern, process_info.name);
                    println!(" DEBUG: ALERT! Suspicious process detected: {}", process_info.name);
                    return Some(RceAlert {
                        alert_type: "SUSPICIOUS_PROCESS_NAME".to_string(),
                        parent_process: process_info.parent_pid.map(|p| format!("PID: {}", p)).unwrap_or_else(|| "Unknown".to_string()),
                        parent_pid: process_info.parent_pid.unwrap_or(0),
                        child_process: process_info.name.clone(),
                        child_pid: process_info.pid,
                        timestamp: Utc::now().to_rfc3339(),
                        explanation: format!(
                            "SUSPICIOUS PROCESS: {} (PID: {}) contains suspicious pattern '{}'",
                            process_info.name, process_info.pid, pattern
                        ),
                        action_taken: "Process flagged for manual review".to_string(),
                        severity: "MEDIUM".to_string(),
                    });
                }
            }
        }
        
        // 3. Detect shell-to-shell spawning (classic RCE pattern)
        // This catches when PowerShell/CMD spawns other shells - very suspicious
        // This check happens BEFORE whitelist to catch all shell-to-shell patterns
        if child_name_lower.contains("powershell") || child_name_lower.contains("cmd") {
            if let Some(parent_pid) = process_info.parent_pid {
                if let Some(parent_process) = sys.process(Pid::from_u32(parent_pid)) {
                    let parent_name = parent_process.name().to_string_lossy().to_lowercase();
                    
                    // Detect shell spawning another shell (highly suspicious RCE pattern)
                    if parent_name.contains("powershell") || parent_name.contains("cmd") {
                        println!(" DEBUG: Shell-to-shell spawning detected: {} ({}) -> {} ({})", 
                            parent_name, parent_pid, process_info.name, process_info.pid);
                        
                        return Some(RceAlert {
                            alert_type: "SHELL_SPAWN_SHELL".to_string(),
                            parent_process: parent_name.clone(),
                            parent_pid: parent_pid,
                            child_process: process_info.name.clone(),
                            child_pid: process_info.pid,
                            timestamp: Utc::now().to_rfc3339(),
                            explanation: format!(
                                "CRITICAL: Shell process {} (PID: {}) spawned another shell {} (PID: {}) - Classic RCE exploitation pattern",
                                parent_name.clone(), parent_pid, process_info.name, process_info.pid
                            ),
                            action_taken: "Process isolated for analysis - Potential RCE exploit".to_string(),
                            severity: "CRITICAL".to_string(),
                        });
                    }
                }
            }
        }
        
        // 4. Now check whitelist for other processes (but not for RCE which we already handled)
        // Only flag PowerShell/CMD if spawned by suspicious parent processes
        if child_name_lower.contains("powershell") || child_name_lower.contains("cmd") {
            // Check if parent is suspicious (not a legitimate system process)
            let is_suspicious_parent = if let Some(parent_pid) = process_info.parent_pid {
                if let Some(parent_process) = sys.process(Pid::from_u32(parent_pid)) {
                    let parent_name = parent_process.name().to_string_lossy().to_lowercase();
                    // Only flag if parent is not a legitimate launcher
                    !self.is_legitimate_launcher(&parent_name)
                } else {
                    false // Unknown parent, be cautious
                }
            } else {
                false // No parent, could be legitimate
            };
            
            if is_suspicious_parent {
                // Generate specific threat type based on process characteristics
                let (threat_type, severity, explanation) = if process_info.parent_pid.is_some() {
                    ("PROCESS_INJECTION", "HIGH", "PowerShell spawned by legitimate process - possible injection")
                } else {
                    ("SUSPICIOUS_ACTIVITY", "MEDIUM", "PowerShell process with no clear parent - suspicious activity")
                };
                
                return Some(RceAlert {
                    alert_type: threat_type.to_string(),
                    parent_process: process_info.parent_pid.map(|p| format!("PID: {}", p)).unwrap_or_else(|| "Unknown".to_string()),
                    parent_pid: process_info.parent_pid.unwrap_or(0),
                    child_process: process_info.name.clone(),
                    child_pid: process_info.pid,
                    timestamp: Utc::now().to_rfc3339(),
                    explanation: format!(
                        "{}: {} (PID: {}) - {}",
                        threat_type, process_info.name, process_info.pid, explanation
                    ),
                    action_taken: "Process isolated for analysis".to_string(),
                    severity: severity.to_string(),
                });
            }
        }
        
        None
    }
}

// Public function to start RCE detection with database
pub async fn start_rce_detection_with_db(app_handle: tauri::AppHandle, db: Arc<Database>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let detector = RceDetector::with_database(db);
    detector.start_monitoring(app_handle).await
}
