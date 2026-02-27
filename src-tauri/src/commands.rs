use crate::db::{Database, EventLog, WhitelistEntry};
use crate::whitelist::{WhitelistManager, FileStatus};
use crate::engines::sentinel::ProcessSentinel;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sysinfo::{Pid, System};
use tauri::State;

#[derive(Debug, Serialize, Deserialize)]
pub struct AiExplanation {
    pub original_log: String,
    pub explanation: String,
    pub recommendations: Vec<String>,
}

#[tauri::command]
pub async fn kill_process(pid: u32) -> Result<String, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let pid = Pid::from_u32(pid);
    
    if let Some(process) = sys.process(pid) {
        if process.kill() {
            Ok(format!("Process {} terminated successfully", pid))
        } else {
            Err("Failed to terminate process".to_string())
        }
    } else {
        Err("Process not found".to_string())
    }
}

#[tauri::command]
pub async fn get_logs(db: State<'_, Arc<Database>>, limit: usize) -> Result<Vec<EventLog>, String> {
    db.get_recent_logs(limit)
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn add_to_whitelist(
    db: State<'_, Arc<Database>>,
    process_name: String,
) -> Result<String, String> {
    println!("=== add_to_whitelist called with: {} ===", process_name);
    
    // Add to database first
    db.add_to_whitelist(&process_name)
        .map_err(|e| format!("Database error: {}", e))?;
    
    // Also add to trusted_app.json - use absolute path
    let config_path = "trusted_app.json";
    
    // Try to calculate hash - if process_name is a file path, use it directly
    // otherwise, try common paths for executables
    let hash = if std::path::Path::new(&process_name).exists() {
        match crate::whitelist::WhitelistManager::calculate_file_hash(&process_name) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!("Warning: Could not calculate hash for {}: {}", process_name, e);
                format!("PLACEHOLDER_{}", process_name.to_uppercase().replace(|c: char| !c.is_alphanumeric(), "_"))
            }
        }
    } else {
        // Try common executable paths
        let common_paths = vec![
            format!("C:\\Windows\\System32\\{}.exe", process_name),
            format!("C:\\Windows\\{}.exe", process_name),
            format!("C:\\Program Files\\{}\\{}.exe", process_name, process_name),
            format!("C:\\Program Files (x86)\\{}\\{}.exe", process_name, process_name),
        ];
        
        let mut last_error = None;
        for path in common_paths {
            if std::path::Path::new(&path).exists() {
                match crate::whitelist::WhitelistManager::calculate_file_hash(&path) {
                    Ok(hash) => {
                        // Found real hash, use it
                        let mut whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
                            .map_err(|e| format!("Failed to load whitelist: {}", e))?;
                        
                        let trusted_app = crate::whitelist::TrustedApp {
                            name: process_name.clone(),
                            hash,
                            path: Some(path),
                            description: Some(format!("User-added trusted application: {}", process_name)),
                            app_type: crate::whitelist::AppType::Application,
                        };
                        
                        whitelist_manager.add_trusted_app(trusted_app)
                            .map_err(|e| format!("Failed to add trusted app: {}", e))?;
                        
                        whitelist_manager.save_config(config_path)
                            .map_err(|e| format!("Failed to save whitelist: {}", e))?;
                        
                        return Ok(format!("Added {} to whitelist and trusted apps", process_name));
                    }
                    Err(e) => last_error = Some(e),
                }
            }
        }
        
        // If no file found, use placeholder hash
        if let Some(e) = last_error {
            eprintln!("Warning: Could not find executable for {}: {}", process_name, e);
        }
        format!("PLACEHOLDER_{}", process_name.to_uppercase().replace(|c: char| !c.is_alphanumeric(), "_"))
    };
    
    // Always add to trusted_app.json
    let mut whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    let trusted_app = crate::whitelist::TrustedApp {
            name: process_name.clone(),
            hash,
            path: Some(format!("{}.exe", process_name)),
            description: Some(format!("User-added trusted application: {}", process_name)),
            app_type: crate::whitelist::AppType::Application,
        };
    
    whitelist_manager.add_trusted_app(trusted_app)
        .map_err(|e| format!("Failed to add trusted app: {}", e))?;
    
    whitelist_manager.save_config(config_path)
        .map_err(|e| format!("Failed to save whitelist: {}", e))?;
    
    Ok(format!("Added {} to whitelist and trusted apps", process_name))
}

#[tauri::command]
pub async fn get_whitelist(db: State<'_, Arc<Database>>) -> Result<Vec<WhitelistEntry>, String> {
    println!("=== get_whitelist called ===");
    
    db.get_whitelist()
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn remove_from_whitelist(
    db: State<'_, Arc<Database>>,
    id: i64,
    process_name: Option<String>,
) -> Result<String, String> {
    println!("=== remove_from_whitelist called with id: {}, process_name: {:?} ===", id, process_name);
    
    // Remove from database
    db.remove_from_whitelist(id)
        .map_err(|e| format!("Database error: {}", e))?;
    
    // If process_name is provided, also try to remove from trusted apps
    if let Some(name) = process_name {
        let config_path = "trusted_app.json";
        let mut whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
            .map_err(|e| format!("Failed to load whitelist: {}", e))?;
        
        // Remove the trusted app by name
        let removed = whitelist_manager.remove_trusted_app_by_name(&name)
            .map_err(|e| format!("Failed to remove trusted app: {}", e))?;
        
        if removed {
            whitelist_manager.save_config(config_path)
                .map_err(|e| format!("Failed to save whitelist: {}", e))?;
            
            Ok(format!("Removed {} from whitelist and trusted apps", name))
        } else {
            Ok(format!("Removed {} from whitelist (not found in trusted apps)", name))
        }
    } else {
        Ok("Removed from whitelist".to_string())
    }
}

#[tauri::command]
pub async fn request_ai_explanation(
    log_text: String,
) -> Result<AiExplanation, String> {
    let api_key = std::env::var("API")
        .map_err(|_| "GEMINI_API_KEY not set in environment variables".to_string())?;
    //let api_key = "AIzaSyAXAdWWJ1UMmXOsZYscQpuZFlbGGhTF4IM";
    let client = reqwest::Client::new();
    
    let prompt = format!(
        "You are a cybersecurity expert explaining threats to non-technical users. \
        Analyze this security log and provide:\n\
        1. A simple explanation of what happened\n\
        2. Why it's dangerous\n\
        3. Three actionable recommendations\n\n\
        Log: {}\n\n\
        Respond in JSON format with fields: explanation (string), recommendations (array of strings)",
        log_text
    );
    
    #[derive(Serialize)]
    struct GeminiRequest {
        contents: Vec<Content>,
    }
    
    #[derive(Serialize)]
    struct Content {
        parts: Vec<Part>,
    }
    
    #[derive(Serialize)]
    struct Part {
        text: String,
    }
    
    #[derive(Deserialize)]
    struct GeminiResponse {
        candidates: Vec<Candidate>,
    }
    
    #[derive(Deserialize)]
    struct Candidate {
        content: ResponseContent,
    }
    
    #[derive(Deserialize)]
    struct ResponseContent {
        parts: Vec<ResponsePart>,
    }
    
    #[derive(Deserialize)]
    struct ResponsePart {
        text: String,
    }
    
    let request_body = GeminiRequest {
        contents: vec![Content {
            parts: vec![Part { text: prompt }],
        }],
    };
    
    let url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent";
    
    let response = client
        .post(url)
        .header("x-goog-api-key", api_key)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}. Check your internet connection and API key.", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error response".to_string());
        return Err(format!("API error {}: {}", status, error_text));
    }
    
    let gemini_response: GeminiResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    let ai_text = gemini_response
        .candidates
        .first()
        .and_then(|c| c.content.parts.first())
        .map(|p| p.text.clone())
        .ok_or("No response from AI")?;
    
    // Parse the AI response (simplified - in production, use proper JSON parsing)
    Ok(AiExplanation {
        original_log: log_text,
        explanation: ai_text.clone(),
        recommendations: vec![
            "Run a full antivirus scan immediately".to_string(),
            "Review your browser extensions and remove suspicious ones".to_string(),
            "Enable Windows Defender real-time protection".to_string(),
        ],
    })
}

#[tauri::command]
pub async fn get_system_health() -> Result<SystemHealth, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    Ok(SystemHealth {
        total_processes: sys.processes().len(),
        cpu_usage: sys.global_cpu_usage() as f64,
        memory_used_gb: sys.used_memory() as f64 / 1_073_741_824.0,
        memory_total_gb: sys.total_memory() as f64 / 1_073_741_824.0,
    })
}

#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub total_processes: usize,
    pub cpu_usage: f64,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
}

#[tauri::command]
pub async fn check_file_hash(file_path: String) -> Result<FileStatus, String> {
    let config_path = "src-tauri/trusted_app.json";
    let whitelist_manager = WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    whitelist_manager.check_file_status(&file_path)
        .map_err(|e| format!("Failed to check file: {}", e))
}

#[tauri::command]
pub async fn add_trusted_app(
    name: String,
    hash: String,
    path: Option<String>,
    description: Option<String>,
) -> Result<String, String> {
    use crate::whitelist::{TrustedApp, AppType};
    
    let config_path = "trusted_app.json";
    let mut whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    let trusted_app = TrustedApp {
        name,
        hash,
        path,
        description,
        app_type: AppType::Application,
    };
    
    whitelist_manager.add_trusted_app(trusted_app)
        .map_err(|e| format!("Failed to add trusted app: {}", e))?;
    
    whitelist_manager.save_config(config_path)
        .map_err(|e| format!("Failed to save whitelist: {}", e))?;
    
    Ok("Trusted app added successfully".to_string())
}

#[tauri::command]
pub async fn add_trusted_folder(folder_path: String) -> Result<String, String> {
    let config_path = "trusted_app.json";
    let mut whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    whitelist_manager.add_trusted_folder(folder_path.clone())
        .map_err(|e| format!("Failed to add trusted folder: {}", e))?;
    
    whitelist_manager.save_config(config_path)
        .map_err(|e| format!("Failed to save whitelist: {}", e))?;
    
    Ok(format!("Added {} to trusted folders", folder_path))
}

#[tauri::command]
pub async fn get_trusted_folders() -> Result<Vec<String>, String> {
    let config_path = "trusted_app.json";
    let whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    Ok(whitelist_manager.get_trusted_folders().to_vec())
}

#[tauri::command]
pub async fn remove_trusted_folder(folder_path: String) -> Result<String, String> {
    let config_path = "trusted_app.json";
    let mut whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    let removed = whitelist_manager.remove_trusted_folder(&folder_path);
    
    if removed {
        whitelist_manager.save_config(config_path)
            .map_err(|e| format!("Failed to save whitelist: {}", e))?;
        
        Ok(format!("Removed {} from trusted folders", folder_path))
    } else {
        Ok(format!("Folder {} not found in trusted folders", folder_path))
    }
}

#[tauri::command]
pub async fn get_trusted_apps() -> Result<Vec<crate::whitelist::TrustedApp>, String> {
    let config_path = "trusted_app.json";
    let whitelist_manager = crate::whitelist::WhitelistManager::new(config_path)
        .map_err(|e| format!("Failed to load whitelist: {}", e))?;
    
    Ok(whitelist_manager.get_trusted_apps().to_vec())
}

// Sandbox management commands

#[derive(Debug, Serialize)]
pub struct SandboxStatus {
    pub active_sandboxes: usize,
    pub sandboxed_processes: Vec<SandboxedProcessInfo>,
    pub total_processes: usize,
}

#[derive(Debug, Serialize)]
pub struct SandboxedProcessInfo {
    pub pid: u32,
    pub name: String,
    pub risk_score: i32,
    pub sandbox_id: Option<String>,
    pub is_trusted: bool,
}

#[tauri::command]
pub async fn migrate_process_to_sandbox(
    pid: u32,
    sentinel: State<'_, Arc<ProcessSentinel>>,
) -> Result<String, String> {
    // Get mutable reference to sentinel for migration
    let mut sentinel_mut = Arc::try_unwrap(Arc::clone(&sentinel))
        .map_err(|_| "Cannot get mutable reference to sentinel".to_string())?;
    
    match sentinel_mut.migrate_to_restricted_sandbox(pid) {
        Ok(()) => Ok(format!("Process {} migrated to sandbox successfully", pid)),
        Err(e) => Err(format!("Failed to migrate process: {}", e)),
    }
}

#[tauri::command]
pub async fn get_sandbox_status(
    sentinel: State<'_, Arc<ProcessSentinel>>,
) -> Result<SandboxStatus, String> {
    let sandbox_manager = sentinel.get_sandbox_manager();
    let processes = sandbox_manager.processes.lock().unwrap();
    
    let sandboxed_processes: Vec<SandboxedProcessInfo> = processes
        .values()
        .map(|p| SandboxedProcessInfo {
            pid: p.id,
            name: p.name.clone(),
            risk_score: p.risk_score,
            sandbox_id: p.sandbox_handle.as_ref().map(|s| s.id.clone()),
            is_trusted: p.is_trusted,
        })
        .collect();
    
    let sandboxes = sandbox_manager.sandboxes.lock().unwrap();
    
    Ok(SandboxStatus {
        active_sandboxes: sandboxes.len(),
        sandboxed_processes,
        total_processes: processes.len(),
    })
}

#[tauri::command]
pub async fn update_process_risk_score(
    pid: u32,
    score_change: i32,
    sentinel: State<'_, Arc<ProcessSentinel>>,
) -> Result<String, String> {
    let sandbox_manager = sentinel.get_sandbox_manager();
    
    match sandbox_manager.update_risk_score(pid, score_change) {
        Ok((new_score, verdict)) => {
            // Check if we need to evaluate verdict based on new score
            if verdict == "RED_ZONE" {
                // Migrate to maximum security sandbox
                let mut sentinel_mut = Arc::try_unwrap(Arc::clone(&sentinel))
                    .map_err(|_| "Cannot get mutable reference to sentinel".to_string())?;
                
                if let Err(e) = sentinel_mut.migrate_to_maximum_security_sandbox(pid) {
                    return Err(format!("Failed to migrate to max security: {}", e));
                }
            } else if verdict == "YELLOW_ZONE" {
                // Restrict network access
                let mut sentinel_mut = Arc::try_unwrap(Arc::clone(&sentinel))
                    .map_err(|_| "Cannot get mutable reference to sentinel".to_string())?;
                
                if let Err(e) = sentinel_mut.restrict_network_access(pid) {
                    return Err(format!("Failed to restrict network: {}", e));
                }
            }
            
            Ok(format!("Updated risk score for process {} to {} - Verdict: {}", pid, new_score, verdict))
        },
        Err(e) => Err(format!("Failed to update risk score: {}", e)),
    }
}

#[tauri::command]
pub async fn handle_threat_decision(
    alert_id: String,
    should_remove: bool,
    pid: Option<u32>,
    db: State<'_, Arc<Database>>,
) -> Result<String, String> {
    println!("=== handle_threat_decision called: alert_id={}, should_remove={}, pid={:?} ===", 
        alert_id, should_remove, pid);
    
    if should_remove {
        if let Some(process_pid) = pid {
            // Kill the malicious process
            let mut sys = System::new_all();
            sys.refresh_all();
            
            let pid_obj = Pid::from_u32(process_pid);
            if let Some(process) = sys.process(pid_obj) {
                if process.kill() {
                    // Log the removal action
                    let removal_log = EventLog {
                        id: None,
                        threat_type: "THREAT_REMOVED".to_string(),
                        severity: "INFO".to_string(),
                        target: format!("Process {} (PID: {}) terminated by user decision", alert_id, process_pid),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        entropy: None,
                    };
                    
                    if let Err(e) = db.log_event(&removal_log) {
                        eprintln!("Failed to log threat removal: {}", e);
                    }
                    
                    Ok(format!("Threat removed: Process {} terminated successfully", process_pid))
                } else {
                    Err("Failed to terminate malicious process".to_string())
                }
            } else {
                Err("Process not found - may have already terminated".to_string())
            }
        } else {
            Err("No process ID provided for threat removal".to_string())
        }
    } else {
        // User chose to keep the process - log this decision
        let keep_log = EventLog {
            id: None,
            threat_type: "THREAT_IGNORED".to_string(),
            severity: "WARNING".to_string(),
            target: format!("User chose to ignore threat: {}", alert_id),
            timestamp: chrono::Utc::now().to_rfc3339(),
            entropy: None,
        };
        
        if let Err(e) = db.log_event(&keep_log) {
            eprintln!("Failed to log threat ignored: {}", e);
        }
        
        Ok("Threat ignored by user choice".to_string())
    }
}
