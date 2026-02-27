use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use sysinfo::System;
use tauri::{AppHandle, Emitter};
use tauri::Manager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub threat_type: String,
    pub severity: String,
    pub target: String,
    pub timestamp: String,
    pub entropy: Option<f64>,
    pub explanation: String,
}

/// Calculate Shannon Entropy for malware detection
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Monitor file system for suspicious activity
pub async fn start_file_watcher(app_handle: AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = channel();
    
    let mut watcher: RecommendedWatcher = Watcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default(),
    )?;
    
    // Watch the Ghost_Secrets directory
    let watch_path = PathBuf::from("C:\\Ghost_Secrets");
    if !watch_path.exists() {
        std::fs::create_dir_all(&watch_path)?;
    }
    
    watcher.watch(&watch_path, RecursiveMode::Recursive)?;
    
    tokio::spawn(async move {
        loop {
            if let Ok(event) = rx.recv() {
                if let Some(path) = event.paths.first() {
                    // Read file and check entropy
                    if let Ok(data) = std::fs::read(path) {
                        let entropy = calculate_entropy(&data);
                        
                        // High entropy suggests encryption/packing
                        if entropy > 7.5 {
                            let alert = ThreatAlert {
                                threat_type: "High Entropy File".to_string(),
                                severity: "HIGH".to_string(),
                                target: path.display().to_string(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                entropy: Some(entropy),
                                explanation: format!(
                                    "Detected file with entropy {:.2}. May be encrypted or packed malware.",
                                    entropy
                                ),
                            };
                            
                            // Emit to all windows
                            let _ = app_handle.emit("threat-alert", &alert);

                            if let Some(win) = app_handle.get_webview_window("alert") {
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                            println!("Emitted threat-alert: {:?}", alert);
                        }
                    }
                }
            }
        }
    });
    
    // Keep watcher alive
    std::mem::forget(watcher);
    Ok(())
}

/// Monitor running processes for suspicious behavior with enhanced parent-child tracking
pub async fn start_process_monitor(app_handle: AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let mut known_processes: HashMap<u32, String> = HashMap::new();
        
        loop {
            sys.refresh_all();
            
            // Track new processes and their parents
            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string_lossy().to_lowercase();
                
                // Skip if already tracked
                if known_processes.contains_key(&pid_u32) {
                    continue;
                }
                
                // Enhanced whitelist for legitimate Windows processes
                let whitelist = [
                    "msfeedssync.exe", "svchost.exe", "explorer.exe", "system", 
                    "powershell.exe", "cmd.exe", "conhost.exe", "winlogon.exe",
                    "services.exe", "csrss.exe", "smss.exe", "wininit.exe",
                    "spoolsv.exe", "lsass.exe", "taskmgr.exe", "regedit.exe",
                    "runtimebroker.exe", "sihost.exe", "dwm.exe", "audiodg.exe",
                    "windefend.exe", "msmpeng.exe", "securityhealthsystray.exe",
                    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
                    "winword.exe", "excel.exe", "powerpnt.exe", "acrobat.exe",
                    "notepad.exe", "wordpad.exe", "dllhost.exe"
                ];
                
                if whitelist.iter().any(|&safe| name.contains(safe)) {
                    known_processes.insert(pid_u32, name);
                    continue;
                }
                
                // Enhanced suspicious process detection
                let suspicious_keywords = [
                    "mimikatz", "psexec", "netcat", "nc.exe", "meterpreter", 
                    "cobaltstrike", "beacon", "empire", "poshc2", "koadic",
                    "metasploit", "burp", "wireshark", "tcpdump", "nmap",
                    "hashcat", "john", "hydra", "sqlmap", "nikto", "dirb",
                    "gobuster", "wfuzz", "ffuf", "sublist3r", "amass",
                    "malware", "virus", "trojan", "backdoor", "rootkit", 
                    "keylog", "keylogger", "bot", "miner", "crypt",
                    "encrypt", "ransom", "lock", "decode", "inject",
                    "hack", "crack", "exploit", "payload", "dropper", "loader"
                ];
                
                let mut is_suspicious = false;
                let mut threat_type = "Suspicious Process";
                let mut severity = "MEDIUM";
                
                for keyword in &suspicious_keywords {
                    if name.contains(keyword) {
                        is_suspicious = true;
                        
                        // Categorize threat level based on keyword
                        match keyword {
                            &"mimikatz" | &"psexec" | &"meterpreter" | &"cobaltstrike" | &"beacon" => {
                                threat_type = "Credential Theft Tool";
                                severity = "CRITICAL";
                            },
                            &"malware" | &"virus" | &"trojan" | &"backdoor" | &"rootkit" => {
                                threat_type = "Malware Detected";
                                severity = "CRITICAL";
                            },
                            &"ransom" | &"crypt" | &"encrypt" | &"lock" => {
                                threat_type = "Ransomware Tool";
                                severity = "CRITICAL";
                            },
                            &"keylog" | &"keylogger" => {
                                threat_type = "Keylogger Detected";
                                severity = "HIGH";
                            },
                            &"bot" | &"miner" => {
                                threat_type = "Cryptocurrency Miner/Bot";
                                severity = "HIGH";
                            },
                            _ => {
                                threat_type = "Hacking Tool";
                                severity = "HIGH";
                            }
                        }
                        break;
                    }
                }
                
                // Check for suspicious process characteristics
                if !is_suspicious {
                    // Processes with random-looking names
                    if name.len() > 8 && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        let vowels = name.chars().filter(|&c| "aeiou".contains(c)).count();
                        let consonants = name.chars().filter(|&c| c.is_alphanumeric() && !"aeiou".contains(c)).count();
                        
                        // Low vowel ratio suggests random name
                        if vowels > 0 && (consonants as f64 / vowels as f64) > 3.0 {
                            is_suspicious = true;
                            threat_type = "Random Process Name";
                            severity = "MEDIUM";
                        }
                    }
                    
                    // Processes in temp directories
                    if let Some(parent) = process.parent() {
                        if let Some(parent_proc) = sys.process(parent) {
                            let parent_name = parent_proc.name().to_string_lossy().to_lowercase();
                            
                            // Suspicious parent-child relationships
                            if (whitelist.iter().any(|&safe| parent_name.contains(safe)) || 
                                parent_name.contains("explorer") || parent_name.contains("winword") || 
                                parent_name.contains("excel") || parent_name.contains("acrobat")) &&
                                (name.contains("powershell") || name.contains("cmd") || name.contains("wscript")) {
                                
                                is_suspicious = true;
                                threat_type = "Suspicious Parent-Child Relationship";
                                severity = "HIGH";
                            }
                        }
                    }
                }
                
                if is_suspicious {
                    let alert = ThreatAlert {
                        threat_type: threat_type.to_string(),
                        severity: severity.to_string(),
                        target: format!("{} (PID: {})", process.name().to_string_lossy(), pid),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        entropy: None,
                        explanation: format!(
                            "Detected {}: {}. This may indicate malicious activity.",
                            threat_type.to_lowercase(),
                            process.name().to_string_lossy()
                        ),
                    };
                    
                    let _ = app_handle.emit("threat-alert", &alert);
                    // Emit to all windows

                    if let Some(win) = app_handle.get_webview_window("alert") {
                        let _ = win.show();
                        
                        let _ = win.set_focus();
                    }   

                    if let Some(pet) = app_handle.get_webview_window("pet") {
                        let _ = pet.emit("pet-alarm", &serde_json::json!({
                        "severity": alert.severity
                    }));
}             

                    println!("Emitted threat-alert: {:?}", alert);
                }
                
                // Track the process
                known_processes.insert(pid_u32, name);
            }
            
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    
    Ok(())
}
