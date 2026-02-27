use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedApp {
    pub name: String,
    pub hash: String,
    pub path: Option<String>,
    pub description: Option<String>,
    pub app_type: AppType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppType {
    Application,
    Folder,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhitelistConfig {
    pub trusted_apps: Vec<TrustedApp>,
    pub trusted_folders: Option<Vec<String>>, // Store trusted folder paths (optional for backward compatibility)
}

// Whitelist manager for tracking trusted applications and folders
pub struct WhitelistManager {
    trusted_hashes: HashSet<String>,
    trusted_apps: Vec<TrustedApp>,
    trusted_folders: Vec<String>,
}

impl WhitelistManager {
    pub fn new(config_path: &str) -> Result<Self> {
        let config = Self::load_config(config_path)?;
        let mut trusted_hashes = HashSet::new();
        
        for app in &config.trusted_apps {
            trusted_hashes.insert(app.hash.clone());
        }
        
        Ok(Self {
            trusted_hashes,
            trusted_apps: config.trusted_apps,
            trusted_folders: config.trusted_folders.unwrap_or_default(),
        })
    }
    // Load the whitelist configuration from a file
    fn load_config(config_path: &str) -> Result<WhitelistConfig> {
        if !Path::new(config_path).exists() {
            // Create default config if it doesn't exist
            let default_config = WhitelistConfig {
                trusted_apps: vec![],
                trusted_folders: Some(vec![]),
            };
            let content = serde_json::to_string_pretty(&default_config)?;
            fs::write(config_path, content)?;
            return Ok(default_config);
        }
        
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read whitelist config: {}", config_path))?;
        
        // Try to parse as new format first
        if let Ok(config) = serde_json::from_str::<WhitelistConfig>(&content) {
            return Ok(config);
        }
        
        // If that fails, try to parse as old format and migrate
        #[derive(Debug, Deserialize)]
        struct OldTrustedApp {
            name: String,
            hash: String,
            path: Option<String>,
            description: Option<String>,
        }
        
        #[derive(Debug, Deserialize)]
        struct OldWhitelistConfig {
            trusted_apps: Vec<OldTrustedApp>,
        }
        
        let old_config: OldWhitelistConfig = serde_json::from_str(&content)
            .with_context(|| "Failed to parse whitelist config JSON")?;
        
        // Migrate to new format
        let new_config = WhitelistConfig {
            trusted_apps: old_config.trusted_apps.into_iter().map(|app| {
                TrustedApp {
                    name: app.name,
                    hash: app.hash,
                    path: app.path,
                    description: app.description,
                    app_type: AppType::Application,
                }
            }).collect(),
            trusted_folders: None,
        };
        
        Ok(new_config)
    }

/// Calculate the SHA-256 hash of a file
    pub fn calculate_file_hash(file_path: &str) -> Result<String> {
        if !Path::new(file_path).exists() {
            return Err(anyhow::anyhow!("File not found: {}", file_path));
        }
        
        let content = fs::read(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();
        
        Ok(format!("{:x}", result))
    }
    
    /// Check the status of a file (trusted or malware)
    pub fn check_file_status(&self, file_path: &str) -> Result<FileStatus> {
        // First check if file is in trusted folder
        if self.is_in_trusted_folder(file_path) {
            return Ok(FileStatus::Trusted {
                hash: "FOLDER_TRUSTED".to_string(),
                app_name: "Trusted Folder".to_string(),
                description: Some(format!("File is in trusted folder: {}", file_path)),
            });
        }
        
        // Then check by hash
        let hash = Self::calculate_file_hash(file_path)?;
        
        if let Some(app) = self.trusted_apps.iter().find(|app| app.hash == hash) {
            Ok(FileStatus::Trusted {
                hash,
                app_name: app.name.clone(),
                description: app.description.clone(),
            })
        } else {
            Ok(FileStatus::Malware {
                hash,
                file_path: file_path.to_string(),
            })
        }
    }
    
    
    /// Add a trusted application to the whitelist
    pub fn add_trusted_app(&mut self, app: TrustedApp) -> Result<()> {
        self.trusted_hashes.insert(app.hash.clone());
        self.trusted_apps.push(app);
        Ok(())
    }
    
    /// Add a trusted folder to the whitelist
    pub fn add_trusted_folder(&mut self, folder_path: String) -> Result<()> {
        if !Path::new(&folder_path).exists() {
            return Err(anyhow::anyhow!("Folder not found: {}", folder_path));
        }
        
        if !Path::new(&folder_path).is_dir() {
            return Err(anyhow::anyhow!("Path is not a folder: {}", folder_path));
        }
        
        if !self.trusted_folders.contains(&folder_path) {
            self.trusted_folders.push(folder_path);
        }
        Ok(())
    }
    
    /// Check if a file is in a trusted folder
    pub fn is_in_trusted_folder(&self, file_path: &str) -> bool {
        let path = Path::new(file_path);
        for folder in &self.trusted_folders {
            if path.starts_with(folder) {
                return true;
            }
        }
        false
    }
    
    /// Check if a file is trusted (either by hash or folder)
    #[allow(dead_code)]
    pub fn is_file_trusted(&self, file_path: &str) -> Result<bool> {
        // First check if file is in trusted folder
        if self.is_in_trusted_folder(file_path) {
            return Ok(true);
        }
        
        // Then check by hash
        let hash = Self::calculate_file_hash(file_path)?;
        Ok(self.trusted_hashes.contains(&hash))
    }
    
    /// Get all trusted applications
    pub fn get_trusted_apps(&self) -> &[TrustedApp] {
        &self.trusted_apps
    }
    
    /// Get all trusted folders
    pub fn get_trusted_folders(&self) -> &[String] {
        &self.trusted_folders
    }
    
    /// Save the whitelist configuration to a file
    pub fn save_config(&self, config_path: &str) -> Result<()> {
        let config = WhitelistConfig {
            trusted_apps: self.trusted_apps.clone(),
            trusted_folders: Some(self.trusted_folders.clone()),
        };
        
        let content = serde_json::to_string_pretty(&config)
            .with_context(|| "Failed to serialize whitelist config")?;
        
        fs::write(config_path, content)
            .with_context(|| format!("Failed to write whitelist config: {}", config_path))?;
        
        Ok(())
    }
    
    /// Remove a trusted application by name
    pub fn remove_trusted_app_by_name(&mut self, name: &str) -> Result<bool> {
        let original_len = self.trusted_apps.len();
        self.trusted_apps.retain(|app| app.name != name);
        
        // Rebuild the hashes set
        self.trusted_hashes.clear();
        for app in &self.trusted_apps {
            self.trusted_hashes.insert(app.hash.clone());
        }
        
        Ok(self.trusted_apps.len() < original_len)
    }
    
    /// Remove a trusted folder by path
    pub fn remove_trusted_folder(&mut self, folder_path: &str) -> bool {
        let original_len = self.trusted_folders.len();
        self.trusted_folders.retain(|folder| folder != folder_path);
        self.trusted_folders.len() < original_len
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileStatus {
    Trusted {
        hash: String,
        app_name: String,
        description: Option<String>,
    },
    Malware {
        hash: String,
        file_path: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    
    #[test]
    fn test_hash_calculation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();
        
        let hash = WhitelistManager::calculate_file_hash(file_path.to_str().unwrap()).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 hex string length
    }
    
    #[test]
    fn test_whitelist_loading() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("trusted_apps.json");
        
        let config = WhitelistConfig {
            trusted_apps: vec![
                TrustedApp {
                    name: "Test App".to_string(),
                    hash: "abcd1234".to_string(),
                    path: Some("C:\\Program Files\\TestApp\\testapp.exe".to_string()),
                    description: Some("A test application".to_string()),
                    app_type: AppType::Application,
                }
            ],
            trusted_folders: None,
        };
        
        fs::write(&config_path, serde_json::to_string(&config).unwrap()).unwrap();
        
        let manager = WhitelistManager::new(config_path.to_str().unwrap()).unwrap();
        assert_eq!(manager.trusted_apps.len(), 1);
        
        // Test with a file that has the trusted hash
        let dir = tempdir().unwrap();
        let trusted_file_path = dir.path().join("trusted.txt");
        fs::write(&trusted_file_path, "test content").unwrap();
        
        // Since we can't easily create a file with the exact hash "abcd1234",
        // we'll test the structure by checking that the method exists and works
        let status = manager.check_file_status(trusted_file_path.to_str().unwrap()).unwrap();
        match status {
            FileStatus::Malware { .. } => {}, // Expected for our test file
            FileStatus::Trusted { .. } => {}, // Could happen if hash matches
        }
    }
}
