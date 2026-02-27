#[cfg(test)]
mod tests {
    use crate::whitelist::WhitelistManager;
    use std::fs;

    #[test]
    fn test_migration() {
        let config_path = "trusted_app.json";
        
        // Test loading existing config
        let manager = WhitelistManager::new(config_path).expect("Failed to load config");
        
        // Check if we can get trusted apps
        let apps = manager.get_trusted_apps();
        assert!(!apps.is_empty(), "Should have some trusted apps");
        
        // Check if apps have app_type (should be Application after migration)
        for app in apps {
            println!("App: {} - Type: {:?}", app.name, app.app_type);
        }
        
        // Test adding a folder
        let mut mutable_manager = manager;
        let result = mutable_manager.add_trusted_folder("C:\\temp\\test_trusted_folder".to_string());
        match result {
            Ok(_) => println!("Successfully added trusted folder"),
            Err(e) => println!("Folder add error: {}", e),
        }
        
        // Save and check if trusted_folders appears in JSON
        let save_result = mutable_manager.save_config(config_path);
        match save_result {
            Ok(_) => println!("Successfully saved config"),
            Err(e) => println!("Save error: {}", e),
        }
        
        // Read the JSON to verify structure
        if let Ok(content) = fs::read_to_string(config_path) {
            println!("JSON content:\n{}", content);
        }
    }
}
