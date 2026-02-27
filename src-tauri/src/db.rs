use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: Option<i64>,
    pub process_name: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    pub id: Option<i64>,
    pub threat_type: String,
    pub severity: String,
    pub target: String,
    pub timestamp: String,
    pub entropy: Option<f64>,
}

#[derive(Debug)]
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY,
                process_name TEXT NOT NULL UNIQUE,
                added_at TEXT NOT NULL
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                entropy REAL
            )",
            [],
        )?;
        
        Ok(Database {
            conn: Mutex::new(conn),
        })
    }
    
    pub fn add_to_whitelist(&self, process_name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO whitelist (process_name, added_at) VALUES (?1, ?2)",
            [process_name, &chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
    
    pub fn get_whitelist(&self) -> Result<Vec<WhitelistEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, process_name, added_at FROM whitelist")?;
        
        let entries = stmt.query_map([], |row| {
            Ok(WhitelistEntry {
                id: Some(row.get(0)?),
                process_name: row.get(1)?,
                added_at: row.get(2)?,
            })
        })?;
        
        entries.collect()
    }
    
    pub fn remove_from_whitelist(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM whitelist WHERE id = ?1", [id])?;
        Ok(())
    }
    
    /// Log a security event to the database
    #[allow(dead_code)]
    pub fn log_event(&self, event: &EventLog) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO event_logs (threat_type, severity, target, timestamp, entropy) 
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &event.threat_type,
                &event.severity,
                &event.target,
                &event.timestamp,
                &event.entropy,
            ],
        )?;
        Ok(())
    }
    
    pub fn get_recent_logs(&self, limit: usize) -> Result<Vec<EventLog>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, threat_type, severity, target, timestamp, entropy 
             FROM event_logs ORDER BY id DESC LIMIT ?1"
        )?;
        
        let logs = stmt.query_map([limit], |row| {
            Ok(EventLog {
                id: Some(row.get(0)?),
                threat_type: row.get(1)?,
                severity: row.get(2)?,
                target: row.get(3)?,
                timestamp: row.get(4)?,
                entropy: row.get(5)?,
            })
        })?;
        
        logs.collect()
    }
}
