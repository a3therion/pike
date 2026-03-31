use anyhow::Result;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

const TICKET_EXPIRY_SECS: u64 = 86400; // 24 hours

pub struct SessionManager {
    ticket_path: PathBuf,
}

impl SessionManager {
    pub fn new() -> Self {
        let ticket_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".pike")
            .join("session_ticket");
        Self { ticket_path }
    }

    pub fn with_path(ticket_path: PathBuf) -> Self {
        Self { ticket_path }
    }

    pub async fn load_ticket(&self) -> Option<Vec<u8>> {
        let data = fs::read(&self.ticket_path).await.ok()?;
        if data.len() < 8 {
            return None;
        }

        let timestamp_bytes: [u8; 8] = data[..8].try_into().ok()?;
        let timestamp = u64::from_be_bytes(timestamp_bytes);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        if now.saturating_sub(timestamp) > TICKET_EXPIRY_SECS {
            return None;
        }

        Some(data[8..].to_vec())
    }

    pub async fn save_ticket(&self, ticket: &[u8]) -> Result<()> {
        if let Some(parent) = self.ticket_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut data = now.to_be_bytes().to_vec();
        data.extend_from_slice(ticket);

        fs::write(&self.ticket_path, &data).await?;

        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            let perms = Permissions::from_mode(0o600);
            fs::set_permissions(&self.ticket_path, perms).await?;
        }

        Ok(())
    }

    pub async fn clear_ticket(&self) -> Result<()> {
        fs::remove_file(&self.ticket_path).await.ok();
        Ok(())
    }

    pub fn ticket_exists(&self) -> bool {
        self.ticket_path.exists()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_save_and_load_ticket() {
        let temp_dir = TempDir::new().unwrap();
        let ticket_path = temp_dir.path().join("session_ticket");
        let manager = SessionManager::with_path(ticket_path);

        let test_ticket = b"test_ticket_data";
        manager.save_ticket(test_ticket).await.unwrap();

        let loaded = manager.load_ticket().await;
        assert_eq!(loaded, Some(test_ticket.to_vec()));
    }

    #[tokio::test]
    async fn test_ticket_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let ticket_path = temp_dir.path().join("session_ticket");
        let manager = SessionManager::with_path(ticket_path);

        let test_ticket = b"expired_ticket";
        manager.save_ticket(test_ticket).await.unwrap();

        // Manually write an expired timestamp
        let expired_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (TICKET_EXPIRY_SECS + 1);

        let mut data = expired_time.to_be_bytes().to_vec();
        data.extend_from_slice(test_ticket);
        fs::write(&manager.ticket_path, &data).await.unwrap();

        let loaded = manager.load_ticket().await;
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn test_clear_ticket() {
        let temp_dir = TempDir::new().unwrap();
        let ticket_path = temp_dir.path().join("session_ticket");
        let manager = SessionManager::with_path(ticket_path);

        manager.save_ticket(b"test").await.unwrap();
        assert!(manager.ticket_exists());

        manager.clear_ticket().await.unwrap();
        assert!(!manager.ticket_exists());
    }

    #[test]
    fn test_ticket_exists() {
        let temp_dir = TempDir::new().unwrap();
        let ticket_path = temp_dir.path().join("nonexistent");
        let manager = SessionManager::with_path(ticket_path);

        assert!(!manager.ticket_exists());
    }
}
