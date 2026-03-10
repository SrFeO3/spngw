use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use log::info;
use pingora::services::background::BackgroundService;

use crate::actions;

const CLEANUP_INTERVAL_SECONDS: u64 = 60;

/// A background service that periodically cleans up expired application sessions.
pub struct SessionCleanupService {
    cleanup_interval: Duration,
}

impl SessionCleanupService {
    pub fn new() -> Self {
        SessionCleanupService {
            cleanup_interval: Duration::from_secs(CLEANUP_INTERVAL_SECONDS),
        }
    }
}

#[async_trait]
impl BackgroundService for SessionCleanupService {
    async fn start(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        info!(
            "Session Cleanup Service started. Checking for expired sessions every {} seconds.",
            self.cleanup_interval.as_secs()
        );
        let mut interval = tokio::time::interval(self.cleanup_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.cleanup_sessions().await;
                }
                _ = shutdown.changed() => {
                    info!("[SessionCleanup] Shutdown signal received, terminating session cleanup service.");
                    break;
                }
            }
        }
    }
}

impl SessionCleanupService {
    async fn cleanup_sessions(&self) {
        info!("[SessionCleanup] Starting expired session cleanup task.");
        let now = Utc::now().timestamp() as u64;
        let mut total_removed_count = 0;

        let all_stores = actions::get_all_auth_session_stores();

        for store_entry in all_stores.iter() {
            let realm_scope_key = store_entry.key();
            let session_store = store_entry.value();
            let mut removed_count_in_scope = 0;

            // `retain` is the most efficient way to remove multiple items from a DashMap.
            session_store.retain(|_session_id, app_session| {
                if app_session.expires_at < now {
                    removed_count_in_scope += 1;
                    false // Remove the session
                } else {
                    true // Keep the session
                }
            });

            if removed_count_in_scope > 0 {
                info!("[SessionCleanup] Removed {} expired sessions from scope '{}'.", removed_count_in_scope, realm_scope_key);
                total_removed_count += removed_count_in_scope;
            }
        }

        if total_removed_count > 0 {
            info!("[SessionCleanup] Finished cleanup task. Total expired sessions removed: {}.", total_removed_count);
        } else {
            info!("[SessionCleanup] Finished cleanup task. No expired sessions found.");
        }
    }
}
