use std::time::Duration;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use chrono::Utc;
use log::info;
use pingora::services::background::BackgroundService;

use crate::actions;

const CLEANUP_INTERVAL_SECONDS: u64 = 60;

/// A background service that periodically cleans up expired application sessions and OIDC metadata cache.
pub struct SessionAndOidcCacheCleanupService {
    cleanup_interval: Duration,
}

impl SessionAndOidcCacheCleanupService {
    pub fn new() -> Self {
        SessionAndOidcCacheCleanupService {
            cleanup_interval: Duration::from_secs(CLEANUP_INTERVAL_SECONDS),
        }
    }
}

#[async_trait]
impl BackgroundService for SessionAndOidcCacheCleanupService {
    async fn start(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        info!(
            "Session and OIDC Cache Cleanup Service started. Checking for expired items every {} seconds.",
            self.cleanup_interval.as_secs()
        );
        let mut interval = tokio::time::interval(self.cleanup_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.cleanup_sessions_and_oidc_metadata().await;
                }
                _ = shutdown.changed() => {
                    info!("[SessionAndOidcCacheCleanup] Shutdown signal received, terminating service.");
                    break;
                }
            }
        }
    }
}

impl SessionAndOidcCacheCleanupService {
    async fn cleanup_sessions_and_oidc_metadata(&self) {
        info!("[SessionAndOidcCacheCleanup] Starting cleanup task.");

        // Offload heavy cleanup logic to a dedicated blocking thread.
        // This ensures the main async worker threads are not blocked by large map iterations.
        let total_removed_count = tokio::task::spawn_blocking(|| {
            let now = Utc::now().timestamp() as u64;
            let mut total_removed_count = 0;

            let all_stores = actions::get_all_auth_session_stores();

            for store_entry in all_stores.iter() {
                let realm_scope_key = store_entry.key();
                let session_store = store_entry.value();
                let mut removed_count_in_scope = 0;

                // Phase 1: Collect expired keys using read-only iteration.
                // This minimizes the duration of locks held on the map shards compared to `retain`.
                let expired_keys: Vec<String> = session_store
                    .iter()
                    .filter(|entry| entry.value().expires_at.load(Ordering::Relaxed) < now)
                    .map(|entry| entry.key().clone())
                    .collect();

                // Phase 2: Remove keys individually.
                // We use `remove_if` to atomically re-check the expiry condition under a write lock.
                // This prevents race conditions where a session might be refreshed between Phase 1 and 2.
                for key in expired_keys {
                    if session_store.remove_if(&key, |_, session| {
                        session.expires_at.load(Ordering::Relaxed) < now
                    }).is_some() {
                        removed_count_in_scope += 1;
                    }
                }

                if removed_count_in_scope > 0 {
                    info!("[SessionAndOidcCacheCleanup] Removed {} expired sessions from scope '{}'.", removed_count_in_scope, realm_scope_key);
                    total_removed_count += removed_count_in_scope;
                }
            }

            // Also cleanup OIDC metadata cache (synchronous map operation)
            actions::cleanup_oidc_metadata_cache();

            total_removed_count
        }).await.unwrap_or(0);

        if total_removed_count > 0 {
            info!("[SessionAndOidcCacheCleanup] Finished cleanup task. Total expired sessions removed: {}.", total_removed_count);
        } else {
            info!("[SessionAndOidcCacheCleanup] Finished cleanup task. No expired sessions found.");
        }
    }
}
