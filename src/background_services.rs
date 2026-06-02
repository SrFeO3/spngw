use std::time::Duration;

use async_trait::async_trait;
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
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
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
        tokio::task::spawn_blocking(|| {
            // Also cleanup OIDC metadata cache (synchronous map operation)
            actions::cleanup_oidc_metadata_cache();
        })
        .await
        .unwrap_or(());

        info!("[SessionAndOidcCacheCleanup] Finished cleanup task.");
    }
}
