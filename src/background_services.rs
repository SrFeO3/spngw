use std::time::Duration;

use async_trait::async_trait;
use log::info;
use pingora::services::background::BackgroundService;

use crate::actions;

const CLEANUP_INTERVAL_SECONDS: u64 = 60;

/// A background service that periodically cleans up the OIDC metadata cache.
pub struct OidcMetadataCleanupService {
    cleanup_interval: Duration,
}

impl OidcMetadataCleanupService {
    pub fn new() -> Self {
        OidcMetadataCleanupService {
            cleanup_interval: Duration::from_secs(CLEANUP_INTERVAL_SECONDS),
        }
    }
}

#[async_trait]
impl BackgroundService for OidcMetadataCleanupService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        info!(
            "OIDC Metadata Cache Cleanup Service started. Checking for expired items every {} seconds.",
            self.cleanup_interval.as_secs()
        );
        let mut interval = tokio::time::interval(self.cleanup_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.cleanup_oidc_metadata().await;
                }
                _ = shutdown.changed() => {
                    info!("[OidcMetadataCleanup] Shutdown signal received, terminating service.");
                    break;
                }
            }
        }
    }
}

impl OidcMetadataCleanupService {
    async fn cleanup_oidc_metadata(&self) {
        info!("[OidcMetadataCleanup] Starting cleanup task.");

        // Offload heavy cleanup logic to a dedicated blocking thread.
        // This ensures the main async worker threads are not blocked by large map iterations.
        tokio::task::spawn_blocking(|| {
            actions::cleanup_oidc_metadata_cache();
        })
        .await
        .unwrap_or(());

        info!("[OidcMetadataCleanup] Finished cleanup task.");
    }
}
