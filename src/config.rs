use arc_swap::ArcSwap;
use async_trait::async_trait;
use log::{info, warn};
use pingora::prelude::*;
use pingora::services::background::BackgroundService;
use pingora::tls::pkey::Private;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CONFIG_PATH: &str = "conf/config.yaml";

// Certificate and its corresponding private key.
pub struct CertAndKey {
    pub cert: pingora::tls::x509::X509,
    pub key: pingora::tls::pkey::PKey<Private>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub realms: Vec<RealmConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RealmConfig {
    pub name: String,
    #[serde(flatten)]
    pub jwt_signing_keys: JwtSigningKeysConfig, // Flatten the keys directly into the realm
    pub virtual_hosts: Vec<VirtualHostConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VirtualHostConfig {
    pub hostname: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtSigningKeysConfig {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

impl AppConfig {
    /// Loads application configuration from a YAML file.
    ///
    /// # Panics
    ///
    /// This function will panic if:
    /// - The file specified by `path` does not exist or cannot be read.
    /// - The file content is not valid YAML or does not match the `AppConfig` structure.
    pub fn load_from_yaml(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = fs::read_to_string(path)?;

        let config: AppConfig = serde_yaml::from_str(&config_str)?;
        Ok(config)
    }
}

/// Application's cryptographic keys.
///
/// A single instance of this struct is created at startup, wrapped in an `Arc`,
/// and shared across all threads. It contains the PEM-encoded key pair used for
/// signing and validating JWTs (e.g., `DEVICE_CONTEXT`).
pub struct JwtSigningKeys {
    pub public_key_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

impl JwtSigningKeys {
    /// Creates `JwtSigningKeys` from a given `RealmConfig`.
    pub fn from_realm_config(realm_config: &RealmConfig) -> Self {
        JwtSigningKeys {
            public_key_pem: realm_config
                .jwt_signing_keys
                .public_key_pem
                .as_bytes()
                .to_vec(),
            private_key_pem: realm_config
                .jwt_signing_keys
                .private_key_pem
                .as_bytes()
                .to_vec(),
        }
    }
}

pub fn load_app_config() -> Arc<AppConfig> {
    // In a real application, you might use command-line arguments or environment variables
    // to determine which configuration file to load.
    let config = AppConfig::load_from_yaml(CONFIG_PATH)
        .unwrap_or_else(|e| panic!("Failed to load configuration from {}: {}", CONFIG_PATH, e));
    Arc::new(config)
}

/// A background service that periodically checks for configuration updates and applies them.
///
pub struct ConfigHotReloadService {
    keys_swapper: Arc<ArcSwap<JwtSigningKeys>>,
    cert_swapper: Arc<ArcSwap<CertificateCache>>,
    last_known_content: Mutex<String>,
}

impl ConfigHotReloadService {
    pub fn new(
        keys_swapper: Arc<ArcSwap<JwtSigningKeys>>,
        cert_swapper: Arc<ArcSwap<CertificateCache>>,
        initial_config_content: String,
    ) -> Self {
        ConfigHotReloadService {
            keys_swapper,
            cert_swapper,
            last_known_content: Mutex::new(initial_config_content),
        }
    }
}

/// All loaded certificates, which can be reloaded atomically.
pub struct CertificateCache {
    // A map from SNI hostname to its certificate and key.
    pub cert_map: HashMap<String, Arc<CertAndKey>>,
}

impl CertificateCache {
    /// Loads certificates from the provided application configuration.
    ///
    /// This function iterates through all virtual hosts in all realms defined in the
    /// `AppConfig` and loads their corresponding PEM-encoded certificates and private keys.
    ///
    /// # Arguments
    ///
    /// * `app_config` - An `Arc<AppConfig>` containing the configuration from which to load certificates.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `CertificateCache` instance on success, or an `Error` if
    /// any certificate or key fails to load.
    pub fn load_from_config(app_config: Arc<AppConfig>) -> Result<Self> {
        let mut cert_map = HashMap::new();
        info!("Loading certificates from configuration...");

        for realm in &app_config.realms {
            for vhost in &realm.virtual_hosts {
                info!("Loading certificate for host: {}", &vhost.hostname);
                let cert = pingora::tls::x509::X509::from_pem(vhost.certificate_pem.as_bytes())
                    .map_err(|e| {
                        let mut err = Error::new(ErrorType::InternalError);
                        err.set_context(format!(
                            "Failed to load certificate for {}: {}",
                            vhost.hostname, e
                        ));
                        err
                    })?;
                let key = pingora::tls::pkey::PKey::<Private>::private_key_from_pem(
                    vhost.private_key_pem.as_bytes(),
                )
                .map_err(|e| {
                    let mut err = Error::new(ErrorType::InternalError);
                    err.set_context(format!(
                        "Failed to load private key for {}: {}",
                        vhost.hostname, e
                    ));
                    err
                })?;
                cert_map.insert(vhost.hostname.clone(), Arc::new(CertAndKey { cert, key }));
            }
        }
        info!("Successfully loaded {} certificates.", cert_map.len());
        Ok(CertificateCache { cert_map })
    }
}

#[async_trait]
impl BackgroundService for ConfigHotReloadService {
    async fn start(&self, _shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if let Ok(current_content) = fs::read_to_string(CONFIG_PATH) {
                // Lock the mutex to safely read the last known content.
                let last_content = self.last_known_content.lock().unwrap().clone();
                if current_content != last_content {
                    info!("Configuration file change detected. Attempting to reload...");
                    self.reload_config(&current_content);
                }
            }
        }
    }
}

impl ConfigHotReloadService {
    fn reload_config(&self, current_content: &str) {
        match serde_yaml::from_str::<AppConfig>(current_content) {
            Ok(new_config) => {
                let new_config_arc = Arc::new(new_config);
                // JWT Keys Reload
                let new_keys = JwtSigningKeys::from_realm_config(
                    new_config_arc
                        .realms
                        .get(0)
                        .expect("Config must have at least one realm"),
                );
                self.keys_swapper.store(Arc::new(new_keys));

                // --- Certificate Cache Differential Reload ---
                let mut updated_count = 0;
                let mut removed_count = 0;

                // 1. Clone the current certificate map to create a new, mutable version.
                let mut new_cert_map = self.cert_swapper.load().cert_map.clone();
                let old_cert_map = &self.cert_swapper.load().cert_map;

                // 2. Collect all hostnames from the new config for easy lookup.
                let new_hostnames: HashSet<_> = new_config_arc
                    .realms
                    .iter()
                    .flat_map(|r| r.virtual_hosts.iter().map(|v| v.hostname.clone()))
                    .collect();

                // 3. Iterate through new config to update or add certificates.
                for realm in &new_config_arc.realms {
                    for vhost in &realm.virtual_hosts {
                        let cert_pem = vhost.certificate_pem.as_bytes();
                        let key_pem = vhost.private_key_pem.as_bytes();

                        // Check if the certificate needs updating (either new or changed).
                        if !old_cert_map.get(&vhost.hostname).map_or(false, |old_cert| {
                            old_cert.cert.to_pem().unwrap() == cert_pem
                                && old_cert.key.private_key_to_pem_pkcs8().unwrap() == key_pem
                        }) {
                            info!("Updating certificate for host: {}", &vhost.hostname);
                            match (
                                pingora::tls::x509::X509::from_pem(cert_pem),
                                pingora::tls::pkey::PKey::private_key_from_pem(key_pem),
                            ) {
                                (Ok(cert), Ok(key)) => {
                                    let cert_and_key = Arc::new(CertAndKey { cert, key });
                                    new_cert_map.insert(vhost.hostname.clone(), cert_and_key);
                                    updated_count += 1;
                                }
                                (Err(e), _) => warn!(
                                    "Failed to parse new certificate for {}: {}. Skipping update.",
                                    vhost.hostname, e
                                ),
                                (_, Err(e)) => warn!(
                                    "Failed to parse new private key for {}: {}. Skipping update.",
                                    vhost.hostname, e
                                ),
                            }
                        }
                    }
                }

                // 4. Remove entries that are no longer in the new config.
                new_cert_map.retain(|hostname, _| {
                    if !new_hostnames.contains(hostname) {
                        info!("Removing certificate for obsolete host: {}", hostname);
                        removed_count += 1;
                        false
                    } else {
                        true
                    }
                });

                // 5. Atomically swap the old cache with the new one.
                self.cert_swapper.store(Arc::new(CertificateCache {
                    cert_map: new_cert_map,
                }));
                info!(
                    "Certificate reload complete. Updated: {}, Removed: {}.",
                    updated_count, removed_count
                );

                // Lock the mutex to safely update the last known content.
                let mut last_content = self.last_known_content.lock().unwrap();
                *last_content = current_content.to_string();

                info!("Successfully reloaded and applied new configuration.");
            }
            Err(e) => warn!(
                "Failed to parse reloaded configuration, continuing with the old version. Error: {}",
                e
            ),
        }
    }
}
