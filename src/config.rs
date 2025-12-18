/// # Configuration Management
///
/// This module is responsible for defining, loading, and managing the application's
/// configuration. It includes data structures that map directly to the `config.yaml` file,
/// and logic for hot-reloading configurations without service interruption.
///
/// ## Key Components:
///
/// - **`AppConfig` and related structs**: These are `serde`-deserializable structures
///   that represent the hierarchy of the `config.yaml` file.
///
/// - **`ConfigHotReloadService`**: A background service that monitors `config.yaml` for changes
///   and applies them to the running application without downtime. It uses `ArcSwap` to
///   atomically update shared configuration data.
///
/// - **Caches and Registries (`UpstreamCache`, `CertificateCache`, `AuthScopeRegistry`, `JwtKeysCache`)**:
///   These components hold processed, ready-to-use data derived from the main configuration.
///   They are designed to be hot-reloaded and are managed by the `ConfigHotReloadService`.
///
/// ## Hot-Reloading and Idempotency
///
/// The hot-reloading mechanism is designed to be idempotent and minimally disruptive:
/// - **JWT Keys, Certificates, and Upstreams**: When the configuration changes, only the
///   items that have been added, modified, or removed are updated. Unchanged items are
///   left as-is.
/// - **Authentication Scopes**: The `AuthScopeRegistry` performs a differential update.
///   It adds new scopes and removes obsolete ones, but crucially, it does **not** touch
///   existing, unchanged scopes. This ensures that active user sessions within those
///   scopes are preserved across configuration reloads.
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use log::{info, warn};
use pingora::prelude::*;
use pingora::services::background::BackgroundService;
use pingora::tls::pkey::Private;
use serde::Deserialize;

use crate::actions;

pub const CONFIG_PATH: &str = "conf/config.yaml";

/// Certificate and its corresponding private key.
pub struct CertAndKey {
    pub cert: pingora::tls::x509::X509,
    pub key: pingora::tls::pkey::PKey<Private>,
}

/// All possible actions that can be performed when a rule matches.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ActionConfig {
    ReturnStaticText {
        content: String,
        status: u16,
    },
    Proxy {
        upstream: String,
    },
    Redirect {
        url: String,
    },
    SetUpstreamRequestHeader {
        name: String,
        value: String,
    },
    SetDownstreamRequestHeader {
        name: String,
        value: String,
    },
    RequireAuthentication {
        protected_backend_addr: String,
        oidc_login_redirect_url: String,
        oidc_client_id: String,
        oidc_callback_url: String,
        oidc_token_endpoint_url: String,
        auth_scope_name: String,
    },
}

/// Rule that matches a request and specifies an action to perform.
#[derive(Debug, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(rename = "match")]
    pub match_expr: String,
    pub action: ActionConfig,
}

/// Routing rules that are evaluated sequentially.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoutingChainConfig {
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<RuleConfig>,
}

/// Virtual host, which maps a hostname to a specific TLS certificate.
#[derive(Debug, Deserialize, Clone)]
pub struct VirtualHostConfig {
    pub hostname: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// PEM-encoded public and private keys for JWT signing.
#[derive(Debug, Deserialize, Clone)]
pub struct JwtSigningKeysConfig {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

/// Realm, which groups together a set of virtual hosts and routing rules.
#[derive(Debug, Deserialize, Clone)]
pub struct RealmConfig {
    pub name: String,
    #[serde(flatten)]
    pub jwt_signing_keys: JwtSigningKeysConfig, // Flatten the keys directly into the realm
    pub virtual_hosts: Vec<VirtualHostConfig>,
    pub routing_chains: Vec<RoutingChainConfig>,
}

/// Root of the application's configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub realms: Vec<RealmConfig>,
}

/// Application's cryptographic keys.
#[derive(Clone)]
pub struct JwtSigningKeys {
    pub public_key_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

/// Cache for JWT signing keys, keyed by realm name.
/// This allows for hot-reloading of keys on a per-realm basis.
pub struct JwtKeysCache {
    pub keys_by_realm: DashMap<String, Arc<JwtSigningKeys>>,
}

impl JwtKeysCache {
    /// Performs a differential update of JWT signing keys from the configuration.
    pub fn reload_from_config(app_config: &Arc<AppConfig>, current_cache: &Self) {
        let new_realms: HashSet<String> =
            app_config.realms.iter().map(|r| r.name.clone()).collect();

        // Update existing or add new keys
        for realm in &app_config.realms {
            let new_keys = JwtSigningKeys {
                public_key_pem: realm.jwt_signing_keys.public_key_pem.as_bytes().to_vec(),
                private_key_pem: realm.jwt_signing_keys.private_key_pem.as_bytes().to_vec(),
            };

            // Check if the key is new or has changed.
            let needs_update = match current_cache.keys_by_realm.get(&realm.name) {
                Some(existing_keys) => {
                    existing_keys.public_key_pem != new_keys.public_key_pem
                        || existing_keys.private_key_pem != new_keys.private_key_pem
                }
                None => true, // It's a new realm.
            };

            if needs_update {
                info!(
                    "[ConfigReload] Updating JWT keys for realm: '{}'",
                    realm.name
                );
                current_cache
                    .keys_by_realm
                    .insert(realm.name.clone(), Arc::new(new_keys));
            }
        }

        // Remove keys for realms that no longer exist
        current_cache.keys_by_realm.retain(|realm_name, _| {
            if !new_realms.contains(realm_name) {
                info!(
                    "[ConfigReload] Removing JWT keys for obsolete realm: '{}'",
                    realm_name
                );
                false
            } else {
                true
            }
        });
    }
}

pub fn load_app_config() -> Arc<AppConfig> {
    // In a real application, you might use command-line arguments or environment variables
    // to determine which configuration file to load.
    let config_str = fs::read_to_string(CONFIG_PATH)
        .unwrap_or_else(|e| panic!("Failed to read configuration from {}: {}", CONFIG_PATH, e));
    let config: AppConfig = serde_yaml::from_str(&config_str)
        .unwrap_or_else(|e| panic!("Failed to parse configuration from {}: {}", CONFIG_PATH, e));
    Arc::new(config)
}

/// A background service that periodically checks for configuration updates and applies them.
pub struct ConfigHotReloadService {
    keys_swapper: Arc<ArcSwap<JwtKeysCache>>,
    cert_swapper: Arc<ArcSwap<CertificateCache>>,
    upstream_swapper: Arc<ArcSwap<UpstreamCache>>,
    main_config_swapper: Arc<ArcSwap<AppConfig>>,
    auth_scope_registry_swapper: Arc<ArcSwap<AuthScopeRegistry>>,
    last_known_content: Mutex<String>,
}

impl ConfigHotReloadService {
    pub fn new(
        keys_swapper: Arc<ArcSwap<JwtKeysCache>>,
        cert_swapper: Arc<ArcSwap<CertificateCache>>,
        upstream_swapper: Arc<ArcSwap<UpstreamCache>>,
        main_config_swapper: Arc<ArcSwap<AppConfig>>,
        auth_scope_registry_swapper: Arc<ArcSwap<AuthScopeRegistry>>,
        initial_config_content: String,
    ) -> Self {
        ConfigHotReloadService {
            keys_swapper,
            cert_swapper,
            upstream_swapper,
            main_config_swapper,
            auth_scope_registry_swapper,
            last_known_content: Mutex::new(initial_config_content),
        }
    }
}

/// All loaded certificates, which can be reloaded atomically.
pub struct UpstreamCache {
    // A map from upstream address string to its HttpPeer object.
    pub peer_map: DashMap<String, Arc<HttpPeer>>,
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

/// Manages the set of active authentication scopes.
#[derive(Default)]
pub struct AuthScopeRegistry {
    // We only need this struct to exist for type consistency in ArcSwap.
    // The actual state is managed globally in `actions.rs`.
    // A `phantom` field could be used if we needed to associate a lifetime.
    _private: (),
}

impl AuthScopeRegistry {
    /// Performs a differential update of authentication scopes based on the new config.
    /// - New scopes in the config are added.
    /// - Scopes removed from the config are unregistered.
    /// - Existing, unchanged scopes are not touched, preserving their session stores.
    pub fn reload_from_config(config: &Arc<AppConfig>) {
        // 1. Collect all scope names from the new configuration into a HashSet.
        let new_auth_scopes: HashSet<String> = config
            .realms
            .iter()
            .flat_map(|realm| &realm.routing_chains)
            .flat_map(|chain| &chain.rules)
            .filter_map(|rule| {
                if let ActionConfig::RequireAuthentication {
                    auth_scope_name, ..
                } = &rule.action
                {
                    Some(auth_scope_name.clone())
                } else {
                    None
                }
            })
            .collect();

        // 2. Get the set of currently registered scopes.
        let stores = actions::get_auth_session_stores();
        let current_auth_scopes: HashSet<String> =
            stores.iter().map(|entry| entry.key().clone()).collect();

        // 3. Add new scopes.
        for scope_to_add in new_auth_scopes.difference(&current_auth_scopes) {
            info!(
                "[ConfigReload] Registering new authentication scope: '{}'",
                scope_to_add
            );
            actions::register_auth_scope(scope_to_add);
        }

        // 4. Remove obsolete scopes.
        for scope_to_remove in current_auth_scopes.difference(&new_auth_scopes) {
            info!(
                "[ConfigReload] Unregistering obsolete authentication scope: '{}'",
                scope_to_remove
            );
            actions::unregister_auth_scope(scope_to_remove);
        }
    }
}

impl UpstreamCache {
    /// Loads upstream peers from the provided application configuration.
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
    pub fn load_from_config(app_config: Arc<AppConfig>) -> Self {
        let peer_map = DashMap::new();
        let mut unique_addrs = HashSet::new();

        // Collect all unique upstream addresses from the configuration
        for realm in &app_config.realms {
            for chain in &realm.routing_chains {
                for rule in &chain.rules {
                    match &rule.action {
                        ActionConfig::Proxy { upstream } => {
                            unique_addrs.insert(upstream.clone());
                        }
                        ActionConfig::RequireAuthentication {
                            protected_backend_addr,
                            ..
                        } => {
                            unique_addrs.insert(protected_backend_addr.clone());
                        }
                        _ => {} // Other actions don't have upstreams
                    }
                }
            }
        }

        // Manually add the default upstream if not already present
        unique_addrs.insert("http://127.0.0.1:8081".to_string());

        // Log all unique upstream addresses that will be created.
        info!(
            "Found unique upstream addresses from config: {:?}",
            unique_addrs
        );

        // Create HttpPeer for each unique address
        for addr_with_scheme in unique_addrs {
            // HttpPeer::new expects "host:port", so we need to strip the scheme.
            let addr_no_scheme = addr_with_scheme
                .strip_prefix("http://")
                .unwrap_or(&addr_with_scheme);
            let is_tls = addr_with_scheme.starts_with("https://");

            info!("Creating upstream peer for: {}", addr_with_scheme);
            let peer = HttpPeer::new(addr_no_scheme, is_tls, "".to_string());
            peer_map.insert(addr_with_scheme, Arc::new(peer));
        }

        info!("Successfully created {} upstream peers.", peer_map.len());
        UpstreamCache { peer_map }
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
                let current_keys_cache = self.keys_swapper.load();
                JwtKeysCache::reload_from_config(&new_config_arc, &current_keys_cache);

                // Upstream Cache Reload
                let new_upstreams = UpstreamCache::load_from_config(new_config_arc.clone());
                self.upstream_swapper.store(Arc::new(new_upstreams));

                // Auth Scopes Reload
                AuthScopeRegistry::reload_from_config(&new_config_arc);
                // We swap the cache object itself, even if it's a unit struct, to maintain consistency.
                self.auth_scope_registry_swapper
                    .store(Arc::new(AuthScopeRegistry::default()));

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
