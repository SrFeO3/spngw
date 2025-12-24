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
///
/// TODO:
/// - Consider default_upstream on UpstreamCache should be configurable instead of hardcoded.
use std::collections::HashSet;
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
    SetDownstreamResponseHeader {
        name: String,
        value: String,
    },
    RequireAuthentication {
        protected_upstream: String,
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
    pub _title: String,
    #[serde(default)]
    pub _description: String,
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
pub struct JwtKeyPairConfig {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

/// Realm, which groups together a set of virtual hosts and routing rules.
#[derive(Debug, Deserialize, Clone)]
pub struct RealmConfig {
    pub name: String,
    #[serde(flatten)]
    pub jwt_key_pair: JwtKeyPairConfig, // Flatten the keys directly into the realm
    pub virtual_hosts: Vec<VirtualHostConfig>,
    pub routing_chains: Vec<RoutingChainConfig>,
}

/// Root of the application's configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub realms: Vec<RealmConfig>,
}

// --- Runtime Data Structures ---

/// Certificate and its corresponding private key.
pub struct CertAndKey {
    pub cert: pingora::tls::x509::X509,
    pub key: pingora::tls::pkey::PKey<Private>,
}

/// All loaded certificates, which can be reloaded atomically.
pub struct CertificateCache {
    // A map from SNI hostname to its certificate and key.
    pub cert_map: DashMap<String, Arc<CertAndKey>>,
}

/// All loaded certificates, which can be reloaded atomically.
pub struct UpstreamCache {
    // A map from upstream address string to its HttpPeer object.
    pub peer_map: DashMap<String, Arc<HttpPeer>>,
}

/// Application's cryptographic keys.
#[derive(Clone)]
pub struct JwtKeyPair {
    pub public_key_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

/// Cache for JWT signing keys, keyed by realm name.
/// This allows for hot-reloading of keys on a per-realm basis.
pub struct JwtKeysCache {
    pub keys_by_realm: DashMap<String, Arc<JwtKeyPair>>,
}

/// Manages the set of active authentication scopes.
#[derive(Default)]
pub struct AuthScopeRegistry {
    // We only need this struct to exist for type consistency in ArcSwap.
    // The actual state is managed globally in `actions.rs`.
    // A `phantom` field could be used if we needed to associate a lifetime.
    _private: (),
}

impl JwtKeysCache {
    /// Performs a differential update of JWT key pairs from the configuration.
    ///
    /// This function is idempotent. It adds new keys, updates changed keys,
    /// and removes obsolete keys, without affecting unchanged ones.
    pub fn reload_from_config(app_config: &Arc<AppConfig>, current_cache: &Self) {
        let new_realms: HashSet<String> =
            app_config.realms.iter().map(|r| r.name.clone()).collect();

        // Update existing or add new keys
        for realm in &app_config.realms {
            let new_keys = JwtKeyPair {
                public_key_pem: realm.jwt_key_pair.public_key_pem.clone().into_bytes(),
                private_key_pem: realm.jwt_key_pair.private_key_pem.clone().into_bytes(),
            };

            // Check if the key is new or has changed.
            let needs_update = match current_cache.keys_by_realm.get(&realm.name) {
                // The realm exists. Check if the key material has changed.
                Some(existing_keys) => {
                    existing_keys.public_key_pem != new_keys.public_key_pem
                        || existing_keys.private_key_pem != new_keys.private_key_pem
                }
                // The realm is new and not in the cache, so it needs to be added.
                None => true,
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
impl CertificateCache {
    /// Performs a differential update of TLS certificates from the configuration.
    ///
    /// This function is idempotent and performs a differential update on the existing cache.
    /// It adds new certificates, updates changed ones, and removes obsolete ones.
    pub fn reload_from_config(app_config: &Arc<AppConfig>, current_cache: &Self) {
        // 1. Collect all hostnames from the new config for easy lookup.
        let new_hostnames: HashSet<_> = app_config
            .realms
            .iter()
            .flat_map(|r| r.virtual_hosts.iter().map(|v| v.hostname.clone()))
            .collect();

        // 2. Iterate through new config to update or add certificates.
        for realm in &app_config.realms {
            for vhost in &realm.virtual_hosts {
                let cert_pem = vhost.certificate_pem.as_bytes();
                let key_pem = vhost.private_key_pem.as_bytes();

                // Check if the certificate needs updating (either new or changed).
                let needs_update = match current_cache.cert_map.get(&vhost.hostname) {
                    // The host exists in the cache. Check if the underlying PEM content has changed.
                    Some(old_cert) => {
                        let old_cert_pem = old_cert.cert.to_pem().unwrap_or_default();
                        let old_key_pem =
                            old_cert.key.private_key_to_pem_pkcs8().unwrap_or_default();

                        old_cert_pem != cert_pem || old_key_pem != key_pem
                    }
                    // The host is not in the cache, so it's new.
                    None => true,
                };

                if needs_update {
                    info!(
                        "[ConfigReload] Realm '{}': Updating certificate for host '{}'",
                        realm.name, &vhost.hostname
                    );
                    match (
                        pingora::tls::x509::X509::from_pem(cert_pem),
                        pingora::tls::pkey::PKey::private_key_from_pem(key_pem),
                    ) {
                        (Ok(cert), Ok(key)) => {
                            let cert_and_key = Arc::new(CertAndKey { cert, key });
                            current_cache
                                .cert_map
                                .insert(vhost.hostname.clone(), cert_and_key);
                        }
                        (Err(e), _) => warn!(
                            "[ConfigReload] Failed to parse new certificate for {}: {}. Skipping update.",
                            vhost.hostname, e
                        ),
                        (_, Err(e)) => warn!(
                            "[ConfigReload] Failed to parse new private key for {}: {}. Skipping update.",
                            vhost.hostname, e
                        ),
                    }
                }
            }
        }

        // 3. Remove entries that are no longer in the new config.
        current_cache.cert_map.retain(|hostname, _| {
            if !new_hostnames.contains(hostname) {
                info!(
                    "[ConfigReload] Removing obsolete certificate for host: {}",
                    hostname
                );
                false
            } else {
                true
            }
        });
    }
}

impl UpstreamCache {
    /// Performs a differential update of upstream peers from the configuration.
    ///
    /// This function is idempotent. It adds new upstream peers and removes
    /// obsolete ones. Note: It does not check for changes in existing peers.
    pub fn reload_from_config(app_config: &Arc<AppConfig>, current_cache: &Self) {
        let mut all_required_addrs = HashSet::new();

        // 1. Add new peers that are not in the current cache, on a per-realm basis.
        for realm in &app_config.realms {
            let mut realm_addrs = HashSet::new();
            for chain in &realm.routing_chains {
                for rule in &chain.rules {
                    if let Some(addr) = match &rule.action {
                        ActionConfig::Proxy { upstream } => Some(upstream.clone()),
                        ActionConfig::RequireAuthentication {
                            protected_upstream, ..
                        } => Some(protected_upstream.clone()),
                        _ => None,
                    } {
                        realm_addrs.insert(addr);
                    }
                }
            }

            for addr in &realm_addrs {
                if !current_cache.peer_map.contains_key(addr) {
                    info!(
                        "[ConfigReload] Realm '{}': Creating new upstream peer for '{}'",
                        realm.name, addr
                    );
                    let addr_no_scheme = addr.strip_prefix("http://").unwrap_or(addr);
                    let is_tls = addr.starts_with("https://");
                    let peer = HttpPeer::new(addr_no_scheme, is_tls, "".to_string());
                    current_cache.peer_map.insert(addr.clone(), Arc::new(peer));
                }
            }
            all_required_addrs.extend(realm_addrs);
        }

        // Manually add the default upstream if not already present.
        let default_upstream = "http://127.0.0.1:8081".to_string();
        if !current_cache.peer_map.contains_key(&default_upstream) {
            info!(
                "[ConfigReload] System: Creating default upstream peer for '{}'",
                default_upstream
            );
            let peer = HttpPeer::new("127.0.0.1:8081", false, "".to_string());
            current_cache
                .peer_map
                .insert(default_upstream.clone(), Arc::new(peer));
        }
        all_required_addrs.insert(default_upstream);

        // 2. Remove peers that are no longer in the new configuration.
        current_cache.peer_map.retain(|addr, _| {
            if !all_required_addrs.contains(addr) {
                info!("[ConfigReload] Removing obsolete upstream peer: {}", addr);
                false
            } else {
                true
            }
        });
    }
}

impl AuthScopeRegistry {
    /// Performs a differential update of authentication scopes based on the new config.
    /// - New scopes in the config are added.
    /// - Scopes removed from the config are unregistered.
    /// - Existing, unchanged scopes are not touched, preserving their session stores.
    pub fn reload_from_config(config: &Arc<AppConfig>) {
        let mut all_required_scopes = HashSet::new();

        // 1. Register all scopes from the new config, on a per-realm basis.
        // `register_auth_scope` is idempotent, so it's safe to call for existing scopes.
        for realm in &config.realms {
            for chain in &realm.routing_chains {
                for rule in &chain.rules {
                    if let ActionConfig::RequireAuthentication {
                        auth_scope_name, ..
                    } = &rule.action
                    {
                        if all_required_scopes.insert((realm.name.clone(), auth_scope_name.clone()))
                        {
                            // Only log on the first encounter of a scope.
                            info!(
                                "[ConfigReload] Realm '{}': Registering new auth scope if not present: '{}'",
                                realm.name, auth_scope_name
                            );
                        }
                        actions::register_auth_scope(&realm.name, auth_scope_name);
                    }
                }
            }
        }

        // 2. Remove scopes that are no longer in the new configuration.
        let stores = actions::get_all_auth_session_stores();
        stores.retain(|realm_scope_key, _| {
            // Note: This is a simple check. It doesn't handle renaming gracefully.
            if !all_required_scopes
                .iter()
                .any(|(r, s)| format!("{}_{}", r, s) == *realm_scope_key)
            {
                info!(
                    "[ConfigReload] Unregistering obsolete authentication scope: '{}'",
                    realm_scope_key
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

// --- Hot Reload Service ---

/// A background service that periodically checks for configuration updates and applies them.
pub struct ConfigHotReloadService {
    keys_swapper: Arc<ArcSwap<JwtKeysCache>>,
    cert_swapper: Arc<ArcSwap<CertificateCache>>,
    upstream_swapper: Arc<ArcSwap<UpstreamCache>>,
    main_config_swapper: Arc<ArcSwap<AppConfig>>,
    last_known_content: Mutex<String>,
}

impl ConfigHotReloadService {
    pub fn new(
        keys_swapper: Arc<ArcSwap<JwtKeysCache>>,
        cert_swapper: Arc<ArcSwap<CertificateCache>>,
        upstream_swapper: Arc<ArcSwap<UpstreamCache>>,
        main_config_swapper: Arc<ArcSwap<AppConfig>>,
        initial_config_content: String,
    ) -> Self {
        ConfigHotReloadService {
            keys_swapper,
            cert_swapper,
            upstream_swapper,
            main_config_swapper,
            last_known_content: Mutex::new(initial_config_content),
        }
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
                // Atomically swap the entire application configuration.
                self.main_config_swapper.store(new_config_arc.clone());

                // JWT Keys Reload
                let current_keys_cache = self.keys_swapper.load();
                JwtKeysCache::reload_from_config(&new_config_arc, &current_keys_cache);

                // Upstream Cache Reload
                let current_upstream_cache = self.upstream_swapper.load();
                UpstreamCache::reload_from_config(&new_config_arc, &current_upstream_cache);

                // Auth Scopes Reload
                AuthScopeRegistry::reload_from_config(&new_config_arc);

                // Certificate Cache Reload
                let current_cert_cache = self.cert_swapper.load();
                CertificateCache::reload_from_config(&new_config_arc, &current_cert_cache);

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
