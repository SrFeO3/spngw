/// # Configuration Management
///
/// This module is responsible for defining, loading, and managing the application's
/// configuration. It includes data structures that map directly to the `config.yaml` file,
/// and logic for hot-reloading configurations without service interruption.
///
/// ## Key Components:
///
/// - **`AppConfig` and related structs**: These are `serde`-deserializable structures
///   that represent the hierarchy of the configuration source (file or API).
///
/// - **`SignalReloadService`**: A background service that reloads configuration upon
///   receiving a signal (e.g., SIGUSR1) and applies changes to the running application
///   without downtime. It uses `ArcSwap` to atomically update shared configuration data.
///
/// - **Caches (`UpstreamCache`, `CertificateCache`, `RealmMap`, `JwtKeysCache`)**:
///   These components hold processed, ready-to-use data derived from the main configuration.
///   They are designed to be hot-reloaded and are managed by the `SignalReloadService`.
///
/// ## Hot-Reloading and Idempotency
///
/// The hot-reloading mechanism is designed to be idempotent and minimally disruptive:
/// - **JWT Keys, Certificates, and Upstreams**: When the configuration changes, only the
///   items that have been added, modified, or removed are updated. Unchanged items are
///   left as-is.
/// - **Authentication Scopes**: A differential update is performed on authentication scopes.
///   New scopes are added and obsolete ones are removed, but crucially, existing,
///   unchanged scopes are not touched. This ensures that active user sessions within those
///   scopes are preserved across configuration reloads.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use futures::future::join_all;
use log::{error, info, warn};
use pingora::prelude::*;
use pingora::services::background::BackgroundService;
use pingora::tls::pkey::Private;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use crate::actions;
use tokio::{self, signal::unix::{signal, SignalKind}};

/// Helper struct to deserialize the realm list from the inventory server.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiRealm {
    name: String,
    #[serde(default)]
    disabled: bool,
    #[serde(rename = "deviceIdVerificationKey")]
    public_key_pem: String,
    #[serde(rename = "deviceIdSigningKey")]
    private_key_pem: String,
    #[serde(rename = "sessionTimeout", default)]
    session_timeout: u64,
}

/// Rule that matches a request and specifies an action to perform.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct RuleConfig {
    #[serde(rename = "match")]
    pub match_expr: String,
    pub action: Arc<actions::GatewayAction>,
}

/// Routing rules that are evaluated sequentially.
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingChainConfig {
    pub name: String,
    #[serde(default)]
    pub _title: String,
    #[serde(default)]
    pub _description: String,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubdomainConfig {
    pub _name: String,
    pub urn: String,
    #[serde(default)]
    pub _title: String,
    #[serde(default)]
    pub _description: String,
    pub fqdn: String,
    #[serde(default)]
    pub share_cookie: bool,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZoneConfig {
    pub _name: String,
    pub _urn: String,
    #[serde(default)]
    pub _title: String,
    #[serde(default)]
    pub _description: String,
    pub _dns_provider: Option<String>,
    pub _acme_certificate_provider: Option<String>,
    #[serde(default)]
    pub subdomains: Vec<SubdomainConfig>,
}

/// Virtual host, which maps a hostname to a specific TLS certificate.
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualHostConfig {
    pub name: String,
    #[serde(skip)]
    pub hostname: String, // This is resolved from `subdomain` URN later
    pub subdomain: String,
    #[serde(rename = "certificate")]
    pub certificate_pem: String,
    #[serde(rename = "key")]
    pub private_key_pem: String,
    #[serde(default)]
    pub disabled: bool,
}

/// PEM-encoded public and private keys for JWT signing.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct JwtKeyPairConfig {
    #[serde(rename = "deviceIdVerificationKey")]
    pub public_key_pem: String,
    #[serde(rename = "deviceIdSigningKey")]
    pub private_key_pem: String,
}

/// Realm, which groups together a set of virtual hosts and routing rules.
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmConfig {
    pub name: String,
    #[serde(default)]
    pub _urn: String,
    #[serde(default)]
    pub _title: String,
    #[serde(default)]
    pub _description: String,
    #[serde(flatten)]
    pub jwt_key_pair: JwtKeyPairConfig, // Flatten the keys directly into the realm
    #[serde(default)]
    pub _cacert: String,
    #[serde(default)]
    pub session_timeout: u64,
    #[serde(default)]
    pub _administrators: Vec<String>,
    #[serde(default)]
    pub _expired_at: String,
    pub virtual_hosts: Vec<VirtualHostConfig>,
    pub routing_chains: Vec<RoutingChainConfig>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub _hubs: Vec<serde_json::Value>, // Using Value as Hubs/Services are not used yet
}

/// Root of the application's configuration.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct AppConfig {
    #[serde(deserialize_with = "deserialize_realms")]
    pub realms: Vec<RealmConfig>,
}

impl AppConfig {
    pub fn resolve_hostnames(&mut self) -> Result<(), String> {
        for realm in &mut self.realms {
            let mut urn_to_fqdn = std::collections::HashMap::new();
            for zone in &realm.zones {
                for subdomain in &zone.subdomains {
                    urn_to_fqdn.insert(subdomain.urn.clone(), subdomain.fqdn.clone());
                }
            }

            for vhost in &mut realm.virtual_hosts {
                if let Some(fqdn) = urn_to_fqdn.get(&vhost.subdomain) {
                    vhost.hostname = fqdn.clone();
                } else {
                    return Err(format!(
                        "Realm '{}': VirtualHost subdomain URN '{}' not found in zones configuration.",
                        realm.name, vhost.subdomain
                    ));
                }
            }
        }
        Ok(())
    }
}

fn deserialize_realms<'de, D>(deserializer: D) -> Result<Vec<RealmConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut realms: Vec<RealmConfig> = Vec::deserialize(deserializer)?;
    realms.retain(|realm| {
        if realm.disabled {
            info!("[ConfigLoad] Skipping disabled realm: '{}'", realm.name);
            false
        } else {
            true
        }
    });
    for realm in &mut realms {
        realm.virtual_hosts.retain(|vhost| {
            if vhost.disabled {
                info!("[ConfigLoad] Skipping disabled virtual host: '{}'", vhost.name);
                false
            } else {
                true
            }
        });
    }
    Ok(realms)
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
    pub peer_map: DashMap<Arc<str>, Arc<HttpPeer>>,
}

/// Application's cryptographic keys.
#[derive(Clone)]
pub struct JwtKeyPair {
    pub public_key_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
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

/// Cache for Realm lookups by hostname.
pub struct RealmMap {
    pub map: DashMap<String, String>,
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
            let public_key_pem = realm.jwt_key_pair.public_key_pem.as_bytes();
            let private_key_pem = realm.jwt_key_pair.private_key_pem.as_bytes();

            // Check if the key is new or has changed.
            let needs_update = match current_cache.keys_by_realm.get(&realm.name) {
                // The realm exists. Check if the key material has changed.
                Some(existing_keys) => {
                    existing_keys.public_key_pem != public_key_pem
                        || existing_keys.private_key_pem != private_key_pem
                }
                // The realm is new and not in the cache, so it needs to be added.
                None => true,
            };

            if needs_update {
                // Parse keys only when update is needed
                let encoding_key = match EncodingKey::from_rsa_pem(private_key_pem) {
                    Ok(k) => k,
                    Err(e) => {
                        warn!("[ConfigReload] Failed to parse private key for realm '{}': {}", realm.name, e);
                        continue;
                    }
                };
                let decoding_key = match DecodingKey::from_rsa_pem(public_key_pem) {
                    Ok(k) => k,
                    Err(e) => {
                        warn!("[ConfigReload] Failed to parse public key for realm '{}': {}", realm.name, e);
                        continue;
                    }
                };

                let new_keys = JwtKeyPair {
                    public_key_pem: public_key_pem.to_vec(),
                    private_key_pem: private_key_pem.to_vec(),
                    encoding_key,
                    decoding_key,
                };

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

impl RealmMap {
    /// Performs a differential update of the hostname-to-realm mapping.
    pub fn reload_from_config(app_config: &Arc<AppConfig>, current_map: &Self) {
        let mut new_map = std::collections::HashMap::new();
        for realm in &app_config.realms {
            for vhost in &realm.virtual_hosts {
                new_map.insert(vhost.hostname.clone(), realm.name.clone());
            }
        }

        // Update existing or insert new
        for (host, realm) in &new_map {
            current_map.map.insert(host.clone(), realm.clone());
        }

        // Remove obsolete
        current_map.map.retain(|host, _| new_map.contains_key(host));
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
            let mut realm_addrs: HashSet<Arc<str>> = HashSet::new();
            for chain in &realm.routing_chains {
                for rule in &chain.rules {
                    if let Some(addr) = match rule.action.as_ref() {
                        actions::GatewayAction::ProxyTo { upstream, .. } => Some(upstream.clone()),
                        actions::GatewayAction::RequireAuthentication {
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
        let stores = actions::get_all_auth_session_stores();

        // 1. Register all scopes from the new config, on a per-realm basis.
        // `register_auth_scope` is idempotent, so it's safe to call for existing scopes.
        for realm in &config.realms {
            for chain in &realm.routing_chains {
                for rule in &chain.rules {
                    if let actions::GatewayAction::RequireAuthentication {
                        auth_scope_name, ..
                    } = rule.action.as_ref()
                    {
                        if all_required_scopes.insert((realm.name.clone(), auth_scope_name.clone()))
                        {
                            // Only log if the scope is actually new (not in the global store).
                            let key = format!("{}_{}", realm.name, auth_scope_name);
                            if !stores.contains_key(&key) {
                                info!(
                                    "[ConfigReload] Realm '{}': Registering new auth scope: '{}'",
                                    realm.name, auth_scope_name
                                );
                            }
                        }
                        actions::register_auth_scope(&realm.name, auth_scope_name);
                    }
                }
            }
        }

        // 2. Remove scopes that are no longer in the new configuration.
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

/// Populates or reloads all caches from a given application configuration.
/// This function centralizes the cache update logic for both initial load and hot reloads.
pub fn populate_caches_from_config(
    app_config: &Arc<AppConfig>,
    keys_cache: &JwtKeysCache,
    cert_cache: &CertificateCache,
    upstream_cache: &UpstreamCache,
    realm_map: &RealmMap,
) {
    // JWT Keys Reload
    JwtKeysCache::reload_from_config(app_config, keys_cache);
    // Certificate Cache Reload
    CertificateCache::reload_from_config(app_config, cert_cache);
    // Upstream Cache Reload
    UpstreamCache::reload_from_config(app_config, upstream_cache);
    // Realm Map Reload
    RealmMap::reload_from_config(app_config, realm_map);
    // Auth Scopes Reload
    AuthScopeRegistry::reload_from_config(app_config);

    // Log a summary of the loaded routing rules for verification.
    for realm in &app_config.realms {
        info!("[Config] Verifying rules for realm: '{}'", realm.name);
        for chain in &realm.routing_chains {
            info!("[Config]   Chain: '{}'", chain.name);
            if chain.rules.is_empty() {
                info!("[Config]     -> No rules configured.");
            } else {
                for (i, rule) in chain.rules.iter().enumerate() {
                    info!(
                        "[Config]     -> Rule {}: match '{}' -> action: {:?}",
                        i + 1,
                        rule.match_expr,
                        rule.action
                    );
                }
            }
        }
    }

    info!("[Config] All caches have been populated from the configuration.");
}

/// Loads configuration from a source specified by a path, which can be a URL or a file URI.
async fn load_config_from_source(path: &str) -> Result<(AppConfig, String), Box<dyn std::error::Error + Send + Sync>> {
    if path.starts_with("http://") || path.starts_with("https://") {
        info!("[ConfigLoad] Fetching configuration from repository: {}", path);
        fetch_config_from_url(path).await
    } else if let Some(file_path) = path.strip_prefix("file://") {
        info!("[ConfigLoad] Reading configuration from file: {}", file_path);
        let content = tokio::fs::read_to_string(file_path).await
            .map_err(|e| format!("Failed to read configuration from {}: {}", file_path, e))?;
        let mut config: AppConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse configuration from {}: {}", file_path, e))?;
        config.resolve_hostnames()?;
        Ok((config, content))
    } else {
        Err(format!("Unsupported configuration source scheme in path: {}. Use 'file://' or 'http(s)://'.", path).into())
    }
}

/// Fetches configuration from multiple repository API endpoints and constructs the AppConfig.
async fn fetch_config_from_url(url: &str) -> Result<(AppConfig, String), Box<dyn std::error::Error + Send + Sync>> {
    // Helper to fetch and deserialize JSON from a URL, with enhanced error reporting.
    async fn fetch_and_deserialize<T: serde::de::DeserializeOwned + Default>(client: &reqwest::Client, url: &str) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        info!("Fetching from {}", url);
        let response = client.get(url).send().await.map_err(|e| format!("Network error while fetching from {}: {}", url, e))?;
        // Handle 404 Not Found gracefully by returning a default (empty) value.
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            warn!("API endpoint not found (404): {}. Assuming empty collection.", url);
            return Ok(T::default());
        }
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_else(|_| "<failed to read body>".to_string());
            error!("API at {} returned error status {}: {}", url, status, &body_text);
            return Err(format!("API error for {}: status {}" , url, status).into());
        }

        // Read body as text first to handle cases where the API might return an empty body for an empty list.
        let body_text = response.text().await?;
        if body_text.is_empty() {
            info!("Received empty body from {}, defaulting to empty collection.", url);
            return Ok(T::default());
        }

        serde_json::from_str(&body_text).map_err(|e| {
            let err_msg = format!("Failed to deserialize JSON from {}: {}. Body: '{}'", url, e, body_text);
            error!("{}", &err_msg);
            err_msg.into()
        })
    }

    let base_url = url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let realms_url = format!("{}/realms", base_url);
    let api_realms: Vec<ApiRealm> = fetch_and_deserialize(&client, &realms_url).await?;

    let realm_tasks = api_realms.into_iter().filter(|r| !r.disabled).map(|api_realm| {
        let client = client.clone();
        let base_url = base_url.to_string();
        async move {
            let realm_name = api_realm.name.clone();

            let vhosts_url = format!("{}/realms/{}/virtual-hosts", base_url, realm_name);
            let chains_url = format!("{}/realms/{}/routing-chains", base_url, realm_name);
            let zones_url = format!("{}/realms/{}/zones", base_url, realm_name);

            let vhosts_future = fetch_and_deserialize::<Vec<VirtualHostConfig>>(&client, &vhosts_url);
            let chains_future = fetch_and_deserialize::<Vec<RoutingChainConfig>>(&client, &chains_url);
            let zones_future = async {
                let zones: Vec<ZoneConfig> = fetch_and_deserialize(&client, &zones_url).await?;
                let zone_tasks = zones.into_iter().map(|mut zone| {
                    let client = client.clone();
                    let base_url = base_url.clone();
                    let realm_name = realm_name.clone();
                    async move {
                        let subdomains_url = format!("{}/realms/{}/zones/{}/subdomains", base_url, realm_name, zone._name);
                        let subdomains: Vec<SubdomainConfig> = fetch_and_deserialize(&client, &subdomains_url).await?;
                        zone.subdomains = subdomains;
                        Ok(zone)
                    }
                });
                join_all(zone_tasks).await.into_iter().collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()
            };

            let (vhosts_res, chains_res, zones_res) = tokio::join!(vhosts_future, chains_future, zones_future);

            let virtual_hosts = vhosts_res?;
            let zones = zones_res?;
            let routing_chains = chains_res?;

            let realm_config = RealmConfig {
                name: api_realm.name,
                jwt_key_pair: JwtKeyPairConfig {
                    public_key_pem: api_realm.public_key_pem,
                    private_key_pem: api_realm.private_key_pem,
                },
                virtual_hosts,
                routing_chains,
                zones,
                disabled: api_realm.disabled,
                session_timeout: api_realm.session_timeout,
                // Assume these fields are not provided by the API and set defaults.
                _urn: String::new(),
                _title: String::new(),
                _description: String::new(),
                _cacert: String::new(),
                _administrators: Vec::new(),
                _expired_at: String::new(),
                _hubs: Vec::new(),
            };

            let result: Result<RealmConfig, Box<dyn std::error::Error + Send + Sync>> = Ok(realm_config);
            result
        }
    });

    let realms: Vec<RealmConfig> = join_all(realm_tasks)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let mut config = AppConfig { realms };
    config.resolve_hostnames()?;

    // Serialize the constructed config to a YAML string to be used as the "content" for change detection.
    let content = serde_yaml::to_string(&config)?;
    Ok((config, content))
}

pub fn load_app_config(path: &str) -> (Arc<AppConfig>, String) {
    // Create a temporary runtime to execute the async load function during synchronous startup.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (config, content) = rt.block_on(load_config_from_source(path))
        .unwrap_or_else(|e| panic!("Failed to load initial configuration from {}: {}", path, e));

    (Arc::new(config), content)
}

// --- Hot Reload Service ---

/// A background service that periodically checks for configuration updates and applies them.
pub struct SignalReloadService {
    keys_swapper: Arc<ArcSwap<JwtKeysCache>>,
    cert_swapper: Arc<ArcSwap<CertificateCache>>,
    upstream_swapper: Arc<ArcSwap<UpstreamCache>>,
    realm_map_swapper: Arc<ArcSwap<RealmMap>>,
    main_config_swapper: Arc<ArcSwap<AppConfig>>,
    config_path: String,
    last_known_content: Mutex<String>,
}

impl SignalReloadService {
    pub fn new(
        keys_swapper: Arc<ArcSwap<JwtKeysCache>>,
        cert_swapper: Arc<ArcSwap<CertificateCache>>,
        upstream_swapper: Arc<ArcSwap<UpstreamCache>>,
        realm_map_swapper: Arc<ArcSwap<RealmMap>>,
        main_config_swapper: Arc<ArcSwap<AppConfig>>,
        config_path: String,
        initial_config_content: String,
    ) -> Self {
        SignalReloadService {
            keys_swapper,
            cert_swapper,
            upstream_swapper,
            realm_map_swapper,
            main_config_swapper,
            config_path,
            last_known_content: Mutex::new(initial_config_content),
        }
    }
}

#[async_trait]
impl BackgroundService for SignalReloadService {
    async fn start(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut sigusr1 = match signal(SignalKind::user_defined1()) { Ok(s) => s, Err(e) => { warn!("Failed to register SIGUSR1 handler: {}. Hot-reloading via signal will be disabled.", e); return; } };
        info!("Signal handler for SIGUSR1 registered. Send SIGUSR1 to this process to reload configuration.");

        loop {
            tokio::select! {
                _ = sigusr1.recv() => {
                    self.reload_config().await;
                }
                _ = shutdown.changed() => {
                    info!("[Signal] Shutdown signal received, terminating signal handler.");
                    break;
                }
            }
        }
    }
}

impl SignalReloadService {
    async fn reload_config(&self) { // This is now synchronous but fast enough.
        info!("[Signal] SIGUSR1 received. Triggering configuration reload.");

        let result = load_config_from_source(&self.config_path).await;

        let (new_config, current_content) = match result {
            Ok(res) => res,
            Err(e) => {
                warn!("[ConfigReload] Failed to load new configuration: {}. Continuing with the old configuration.", e);
                return;
            }
        };

        {
            let last_content = self.last_known_content.lock().unwrap();
            if *last_content == current_content {
                info!("[ConfigReload] Configuration content has not changed. Skipping reload.");
                return;
            }
        }

        let new_config_arc = Arc::new(new_config);

        // Atomically swap the main config first.
        self.main_config_swapper.store(new_config_arc.clone());

        // Use the unified function to reload all caches.
        populate_caches_from_config(
            &new_config_arc,
            &self.keys_swapper.load(),
            &self.cert_swapper.load(),
            &self.upstream_swapper.load(),
            &self.realm_map_swapper.load(),
        );
        // Lock the mutex to safely update the last known content.
        let mut last_content = self.last_known_content.lock().unwrap();
        *last_content = current_content;

        info!("Successfully reloaded and applied new configuration.");
    }
}
