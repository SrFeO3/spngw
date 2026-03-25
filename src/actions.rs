/// # Gateway Actions and Logic
///
/// This file defines the core routing and middleware architecture. The `GatewayAction`
/// enum represents the set of possible operations in a request pipeline. Each variant
/// is implemented as a struct that fulfills the `RouteLogic` trait.
///
/// ## Action Categories
///
/// Actions are categorized based on their behavior within the request pipeline:
///
/// ### 1. Terminal Actions
/// These actions terminate the pipeline and generate a final response.
/// (Note: `response_filter` is not executed for these actions).
/// - `ReturnStaticText`: Responds with a predefined static body and status.
/// - `Redirect`: Issues a 302 redirect to a specified URL.
///
/// ### 2. Modifier Actions
/// These actions modify the request or response but allow the pipeline to continue.
/// - `ProxyTo`: Overrides the default upstream and proxies the request.
/// - `IssueDeviceCookie`: Ensures a device identifier cookie (`DEV_COOKIE`) exists.
/// - `SetUpstreamRequestHeader`: Adds or replaces a header sent to the upstream.
/// - `SetDownstreamResponseHeader`: Adds or replaces a header sent to the client.
///
/// ### 3. Composite Actions
/// These are complex, multi-step workflows encapsulated into a single action.
/// - `RequireAuthentication`: An action for paths that require OIDC authentication. It manages
///   the redirect-based login flow. (Note: Callback handling is not yet implemented).
use std::sync::{atomic::{AtomicU64, Ordering}, Arc, OnceLock};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose};
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, Header, Validation, decode, encode};
use log::{info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::GatewayCtx;

pub const HSTS_HEADER_VALUE: &str = "max-age=31536000; includeSubDomains; preload";
pub const BFF_USER_SUB_HEADER: &str = "X-BFF-IDToken-Sub";
const DEVICE_COOKIE_MAX_AGE: u64 = 60 * 60 * 24 * 365; // 1 year
const SESSION_REFRESH_WINDOW_SECONDS: u64 = 300; // 5 minutes
const OIDC_METADATA_CACHE_TTL_SECONDS: u64 = 3600; // 1 hour

/// A type alias for a session store, which is a thread-safe map from session IDs to ApplicationSession objects.
pub type SessionStore = Arc<DashMap<String, Arc<ApplicationSession>>>;

/// A global, thread-safe registry for authentication session stores, keyed by scope name.
static AUTH_SESSION_STORES: OnceLock<DashMap<String, SessionStore>> = OnceLock::new();

/// Generates a unique key for the session store from a realm and scope name.
fn create_realm_scope_key(realm_name: &str, scope_name: &str) -> String {
    format!("{}_{}", realm_name, scope_name)
}

/// Registers a new authentication scope and initializes its session store.
/// This function should be called at application startup for each required scope.
/// It's idempotent; if a scope is already registered, it does nothing.
pub fn register_auth_scope(realm_name: &str, scope_name: &str) {
    let key = create_realm_scope_key(realm_name, scope_name);
    AUTH_SESSION_STORES
        .get_or_init(DashMap::new)
        .entry(key)
        .or_insert_with(|| Arc::new(DashMap::new()));
}

/// Retrieves the specific session store for a given realm and scope.
pub fn get_auth_session_store(realm_name: &str, scope_name: &str) -> Option<SessionStore> {
    let key = create_realm_scope_key(realm_name, scope_name);
    AUTH_SESSION_STORES
        .get_or_init(DashMap::new)
        .get(&key)
        .map(|store| store.value().clone())
}

/// Returns a reference to the entire map of session stores for internal cleanup operations.
pub(crate) fn get_all_auth_session_stores() -> &'static DashMap<String, SessionStore> {
    AUTH_SESSION_STORES.get_or_init(DashMap::new)
}

/// ApplicationSession object, as it's a core data model for the gateway.
#[derive(Debug, Clone)]
pub struct ApplicationSession {
    pub session_id: String,
    pub user_id: String,
    pub username: String,
    pub is_authenticated: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<u64>, // Unix timestamp
    pub expires_at: Arc<AtomicU64>,           // Unix timestamp for the session itself
    pub oidc_nonce: Option<String>,
    pub oidc_pkce_verifier: Option<String>,
    pub oidc_state: Option<String>,
    pub oidc_token_endpoint: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: String,
    pub auth_scope_name: Option<String>,
    pub auth_original_destination: Option<String>,
    // Timestamp of the last token refresh attempt to mitigate dog-piling.
    pub last_refresh_attempt_at: Arc<AtomicU64>,
}

/// Device context for JWT cookie
#[derive(Debug, Serialize, Deserialize)]
struct DeviceContext {
    iss: String, // Issuer
    sub: String, // Subject (device ID)
    cn: String,  // Common Name (e.g., user-friendly device name)
    iat: u64,    // Issued At
    exp: u64,    // Expiration Time
}

/// Set of possible actions that can be applied to a request in the pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum GatewayAction {
    // --- Terminal Actions: Mutually exclusive actions that define the final request handling. ---
    ReturnStaticText {
        content: Arc<str>,
        status: u16,
    },
    Redirect {
        url: Arc<str>,
    },
    // --- Modifier Actions: Actions that can be combined with a terminal action and each other. ---
    #[serde(rename = "proxy")]
    ProxyTo {
        upstream: Arc<str>,
        auth_scope_name: Option<Arc<str>>,
    },
    #[serde(skip)]
    IssueDeviceCookie,
    SetUpstreamRequestHeader {
        name: Arc<str>,
        value: Arc<str>,
    },
    SetDownstreamResponseHeader {
        name: Arc<str>,
        value: Arc<str>,
    },
    // --- Composite Actions: Complex workflows composed of multiple steps. ---
    RequireAuthentication {
        protected_upstream: Arc<str>,
        oidc_authorization_endpoint: Arc<str>,
        oidc_client_id: Arc<str>,
        oidc_redirect_url: Arc<str>,
        oidc_token_endpoint: Arc<str>,
        auth_scope_name: Arc<str>,
        oidc_client_secret: Arc<str>,
        oidc_dialect: Option<Arc<str>>,
    },
}

#[derive(Deserialize, Debug, Clone)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Jwks {
    keys: Vec<serde_json::Value>, // Use serde_json::Value to parse individual keys
}

#[derive(Clone)]
struct CachedOidcMetadata {
    discovery: OidcDiscovery,
    jwks: Jwks,
    expires_at: std::time::Instant,
}
static OIDC_METADATA_CACHE: OnceLock<DashMap<String, CachedOidcMetadata>> = OnceLock::new();

// Define a trait for all route-specific logic.
#[async_trait]
pub trait RouteLogic: Send + Sync {
    fn name(&self) -> &'static str {
        "default"
    }

    async fn request_filter_and_prepare_upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut GatewayCtx,
    ) -> Result<bool> {
        Ok(false) // Continue processing by default
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut GatewayCtx,
    ) -> Result<()> {
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        _response: &mut ResponseHeader,
        _ctx: &mut GatewayCtx,
    ) -> Result<()> {
        Ok(())
    }
}

// Create structs for each route.
pub struct ReturnStaticTextRoute<'a> {
    pub content: &'a str,
    pub status_code: u16,
}
pub struct RedirectRoute<'a> {
    pub url: &'a str,
}
pub struct ProxyToRoute<'a> {
    pub upstream: &'a str,
    pub auth_scope_name: Option<&'a str>,
}
pub struct IssueDeviceCookieRoute;
pub struct SetUpstreamRequestHeaderRoute<'a> {
    pub name: &'a str,
    pub value: &'a str,
}
pub struct SetDownstreamResponseHeaderRoute<'a> {
    pub name: &'a str,
    pub value: &'a str,
}
pub struct RequireAuthenticationRoute<'a> {
    pub protected_upstream: &'a str,
    pub oidc_authorization_endpoint: &'a str,
    pub oidc_client_id: &'a str,
    pub oidc_redirect_url: &'a str,
    pub oidc_token_endpoint: &'a str,
    pub auth_scope_name: &'a str,
    pub oidc_client_secret: &'a str,
    pub oidc_dialect: Option<&'a str>,
}

/// Fetches OIDC discovery document and JWKS.
/// This is a helper function to centralize the logic for fetching OIDC provider metadata.
async fn fetch_oidc_keys(
    client: &reqwest::Client,
    oidc_token_endpoint: &str,
    oidc_dialect: Option<&str>,
    request_id: &str,
    action_name: &str,
) -> Result<(OidcDiscovery, Jwks), Error> {
    // Check cache first
    let cache_key = format!("{}|{:?}", oidc_token_endpoint, oidc_dialect);
    let cache = OIDC_METADATA_CACHE.get_or_init(DashMap::new);

    if let Some(entry) = cache.get(&cache_key) {
        if entry.expires_at > std::time::Instant::now() {
            info!(
                "[{}] [{}] OIDC metadata found in cache for {}",
                request_id, action_name, oidc_token_endpoint
            );
            return Ok((entry.discovery.clone(), entry.jwks.clone()));
        }
    }

    // Fetch OIDC configuration (Discovery) to get JWKS URI and Issuer.
    // We attempt to find the discovery document relative to the token endpoint.
    // Heuristic: Assume the token endpoint is something like `.../token`, go up one level, and look for `.well-known/openid-configuration`.
    // NOTE: This includes optimistic code to handle Google's OIDC dialect.
    let is_google = oidc_dialect == Some("google");
    let discovery_url = if is_google {
        Url::parse("https://accounts.google.com/.well-known/openid-configuration").map_err(|e| {
            warn!(
                "[{}] [{}] Failed to parse Google OIDC discovery URL: {}",
                request_id, action_name, e
            );
            *Error::explain(ErrorType::InternalError, "Failed to parse Google OIDC discovery URL")
        })?
    } else {
        let token_endpoint_url = Url::parse(oidc_token_endpoint).map_err(|e| {
            warn!(
                "[{}] [{}] Invalid OIDC token endpoint URL: {}",
                request_id, action_name, e
            );
            *Error::explain(ErrorType::InternalError, "Invalid OIDC token endpoint URL")
        })?;

        token_endpoint_url
            .join("../.well-known/openid-configuration")
            .map_err(|e| {
                warn!(
                    "[{}] [{}] Failed to construct OIDC discovery URL: {}",
                    request_id, action_name, e
                );
                *Error::explain(ErrorType::InternalError, "Failed to construct OIDC discovery URL")
            })?
    };

    info!(
        "[{}] [{}] Fetching OIDC discovery from: {}",
        request_id, action_name, discovery_url
    );

    let discovery_resp = client.get(discovery_url.clone()).send().await.map_err(|e| {
        warn!(
            "[{}] [{}] Failed to fetch OIDC discovery from {}: {}",
            request_id, action_name, discovery_url, e
        );
        *Error::explain(ErrorType::InternalError, "Failed to fetch OIDC discovery")
    })?;

    let oidc_config: OidcDiscovery = discovery_resp.json().await.map_err(|e| {
        warn!(
            "[{}] [{}] Failed to parse OIDC discovery response: {}",
            request_id, action_name, e
        );
        *Error::explain(ErrorType::InternalError, "Failed to parse OIDC discovery response")
    })?;

    // Fetch JWKS using the URI from discovery
    let jwks_response = client.get(&oidc_config.jwks_uri).send().await.map_err(|e| {
        warn!(
            "[{}] [{}] Failed to fetch JWKS from {}: {}",
            request_id, action_name, oidc_config.jwks_uri, e
        );
        *Error::explain(ErrorType::InternalError, "Failed to fetch JWKS")
    })?;

    let jwks: Jwks = jwks_response.json().await.map_err(|e| {
        warn!("[{}] [{}] Failed to parse JWKS: {}", request_id, action_name, e);
        *Error::explain(ErrorType::InternalError, "Failed to parse JWKS")
    })?;

    // Update cache
    cache.insert(cache_key, CachedOidcMetadata {
        discovery: oidc_config.clone(),
        jwks: jwks.clone(),
        expires_at: std::time::Instant::now() + std::time::Duration::from_secs(OIDC_METADATA_CACHE_TTL_SECONDS),
    });

    Ok((oidc_config, jwks))
}

/// Performs maintenance on the OIDC metadata cache, removing expired entries.
/// This is intended to be called periodically by a background service.
pub fn cleanup_oidc_metadata_cache() {
    if let Some(cache) = OIDC_METADATA_CACHE.get() {
        let start_len = cache.len();
        cache.retain(|_, v| v.expires_at > std::time::Instant::now());
        let removed = start_len - cache.len();
        if removed > 0 {
            info!("[CacheCleanup] Removed {} expired OIDC metadata entries.", removed);
        }
    }
}

// Helper function to inject the Authorization header into the upstream request.
// It ensures the access token is fresh by refreshing it if necessary.
// Returns `true` if the token is valid (or if no session exists), and `false` if the token refresh failed.
// This logic is shared between ProxyToRoute and RequireAuthenticationRoute.
async fn inject_authorization_header_and_token_refresh(
    ctx: &mut GatewayCtx,
    upstream_request: &mut RequestHeader,
    action_name: &str,
    fallback_auth_scope_name: Option<&str>,
) -> bool {
    let mut is_token_valid = true;
    if let Some(app_session) = &mut ctx.action_state_app_session {
        // Prevent mixing sessions from different scopes.
        // If the action specifies a scope, and the session has a scope, they must match.
        if let (Some(req_scope), Some(session_scope)) = (fallback_auth_scope_name, &app_session.auth_scope_name) {
            if req_scope != session_scope.as_str() {
                warn!(
                    "[{}] [{}] Scope mismatch: required='{}', found='{}'. Skipping token injection.",
                    ctx.request_id, action_name, req_scope, session_scope
                );
                return true;
            }
        }

        let mut session_needs_update = false;
        if app_session.is_authenticated {
            let now = Utc::now().timestamp() as u64;
            // Check if expired or expiring within 60 seconds
            if let Some(expires_at) = app_session.access_token_expires_at {
                info!(
                    "[{}] [{}] Access token check: expires_at={}, now={}, remaining={}s",
                    ctx.request_id,
                    action_name,
                    expires_at,
                    now,
                    expires_at.saturating_sub(now)
                );
                // Mitigate token refresh dog-piling: use a timestamp-based cooldown.
                // This allows only one refresh attempt per short interval (e.g., 10s)
                // to prevent a stampede of requests, without using a heavy lock.
                const REFRESH_COOLDOWN_SECONDS: u64 = 10;
                if now >= expires_at.saturating_sub(60) {
                    let mut should_refresh = false;

                    // Atomically check and update the cooldown timestamp in the shared store to prevent dog-piling.
                    // This lock is extremely short-lived (microseconds) and does not cover the network request.
                    let scope_to_use = app_session.auth_scope_name.as_deref().or(fallback_auth_scope_name);
                    if let Some(scope) = scope_to_use {
                        if let Some(store) = get_auth_session_store(&ctx.realm_name, scope) {
                            let session_arc = if let Some(entry) = store.get(&app_session.session_id) {
                                let last_attempt_atomic = &entry.value().last_refresh_attempt_at;
                                let last_attempt = last_attempt_atomic.load(Ordering::Relaxed);
                                if now > last_attempt.saturating_add(REFRESH_COOLDOWN_SECONDS) {
                                    // This request attempts to win the race.
                                    // Use compare_exchange to ensure only one thread enters the refresh block.
                                    if last_attempt_atomic.compare_exchange(
                                        last_attempt,
                                        now,
                                        Ordering::Relaxed,
                                        Ordering::Relaxed
                                    ).is_ok() {
                                        should_refresh = true;
                                    }
                                }
                                Some(entry.value().clone())
                            } else {
                                None
                            };

                            if let Some(arc) = session_arc {
                                // In either case (win or lose), sync our local session with the latest from the store.
                                // This ensures we have the latest timestamp and potentially a new token if we lost the race.
                                *app_session = arc.as_ref().clone();
                            }
                        }
                    }

                    if should_refresh {
                        info!(
                            "[{}] [{}] Access token expired or expiring soon. Attempting refresh.",
                            ctx.request_id, action_name
                        );

                        // The timestamp is already updated in the shared store and our local copy.
                        // We just need to ensure the final session state is saved after the refresh logic.
                        session_needs_update = true;

                        if let (Some(refresh_token), Some(endpoint), Some(client_id)) = (
                            &app_session.refresh_token,
                            &app_session.oidc_token_endpoint,
                            &app_session.oidc_client_id,
                        ) {
                            let client = &ctx.http_client;
                            #[derive(Deserialize)]
                            struct RefreshResponse {
                                access_token: String,
                                expires_in: u64,
                                refresh_token: Option<String>,
                            }

                            let params = vec![
                                ("grant_type", "refresh_token"),
                                ("refresh_token", refresh_token.as_str()),
                                ("client_id", client_id.as_str()),
                                ("client_secret", app_session.oidc_client_secret.as_str()),
                            ];

                            match client.post(endpoint).form(&params).send().await {
                                Ok(resp) => {
                                    if resp.status().is_success() {
                                        if let Ok(tokens) = resp.json::<RefreshResponse>().await {
                                            info!(
                                                "[{}] [{}] Token refresh successful.",
                                                ctx.request_id, action_name
                                            );
                                            app_session.access_token = Some(tokens.access_token);
                                            app_session.access_token_expires_at =
                                                Some(now + tokens.expires_in);
                                            if let Some(new_rt) = tokens.refresh_token {
                                                app_session.refresh_token = Some(new_rt);
                                            }
                                            // session_needs_update is already true
                                        }
                                    } else {
                                        let status = resp.status();
                                        // Attempt to parse the error response from the IdP.
                                        #[derive(Deserialize, Debug)]
                                        struct ErrorResponse {
                                            error: Option<String>,
                                        }
                                        let error_body: Option<ErrorResponse> = resp.json().await.ok();

                                        warn!(
                                            "[{}] [{}] Token refresh failed. Status: {}, Parsed Error: {:?}",
                                            ctx.request_id,
                                            action_name,
                                            status,
                                            error_body
                                        );

                                        // Decide if the failure is permanent (e.g., token revoked) or temporary (e.g., network issue).
                                        let is_permanent_error = if let Some(ErrorResponse { error: Some(err_code) }) = &error_body {
                                            err_code == "invalid_grant"
                                        } else {
                                            status.is_client_error() // Treat all other 4xx as permanent.
                                        };

                                        if is_permanent_error {
                                            info!("[{}] [{}] Token refresh failed with a permanent error (e.g., invalid_grant). Invalidating session.", ctx.request_id, action_name);
                                            app_session.is_authenticated = false;
                                            session_needs_update = true;
                                            is_token_valid = false;
                                        } else {
                                            // For temporary errors (e.g., IdP 5xx), we keep the session to allow retries.
                                            // However, we MUST NOT forward the request if the current token is already expired.
                                            // It is the BFF's responsibility to only send valid tokens to the backend.
                                            // If the current token is already expired when a temporary refresh error occurs,
                                            // we must block the request. The caller will then decide how to respond.
                                            if app_session.access_token_expires_at.map_or(true, |exp| now >= exp) {
                                                warn!("[{}] [{}] Token refresh failed temporarily, and the current token is expired. Blocking upstream request.", ctx.request_id, action_name);
                                                is_token_valid = false; // Signal failure to the caller.
                                            } else {
                                                warn!("[{}] [{}] Token refresh failed temporarily, but current token is still valid. Proceeding with old token.", ctx.request_id, action_name);
                                                // is_token_valid remains true, the old token will be used for this single request.
                                            }
                                        }
                                    }
                                }
                                Err(e) => warn!(
                                    "[{}] [{}] Token refresh request failed: {}",
                                    ctx.request_id, action_name, e
                                ),
                            }
                        } else {
                            let missing = [
                                ("refresh_token", &app_session.refresh_token),
                                ("oidc_token_endpoint", &app_session.oidc_token_endpoint),
                                ("oidc_client_id", &app_session.oidc_client_id),
                            ]
                            .iter()
                            .filter_map(|(k, v)| v.is_none().then_some(*k))
                            .collect::<Vec<_>>()
                            .join(", ");
                            warn!(
                                "[{}] [{}] Cannot refresh token: missing fields: {}",
                                ctx.request_id, action_name, missing
                            );
                        }
                    }
                }
            }
        }

        // Inject the Authorization header if the session is authenticated and we have a valid token.
        if app_session.is_authenticated && is_token_valid {
            if let Some(access_token) = &app_session.access_token {
                info!(
                    "[{}] [{}] Attaching Authorization header to upstream request.",
                    ctx.request_id, action_name
                );
                let auth_header_value = format!("Bearer {}", access_token);
                // Pass the original Access Token to the upstream (upsert)
                upstream_request
                    .insert_header("Authorization", auth_header_value)
                    .unwrap();
                // Inject BFF metadata headers (upsert)
                upstream_request
                    .insert_header(BFF_USER_SUB_HEADER, &app_session.user_id)
                    .unwrap();
            }
        }

        // Save updated session to store if refresh occurred
        if session_needs_update {
            // Determine scope name to find the store. Prefer the one in session, fallback to route config.
            let scope_to_use = app_session
                .auth_scope_name
                .as_deref()
                .or(fallback_auth_scope_name);

            if let Some(scope) = scope_to_use {
                if let Some(store) = get_auth_session_store(&ctx.realm_name, scope) {
                    if is_token_valid {
                        store.insert(
                            app_session.session_id.clone(),
                            Arc::new(app_session.clone()),
                        );
                        info!(
                            "[{}] [{}] Updated session in store after refresh.",
                            ctx.request_id, action_name
                        );
                    } else {
                        store.remove(&app_session.session_id);
                        info!(
                            "[{}] [{}] Removed session from store due to invalid refresh token.",
                            ctx.request_id, action_name
                        );
                    }
                }
            } else {
                warn!(
                    "[{}] [{}] Could not save refreshed session: scope name unknown.",
                    ctx.request_id, action_name
                );
            }
        }
    }
    is_token_valid
}

// Implement the `RouteLogic` trait for each route struct.

/// Terminates the request and responds with a static text body and status code.
///
/// # Arguments
/// * `content` - The static text content to be sent in the response body.
/// * `status_code` - The HTTP status code for the response.
#[async_trait]
impl<'a> RouteLogic for ReturnStaticTextRoute<'a> {
    fn name(&self) -> &'static str {
        "ReturnStaticText"
    }

    async fn request_filter_and_prepare_upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut GatewayCtx,
    ) -> Result<bool> {
        info!(
            "[{}] [{}] Executing request_filter_and_prepare_upstream_peer, responding with static text",
            _ctx.request_id,
            self.name()
        );
        // Manually build the response to ensure HSTS header is included.
        // `session.respond_error_with_body` does not allow for header customization.
        let body = Bytes::from(self.content.as_bytes().to_vec());
        let mut header = ResponseHeader::build(self.status_code, None)?;
        header
            .insert_header("Content-Length", body.len().to_string())?;
        // It's good practice to set the Content-Type for static text.
        header
            .insert_header("Content-Type", "text/plain; charset=utf-8")?;
        // Add the HSTS header as this action terminates the request before the global response_filter.
        header
            .insert_header("Strict-Transport-Security", HSTS_HEADER_VALUE)?;
        header.insert_header("Connection", "close")?;

        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(body), true).await?;
        // Return true to stop the pipeline and send the response immediately.
        Ok(true)
    }
}

/// Terminates the request and responds with a 302 redirect to the specified URL.
///
/// # Arguments
/// * `url` - The destination URL for the redirect.
#[async_trait]
impl<'a> RouteLogic for RedirectRoute<'a> {
    fn name(&self) -> &'static str {
        "Redirect"
    }

    async fn request_filter_and_prepare_upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut GatewayCtx,
    ) -> Result<bool> {
        info!(
            "[{}] [{}] Executing request_filter_and_prepare_upstream_peer, redirecting to {}",
            _ctx.request_id,
            self.name(),
            self.url
        );

        // It's good practice to provide a minimal body for clients that don't automatically follow redirects.
        let body = Bytes::from_static(b"Redirecting...");

        // Create a 302 Found response header.
        let mut header = ResponseHeader::build(302, None).unwrap();
        header.insert_header("Location", &*self.url).unwrap();
        header
            .insert_header("Content-Length", body.len().to_string())
            .unwrap();
        header
            .insert_header("Strict-Transport-Security", HSTS_HEADER_VALUE)
            .unwrap();
        header.insert_header("Connection", "close").unwrap();
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(body), true).await?;

        // Return true to stop the pipeline.
        Ok(true)
    }
}

/// Overrides the default upstream address for the request.
///
/// # Arguments
/// * `upstream` - The address of the upstream service to proxy to (e.g., "127.0.0.1:8083").
#[async_trait]
impl<'a> RouteLogic for ProxyToRoute<'a> {
    fn name(&self) -> &'static str {
        "ProxyTo"
    }

    async fn request_filter_and_prepare_upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut GatewayCtx,
    ) -> Result<bool> {
        info!(
            "[{}] [{}] Setting upstream peer to {}",
            ctx.request_id,
            self.name(),
            self.upstream
        );
        // Overwrite the upstream peer address in the context.
        ctx.override_upstream_addr = Some(self.upstream.into());
        Ok(false) // Continue the pipeline
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut GatewayCtx,
    ) -> Result<()> {
        info!(
            "[{}] [{}] Executing upstream_request_filter",
            ctx.request_id,
            self.name()
        );

        // Retrieve session information from the CHIPIN_SESSION_ID cookie
        // in case RequireAuthentication has not been executed before this action.
        if ctx.action_state_app_session.is_none() {
            if let Some(scope_name) = &self.auth_scope_name {
                info!(
                    "[{}] [{}] No app_session in context, attempting to load from CHIPIN_SESSION_ID for scope: {}",
                    ctx.request_id,
                    self.name(),
                    scope_name
                );
                // Get the session store for the specified scope.
                if let Some(session_store) = get_auth_session_store(&ctx.realm_name, scope_name) {
                    let cookie_name = format!("CHIPIN_SESSION_ID_{}", scope_name.to_uppercase());
                    // Extract the session ID from the cookie header.
                    let app_session_opt = _session
                        .req_header()
                        .headers
                        .get("Cookie")
                        .and_then(|cookie_header| cookie_header.to_str().ok())
                        .and_then(|cookies_str| {
                            cookies_str.split(';').find_map(|cookie| {
                                cookie.trim().strip_prefix(&format!("{}=", cookie_name))
                            })
                        })
                        .and_then(|session_id| {
                            // Retrieve the session from the session store.
                            session_store
                                .get(session_id)
                                .map(|app_session_ref| app_session_ref.value().as_ref().clone())
                        });

                    // Store the retrieved session in the context.
                    ctx.action_state_app_session = app_session_opt;
                }
            }
        }

        let _ = inject_authorization_header_and_token_refresh(
            ctx,
            upstream_request,
            self.name(),
            self.auth_scope_name.as_deref(),
        )
        .await;

        Ok(())
    }
}

/// Issues a long-lived device cookie if one is not already present. This action has no arguments.
#[async_trait]
impl RouteLogic for IssueDeviceCookieRoute {
    fn name(&self) -> &'static str {
        "IssueDeviceCookie"
    }

    async fn request_filter_and_prepare_upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut GatewayCtx,
    ) -> Result<bool> {
        info!(
            "[{}] [{}] Executing request_filter_and_prepare_upstream_peer",
            ctx.request_id,
            self.name()
        );

        // Extract the DEV_COOKIE value using an iterator chain for a more functional style.
        let dev_cookie_value = session
            .req_header()
            .headers
            .get("Cookie")
            .and_then(|cookie_header| cookie_header.to_str().ok())
            .and_then(|cookies_str| {
                cookies_str.split(';').find_map(|cookie| {
                    cookie
                        .trim()
                        .strip_prefix("CHIPIN_DEVICE_CONTEXT=")
                        .map(str::to_string)
                })
            });

        // Attempt to validate the cookie if it exists.
        let is_cookie_valid = if let Some(token) = dev_cookie_value {
            // Use the key corresponding to the current realm.
            let key = match ctx.jwt_keys.keys_by_realm.get(&ctx.realm_name) {
                Some(entry) => entry.value().clone(),
                None => {
                    warn!(
                        "[{}] [{}] No JWT keys found in cache for realm: {}.",
                        ctx.request_id,
                        self.name(),
                        ctx.realm_name
                    );
                    return Ok(false); // Cannot validate, treat as invalid.
                }
            };
            let validation = Validation::new(jsonwebtoken::Algorithm::RS256);

            let token_string = token.to_string();
            let key_clone = key.clone();
            let request_id = ctx.request_id.clone();
            let action_name = self.name().to_string();

            // Offload heavy RSA signature validation to blocking thread
            let task_result = tokio::task::spawn_blocking(move || {
                match decode::<DeviceContext>(&token_string, &key_clone.decoding_key, &validation) {
                    Ok(token_data) => {
                        let claims = token_data.claims;
                        info!(
                            "[{}] [{}] Successfully validated CHIPIN_DEVICE_CONTEXT JWT. iss: {}, sub: {}, cn: {}, iat: {}, exp: {}",
                            request_id,
                            action_name,
                            claims.iss,
                            claims.sub,
                            claims.cn,
                            claims.iat,
                            claims.exp
                        );

                        // Check if the cookie needs to be refreshed (50% of life passed)
                        let now_ts = Utc::now().timestamp() as u64;
                        let total_duration = claims.exp.saturating_sub(claims.iat);
                        let elapsed = now_ts.saturating_sub(claims.iat);
                        let mut new_token_opt = None;

                        if elapsed > total_duration / 2 {
                            info!(
                                "[{}] [{}] CHIPIN_DEVICE_CONTEXT passed 50% of life ({}s / {}s). Refreshing.",
                                request_id,
                                action_name,
                                elapsed,
                                total_duration
                            );

                            let new_claims = DeviceContext {
                                iss: claims.iss,
                                sub: claims.sub,
                                cn: claims.cn,
                                iat: now_ts,
                                exp: now_ts + DEVICE_COOKIE_MAX_AGE,
                            };

                            // Signing is also heavy
                            match encode(
                                &Header::new(jsonwebtoken::Algorithm::RS256),
                                &new_claims,
                                &key_clone.encoding_key,
                            ) {
                                Ok(new_token) => {
                                    new_token_opt = Some(new_token);
                                }
                                Err(e) => {
                                    warn!(
                                        "[{}] [{}] Failed to refresh device cookie: {}",
                                        request_id,
                                        action_name,
                                        e
                                    );
                                }
                            }
                        }
                        Ok(new_token_opt)
                    }
                    Err(e) => Err(e),
                }
            }).await;

            match task_result {
                Ok(Ok(new_token_opt)) => {
                    if let Some(new_token) = new_token_opt {
                        ctx.action_state_new_dev_cookie = Some(new_token);
                    }
                    true // The cookie is valid.
                }
                Ok(Err(e)) => {
                    warn!(
                        "[{}] [{}] Failed to validate CHIPIN_DEVICE_CONTEXT JWT: {}. A new cookie will be issued.",
                        ctx.request_id,
                        self.name(),
                        e
                    );
                    false // The cookie is invalid.
                }
                Err(e) => {
                    warn!(
                        "[{}] [{}] Blocking task failed during validation: {}",
                        ctx.request_id,
                        self.name(),
                        e
                    );
                    false
                }
            }
        } else {
            false // The cookie does not exist.
        };

        // If the cookie is not valid (or doesn't exist), generate a new one.
        if !is_cookie_valid {
            info!(
                "[{}] [{}] Issuing a new CHIPIN_DEVICE_CONTEXT.",
                ctx.request_id,
                self.name()
            );
            // Generate 9 random bytes and Base64-encode them to get a 12-character URL-safe string.
            let mut sub_bytes = [0u8; 9];
            rand::rng().fill_bytes(&mut sub_bytes);
            let sub = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sub_bytes);
            let now_ts = Utc::now().timestamp() as u64;
            let issuer = ctx.front_sni_name.as_deref().unwrap_or_default().to_string();

            // Use the key corresponding to the current realm for signing.
            let key = match ctx.jwt_keys.keys_by_realm.get(&ctx.realm_name) {
                Some(entry) => entry.value().clone(),
                None => {
                    warn!(
                        "[{}] [{}] No JWT keys found in cache for signing (realm: {}).",
                        ctx.request_id,
                        self.name(),
                        ctx.realm_name
                    );
                    let err = Error::new(ErrorType::InternalError);
                    return Err(err);
                }
            };

            let key_clone = key.clone();
            // Offload heavy RSA signing to blocking thread
            let task_result = tokio::task::spawn_blocking(move || {
                let claims = DeviceContext {
                    iss: issuer,
                    sub,
                    cn: "Device-000".to_string(),
                    iat: now_ts,
                    exp: now_ts + DEVICE_COOKIE_MAX_AGE,
                };
                encode(
                    &Header::new(jsonwebtoken::Algorithm::RS256),
                    &claims,
                    &key_clone.encoding_key,
                )
            }).await;

            match task_result {
                Ok(Ok(token)) => {
                    ctx.action_state_new_dev_cookie = Some(token);
                }
                Ok(Err(e)) => {
                    let mut err = Error::new(ErrorType::InternalError);
                    err.context = Some(format!("Failed to create JWT: {}", e).into());
                    return Err(err);
                }
                Err(e) => {
                    let mut err = Error::new(ErrorType::InternalError);
                    err.context = Some(format!("Blocking task failed during signing: {}", e).into());
                    return Err(err);
                }
            }
        }

        Ok(false) // Continue the pipeline
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut GatewayCtx,
    ) -> Result<()> {
        info!(
            "[{}] [{}] Executing response_filter",
            ctx.request_id,
            self.name()
        );
        if let Some(new_cookie_value) = &ctx.action_state_new_dev_cookie {
            info!(
                "[{}] [{}] Setting new CHIPIN_DEVICE_CONTEXT in response.",
                ctx.request_id,
                self.name()
            );
            let mut cookie_value = format!(
                "CHIPIN_DEVICE_CONTEXT={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
                new_cookie_value, DEVICE_COOKIE_MAX_AGE
            );
            if let Some(domain) = &ctx.cookie_domain {
                cookie_value.push_str(&format!("; Domain={}", domain));
            }
            response.append_header("Set-Cookie", cookie_value).unwrap();
        }
        Ok(())
    }
}

/// Upserts (adds or replaces) a header in the request sent to the upstream service.
///
/// # Arguments
/// * `name` - The name of the HTTP header.
/// * `value` - The value of the HTTP header.
#[async_trait]
impl<'a> RouteLogic for SetUpstreamRequestHeaderRoute<'a> {
    fn name(&self) -> &'static str {
        "SetUpstreamRequestHeader"
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut GatewayCtx,
    ) -> Result<()> {
        info!(
            "[{}] [{}] Executing upstream_request_filter, setting header: {}: {}",
            _ctx.request_id,
            self.name(),
            self.name,
            self.value
        );
        // Then, replace our specific header by removing any existing ones first.
        upstream_request.remove_header(&*self.name); // remove_header is fine with a reference
        upstream_request
            .insert_header(
                self.name.to_string(),
                self.value.to_string(),
            )
            .unwrap();
        Ok(())
    }
}

/// Upserts (adds or replaces) a header in the response sent to the downstream client.
///
/// # Arguments
/// * `name` - The name of the HTTP header.
/// * `value` - The value of the HTTP header.
#[async_trait]
impl<'a> RouteLogic for SetDownstreamResponseHeaderRoute<'a> {
    fn name(&self) -> &'static str {
        "SetDownstreamResponseHeader"
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        _ctx: &mut GatewayCtx,
    ) -> Result<()> {
        info!(
            "[{}] [{}] Executing response_filter, setting header: {}: {}",
            _ctx.request_id,
            self.name(),
            self.name,
            self.value
        );
        // Then, replace our specific header by removing any existing ones first.
        response.remove_header(&*self.name); // remove_header is fine with a reference
        response
            .insert_header(
                self.name.to_string(),
                self.value.to_string(),
            )
            .unwrap();
        Ok(())
    }
}

/// Manages the application session and OIDC authentication flow for a protected backend.
///
/// # Arguments
/// * `protected_upstream` - The upstream address of the service protected by this authentication.
/// * `oidc_authorization_endpoint` - The authorization endpoint of the OIDC provider.
/// * `oidc_client_id` - The client ID registered with the OIDC provider.
/// * `oidc_redirect_url` - The callback URL on this BFF that the OIDC provider will redirect to.
/// * `oidc_token_endpoint` - The token endpoint of the OIDC provider.
/// * `auth_scope_name` - A unique name for this authentication scope, used to isolate session cookies.
#[async_trait]
impl<'a> RouteLogic for RequireAuthenticationRoute<'a> {
    fn name(&self) -> &'static str {
        "RequireAuthentication"
    }

    async fn request_filter_and_prepare_upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut GatewayCtx,
    ) -> Result<bool> {
        info!(
            "[{}] [{}] Executing request_filter_and_prepare_upstream_peer",
            ctx.request_id,
            self.name()
        );

        // Retrieve the specific session store for this realm and scope using the helper function.
        let session_store = get_auth_session_store(&ctx.realm_name, &self.auth_scope_name)
            .unwrap_or_else(|| panic!("Authentication scope '{}' for realm '{}' not registered. Please call register_auth_scope at startup.", self.auth_scope_name, ctx.realm_name));

        ctx.override_upstream_addr = Some(self.protected_upstream.into());
        let mut session_found = false;
        let mut app_session_opt: Option<ApplicationSession> = None;
        let now = Utc::now().timestamp() as u64;

        let cookie_name = format!("CHIPIN_SESSION_ID_{}", self.auth_scope_name.to_uppercase());
        if let Some(cookie_header) = session.req_header().headers.get("Cookie") {
            if let Ok(cookies) = cookie_header.to_str() {
                for cookie in cookies.split(';') {
                    if let Some((name, value)) = cookie.trim().split_once('=') {
                        if name == cookie_name {
                            let session_id = value.to_string();
                            info!(
                                "[{}] [{}] Found {}: {}",
                                ctx.request_id,
                                self.name(),
                                cookie_name,
                                session_id
                            );

                            // Retrieve session to check/extend; clone to release lock immediately.
                            let session_from_store = session_store.get(&session_id).map(|r| r.value().clone());

                            if let Some(app_session) = session_from_store {
                                let current_expiry = app_session.expires_at.load(Ordering::Relaxed);
                                // Check if session is expired
                                if current_expiry < now {
                                    warn!(
                                        "[{}] [{}] Session {} for user {} has expired. Removing.",
                                        ctx.request_id,
                                        self.name(),
                                        app_session.session_id,
                                        app_session.user_id
                                    );
                                    session_store.remove(&session_id); // Safe to write now
                                    session_found = false;
                                } else {
                                    info!(
                                        "[{}] [{}] Found active session for user: {}",
                                        ctx.request_id,
                                        self.name(),
                                        app_session.user_id
                                    );

                                    // Only refresh if within the refresh window of expiry to reduce Set-Cookie noise
                                    if current_expiry.saturating_sub(now) <= SESSION_REFRESH_WINDOW_SECONDS {
                                        // Extend session lifetime
                                        app_session.expires_at.store(now + ctx.session_timeout, Ordering::Relaxed);

                                        // Extend cookie lifetime by signaling response_filter to issue Set-Cookie
                                        ctx.action_state_new_app_session_cookie =
                                            Some((session_id.clone(), self.auth_scope_name.to_string()));

                                        info!(
                                            "[{}] [{}] Session expiring soon. Extended lifetime and refreshing cookie.",
                                            ctx.request_id,
                                            self.name()
                                        );
                                    }

                                    app_session_opt = Some(app_session.as_ref().clone());
                                    session_found = true;
                                }
                            } else {
                                warn!(
                                    "[{}] [{}] {} cookie found, but no active session in store.",
                                    ctx.request_id,
                                    self.name(),
                                    cookie_name
                                );
                            }
                            break;
                        }
                    }
                }
            }
        }

        if !session_found {
            info!(
                "[{}] [{}] No active session found, creating a new one.",
                ctx.request_id,
                self.name()
            );
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let new_session_id: String = general_purpose::URL_SAFE_NO_PAD.encode(bytes);

            let new_app_session = ApplicationSession {
                session_id: new_session_id.clone(),
                user_id: format!("user-{}", rand::random::<u16>()),
                username: "Guest".to_string(),
                is_authenticated: false,
                access_token: None,
                refresh_token: None,
                access_token_expires_at: None,
                expires_at: Arc::new(AtomicU64::new(now + crate::UNAUTHENTICATED_SESSION_TIMEOUT_SECONDS)), // Short expiry for unauthenticated sessions
                oidc_nonce: None,
                oidc_pkce_verifier: None,
                oidc_state: None,
                oidc_token_endpoint: Some(self.oidc_token_endpoint.to_string()),
                oidc_client_id: Some(self.oidc_client_id.to_string()),
                oidc_client_secret: self.oidc_client_secret.to_string(),
                auth_scope_name: Some(self.auth_scope_name.to_string()),
                auth_original_destination: None,
                last_refresh_attempt_at: Arc::new(AtomicU64::new(0)),
            };

            session_store.insert(new_session_id.clone(), Arc::new(new_app_session.clone()));
            info!(
                "[{}] [{}] New session stored for user: {}",
                ctx.request_id,
                self.name(),
                new_app_session.user_id
            );
            app_session_opt = Some(new_app_session);

            // Prepare to set the cookie in the response
            ctx.action_state_new_app_session_cookie =
                Some((new_session_id, self.auth_scope_name.to_string()));
        }

        // Store the application session in the main context for other actions to use.
        ctx.action_state_app_session = app_session_opt;

        let is_authenticated = ctx
            .action_state_app_session
            .as_ref()
            .map_or(false, |s| s.is_authenticated);

        if !is_authenticated {
            // The user is not authenticated. This block handles two potential scenarios:
            // 1. A new user accessing a protected resource -> Initiate OIDC login flow.
            // 2. A user returning from the OIDC provider -> Handle the callback (success or error).

            // First, determine if this is an OIDC callback request from an unauthenticated user.
            // A callback is identified by the presence of 'code' and 'state' query parameters,
            // and the request path must match the configured `oidc_redirect_url`.
            let mut oidc_code = None;
            let mut oidc_state = None;
            let mut oidc_error = None;
            let mut oidc_error_description = None;
            if let Some(query) = session.req_header().uri.query() {
                for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                    match key.as_ref() {
                        "code" => oidc_code = Some(value.into_owned()),
                        "state" => oidc_state = Some(value.into_owned()),
                        "error" => oidc_error = Some(value.into_owned()),
                        "error_description" => {
                            oidc_error_description = Some(value.into_owned())
                        }
                        _ => {}
                    }
                }
            }

            // Handle OIDC error response from the provider. This takes precedence over a successful code exchange.
            if let Some(error_code) = oidc_error {
                warn!(
                    "[{}] [{}] Received error from OIDC provider: {} (Description: {})",
                    ctx.request_id,
                    self.name(),
                    error_code,
                    oidc_error_description.as_deref().unwrap_or("N/A")
                );
                // Sanitize the error code to prevent XSS.
                // We limit the length to prevent potential DoS or layout-breaking issues.
                let sanitized_error_code = &error_code[..error_code.len().min(64)];
                let escaped_error_code = html_escape::encode_text(sanitized_error_code);
                let body = format!(
                    "Authentication failed: {}. Please try again or contact support if the problem persists.",
                    escaped_error_code
                );
                let body_bytes = Bytes::from(body);
                let mut header = ResponseHeader::build(401, None)?;
                header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
                header.insert_header("Content-Length", body_bytes.len().to_string())?;
                header.insert_header("Strict-Transport-Security", HSTS_HEADER_VALUE)?;
                header.insert_header("Connection", "close")?;

                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(body_bytes), true).await?;
                return Ok(true); // Stop the pipeline.
            }

            // A request is considered a successful OIDC callback only if it has both 'code' and 'state'
            // and is on the correct redirect URI path.
            let is_successful_callback = if let (Some(_), Some(_)) = (&oidc_code, &oidc_state) {
                let configured_redirect_path = Url::parse(self.oidc_redirect_url)
                    .map(|url| url.path().to_string())
                    .unwrap_or_else(|_| {
                        warn!("[{}] [{}] Invalid oidc_redirect_url in configuration: {}. Cannot process callback.", ctx.request_id, self.name(), self.oidc_redirect_url);
                        String::new()
                    });

                let request_path = session.req_header().uri.path();
                if request_path == configured_redirect_path {
                    true
                } else {
                    warn!(
                        "[{}] [{}] OIDC callback parameters detected on an unexpected path. Expected: '{}', Actual: '{}'. Ignoring callback.",
                        ctx.request_id, self.name(), configured_redirect_path, request_path
                    );
                    false
                }
            } else {
                false
            };

            if is_successful_callback {
                // --- Scenario 2: Handle OIDC Callback ---
                // This block is executed when the user is redirected back from the OIDC provider.
                // It validates the response and exchanges the authorization code for tokens.
                let code = oidc_code.unwrap(); // Safe due to the check above
                let state = oidc_state.unwrap(); // Safe due to the check above

                info!(
                    "[{}] [{}] OIDC callback detected. Handling token exchange.",
                    ctx.request_id,
                    self.name()
                );

                // 2-1. Validate the 'state' parameter against the one stored in the session to prevent CSRF.
                let is_state_valid = if let Some(app_session) = &ctx.action_state_app_session {
                    if let Some(stored_state) = &app_session.oidc_state {
                        *stored_state == state
                    } else {
                        warn!(
                            "[{}] [{}] OIDC callback received, but no state found in session.",
                            ctx.request_id,
                            self.name()
                        );
                        false
                    }
                } else {
                    warn!(
                        "[{}] [{}] OIDC callback received, but no application session context found.",
                        ctx.request_id,
                        self.name()
                    );
                    false
                };

                if !is_state_valid {
                    warn!(
                        "[{}] [{}] OIDC state parameter mismatch. Potential CSRF attack detected.",
                        ctx.request_id,
                        self.name()
                    );
                    let _ = session.respond_error(400).await; // Bad Request
                    return Ok(true);
                }

                // 2-2. PKCE Validation: Retrieve the verifier to prove we initiated the login.
                // The `code_verifier` was stored in the session when the auth flow began.
                // We send it to the token endpoint, where the OIDC provider validates it
                // against the `code_challenge` from the initial request. This prevents
                // authorization code interception attacks.
                let pkce_verifier =
                    ctx.action_state_app_session.as_ref()
                        .and_then(|s| s.oidc_pkce_verifier.clone())
                        .ok_or_else(|| {
                            warn!(
                                "[{}] [{}] No PKCE verifier found in session for token exchange.",
                                ctx.request_id, self.name()
                            );
                            Error::new(ErrorType::HTTPStatus(400)) // Bad Request
                        })?;

                // 2-3. Exchange the authorization code for an access token and ID token.
                // Define a struct to deserialize the token endpoint's response.
                #[derive(Deserialize, Debug)]
                struct TokenResponse {
                    access_token: String,
                    id_token: String,
                    expires_in: u64,
                    refresh_token: Option<String>,
                }

                let client = &ctx.http_client;
                let token_params = vec![
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", self.oidc_redirect_url),
                    ("client_id", self.oidc_client_id),
                    ("code_verifier", &pkce_verifier),
                    ("client_secret", self.oidc_client_secret),
                ];
                let response = client
                    .post(self.oidc_token_endpoint)
                    .form(&token_params)
                    .send()
                    .await
                    .map_err(|e| {
                        warn!(
                            "[{}] [{}] Error sending request to token endpoint: {}",
                            ctx.request_id,
                            self.name(),
                            e
                        );
                        Error::new(ErrorType::InternalError)
                    })?;

                if !response.status().is_success() {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
                    warn!(
                        "[{}] [{}] Failed to exchange code for token.\n\
                        > Target Endpoint: {}\n\
                        > Request Parameters: client_id={}, redirect_uri={}, grant_type=authorization_code, code_verifier={}\n\
                        > Response Status: {}\n\
                        > Response Body: {}",
                        ctx.request_id,
                        self.name(),
                        self.oidc_token_endpoint,
                        self.oidc_client_id,
                        self.oidc_redirect_url,
                        pkce_verifier,
                        status,
                        body
                    );
                    let _ = session.respond_error(502).await; // Bad Gateway
                    return Ok(true);
                }

                info!(
                    "[{}] [{}] Successfully exchanged code for token.",
                    ctx.request_id,
                    self.name()
                );
                let tokens: TokenResponse = match response.json().await {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            "[{}] [{}] Failed to parse token response: {}",
                            ctx.request_id,
                            self.name(),
                            e
                        );
                        let _ = session.respond_error(502).await; // Bad Gateway
                        return Ok(true);
                    }
                };

                info!(
                    "[{}] [{}] Token response content: {:?}",
                    ctx.request_id,
                    self.name(),
                    tokens
                );

                // 2-4. Validate the received tokens (ID Token and Access Token).

                // 2-4-1. Fetch OIDC provider's keys for validation.
                let (oidc_config, jwks) = fetch_oidc_keys(
                    client,
                    self.oidc_token_endpoint,
                    self.oidc_dialect,
                    &ctx.request_id,
                    self.name(),
                )
                .await?;

                // 2-4-2. Validate the ID Token.
                let id_token = &tokens.id_token;
                let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256); // Assuming RS256 for OIDC
                validation.set_audience(&[self.oidc_client_id]);
                validation.set_issuer(&[oidc_config.issuer.as_str()]);

                if let Some(_stored_nonce) = ctx
                    .action_state_app_session
                    .as_ref()
                    .and_then(|s| s.oidc_nonce.as_ref())
                {
                    validation.required_spec_claims.insert("nonce".to_owned());
                } else {
                    warn!(
                        "[{}] [{}] No nonce found in session for ID token validation.",
                        ctx.request_id,
                        self.name()
                    );
                    let _ = session.respond_error(400).await; // Bad Request
                    return Ok(true);
                }

                // Decode the header to extract the Key ID (kid) for efficient key lookup.
                let header = match jsonwebtoken::decode_header(id_token) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(
                            "[{}] [{}] Failed to decode ID token header: {}",
                            ctx.request_id,
                            self.name(),
                            e
                        );
                        let _ = session.respond_error(400).await; // Bad Request
                        return Ok(true);
                    }
                };
                let target_kid = header.kid;

                let mut decoded_token = None;

                if let Some(t_kid) = &target_kid {
                    // A Key ID is specified. Find the specific key and use only that one.
                    info!("[{}] [{}] ID token has kid: '{}'. Searching for matching key.", ctx.request_id, self.name(), t_kid);
                    if let Some(jwk_value) = jwks.keys.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(t_kid.as_str())) {
                        let jwk: jsonwebtoken::jwk::Jwk = match serde_json::from_value(jwk_value.clone()) {
                            Ok(j) => j,
                            Err(_) => {
                                warn!("[{}] [{}] Failed to parse matching JWK for kid: {}", ctx.request_id, self.name(), t_kid);
                                let _ = session.respond_error(401).await;
                                return Ok(true);
                            }
                        };
                        if let Ok(decoding_key) = DecodingKey::from_jwk(&jwk) {
                            match decode::<serde_json::Value>(id_token, &decoding_key, &validation) {
                                Ok(token_data) => decoded_token = Some(token_data),
                                Err(e) => {
                                    // If the specified key fails for any reason, the token is invalid. No fallback.
                                    warn!("[{}] [{}] ID token validation failed for specified kid '{}': {}", ctx.request_id, self.name(), t_kid, e);
                                    let _ = session.respond_error(401).await;
                                    return Ok(true);
                                }
                            }
                        }
                    } else {
                        warn!(
                            "[{}] [{}] ID token specifies kid '{}' but no matching key found in JWKS.",
                            ctx.request_id,
                            self.name(),
                            t_kid
                        );
                        let _ = session.respond_error(401).await;
                        return Ok(true);
                    }

                } else {
                    // No Key ID in header. Try all available keys.
                    info!("[{}] [{}] ID token has no kid. Trying all available keys.", ctx.request_id, self.name());
                    for jwk_value in &jwks.keys {
                        let jwk: jsonwebtoken::jwk::Jwk = match serde_json::from_value(jwk_value.clone()) {
                            Ok(jwk) => jwk,
                            Err(_) => continue, // Skip malformed JWK entries.
                        };

                        if let Ok(decoding_key) = DecodingKey::from_jwk(&jwk) {
                            match decode::<serde_json::Value>(id_token, &decoding_key, &validation) {
                                Ok(token_data) => {
                                    decoded_token = Some(token_data);
                                    break;
                                }
                                Err(e) => {
                                    // Only continue if it's a signature/alg error. Other errors are fatal.
                                    if e.kind() != &jsonwebtoken::errors::ErrorKind::InvalidSignature
                                        && e.kind() != &jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                                    {
                                        warn!("[{}] [{}] ID token validation failed with non-signature error: {}", ctx.request_id, self.name(), e);
                                        let _ = session.respond_error(401).await; // Unauthorized
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }

                let token_data = match decoded_token {
                    Some(td) => td,
                    None => {
                        warn!(
                            "[{}] [{}] No matching JWK found or all keys failed to validate ID token.",
                            ctx.request_id,
                            self.name()
                        );
                        let _ = session.respond_error(401).await; // Unauthorized
                        return Ok(true);
                    }
                };

                // 2-4-3. Nonce Validation: Check the nonce to prevent replay attacks.
                // The nonce is a random string generated at the start of the login flow.
                // The OIDC provider must include this same nonce in the ID Token.
                // This check ensures the token was issued for this specific login attempt.
                if let Some(stored_nonce) = ctx
                    .action_state_app_session
                    .as_ref()
                    .and_then(|s| s.oidc_nonce.as_ref())
                {
                    let token_nonce = token_data
                        .claims
                        .get("nonce")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""); // Should not happen due to `required_spec_claims`
                    if token_nonce != stored_nonce {
                        warn!(
                            "[{}] [{}] ID token nonce mismatch (replay attack?). Expected: {}, Got: {}",
                            ctx.request_id,
                            self.name(),
                            stored_nonce,
                            token_nonce
                        );
                        let _ = session.respond_error(401).await; // Unauthorized
                        return Ok(true);
                    }
                }
                info!("[{}] [{}] Nonce validation successful.", ctx.request_id, self.name());

                info!(
                    "[{}] [{}] ID Token successfully validated. Claims: {:?}",
                    ctx.request_id,
                    self.name(),
                    token_data.claims
                );

                // 2-4-4. Validate the Access Token.
                // We perform this check immediately upon receipt to ensure we don't store an invalid token.
                // We reuse the JWKS and OIDC config fetched for the ID token to avoid extra network costs.
                {
                    let access_token = &tokens.access_token;
                    // Only attempt to validate if it looks like a JWT (has a valid header)
                    if let Ok(at_header) = jsonwebtoken::decode_header(access_token) {
                        if let Some(kid) = at_header.kid {
                            let mut at_validation = Validation::new(at_header.alg);
                            at_validation.set_issuer(&[oidc_config.issuer.as_str()]);
                            // The audience ('aud') of an access token is the Resource Server (the API),
                            // not this client (the BFF). So we skip the audience check here.
                            at_validation.validate_aud = false;

                            let validation_result = if let Some(jwk_value) = jwks.keys.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(&kid)) {
                                let jwk: jsonwebtoken::jwk::Jwk = match serde_json::from_value(jwk_value.clone()) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        warn!("[{}] [{}] Failed to parse matching JWK for access token kid '{}': {}. Rejecting.", ctx.request_id, self.name(), kid, e);
                                        let _ = session.respond_error(401).await;
                                        return Ok(true);
                                    }
                                };
                                DecodingKey::from_jwk(&jwk)
                                    .and_then(|key| decode::<serde_json::Value>(access_token, &key, &at_validation))
                            } else {
                                // No matching key found in JWKS
                                Err(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into())
                            };

                            if let Err(e) = validation_result {
                                warn!("[{}] [{}] Access Token validation failed. Rejecting authentication. Reason: {}", ctx.request_id, self.name(), e);
                                let _ = session.respond_error(401).await;
                                return Ok(true);
                            }

                            info!(
                                "[{}] [{}] Access Token successfully validated.",
                                ctx.request_id,
                                self.name()
                            );

                        } else {
                            warn!(
                                "[{}] [{}] Access Token is a JWT but missing 'kid'. Rejecting.",
                                ctx.request_id,
                                self.name()
                            );
                            let _ = session.respond_error(401).await;
                            return Ok(true);
                        }
                    } else {
                         info!(
                            "[{}] [{}] Access Token is not a valid JWT (could not decode header). Assuming opaque token and skipping validation.",
                            ctx.request_id,
                            self.name()
                        );
                    }
                }

                // 2-5. Session Fixation Mitigation: Regenerate Session ID.
                // Upon successful authentication, we must regenerate the session ID
                // to prevent session fixation attacks.

                // 2-5-1. Get the old session ID before we modify the session object.
                let old_session_id = ctx.action_state_app_session.as_ref().unwrap().session_id.clone();

                // 2-5-2. Generate a new, cryptographically secure session ID.
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                let new_session_id: String = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
                info!(
                    "[{}] [{}] Regenerating session ID to prevent fixation: {} -> {}",
                    ctx.request_id,
                    self.name(),
                    old_session_id,
                    new_session_id
                );

                // 2-5-3. Update the ApplicationSession with the new ID and authenticated state.
                let app_session = ctx.action_state_app_session.as_mut().unwrap(); // We know it exists and is mutable
                app_session.is_authenticated = true;
                // Now that the user is authenticated, extend the session lifetime to the full duration.
                app_session.expires_at.store(Utc::now().timestamp() as u64 + ctx.session_timeout, Ordering::Relaxed);

                app_session.access_token = Some(tokens.access_token);
                app_session.access_token_expires_at =
                    Some(Utc::now().timestamp() as u64 + tokens.expires_in);
                app_session.refresh_token = tokens.refresh_token;
                // The 'sub' claim is REQUIRED by the OIDC spec. If it's missing, the token is invalid.
                let sub = match token_data.claims.get("sub").and_then(|v| v.as_str()) {
                    Some(s) => s.to_string(),
                    None => {
                        warn!(
                            "[{}] [{}] ID token is missing 'sub' claim. Rejecting authentication.",
                            ctx.request_id,
                            self.name()
                        );
                        let _ = session.respond_error(401).await; // Unauthorized
                        return Ok(true);
                    }
                };
                app_session.user_id = sub;
                app_session.username = token_data
                    .claims
                    .get("name")
                    .or_else(|| token_data.claims.get("preferred_username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string();

                // Clear OIDC state from session as it is no longer needed
                app_session.oidc_nonce = None;
                app_session.oidc_pkce_verifier = None;
                app_session.oidc_state = None;

                // 2-5-4. Update the session ID within the session object itself.
                app_session.session_id = new_session_id.clone();

                // 2-5-5. Remove the old, unauthenticated session from the store.
                session_store.remove(&old_session_id);

                // 2-5-6. Insert the newly authenticated session into the store under the new ID.
                session_store.insert(
                    new_session_id.clone(),
                    Arc::new(app_session.clone()),
                );

                // 2-5-7. Prepare to issue the new session cookie to the client.
                // This will overwrite the old session cookie.
                ctx.action_state_new_app_session_cookie = Some((new_session_id, self.auth_scope_name.to_string()));

                // 2-6. Redirect the user back to their original destination.
                // Retrieve the original destination from the session, or default to the root.
                let redirect_path = app_session
                    .auth_original_destination
                    .take()
                    .unwrap_or_else(|| "/".to_string());
                info!(
                    "[{}] [{}] OIDC callback processed. Authentication successful. Redirecting to {}.",
                    ctx.request_id,
                    self.name(),
                    redirect_path
                );

                let body = Bytes::from_static(b"Login successful. Redirecting...");
                let mut header = ResponseHeader::build(302, None).unwrap();
                header.insert_header("Location", redirect_path).unwrap();

                // Set the new session cookie in the redirect response.
                if let Some((cookie_val, scope_name)) = &ctx.action_state_new_app_session_cookie {
                    let cookie_name = format!("CHIPIN_SESSION_ID_{}", scope_name.to_uppercase());
                    let mut cookie_string = format!(
                        "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
                        cookie_name, cookie_val, ctx.session_timeout
                    );
                    if let Some(domain) = &ctx.cookie_domain {
                        cookie_string.push_str(&format!("; Domain={}", domain));
                    }
                    header.append_header("Set-Cookie", cookie_string).unwrap();
                }

                header
                    .insert_header("Content-Length", body.len().to_string())
                    .unwrap();
                header.insert_header("Connection", "close").unwrap();
                header
                    .insert_header("Strict-Transport-Security", HSTS_HEADER_VALUE)
                    .unwrap();
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session.write_response_body(Some(body), true).await?;
                return Ok(true); // Stop the pipeline.
            }

            // --- Scenario 1: Initiate New Authentication Flow ---
            // This block is executed for unauthenticated users on a protected route.
            // It generates OIDC parameters (state, nonce, PKCE), saves them to the session,
            // and redirects the user to the OIDC provider's authorization endpoint.

            let mut app_session = match ctx.action_state_app_session.clone() {
                Some(s) => s, // Clone the session to modify it.
                None => {
                    // This should not happen due to the session creation logic above, but handle defensively.
                    warn!(
                        "[{}] [{}] No app_session found in RequireAuthentication. This is unexpected.",
                        ctx.request_id,
                        self.name()
                    );
                    let _ = session.respond_error(500).await;
                    return Ok(true);
                }
            };

            // 1-1. Generate and store a 'nonce' for replay attack protection.
            let mut bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut bytes);
            let nonce: String = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            app_session.oidc_nonce = Some(nonce.clone());

            // 1-2. Generate and store a 'code_verifier' for PKCE.
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let code_verifier: String = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            app_session.oidc_pkce_verifier = Some(code_verifier.clone());

            // 1-3. Create the 'code_challenge' from the verifier.
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let challenge_bytes = hasher.finalize();
            let code_challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
            // The result is Base64-URL encoded with no padding, as required by the PKCE spec (RFC 7636).

            // 1-4. Generate a 'state' parameter for CSRF protection.
            let mut bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut bytes);
            let state: String = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            app_session.oidc_state = Some(state.clone());

            // 1-5. Save the original request path and query to the session to redirect back later.
            // We strictly avoid storing the full URL to prevent open redirect vulnerabilities.
            let original_path = session.req_header().uri.path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            app_session.auth_original_destination = Some(original_path.to_string());

            // 1-6. Update the session in the central store with the new OIDC values.
            session_store.insert(app_session.session_id.clone(), Arc::new(app_session));

            // 1-7. Build the OIDC authorization URL with all the necessary parameters.
            let mut auth_url =
                Url::parse(self.oidc_authorization_endpoint).expect("Invalid OIDC login URL");

            {
                let mut url_pairs = auth_url.query_pairs_mut();
                url_pairs
                    .append_pair("response_type", "code")
                    .append_pair("client_id", &self.oidc_client_id)
                    .append_pair("redirect_uri", &self.oidc_redirect_url);

                if self.oidc_dialect == Some("google") {
                    // Google dialect: Requires 'access_type=offline' and 'prompt=consent' to obtain a refresh token.
                    url_pairs
                        .append_pair("scope", "openid")
                        .append_pair("access_type", "offline")
                        .append_pair("prompt", "consent");
                } else {
                    // Standard OIDC: Use 'offline_access' scope to obtain a refresh token.
                    url_pairs.append_pair("scope", "openid offline_access");
                }

                url_pairs
                    .append_pair("state", &state)
                    .append_pair("nonce", &nonce)
                    .append_pair("code_challenge", &code_challenge)
                    .append_pair("code_challenge_method", "S256")
                    .append_pair("response_mode", "query"); // Explicitly request query parameters for callback
            }

            info!(
                "[{}] [{}] User not authenticated. Redirecting to OIDC provider.",
                ctx.request_id,
                self.name()
            );

            // 1-8. Perform the redirect.
            let mut header = ResponseHeader::build(302, None).unwrap();
            header.insert_header("Location", auth_url.as_str()).unwrap();

            // Set the CHIPIN_SESSION_ID here because the response_filter will not be called on redirect.
            if let Some((new_cookie_value, scope_name)) = &ctx.action_state_new_app_session_cookie {
                info!(
                    "[{}] [{}] Setting new CHIPIN_SESSION_ID in redirect response.",
                    ctx.request_id,
                    self.name()
                );
                let cookie_name = format!("CHIPIN_SESSION_ID_{}", scope_name.to_uppercase());
                let mut cookie_value = format!(
                    "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
                    cookie_name, new_cookie_value, ctx.session_timeout
                );
                if let Some(domain) = &ctx.cookie_domain {
                    cookie_value.push_str(&format!("; Domain={}", domain));
                }
                // Use `append_header` in case other cookies (like DEV_COOKIE) are also being set.
                header.append_header("Set-Cookie", cookie_value).unwrap();
            }

            let body = Bytes::from_static(b"Redirecting to login...");

            header
                .insert_header("Content-Length", body.len().to_string())
                .unwrap();
            header
                .insert_header("Strict-Transport-Security", HSTS_HEADER_VALUE)
                .unwrap();
            header.insert_header("Connection", "close").unwrap();
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body), true).await?;

            return Ok(true); // Stop the pipeline
        }

        info!(
            "[{}] [{}] Application session found and authenticated. Allowing access.",
            ctx.request_id,
            self.name()
        );

        // Scenario 3: Return user info for /api/me
        if session.req_header().uri.path().ends_with("/api/me") {
            info!(
                "[{}] [{}] Intercepting /api/me request.",
                ctx.request_id,
                self.name()
            );
            let (username, sub) = ctx
                .action_state_app_session
                .as_ref()
                .map(|s| (s.username.as_str(), s.user_id.as_str()))
                .unwrap_or(("Unknown", ""));
            let body_content = serde_json::json!({ "name": username, "sub": sub }).to_string();
            let body = Bytes::from(body_content);

            let mut header = ResponseHeader::build(200, None).unwrap();
            header
                .insert_header("Content-Type", "application/json")
                .unwrap();
            header
                .insert_header("Content-Length", body.len().to_string())
                .unwrap();
            header
                .insert_header("Strict-Transport-Security", HSTS_HEADER_VALUE)
                .unwrap();

            // Inject Set-Cookie if the session was extended during this request.
            if let Some((new_cookie_value, scope_name)) = &ctx.action_state_new_app_session_cookie {
                let cookie_name = format!("CHIPIN_SESSION_ID_{}", scope_name.to_uppercase());
                let mut cookie_value = format!(
                    "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
                    cookie_name, new_cookie_value, ctx.session_timeout
                );
                if let Some(domain) = &ctx.cookie_domain {
                    cookie_value.push_str(&format!("; Domain={}", domain));
                }
                header.append_header("Set-Cookie", cookie_value).unwrap();
            }

            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body), true).await?;
            return Ok(true);
        }

        Ok(false) // Continue the pipeline
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut GatewayCtx,
    ) -> Result<()> {
        // Inject the Authorization header, checking and updating the access token to ensure it is fresh.
        let is_token_valid = inject_authorization_header_and_token_refresh(
            ctx,
            upstream_request,
            self.name(),
            Some(self.auth_scope_name),
        )
        .await;

        if !is_token_valid {
            // If the access token is invalid (e.g., expired and refresh failed), do not proxy the request.
            // Return 401 Unauthorized instead of a 302 redirect to prevent redirect loops and POST data loss,
            // allowing client-side applications (like SPAs) to handle re-authentication gracefully.
            warn!(
                "[{}] [{}] Token is invalid and refresh failed. Responding with 401 Unauthorized.",
                ctx.request_id,
                self.name()
            );
            let mut resp = ResponseHeader::build(401, None)?;
            resp.insert_header("Content-Length", "0")?;
            resp.insert_header("Connection", "close")?;
            session.write_response_header(Box::new(resp), true).await?;

            // Return a custom error to signal that we've handled the response and to stop further processing.
            return Err(Error::new(ErrorType::Custom(
                "Token invalid, responded with 401".into(),
            )));
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut GatewayCtx,
    ) -> Result<()> {
        if let Some((new_cookie_value, scope_name)) = &ctx.action_state_new_app_session_cookie {
            if scope_name != self.auth_scope_name {
                return Ok(());
            }
            info!(
                "[{}] [{}] Setting new CHIPIN_SESSION_ID in response.",
                ctx.request_id,
                self.name()
            );
            let cookie_name = format!("CHIPIN_SESSION_ID_{}", scope_name.to_uppercase());
            let mut cookie_value = format!(
                "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
                cookie_name, new_cookie_value, ctx.session_timeout
            );
            if let Some(domain) = &ctx.cookie_domain {
                cookie_value.push_str(&format!("; Domain={}", domain));
            }
            response.append_header("Set-Cookie", cookie_value).unwrap();
        }

        Ok(())
    }
}
