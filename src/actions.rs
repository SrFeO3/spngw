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
use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose};
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use log::{info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use rand::distr::Alphanumeric;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::GatewayCtx;

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
    pub oidc_nonce: Option<String>,
    pub oidc_pkce_verifier: Option<String>,
    pub oidc_state: Option<String>,
    pub oidc_token_endpoint: Option<String>,
    pub oidc_client_id: Option<String>,
    pub auth_scope_name: Option<String>,
    pub auth_original_destination: Option<String>,
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
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayAction {
    // --- Terminal Actions: Mutually exclusive actions that define the final request handling. ---
    ReturnStaticText {
        content: Cow<'static, str>,
        status_code: u16,
    },
    Redirect {
        url: Cow<'static, str>,
    },
    // --- Modifier Actions: Actions that can be combined with a terminal action and each other. ---
    ProxyTo {
        upstream: Cow<'static, str>,
        auth_scope_name: Option<Cow<'static, str>>,
    },
    IssueDeviceCookie,
    SetUpstreamRequestHeader {
        name: Cow<'static, str>,
        value: Cow<'static, str>,
    },
    SetDownstreamResponseHeader {
        name: Cow<'static, str>,
        value: Cow<'static, str>,
    },
    // --- Composite Actions: Complex workflows composed of multiple steps. ---
    RequireAuthentication {
        protected_upstream: Cow<'static, str>,
        oidc_login_redirect_url: Cow<'static, str>,
        oidc_client_id: Cow<'static, str>,
        oidc_callback_url: Cow<'static, str>,
        oidc_token_endpoint_url: Cow<'static, str>,
        auth_scope_name: Cow<'static, str>,
    },
}

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
pub struct ReturnStaticTextRoute {
    pub content: Cow<'static, str>,
    pub status_code: u16,
}
pub struct RedirectRoute {
    pub url: Cow<'static, str>,
}
pub struct ProxyToRoute {
    pub upstream: Cow<'static, str>,
    pub auth_scope_name: Option<Cow<'static, str>>,
}
pub struct IssueDeviceCookieRoute;
pub struct SetUpstreamRequestHeaderRoute {
    pub name: Cow<'static, str>,
    pub value: Cow<'static, str>,
}
pub struct SetDownstreamResponseHeaderRoute {
    pub name: Cow<'static, str>,
    pub value: Cow<'static, str>,
}
pub struct RequireAuthenticationRoute {
    pub protected_upstream: Cow<'static, str>,
    pub oidc_login_redirect_url: Cow<'static, str>,
    pub oidc_client_id: Cow<'static, str>,
    pub oidc_callback_url: Cow<'static, str>,
    pub oidc_token_endpoint_url: Cow<'static, str>,
    pub auth_scope_name: Cow<'static, str>,
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
                if now >= expires_at.saturating_sub(60) {
                    info!(
                        "[{}] [{}] Access token expired or expiring soon. Attempting refresh.",
                        ctx.request_id, action_name
                    );

                    if let (Some(refresh_token), Some(endpoint), Some(client_id)) = (
                        &app_session.refresh_token,
                        &app_session.oidc_token_endpoint,
                        &app_session.oidc_client_id,
                    ) {
                        let client = reqwest::Client::new();
                        #[derive(Deserialize)]
                        struct RefreshResponse {
                            access_token: String,
                            expires_in: u64,
                            refresh_token: Option<String>,
                        }

                        let params = [
                            ("grant_type", "refresh_token"),
                            ("refresh_token", refresh_token),
                            ("client_id", client_id),
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
                                        session_needs_update = true;
                                    }
                                } else {
                                    warn!(
                                        "[{}] [{}] Token refresh failed. Status: {}",
                                        ctx.request_id,
                                        action_name,
                                        resp.status()
                                    );
                                    // If refresh fails (e.g. refresh token expired or revoked),
                                    // revert the session to unauthenticated state to guide the user to the re-login flow on next access.
                                    app_session.is_authenticated = false;
                                    session_needs_update = true;
                                    is_token_valid = false;
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

        // Inject the Authorization header, checking and updating the access token to ensure it is fresh.
        if app_session.is_authenticated {
            if let Some(access_token) = &app_session.access_token {
                info!(
                    "[{}] [{}] Attaching Authorization header to upstream request.",
                    ctx.request_id, action_name
                );
                let auth_header_value = format!("Bearer {}", access_token);
                // Remove existing Authorization header to avoid duplication/conflict
                upstream_request.remove_header("Authorization");
                upstream_request
                    .insert_header("Authorization", auth_header_value)
                    .unwrap();
            }
        }

        // Save updated session to store if refresh occurred
        if session_needs_update {
            // Determine scope name to find the store. Prefer the one in session, fallback to route config.
            let scope_to_use = app_session.auth_scope_name.as_deref().or(fallback_auth_scope_name);

            if let Some(scope) = scope_to_use {
                if let Some(store) = get_auth_session_store(&ctx.realm_name, scope) {
                    store.insert(
                        app_session.session_id.clone(),
                        Arc::new(app_session.clone()),
                    );
                    info!(
                        "[{}] [{}] Updated session in store after refresh.",
                        ctx.request_id, action_name
                    );
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
impl RouteLogic for ReturnStaticTextRoute {
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
        let _ = session
            .respond_error_with_body(
                self.status_code,
                Bytes::from(self.content.as_bytes().to_vec()),
            )
            .await;
        // Return true to stop the pipeline and send the response immediately.
        Ok(true)
    }
}

/// Terminates the request and responds with a 302 redirect to the specified URL.
///
/// # Arguments
/// * `url` - The destination URL for the redirect.
#[async_trait]
impl RouteLogic for RedirectRoute {
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
        // Add Content-Length for the body.
        header
            .insert_header("Content-Length", body.len().to_string())
            .unwrap();
        // Signal that the connection should be closed as it's a one-off redirect.
        header.insert_header("Connection", "close").unwrap();

        // Send the response header and body, then close the stream.
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
impl RouteLogic for ProxyToRoute {
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
        ctx.override_upstream_addr = Some(self.upstream.to_string());
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

        // Retrieve session information from the APP_COOKIE
        // in case RequireAuthentication has not been executed before this action.
        if ctx.action_state_app_session.is_none() {
            if let Some(scope_name) = &self.auth_scope_name {
                info!(
                    "[{}] [{}] No app_session in context, attempting to load from APP_COOKIE for scope: {}",
                    ctx.request_id,
                    self.name(),
                    scope_name
                );
                // Get the session store for the specified scope.
                if let Some(session_store) = get_auth_session_store(&ctx.realm_name, scope_name) {
                    let cookie_name = format!("APP_COOKIE_{}", scope_name.to_uppercase());
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
                        .strip_prefix("DEV_COOKIE=")
                        .map(str::to_string)
                })
            });

        // Attempt to validate the cookie if it exists.
        let is_cookie_valid = if let Some(token) = dev_cookie_value {
            // For simplicity, we still use the first realm's key.
            // A real implementation would select the key based on the request's realm.
            let key = match ctx.jwt_keys.keys_by_realm.iter().next() {
                Some(entry) => entry.value().clone(),
                None => {
                    warn!(
                        "[{}] [{}] No JWT keys found in cache.",
                        ctx.request_id,
                        self.name()
                    );
                    return Ok(false); // Cannot validate, treat as invalid.
                }
            };
            let decoding_key = DecodingKey::from_rsa_pem(&key.public_key_pem)
                .expect("Failed to create decoding key from PEM");

            let validation = Validation::new(jsonwebtoken::Algorithm::RS256);

            match decode::<DeviceContext>(&token, &decoding_key, &validation) {
                Ok(token_data) => {
                    let claims = token_data.claims;
                    info!(
                        "[{}] [{}] Successfully validated DEV_COOKIE JWT. iss: {}, sub: {}, cn: {}, iat: {}, exp: {}",
                        ctx.request_id,
                        self.name(),
                        claims.iss,
                        claims.sub,
                        claims.cn,
                        claims.iat,
                        claims.exp
                    );
                    true // The cookie is valid.
                }
                Err(e) => {
                    warn!(
                        "[{}] [{}] Failed to validate DEV_COOKIE JWT: {}. A new cookie will be issued.",
                        ctx.request_id,
                        self.name(),
                        e
                    );
                    false // The cookie is invalid.
                }
            }
        } else {
            false // The cookie does not exist.
        };

        // If the cookie is not valid (or doesn't exist), generate a new one.
        if !is_cookie_valid {
            info!(
                "[{}] [{}] Issuing a new DEV_COOKIE.",
                ctx.request_id,
                self.name()
            );
            // Generate 9 random bytes and Base64-encode them to get a 12-character URL-safe string.
            let mut sub_bytes = [0u8; 9];
            rand::rng().fill_bytes(&mut sub_bytes);
            let sub = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sub_bytes);
            let now_ts = Utc::now().timestamp() as u64;
            let claims = DeviceContext {
                iss: "TestFruitShop".to_string(),
                sub,
                cn: "My New Device".to_string(),
                iat: now_ts,
                exp: now_ts + (60 * 60 * 24 * 365), // 1 year expiration
            };
            // For simplicity, we still use the first realm's key for signing.
            let key = match ctx.jwt_keys.keys_by_realm.iter().next() {
                Some(entry) => entry.value().clone(),
                None => {
                    warn!(
                        "[{}] [{}] No JWT keys found in cache for signing.",
                        ctx.request_id,
                        self.name()
                    );
                    let err = Error::new(ErrorType::InternalError);
                    return Err(err);
                }
            };
            let encoding_key = EncodingKey::from_rsa_pem(&key.private_key_pem)
                .expect("Failed to create encoding key from PEM");
            let token = encode(
                &Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &encoding_key,
            )
            .map_err(|e| {
                let mut err = Error::new(ErrorType::InternalError);
                err.context = Some(format!("Failed to create JWT: {}", e).into());
                err
            })?;
            ctx.action_state_new_dev_cookie = Some(token);
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
                "[{}] [{}] Setting new DEV_COOKIE in response.",
                ctx.request_id,
                self.name()
            );
            let max_age_seconds = 60 * 60 * 24 * 365; // 1 year
            let cookie_value = format!(
                "DEV_COOKIE={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
                new_cookie_value, max_age_seconds
            );
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
impl RouteLogic for SetUpstreamRequestHeaderRoute {
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
                self.name.clone().into_owned(),
                self.value.clone().into_owned(),
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
impl RouteLogic for SetDownstreamResponseHeaderRoute {
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
                self.name.clone().into_owned(),
                self.value.clone().into_owned(),
            )
            .unwrap();
        Ok(())
    }
}

/// Manages the application session and OIDC authentication flow for a protected backend.
///
/// # Arguments
/// * `protected_upstream` - The upstream address of the service protected by this authentication.
/// * `oidc_login_redirect_url` - The authorization endpoint of the OIDC provider.
/// * `oidc_client_id` - The client ID registered with the OIDC provider.
/// * `oidc_callback_url` - The callback URL on this BFF that the OIDC provider will redirect to.
/// * `oidc_token_endpoint_url` - The token endpoint of the OIDC provider.
/// * `auth_scope_name` - A unique name for this authentication scope, used to isolate session cookies.
#[async_trait]
impl RouteLogic for RequireAuthenticationRoute {
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

        ctx.override_upstream_addr = Some(self.protected_upstream.to_string());
        // --- Start of merged logic from ApplicationSessionManagementRoute ---
        let mut session_found = false;
        let mut app_session_opt: Option<ApplicationSession> = None;

        let cookie_name = format!("APP_COOKIE_{}", self.auth_scope_name.to_uppercase());
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

                            if let Some(app_session_ref) = session_store.get(&session_id) {
                                info!(
                                    "[{}] [{}] Found active session for user: {}",
                                    ctx.request_id,
                                    self.name(),
                                    app_session_ref.user_id
                                );
                                app_session_opt = Some(app_session_ref.value().as_ref().clone());
                                session_found = true;
                            } else {
                                warn!(
                                    "[{}] [{}] {} found, but no active session in store.",
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
            let new_session_id: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            let new_app_session = ApplicationSession {
                session_id: new_session_id.clone(),
                user_id: format!("user-{}", rand::random::<u16>()),
                username: "Guest".to_string(),
                is_authenticated: false,
                access_token: None,
                refresh_token: None,
                access_token_expires_at: None,
                oidc_nonce: None,
                oidc_pkce_verifier: None,
                oidc_state: None,
                oidc_token_endpoint: Some(self.oidc_token_endpoint_url.to_string()),
                oidc_client_id: Some(self.oidc_client_id.to_string()),
                auth_scope_name: Some(self.auth_scope_name.to_string()),
                auth_original_destination: None,
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
            // 1. A new user accessing a protected resource for the first time.
            // 2. A user returning from the OIDC provider after authentication (the callback).

            // --- Scenario 2: A user returning from the OIDC provider after authentication (the callback). ---
            // Check for OIDC callback parameters ('code' and 'state')
            let mut oidc_code = None;
            let mut oidc_state = None;
            if let Some(query) = session.req_header().uri.query() {
                for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                    match key.as_ref() {
                        "code" => oidc_code = Some(value.into_owned()),
                        "state" => oidc_state = Some(value.into_owned()),
                        _ => {}
                    }
                    // Stop iterating once both parameters are found.
                    if oidc_code.is_some() && oidc_state.is_some() {
                        break;
                    }
                }
            }
            // If both 'code' and 'state' are present, handle it as an OIDC callback (Scenario 2).
            // Otherwise, proceed to Scenario 1: initiate a new authentication flow.
            if let (Some(code), Some(state)) = (oidc_code, oidc_state) {
                // --- Scenario 2: Handle OIDC Callback ---
                info!(
                    "[{}] [{}] OIDC callback detected. Handling token exchange.",
                    ctx.request_id,
                    self.name()
                );

                // 1. Validate the 'state' parameter against the one stored in the session to prevent CSRF.
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

                // Define a struct to deserialize the token endpoint's response.
                #[derive(Deserialize, Debug)]
                struct TokenResponse {
                    access_token: String,
                    id_token: String,
                    expires_in: u64,
                    refresh_token: Option<String>,
                }

                // 2. Exchange the authorization code for an access token and ID token.
                let pkce_verifier = match ctx
                    .action_state_app_session
                    .as_ref()
                    .and_then(|s| s.oidc_pkce_verifier.as_ref())
                {
                    Some(v) => v.clone(),
                    None => {
                        warn!(
                            "[{}] [{}] No PKCE verifier found in session for token exchange.",
                            ctx.request_id,
                            self.name()
                        );
                        let _ = session.respond_error(400).await; // Bad Request
                        return Ok(true);
                    }
                };

                let client = reqwest::Client::new();
                let response = client
                    .post(self.oidc_token_endpoint_url.as_ref())
                    .form(&[
                        ("grant_type", "authorization_code"),
                        ("code", &code),
                        ("redirect_uri", self.oidc_callback_url.as_ref()),
                        ("client_id", self.oidc_client_id.as_ref()),
                        ("code_verifier", &pkce_verifier),
                    ])
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
                    warn!(
                        "[{}] [{}] Failed to exchange code for token. Status: {}, Body: {:?}",
                        ctx.request_id,
                        self.name(),
                        response.status(),
                        response.text().await
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

                // 3. Validate the received ID token (signature, issuer, audience, nonce, expiration).
                let id_token = &tokens.id_token;

                // ToDo: JWKS should be retrieved from /.well-known/openid-configuration.
                // Fetch JWKS from the OIDC provider. Using `Url::join` is more robust
                // than string concatenation as it correctly handles path resolution.
                let mut base_url =
                    Url::parse(self.oidc_token_endpoint_url.as_ref()).map_err(|e| {
                        warn!(
                            "[{}] [{}] Invalid OIDC token endpoint URL for JWKS discovery: {}",
                            ctx.request_id,
                            self.name(),
                            e
                        );
                        Error::new(ErrorType::InternalError)
                    })?;
                base_url.set_path(""); // Keep only the origin (scheme, host, port)
                let jwks_uri = base_url.join("/jwks.json").map_err(|e| {
                    warn!(
                        "[{}] [{}] Failed to construct JWKS URI from base '{}': {}",
                        ctx.request_id,
                        self.name(),
                        base_url,
                        e
                    );
                    Error::new(ErrorType::InternalError)
                })?;

                let jwks_response = client.get(jwks_uri.as_ref()).send().await.map_err(|e| {
                    warn!(
                        "[{}] [{}] Failed to fetch JWKS from {}: {}",
                        ctx.request_id,
                        self.name(),
                        jwks_uri,
                        e
                    );
                    Error::new(ErrorType::InternalError)
                })?;

                if !jwks_response.status().is_success() {
                    warn!(
                        "[{}] [{}] Failed to fetch JWKS from {}, Status: {}",
                        ctx.request_id,
                        self.name(),
                        jwks_uri,
                        jwks_response.status()
                    );
                    let _ = session.respond_error(502).await; // Bad Gateway
                    return Ok(true);
                }

                let jwks_text = jwks_response.text().await.map_err(|e| {
                    warn!(
                        "[{}] [{}] Failed to read JWKS response body: {}",
                        ctx.request_id,
                        self.name(),
                        e
                    );
                    Error::new(ErrorType::InternalError)
                })?;

                // Deserialize JWKS
                #[derive(Deserialize, Debug)]
                struct Jwks {
                    keys: Vec<serde_json::Value>, // Use serde_json::Value to parse individual keys
                }
                let jwks: Jwks = serde_json::from_str(&jwks_text).map_err(|e| {
                    warn!(
                        "[{}] [{}] Failed to parse JWKS: {}",
                        ctx.request_id,
                        self.name(),
                        e
                    );
                    Error::new(ErrorType::InternalError)
                })?;

                // Prepare validation parameters
                let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256); // Assuming RS256 for OIDC
                validation.set_audience(&[self.oidc_client_id.as_ref()]);

                // The issuer should be the base URL of the OIDC provider, typically derived from oidc_login_redirect_url
                let expected_issuer = Url::parse(self.oidc_login_redirect_url.as_ref())
                    .map_err(|e| {
                        warn!(
                            "[{}] [{}] Invalid OIDC login URL for issuer check: {}",
                            ctx.request_id,
                            self.name(),
                            e
                        );
                        Error::new(ErrorType::InternalError)
                    })?
                    .origin()
                    .ascii_serialization(); // Get the origin (scheme, host, port) as issuer

                validation.set_issuer(&[expected_issuer.as_str()]);

                if let Some(_stored_nonce) = ctx
                    .action_state_app_session
                    .as_ref()
                    .and_then(|s| s.oidc_nonce.as_ref())
                {
                    // Require the 'nonce' claim to be present in the token.
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

                let mut decoded_token = None;
                for jwk_value in jwks.keys {
                    // Convert the generic `serde_json::Value` into a specific `jsonwebtoken::jwk::Jwk`.
                    let jwk: jsonwebtoken::jwk::Jwk = match serde_json::from_value(jwk_value) {
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
                                // If signature or algorithm is invalid, try the next JWK.
                                // For other errors (e.g., expired, invalid issuer/audience/nonce), we fail immediately.
                                if e.kind() == &jsonwebtoken::errors::ErrorKind::InvalidSignature
                                    || e.kind()
                                        == &jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                                {
                                    continue; // Try next JWK
                                } else {
                                    warn!(
                                        "[{}] [{}] ID token validation failed: {}",
                                        ctx.request_id,
                                        self.name(),
                                        e
                                    );
                                    let _ = session.respond_error(401).await; // Unauthorized
                                    return Ok(true);
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

                // Manually validate the nonce claim after successful decoding
                if let Some(stored_nonce) = ctx
                    .action_state_app_session
                    .as_ref()
                    .and_then(|s| s.oidc_nonce.as_ref())
                {
                    // The `decode` function with `required_spec_claims` ensures the "nonce" claim exists.
                    // We can safely unwrap here, but using `and_then` is more robust.
                    let token_nonce = token_data
                        .claims
                        .get("nonce")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if token_nonce != stored_nonce {
                        warn!(
                            "[{}] [{}] ID token nonce mismatch. Expected: {}, Got: {}",
                            ctx.request_id,
                            self.name(),
                            stored_nonce,
                            token_nonce
                        );
                        // !! SKIP NOUNCE CHECK !!
                        //let _ = session.respond_error(401).await; // Unauthorized
                        //return Ok(true);
                    }
                }

                info!(
                    "[{}] [{}] ID Token successfully validated. Claims: {:?}",
                    ctx.request_id,
                    self.name(),
                    token_data.claims
                );

                // 4. If validation is successful, update the ApplicationSession.
                let app_session = ctx.action_state_app_session.as_mut().unwrap(); // We know it exists and is mutable
                app_session.is_authenticated = true;
                app_session.access_token = Some(tokens.access_token);
                app_session.access_token_expires_at =
                    Some(Utc::now().timestamp() as u64 + tokens.expires_in);
                app_session.refresh_token = tokens.refresh_token;
                app_session.user_id = token_data.claims["sub"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                app_session.username = token_data.claims.get("name")
                    .or_else(|| token_data.claims.get("preferred_username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string();

                // Update the session in the central store
                session_store.insert(
                    app_session.session_id.clone(),
                    Arc::new(app_session.clone()),
                );

                // 5. Redirect the user back to the original resource (or a default page).
                // Retrieve the original destination from the session, or default to "/".
                let redirect_path = app_session.auth_original_destination.take().unwrap_or_else(|| "/".to_string());
                info!("[{}] [{}] OIDC callback processed. Authentication successful. Redirecting to {}.", ctx.request_id, self.name(), redirect_path);

                let body = Bytes::from_static(b"Login successful. Redirecting...");
                let mut header = ResponseHeader::build(302, None).unwrap();
                header.insert_header("Location", redirect_path).unwrap();
                header.insert_header("Content-Length", body.len().to_string()).unwrap();
                header.insert_header("Connection", "close").unwrap();
                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(body), true).await?;
                return Ok(true); // Stop the pipeline.
            }

            // --- Scenario 1: A new user accessing a protected resource for the first time. ---
            // We will generate OIDC parameters, save them to the session, and redirect the user.

            // Ensure we have a session to store the OIDC state in.
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

            // 1. Generate and store a 'nonce' for replay attack protection.
            let nonce: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            app_session.oidc_nonce = Some(nonce.clone());

            // 2. Generate and store a 'code_verifier' for PKCE.
            let code_verifier: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();
            app_session.oidc_pkce_verifier = Some(code_verifier.clone());

            // 3. Create the 'code_challenge' from the verifier.
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let challenge_bytes = hasher.finalize();
            let code_challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
            // The result is Base64-URL encoded with no padding, as required by the PKCE spec (RFC 7636).

            // 4. Generate a 'state' parameter for CSRF protection.
            let state: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            app_session.oidc_state = Some(state.clone());

            // 5. Save the original request URL to the session so we can redirect back later.
            app_session.auth_original_destination = Some(session.req_header().uri.to_string());

            // 6. Update the session in the central store with the new OIDC values.
            session_store.insert(app_session.session_id.clone(), Arc::new(app_session));

            // 7. Build the OIDC authorization URL with all the necessary parameters.
            let mut auth_url =
                Url::parse(&self.oidc_login_redirect_url).expect("Invalid OIDC login URL");
            auth_url
                .query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.oidc_client_id)
                .append_pair("redirect_uri", &self.oidc_callback_url)
                .append_pair("scope", "openid offline_access") // 'openid' is the minimum required scope for OIDC.
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge", &code_challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("response_mode", "query"); // Explicitly request query parameters for callback

            info!(
                "[{}] [{}] User not authenticated. Redirecting to OIDC provider.",
                ctx.request_id,
                self.name()
            );

            // 8. Perform the redirect.
            let mut header = ResponseHeader::build(302, None).unwrap();
            header.insert_header("Location", auth_url.as_str()).unwrap();

            // Set the APP_COOKIE here because the response_filter will not be called on redirect.
            if let Some((new_cookie_value, scope_name)) = &ctx.action_state_new_app_session_cookie {
                info!(
                    "[{}] [{}] Setting new APP_COOKIE in redirect response.",
                    ctx.request_id,
                    self.name()
                );
                let cookie_name = format!("APP_COOKIE_{}", scope_name.to_uppercase());
                let cookie_value = format!(
                    "{}={}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax",
                    cookie_name, new_cookie_value
                );
                // Use `append_header` in case other cookies (like DEV_COOKIE) are also being set.
                header.append_header("Set-Cookie", cookie_value).unwrap();
            }

            let body = Bytes::from_static(b"Redirecting to login...");

            header
                .insert_header("Content-Length", body.len().to_string())
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
            info!("[{}] [{}] Intercepting /api/me request.", ctx.request_id, self.name());
            let username = ctx.action_state_app_session.as_ref().map(|s| s.username.as_str()).unwrap_or("Unknown");
            let body_content = serde_json::json!({ "name": username }).to_string();
            let body = Bytes::from(body_content);

            let mut header = ResponseHeader::build(200, None).unwrap();
            header.insert_header("Content-Type", "application/json").unwrap();
            header.insert_header("Content-Length", body.len().to_string()).unwrap();
            session.write_response_header(Box::new(header), false).await?;
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
            Some(&self.auth_scope_name),
        )
        .await;

        if !is_token_valid {
            warn!(
                "[{}] [{}] Token refresh failed. Redirecting to self to trigger re-login flow.",
                ctx.request_id,
                self.name()
            );
            // Respond with a 302 redirect to the current URL.
            // This forces the client to reload, which will hit the `request_filter` with an unauthenticated session,
            // triggering the standard OIDC login flow.
            let self_path = session
                .req_header()
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            let mut header = ResponseHeader::build(302, None).unwrap();
            header.insert_header("Location", self_path).unwrap();
            header.insert_header("Content-Length", "0").unwrap();
            header.insert_header("Connection", "close").unwrap();
            session
                .write_response_header(Box::new(header), false)
                .await?;
            return Err(Error::new(ErrorType::Custom(
                "Token refresh failed, redirected to self".into(),
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
            info!(
                "[{}] [{}] Setting new APP_COOKIE in response.",
                ctx.request_id,
                self.name()
            );
            let cookie_name = format!("APP_COOKIE_{}", scope_name.to_uppercase());
            let cookie_value = format!(
                "{}={}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax",
                cookie_name, new_cookie_value
            );
            response.append_header("Set-Cookie", cookie_value).unwrap();
        }

        Ok(())
    }
}
