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
use crate::GatewayCtx;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use log::{info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::OnceLock;

/// A type alias for a session store, which is a thread-safe map from session IDs to ApplicationSession objects.
pub type SessionStore = Arc<DashMap<String, Arc<ApplicationSession>>>;

/// A global, thread-safe registry for authentication session stores, keyed by scope name.
static AUTH_SESSION_STORES: OnceLock<DashMap<String, SessionStore>> = OnceLock::new();

/// Registers a new authentication scope and initializes its session store.
/// This function should be called at application startup for each required scope.
/// It's idempotent; if a scope is already registered, it does nothing.
pub fn register_auth_scope(scope_name: &str) {
    AUTH_SESSION_STORES
        .get_or_init(DashMap::new)
        .entry(scope_name.to_string())
        .or_insert_with(|| Arc::new(DashMap::new()));
    info!("Authentication scope '{}' registered.", scope_name);
}

/// ApplicationSession object, as it's a core data model for the gateway.
#[derive(Debug, Clone)]
pub struct ApplicationSession {
    pub session_id: String,
    pub user_id: String,
    pub is_authenticated: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<u64>, // Unix timestamp
    pub oidc_nonce: Option<String>,
    pub oidc_pkce_verifier: Option<String>,
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
        protected_backend_addr: Cow<'static, str>,
        oidc_login_redirect_url: Cow<'static, str>,
        oidc_client_id: Cow<'static, str>,
        oidc_callback_url: Cow<'static, str>,
        oidc_token_endpoint_url: Cow<'static, str>,
        scope_name: Cow<'static, str>,
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
    pub protected_backend_addr: Cow<'static, str>,
    pub oidc_login_redirect_url: Cow<'static, str>,
    pub oidc_client_id: Cow<'static, str>,
    pub oidc_callback_url: Cow<'static, str>,
    pub oidc_token_endpoint_url: Cow<'static, str>,
    pub scope_name: Cow<'static, str>,
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
            let decoding_key = DecodingKey::from_rsa_pem(&ctx.jwt_keys.public_key_pem)
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
            let encoding_key = EncodingKey::from_rsa_pem(&ctx.jwt_keys.private_key_pem)
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
/// * `protected_backend_addr` - The upstream address of the service protected by this authentication.
/// * `oidc_login_redirect_url` - The authorization endpoint of the OIDC provider.
/// * `oidc_client_id` - The client ID registered with the OIDC provider.
/// * `oidc_callback_url` - The callback URL on this BFF that the OIDC provider will redirect to.
/// * `oidc_token_endpoint_url` - The token endpoint of the OIDC provider.
/// * `scope_name` - A unique name for this authentication scope, used to isolate session cookies.
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
        Ok(false) // Continue the pipeline
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut GatewayCtx,
    ) -> Result<()> {
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut GatewayCtx,
    ) -> Result<()> {
        Ok(())
    }
}
