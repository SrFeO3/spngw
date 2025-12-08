// spngw is a gateway system designed to work alongside the spn infrastructure system.
// It acts as an SNI-based TLS router for request/response routing and manipulation,
// and also serves as a BFF (Backend for Frontend) for SPAs (Single Page Applications)
// to enhance system simplicity and security.
//
// USAGE:
//   It requires certificate PEM files for each SNI to operate.
//   To run the gw with info-level logging:
//   RUST_LOG=info cargo run
//
// TODO:
//   - Allow operational settings to be configured externally.
//   - Implement /api/logout endpoint to invalidate session and tokens.
//   - Implement a lock for token refresh to prevent dog-piling effect.
//   - Review the backend SSL implementation for Pingora (currently using boringssl).

use arc_swap::ArcSwap;
use arc_swap::ArcSwapOption; // for Application session
use async_trait::async_trait;
use boring::ex_data::Index;
use bytes::Bytes;
use chrono::Utc;
use cookie::{Cookie, CookieJar};
use dashmap::DashMap;
use hex;
use hyper::Client;
use hyper::{
    Body, Method, Request, Uri,
    body::to_bytes,
    header::{COOKIE, SET_COOKIE},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use pingora::server::ShutdownWatch;
use pingora::server::configuration::Opt;
use pingora::services::background::BackgroundService;
use pingora::tls::pkey::Private;
use pingora::tls::ssl::Ssl;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::SystemTime;
use std::time::{Duration, Instant};
use uuid::Uuid;

use log::{info, warn, error};

/// Holds the application's cryptographic keys.
///
/// A single instance of this struct is created at startup, wrapped in an `Arc`,
/// and shared across all threads. It contains the PEM-encoded key pair used for
/// signing and validating JWTs (e.g., `DEVICE_CONTEXT`).
struct JwtSigningKeys {
    public_key_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

impl JwtSigningKeys {
    fn new() -> Self {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
        let public_key = private_key.to_public_key();
        let public_key_pem = public_key
            .to_pkcs1_pem(Default::default())
            .expect("Failed to encode public key to PEM")
            .as_bytes()
            .to_vec();
        let private_key_pem = private_key
            .to_pkcs8_pem(Default::default())
            .expect("Failed to encode private key to PEM")
            .as_bytes()
            .to_vec();
        JwtSigningKeys {
            public_key_pem,
            private_key_pem,
        }
    }
}

type SessionStore = Arc<DashMap<String, Arc<ApplicationSession>>>;
// NEW pub type SessionStore = Arc<RwLock<HashMap<String, ApplicationSession>>>;

/// Represents a user's application-level session.
///
/// An instance of this struct is created for each unique client session, identified
/// by the `SPN_SESSION` cookie. It stores session-specific data such as OAuth
/// tokens and activity metadata.
///
/// Instances are stored in a shared `DashMap` and are managed by a background
/// service (`SessionPurger`) that removes them after a TTL. Each instance is
/// wrapped in an `Arc` to be safely shared.
struct ApplicationSession {
    counter: AtomicUsize,     //　For demonstration, let's just store a counter.
    _created_at: Instant,     // May not be necessary.
    last_accessed: AtomicU64, // seconds since START_TIME for lock-free updates.
    access_token: ArcSwapOption<String>,
    refresh_token: ArcSwapOption<String>,
    access_token_expires_at: ArcSwapOption<SystemTime>,
}

/// A container for all upstream peer definitions.
///
/// This struct centralizes the management of different upstream categories:
/// - `sni_map`: A map for SNI-based and path-based routing lookups.
/// - `no_sni`: The default upstream for requests without an SNI header.
/// - `fallback`: The default upstream for requests with an unrecognized SNI.
struct UpstreamSet {
    sni_map: Arc<DashMap<String, Arc<HttpPeer>>>,
    no_sni: Arc<HttpPeer>,
    fallback: Arc<HttpPeer>,
}

/// The core logic and shared state for the proxy service.
///
/// This struct implements the `ProxyHttp` trait and holds all shared resources
/// required for request processing, such as upstream server definitions, the
/// session map, and cryptographic keys.
///
/// It manages two primary forms of client state via cookies:
/// - **Application Session**: A stateful session identified by the `MY_APP_SESSION`
///   cookie, storing server-side data like OAuth tokens in `session_store`.
/// - **Device Cookie**: A stateless JWT (`DEVICE_CONTEXT`) used to identify a
///   client device or browser instance, signed using keys from `JwtSigningKeys`.
///
/// A single instance is created at startup and shared immutably across all
/// worker threads for the lifetime of the application.
struct GatewayRouter {
    session_store: SessionStore,
    upstreams: UpstreamSet,
    sni_ex_data_index: Index<Ssl, Option<String>>,
    keys: Arc<JwtSigningKeys>,
    start_time: Instant,
}

/// A custom context that holds state for a single HTTP request.
///
/// An instance of this struct is created for each request via `ProxyHttp::new_ctx()`
/// and is passed through the different phases of the request proxying lifecycle
/// (e.g., `request_filter`, `upstream_peer`). Its lifetime is tied to a single
/// request-response cycle.
pub struct GatewayCtx {
    // A reference to the shared session store.
    session_store: SessionStore,
    start_time: Instant,
    upstream_sni_name: Option<String>,
    session_id: Option<String>,
    app_session_is_new: bool,
    device_context_is_new: bool,
}

/// Claims for the device context JWT
#[derive(Debug, Serialize, Deserialize)]
struct DeviceContext {
    iss: String, // Issuer
    sub: String, // Subject (device/session ID)
    iat: u64,    // Issued At
    exp: u64,    // Expiration Time
}

impl GatewayRouter {
    /// Verifies the application-level session from the incoming request.
    ///
    /// This function inspects the `SPN_SESSION` cookie.
    /// - If a valid, active session is found, it updates the context (`ctx`) with the
    ///   session ID and sets `is_new` to `false`.
    /// - If no cookie is found, or the session is invalid/expired, it generates a
    ///   *new* session ID, updates the context, and sets `is_new` to `true`.
    ///
    /// Note: This function *does not* create the session object in the shared map;
    /// that is deferred to `create_application_session_if_new` in the response phase.
    fn verify_application_session(&self, session: &Session, ctx: &mut GatewayCtx) {
        let cookie_value = session
            .get_header("Cookie")
            .and_then(|header| header.to_str().ok())
            .and_then(|cookie_str| {
                cookie_str
                    .split(';')
                    .find_map(|s| Cookie::parse(s.trim()).ok())
                    .and_then(|cookie| {
                        if cookie.name() == "SPN_SESSION" {
                            Some(cookie.value().to_string())
                        } else {
                            None
                        }
                    })
            });

        if let Some(sid) = cookie_value {
            if sid.len() == 32 && ctx.session_store.contains_key(&sid) {
                if let Some(data) = ctx.session_store.get(&sid) {
                    info!(
                        "Application Session SPN_SESSION: Existing session found: {}",
                        sid
                    );
                    ctx.session_id = Some(sid);
                    ctx.app_session_is_new = false;
                    let secs_since_start = Instant::now().duration_since(self.start_time).as_secs();
                    data.last_accessed
                        .store(secs_since_start, Ordering::Relaxed);
                    data.counter.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
            warn!(
                "Application Session SPN_SESSION: Session ID '{}' from cookie is invalid or not found. A new session will be created.",
                sid
            );
        } else {
            info!(
                "Application Session SPN_SESSION: No valid cookie found. A new session will be created."
            );
        }

        // If we reach here, we need a new session. Generate a new ID and mark it for creation.
        let mut new_sid_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut new_sid_bytes);
        let new_sid = hex::encode(new_sid_bytes);

        info!(
            "Application Session SPN_SESSION: Generated new session ID for pending creation: {}",
            new_sid
        );
        ctx.session_id = Some(new_sid);
        ctx.app_session_is_new = true;
    }

    /// Creates a new application session and issues a cookie if the session is new.
    ///
    /// This function is called from `response_filter`. It checks the `is_new` flag in
    /// the context. If true, it creates a new `ApplicationSession`, inserts it into
    /// the shared map, and adds a `Set-Cookie` header to the upstream response.
    fn create_application_session_if_new(
        &self,
        ctx: &GatewayCtx,
        upstream_response: &mut ResponseHeader,
    ) -> Result<()> {
        if !ctx.app_session_is_new {
            return Ok(());
        }

        let new_sid = ctx
            .session_id
            .as_ref()
            .ok_or_else(|| Error::new_str("New session is missing session ID"))?
            .as_str();

        let now = Instant::now();
        let secs_since_start = now.duration_since(self.start_time).as_secs();
        let app_session = Arc::new(ApplicationSession {
            counter: AtomicUsize::new(1),
            _created_at: now,
            last_accessed: AtomicU64::new(secs_since_start),
            access_token: ArcSwapOption::from(None),
            refresh_token: ArcSwapOption::from(None),
            access_token_expires_at: ArcSwapOption::from(None),
        });
        ctx.session_store
            .insert(new_sid.to_string(), app_session);

        // Issue session cookie
        let cookie_header = format!(
            "SPN_SESSION={}; Path=/; HttpOnly; Secure; SameSite=Lax",
            new_sid
        );
        info!("Setting new HTTP session cookie: {}", &cookie_header);
        upstream_response.insert_header("Set-Cookie", cookie_header)?;

        // Log all current session IDs
        let session_ids: Vec<String> = self
            .session_store
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        info!(
            "Application Session SPN_SESSION: Current active sessions ({}): {:?}",
            session_ids.len(),
            session_ids
        );

        Ok(())
    }

    /// Verifies the `DEVICE_CONTEXT` JWT cookie.
    ///
    /// This function is called from `request_filter`. It checks for the presence of
    /// the `DEVICE_CONTEXT` cookie. If found, it validates the JWT's signature and
    /// claims. If validation fails (e.g., invalid signature, expired), it sets a
    /// flag in the `GatewayCtx` to signal that a new cookie should be issued.
    fn verify_device_cookie(&self, session: &Session, ctx: &mut GatewayCtx) {
        let jwt_cookie_value = session.get_header("Cookie").and_then(|c| {
            c.to_str().ok().and_then(|cookie_str| {
                cookie_str.split(';').find_map(|s| {
                    Cookie::parse(s.trim())
                        .ok()
                        .filter(|c| c.name() == "DEVICE_CONTEXT")
                        .map(|c| c.value().to_string())
                })
            })
        });

        if let Some(token) = jwt_cookie_value {
            let decoding_key = DecodingKey::from_rsa_pem(&self.keys.public_key_pem)
                .expect("Failed to create decoding key from PEM");
            match decode::<DeviceContext>(
                &token,
                &decoding_key,
                &Validation::new(jsonwebtoken::Algorithm::RS256),
            ) {
                Ok(token_data) => {
                    let claims = token_data.claims;
                    info!(
                        "Successfully validated DEVICE_CONTEXT JWT. iss: {}, sub: {}, iat: {}, exp: {}",
                        claims.iss,
                        claims.sub,
                        claims.iat,
                        claims.exp
                    );
                }
                Err(e) => {
                    warn!("Failed to validate DEVICE_CONTEXT JWT: {}", e);
                    ctx.device_context_is_new = true;
                }
            }
        }
    }

    /// Issues a new `DEVICE_CONTEXT` cookie if one is not present or is invalid.
    ///
    /// This function is called from `response_filter`. It generates a new JWT,
    /// sets it in a `Set-Cookie` header with a 1-year expiration, and adds it
    /// to the upstream response.
    fn issue_device_cookie(&self, upstream_response: &mut ResponseHeader) -> Result<()> {
        let now_ts = Utc::now().timestamp() as u64;
        let claims = DeviceContext {
            iss: "TestFruitShop".to_string(),
            sub: Uuid::new_v4().to_string(),
            iat: now_ts,
            exp: now_ts + (60 * 60 * 24 * 365), // 1 year expiration
        };
        let encoding_key = EncodingKey::from_rsa_pem(&self.keys.private_key_pem)
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
        let max_age_seconds = 60 * 60 * 24 * 365; // 1 year
        let jwt_cookie_header = format!(
            "DEVICE_CONTEXT={}; Path=/; Secure; SameSite=Lax; Max-Age={}",
            token, max_age_seconds
        );
        info!("Setting new JWT cookie.");
        upstream_response.append_header("Set-Cookie", jwt_cookie_header)?;
        Ok(())
    }
}

#[async_trait]
impl ProxyHttp for GatewayRouter {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx {
            session_store: Arc::clone(&self.session_store),
            start_time: Instant::now(),
            upstream_sni_name: None,
            session_id: None,
            app_session_is_new: false,
            device_context_is_new: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Get SNI from the ex_data stored during the TLS handshake and set to no_sni_upstream.sni.
        // This is the earliest point where we can determine the upstream based on SNI.
        let sni_opt = session
            .stream()
            .unwrap()
            .get_ssl()
            .and_then(|ssl| ssl.ex_data(self.sni_ex_data_index));
        //let sni: Option<&str> = sni_opt.and_then(Option::as_deref);
        let sni: Option<String> = sni_opt.and_then(|s| s.as_deref().map(String::from));

        let upstream_sni_name = match sni.as_deref() {
            Some(sni_name) => {
                info!("SNI found: {}. Looking for specific upstream.", sni_name);
                // For bff.example.com, we just pass the SNI name to upstream_peer for path-based routing.
                // For other SNIs, we check if a specific upstream exists.
                if sni_name == "bff.wgd.example.com" || self.upstreams.sni_map.contains_key(sni_name) {
                    sni_name.to_string()
                } else {
                    self.upstreams.fallback.sni.clone()
                }
            }
            None => {
                info!("No SNI found. Using no-SNI upstream.");
                self.upstreams.no_sni.sni.clone()
            }
        };
        ctx.upstream_sni_name = Some(upstream_sni_name);

        // First, ensure the application session is handled for all requests.
        self.verify_application_session(session, ctx);

        // SAMPLE REQ-1 BFF get token
        if session.req_header().method == "POST" && session.req_header().uri.path() == "/api/token"
        {
            info!("Received POST request for /api/token. Reading body...");

            // Read the entire request body.
            // This consumes the body. Since we are responding directly, we don't need to put it back.
            if let Some(body_bytes) = session.read_request_body().await? {
                info!("Request body read, size: {} bytes.", body_bytes.len());

                // Parse the application/x-www-form-urlencoded body
                // Parse into a HashMap to display all key-value pairs.
                if let Ok(form_data) =
                    serde_urlencoded::from_bytes::<HashMap<String, String>>(&body_bytes)
                {
                    info!("[BFF] Received form data for /api/token:");
                    for (key, value) in &form_data {
                        info!("[BFF] front -> bff   {}: {}", key, value);
                    }

                    // Convert HashMap to slice of tuples for the function call
                    let form_data_slice: Vec<(&str, &str)> = form_data
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();

                    // Send the form data to the auth server
                    info!(
                        "[BFF] Fetching form data to http://192.168.10.132:8082/api/token"
                    );
                    match send_form_post_request(
                        "http://192.168.10.132:8082/api/token",
                        &[],               // No extra headers
                        &CookieJar::new(), // No cookies
                        &form_data_slice,
                    )
                    .await
                    {
                        Ok((resp, _cookies)) => {
                            info!("[BFF] Auth server response status: {}", resp.status());
                            // Read response body
                            let body_bytes = to_bytes(resp.into_body()).await.unwrap_or_default();
                            match serde_json::from_slice::<HashMap<String, serde_json::Value>>(
                                &body_bytes,
                            ) {
                                Ok(json_body) => {
                                    info!("[BFF] Parsed auth server JSON response.");

                                    // extract access_token, id_token, refresh_token, token_type, expires_in
                                    let access_token =
                                        json_body.get("access_token").and_then(|v| v.as_str());
                                    let id_token =
                                        json_body.get("id_token").and_then(|v| v.as_str());
                                    let refresh_token =
                                        json_body.get("refresh_token").and_then(|v| v.as_str());
                                    let token_type =
                                        json_body.get("token_type").and_then(|v| v.as_str());
                                    let expires_in =
                                        json_body.get("expires_in").and_then(|v| v.as_u64());
                                    let scope = json_body.get("scope").and_then(|v| v.as_str());

                                    //use std::time::{Duration, SystemTime, UNIX_EPOCH};
                                    let expires_at = expires_in.and_then(|secs| {
                                        SystemTime::now().checked_add(Duration::from_secs(secs))
                                    });

                                    info!(
                                        "[BFF] Extracted tokens: access_token: {:?}, id_token: {:?}, refresh_token: {:?}, token_type: {:?}, expires_in: {:?}, scope: {:?}, expires_at: {:?}",
                                        access_token,
                                        id_token,
                                        refresh_token,
                                        token_type,
                                        expires_in,
                                        scope,
                                        expires_at
                                    );

                                    if let Some(token) =
                                        json_body.get("access_token").and_then(|v| v.as_str())
                                    {
                                        //app_session.access_token.store(Some(Arc::new(token.to_string())));
                                        //access_token = token;
                                        //info!("[BFF] Storing access_token {}.", token);
                                        if let Some(sid) = &ctx.session_id {
                                            if let Some(app_session) =
                                                ctx.session_store.get(sid)
                                            {
                                                app_session
                                                    .access_token
                                                    .store(Some(Arc::new(token.to_string())));
                                                app_session.refresh_token.store(Some(Arc::new(
                                                    refresh_token.unwrap().to_string(),
                                                )));
                                                app_session
                                                    .access_token_expires_at
                                                    .store(expires_at.map(Arc::new));
                                                info!(
                                                    "[BFF] Stored access_token, expires_at, refresh_token stored at session {}",
                                                    sid
                                                );
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "[BFF] No access_token found in auth server response."
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "[BFF] Failed to parse auth server response as JSON: {}",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("[BFF] Error sending request to auth server: {}", e);
                        }
                    }
                } else {
                    warn!("Failed to parse token request form.");
                }
            } else {
                info!("POST request to /api/token had no body.");
            }

            // Return only "OK" or "NG" to the SPA JavaScript.
            // Send a simple response and terminate the session.
            let body =
                r#"{"status": "ok", "message": "Token request processed by BFF"}"#.as_bytes();
            let mut resp = ResponseHeader::build(200, None)?;
            resp.insert_header("Content-Type", "application/json")?;
            resp.insert_header("Content-Length", body.len().to_string())?;
            resp.insert_header(
                "Access-Control-Allow-Origin",
                "https://bff.wgd.example.com:8000",
            )?; // BFF ORIGIN!!!
            resp.insert_header("Access-Control-Allow-credentials", "true")?; // BFF ORIGIN!!!

            // Write header, end_of_stream=false because we will write a body
            session.write_response_header(Box::new(resp), false).await?;
            // Write body, end_of_stream=true to finish the response
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
        }

        // SAMPLE REQ-2
        // Block requests to www1.example.com and return a direct response.
        if ctx.upstream_sni_name.as_deref() == Some("www1.example.com") {
            warn!("Blocking NO SNI request as per policy");
            let body = "NO SNI Request is blocked by the proxy.";
            let mut resp = ResponseHeader::build(403, None)?; // 403 Forbidden is more appropriate
            resp.insert_header("Content-Type", "text/plain")?;
            resp.insert_header("Content-Length", body.len().to_string())?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            // Return Ok(true) to signal that the proxy session should be terminated.
            return Ok(true);
        }

        // SAMPLE REQ-3 CORS
        // CORS preflight request handling
        if session.req_header().method == "OPTIONS"
            && session
                .get_header("Access-Control-Request-Method")
                .is_some()
        {
            info!("Handling CORS preflight request");
            let mut resp = ResponseHeader::build(204, None)?;

            // For this example, we reflect the request's Origin header.
            // In a production environment, you should validate this against a whitelist.
            if let Some(origin) = session.get_header("Origin") {
                resp.insert_header("Access-Control-Allow-Origin", origin.clone())?;
                // The `Vary` header is important for caching to work correctly.
                resp.insert_header("Vary", "Origin")?;
            } else {
                // As a fallback, allow any origin.
                resp.insert_header("Access-Control-Allow-Origin", "*")?;
            }

            resp.insert_header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, PATCH, OPTIONS",
            )?;

            // Allow all headers requested by the client.
            if let Some(req_headers) = session.get_header("Access-Control-Request-Headers") {
                resp.insert_header("Access-Control-Allow-Headers", req_headers.clone())?;
            }

            resp.insert_header("Access-Control-Max-Age", "86400")?; // 24 hours

            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
        }

        // SAMPLE REQ-4 DEVICE_CONTEXT JWT Cookie
        //  verify only here ... issue on response_filter
        self.verify_device_cookie(session, ctx);

        // [BFF] Add Authorization header for /api/* requests
        info!("[BFF] API call ... adding token");
        if let Some(sni_name) = &sni {
            if sni_name == "bff.wgd.example.com"
                && session.req_header().uri.path().starts_with("/api")
            {
                if let Some(sid) = &ctx.session_id {
                    info!("[BFF] API call ... session id {}", sid);
                    if let Some(app_session) = ctx.session_store.get(sid) {
                        info!("[BFF] API call ... app_session exists");
                        if let Some(access_token_arc) = app_session.access_token.load_full() {
                            // Check if the access token is expired
                            if let Some(expires_at_arc) =
                                app_session.access_token_expires_at.load_full()
                            {
                                let expires_at = *expires_at_arc;
                                let now = SystemTime::now();
                                let remaining_secs = expires_at
                                    .duration_since(now)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or_else(|e| -(e.duration().as_secs() as i64));

                                if now < expires_at {
                                    info!(
                                        "[BFF] Access token is valid. Expires at: {:?}, Now: {:?}, Diff: {:?}",
                                        expires_at,
                                        now,
                                        remaining_secs
                                    );
                                } else {
                                    warn!(
                                        "[BFF] Access token has expired. Expired at: {:?}, Now: {:?},  Diff: {:?}",
                                        expires_at,
                                        now,
                                        remaining_secs
                                    );

                                    // Attempt to refresh the token
                                    if let Some(refresh_token_arc) =
                                        app_session.refresh_token.load_full()
                                    {
                                        let refresh_token_str = &*refresh_token_arc;
                                        let form_data_slice = [
                                            ("grant_type", "refresh_token"),
                                            ("refresh_token", refresh_token_str),
                                            ("client_id", "fruit-shop"),
                                        ];

                                        info!(
                                            "[BFF] Refreshing token. Fetching form data to http://192.168.10.132:8082/api/token"
                                        );
                                        match send_form_post_request(
                                            "http://192.168.10.132:8082/api/token",
                                            &[],               // No extra headers
                                            &CookieJar::new(), // No cookies
                                            &form_data_slice,
                                        )
                                        .await
                                        {
                                            Ok((resp, _cookies)) => {
                                                info!(
                                                    "[BFF] Auth server response status for refresh: {}",
                                                    resp.status()
                                                );
                                                // Read response body and update session tokens
                                                let body_bytes = to_bytes(resp.into_body())
                                                    .await
                                                    .unwrap_or_default();
                                                if let Ok(json_body) = serde_json::from_slice::<
                                                    HashMap<String, serde_json::Value>,
                                                >(
                                                    &body_bytes
                                                ) {
                                                    info!(
                                                        "[BFF] Parsed token refresh response."
                                                    );
                                                    // Update access token, refresh token (if rotated), and expiration
                                                    let new_access_token = json_body
                                                        .get("access_token")
                                                        .and_then(|v| v.as_str());
                                                    let new_refresh_token = json_body
                                                        .get("refresh_token")
                                                        .and_then(|v| v.as_str());
                                                    let expires_in = json_body
                                                        .get("expires_in")
                                                        .and_then(|v| v.as_u64());
                                                    let new_expires_at =
                                                        expires_in.and_then(|secs| {
                                                            SystemTime::now().checked_add(
                                                                Duration::from_secs(secs),
                                                            )
                                                        });

                                                    info!(
                                                        "[BFF] Refreshed tokens: new_access_token: {:?}, new_refresh_token: {:?}, expires_in: {:?}, new_expires_at: {:?}",
                                                        new_access_token,
                                                        new_refresh_token,
                                                        expires_in,
                                                        new_expires_at
                                                    );

                                                    app_session.access_token.store(
                                                        new_access_token
                                                            .map(|s| Arc::new(s.to_string())),
                                                    );
                                                    if let Some(rt) = new_refresh_token {
                                                        app_session
                                                            .refresh_token
                                                            .store(Some(Arc::new(rt.to_string())));
                                                        info!(
                                                            "[BFF] Refresh token was rotated."
                                                        );
                                                    }
                                                    app_session
                                                        .access_token_expires_at
                                                        .store(new_expires_at.map(Arc::new));
                                                    info!(
                                                        "[BFF] Session tokens refreshed successfully."
                                                    );
                                                } else {
                                                    error!(
                                                        "[BFF] Failed to parse token refresh response as JSON."
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "[BFF] Error sending token refresh request: {}",
                                                    e
                                                );
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "[BFF] Access token expired, but no refresh token available."
                                        );
                                    }
                                }
                            } else {
                                info!("[BFF] Access token expiration time not set.");
                            }

                            // get access token
                            info!("[BFF] API call ... access_token loaded");
                            let token_str = &*access_token_arc;
                            let auth_header_value = format!("Bearer {}", token_str);
                            session
                                .req_header_mut()
                                .insert_header("Authorization", auth_header_value)?;
                            info!(
                                "[BFF] API call ... Added Authorization header to upstream request for session {}.",
                                sid
                            );
                        } else {
                            info!("[BFF] API call ... no access_token");
                        }
                    }
                }
            }
        }

        Ok(false) // Continue to the next phase
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {

        // Use the upstream name that was already determined in request_filter.
        let upstream_sni_name = ctx.upstream_sni_name.as_deref().unwrap_or_default();

        let upstream = if upstream_sni_name == "bff.wgd.example.com" {
            let path = session.req_header().uri.path();
            info!("Path-based routing for bff.example.com, path: {}", path);
            if path.starts_with("/api") {
                self.upstreams.sni_map.get("bff_api").unwrap().value().clone()
            } else {
                self.upstreams.sni_map.get("bff_root").unwrap().value().clone()
            }
        } else {
            if upstream_sni_name == self.upstreams.no_sni.sni {
                self.upstreams.no_sni.clone()
            } else if upstream_sni_name == self.upstreams.fallback.sni {
                self.upstreams.fallback.clone()
            } else {
                // Look up the peer from the upstreams map.
                // If not found (which shouldn't happen if logic is consistent), use fallback.
                self.upstreams
                    .sni_map.get(upstream_sni_name)
                    .map(|p| p.value().clone())
                    .unwrap_or_else(|| {
                        warn!(
                            "Upstream for SNI '{}' not found, using fallback.",
                            upstream_sni_name
                        );
                        self.upstreams.fallback.clone()
                    })
            }
        };

        info!("Forwarding to upstream: {}", upstream);
        // HttpPeer is Clone, so we can clone it from the Arc.
        Ok(Box::new((*upstream).clone()))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        {

            // Use the upstream name that was already determined in request_filter.
            let upstream_sni_name = ctx.upstream_sni_name.as_deref().unwrap_or("");

            info!(
                "Reesponse started for {} {} from client {:?} with SNI: {:?}",
                session.req_header().method,
                session.req_header().uri,
                session.client_addr(),
                upstream_sni_name,
            );
        }

        // SAMPLE RES-1 CORS
        // Add CORS headers to the actual response.
        // In a production environment, you should have a whitelist of allowed origins.
        if let Some(origin) = session.get_header("Origin") {
            upstream_response.insert_header("Access-Control-Allow-Origin", origin.clone())?;
            upstream_response.insert_header("Vary", "Origin")?;
            if let Ok(origin_str) = origin.to_str() {
                info!("CORS: {}", origin_str);
            } else {
                warn!("CORS: origin header contains non-UTF8 characters");
            }
        } else {
            upstream_response.insert_header("Access-Control-Allow-Origin", "*")?;
            info!("CORS: *");
        }

        // SAMPLE RES-2 DEVICE Cookie
        // Issue JWT cookie if it doesn't exist or was invalid.
        let has_device_context = session
            .get_header("Cookie")
            .and_then(|h| h.to_str().ok())
            .map_or(false, |s| s.contains("DEVICE_CONTEXT="));

        if !has_device_context || ctx.device_context_is_new {
            self.issue_device_cookie(upstream_response)?;
        }

        // SAMPLE RES-3 Application session cookie
        // Create new application session and issue cookie if needed.
        self.create_application_session_if_new(ctx, upstream_response)?;

        // SAMPLE RES-5 Statick Headers
        upstream_response.insert_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )?;
        // example: upstream_response.insert_header("Access-Control-Allow-credentials", "true")?;

        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "Request finished for {} {} from {:?} with status {} in {:?}",
            session.req_header().method,
            session.req_header().uri,
            session.client_addr(),
            response_code,
            ctx.start_time.elapsed()
        );
    }
}

// A struct to hold a certificate and its corresponding private key.
struct CertAndKey {
    cert: pingora::tls::x509::X509,
    key: pingora::tls::pkey::PKey<Private>,
}

// A struct to hold all loaded certificates, which can be reloaded atomically.
struct CertificateCache {
    // A map from SNI hostname to its certificate and key.
    cert_map: HashMap<String, Arc<CertAndKey>>,
    // The default certificate and key to use when a specific SNI is not found.
    default_cert: Arc<CertAndKey>,
    // The certificate and key to use when no SNI is provided.
    no_sni_cert: Arc<CertAndKey>,
}

impl CertificateCache {
    fn load() -> Result<Self> {
        // Helper function to load a certificate and key from disk.
        fn load_cert_key(cert_path: &str, key_path: &str) -> Result<Arc<CertAndKey>> {
            let cert_bytes = fs::read(cert_path).map_err(|e| {
                let mut err = pingora::Error::new(pingora::ErrorType::InternalError);
                err.context = Some(format!("failed to read cert {}: {}", cert_path, e).into());
                err.set_cause(e);
                err
            })?;
            let key_bytes = fs::read(key_path).map_err(|e| {
                let mut err = pingora::Error::new(pingora::ErrorType::InternalError);
                err.context = Some(format!("failed to read key {}: {}", key_path, e).into());
                err.set_cause(e);
                err
            })?;
            let cert = pingora::tls::x509::X509::from_pem(&cert_bytes).map_err(|e| {
                let mut err = pingora::Error::new(pingora::ErrorType::InternalError);
                err.set_cause(e);
                err
            })?;
            let key = pingora::tls::pkey::PKey::private_key_from_pem(&key_bytes).map_err(|e| {
                let mut err = pingora::Error::new(pingora::ErrorType::InternalError);
                err.set_cause(e);
                err
            })?;
            // Log certificate details
            let cn = cert
                .subject_name()
                .entries_by_nid(pingora::tls::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok());
            info!("Loaded certificate from {}", cert_path);
            info!("  Subject CN: {}", cn.as_deref().map_or("N/A", |s| &*s));
            info!(
                "  Validity: Not Before: {}, Not After: {}",
                cert.not_before(),
                cert.not_after()
            );

            Ok(Arc::new(CertAndKey { cert, key }))
        }

        info!("Loading certificates and keys into memory...");

        let mut cert_map = HashMap::new();

        // Load certificates for www, api, authm bff
        let cert_www = load_cert_key(
            "../cert_server/server-www.pem",
            "../cert_server/server-key-www.pem",
        )?;
        cert_map.insert("www.wgd.example.com".to_string(), cert_www);
        let cert_api = load_cert_key(
            "../cert_server/server-api.pem",
            "../cert_server/server-key-api.pem",
        )?;
        cert_map.insert("api.wgd.example.com".to_string(), cert_api);
        let cert_auth = load_cert_key(
            "../cert_server/server-auth.pem",
            "../cert_server/server-key-auth.pem",
        )?;
        cert_map.insert("auth.wgd.example.com".to_string(), cert_auth);
        let cert_bff = load_cert_key(
            "../cert_server/server-bff.pem",
            "../cert_server/server-key-bff.pem",
        )?;
        cert_map.insert("bff.wgd.example.com".to_string(), cert_bff);

        // Load the fallback/default certificate (for www2, etc.)
        let default_cert = load_cert_key(
            "../cert_server/server-www.pem",
            "../cert_server/server-key-www.pem",
        )?;
        // Load the certificate for requests with no SNI
        let no_sni_cert = load_cert_key(
            "../cert_server/server-www.pem",
            "../cert_server/server-key-www.pem",
        )?;

        info!("Certificates and keys loaded successfully.");

        Ok(CertificateCache {
            cert_map,
            default_cert,
            no_sni_cert,
        })
    }
}

struct SniCertificateSelector {
    sni_ex_data_index: Index<Ssl, Option<String>>,
    cache: Arc<ArcSwap<CertificateCache>>,
}

impl SniCertificateSelector {
    fn new(sni_ex_data_index: Index<Ssl, Option<String>>) -> Result<Self> {
        let cache = CertificateCache::load()?;
        Ok(SniCertificateSelector {
            sni_ex_data_index,
            cache: Arc::new(ArcSwap::new(Arc::new(cache))),
        })
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for SniCertificateSelector {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        let sni_opt_string = ssl
            .servername(pingora::tls::ssl::NameType::HOST_NAME)
            .map(|s| s.to_string());
        info!("SNI from client: {:?}", sni_opt_string.as_deref());

        // Store SNI in ex_data to pass it to the http proxy phase.
        ssl.set_ex_data(self.sni_ex_data_index, sni_opt_string.clone());

        // Load the current certificate cache. This is a lock-free operation.
        let cache = self.cache.load();

        // Select the certificate and key from the in-memory cache.
        let cert_and_key = match sni_opt_string.as_deref() {
            Some(sni) => cache
                .cert_map
                .get(sni)
                .unwrap_or(&cache.default_cert)
                .clone(),
            None => cache.no_sni_cert.clone(),
        };

        // Apply the selected certificate and key to the SSL context.
        if let Err(e) = pingora::tls::ext::ssl_use_certificate(ssl, &cert_and_key.cert) {
            error!("ssl_use_certificate failed: {}", e);
            // The connection will be terminated by the TLS library.
            return;
        }
        if let Err(e) = pingora::tls::ext::ssl_use_private_key(ssl, &cert_and_key.key) {
            error!("ssl_use_private_key failed: {}", e);
            // The connection will be terminated by the TLS library.
            return;
        }
    }
}

// A background service to periodically reload certificates.
struct CertificateReloader {
    cache: Arc<ArcSwap<CertificateCache>>,
}

#[async_trait]
impl BackgroundService for CertificateReloader {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Define the reload interval.
        let reload_interval = Duration::from_secs(60 * 60 * 2); // 2 hours

        info!(
            "Certificate reloader service started. Will reload every {} seconds.",
            reload_interval.as_secs()
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(reload_interval) => {
                    info!("Attempting to reload certificates...");
                    match CertificateCache::load() {
                        Ok(new_cache) => {
                            // Atomically swap the cache with the new one.
                            self.cache.store(Arc::new(new_cache));
                            info!("Certificates reloaded successfully.");
                        }
                        Err(e) => {
                            error!("Failed to reload certificates, keeping old ones. Error: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    info!("Certificate reloader service shutting down.");
                    break;
                }
            }
        }
    }
}

// A background service to periodically clean up expired sessions.
struct SessionPurger {
    start_time: Instant,
    session_store: SessionStore,
    session_ttl: Duration,
}

impl SessionPurger {
    fn cleanup_expired_sessions(&self) {
        let before_count = self.session_store.len();
        if before_count == 0 {
            return; // No sessions to clean up.
        }
        let now = Instant::now();
        self.session_store.retain(|_sid, session| {
            let last_accessed_secs = session.last_accessed.load(Ordering::Relaxed);
            let last_accessed_instant = self.start_time + Duration::from_secs(last_accessed_secs);
            now.duration_since(last_accessed_instant) < self.session_ttl
        });
        let after_count = self.session_store.len();
        let cleaned_count = before_count - after_count;
        if cleaned_count > 0 {
            info!(
                "Cleaned up {} expired sessions. Current count: {}",
                cleaned_count,
                after_count
            );
        }
    }
}

#[async_trait]
impl BackgroundService for SessionPurger {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Check for expired sessions more frequently than the TTL.
        // For example, check every 5 minutes for a 30-minute TTL.
        let mut interval = tokio::time::interval(self.session_ttl.min(Duration::from_secs(5 * 60)));
        info!(
            "Session purger service started. Session TTL is {:?}, check interval is {:?}.",
            self.session_ttl,
            interval.period()
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.cleanup_expired_sessions();
                }
                _ = shutdown.changed() => {
                    info!("Session purger service shutting down.");
                    break;
                }
            }
        }
    }
}

fn main() -> pingora::Result<()> {
    env_logger::init();

    let start_time = Instant::now();
    let keys = Arc::new(JwtSigningKeys::new());

    // The Server::new() function expects an Option<Opt>.
    // To load from a conf file, we create an Opt struct and pass it in.
    let opt = Opt {
        conf: Some("src/conf.yaml".to_string()),
        ..Default::default()
    };
    let mut my_server = Server::new(Some(opt))?;

    // Create an index to store SNI data in the SSL session
    let sni_ex_data_index = match Ssl::new_ex_index::<Option<String>>() {
        Ok(index) => index,
        Err(e) => {
            let mut err = pingora::Error::new(pingora::ErrorType::InternalError);
            err.set_cause(e);
            return Err(err);
        }
    };

    let sessions = Arc::new(DashMap::new());

    // Define upstreams for different SNIs
    let upstreams = Arc::new(DashMap::new());

    // The connection pool size is now a global setting read from conf.yaml

    // FOR BFF TEST
    let www1_peer = HttpPeer::new(
        "192.168.10.132:8080",
        false,
        "www.wgd.example.com".to_string(),
    );
    upstreams.insert("www.wgd.example.com".to_string(), Arc::new(www1_peer));
    let www2_peer = HttpPeer::new(
        "192.168.10.132:5001",
        false,
        "api.wgd.example.com".to_string(),
    );
    upstreams.insert("api.wgd.example.com".to_string(), Arc::new(www2_peer));
    let www3_peer = HttpPeer::new(
        "192.168.10.132:8082",
        false,
        "auth.wgd.example.com".to_string(),
    );
    upstreams.insert("auth.wgd.example.com".to_string(), Arc::new(www3_peer));
    let www4_peer = HttpPeer::new(
        "192.168.10.132:8080",
        false,
        "bff.wgd.example.com".to_string(),
    );
    upstreams.insert("bff.wgd.example.com".to_string(), Arc::new(www4_peer));
    // bff.example.com paths -> need request_filter support
    let bff_root_peer = HttpPeer::new("192.168.10.132:8080", false, "bff_root".to_string());
    upstreams.insert("bff_root".to_string(), Arc::new(bff_root_peer));
    let bff_api_peer = HttpPeer::new("192.168.10.132:5001", false, "bff_api".to_string());
    upstreams.insert("bff_api".to_string(), Arc::new(bff_api_peer));

    // Upstream for requests with no SNI
    let no_sni_upstream = Arc::new(HttpPeer::new("127.0.0.1:8080", false, "".to_string()));

    // Fallback for any other SNI (e.g., www2.example.com)
    let fallback_upstream = Arc::new(HttpPeer::new("127.0.0.1:8089", false, "".to_string()));

    let upstream_set = UpstreamSet {
        sni_map: upstreams,
        no_sni: no_sni_upstream,
        fallback: fallback_upstream,
    };

    let router_logic = GatewayRouter {
        session_store: sessions.clone(),
        upstreams: upstream_set,
        sni_ex_data_index: sni_ex_data_index.clone(),
        keys,
        start_time,
    };

    let mut http_service = http_proxy_service(&my_server.configuration, router_logic);
    let selector = SniCertificateSelector::new(sni_ex_data_index.clone())?;

    // Create and add the background service for reloading certificates
    let reloader_logic = Arc::new(CertificateReloader {
        cache: selector.cache.clone(),
    });
    let reloader_service = pingora::services::background::GenBackgroundService::new(
        "Certificate Reloader".to_string(),
        reloader_logic,
    );
    my_server.add_service(reloader_service);

    // Create and add the background service for cleaning up sessions
    let session_ttl = Duration::from_secs(30 * 60); // 30 minutes
    let purger_logic = Arc::new(SessionPurger {
        start_time,
        session_store: sessions.clone(),
        session_ttl,
    });
    let purger_service = pingora::services::background::GenBackgroundService::new(
        "Session Purger".to_string(),
        purger_logic,
    );
    my_server.add_service(purger_service);

    // TLS settings for TCP (H1/H2)
    let tls_settings_tcp =
        pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(selector))?;
    http_service.add_tls_with_settings("0.0.0.0:8000", None, tls_settings_tcp);
    my_server.add_service(http_service);

    my_server.run_forever();
}

///
/// FOR BFF
///
/// Sends an HTTP request with the specified method, URI, headers, cookies, and body.
///
/// # Arguments
///
/// * `method`: The HTTP method (e.g., GET, POST).
/// * `uri_str`: The URI to send the request to.
/// * `headers`: A slice of key-value pairs for request headers.
/// * `cookies`: A `CookieJar` containing cookies to be sent.
/// * `request_body`: An optional string slice for the request body.
///
/// # Returns
///
/// A `Result` containing a tuple of the `hyper::Response` and a `CookieJar` with cookies
/// from the response, or an error.
async fn send_http_request(
    method: Method,
    uri_str: &str,
    headers: &[(&str, &str)],
    cookies: &CookieJar,
    request_body: Option<&str>,
) -> Result<(hyper::Response<Body>, CookieJar), Box<dyn std::error::Error + Send + Sync>> {
    let uri: Uri = uri_str.parse()?; // Parse the string into a hyper::Uri

    let mut req_builder = Request::builder().method(method).uri(uri);

    // Add headers
    for &(key, value) in headers {
        req_builder = req_builder.header(key, value);
    }

    // Add cookies to send to the Cookie header
    let cookie_str = cookies
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if !cookie_str.is_empty() {
        req_builder = req_builder.header(COOKIE, cookie_str);
    }

    // Set the request body
    let body = match request_body {
        Some(b) => Body::from(b.to_string()), // Convert &str to String and pass to Body::from
        None => Body::empty(),                // Empty body if there is no body
    };

    let req = req_builder.body(body)?;

    let client = Client::new();
    let resp = client.request(req).await?;

    // Extract Set-Cookie headers from the response
    let mut received_cookies = CookieJar::new();
    for header_value in resp.headers().get_all(SET_COOKIE) {
        if let Ok(s) = header_value.to_str() {
            if let Ok(cookie) = Cookie::parse(s) {
                received_cookies.add(cookie.into_owned());
            }
        }
    }
    Ok((resp, received_cookies))
}

///
/// FOR BFF
///
/// Sends an HTTP POST request with application/x-www-form-urlencoded data.
///
/// # Arguments
///
/// * `uri_str`: The URI to send the request to.
/// * `headers`: A slice of key-value pairs for additional request headers.
/// * `cookies`: A `CookieJar` containing cookies to be sent.
/// * `form_data`: A slice of key-value pairs for the form data body.
///
/// # Returns
///
/// A `Result` containing a tuple of the `hyper::Response` and a `CookieJar` with cookies
/// from the response, or an error.
async fn send_form_post_request(
    uri_str: &str,
    headers: &[(&str, &str)],
    cookies: &CookieJar,
    form_data: &[(&str, &str)],
) -> Result<(hyper::Response<Body>, CookieJar), Box<dyn std::error::Error + Send + Sync>> {
    // URL-encode the form data using serde_urlencoded
    let encoded_form = serde_urlencoded::to_string(form_data)?;

    let mut all_headers = headers.to_vec();
    // Add/overwrite Content-Type header for x-www-form-urlencoded
    all_headers.push(("Content-Type", "application/x-www-form-urlencoded"));

    // Call the generic send_http_request function with POST method and the urlencoded body
    send_http_request(
        Method::POST,
        uri_str,
        &all_headers,
        cookies,
        Some(&encoded_form),
    )
    .await
}
