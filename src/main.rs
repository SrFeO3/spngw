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
// - Consider making the default certificate configurable instead of using the first one found.
// - Implement `/api/logout` endpoint to invalidate sessions and tokens
// - Implement a locking mechanism for token refresh to prevent the dog-piling effect.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use boring::ex_data::Index;
use bytes::Bytes;
use dashmap::DashMap;
use log::{info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::tls::ssl::Ssl;

mod actions;
use actions::{GatewayAction, RouteLogic};

mod config;
use crate::config::{
    AppConfig, CertificateCache, JwtKeysCache, RealmMap, UpstreamCache,
};

mod background_services;

/// The default lifetime for an authenticated session, used as a fallback if a realm does not specify a `sessionTimeout`.
const DEFAULT_SESSION_TIMEOUT_SECONDS: u64 = 86400; // 1 day
/// A short timeout for unauthenticated sessions to prevent store bloat from abandoned login attempts.
pub const UNAUTHENTICATED_SESSION_TIMEOUT_SECONDS: u64 = 300; // 5 minutes

/// Core logic and shared state for the proxy service
///
/// This struct implements the `ProxyHttp` trait and holds all shared resources
/// required for request processing, such as upstream server definitions, the
/// session map, and cryptographic keys.
///
/// A single instance is created at startup and shared immutably across all
/// worker threads for the lifetime of the application.
struct GatewayRouter {
    upstream_peer_cache: Arc<ArcSwap<UpstreamCache>>,
    sni_ex_data_index: Index<Ssl, Option<String>>,
    jwt_keys_cache: Arc<ArcSwap<JwtKeysCache>>,
    realm_map: Arc<ArcSwap<RealmMap>>,
    main_config: Arc<ArcSwap<AppConfig>>,
    _gateway_start_time: Instant,
    http_client: reqwest::Client,
}

/// Context that holds state for each HTTP request
///
/// An instance of this struct is created for each request via `ProxyHttp::new_ctx()`
/// and is passed through the different phases of the request proxying lifecycle
/// (e.g., `request_filter`, `upstream_peer`). Its lifetime is tied to a single
/// request-response cycle.
struct GatewayCtx {
    // The name of the realm processing this request.
    realm_name: String,
    session_timeout: u64,
    app_config: Option<Arc<AppConfig>>,
    realm_index: Option<usize>,
    request_id: String,
    request_start_time: Instant,
    // JWT signing keys for the current request, passed from the GatewayRouter.
    jwt_keys: Arc<JwtKeysCache>,
    front_sni_name: Option<String>,
    // Pipeline of routes to be applied to the request
    action_pipeline: Vec<Arc<GatewayAction>>,
    // The default upstream address for the request, can be overridden by an action.
    default_upstream_addr: Option<Arc<str>>,
    // The upstream address set by an action, which overrides the default.
    override_upstream_addr: Option<Arc<str>>,

    // --- State for GatewayActions ---
    // These fields store state that is shared across the lifecycle of a single request.
    // They are set and read by different filter hooks within GatewayActions.
    //
    // WARNING: Each field is shared by all instances of a given action type within the
    // pipeline. For example, if two `IssueDeviceCookie` actions are in the pipeline,
    // they will both read from and write to the *same* `action_new_dev_cookie` field.
    // This can lead to state being overwritten. The current design assumes that each
    // action type appears at most once in the pipeline.

    // Set by IssueDeviceCookie action
    action_state_new_dev_cookie: Option<String>,
    // Set by RequireAuthentication action when a new session is created
    action_state_new_app_session_cookie: Option<(String, String)>, // (value, scope_name)
    // Set by RequireAuthentication action
    action_state_app_session: Option<actions::ApplicationSession>,
    // The domain to set on cookies, if share_cookie is enabled.
    pub cookie_domain: Option<String>,
    // Shared HTTP client for actions
    pub http_client: reqwest::Client,
}

#[async_trait]
impl ProxyHttp for GatewayRouter {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx {
            realm_name: String::new(),
            session_timeout: 0, // Will be set from realm config, with a default fallback.
            app_config: None,
            realm_index: None,
            request_id: format!("req-{}", rand::random::<u32>()),
            request_start_time: Instant::now(),
            // Load the current value from the ArcSwap.
            // .load() returns a Guard, which dereferences to an Arc<JwtSigningKeys>.
            // We clone the Arc so that the context owns it for the lifetime of the request.
            jwt_keys: self.jwt_keys_cache.load().clone(),
            front_sni_name: None,
            action_pipeline: Vec::new(),
            default_upstream_addr: None,
            override_upstream_addr: None,
            action_state_new_dev_cookie: None,
            action_state_new_app_session_cookie: None,
            action_state_app_session: None,
            cookie_domain: None,
            http_client: self.http_client.clone(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        info!(
            "********** [{}] New request received for path: {}",
            ctx.request_id,
            session.req_header().uri.path()
        );

        //
        // Get SNI from the ex_data stored during the TLS handshake and set to no_sni_upstream.sni.
        //
        let sni_opt = session
            .stream()
            .and_then(|s| s.get_ssl())
            .and_then(|ssl| ssl.ex_data(self.sni_ex_data_index));
        let sni: Option<String> = sni_opt.and_then(|s| s.as_deref().map(String::from));
        let front_sni_name = match sni.as_deref() {
            Some(sni_name) => {
                info!("[{}] SNI found: {}", ctx.request_id, sni_name);
                sni_name.to_string()
            }
            None => {
                warn!("[{}] No SNI found. Using no-SNI upstream.", ctx.request_id);
                let body = "SNI is required.";
                let mut resp = ResponseHeader::build(400, None)?;
                resp.insert_header("Content-Type", "text/plain")?;
                resp.insert_header("Content-Length", body.len().to_string())?;
                resp.insert_header("Connection", "Close")?;
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(body)), true)
                    .await?;
                return Ok(true);
            }
        };

        // Verify that the HTTP Host header matches the SNI, as per the specification.
        let host_header_val = session
            .get_header("Host")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h));

        if !host_header_val.map_or(false, |h| h.eq_ignore_ascii_case(&front_sni_name)) {
            warn!(
                "[{}] Host header ({:?}) does not match SNI ({}). Rejecting request.",
                ctx.request_id,
                host_header_val.unwrap_or(""),
                front_sni_name
            );
            let body = "Host header does not match SNI.";
            let mut resp = ResponseHeader::build(400, None)?;
            resp.insert_header("Content-Type", "text/plain")?;
            resp.insert_header("Content-Length", body.len().to_string())?;
            resp.insert_header("Connection", "Close")?;
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(Bytes::from(body)), true).await?;
            return Ok(true);
        }
        ctx.front_sni_name = Some(front_sni_name);

        // Determine Realm for this request.
        let app_config = self.main_config.load();
        let realm_map = self.realm_map.load();
        ctx.app_config = Some(app_config.clone());

        let realm_name = ctx
            .front_sni_name
            .as_ref()
            .and_then(|sni| realm_map.map.get(sni).map(|v| v.value().clone()));

        if let Some(name) = realm_name {
            ctx.realm_name = name.clone();
            let index = app_config
                .realms
                .iter()
                .position(|r| r.name == ctx.realm_name)
                .unwrap_or(0); // Should be safe if map is consistent with config
            ctx.realm_index = Some(index);

            // Get session timeout from realm config
            let realm_config = &app_config.realms[index];
            let session_timeout = if realm_config.session_timeout > 0 {
                info!("[{}] Using session timeout from realm '{}': {} seconds", ctx.request_id, realm_config.name, realm_config.session_timeout);
                realm_config.session_timeout
            } else {
                info!("[{}] Realm '{}' has no session timeout configured, using default: {} seconds", ctx.request_id, realm_config.name, DEFAULT_SESSION_TIMEOUT_SECONDS);
                DEFAULT_SESSION_TIMEOUT_SECONDS
            };
            ctx.session_timeout = session_timeout;


            // Resolve Cookie Domain if share_cookie is enabled
            if let Some(sni) = &ctx.front_sni_name {
                if let Some(vhost) = realm_config
                    .virtual_hosts
                    .iter()
                    .find(|vh| &vh.hostname == sni)
                {
                    // The cookie_domain is pre-resolved during config load.
                    ctx.cookie_domain = vhost.cookie_domain.clone();
                }
            }
        } else {
            warn!("[{}] No realm found", ctx.request_id);
            let body = "SNI not registered.";
            let mut resp = ResponseHeader::build(400, None)?;
            resp.insert_header("Content-Type", "text/plain")?;
            resp.insert_header("Content-Length", body.len().to_string())?;
            resp.insert_header("Connection", "Close")?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            return Ok(true);
        }

        //
        // Set the action pipeline actions for this request.
        //

        // No default upstream is set. A route must explicitly define one using
        // `proxyTo` or `requireAuthentication`, otherwise a 503 Service Unavailable will be returned.
        ctx.default_upstream_addr = None;
        ctx.action_pipeline.clear();

        // All for DeviceCookie
        ctx.action_pipeline.push(Arc::new(GatewayAction::IssueDeviceCookie));

        // Dynamically generate Action Pipelines from config
        let path = session.req_header().uri.path();

        /// Evaluates a single match expression against the request's hostname and path.
        fn evaluate_single_expr(expr: &str, hostname: &str, path: &str, request_id: &str) -> bool {
            if let (Some(start_paren), Some(end_paren)) = (expr.find("('"), expr.rfind("')")) {
                if start_paren < end_paren {
                    let key = &expr[..start_paren];
                    let value = &expr[start_paren + 2..end_paren];

                    return match key {
                        "request.path.starts_with" => path.starts_with(value),
                        "request.path.ends_with" => path.ends_with(value),
                        "request.path.equals" => path == value,
                        "hostname.starts_with" => hostname.starts_with(value),
                        "hostname.ends_with" => hostname.ends_with(value),
                        "hostname.equals" => hostname == value,
                        _ => false,
                    };
                }
            }

            warn!(
                "[{}] Unsupported or malformed match expression: {}",
                request_id, expr
            );
            false
        }

        if let (Some(app_config), Some(realm_index)) = (&ctx.app_config, ctx.realm_index) {
            let realm_config = &app_config.realms[realm_index];
            if let Some(chain) = realm_config.routing_chains.get(0) {
                info!(
                    "[{}] Using routing_chain '{}' for request",
                    ctx.request_id, chain.name
                );
                let sni_str = ctx.front_sni_name.as_deref().unwrap_or("");
                for rule in &chain.rules {
                    let is_match = if rule.match_expr.contains(" and ") {
                        // Handle 'and' conditions
                        let parts: Vec<&str> = rule.match_expr.splitn(2, " and ").collect();
                        if parts.len() == 2 {
                            let part1 = parts[0].trim();
                            let part2 = parts[1].trim();

                            // Evaluate both conditions. For simplicity, we assume one is hostname and one is path.
                            // A more robust solution would parse them regardless of order.
                            let match1 = evaluate_single_expr(
                                part1,
                                sni_str,
                                path,
                                &ctx.request_id,
                            );
                            let match2 = evaluate_single_expr(
                                part2,
                                sni_str,
                                path,
                                &ctx.request_id,
                            );

                            match1 && match2
                        } else {
                            warn!(
                                "[{}] Invalid 'and' expression: {}",
                                ctx.request_id, rule.match_expr
                            );
                            false
                        }
                    } else {
                        // Handle single conditions
                        evaluate_single_expr(
                            &rule.match_expr,
                            sni_str,
                            path,
                            &ctx.request_id,
                        )
                    };

                    if is_match {
                        info!(
                            "[{}] Matched rule: '{}', applying action",
                            ctx.request_id, rule.match_expr
                        );
                        ctx.action_pipeline.push(rule.action.clone());
                    }
                }
            }
        }

        info!(
            "[{}] Final action pipeline: {:?}",
            ctx.request_id, ctx.action_pipeline
        );

        //
        // Execute the pipeline for request_filter_and_prepare_upstream_peer.
        //
        let pipeline = std::mem::take(&mut ctx.action_pipeline);
        for action in &pipeline {
            info!(
                "[{}] Pipeline: Executing request_filter_and_prepare_upstream_peer for action: {:?}",
                ctx.request_id, action
            );
            // Pass the session stores to the dispatch macro so it can construct the full scope.
            let early_exit = match action.as_ref() {
                GatewayAction::ReturnStaticText {
                    content,
                    status,
                } => {
                    let logic = actions::ReturnStaticTextRoute {
                        content,
                        status_code: *status,
                    };
                    logic
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
                GatewayAction::SetUpstreamRequestHeader { name, value } => {
                    let logic = actions::SetUpstreamRequestHeaderRoute { name, value };
                    logic
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
                GatewayAction::SetDownstreamResponseHeader { name, value } => {
                    let logic = actions::SetDownstreamResponseHeaderRoute { name, value };
                    logic
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
                GatewayAction::RequireAuthentication {
                    protected_upstream,
                    oidc_authorization_endpoint,
                    oidc_client_id,
                    oidc_redirect_url,
                    oidc_token_endpoint,
                    auth_scope_name,
                    oidc_client_secret,
                    oidc_dialect,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_upstream,
                        oidc_authorization_endpoint,
                        oidc_client_id,
                        oidc_redirect_url,
                        oidc_token_endpoint,
                        auth_scope_name,
                        oidc_client_secret: oidc_client_secret.as_ref(),
                        oidc_dialect: oidc_dialect.as_deref(),
                    };
                    logic
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
                GatewayAction::Redirect { url } => {
                    let logic = actions::RedirectRoute { url };
                    logic
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
                GatewayAction::ProxyTo {
                    upstream,
                    auth_scope_name,
                } => {
                    let logic = actions::ProxyToRoute {
                        upstream,
                        auth_scope_name: auth_scope_name.as_deref(),
                    };
                    logic
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
                GatewayAction::IssueDeviceCookie => {
                    actions::IssueDeviceCookieRoute
                        .request_filter_and_prepare_upstream_peer(session, ctx)
                        .await
                }
            }?;
            if early_exit {
                ctx.action_pipeline = pipeline;
                return Ok(true); // Stop the pipeline if a filter decides to exit early.
            }
        }

        ctx.action_pipeline = pipeline;
        Ok(false) // Continue to the next phase
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // The upstream address is now determined during the request_filter_and_prepare_upstream_peer phase and stored in the context.
        // We prioritize the address set by a specific action, and fall back to the default if none is set.
        let upstream_addr = match ctx
            .override_upstream_addr
            .as_ref()
            .or(ctx.default_upstream_addr.as_ref())
        {
            Some(addr) => addr,
            None => {
                warn!(
                    "[{}] No upstream defined for this request and no default is set. Responding with 503.",
                    ctx.request_id
                );
                return Err(Error::new(pingora::ErrorType::HTTPStatus(503)));
            }
        };
        info!(
            "[{}] Selecting upstream peer for address: {}",
            ctx.request_id, upstream_addr
        );

        // Retrieve the pre-configured HttpPeer from the cache.
        self.upstream_peer_cache
            .load()
            .peer_map
            .get(upstream_addr)
            .map(|peer| Box::new(peer.as_ref().clone()))
            .ok_or_else(|| {
                warn!(
                    "[{}] Upstream peer not found in cache for address: {}",
                    ctx.request_id, upstream_addr
                );
                Error::new(pingora::ErrorType::HTTPStatus(502))
            })
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Dispatch to the correct upstream request filter logic.
        // Loop through the pipeline to apply all relevant filters.
        let pipeline = std::mem::take(&mut ctx.action_pipeline);
        for action in &pipeline {
            info!(
                "[{}] Pipeline: Executing upstream_request_filter for action: {:?}",
                ctx.request_id, action
            );
            // Use the dispatch macro to call the upstream_request_filter method.
            match action.as_ref() {
                GatewayAction::ReturnStaticText {
                    content,
                    status,
                } => {
                    let logic = actions::ReturnStaticTextRoute {
                        content,
                        status_code: *status,
                    };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
                GatewayAction::SetUpstreamRequestHeader { name, value } => {
                    let logic = actions::SetUpstreamRequestHeaderRoute { name, value };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
                GatewayAction::SetDownstreamResponseHeader { name, value } => {
                    let logic = actions::SetDownstreamResponseHeaderRoute { name, value };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
                GatewayAction::RequireAuthentication {
                    protected_upstream,
                    oidc_authorization_endpoint,
                    oidc_client_id,
                    oidc_redirect_url,
                    oidc_token_endpoint,
                    auth_scope_name,
                    oidc_client_secret,
                    oidc_dialect,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_upstream,
                        oidc_authorization_endpoint,
                        oidc_client_id,
                        oidc_redirect_url,
                        oidc_token_endpoint,
                        auth_scope_name,
                        oidc_client_secret: oidc_client_secret.as_ref(),
                        oidc_dialect: oidc_dialect.as_deref(),
                    };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
                GatewayAction::IssueDeviceCookie => {
                    actions::IssueDeviceCookieRoute
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
                GatewayAction::Redirect { url } => {
                    let logic = actions::RedirectRoute { url };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
                GatewayAction::ProxyTo {
                    upstream,
                    auth_scope_name,
                } => {
                    let logic = actions::ProxyToRoute {
                        upstream,
                        auth_scope_name: auth_scope_name.as_deref(),
                    };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
            }?;
        }

        ctx.action_pipeline = pipeline;
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Add HSTS header to all responses
        response
            .insert_header("Strict-Transport-Security", actions::HSTS_HEADER_VALUE)
            .unwrap();

        // Dispatch to the response filter logic.
        // Loop through the pipeline in reverse order to apply response filters.
        // This follows the common middleware pattern (LIFO - Last-In, First-Out),
        // ensuring that the last request filter added is the first response filter executed.
        // We iterate by reference to avoid cloning the pipeline.
        let pipeline = std::mem::take(&mut ctx.action_pipeline);
        for action in pipeline.iter().rev() {
            info!(
                "[{}] Pipeline: Executing response_filter for action: {:?}",
                ctx.request_id, action
            );

            match action.as_ref() {
                GatewayAction::ReturnStaticText {
                    content,
                    status,
                } => {
                    let logic = actions::ReturnStaticTextRoute {
                        content,
                        status_code: *status,
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::SetUpstreamRequestHeader { name, value } => {
                    let logic = actions::SetUpstreamRequestHeaderRoute {
                        name,
                        value,
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::SetDownstreamResponseHeader { name, value } => {
                    let logic = actions::SetDownstreamResponseHeaderRoute {
                        name,
                        value,
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::RequireAuthentication {
                    protected_upstream,
                    oidc_authorization_endpoint,
                    oidc_client_id,
                    oidc_redirect_url,
                    oidc_token_endpoint,
                    auth_scope_name,
                    oidc_client_secret,
                    oidc_dialect,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_upstream,
                        oidc_authorization_endpoint,
                        oidc_client_id,
                        oidc_redirect_url,
                        oidc_token_endpoint,
                        auth_scope_name,
                        oidc_client_secret: oidc_client_secret.as_ref(),
                        oidc_dialect: oidc_dialect.as_deref(),
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::IssueDeviceCookie => {
                    actions::IssueDeviceCookieRoute
                        .response_filter(session, response, ctx)
                        .await
                }
                GatewayAction::Redirect { url } => {
                    let logic = actions::RedirectRoute { url };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::ProxyTo {
                    upstream,
                    auth_scope_name,
                } => {
                    let logic = actions::ProxyToRoute {
                        upstream,
                        auth_scope_name: auth_scope_name.as_deref(),
                    };
                    logic.response_filter(session, response, ctx).await
                }
            }?;
        }
        ctx.action_pipeline = pipeline;
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "********** [{}] Request finished for {} {} from {:?} with status {} in {:?}",
            ctx.request_id,
            session.req_header().method,
            session.req_header().uri,
            session.client_addr(),
            response_code,
            ctx.request_start_time.elapsed()
        );
    }
}

//
// A dedicated router for handling HTTP traffic and redirecting to HTTPS.
//
struct HttpRedirectRouter {
    tls_port: u16,
    realm_map: Arc<ArcSwap<RealmMap>>,
}

#[async_trait]
impl ProxyHttp for HttpRedirectRouter {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let host_header = session
            .get_header("Host")
            .and_then(|v| v.to_str().ok());

        if let Some(host_str) = host_header {
            let hostname = host_str.split(':').next().unwrap_or(host_str);

            if let Some(entry) = self.realm_map.load().map.get(hostname) {
                let canonical_host = entry.key();
                let path = session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/");

                // Per RFC 7230 Section 5.3, the request-target (origin-form) must begin with a '/'.
                // While path_and_query() returning None is acceptable (we treat it as "/"),
                // a non-empty path that doesn't start with '/' is a malformed request.
                if path != "/" && !path.starts_with('/') {
                    warn!("HTTP request for {} rejected: invalid path '{}' does not start with '/'.", hostname, path);
                    let mut resp = ResponseHeader::build(400, None)?;
                    resp.insert_header("Connection", "Close")?;
                    resp.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
                let location = format!("https://{}:{}{}", canonical_host, self.tls_port, path);

                info!("HTTP request for {}. Redirecting to {}", hostname, location);
                let mut resp = ResponseHeader::build(301, None)?;
                resp.insert_header("Location", location)?;
                resp.insert_header("Connection", "Close")?;
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        warn!("HTTP request rejected: missing or unknown Host header.");
        let mut resp = ResponseHeader::build(400, None)?;
        resp.insert_header("Connection", "Close")?;
        resp.insert_header("Content-Length", "0")?;
        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(Error::explain(
            ErrorType::InternalError,
            "Should not be reached",
        ))
    }
}

//
// L4 for get SNI string on TLS handshake
//
struct SniCertificateSelector {
    sni_ex_data_index: Index<Ssl, Option<String>>,
    cert_cache: Arc<ArcSwap<CertificateCache>>,
    realm_map: Arc<ArcSwap<RealmMap>>,
    default_cert: Arc<config::CertAndKey>,
}

#[async_trait]
impl pingora::listeners::TlsAccept for SniCertificateSelector {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        let sni_opt_string = ssl
            .servername(pingora::tls::ssl::NameType::HOST_NAME)
            .map(|s| s.to_string());
        info!("SNI from client: {:?}", sni_opt_string.as_deref());

        // Check if the host is allowed (exists in RealmMap)
        let is_allowed = sni_opt_string
            .as_ref()
            .map_or(false, |sni| self.realm_map.load().map.contains_key(sni));

        if !is_allowed {
            warn!("Connection rejected: Hostname not found in configuration.");
            // Returning without setting a certificate will typically cause the TLS handshake to fail.
            return;
        }

        // Store SNI in ex_data to pass it to the http proxy phase.
        ssl.set_ex_data(self.sni_ex_data_index, sni_opt_string.clone());
        // Load the current certificate cache. This is a lock-free operation.
        let cert_cache = self.cert_cache.load();

        // Select the certificate and key from the in-memory cache.
        // If SNI is present and a matching certificate is found, use it.
        // Otherwise, fall back to the default certificate.
        let cert_and_key = match sni_opt_string.as_deref() {
            Some(hostname) => {
                if let Some(cert) = cert_cache.cert_map.get(hostname) {
                    info!("Found matching certificate for SNI: {}", hostname);
                    cert.clone()
                } else {
                    warn!(
                        "No matching certificate for SNI: {}. Falling back to default.",
                        hostname
                    );
                    self.default_cert.clone()
                }
            }
            None => {
                info!("No SNI provided. Using default certificate.");
                self.default_cert.clone()
            }
        };

        // Apply the selected certificate and key to the SSL context.
        if let Err(e) = pingora::tls::ext::ssl_use_certificate(ssl, &cert_and_key.cert) {
            warn!("ssl_use_certificate failed: {}", e);
            // The connection will be terminated by the TLS library.
            return;
        }
        if let Err(e) = pingora::tls::ext::ssl_use_private_key(ssl, &cert_and_key.key) {
            warn!("ssl_use_private_key failed: {}", e);
            // The connection will be terminated by the TLS library.
            return;
        }
    }
}

fn main() -> pingora::Result<()> {
    env_logger::init();

    // Read environment variables
    let config_path = std::env::var("APIGW_INVENTORY_URL")
        .expect("APIGW_INVENTORY_URL must be set. Use 'file:///path/to/config.yaml' or 'http(s)://...'.");
    let gateway_listen_addr = std::env::var("APIGW_TLS_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let redirect_service_listen_addr = std::env::var("APIGW_HTTP_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    info!(
        "Startup settings:\n\
        APIGW_INVENTORY_URL (config path): {}\n\
        APIGW_TLS_BIND_ADDRESS: {}\n\
        APIGW_HTTP_BIND_ADDRESS: {}",
        config_path, gateway_listen_addr, redirect_service_listen_addr
    );

    let tls_port = gateway_listen_addr
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .expect("Invalid APIGW_TLS_BIND_ADDRESS format");

    let opt = Opt {
        conf: Some("conf/pinconfig.yaml".to_string()),
        ..Default::default()
    };

    let gateway_start_time = Instant::now();
    let (app_config, initial_config_content) = config::load_app_config(&config_path);
    let main_config_swapper = Arc::new(ArcSwap::new(app_config.clone()));

    // Load initial JWT signing keys and wrap them in ArcSwap for hot-reloading.
    let initial_keys_cache = JwtKeysCache {
        keys_by_realm: dashmap::DashMap::new(),
    };

    // Load initial certificates and wrap them in ArcSwap for hot-reloading.
    let initial_certs = CertificateCache {
        cert_map: DashMap::new(),
    };

    // Create initial upstream peer cache and wrap it in ArcSwap for hot-reloading.
    let initial_upstream_cache = UpstreamCache {
        peer_map: DashMap::new(),
    };

    // Load initial realm map and wrap it in ArcSwap for hot-reloading.
    let initial_realm_map = RealmMap {
        map: DashMap::new(),
    };

    // Populate all caches using the unified function
    config::populate_caches_from_config(
        &app_config,
        &initial_keys_cache,
        &initial_certs,
        &initial_upstream_cache,
        &initial_realm_map,
    );

    let jwt_keys_cache_swapper = Arc::new(ArcSwap::new(Arc::new(initial_keys_cache)));
    let cert_cache_swapper = Arc::new(ArcSwap::new(Arc::new(initial_certs)));
    let upstream_peer_swapper = Arc::new(ArcSwap::new(Arc::new(initial_upstream_cache)));
    let realm_map_swapper = Arc::new(ArcSwap::new(Arc::new(initial_realm_map)));

    // Determine the default certificate. For simplicity, we use the first one found.
    let default_cert = cert_cache_swapper
        .load()
        .cert_map
        .iter() // Use .iter() to get an iterator
        .next() // Get the first key-value pair
        .map(|pair| pair.value().clone()) // Extract and clone the value (the Arc<CertAndKey>)
        .expect("At least one certificate must be configured to serve as the default.");

    let mut my_server = Server::new(Some(opt))?;

    // Create an index to store SNI in the SSL session
    let sni_ex_data_index = match Ssl::new_ex_index::<Option<String>>() {
        Ok(index) => index,
        Err(e) => {
            let mut err = pingora::Error::new(pingora::ErrorType::InternalError);
            err.set_cause(e);
            return Err(err);
        }
    };

    // Create and add the configuration hot reload service.
    let signal_reload_service = config::SignalReloadService::new(
        jwt_keys_cache_swapper.clone(),
        cert_cache_swapper.clone(),
        upstream_peer_swapper.clone(),
        realm_map_swapper.clone(),
        main_config_swapper.clone(),
        config_path,
        initial_config_content,
    );
    my_server.add_service(background_service("Config Reloader", signal_reload_service));

    // Create and add the session cleanup service.
    let session_cleanup_service = background_services::SessionCleanupService::new();
    my_server.add_service(background_service("Session Cleaner", session_cleanup_service));

    // Initialize a shared HTTP client for outbound requests (e.g., OIDC).
    // This enables connection pooling to reduce TLS handshake overhead.
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");

    let gw = GatewayRouter {
        upstream_peer_cache: upstream_peer_swapper,
        sni_ex_data_index: sni_ex_data_index.clone(),
        jwt_keys_cache: jwt_keys_cache_swapper,
        realm_map: realm_map_swapper.clone(),
        main_config: main_config_swapper,
        _gateway_start_time: gateway_start_time,
        http_client,
    };

    let mut gateway_service = http_proxy_service(&my_server.configuration, gw);
    let selector = SniCertificateSelector {
        sni_ex_data_index: sni_ex_data_index.clone(),
        cert_cache: cert_cache_swapper.clone(),
        realm_map: realm_map_swapper.clone(),
        default_cert,
    };

    // TLS settings for select Certificate and get SNI
    let tls_settings_tcp =
        pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(selector))?;

    gateway_service.add_tls_with_settings(&gateway_listen_addr, None, tls_settings_tcp);
    my_server.add_service(gateway_service);
    info!(
        "Gateway server starting on {}. Preparation took {:?}",
        gateway_listen_addr,
        gateway_start_time.elapsed()
    );

    // Create a separate service for HTTP redirects
    let mut redirect_service = http_proxy_service(&my_server.configuration, HttpRedirectRouter {
        tls_port,
        realm_map: realm_map_swapper.clone(),
    });
    redirect_service.add_tcp(&redirect_service_listen_addr);
    my_server.add_service(redirect_service);
    info!(
        "Redirect server starting on {}. Preparation took {:?}",
        redirect_service_listen_addr,
        gateway_start_time.elapsed()
    );

    my_server.run_forever();
}
