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
// - Consider adding a route for requests with no SNI found in the filter
// - Consider handling cases where no upstream is found in upstream_peer
// - Implement RequireAuthentication action
// - Implement the proxy rule action pipeline
// - Consider default TLS cert
// - Implement application sessions and background session cleaner
// - Implement operational settings to be configured externally
// - Implement `/api/logout` endpoint to invalidate sessions and tokens
// - Implement a lock for token refresh to prevent the dog-piling effect
// - Review the backend SSL implementation using Pingora (currently using boringssl)

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use boring::ex_data::Index;
use dashmap::DashMap;
use log::{error, info, warn};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pingora::tls::pkey::Private;
use pingora::tls::ssl::Ssl;

mod actions;
use actions::{GatewayAction, RouteLogic};

mod config;
use crate::config::{
    ActionConfig, AppConfig, AuthScopeRegistry, CertificateCache, JwtSigningKeys, UpstreamCache,
};

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
    jwt_keys: Arc<ArcSwap<JwtSigningKeys>>,
    main_config: Arc<ArcSwap<AppConfig>>,
    _gateway_start_time: Instant,
}

/// Context that holds state for each HTTP request
///
/// An instance of this struct is created for each request via `ProxyHttp::new_ctx()`
/// and is passed through the different phases of the request proxying lifecycle
/// (e.g., `request_filter`, `upstream_peer`). Its lifetime is tied to a single
/// request-response cycle.
struct GatewayCtx {
    request_id: String,
    request_start_time: Instant,
    // JWT signing keys for the current request, passed from the GatewayRouter.
    jwt_keys: Arc<JwtSigningKeys>,
    upstream_sni_name: Option<String>,
    // Pipeline of routes to be applied to the request
    action_pipeline: Vec<GatewayAction>,
    // The default upstream address for the request, can be overridden by an action.
    pub default_upstream_addr: Option<String>,
    // The upstream address set by an action, which overrides the default.
    pub override_upstream_addr: Option<String>,

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
    pub action_state_new_dev_cookie: Option<String>,
    // Set by RequireAuthentication action when a new session is created
    pub action_state_new_app_session_cookie: Option<(String, String)>, // (value, scope_name)
    // Set by RequireAuthentication action
    pub action_state_app_session: Option<actions::ApplicationSession>,
}

#[async_trait]
impl ProxyHttp for GatewayRouter {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx {
            request_id: format!("req-{}", rand::random::<u32>()),
            request_start_time: Instant::now(),
            // Load the current value from the ArcSwap.
            // .load() returns a Guard, which dereferences to an Arc<JwtSigningKeys>.
            // We clone the Arc so that the context owns it for the lifetime of the request.
            jwt_keys: self.jwt_keys.load().clone(),
            upstream_sni_name: None,
            action_pipeline: Vec::new(),
            default_upstream_addr: None,
            override_upstream_addr: None,
            action_state_new_dev_cookie: None,
            action_state_new_app_session_cookie: None,
            action_state_app_session: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        info!(
            "[{}] New request received for path: {}",
            ctx.request_id,
            session.req_header().uri.path()
        );

        //
        // Get SNI from the ex_data stored during the TLS handshake and set to no_sni_upstream.sni.
        //
        let sni_opt = session
            .stream()
            .unwrap()
            .get_ssl()
            .and_then(|ssl| ssl.ex_data(self.sni_ex_data_index));
        let sni: Option<String> = sni_opt.and_then(|s| s.as_deref().map(String::from));
        let upstream_sni_name = match sni.as_deref() {
            Some(sni_name) => {
                info!("[{}] SNI found: {}", ctx.request_id, sni_name);
                sni_name.to_string()
            }
            None => {
                info!("[{}] No SNI found. Using no-SNI upstream.", ctx.request_id);
                "bad sni".to_string() // !!!!!
            }
        };
        ctx.upstream_sni_name = Some(upstream_sni_name);

        //
        // Set the action pipeline actions for this request.
        //

        // Set the default upstream for all routes that fall into this block.
        ctx.default_upstream_addr = Some("127.0.0.1:8081".to_string());

        ctx.action_pipeline.clear();

        // All for DeviceCookie
        ctx.action_pipeline.push(GatewayAction::IssueDeviceCookie);

        // Dynamically generate Action Pipelines from config
        let path = session.req_header().uri.path();
        // For simplicity, we are using the first realm and its first routing chain.
        // A real-world scenario would involve matching the request's hostname to a virtual_host
        // and then finding the associated routing_chain.

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

        let app_config = self.main_config.load();
        if let Some(realm) = app_config.realms.get(0) {
            if let Some(chain) = realm.routing_chains.get(0) {
                info!(
                    "[{}] Using routing_chain '{}' for request",
                    ctx.request_id, chain.name
                );
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
                                &ctx.upstream_sni_name.clone().expect("").to_string(), // !!!
                                path,
                                &ctx.request_id,
                            );
                            let match2 = evaluate_single_expr(
                                part2,
                                &ctx.upstream_sni_name.clone().expect("").to_string(), // !!!
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
                            &ctx.upstream_sni_name.clone().expect("").to_string(), // !!!
                            path,
                            &ctx.request_id,
                        )
                    };

                    if is_match {
                        info!(
                            "[{}] Matched rule: '{}', applying action",
                            ctx.request_id, rule.match_expr
                        );
                        let action = match &rule.action {
                            ActionConfig::ReturnStaticText { content, status } => {
                                GatewayAction::ReturnStaticText {
                                    content: content.clone().into(),
                                    status_code: *status,
                                }
                            }
                            ActionConfig::Proxy { upstream } => GatewayAction::ProxyTo {
                                upstream: upstream.clone().into(),
                            },
                            ActionConfig::Redirect { url } => GatewayAction::Redirect {
                                url: url.clone().into(),
                            },
                            ActionConfig::SetUpstreamRequestHeader { name, value } => {
                                GatewayAction::SetUpstreamRequestHeader {
                                    name: name.clone().into(),
                                    value: value.clone().into(),
                                }
                            }
                            ActionConfig::SetDownstreamRequestHeader { name, value } => {
                                GatewayAction::SetDownstreamResponseHeader {
                                    name: name.clone().into(),
                                    value: value.clone().into(),
                                }
                            }
                            ActionConfig::RequireAuthentication {
                                protected_backend_addr,
                                oidc_login_redirect_url,
                                oidc_client_id,
                                oidc_callback_url,
                                oidc_token_endpoint_url,
                                auth_scope_name,
                            } => GatewayAction::RequireAuthentication {
                                protected_backend_addr: protected_backend_addr.clone().into(),
                                oidc_login_redirect_url: oidc_login_redirect_url.clone().into(),
                                oidc_client_id: oidc_client_id.clone().into(),
                                oidc_callback_url: oidc_callback_url.clone().into(),
                                oidc_token_endpoint_url: oidc_token_endpoint_url.clone().into(),
                                auth_scope_name: auth_scope_name.clone().into(),
                            },
                        };
                        ctx.action_pipeline.push(action);
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
        for action in ctx.action_pipeline.clone() {
            info!(
                "[{}] Pipeline: Executing request_filter_and_prepare_upstream_peer for action: {:?}",
                ctx.request_id, action
            );
            // Pass the session stores to the dispatch macro so it can construct the full scope.
            let early_exit = match action {
                GatewayAction::ReturnStaticText {
                    content,
                    status_code,
                } => {
                    let logic = actions::ReturnStaticTextRoute {
                        content,
                        status_code,
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
                    protected_backend_addr,
                    oidc_login_redirect_url,
                    oidc_client_id,
                    oidc_callback_url,
                    oidc_token_endpoint_url,
                    auth_scope_name,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_backend_addr,
                        oidc_login_redirect_url,
                        oidc_client_id,
                        oidc_callback_url,
                        oidc_token_endpoint_url,
                        auth_scope_name,
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
                GatewayAction::ProxyTo { upstream } => {
                    let logic = actions::ProxyToRoute { upstream };
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
                return Ok(true); // Stop the pipeline if a filter decides to exit early.
            }
        }

        Ok(false) // Continue to the next phase
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // The upstream address is now determined during the request_filter_and_prepare_upstream_peer phase and stored in the context.
        // We prioritize the address set by a specific action, and fall back to the default if none is set.
        let upstream_addr = ctx
            .override_upstream_addr
            .as_ref()
            .or(ctx.default_upstream_addr.as_ref())
            .expect(
                "Upstream address not set in GatewayCtx, neither by an action nor as a default",
            );

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
        for action in ctx.action_pipeline.clone() {
            info!(
                "[{}] Pipeline: Executing upstream_request_filter for action: {:?}",
                ctx.request_id, action
            );
            // Use the dispatch macro to call the upstream_request_filter method.
            match action {
                GatewayAction::ReturnStaticText {
                    content,
                    status_code,
                } => {
                    let logic = actions::ReturnStaticTextRoute {
                        content,
                        status_code,
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
                    protected_backend_addr,
                    oidc_login_redirect_url,
                    oidc_client_id,
                    oidc_callback_url,
                    oidc_token_endpoint_url,
                    auth_scope_name,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_backend_addr,
                        oidc_login_redirect_url,
                        oidc_client_id,
                        oidc_callback_url,
                        oidc_token_endpoint_url,
                        auth_scope_name,
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
                GatewayAction::ProxyTo { upstream } => {
                    let logic = actions::ProxyToRoute { upstream };
                    logic
                        .upstream_request_filter(session, upstream_request, ctx)
                        .await
                }
            }?;
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Dispatch to the response filter logic.
        // Loop through the pipeline in reverse order to apply response filters.
        // This follows the common middleware pattern (LIFO - Last-In, First-Out),
        // ensuring that the last request filter added is the first response filter executed.
        // We clone the pipeline to avoid borrow checker issues with `ctx`.
        for action in ctx.action_pipeline.clone().iter().rev() {
            info!(
                "[{}] Pipeline: Executing response_filter for action: {:?}",
                ctx.request_id, action
            );

            match action {
                GatewayAction::ReturnStaticText {
                    content,
                    status_code,
                } => {
                    let logic = actions::ReturnStaticTextRoute {
                        content: content.clone(),
                        status_code: *status_code,
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::SetUpstreamRequestHeader { name, value } => {
                    let logic = actions::SetUpstreamRequestHeaderRoute {
                        name: name.clone(),
                        value: value.clone(),
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::SetDownstreamResponseHeader { name, value } => {
                    let logic = actions::SetDownstreamResponseHeaderRoute {
                        name: name.clone(),
                        value: value.clone(),
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::RequireAuthentication {
                    protected_backend_addr,
                    oidc_login_redirect_url,
                    oidc_client_id,
                    oidc_callback_url,
                    oidc_token_endpoint_url,
                    auth_scope_name,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_backend_addr: protected_backend_addr.clone(),
                        oidc_login_redirect_url: oidc_login_redirect_url.clone(),
                        oidc_client_id: oidc_client_id.clone(),
                        oidc_callback_url: oidc_callback_url.clone(),
                        oidc_token_endpoint_url: oidc_token_endpoint_url.clone(),
                        auth_scope_name: auth_scope_name.clone(),
                    };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::IssueDeviceCookie => {
                    actions::IssueDeviceCookieRoute
                        .response_filter(session, response, ctx)
                        .await
                }
                GatewayAction::Redirect { url } => {
                    let logic = actions::RedirectRoute { url: url.clone() };
                    logic.response_filter(session, response, ctx).await
                }
                GatewayAction::ProxyTo { upstream } => {
                    let logic = actions::ProxyToRoute {
                        upstream: upstream.clone(),
                    };
                    logic.response_filter(session, response, ctx).await
                }
            }?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "[{}] Request finished for {} {} from {:?} with status {} in {:?}",
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
// L4 for get SNI string on TLS handshake
//
struct SniCertificateSelector {
    sni_ex_data_index: Index<Ssl, Option<String>>,
    cert_cache: Arc<ArcSwap<CertificateCache>>,
    default_cert: Arc<config::CertAndKey>,
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

    let opt = Opt {
        conf: Some("src/conf.yaml".to_string()),
        ..Default::default()
    };

    let gateway_start_time = Instant::now();
    let app_config = config::load_app_config();
    let main_config_swapper = Arc::new(ArcSwap::new(app_config.clone()));

    // Load initial JWT signing keys and wrap them in ArcSwap for hot-reloading.
    // For simplicity, we'll use the keys from the first realm defined in the config.
    // A more advanced implementation might select a realm based on the request's hostname.
    let initial_keys = config::JwtSigningKeys::from_realm_config(
        app_config
            .realms
            .get(0)
            .expect("Configuration must contain at least one realm."),
    );
    let jwt_keys = Arc::new(ArcSwap::new(Arc::new(initial_keys)));

    // Load initial certificates and wrap them in ArcSwap for hot-reloading.
    let initial_certs = CertificateCache::load_from_config(app_config.clone())
        .expect("Failed to load initial certificates");
    let cert_cache = Arc::new(ArcSwap::new(Arc::new(initial_certs)));

    // Determine the default certificate. For simplicity, we use the first one found.
    // !!!!!
    let default_cert = cert_cache
        .load()
        .cert_map
        .values()
        .next()
        .expect("At least one certificate must be configured to serve as the default.")
        .clone();

    // Create initial upstream peer cache and wrap it in ArcSwap for hot-reloading.
    let initial_upstreams = UpstreamCache::load_from_config(app_config.clone());
    let upstream_peer_swapper = Arc::new(ArcSwap::new(Arc::new(initial_upstreams)));

    // --- Initialize and register authentication scopes from config ---
    AuthScopeRegistry::reload_from_config(&app_config);
    let initial_auth_scope_registry = AuthScopeRegistry::default();
    let auth_scope_registry_swapper = Arc::new(ArcSwap::new(Arc::new(initial_auth_scope_registry)));

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

    // Read the initial config content to pass to the hot-reload service.
    // This ensures the service starts with the same state as the main application.
    let initial_config_content = std::fs::read_to_string(config::CONFIG_PATH)
        .expect("Failed to read initial configuration file content.");

    // Create and add the configuration hot reload service.
    let config_reload_service = config::ConfigHotReloadService::new(
        jwt_keys.clone(),
        cert_cache.clone(),
        upstream_peer_swapper.clone(),
        main_config_swapper.clone(),
        auth_scope_registry_swapper,
        initial_config_content,
    );
    my_server.add_service(background_service("Config Reloader", config_reload_service));

    let gw = GatewayRouter {
        upstream_peer_cache: upstream_peer_swapper,
        sni_ex_data_index: sni_ex_data_index.clone(),
        jwt_keys,
        main_config: main_config_swapper,
        _gateway_start_time: gateway_start_time,
    };

    let mut http_service = http_proxy_service(&my_server.configuration, gw);
    let selector = SniCertificateSelector {
        sni_ex_data_index: sni_ex_data_index.clone(),
        cert_cache,
        default_cert,
    };

    // TLS settings for select Certificate and get SNI
    let tls_settings_tcp =
        pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(selector))?;

    let listen_addr = "0.0.0.0:8000";
    http_service.add_tls_with_settings(listen_addr, None, tls_settings_tcp);
    my_server.add_service(http_service);

    info!(
        "Gateway server starting on {}. Preparation took {:?}",
        listen_addr,
        gateway_start_time.elapsed()
    );

    my_server.run_forever();
}
