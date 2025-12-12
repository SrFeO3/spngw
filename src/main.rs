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
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod actions;
use actions::{GatewayAction, RouteLogic};

mod config;
use crate::config::{AppConfig, CertificateCache, JwtSigningKeys, RealmConfig};

/// Core logic and shared state for the proxy service
///
/// This struct implements the `ProxyHttp` trait and holds all shared resources
/// required for request processing, such as upstream server definitions, the
/// session map, and cryptographic keys.
///
/// A single instance is created at startup and shared immutably across all
/// worker threads for the lifetime of the application.
struct GatewayRouter {
    upstream_peer_cache: Arc<DashMap<String, Arc<HttpPeer>>>,
    sni_ex_data_index: Index<Ssl, Option<String>>,
    jwt_keys: Arc<ArcSwap<JwtSigningKeys>>,
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

        // gateway actions
        // Set the default upstream for all routes that fall into this block.
        ctx.default_upstream_addr = Some("127.0.0.1:8081".to_string());

        // Build the pipeline of routes based on the request path.
        let path = session.req_header().uri.path();
        ctx.action_pipeline.clear();

        //
        // Set the action pipeline actions for this request.
        //

        // Set the default upstream for all routes that fall into this block.
        ctx.default_upstream_addr = Some("127.0.0.1:8081".to_string());

        // Build the pipeline of routes based on the request path.
        let path = session.req_header().uri.path();
        ctx.action_pipeline.clear();

        // All for DeviceCookie
        ctx.action_pipeline.push(GatewayAction::IssueDeviceCookie);

        // Terminal Actions
        if path == "/hello" {
            // This route terminates the request with a static response.
            ctx.action_pipeline.push(GatewayAction::ReturnStaticText {
                content: "Hello from your new generic route!".into(),
                status_code: 200,
            });
        } else if path == "/robot.txt" {
            // This route terminates the request with a static response.
            ctx.action_pipeline.push(GatewayAction::ReturnStaticText {
                content: "User-agent: *\nDisallow: /".into(),
                status_code: 200,
            });
        } else if path.starts_with("/static") {
            // This route proxies to a specific upstream.
            ctx.action_pipeline.push(GatewayAction::ProxyTo {
                upstream: "127.0.0.1:8083".into(),
            });
        } else if path.starts_with("/external") {
            // This route terminates the request with a redirect.
            ctx.action_pipeline.push(GatewayAction::Redirect {
                url: "https://ext.example.com/hello".into(),
            });
        }

        // Modifier Actions:
        match path {
            "/fruit/apple" => ctx
                .action_pipeline
                .push(GatewayAction::SetUpstreamRequestHeader {
                    name: "X-Sweet".into(),
                    value: "pie".into(),
                }),
            "/fruit/orange" => ctx
                .action_pipeline
                .push(GatewayAction::SetUpstreamRequestHeader {
                    name: "X-Drink".into(),
                    value: "juice".into(),
                }),
            "/fruit/banana" => {
                ctx.action_pipeline
                    .push(GatewayAction::SetDownstreamResponseHeader {
                        name: "X-Powered-By".into(),
                        value: "BFF-proxy".into(),
                    })
            }
            _ => {}
        }

        // Composite Actions
        if path.starts_with("/private/") {
            ctx.action_pipeline
                .push(GatewayAction::RequireAuthentication {
                    protected_backend_addr: "127.0.0.1:8082".into(), // Proxy to this backend if authenticated
                    oidc_login_redirect_url: "https://auth2.example.com/auth".into(), // OIDC provider's authorization endpoint
                    oidc_client_id: "my-client-2".into(),
                    oidc_callback_url: "http://127.0.0.1:8002/auth/callback".into(), // BFF's callback endpoint
                    oidc_token_endpoint_url: "http://127.0.0.1:8082/api/token".into(), // The OIDC token endpoint
                    scope_name: "private_scope".into(),
                });
        } else if path.starts_with("/protected/") {
            ctx.action_pipeline
                .push(GatewayAction::RequireAuthentication {
                    protected_backend_addr: "127.0.0.1:8083".into(), // Proxy to this backend if authenticated
                    oidc_login_redirect_url: "https://auth.example.com/auth".into(), // OIDC provider's authorization endpoint
                    oidc_client_id: "my-client-1".into(),
                    oidc_callback_url: "http://127.0.0.1:8001/auth/callback".into(), // BFF's callback endpoint
                    oidc_token_endpoint_url: "http://127.0.0.1:8081/api/token".into(), // The OIDC token endpoint
                    scope_name: "protected_scope".into(),
                });
        }

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
                    scope_name,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_backend_addr,
                        oidc_login_redirect_url,
                        oidc_client_id,
                        oidc_callback_url,
                        oidc_token_endpoint_url,
                        scope_name,
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
        // !!!!!
        let peer = self
            .upstream_peer_cache
            .get(upstream_addr)
            .map(|p| p.value().clone())
            .unwrap_or_else(|| {
                panic!(
                    "[{}] Upstream peer not found in cache for address: {}",
                    ctx.request_id, upstream_addr
                )
            });

        Ok(Box::new((*peer).clone()))
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
                    scope_name,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_backend_addr,
                        oidc_login_redirect_url,
                        oidc_client_id,
                        oidc_callback_url,
                        oidc_token_endpoint_url,
                        scope_name,
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
                    scope_name,
                } => {
                    let logic = actions::RequireAuthenticationRoute {
                        protected_backend_addr: protected_backend_addr.clone(),
                        oidc_login_redirect_url: oidc_login_redirect_url.clone(),
                        oidc_client_id: oidc_client_id.clone(),
                        oidc_callback_url: oidc_callback_url.clone(),
                        oidc_token_endpoint_url: oidc_token_endpoint_url.clone(),
                        scope_name: scope_name.clone(),
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

    // Register authentication scopes. This initializes the session stores within the actions module.
    actions::register_auth_scope("protected_scope");
    actions::register_auth_scope("private_scope");
    // Add more scopes as needed, e.g., for /admin, /shop, etc.
    // actions::register_auth_scope("admin_scope");

    // Create an upstream peer cache to store pre-configured HttpPeer objects for each backend.
    let upstream_peer_cache = Arc::new(DashMap::new());
    upstream_peer_cache.insert(
        "127.0.0.1:8081".to_string(),
        Arc::new(HttpPeer::new("127.0.0.1:8081", false, "".to_string())),
    );
    upstream_peer_cache.insert(
        "127.0.0.1:8082".to_string(),
        Arc::new(HttpPeer::new("127.0.0.1:8082", false, "".to_string())),
    );
    upstream_peer_cache.insert(
        "127.0.0.1:8083".to_string(),
        Arc::new(HttpPeer::new("127.0.0.1:8083", false, "".to_string())),
    );
    // Add more upstreams as needed, e.g., for 127.0.0.1:9001, 127.0.0.1:9002 etc.

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
        initial_config_content,
    );
    my_server.add_service(background_service("Config Reloader", config_reload_service));

    let gw = GatewayRouter {
        upstream_peer_cache,
        sni_ex_data_index: sni_ex_data_index.clone(),
        jwt_keys,
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
