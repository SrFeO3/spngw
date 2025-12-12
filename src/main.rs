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
// - Implement application sessions and background session cleaner
// - Implement operational settings to be configured externally
// - Implement `/api/logout` endpoint to invalidate sessions and tokens
// - Implement a lock for token refresh to prevent the dog-piling effect
// - Review the backend SSL implementation using Pingora (currently using boringssl)

use arc_swap::ArcSwap;
use async_trait::async_trait;
use boring::ex_data::Index;
use dashmap::DashMap;
use log::{error, info};
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

const JWT_PRIVATE_KEY_PEM_STRING: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD3rI43cNccdLsM
x97iHVZVLJEkj+aSso2AOYhuggZhg1wEAsxuULchGAT2ASloYnUuX4C3nKXhQX3S
Ku77gqv9s9FGOcJQEjIHO1ftNxE+VsfjN+9gfH28m1S5yRUQvDOZXPlPUrpSBtdA
5m/3pjo81wGetz8zTNbsZYipyS0Qy5J1wyVh0nxUlg0Dix+lJAsl9kj6P3ri2OhW
GvYk2yKQicbpNmY0GOM9KoW0PNMvELXaeDElANS43UhGoBxJyGNYwXBjru+hWlLf
27acVWOtuccUxTxuSZMXdaLMv7pk8o9Tbz5atjEfgQgSFOjIiGS0Jv0NIpRKIgZr
r4q+l83LAgMBAAECggEALuPI0v82gokpBozqigWC3EJBQlpKDVjniDCcP0u3mIuN
hqbe/D2kxgutmMN0ivIk/EARdvGdyA0lnH4LW6uME06RXsm9m3ouZYcbKOplhddZ
JY/n7mzzQxtnSXsj1VTEMhNTkex4IOJxqzRVW13ppa4Q/PL1cKlqATxhyL8xHH4G
pmq8Q899T7OW7vLdysede68sjbA04fL/gaPNxPj5TpsPKvreIQRpziXDoJCalMp9
EUi0CbzpoVheahJlSi6In9byRxGauVIao+BgNh/NNYqVnj/Tp6X2YGnhN5UXYA+j
V4xMjmKFgHIFaptpUTudpyAZZnG/WQVKJDeixhscaQKBgQD9MpJw0cgLhRenwL0V
zJeMlt1OwnA4sbbmxUS67eAy31cZzUS6N2cF+2RaP0WjGSnZyxcXPA72HXnM8/dP
B5tX6ce9PJ0px7YtOnwwcjGMKqQsPALF9Uvm5FfuWlCdHaHzfUv2wUGS8ON6cJDW
qgufBrMynmtw8ZG1Wr+5MIiRgwKBgQD6alUzZrAJOwM/IYdIte3YISx4a69j0epc
Vh7Bzm3tQYF02nSFpMSKX8sQeQ5wFx4gjhGWJp3tn0xrWrsN44b0oG4zKE9QaRVJ
hCzBa/Ka+p/EsXc/kc9CSMuylJ20LtA0B5TEgYJ8QzzCA8BsRUc47+JkR3gO1N9w
jS5bPfyIGQKBgQC6f9Kv+UXBfoJDFUvxz6Zdbw6KIdxpVjWj2/BZRDgdILdWkQUr
qP1gwaBUfUB8918FRnu2qI1YqbN6zMUAWFkLM27lq80T5kABJpAtWx+13/7XekiM
qbcD1nQSZEH2yMnuwP8APa9gXcEhAeMdy1kOBPBfu6LmKXmrPLH15ZLiowKBgDgO
u7oA/+FhG43zZISLbY4XhwwCF0ZCRLOc98+s9YDKTD+rc7BDPVg4r42le+ztz+m7
xAYX6Py7z3Cs4/js+VYj3+eF25OFoqVNeHNoRewZtNBkZeyOKJaPE0KL8G3YmPU8
yTngQCSvLJfGHTpfm90MHmMSeLbhQo/AmyMD0ldpAoGBAJ9tQ3R33AYkkjCJSc/u
8X121N2+URZxuA23bMJH6OoJddtz8AFyKV36ihbVKrJ1/mcXkdZ9+WEszQaVsGsm
CvsxaZWlMj4yZoVCx7ZqrFx17AThlxCpi7rFoFZbkk+M9+RX6U8d8r39qyfqjJFp
0kaUPHgv1Qgvn5SYcebU+AQ4
-----END PRIVATE KEY-----"#;

const JWT_PUBLIC_KEY_PEM_STRING: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA96yON3DXHHS7DMfe4h1W
VSyRJI/mkrKNgDmIboIGYYNcBALMblC3IRgE9gEpaGJ1Ll+At5yl4UF90iru+4Kr
/bPRRjnCUBIyBztX7TcRPlbH4zfvYHx9vJtUuckVELwzmVz5T1K6UgbXQOZv96Y6
PNcBnrc/M0zW7GWIqcktEMuSdcMlYdJ8VJYNA4sfpSQLJfZI+j964tjoVhr2JNsi
kInG6TZmNBjjPSqFtDzTLxC12ngxJQDUuN1IRqAcSchjWMFwY67voVpS39u2nFVj
rbnHFMU8bkmTF3WizL+6ZPKPU28+WrYxH4EIEhToyIhktCb9DSKUSiIGa6+KvpfN
ywIDAQAB
-----END PUBLIC KEY-----"#;

/// Application's cryptographic keys
///　Used for signing and validating JWTs. (e.g., `DEVICE_CONTEXT`).
struct JwtSigningKeys {
    public_key_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

impl JwtSigningKeys {
    fn new() -> Self {
        JwtSigningKeys {
            public_key_pem: JWT_PUBLIC_KEY_PEM_STRING.as_bytes().to_vec(),
            private_key_pem: JWT_PRIVATE_KEY_PEM_STRING.as_bytes().to_vec(),
        }
    }
}

// Certificate and its corresponding private key
struct CertAndKey {
    cert: pingora::tls::x509::X509,
    key: pingora::tls::pkey::PKey<Private>,
}

// All loaded certificates, which can be reloaded atomically
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

// Background service to periodically reload certificates.
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
    jwt_keys: Arc<JwtSigningKeys>,
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
    pub jwt_keys: Arc<JwtSigningKeys>,
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
            jwt_keys: self.jwt_keys.clone(),
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

fn main() -> pingora::Result<()> {
    env_logger::init();

    let gateway_start_time = Instant::now();
    let jwt_keys = Arc::new(JwtSigningKeys::new());

    let opt = Opt {
        conf: Some("src/conf.yaml".to_string()),
        ..Default::default()
    };

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

    let gw = GatewayRouter {
        upstream_peer_cache,
        sni_ex_data_index: sni_ex_data_index.clone(),
        jwt_keys,
        _gateway_start_time: gateway_start_time,
    };

    let mut http_service = http_proxy_service(&my_server.configuration, gw);
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
