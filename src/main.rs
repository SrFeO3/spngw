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
//   - Implement proxy rule action pipeline
//   - Implement application session and background session cleaner
//   - Implement operational settings to be configured externally.
//   - Implement /api/logout endpoint to invalidate session and tokens.
//   - Implement a lock for token refresh to prevent dog-piling effect.
//   - Review the backend SSL implementation for Pingora (currently using boringssl).

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
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Application's cryptographic keys
///　Used for signing and validating JWTs. (e.g., `DEVICE_CONTEXT`).
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

/// Container for all upstream peer definitions
struct UpstreamSet {
    sni_map: Arc<DashMap<String, Arc<HttpPeer>>>,
    no_sni: Arc<HttpPeer>,
    fallback: Arc<HttpPeer>,
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
    upstreams: UpstreamSet,
    sni_ex_data_index: Index<Ssl, Option<String>>,
    keys: Arc<JwtSigningKeys>,
    gateway_start_time: Instant,
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
    upstream_sni_name: Option<String>,
}

#[async_trait]
impl ProxyHttp for GatewayRouter {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx {
            request_id: format!("req-{}", rand::random::<u32>()),
            request_start_time: Instant::now(),
            upstream_sni_name: None,
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
        let sni: Option<String> = sni_opt.and_then(|s| s.as_deref().map(String::from));
        let upstream_sni_name = match sni.as_deref() {
            Some(sni_name) => {
                if sni_name == "bff.wgd.example.com"
                    || self.upstreams.sni_map.contains_key(sni_name)
                {
                    info!("[{}] SNI found: {}. Got specific upstream.", ctx.request_id, sni_name);
                    sni_name.to_string()
                } else {
                    info!("[{}] SNI found: {}. But no specific upstream. Using fallback upstream.", ctx.request_id, sni_name);
                    self.upstreams.fallback.sni.clone()
                }
            }
            None => {
                info!("[{}] No SNI found. Using no-SNI upstream.", ctx.request_id);
                self.upstreams.no_sni.sni.clone()
            }
        };
        ctx.upstream_sni_name = Some(upstream_sni_name);

        // filter logincs here

        Ok(false) // Continue to the next phase
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Use the upstream name that was already determined in request_filter.
        let upstream_sni_name = ctx.upstream_sni_name.as_deref().unwrap_or_default();

        let upstream = {
            if upstream_sni_name == self.upstreams.no_sni.sni {
                self.upstreams.no_sni.clone()
            } else if upstream_sni_name == self.upstreams.fallback.sni {
                self.upstreams.fallback.clone()
            } else {
                // Look up the peer from the upstreams map.
                // If not found (which shouldn't happen if logic is consistent), use fallback.
                self.upstreams
                    .sni_map
                    .get(upstream_sni_name)
                    .map(|p| p.value().clone())
                    .unwrap_or_else(|| {
                        warn!(
                            "[{}] Upstream for SNI '{}' not found, using fallback.",
                            ctx.request_id,
                            upstream_sni_name
                        );
                        self.upstreams.fallback.clone()
                    })
            }
        };

        info!("[{}] Forwarding to upstream: {}", ctx.request_id, upstream);
        // HttpPeer is Clone, so we can clone it from the Arc.
        Ok(Box::new((*upstream).clone()))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        {
            // Use the upstream name that was already determined in request_filter.
            let upstream_sni_name = ctx.upstream_sni_name.as_deref().unwrap_or("");

            info!(
                "[{}] Reesponse started for {} {} from client {:?} with SNI: {:?}",
                ctx.request_id,
                session.req_header().method,
                session.req_header().uri,
                session.client_addr(),
                upstream_sni_name,
            );
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
    let keys = Arc::new(JwtSigningKeys::new());

    let opt = Opt {
        conf: Some("src/conf.yaml".to_string()),
        ..Default::default()
    };
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

    let upstreams = Arc::new(DashMap::new());

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

    // Upstream for requests with no SNI
    let no_sni_upstream = Arc::new(HttpPeer::new("127.0.0.1:8080", false, "".to_string()));

    // Fallback for any other SNI
    let fallback_upstream = Arc::new(HttpPeer::new("127.0.0.1:8089", false, "".to_string()));

    let upstream_set = UpstreamSet {
        sni_map: upstreams,
        no_sni: no_sni_upstream,
        fallback: fallback_upstream,
    };

    let router_logic = GatewayRouter {
        upstreams: upstream_set,
        sni_ex_data_index: sni_ex_data_index.clone(),
        keys,
        gateway_start_time,
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

    // TLS settings for select Certificate and get SNI
    let tls_settings_tcp =
        pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(selector))?;

    let listen_addr = "0.0.0.0:8000";
    http_service.add_tls_with_settings(listen_addr, None, tls_settings_tcp);
    my_server.add_service(http_service);

    info!("Gateway server starting on {}. Preparation took {:?}", listen_addr, gateway_start_time.elapsed());

    my_server.run_forever();
}
