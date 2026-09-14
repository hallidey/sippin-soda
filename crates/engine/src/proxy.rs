use crate::{
    authorize, establish_verified_tls_with_config, platform_tls_client_config, Action, CaManager,
    DestinationClass, EnginePhase, EngineStatus, IssuedLeaf, TlsClientIdentity, TlsInterceptError,
    TlsTrustCheckManager, HTTP2_ALPN, INSPECTION_ALPN,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
mod bodies;
mod tunnel;
pub use bodies::{BodyPage, JsonStatus, SearchStep};
use bodies::{BodyStore, RecordedBody};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{HeaderMap, HeaderValue, HOST},
    http::uri::Authority,
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::rustls::ClientConfig;
use tunnel::Tunnel;

type WireBody = BoxBody<Bytes, hyper::Error>;

enum UpstreamSender {
    Http1(hyper::client::conn::http1::SendRequest<RequestBody>),
    Http2(hyper::client::conn::http2::SendRequest<RequestBody>),
}

impl UpstreamSender {
    fn is_http2(&self) -> bool {
        matches!(self, Self::Http2(_))
    }

    async fn send_request(
        &mut self,
        request: Request<RequestBody>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            Self::Http1(sender) => sender.send_request(request).await,
            Self::Http2(sender) => sender.send_request(request).await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub capture_limit: usize,
    pub connection_limit: usize,
    pub request_timeout: Duration,
    pub tunnel_timeout: Duration,
    pub capture_bodies: bool,
    pub body_disk_budget: u64,
    pub request_redaction_paths: Vec<String>,
    pub development_hosts: Vec<String>,
    pub production_hosts: Vec<String>,
    pub client_auth: Option<ProxyClientAuth>,
    pub tls_interception: Option<ProxyTlsInterception>,
    pub break_on_responses: bool,
}

type LeafIssuer =
    dyn Fn(&str, DestinationClass) -> Result<Option<IssuedLeaf>, String> + Send + Sync;

#[derive(Clone)]
pub struct ProxyTlsInterception {
    profile_id: String,
    upstream_config: Arc<ClientConfig>,
    issue_leaf: Arc<LeafIssuer>,
}

impl fmt::Debug for ProxyTlsInterception {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyTlsInterception")
            .field("profile_id", &self.profile_id)
            .finish_non_exhaustive()
    }
}

impl ProxyTlsInterception {
    pub fn platform(
        ca: Arc<CaManager>,
        trust: Arc<TlsTrustCheckManager>,
        profile_id: &str,
    ) -> Result<Self, String> {
        let profile_id = TlsClientIdentity::validate_id(profile_id)?;
        let proof_profile_id = profile_id.clone();
        let issue_leaf = Arc::new(move |host: &str, destination: DestinationClass| {
            if destination != DestinationClass::Development {
                return Ok(None);
            }
            let status = ca.status()?;
            let ready = trust
                .readiness(&status, &proof_profile_id)
                .is_some_and(|readiness| readiness.can_inspect_development);
            if !ready {
                return Ok(None);
            }
            let leaf = ca.issue_leaf(host, destination)?;
            if Some(&leaf.issuer_fingerprint_sha256) != status.fingerprint_sha256.as_ref() {
                return Err("The local CA changed while preparing TLS interception.".into());
            }
            Ok(Some(leaf))
        });
        Ok(Self {
            profile_id,
            upstream_config: platform_tls_client_config()?,
            issue_leaf,
        })
    }

    fn profile_id(&self) -> &str {
        &self.profile_id
    }

    async fn prepare(
        &self,
        host: &str,
        destination: DestinationClass,
        client_profile_id: Option<&str>,
    ) -> Result<Option<TlsInterceptRoute>, String> {
        if destination != DestinationClass::Development
            || client_profile_id != Some(self.profile_id())
        {
            return Ok(None);
        }
        let issue_leaf = self.issue_leaf.clone();
        let host = host.to_owned();
        let worker_host = host.clone();
        let leaf = tokio::task::spawn_blocking(move || issue_leaf(&worker_host, destination))
            .await
            .map_err(|_| "TLS certificate worker failed.".to_string())??;
        Ok(leaf.map(|leaf| TlsInterceptRoute {
            host,
            leaf,
            upstream_config: self.upstream_config.clone(),
        }))
    }
}

struct TlsInterceptRoute {
    host: String,
    leaf: IssuedLeaf,
    upstream_config: Arc<ClientConfig>,
}

#[derive(Debug, Clone)]
pub struct ProxyClientAuth {
    profile_id: String,
    token_sha256: [u8; 32],
}

impl ProxyClientAuth {
    pub fn new(profile_id: &str, token: &str) -> Result<Self, String> {
        let profile_id = TlsClientIdentity::validate_id(profile_id)?;
        if !(32..=128).contains(&token.len())
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("Proxy client tokens must use 32-128 letters, numbers, '-' or '_'.".into());
        }
        Ok(Self {
            profile_id,
            token_sha256: Sha256::digest(token.as_bytes()).into(),
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    fn accepts(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers
            .get("proxy-authorization")
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let Some(encoded) = value
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
            .map(|(_, encoded)| encoded.trim())
        else {
            return false;
        };
        let Ok(decoded) = BASE64.decode(encoded) else {
            return false;
        };
        let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
            return false;
        };
        let (profile_id, token) = decoded.split_at(separator);
        let token = &token[1..];
        let presented_token_sha256: [u8; 32] = Sha256::digest(token).into();
        profile_id == self.profile_id.as_bytes()
            && bool::from(presented_token_sha256.ct_eq(&self.token_sha256))
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            capture_limit: 200,
            connection_limit: 64,
            request_timeout: Duration::from_secs(30),
            tunnel_timeout: Duration::from_secs(300),
            capture_bodies: false,
            body_disk_budget: 10 * 1024 * 1024 * 1024,
            request_redaction_paths: vec![],
            development_hosts: vec![],
            production_hosts: vec![],
            client_auth: None,
            tls_interception: None,
            break_on_responses: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    pub id: u64,
    pub kind: String,
    pub method: String,
    pub target: String,
    pub destination_class: DestinationClass,
    pub client_profile_id: Option<String>,
    pub started_at: u64,
    pub status: Option<u16>,
    pub phase: String,
    pub duration_ms: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub error: Option<String>,
    pub request_body_state: String,
    pub request_body_error: Option<String>,
    pub response_body_error: Option<String>,
    pub breakpoint_state: String,
    pub original_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub revision: u64,
    pub status: EngineStatus,
    pub traffic: Vec<Capture>,
}

#[derive(Clone)]
enum HostPattern {
    Exact(String),
    Suffix(String),
}

impl HostPattern {
    fn compile(value: &str) -> Result<Self, String> {
        let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if value.is_empty() || value.len() > 253 || !value.is_ascii() {
            return Err(
                "Destination host rules must be non-empty ASCII names up to 253 characters.".into(),
            );
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') || !valid_hostname(suffix) {
                return Err("Host wildcards must use the form *.example.com.".into());
            }
            Ok(Self::Suffix(suffix.into()))
        } else if value.contains('*') {
            Err("Host wildcards must use the form *.example.com.".into())
        } else {
            let unbracketed = value
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(&value);
            if unbracketed.parse::<std::net::IpAddr>().is_err() && !valid_hostname(unbracketed) {
                return Err(
                    "Host rules must be DNS names or IP addresses without a port or URL scheme."
                        .into(),
                );
            }
            Ok(Self::Exact(unbracketed.into()))
        }
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(expected) => host == expected,
            Self::Suffix(suffix) => {
                host.len() > suffix.len()
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(left), Self::Exact(right)) => left == right,
            (Self::Exact(host), pattern) | (pattern, Self::Exact(host)) => pattern.matches(host),
            (Self::Suffix(left), Self::Suffix(right)) => {
                left == right
                    || left.ends_with(&format!(".{right}"))
                    || right.ends_with(&format!(".{left}"))
            }
        }
    }
}

fn valid_hostname(value: &str) -> bool {
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

#[derive(Clone, Default)]
struct DestinationClassifier {
    development: Vec<HostPattern>,
    production: Vec<HostPattern>,
}

impl DestinationClassifier {
    fn compile(development: &[String], production: &[String]) -> Result<Self, String> {
        if development.len() > 128 || production.len() > 128 {
            return Err(
                "At most 128 Development and 128 Production host rules are allowed.".into(),
            );
        }
        let development = development
            .iter()
            .map(|value| HostPattern::compile(value))
            .collect::<Result<Vec<_>, _>>()?;
        let production = production
            .iter()
            .map(|value| HostPattern::compile(value))
            .collect::<Result<Vec<_>, _>>()?;
        if development
            .iter()
            .any(|dev| production.iter().any(|prod| dev.overlaps(prod)))
        {
            return Err(
                "Development and Production host rules overlap; classification must be unambiguous."
                    .into(),
            );
        }
        Ok(Self {
            development,
            production,
        })
    }

    fn classify(&self, host: &str) -> DestinationClass {
        let host = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if self.production.iter().any(|pattern| pattern.matches(&host)) {
            DestinationClass::Production
        } else if self
            .development
            .iter()
            .any(|pattern| pattern.matches(&host))
            || host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
        {
            DestinationClass::Development
        } else {
            DestinationClass::Unknown
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyExportPreview {
    pub id: u64,
    pub direction: String,
    pub bytes: u64,
    pub state: String,
    pub encoding: String,
    pub redacted: bool,
    pub warning: String,
    pub suggested_file_name: String,
}

struct State {
    revision: u64,
    next_id: u64,
    status: EngineStatus,
    traffic: VecDeque<Capture>,
    limit: usize,
    request_bodies: Arc<BodyStore>,
    response_bodies: Arc<BodyStore>,
    capture_bodies: bool,
    body_budget: u64,
    request_redaction_paths: Vec<Vec<String>>,
    destination_classifier: DestinationClassifier,
    break_on_responses: bool,
    breakpoints: HashMap<u64, oneshot::Sender<BreakpointDecision>>,
}

struct BreakpointDecision {
    status: Option<StatusCode>,
    body: Option<Bytes>,
    content_type: Option<HeaderValue>,
}

type Shared = Arc<Mutex<State>>;

struct Running {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Lifecycle operations are serialized. Snapshots never expose raw URLs,
/// credential values or payload data, and are bounded by the capture limit.
pub struct ProxyEngine {
    shared: Shared,
    running: tokio::sync::Mutex<Option<Running>>,
}

impl Default for ProxyEngine {
    fn default() -> Self {
        let (request_bodies, response_bodies) = BodyStore::shared_pair();
        Self {
            shared: Arc::new(Mutex::new(State {
                revision: 0,
                next_id: 1,
                status: EngineStatus::default(),
                traffic: VecDeque::new(),
                limit: 200,
                request_bodies,
                response_bodies,
                capture_bodies: false,
                body_budget: 0,
                request_redaction_paths: vec![],
                destination_classifier: DestinationClassifier::default(),
                break_on_responses: false,
                breakpoints: HashMap::new(),
            })),
            running: tokio::sync::Mutex::new(None),
        }
    }
}

impl ProxyEngine {
    pub fn resolve_response_breakpoint(
        &self,
        id: u64,
        status: Option<u16>,
        body: Option<String>,
        content_type: Option<String>,
    ) -> Result<Snapshot, String> {
        let status = status
            .map(|value| {
                StatusCode::from_u16(value)
                    .ok()
                    .filter(|status| {
                        status.is_success()
                            || status.is_redirection()
                            || status.is_client_error()
                            || status.is_server_error()
                    })
                    .ok_or("Replacement status must be between 200 and 599.")
            })
            .transpose()?;
        let body = body.map(Bytes::from);
        if body.as_ref().is_some_and(|body| body.len() > 64 * 1024) {
            return Err("Replacement body must be at most 65536 UTF-8 bytes.".into());
        }
        if content_type.is_some() && body.is_none() {
            return Err("Content-Type can be replaced only with a replacement body.".into());
        }
        let content_type = content_type
            .map(|value| {
                if value.trim().is_empty() || value.len() > 128 || value.contains(['\r', '\n']) {
                    return Err("Replacement Content-Type is invalid or longer than 128 bytes.");
                }
                HeaderValue::from_str(value.trim())
                    .map_err(|_| "Replacement Content-Type is invalid or longer than 128 bytes.")
            })
            .transpose()?;
        let sender = self
            .shared
            .lock()
            .unwrap()
            .breakpoints
            .remove(&id)
            .ok_or("Response breakpoint is no longer waiting.")?;
        sender
            .send(BreakpointDecision {
                status,
                body,
                content_type,
            })
            .map_err(|_| "Response breakpoint closed.".to_string())?;
        Ok(self.snapshot())
    }
    pub fn body_export_preview(
        &self,
        id: u64,
        direction: &str,
    ) -> Result<BodyExportPreview, String> {
        let state = self.shared.lock().unwrap();
        let capture = state
            .traffic
            .iter()
            .find(|capture| capture.id == id)
            .ok_or("Capture cleared or evicted.")?;
        let (store, redacted, error) = match direction {
            "request" => (
                state.request_bodies.clone(),
                true,
                capture.request_body_error.as_ref(),
            ),
            "response" => (
                state.response_bodies.clone(),
                false,
                capture.response_body_error.as_ref(),
            ),
            _ => return Err("Body direction must be request or response.".into()),
        };
        if let Some(error) = error {
            return Err(error.clone());
        }
        let info = store.info(id)?;
        if info.state != "complete" {
            return Err(info.error.unwrap_or_else(|| {
                "Only a complete body can be exported; wait for recording to finish.".into()
            }));
        }
        Ok(BodyExportPreview {
            id,
            direction: direction.into(),
            bytes: info.total,
            state: info.state,
            encoding: info.encoding,
            redacted,
            warning: if redacted {
                "This exports the redacted JSON inspection copy, not the original request bytes. Review custom fields before sharing it."
                    .into()
            } else {
                "This response body is unredacted and may contain credentials or personal data. Review it before sharing."
                    .into()
            },
            suggested_file_name: format!(
                "sippin-{id}-{direction}.{}",
                if redacted { "json" } else { "bin" }
            ),
        })
    }

    pub async fn export_body(
        &self,
        id: u64,
        direction: &str,
        destination: std::path::PathBuf,
    ) -> Result<u64, String> {
        self.body_export_preview(id, direction)?;
        let store = match direction {
            "request" => self.shared.lock().unwrap().request_bodies.clone(),
            "response" => self.shared.lock().unwrap().response_bodies.clone(),
            _ => return Err("Body direction must be request or response.".into()),
        };
        store.export(id, destination).await
    }

    pub async fn search_request_body(
        &self,
        id: u64,
        needle: String,
        start: u64,
        end: u64,
    ) -> Result<SearchStep, String> {
        let bodies = self.shared.lock().unwrap().request_bodies.clone();
        bodies.search(id, needle, start, end).await
    }
    pub fn request_json_view(
        &self,
        id: u64,
        start: bool,
        cancel: bool,
    ) -> Result<JsonStatus, String> {
        let bodies = self.shared.lock().unwrap().request_bodies.clone();
        bodies.json_view(id, start, cancel)
    }
    pub async fn request_json_page(
        &self,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<BodyPage, String> {
        let bodies = self.shared.lock().unwrap().request_bodies.clone();
        bodies.json_page(id, offset, length).await
    }
    pub async fn request_body_page(
        &self,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<BodyPage, String> {
        let bodies = {
            let state = self.shared.lock().unwrap();
            let capture = state
                .traffic
                .iter()
                .find(|capture| capture.id == id)
                .ok_or("Capture cleared or evicted.")?;
            if let Some(error) = &capture.request_body_error {
                return Err(error.clone());
            }
            state.request_bodies.clone()
        };
        bodies.page(id, offset, length).await
    }
    pub async fn search_response_body(
        &self,
        id: u64,
        needle: String,
        start: u64,
        end: u64,
    ) -> Result<SearchStep, String> {
        let bodies = self.shared.lock().unwrap().response_bodies.clone();
        bodies.search(id, needle, start, end).await
    }
    pub fn response_json_view(
        &self,
        id: u64,
        start: bool,
        cancel: bool,
    ) -> Result<JsonStatus, String> {
        let bodies = self.shared.lock().unwrap().response_bodies.clone();
        bodies.json_view(id, start, cancel)
    }
    pub async fn response_json_page(
        &self,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<BodyPage, String> {
        let bodies = self.shared.lock().unwrap().response_bodies.clone();
        bodies.json_page(id, offset, length).await
    }
    pub async fn response_body_page(
        &self,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<BodyPage, String> {
        let bodies = {
            let state = self.shared.lock().unwrap();
            let capture = state
                .traffic
                .iter()
                .find(|capture| capture.id == id)
                .ok_or("Capture cleared or evicted.")?;
            if let Some(error) = &capture.response_body_error {
                return Err(error.clone());
            }
            state.response_bodies.clone()
        };
        bodies.page(id, offset, length).await
    }
    pub fn snapshot(&self) -> Snapshot {
        let state = self.shared.lock().unwrap();
        Snapshot {
            revision: state.revision,
            status: state.status.clone(),
            traffic: state.traffic.iter().rev().cloned().collect(),
        }
    }

    pub fn revision(&self) -> u64 {
        self.shared.lock().unwrap().revision
    }

    pub async fn start(&self, config: ProxyConfig) -> Result<Snapshot, String> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Err("The proxy is already running.".into());
        }
        if config.capture_limit == 0
            || config.capture_limit > 1000
            || config.connection_limit == 0
            || config.connection_limit > 256
            || config.request_timeout.is_zero()
            || config.request_timeout > Duration::from_secs(300)
            || config.tunnel_timeout.is_zero()
            || config.tunnel_timeout > Duration::from_secs(3600)
            || config.body_disk_budget == 0
        {
            return Err("Invalid proxy resource limits.".into());
        }
        if let Some(tls) = &config.tls_interception {
            if config.client_auth.as_ref().map(ProxyClientAuth::profile_id)
                != Some(tls.profile_id())
            {
                return Err(
                    "HTTPS inspection requires authentication for the same client profile.".into(),
                );
            }
        }
        let request_redaction_paths =
            bodies::compile_redaction_paths(&config.request_redaction_paths)?;
        let destination_classifier =
            DestinationClassifier::compile(&config.development_hosts, &config.production_hosts)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
            .await
            .map_err(|e| format!("Cannot listen on 127.0.0.1:{}: {e}", config.port))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        {
            let mut state = self.shared.lock().unwrap();
            state.limit = config.capture_limit;
            state.capture_bodies = config.capture_bodies;
            state.body_budget = config.body_disk_budget;
            state.request_redaction_paths = request_redaction_paths;
            state.destination_classifier = destination_classifier;
            state.break_on_responses = config.break_on_responses;
            while state.traffic.len() > state.limit {
                if let Some(capture) = state.traffic.pop_front() {
                    state.breakpoints.remove(&capture.id);
                    state.request_bodies.remove(capture.id);
                    state.response_bodies.remove(capture.id);
                }
                state.status.evicted_captures += 1;
            }
            state.status.captures = state.traffic.len();
            state.status.phase = EnginePhase::Running;
            state.status.listen_address = address;
            state.status.client_profile_id = config
                .client_auth
                .as_ref()
                .map(|auth| auth.profile_id().to_owned());
            state.status.https_inspection = config.tls_interception.is_some();
            state.revision += 1;
        }
        let (shutdown, mut stop) = oneshot::channel();
        let shared = self.shared.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stop => break,
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        if connections.len() >= config.connection_limit {
                            let mut state = shared.lock().unwrap();
                            state.status.rejected_connections += 1;
                            state.revision += 1;
                            drop(stream);
                            continue;
                        }
                        let shared = shared.clone();
                        let client_auth = config.client_auth.clone();
                        let tls_interception = config.tls_interception.clone();
                        let deadline = config.request_timeout;
                        let tunnel_deadline = config.tunnel_timeout;
                        connections.spawn(async move {
                            let (tunnel_tx, mut tunnel_rx) = oneshot::channel::<Tunnel>();
                            let tunnel_slot = Arc::new(Mutex::new(Some(tunnel_tx)));
                            let service = service_fn(move |request| handle(request, shared.clone(), address, deadline, tunnel_slot.clone(), client_auth.clone(), tls_interception.clone()));
                            // The same tracked task owns HTTP negotiation AND the tunnel,
                            // so upgrades cannot escape the connection cap or Stop.
                            let mut builder = http1::Builder::new();
                            builder.keep_alive(false).max_buf_size(32 * 1024).timer(TokioTimer::new()).header_read_timeout(deadline);
                            let _ = builder.serve_connection(TokioIo::new(stream), service).with_upgrades().await;
                            if let Ok(tunnel) = tunnel_rx.try_recv() {
                                tunnel.run(deadline, tunnel_deadline).await;
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            drop(listener);
            let mut state = shared.lock().unwrap();
            state.status.phase = EnginePhase::Stopped;
            state.status.client_profile_id = None;
            state.status.https_inspection = false;
            state.revision += 1;
        });
        *running = Some(Running { shutdown, task });
        Ok(self.snapshot())
    }

    pub async fn stop(&self) -> Snapshot {
        let mut running = self.running.lock().await;
        if let Some(active) = running.take() {
            let _ = active.shutdown.send(());
            let _ = active.task.await;
        }
        self.snapshot()
    }

    pub fn clear(&self) -> Snapshot {
        let mut state = self.shared.lock().unwrap();
        state.breakpoints.clear();
        state.traffic.clear();
        state.request_bodies.clear();
        state.response_bodies.clear();
        state.status.captures = 0;
        state.status.evicted_captures = 0;
        state.revision += 1;
        drop(state);
        self.snapshot()
    }
}

fn clipped(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn safe_target(request: &Request<Incoming>) -> String {
    // Entire query is omitted, rather than guessing the names of secret fields.
    let uri = request.uri();
    let host = uri
        .authority()
        .map(|a| a.as_str())
        .unwrap_or("invalid-target");
    let host = host.rsplit('@').next().unwrap_or("invalid-target");
    if request.method() == Method::CONNECT {
        return clipped(host, 256);
    }
    format!(
        "{}{}{}",
        clipped(host, 256),
        clipped(uri.path(), 1024),
        if uri.query().is_some() {
            "?[REDACTED]"
        } else {
            ""
        }
    )
}

fn safe_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .take(48)
        .map(|(name, value)| {
            let text = if [
                "content-type",
                "content-length",
                "accept",
                "accept-encoding",
                "content-encoding",
                "cache-control",
                "connection",
                "transfer-encoding",
            ]
            .contains(&name.as_str())
            {
                clipped(value.to_str().unwrap_or("[binary]"), 256)
            } else {
                "[REDACTED]".into()
            };
            (clipped(name.as_str(), 128), text)
        })
        .collect()
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_string()))
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

struct Exchange {
    shared: Shared,
    id: u64,
    started: Instant,
}

impl Exchange {
    fn update(&self, update: impl FnOnce(&mut Capture)) {
        let mut state = self.shared.lock().unwrap();
        if let Some(capture) = state
            .traffic
            .iter_mut()
            .find(|capture| capture.id == self.id)
        {
            update(capture);
        }
    }
    fn finish(&self, error: Option<&str>) {
        self.update(|capture| {
            if capture.phase != "pending" {
                return;
            }
            capture.phase = if error.is_some() { "error" } else { "complete" }.into();
            capture.duration_ms = self.started.elapsed().as_millis() as u64;
            capture.error = error.map(String::from);
        });
        self.shared.lock().unwrap().revision += 1;
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        self.finish(Some("Transfer interrupted, cancelled or timed out."));
    }
}

/// Observes byte counts while forwarding frames with Hyper backpressure.
/// It deliberately does not retain body data.
struct ObservedBody {
    inner: Incoming,
    exchange: Arc<Exchange>,
    response: bool,
}

/// Captures only bounded JSON request bodies in memory. The original frames
/// are forwarded unchanged; redaction happens before the safe copy reaches
/// temporary storage.
struct RequestBody {
    observed: ObservedBody,
    capture: Option<Vec<u8>>,
    content_type: String,
    limit: usize,
    redaction_paths: Vec<Vec<String>>,
}

impl RequestBody {
    fn finish_capture(&mut self) {
        let Some(bytes) = self.capture.take() else {
            return;
        };
        if bytes.is_empty() {
            return;
        }
        let (store, budget) = {
            let state = self.observed.exchange.shared.lock().unwrap();
            (state.request_bodies.clone(), state.body_budget)
        };
        let exchange = self.observed.exchange.clone();
        let content_type = self.content_type.clone();
        let redaction_paths = self.redaction_paths.clone();
        tokio::spawn(async move {
            if let Err(error) = store
                .store_redacted_json(exchange.id, bytes, content_type, budget, redaction_paths)
                .await
            {
                exchange.update(|capture| {
                    capture.request_body_state = "unavailable".into();
                    capture.request_body_error = Some(error);
                });
            } else {
                exchange.update(|capture| capture.request_body_state = "complete".into());
            }
            exchange.shared.lock().unwrap().revision += 1;
            if !exchange
                .shared
                .lock()
                .unwrap()
                .traffic
                .iter()
                .any(|capture| capture.id == exchange.id)
            {
                store.remove(exchange.id);
            }
        });
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let result = Pin::new(&mut self.observed).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                let limit = self.limit;
                if let (Some(buffer), Some(bytes)) = (&mut self.capture, frame.data_ref()) {
                    if buffer.len().saturating_add(bytes.len()) <= limit {
                        buffer.extend_from_slice(bytes);
                    } else {
                        self.capture.take();
                        self.observed.exchange.update(|capture| {
                            capture.request_body_error = Some(
                                "Request body exceeds the 1 MiB safe inspection limit; original bytes were forwarded but not recorded."
                                    .into(),
                            )
                        });
                    }
                }
                if self.observed.is_end_stream() {
                    self.finish_capture();
                }
            }
            Poll::Ready(None) => {
                self.finish_capture();
            }
            Poll::Ready(Some(Err(_))) => {
                self.capture.take();
                self.observed.exchange.update(|capture| {
                    capture.request_body_error =
                        Some("Request body transfer failed before it could be inspected.".into())
                });
            }
            Poll::Pending => {}
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.observed.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.observed.size_hint()
    }
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    self.exchange.update(|capture| {
                        if self.response {
                            capture.response_bytes += bytes.len() as u64;
                        } else {
                            capture.request_bytes += bytes.len() as u64;
                        }
                    });
                }
                if self.response && self.inner.is_end_stream() {
                    self.exchange.finish(None);
                }
            }
            Poll::Ready(None) if self.response => self.exchange.finish(None),
            Poll::Ready(Some(Err(_))) => self.exchange.finish(Some("Body transfer failed.")),
            _ => {}
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn response(status: StatusCode, message: &'static str) -> Response<WireBody> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn proxy_authentication_required() -> Response<WireBody> {
    let mut result = response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "Valid proxy client credentials are required.",
    );
    result.headers_mut().insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"Sippin Soda\", charset=\"UTF-8\""),
    );
    result
}

async fn handle(
    request: Request<Incoming>,
    shared: Shared,
    proxy: SocketAddr,
    deadline: Duration,
    tunnel_slot: Arc<Mutex<Option<oneshot::Sender<Tunnel>>>>,
    client_auth: Option<ProxyClientAuth>,
    tls_interception: Option<ProxyTlsInterception>,
) -> Result<Response<WireBody>, Infallible> {
    let client_profile_id = match client_auth {
        Some(auth) if auth.accepts(request.headers()) => Some(auth.profile_id().to_owned()),
        Some(_) => return Ok(proxy_authentication_required()),
        None => None,
    };
    let destination_class = {
        let state = shared.lock().unwrap();
        state
            .destination_classifier
            .classify(request.uri().host().unwrap_or(""))
    };
    let exchange = begin_exchange(
        shared,
        &request,
        destination_class,
        client_profile_id.clone(),
    );
    let operation = async {
        if request.method() == Method::CONNECT {
            tunnel::establish(
                request,
                exchange.clone(),
                proxy,
                tunnel_slot,
                destination_class,
                client_profile_id.as_deref(),
                tls_interception,
            )
            .await
        } else {
            forward(request, exchange.clone(), proxy).await
        }
    };
    let outcome = timeout(deadline, operation).await;
    let result = match outcome {
        Ok(Ok(result)) => result,
        Ok(Err((status, message))) => {
            exchange.update(|capture| capture.status = Some(status.as_u16()));
            exchange.finish(Some(message));
            response(status, message)
        }
        Err(_) => {
            exchange.update(|capture| capture.status = Some(504));
            exchange.finish(Some("Upstream request timed out."));
            response(StatusCode::GATEWAY_TIMEOUT, "Upstream request timed out.")
        }
    };
    Ok(result)
}

fn begin_exchange(
    shared: Shared,
    request: &Request<Incoming>,
    destination_class: DestinationClass,
    client_profile_id: Option<String>,
) -> Arc<Exchange> {
    let mut state = shared.lock().unwrap();
    let id = state.next_id;
    state.next_id += 1;
    if state.traffic.len() == state.limit {
        if let Some(capture) = state.traffic.pop_front() {
            state.breakpoints.remove(&capture.id);
            state.request_bodies.remove(capture.id);
            state.response_bodies.remove(capture.id);
        }
        state.status.evicted_captures += 1;
    }
    state.traffic.push_back(Capture {
        id,
        kind: if request.method() == Method::CONNECT {
            "tunnel"
        } else {
            "http"
        }
        .into(),
        method: request.method().to_string(),
        target: safe_target(request),
        destination_class,
        client_profile_id,
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        status: None,
        phase: "pending".into(),
        duration_ms: 0,
        request_bytes: 0,
        response_bytes: 0,
        request_headers: safe_headers(request.headers()),
        response_headers: vec![],
        error: None,
        request_body_state: "disabled".into(),
        request_body_error: None,
        response_body_error: None,
        breakpoint_state: "none".into(),
        original_status: None,
    });
    state.status.captures = state.traffic.len();
    state.revision += 1;
    drop(state);
    Arc::new(Exchange {
        shared,
        id,
        started: Instant::now(),
    })
}

type ForwardError = (StatusCode, &'static str);

async fn forward(
    request: Request<Incoming>,
    exchange: Arc<Exchange>,
    proxy: SocketAddr,
) -> Result<Response<WireBody>, ForwardError> {
    if request.headers().contains_key("upgrade") {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "HTTP protocol upgrades are not supported. Use CONNECT for opaque tunnels.",
        ));
    }
    if request.uri().scheme_str() != Some("http") || request.uri().authority().is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "An absolute http:// target URL is required.",
        ));
    }
    let authority = request.uri().authority().unwrap().clone();
    if authority.as_str().contains('@') {
        return Err((
            StatusCode::BAD_REQUEST,
            "URL credentials are not supported.",
        ));
    }
    let host = request
        .uri()
        .host()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = request.uri().port_u16().unwrap_or(80);
    let stream = connect_upstream(&host, port, proxy).await?;
    forward_connected(request, exchange, stream, authority).await
}

async fn forward_connected<S>(
    request: Request<Incoming>,
    exchange: Arc<Exchange>,
    stream: S,
    authority: Authority,
) -> Result<Response<WireBody>, ForwardError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream HTTP handshake failed."))?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut sender = UpstreamSender::Http1(sender);
    forward_with_sender(
        request,
        exchange,
        &mut sender,
        authority,
        Some(ConnectionGuard(connection)),
    )
    .await
}

async fn forward_with_sender(
    mut request: Request<Incoming>,
    exchange: Arc<Exchange>,
    sender: &mut UpstreamSender,
    authority: Authority,
    connection: Option<ConnectionGuard>,
) -> Result<Response<WireBody>, ForwardError> {
    let path: hyper::http::uri::PathAndQuery = request
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/")
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid request path."))?;
    *request.uri_mut() = if sender.is_http2() {
        hyper::Uri::builder()
            .scheme("https")
            .authority(authority.clone())
            .path_and_query(path)
            .build()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid HTTPS request target."))?
    } else {
        path.into()
    };
    strip_hop_headers(request.headers_mut());
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(authority.as_str())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid target host."))?,
    );
    let (capture_request, request_redaction_paths) = {
        let state = exchange.shared.lock().unwrap();
        (state.capture_bodies, state.request_redaction_paths.clone())
    };
    let request_has_body = !request.body().is_end_stream();
    let request_content_type = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let request_is_json = request_content_type
        .split(';')
        .next()
        .is_some_and(|kind| kind.trim() == "application/json" || kind.trim().ends_with("+json"));
    if capture_request && request_has_body && !request_is_json {
        exchange.update(|capture| {
            capture.request_body_state = "unavailable".into();
            capture.request_body_error = Some(
                "Request body was forwarded but not recorded: safe inspection currently supports JSON content types only."
                    .into(),
            )
        });
    } else if capture_request && request_has_body {
        exchange.update(|capture| capture.request_body_state = "recording".into());
    } else if capture_request {
        exchange.update(|capture| capture.request_body_state = "empty".into());
    }
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(
        parts,
        RequestBody {
            observed: ObservedBody {
                inner: body,
                exchange: exchange.clone(),
                response: false,
            },
            capture: (capture_request && request_has_body && request_is_json).then(Vec::new),
            content_type: request_content_type,
            limit: 1024 * 1024,
            redaction_paths: request_redaction_paths,
        },
    );
    let upstream_http2 = sender.is_http2();
    let upstream = sender
        .send_request(request)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream HTTP request failed."))?;
    let (mut parts, body) = upstream.into_parts();
    let breakpoint = {
        let mut state = exchange.shared.lock().unwrap();
        let enabled = state.break_on_responses
            && state
                .traffic
                .iter()
                .find(|capture| capture.id == exchange.id)
                .is_some_and(|capture| {
                    authorize(capture.destination_class, Action::Modify).is_ok()
                });
        if enabled {
            let (sender, receiver) = oneshot::channel();
            state.breakpoints.insert(exchange.id, sender);
            if let Some(capture) = state
                .traffic
                .iter_mut()
                .find(|capture| capture.id == exchange.id)
            {
                capture.breakpoint_state = "waiting".into();
                capture.original_status = Some(parts.status.as_u16());
            }
            state.revision += 1;
            Some(receiver)
        } else {
            None
        }
    };
    let mut replacement_body = None;
    if let Some(receiver) = breakpoint {
        let decision = timeout(Duration::from_secs(15), receiver).await;
        exchange
            .shared
            .lock()
            .unwrap()
            .breakpoints
            .remove(&exchange.id);
        match decision {
            Ok(Ok(decision)) => {
                if let Some(status) = decision.status {
                    parts.status = status;
                }
                replacement_body = decision.body.map(|body| (body, decision.content_type));
                let modified = decision.status.is_some() || replacement_body.is_some();
                exchange.update(|capture| {
                    capture.breakpoint_state =
                        if modified { "modified" } else { "continued" }.into()
                });
            }
            _ => exchange.update(|capture| capture.breakpoint_state = "timed_out".into()),
        }
        exchange.shared.lock().unwrap().revision += 1;
    }
    if let Some((replacement, content_type)) = replacement_body {
        strip_hop_headers(&mut parts.headers);
        for name in [
            "content-encoding",
            "content-range",
            "etag",
            "content-md5",
            "accept-ranges",
        ] {
            parts.headers.remove(name);
        }
        parts.headers.insert(
            "content-length",
            HeaderValue::from_str(&replacement.len().to_string())
                .expect("a byte length is a valid header value"),
        );
        parts.headers.insert(
            "content-type",
            content_type.unwrap_or_else(|| HeaderValue::from_static("text/plain; charset=utf-8")),
        );
        if !upstream_http2 {
            parts
                .headers
                .insert("connection", HeaderValue::from_static("close"));
        }
        exchange.update(|capture| {
            capture.status = Some(parts.status.as_u16());
            capture.response_headers = safe_headers(&parts.headers);
            capture.response_bytes = replacement.len() as u64;
        });
        let (bodies, enabled, budget) = {
            let state = exchange.shared.lock().unwrap();
            (
                state.response_bodies.clone(),
                state.capture_bodies,
                state.body_budget,
            )
        };
        if enabled {
            if let Err(error) = bodies
                .store_complete(exchange.id, replacement.to_vec(), budget)
                .await
            {
                exchange.update(|capture| {
                    capture.response_body_error = Some(error);
                });
            }
        }
        exchange.finish(None);
        return Ok(Response::from_parts(
            parts,
            Full::new(replacement)
                .map_err(|never: Infallible| match never {})
                .boxed(),
        ));
    }
    exchange.update(|capture| {
        capture.status = Some(parts.status.as_u16());
        capture.response_headers = safe_headers(&parts.headers);
    });
    strip_hop_headers(&mut parts.headers);
    let (bodies, enabled, budget) = {
        let state = exchange.shared.lock().unwrap();
        (
            state.response_bodies.clone(),
            state.capture_bodies,
            state.body_budget,
        )
    };
    let mut tap = if enabled {
        let encoding = if body.is_end_stream() {
            String::new()
        } else {
            parts
                .headers
                .get_all("content-encoding")
                .iter()
                .map(|value| {
                    value
                        .to_str()
                        .unwrap_or("unsupported")
                        .trim()
                        .to_ascii_lowercase()
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        match bodies.record(exchange.id, encoding, budget).await {
            Ok(tap) => {
                if !exchange
                    .shared
                    .lock()
                    .unwrap()
                    .traffic
                    .iter()
                    .any(|capture| capture.id == exchange.id)
                {
                    bodies.remove(exchange.id);
                }
                Some(tap)
            }
            Err(error) => {
                exchange.update(|capture| capture.response_body_error = Some(error));
                None
            }
        }
    } else {
        None
    };
    if body.is_end_stream() {
        if let Some(tap) = tap.take() {
            tap.finish_empty().await;
        }
        exchange.finish(None);
    }
    let body = ResponseBody {
        observed: RecordedBody {
            inner: ObservedBody {
                inner: body,
                exchange,
                response: true,
            },
            tap,
            pending: None,
            written: 0,
        },
        _connection: connection,
    };
    Ok(Response::from_parts(parts, body.boxed()))
}

async fn connect_upstream(
    host: &str,
    port: u16,
    proxy: SocketAddr,
) -> Result<TcpStream, ForwardError> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream DNS lookup failed."))?
        .take(16)
        .collect();
    if addresses.is_empty() {
        return Err((StatusCode::BAD_GATEWAY, "No upstream address found."));
    }
    // Reject the proxy endpoint after DNS resolution, including aliases.
    if addresses.iter().any(|address| {
        address.port() == proxy.port()
            && (address.ip().to_canonical().is_loopback()
                || address.ip().to_canonical().is_unspecified())
    }) {
        return Err((
            StatusCode::LOOP_DETECTED,
            "Routing a request back to this proxy is not allowed.",
        ));
    }
    TcpStream::connect(addresses.as_slice())
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream connection failed."))
}

struct ConnectionGuard(JoinHandle<()>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ResponseBody {
    observed: RecordedBody,
    _connection: Option<ConnectionGuard>,
}
impl Body for ResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.observed).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.observed.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.observed.size_hint()
    }
}

#[cfg(test)]
mod destination_tests {
    use super::DestinationClassifier;
    use crate::DestinationClass;

    #[test]
    fn classifies_exact_wildcard_loopback_and_unknown_hosts() {
        let classifier = DestinationClassifier::compile(
            &["api.dev.example".into(), "*.internal".into()],
            &["api.example.com".into(), "*.prod.example".into()],
        )
        .unwrap();
        assert_eq!(
            classifier.classify("API.DEV.EXAMPLE."),
            DestinationClass::Development
        );
        assert_eq!(
            classifier.classify("orders.internal"),
            DestinationClass::Development
        );
        assert_eq!(
            classifier.classify("127.0.0.1"),
            DestinationClass::Development
        );
        assert_eq!(
            classifier.classify("api.example.com"),
            DestinationClass::Production
        );
        assert_eq!(
            classifier.classify("payments.prod.example"),
            DestinationClass::Production
        );
        assert_eq!(
            classifier.classify("prod.example"),
            DestinationClass::Unknown
        );
    }

    #[test]
    fn rejects_invalid_or_ambiguous_host_rules() {
        assert!(DestinationClassifier::compile(&["api.*.test".into()], &[]).is_err());
        assert!(DestinationClassifier::compile(&["https://api.test".into()], &[]).is_err());
        assert!(DestinationClassifier::compile(&["api.test:443".into()], &[]).is_err());
        assert!(DestinationClassifier::compile(
            &["api.example.com".into()],
            &["*.example.com".into()]
        )
        .is_err());
        assert!(DestinationClassifier::compile(
            &["*.dev.example.com".into()],
            &["*.example.com".into()]
        )
        .is_err());
    }
}

#[cfg(test)]
mod tls_listener_tests {
    use super::*;
    use crate::HTTP1_ALPN;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{
        rustls::{
            pki_types::{PrivatePkcs8KeyDer, ServerName},
            RootCertStore, ServerConfig,
        },
        TlsAcceptor, TlsConnector,
    };

    fn test_interception(
        leaf: IssuedLeaf,
        upstream_config: Arc<ClientConfig>,
    ) -> ProxyTlsInterception {
        let leaf = Arc::new(Mutex::new(Some(leaf)));
        ProxyTlsInterception {
            profile_id: "browser-1".into(),
            upstream_config,
            issue_leaf: Arc::new(move |_, destination| {
                assert_eq!(destination, DestinationClass::Development);
                Ok(leaf.lock().unwrap().take())
            }),
        }
    }

    async fn response_headers(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    }

    async fn http_message<S: AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        let headers_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = String::from_utf8(bytes[..headers_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        bytes.resize(headers_end + content_length, 0);
        stream.read_exact(&mut bytes[headers_end..]).await.unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn authenticated_development_connect_captures_inner_http_safely() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let upstream_identity =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let mut upstream_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![upstream_identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(upstream_identity.signing_key.serialize_der()).into(),
            )
            .unwrap();
        upstream_server_config.alpn_protocols = vec![HTTP1_ALPN.to_vec()];
        let mut upstream_roots = RootCertStore::empty();
        upstream_roots
            .add(upstream_identity.cert.der().clone())
            .unwrap();
        let mut upstream_client_config = ClientConfig::builder()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        upstream_client_config.alpn_protocols = vec![HTTP1_ALPN.to_vec()];
        let upstream_client_config = Arc::new(upstream_client_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(Arc::new(upstream_server_config))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(HTTP1_ALPN));
            let request = http_message(&mut tls).await;
            assert!(request.starts_with("POST /submit?token=secret HTTP/1.1\r\n"));
            let lowercase_request = request.to_ascii_lowercase();
            assert!(lowercase_request.contains(&format!("host: 127.0.0.1:{upstream_port}\r\n")));
            assert!(!lowercase_request.contains("proxy-authorization"));
            assert!(request.contains(r#"{"password":"secret","value":"safe"}"#));
            tls.write_all(
                b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
            )
            .await
            .unwrap();
            let request = http_message(&mut tls).await;
            assert!(request.starts_with("GET /second?key=secret HTTP/1.1\r\n"));
            let lowercase_request = request.to_ascii_lowercase();
            assert!(lowercase_request.contains(&format!("host: 127.0.0.1:{upstream_port}\r\n")));
            assert!(!lowercase_request.contains("proxy-authorization"));
            tls.write_all(
                b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"sequence\":2}",
            )
            .await
            .unwrap();
            tls.shutdown().await.unwrap();
        });

        let (ca_pem, leaf, _) = CaManager::ephemeral_leaf_for_test("127.0.0.1");
        let engine = ProxyEngine::default();
        let snapshot = engine
            .start(ProxyConfig {
                port: 0,
                client_auth: Some(ProxyClientAuth::new("browser-1", TOKEN).unwrap()),
                tls_interception: Some(test_interception(leaf, upstream_client_config)),
                capture_bodies: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(snapshot.status.https_inspection);
        let mut client = TcpStream::connect(snapshot.status.listen_address)
            .await
            .unwrap();
        let credentials = BASE64.encode(format!("browser-1:{TOKEN}"));
        client
            .write_all(
                format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        assert!(response_headers(&mut client)
            .await
            .starts_with("HTTP/1.1 200"));
        let mut downstream_roots = RootCertStore::empty();
        downstream_roots
            .add(
                rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem.as_bytes()))
                    .next()
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut downstream_config = ClientConfig::builder()
            .with_root_certificates(downstream_roots)
            .with_no_client_auth();
        downstream_config.alpn_protocols = vec![HTTP1_ALPN.to_vec()];
        let mut tls = TlsConnector::from(Arc::new(downstream_config))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), client)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(HTTP1_ALPN));
        let body = r#"{"password":"secret","value":"safe"}"#;
        tls.write_all(
            format!(
                "POST /submit?token=secret HTTP/1.1\r\nHost: wrong.example\r\nAuthorization: Bearer inner-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        tls.flush().await.unwrap();
        let reply = http_message(&mut tls).await;
        assert!(reply.starts_with("HTTP/1.1 201 Created"));
        assert!(reply.ends_with(r#"{"ok":true}"#));
        tls.write_all(
            b"GET /second?key=secret HTTP/1.1\r\nHost: another-wrong.example\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        tls.flush().await.unwrap();
        let reply = http_message(&mut tls).await;
        assert!(reply.starts_with("HTTP/1.1 202 Accepted"));
        assert!(reply.ends_with(r#"{"sequence":2}"#));
        upstream.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while {
                let snapshot = engine.snapshot();
                snapshot.traffic.len() != 2
                    || snapshot.traffic.iter().any(|capture| {
                        capture.phase == "pending" || capture.request_body_state == "recording"
                    })
            } {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let snapshot = engine.snapshot();
        let first_capture_id = snapshot.traffic[1].id;
        let request_body = engine
            .request_body_page(first_capture_id, 0, 1024)
            .await
            .unwrap();
        let response_body = engine
            .response_body_page(first_capture_id, 0, 1024)
            .await
            .unwrap();
        let second_response_body = engine
            .response_body_page(snapshot.traffic[0].id, 0, 1024)
            .await
            .unwrap();
        let snapshot = engine.stop().await;
        assert!(!snapshot.status.https_inspection);
        let first = &snapshot.traffic[1];
        assert_eq!(first.kind, "https");
        assert_eq!(first.method, "POST");
        assert_eq!(
            first.target,
            format!("127.0.0.1:{upstream_port}/submit?[REDACTED]")
        );
        assert_eq!(first.status, Some(201));
        assert_eq!(first.request_bytes, body.len() as u64);
        assert_eq!(first.response_bytes, 11);
        assert!(first
            .request_headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "[REDACTED]"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request_body.bytes).unwrap(),
            serde_json::json!({"password": "[REDACTED]", "value": "safe"})
        );
        assert_eq!(
            String::from_utf8(response_body.bytes).unwrap(),
            r#"{"ok":true}"#
        );
        assert_eq!(first.phase, "complete");
        let second = &snapshot.traffic[0];
        assert_eq!(second.kind, "https");
        assert_eq!(second.method, "GET");
        assert_eq!(
            second.target,
            format!("127.0.0.1:{upstream_port}/second?[REDACTED]")
        );
        assert_eq!(second.status, Some(202));
        assert_eq!(second.response_bytes, 14);
        assert_eq!(
            String::from_utf8(second_response_body.bytes).unwrap(),
            r#"{"sequence":2}"#
        );
        assert_eq!(second.phase, "complete");
    }

    #[tokio::test]
    async fn authenticated_development_connect_captures_multiplexed_http2_streams() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let identity = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )
            .unwrap();
        server_config.alpn_protocols = vec![HTTP2_ALPN.to_vec()];
        let mut roots = RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let mut upstream_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream_config.alpn_protocols = vec![HTTP2_ALPN.to_vec(), HTTP1_ALPN.to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(HTTP2_ALPN));
            let service = service_fn(|request: Request<Incoming>| async move {
                let status = if request.uri().path() == "/one" {
                    201
                } else {
                    202
                };
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let mut response = Response::new(Full::new(body));
                *response.status_mut() = StatusCode::from_u16(status).unwrap();
                Ok::<_, Infallible>(response)
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
        });

        let (ca_pem, leaf, _) = CaManager::ephemeral_leaf_for_test("127.0.0.1");
        let engine = ProxyEngine::default();
        let snapshot = engine
            .start(ProxyConfig {
                port: 0,
                client_auth: Some(ProxyClientAuth::new("browser-1", TOKEN).unwrap()),
                tls_interception: Some(test_interception(leaf, Arc::new(upstream_config))),
                capture_bodies: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let mut client = TcpStream::connect(snapshot.status.listen_address)
            .await
            .unwrap();
        let credentials = BASE64.encode(format!("browser-1:{TOKEN}"));
        client
            .write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        assert!(response_headers(&mut client)
            .await
            .starts_with("HTTP/1.1 200"));
        let mut roots = RootCertStore::empty();
        roots
            .add(
                rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem.as_bytes()))
                    .next()
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![HTTP2_ALPN.to_vec()];
        let tls = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), client)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(HTTP2_ALPN));
        let (sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(tls),
        )
        .await
        .unwrap();
        let connection = tokio::spawn(connection);
        let mut first_sender = sender.clone();
        let mut second_sender = sender;
        let first = Request::post(format!("https://127.0.0.1:{upstream_port}/one?token=a"))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(b"{\"password\":\"secret\"}")))
            .unwrap();
        let second = Request::get(format!("https://127.0.0.1:{upstream_port}/two?token=b"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (first, second) = tokio::join!(
            first_sender.send_request(first),
            second_sender.send_request(second)
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.status(), 201);
        assert_eq!(second.status(), 202);
        first.into_body().collect().await.unwrap();
        second.into_body().collect().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while {
                let snapshot = engine.snapshot();
                snapshot.traffic.len() != 2
                    || snapshot
                        .traffic
                        .iter()
                        .any(|capture| capture.phase == "pending")
            } {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let snapshot = engine.stop().await;
        assert_eq!(snapshot.traffic.len(), 2);
        assert!(snapshot
            .traffic
            .iter()
            .all(|capture| capture.kind == "https"));
        assert!(snapshot
            .traffic
            .iter()
            .any(|capture| capture.status == Some(201)));
        assert!(snapshot
            .traffic
            .iter()
            .any(|capture| capture.status == Some(202)));
        connection.abort();
        upstream.abort();
    }

    #[tokio::test]
    async fn interception_route_rejects_non_development_and_mismatched_profiles() {
        let called = Arc::new(AtomicBool::new(false));
        let issuer_called = called.clone();
        let interception = ProxyTlsInterception {
            profile_id: "browser-1".into(),
            upstream_config: Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth(),
            ),
            issue_leaf: Arc::new(move |_, _| {
                issuer_called.store(true, Ordering::SeqCst);
                Ok(None)
            }),
        };
        assert!(interception
            .prepare(
                "api.example.com",
                DestinationClass::Production,
                Some("browser-1"),
            )
            .await
            .unwrap()
            .is_none());
        assert!(interception
            .prepare(
                "api.dev.example",
                DestinationClass::Development,
                Some("other-client"),
            )
            .await
            .unwrap()
            .is_none());
        assert!(!called.load(Ordering::SeqCst));
        assert!(ProxyEngine::default()
            .start(ProxyConfig {
                port: 0,
                client_auth: Some(
                    ProxyClientAuth::new("other-client", "0123456789abcdef0123456789abcdef",)
                        .unwrap(),
                ),
                tls_interception: Some(interception),
                ..Default::default()
            })
            .await
            .is_err());
    }
}
