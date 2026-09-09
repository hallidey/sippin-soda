use crate::{EnginePhase, EngineStatus};
mod bodies;
mod tunnel;
pub use bodies::{BodyPage, JsonStatus, SearchStep};
use bodies::{BodyStore, RecordedBody};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{HeaderMap, HeaderValue, HOST},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use std::{
    collections::VecDeque,
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tunnel::Tunnel;

type WireBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub capture_limit: usize,
    pub connection_limit: usize,
    pub request_timeout: Duration,
    pub tunnel_timeout: Duration,
    pub capture_response_bodies: bool,
    pub body_disk_budget: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            capture_limit: 200,
            connection_limit: 64,
            request_timeout: Duration::from_secs(30),
            tunnel_timeout: Duration::from_secs(300),
            capture_response_bodies: false,
            body_disk_budget: 10 * 1024 * 1024 * 1024,
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
    pub started_at: u64,
    pub status: Option<u16>,
    pub phase: String,
    pub duration_ms: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub error: Option<String>,
    pub response_body_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub revision: u64,
    pub status: EngineStatus,
    pub traffic: Vec<Capture>,
}

struct State {
    revision: u64,
    next_id: u64,
    status: EngineStatus,
    traffic: VecDeque<Capture>,
    limit: usize,
    bodies: Arc<BodyStore>,
    capture_bodies: bool,
    body_budget: u64,
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
        Self {
            shared: Arc::new(Mutex::new(State {
                revision: 0,
                next_id: 1,
                status: EngineStatus::default(),
                traffic: VecDeque::new(),
                limit: 200,
                bodies: Arc::new(BodyStore::default()),
                capture_bodies: false,
                body_budget: 0,
            })),
            running: tokio::sync::Mutex::new(None),
        }
    }
}

impl ProxyEngine {
    pub async fn search_response_body(
        &self,
        id: u64,
        needle: String,
        start: u64,
        end: u64,
    ) -> Result<SearchStep, String> {
        let bodies = self.shared.lock().unwrap().bodies.clone();
        bodies.search(id, needle, start, end).await
    }
    pub fn response_json_view(
        &self,
        id: u64,
        start: bool,
        cancel: bool,
    ) -> Result<JsonStatus, String> {
        let bodies = self.shared.lock().unwrap().bodies.clone();
        bodies.json_view(id, start, cancel)
    }
    pub async fn response_json_page(
        &self,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<BodyPage, String> {
        let bodies = self.shared.lock().unwrap().bodies.clone();
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
            state.bodies.clone()
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
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
            .await
            .map_err(|e| format!("Cannot listen on 127.0.0.1:{}: {e}", config.port))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        {
            let mut state = self.shared.lock().unwrap();
            state.limit = config.capture_limit;
            state.capture_bodies = config.capture_response_bodies;
            state.body_budget = config.body_disk_budget;
            while state.traffic.len() > state.limit {
                if let Some(capture) = state.traffic.pop_front() {
                    state.bodies.remove(capture.id);
                }
                state.status.evicted_captures += 1;
            }
            state.status.captures = state.traffic.len();
            state.status.phase = EnginePhase::Running;
            state.status.listen_address = address;
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
                        let deadline = config.request_timeout;
                        let tunnel_deadline = config.tunnel_timeout;
                        connections.spawn(async move {
                            let (tunnel_tx, mut tunnel_rx) = oneshot::channel::<Tunnel>();
                            let tunnel_slot = Arc::new(Mutex::new(Some(tunnel_tx)));
                            let service = service_fn(move |request| handle(request, shared.clone(), address, deadline, tunnel_slot.clone()));
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
        state.traffic.clear();
        state.bodies.clear();
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

async fn handle(
    request: Request<Incoming>,
    shared: Shared,
    proxy: SocketAddr,
    deadline: Duration,
    tunnel_slot: Arc<Mutex<Option<oneshot::Sender<Tunnel>>>>,
) -> Result<Response<WireBody>, Infallible> {
    let exchange = {
        let mut state = shared.lock().unwrap();
        let id = state.next_id;
        state.next_id += 1;
        if state.traffic.len() == state.limit {
            if let Some(capture) = state.traffic.pop_front() {
                state.bodies.remove(capture.id);
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
            target: safe_target(&request),
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
            response_body_error: None,
        });
        state.status.captures = state.traffic.len();
        state.revision += 1;
        Arc::new(Exchange {
            shared: shared.clone(),
            id,
            started: Instant::now(),
        })
    };
    let operation = async {
        if request.method() == Method::CONNECT {
            tunnel::establish(request, exchange.clone(), proxy, tunnel_slot).await
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

type ForwardError = (StatusCode, &'static str);

async fn forward(
    mut request: Request<Incoming>,
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
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream HTTP handshake failed."))?;
    let path = request
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/")
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid request path."))?;
    *request.uri_mut() = path;
    strip_hop_headers(request.headers_mut());
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(authority.as_str())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid target host."))?,
    );
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(
        parts,
        ObservedBody {
            inner: body,
            exchange: exchange.clone(),
            response: false,
        },
    );
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let guard = ConnectionGuard(connection);
    let upstream = sender
        .send_request(request)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "Upstream HTTP request failed."))?;
    let (mut parts, body) = upstream.into_parts();
    exchange.update(|capture| {
        capture.status = Some(parts.status.as_u16());
        capture.response_headers = safe_headers(&parts.headers);
    });
    strip_hop_headers(&mut parts.headers);
    let (bodies, enabled, budget) = {
        let state = exchange.shared.lock().unwrap();
        (
            state.bodies.clone(),
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
        _connection: guard,
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
    _connection: ConnectionGuard,
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
