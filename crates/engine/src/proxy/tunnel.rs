use super::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Kept in the listener's tracked connection task, never a detached task.
pub(super) struct Tunnel {
    upgrade: hyper::upgrade::OnUpgrade,
    upstream: TcpStream,
    exchange: Arc<Exchange>,
    interception: Option<TlsInterceptRoute>,
    authority: Authority,
}

pub(super) async fn establish(
    mut request: Request<Incoming>,
    exchange: Arc<Exchange>,
    proxy: SocketAddr,
    slot: Arc<Mutex<Option<oneshot::Sender<Tunnel>>>>,
    destination: DestinationClass,
    client_profile_id: Option<&str>,
    tls_interception: Option<ProxyTlsInterception>,
) -> Result<Response<WireBody>, ForwardError> {
    let invalid = (
        StatusCode::BAD_REQUEST,
        "CONNECT requires an authority-only host:port target with no request body.",
    );
    let uri = request.uri();
    let authority = uri.authority().ok_or(invalid)?;
    let authority = authority.clone();
    if uri.scheme().is_some() || uri.path_and_query().is_some() || authority.as_str().contains('@')
    {
        return Err(invalid);
    }
    let port = authority
        .port_u16()
        .filter(|port| *port != 0)
        .ok_or(invalid)?;
    if request.headers().contains_key("transfer-encoding")
        || request.headers().contains_key("upgrade")
        || request
            .headers()
            .get("content-length")
            .is_some_and(|v| v.to_str().ok().and_then(|s| s.parse::<u64>().ok()) != Some(0))
    {
        return Err(invalid);
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let interception = match tls_interception {
        Some(tls) => tls
            .prepare(host, destination, client_profile_id)
            .await
            .map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    "TLS interception preparation failed.",
                )
            })?,
        None => None,
    };
    // Establish upstream before acknowledging CONNECT. Proxy credentials and
    // HTTP request headers never enter the tunnel.
    let upstream = connect_upstream(host, port, proxy).await?;
    let upgrade = hyper::upgrade::on(&mut request);
    let sender = slot.lock().unwrap().take().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Tunnel owner is unavailable.",
    ))?;
    exchange.update(|capture| capture.status = Some(200));
    if interception.is_some() {
        exchange.update(|capture| capture.kind = "tls".into());
    }
    exchange.shared.lock().unwrap().revision += 1;
    sender
        .send(Tunnel {
            upgrade,
            upstream,
            exchange,
            interception,
            authority,
        })
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "Proxy is stopping."))?;
    let mut result = response(StatusCode::OK, "");
    result.headers_mut().clear();
    Ok(result)
}

impl Tunnel {
    pub(super) async fn run(self, handshake_timeout: Duration, lifetime: Duration) {
        let Self {
            upgrade,
            upstream,
            exchange,
            interception,
            authority,
        } = self;
        let upgraded = match timeout(handshake_timeout, upgrade).await {
            Ok(Ok(io)) => io,
            _ => {
                exchange.finish(Some("CONNECT upgrade failed or timed out."));
                return;
            }
        };
        if let Some(route) = interception {
            let established = match establish_verified_tls_with_config(
                TokioIo::new(upgraded),
                upstream,
                &route.host,
                route.leaf,
                route.upstream_config,
                handshake_timeout,
            )
            .await
            {
                Ok(established) => established,
                Err(_) => {
                    exchange.finish(Some("Verified TLS handshakes failed."));
                    return;
                }
            };
            let upstream = Arc::new(Mutex::new(Some(established.upstream)));
            let service_exchange = exchange.clone();
            let service = service_fn(move |request: Request<Incoming>| {
                let exchange = service_exchange.clone();
                let upstream = upstream.clone();
                let authority = authority.clone();
                async move {
                    let result =
                        forward_intercepted_https(request, exchange.clone(), upstream, authority)
                            .await;
                    Ok::<_, Infallible>(match result {
                        Ok(response) => response,
                        Err((status, message)) => {
                            exchange.update(|capture| capture.status = Some(status.as_u16()));
                            exchange.finish(Some(message));
                            response(status, message)
                        }
                    })
                }
            });
            let mut builder = http1::Builder::new();
            builder
                .keep_alive(false)
                .max_buf_size(32 * 1024)
                .timer(TokioTimer::new())
                .header_read_timeout(handshake_timeout);
            match timeout(
                lifetime,
                builder.serve_connection(TokioIo::new(established.downstream), service),
            )
            .await
            {
                Ok(Ok(())) => exchange.finish(Some(
                    "The HTTPS connection ended before a complete HTTP exchange.",
                )),
                Ok(Err(_)) => exchange.finish(Some("Inner HTTPS HTTP/1 transfer failed.")),
                Err(_) => exchange.finish(Some("Tunnel lifetime limit reached.")),
            }
            return;
        }
        let mut client = CountedIo {
            inner: TokioIo::new(upgraded),
            exchange: exchange.clone(),
            response: true,
        };
        let mut server = CountedIo {
            inner: upstream,
            exchange: exchange.clone(),
            response: false,
        };
        match timeout(
            lifetime,
            tokio::io::copy_bidirectional(&mut client, &mut server),
        )
        .await
        {
            Ok(Ok(_)) => exchange.finish(None),
            Ok(Err(_)) => exchange.finish(Some("Tunnel transport failed.")),
            Err(_) => exchange.finish(Some("Tunnel lifetime limit reached.")),
        }
    }
}

async fn forward_intercepted_https<U>(
    request: Request<Incoming>,
    exchange: Arc<Exchange>,
    upstream: Arc<Mutex<Option<U>>>,
    authority: Authority,
) -> Result<Response<WireBody>, ForwardError>
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if request.headers().contains_key("upgrade") {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "HTTPS protocol upgrades are not supported.",
        ));
    }
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "An origin-form HTTPS request target is required inside CONNECT.",
        ));
    }
    let target = format!(
        "{}{}{}",
        clipped(authority.as_str(), 256),
        clipped(request.uri().path(), 1024),
        if request.uri().query().is_some() {
            "?[REDACTED]"
        } else {
            ""
        }
    );
    exchange.update(|capture| {
        capture.kind = "https".into();
        capture.method = request.method().to_string();
        capture.target = target;
        capture.status = None;
        capture.request_headers = safe_headers(request.headers());
        capture.response_headers.clear();
    });
    exchange.shared.lock().unwrap().revision += 1;
    let stream = upstream.lock().unwrap().take().ok_or((
        StatusCode::BAD_GATEWAY,
        "Only one HTTP/1 request is supported per inspected CONNECT tunnel.",
    ))?;
    forward_connected(request, exchange, stream, authority).await
}

/// Count bytes accepted by the opposite transport, without retaining payload.
struct CountedIo<T> {
    inner: T,
    exchange: Arc<Exchange>,
    response: bool,
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = result {
            if count > 0 {
                self.exchange.update(|capture| {
                    if self.response {
                        capture.response_bytes += count as u64;
                    } else {
                        capture.request_bytes += count as u64;
                    }
                });
                self.exchange.shared.lock().unwrap().revision += 1;
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
