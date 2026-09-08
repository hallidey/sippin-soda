use super::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Kept in the listener's tracked connection task, never a detached task.
pub(super) struct Tunnel {
    upgrade: hyper::upgrade::OnUpgrade,
    upstream: TcpStream,
    exchange: Arc<Exchange>,
}

pub(super) async fn establish(
    mut request: Request<Incoming>,
    exchange: Arc<Exchange>,
    proxy: SocketAddr,
    slot: Arc<Mutex<Option<oneshot::Sender<Tunnel>>>>,
) -> Result<Response<WireBody>, ForwardError> {
    let invalid = (
        StatusCode::BAD_REQUEST,
        "CONNECT requires an authority-only host:port target with no request body.",
    );
    let uri = request.uri();
    let authority = uri.authority().ok_or(invalid)?;
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
    // Establish upstream before acknowledging CONNECT. Proxy credentials and
    // HTTP request headers never enter the tunnel.
    let upstream = connect_upstream(host, port, proxy).await?;
    let upgrade = hyper::upgrade::on(&mut request);
    let sender = slot.lock().unwrap().take().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Tunnel owner is unavailable.",
    ))?;
    exchange.update(|capture| capture.status = Some(200));
    exchange.shared.lock().unwrap().revision += 1;
    sender
        .send(Tunnel {
            upgrade,
            upstream,
            exchange,
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
        } = self;
        let upgraded = match timeout(handshake_timeout, upgrade).await {
            Ok(Ok(io)) => io,
            _ => {
                exchange.finish(Some("CONNECT upgrade failed or timed out."));
                return;
            }
        };
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
