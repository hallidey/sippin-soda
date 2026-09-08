use sippin_soda_engine::{EnginePhase, ProxyConfig, ProxyEngine};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{sleep, timeout},
};

async fn fixture(reply: Vec<u8>, delay: Duration) -> (u16, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sent, received) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![];
        loop {
            let mut byte = [0];
            if stream.read_exact(&mut byte).await.is_err() {
                return;
            }
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = sent.send(String::from_utf8_lossy(&request).into_owned());
        sleep(delay).await;
        let _ = stream.write_all(&reply).await;
    });
    (port, received)
}

async fn send(proxy: u16, request: String) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = vec![];
    timeout(Duration::from_secs(3), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&reply).into_owned()
}

async fn start() -> (ProxyEngine, u16) {
    let engine = ProxyEngine::default();
    let snapshot = engine
        .start(ProxyConfig {
            port: 0,
            ..Default::default()
        })
        .await
        .unwrap();
    let port = snapshot.status.listen_address.port();
    (engine, port)
}

#[tokio::test]
async fn forwards_to_real_upstream_and_captures_only_filtered_metadata() {
    let (upstream, received) = fixture(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nSet-Cookie: private=value\r\nConnection: X-Internal\r\nX-Internal: hop\r\n\r\nhello".to_vec(), Duration::ZERO).await;
    let (engine, port) = start().await;
    let reply = send(port, format!("GET http://127.0.0.1:{upstream}/users?token=private HTTP/1.1\r\nHost: wrong.invalid\r\nAuthorization: Bearer secret\r\nProxy-Authorization: proxy-secret\r\nConnection: X-Remove\r\nX-Remove: hop\r\n\r\n")).await;
    assert!(reply.starts_with("HTTP/1.1 201"));
    assert!(reply.ends_with("hello"));
    assert!(!reply.to_lowercase().contains("x-internal"));
    let forwarded = received.await.unwrap();
    assert!(forwarded.starts_with("GET /users?token=private HTTP/1.1"));
    assert!(forwarded
        .to_lowercase()
        .contains(&format!("host: 127.0.0.1:{upstream}")));
    assert!(forwarded.contains("Bearer secret"));
    assert!(!forwarded.to_lowercase().contains("proxy-authorization"));
    assert!(!forwarded.to_lowercase().contains("x-remove"));
    let snapshot = engine.stop().await;
    let capture = &snapshot.traffic[0];
    assert_eq!(capture.status, Some(201));
    assert_eq!(capture.phase, "complete");
    assert_eq!(capture.response_bytes, 5);
    assert!(!capture.target.contains("private"));
    assert!(capture
        .request_headers
        .iter()
        .any(|(name, value)| name == "authorization" && value == "[REDACTED]"));
    assert!(capture
        .response_headers
        .iter()
        .any(|(name, value)| name == "set-cookie" && value == "[REDACTED]"));
}

#[tokio::test]
async fn rejects_upgrades_invalid_targets_and_dns_alias_loops() {
    let (engine, port) = start().await;
    for (request, expected) in [
        (
            "GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n".to_string(),
            "501",
        ),
        (
            "GET /relative HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string(),
            "400",
        ),
        (
            format!("GET http://localhost:{port}/loop HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            "508",
        ),
    ] {
        assert!(send(port, request)
            .await
            .starts_with(&format!("HTTP/1.1 {expected}")));
    }
    engine.stop().await;
}

#[tokio::test]
async fn unreachable_upstream_is_a_captured_502() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = unused.local_addr().unwrap().port();
    drop(unused);
    let (engine, port) = start().await;
    assert!(send(
        port,
        format!("GET http://127.0.0.1:{upstream}/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
    )
    .await
    .starts_with("HTTP/1.1 502"));
    let snapshot = engine.stop().await;
    assert_eq!(snapshot.traffic[0].phase, "error");
}

#[tokio::test]
async fn request_timeout_returns_504_and_stop_releases_listener() {
    let (upstream, _) = fixture(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Duration::from_secs(1),
    )
    .await;
    let engine = ProxyEngine::default();
    let status = engine
        .start(ProxyConfig {
            port: 0,
            request_timeout: Duration::from_millis(100),
            ..Default::default()
        })
        .await
        .unwrap();
    let port = status.status.listen_address.port();
    assert!(send(
        port,
        format!("GET http://127.0.0.1:{upstream}/slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
    )
    .await
    .starts_with("HTTP/1.1 504"));
    assert_eq!(engine.stop().await.status.phase, EnginePhase::Stopped);
    let reused = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    drop(reused);
    engine
        .start(ProxyConfig {
            port,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(engine.start(ProxyConfig::default()).await.is_err());
    engine.stop().await;
}

#[tokio::test]
async fn ring_buffer_eviction_and_clear_are_explicit() {
    let engine = ProxyEngine::default();
    let status = engine
        .start(ProxyConfig {
            port: 0,
            capture_limit: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    for _ in 0..3 {
        send(
            status.status.listen_address.port(),
            "GET /invalid HTTP/1.1\r\nHost: localhost\r\n\r\n".into(),
        )
        .await;
    }
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.traffic.len(), 2);
    assert_eq!(snapshot.status.evicted_captures, 1);
    assert_eq!(snapshot.traffic[0].id, 3);
    assert!(engine.clear().traffic.is_empty());
    engine.stop().await;
}

#[tokio::test]
async fn stop_cancels_an_inflight_request() {
    let (upstream, received) = fixture(vec![], Duration::from_secs(2)).await;
    let (engine, port) = start().await;
    let engine = Arc::new(engine);
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client
        .write_all(
            format!("GET http://127.0.0.1:{upstream}/slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    received.await.unwrap();
    timeout(Duration::from_secs(1), engine.stop())
        .await
        .unwrap();
    let mut reply = vec![];
    let _ = timeout(Duration::from_secs(1), client.read_to_end(&mut reply))
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while engine.snapshot().traffic[0].phase == "pending" {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(engine.snapshot().traffic[0].phase, "error");
}

#[tokio::test]
async fn streams_large_response_without_retaining_the_payload() {
    let body = vec![b'x'; 2 * 1024 * 1024];
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(&body);
    let (upstream, _) = fixture(response, Duration::ZERO).await;
    let (engine, port) = start().await;
    let result = send(
        port,
        format!("GET http://127.0.0.1:{upstream}/large HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    )
    .await;
    assert!(result.ends_with(&String::from_utf8(body).unwrap()));
    let capture = engine.stop().await.traffic.remove(0);
    assert_eq!(capture.response_bytes, 2 * 1024 * 1024);
    assert_eq!(capture.phase, "complete");
    assert!(capture.response_headers.len() < 10);
}

#[tokio::test]
async fn occupied_port_does_not_claim_to_be_running() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let engine = ProxyEngine::default();
    assert!(engine
        .start(ProxyConfig {
            port: occupied.local_addr().unwrap().port(),
            ..Default::default()
        })
        .await
        .is_err());
    assert_eq!(engine.snapshot().status.phase, EnginePhase::Stopped);
}

#[tokio::test]
async fn forwards_post_body_without_recording_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let body = "secret-payload";
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut headers = vec![];
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
        let mut payload = vec![0; body.len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, body.as_bytes());
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
    });
    let (engine, port) = start().await;
    let reply = send(port, format!("POST http://127.0.0.1:{upstream}/echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await;
    assert!(reply.starts_with("HTTP/1.1 204"));
    upstream_task.await.unwrap();
    let snapshot = engine.stop().await;
    assert_eq!(snapshot.traffic[0].request_bytes, body.len() as u64);
    assert_eq!(snapshot.traffic[0].phase, "complete");
}

#[tokio::test]
async fn response_bytes_arrive_before_upstream_finishes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let (release, wait) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut headers = vec![];
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")
            .await
            .unwrap();
        wait.await.unwrap();
        stream.write_all(b"world").await.unwrap();
    });
    let (engine, port) = start().await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client
        .write_all(
            format!("GET http://127.0.0.1:{upstream}/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut received = vec![];
    timeout(Duration::from_secs(2), async {
        while !received.ends_with(b"hello") {
            received.push(client.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert_eq!(engine.snapshot().traffic[0].phase, "pending");
    release.send(()).unwrap();
    client.read_to_end(&mut received).await.unwrap();
    assert!(received.ends_with(b"helloworld"));
    upstream_task.await.unwrap();
    assert_eq!(engine.stop().await.traffic[0].response_bytes, 10);
}

#[tokio::test]
async fn concurrency_limit_closes_and_counts_excess_connections() {
    let (upstream, received) = fixture(vec![], Duration::from_secs(2)).await;
    let engine = ProxyEngine::default();
    let status = engine
        .start(ProxyConfig {
            port: 0,
            connection_limit: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    let port = status.status.listen_address.port();
    let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    first
        .write_all(
            format!("GET http://127.0.0.1:{upstream}/slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    received.await.unwrap();
    let mut excess = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let result = timeout(Duration::from_secs(1), excess.read_u8())
        .await
        .unwrap();
    assert!(result.is_err());
    assert_eq!(engine.snapshot().status.rejected_connections, 1);
    engine.stop().await;
}
