use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sippin_soda_engine::{ProxyClientAuth, ProxyConfig, ProxyEngine};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn start(mut config: ProxyConfig) -> (ProxyEngine, u16) {
    config.port = 0;
    let engine = ProxyEngine::default();
    let port = engine
        .start(config)
        .await
        .unwrap()
        .status
        .listen_address
        .port();
    (engine, port)
}

async fn headers(client: &mut TcpStream) -> String {
    timeout(Duration::from_secs(3), async {
        let mut bytes = vec![];
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(client.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}

async fn connect(proxy: u16, upstream: u16, early: &[u8]) -> TcpStream {
    let mut client = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    let mut request = format!("CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nProxy-Authorization: secret\r\n\r\n").into_bytes();
    request.extend_from_slice(early);
    client.write_all(&request).await.unwrap();
    let reply = headers(&mut client).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(!reply.to_lowercase().contains("content-length"));
    assert!(!reply.to_lowercase().contains("transfer-encoding"));
    client
}

async fn settled(engine: &ProxyEngine) {
    timeout(Duration::from_secs(3), async {
        while engine.snapshot().traffic[0].phase == "pending" {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authenticated_connect_is_bound_to_the_configured_client_profile() {
    const TOKEN: &str = "abcdef0123456789abcdef0123456789";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let (engine, proxy) = start(ProxyConfig {
        client_auth: Some(ProxyClientAuth::new("runtime-1", TOKEN).unwrap()),
        ..Default::default()
    })
    .await;

    let mut unauthenticated = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    unauthenticated
        .write_all(
            format!("CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    assert!(headers(&mut unauthenticated)
        .await
        .starts_with("HTTP/1.1 407"));
    assert!(timeout(Duration::from_millis(50), listener.accept())
        .await
        .is_err());

    let credentials = BASE64.encode(format!("runtime-1:{TOKEN}"));
    let mut client = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    client
        .write_all(
            format!("CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic {credentials}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    assert!(headers(&mut client).await.starts_with("HTTP/1.1 200"));
    let (server, _) = listener.accept().await.unwrap();
    drop(client);
    drop(server);
    settled(&engine).await;
    let capture = engine.stop().await.traffic.remove(0);
    assert_eq!(capture.client_profile_id.as_deref(), Some("runtime-1"));
}

#[tokio::test]
async fn preserves_early_bytes_half_close_and_bidirectional_counts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut server, _) = listener.accept().await.unwrap();
        let mut body = vec![];
        server.read_to_end(&mut body).await.unwrap();
        // Only tunnel bytes, never the CONNECT headers or proxy credentials.
        assert_eq!(body, b"early-later");
        server.write_all(b"reply-after-eof").await.unwrap();
    });
    let (engine, port) = start(Default::default()).await;
    let mut client = connect(port, upstream, b"early-").await;
    client.write_all(b"later").await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = vec![];
    timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"reply-after-eof");
    task.await.unwrap();
    settled(&engine).await;
    let capture = engine.stop().await.traffic.remove(0);
    assert_eq!(capture.kind, "tunnel");
    assert_eq!(capture.phase, "complete");
    assert_eq!(capture.status, Some(200));
    assert_eq!(
        capture.destination_class,
        sippin_soda_engine::DestinationClass::Development
    );
    assert_eq!(capture.request_bytes, 11);
    assert_eq!(capture.response_bytes, 15);
    assert!(capture.response_headers.is_empty());
    assert!(capture
        .request_headers
        .iter()
        .any(|(k, v)| k == "proxy-authorization" && v == "[REDACTED]"));
}

#[tokio::test]
async fn rejects_invalid_authorities_bodies_loops_and_unreachable_servers() {
    let (engine, port) = start(Default::default()).await;
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = unused.local_addr().unwrap().port();
    drop(unused);
    for (target, extra, status) in [
        ("localhost".to_string(), "", 400),
        ("localhost:0".to_string(), "", 400),
        ("user:secret@localhost:443".to_string(), "", 400),
        ("http://localhost:443/path".to_string(), "", 400),
        ("localhost:443".to_string(), "Content-Length: 1\r\n", 400),
        (format!("localhost:{port}"), "", 508),
        (format!("[::ffff:127.0.0.1]:{port}"), "", 508),
        (format!("127.0.0.1:{closed}"), "", 502),
    ] {
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(
                format!("CONNECT {target} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let reply = headers(&mut client).await;
        assert!(
            reply.starts_with(&format!("HTTP/1.1 {status}")),
            "{target}: {reply}"
        );
    }
    let snapshot = engine.stop().await;
    assert!(snapshot
        .traffic
        .iter()
        .all(|capture| !capture.target.contains("secret")));
}

#[tokio::test]
async fn upgraded_tunnels_count_toward_limit_and_stop_closes_both_sockets() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (engine, port) = start(ProxyConfig {
        connection_limit: 1,
        ..Default::default()
    })
    .await;
    let mut client = connect(port, listener.local_addr().unwrap().port(), b"").await;
    let (mut server, _) = listener.accept().await.unwrap();
    let mut excess = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(timeout(Duration::from_secs(3), excess.read_u8())
        .await
        .unwrap()
        .is_err());
    assert_eq!(engine.snapshot().status.rejected_connections, 1);
    engine.stop().await;
    assert!(timeout(Duration::from_secs(3), client.read_u8())
        .await
        .unwrap()
        .is_err());
    assert!(timeout(Duration::from_secs(3), server.read_u8())
        .await
        .unwrap()
        .is_err());
    assert_eq!(engine.snapshot().traffic[0].phase, "error");
    TcpListener::bind(("127.0.0.1", port)).await.unwrap();
}

#[tokio::test]
async fn tunnel_lifetime_is_bounded_and_partial_counts_are_visible() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (engine, port) = start(ProxyConfig {
        tunnel_timeout: Duration::from_millis(200),
        ..Default::default()
    })
    .await;
    let mut client = connect(port, listener.local_addr().unwrap().port(), b"hello").await;
    let (mut server, _) = listener.accept().await.unwrap();
    let mut bytes = [0; 5];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(engine.snapshot().traffic[0].request_bytes, 5);
    assert!(timeout(Duration::from_secs(3), client.read_u8())
        .await
        .unwrap()
        .is_err());
    settled(&engine).await;
    let capture = engine.stop().await.traffic.remove(0);
    assert_eq!(
        capture.error.as_deref(),
        Some("Tunnel lifetime limit reached.")
    );
    assert_eq!(capture.request_bytes, 5);
}

#[tokio::test]
async fn https_remains_end_to_end_and_client_certificate_validation_is_preserved() {
    use tokio_rustls::{
        rustls::{
            pki_types::{PrivatePkcs8KeyDer, ServerName},
            ClientConfig, RootCertStore, ServerConfig,
        },
        TlsAcceptor, TlsConnector,
    };
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            request.push(tls.read_u8().await.unwrap());
        }
        assert!(request.starts_with(b"GET /private?token=secret"));
        tls.write_all(b"HTTP/1.1 418 Teapot\r\nContent-Length: 6\r\n\r\nsecret")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
        drop(tls);
        let (socket, _) = listener.accept().await.unwrap();
        assert!(acceptor.accept(socket).await.is_err());
    });
    let (engine, port) = start(Default::default()).await;
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap(); // Trust only inside this test client, never the OS.
    let trusted = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let socket = connect(port, upstream, b"").await;
    let mut tls = trusted
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap();
    tls.write_all(b"GET /private?token=secret HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tls.flush().await.unwrap();
    let mut reply = vec![];
    timeout(Duration::from_secs(3), tls.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 418"));
    drop(tls);
    settled(&engine).await;
    let capture = &engine.snapshot().traffic[0];
    assert_eq!(capture.status, Some(200)); // CONNECT status, never the inner 418.
    assert_eq!(capture.target, format!("127.0.0.1:{upstream}"));
    assert!(capture.response_headers.is_empty());
    assert!(capture.response_bytes > reply.len() as u64);
    let untrusted = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    ));
    let socket = connect(port, upstream, b"").await;
    assert!(untrusted
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .is_err());
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    engine.stop().await;
}
