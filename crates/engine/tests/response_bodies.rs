use sippin_soda_engine::{ProxyConfig, ProxyEngine};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn start(budget: u64) -> (ProxyEngine, u16) {
    let engine = ProxyEngine::default();
    let port = engine
        .start(ProxyConfig {
            port: 0,
            capture_bodies: true,
            body_disk_budget: budget,
            ..Default::default()
        })
        .await
        .unwrap()
        .status
        .listen_address
        .port();
    (engine, port)
}

async fn drain_headers(stream: &mut TcpStream) {
    let mut bytes = vec![];
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
}

async fn request(proxy: u16, upstream: u16) -> TcpStream {
    let mut client = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    client
        .write_all(
            format!("GET http://127.0.0.1:{upstream}/large HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    drain_headers(&mut client).await;
    client
}

async fn patterned_response(size: usize) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        drain_headers(&mut stream).await;
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes()).await.unwrap();
        let block: Vec<u8> = (0..65536).map(|index| (index % 251) as u8).collect();
        for offset in (0..size).step_by(block.len()) {
            stream
                .write_all(&block[..block.len().min(size - offset)])
                .await
                .unwrap();
        }
    });
    (port, task)
}

async fn completed(engine: &ProxyEngine, id: u64) -> sippin_soda_engine::BodyPage {
    timeout(Duration::from_secs(5), async {
        loop {
            let page = engine.response_body_page(id, 0, 64).await.unwrap();
            if page.state != "recording" {
                return page;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn reads_the_end_of_a_128_mib_response_with_bounded_pages() {
    timeout(Duration::from_secs(60), async {
        let size = 128 * 1024 * 1024;
        let (upstream, server) = patterned_response(size).await;
        let (engine, port) = start(size as u64).await;
        let mut client = request(port, upstream).await;
        let count = tokio::io::copy(&mut client, &mut tokio::io::sink())
            .await
            .unwrap();
        assert_eq!(count, size as u64);
        server.await.unwrap();
        let page = completed(&engine, 1).await;
        assert_eq!(page.state, "complete", "{:?}", page.error);
        assert_eq!(page.total, size as u64);
        let tail = engine
            .response_body_page(1, size as u64 - 65536, 65536)
            .await
            .unwrap();
        assert_eq!(tail.bytes.len(), 65536);
        assert!(tail
            .bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == (index % 251) as u8));
        assert!(engine.response_body_page(1, 0, 65537).await.is_err());
        assert!(engine
            .response_body_page(1, size as u64 + 1, 10)
            .await
            .is_err());
        engine.stop().await;
        assert_eq!(
            engine
                .response_body_page(1, size as u64 - 1, 1)
                .await
                .unwrap()
                .bytes
                .len(),
            1
        );
        engine.clear();
        assert!(engine.response_body_page(1, 0, 1).await.is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exhausted_disk_budget_does_not_truncate_the_forwarded_response() {
    let size = 4 * 1024 * 1024;
    let (upstream, server) = patterned_response(size).await;
    let (engine, port) = start(65536).await;
    let mut client = request(port, upstream).await;
    assert_eq!(
        tokio::io::copy(&mut client, &mut tokio::io::sink())
            .await
            .unwrap(),
        size as u64
    );
    server.await.unwrap();
    let page = completed(&engine, 1).await;
    assert_eq!(page.state, "partial");
    assert!(page.total <= 65536);
    assert!(page.error.unwrap().contains("budget"));
    engine.clear();
    let (upstream, server) = patterned_response(32768).await;
    let mut client = request(port, upstream).await;
    tokio::io::copy(&mut client, &mut tokio::io::sink())
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(completed(&engine, 2).await.state, "complete");
    engine.stop().await;
}

#[tokio::test]
async fn decodes_gzip_deflate_and_brotli_without_changing_wire_bytes() {
    use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZlibEncoder};
    for encoding in ["gzip", "deflate", "br"] {
        let original = b"{\"message\":\"large response, including secrets\"}".repeat(10000);
        let reader = tokio::io::BufReader::new(original.as_slice());
        let mut encoder: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> = match encoding {
            "gzip" => Box::pin(GzipEncoder::new(reader)),
            "deflate" => Box::pin(ZlibEncoder::new(reader)),
            _ => Box::pin(BrotliEncoder::new(reader)),
        };
        let mut compressed = vec![];
        encoder.read_to_end(&mut compressed).await.unwrap();
        let wire = compressed.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            drain_headers(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: {encoding}\r\n\r\n", wire.len()).as_bytes()).await.unwrap();
            stream.write_all(&wire).await.unwrap();
        });
        let (engine, port) = start(1024 * 1024).await;
        let mut client = request(port, upstream).await;
        let mut received = vec![];
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, compressed);
        server.await.unwrap();
        let page = completed(&engine, 1).await;
        assert_eq!(page.state, "complete", "{encoding}: {:?}", page.error);
        assert_eq!(page.total, original.len() as u64);
        let tail = engine
            .response_body_page(1, original.len() as u64 - 100, 100)
            .await
            .unwrap();
        assert_eq!(tail.bytes, original[original.len() - 100..]);
        engine.stop().await;
    }
}

#[tokio::test]
async fn long_response_outlives_header_timeout_and_can_be_read_while_streaming() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let (release, wait) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        drain_headers(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")
            .await
            .unwrap();
        wait.await.unwrap();
        stream.write_all(b"world").await.unwrap();
    });
    let engine = ProxyEngine::default();
    let port = engine
        .start(ProxyConfig {
            port: 0,
            capture_bodies: true,
            request_timeout: Duration::from_millis(100),
            ..Default::default()
        })
        .await
        .unwrap()
        .status
        .listen_address
        .port();
    let mut client = request(port, upstream).await;
    let mut first = [0; 5];
    client.read_exact(&mut first).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let page = engine.response_body_page(1, 0, 5).await.unwrap();
    assert_eq!(page.bytes, b"hello");
    assert_eq!(page.state, "recording");
    release.send(()).unwrap();
    let mut rest = vec![];
    client.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"world");
    server.await.unwrap();
    assert_eq!(completed(&engine, 1).await.total, 10);
    engine.stop().await;
}

#[tokio::test]
async fn stop_marks_body_partial_and_clear_during_stream_does_not_stop_forwarding() {
    for clear in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap().port();
        let (release, wait) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            drain_headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")
                .await
                .unwrap();
            wait.await.unwrap();
            let _ = stream.write_all(b"world").await;
        });
        let (engine, port) = start(65536).await;
        let mut client = request(port, upstream).await;
        client.read_exact(&mut [0; 5]).await.unwrap();
        if clear {
            engine.clear();
        } else {
            engine.stop().await;
        }
        release.send(()).unwrap();
        let mut rest = vec![];
        let _ = timeout(Duration::from_secs(3), client.read_to_end(&mut rest))
            .await
            .unwrap();
        if clear {
            assert_eq!(rest, b"world");
            assert!(engine.response_body_page(1, 0, 1).await.is_err());
        } else {
            assert_eq!(completed(&engine, 1).await.state, "partial");
        }
        server.await.unwrap();
        engine.stop().await;
    }
}

#[tokio::test]
async fn empty_bodies_and_unsupported_or_corrupt_encodings_have_explicit_states() {
    for (status, encoding, body, expected) in [
        (204, "gzip", "", "complete"),
        (200, "", "", "complete"),
        (200, "gzip", "broken", "partial"),
        (200, "zstd", "opaque", "unavailable"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            drain_headers(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Encoding: {encoding}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let (engine, port) = start(65536).await;
        let mut client = request(port, upstream).await;
        let mut received = vec![];
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, body.as_bytes());
        server.await.unwrap();
        assert_eq!(
            completed(&engine, 1).await.state,
            expected,
            "{status} {encoding}"
        );
        engine.stop().await;
    }
}

async fn record_payload(payload: Vec<u8>, budget: u64) -> ProxyEngine {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        drain_headers(&mut stream).await;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    payload.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let (engine, port) = start(budget).await;
    let mut client = request(port, upstream).await;
    tokio::io::copy(&mut client, &mut tokio::io::sink())
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(completed(&engine, 1).await.state, "complete");
    engine.stop().await;
    engine
}

async fn wait_json(engine: &ProxyEngine) -> sippin_soda_engine::JsonStatus {
    timeout(Duration::from_secs(15), async {
        loop {
            let status = engine.response_json_view(1, false, false).unwrap();
            if status.state != "building" {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn json_layout_preserves_numbers_duplicate_keys_and_escapes() {
    let original = br#"{"n":9007199254740993123456789,"n":1e9999,"s":"a\"b\\c\u0041","empty":[]}"#;
    let engine = record_payload(original.to_vec(), 1024 * 1024).await;
    engine.response_json_view(1, true, false).unwrap();
    let status = wait_json(&engine).await;
    assert_eq!(status.state, "ready", "{:?}", status.error);
    let page = engine.response_json_page(1, 0, 65536).await.unwrap();
    let rendered = String::from_utf8(page.bytes).unwrap();
    assert!(rendered.contains("\n  \"n\": 9007199254740993123456789,"));
    assert!(rendered.contains("\"n\": 1e9999"));
    assert!(rendered.contains(r#""s": "a\"b\\c\u0041""#));
    assert_eq!(
        engine.response_body_page(1, 0, 65536).await.unwrap().bytes,
        original
    );
    assert!(engine.response_json_page(1, 0, 65537).await.is_err());
    engine.clear();
    assert!(engine.response_json_page(1, 0, 1).await.is_err());
}

#[tokio::test]
async fn large_json_layout_and_full_body_search_reach_the_tail() {
    let mut original = b"{\"payload\":\"".to_vec();
    original.extend(vec![b'x'; 5 * 1024 * 1024]);
    original.extend_from_slice(b"\",\"tail\":\"END-OF-LARGE-RESPONSE\"}");
    let length = original.len() as u64;
    let engine = record_payload(original, 20 * 1024 * 1024).await;
    let first = engine
        .search_response_body(1, "END-OF-LARGE-RESPONSE".into(), 0, length)
        .await
        .unwrap();
    assert!(!first.done);
    let second = engine
        .search_response_body(1, "END-OF-LARGE-RESPONSE".into(), first.next_offset, length)
        .await
        .unwrap();
    let hit = second.found.unwrap();
    assert_eq!(
        engine.response_body_page(1, hit, 21).await.unwrap().bytes,
        b"END-OF-LARGE-RESPONSE"
    );
    engine.response_json_view(1, true, false).unwrap();
    let status = wait_json(&engine).await;
    assert_eq!(status.state, "ready", "{:?}", status.error);
    let total = engine.response_json_page(1, 0, 1).await.unwrap().total;
    let tail = engine.response_json_page(1, total - 64, 64).await.unwrap();
    assert!(String::from_utf8(tail.bytes)
        .unwrap()
        .contains("\"tail\": \"END-OF-LARGE-RESPONSE\""));
}

#[tokio::test]
async fn invalid_json_and_expanded_layout_budget_do_not_damage_raw_capture() {
    for original in [
        b"{broken}".to_vec(),
        b"{} {}".to_vec(),
        vec![b'"', 0xff, b'"'],
        format!("{}0{}", "[".repeat(129), "]".repeat(129)).into_bytes(),
    ] {
        let engine = record_payload(original.clone(), 1024 * 1024).await;
        engine.response_json_view(1, true, false).unwrap();
        assert_eq!(wait_json(&engine).await.state, "error");
        assert_eq!(
            engine.response_body_page(1, 0, 65536).await.unwrap().bytes,
            original
        );
    }
    let original = b"[1,2,3,4,5]";
    let engine = record_payload(original.to_vec(), original.len() as u64 + 10).await;
    engine.response_json_view(1, true, false).unwrap();
    assert!(wait_json(&engine).await.error.unwrap().contains("budget"));
    assert_eq!(
        engine.response_body_page(1, 0, 65536).await.unwrap().bytes,
        original
    );
    assert!(engine
        .search_response_body(1, "".into(), 0, 1)
        .await
        .is_err());
    assert!(engine
        .search_response_body(1, "x".repeat(4097), 0, 1)
        .await
        .is_err());
}

#[tokio::test]
async fn json_layout_can_be_cancelled_and_retried() {
    let mut payload = b"[\"".to_vec();
    payload.extend(vec![b'x'; 8 * 1024 * 1024]);
    payload.extend_from_slice(b"\"]");
    let engine = record_payload(payload, 24 * 1024 * 1024).await;
    engine.response_json_view(1, true, false).unwrap();
    engine.response_json_view(1, false, true).unwrap();
    assert_eq!(wait_json(&engine).await.state, "error");
    engine.response_json_view(1, true, false).unwrap();
    assert_eq!(wait_json(&engine).await.state, "ready");
}
