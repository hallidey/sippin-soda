use crate::IssuedLeaf;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor, TlsConnector,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsInterceptError {
    InvalidUpstreamName,
    InvalidLeafMaterial,
    HandshakeTimeout,
    DownstreamHandshake,
    UpstreamVerification,
    Transport,
    LifetimeExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsBridgeResult {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

/// Terminates a client TLS stream and establishes a separately verified TLS
/// connection to the upstream. The caller must authorize the destination and
/// obtain `leaf` through `CaManager::issue_leaf` before invoking this bridge.
/// No certificate-verification bypass is available in this API.
pub async fn bridge_verified_tls<C>(
    client: C,
    upstream: tokio::net::TcpStream,
    upstream_name: &str,
    leaf: IssuedLeaf,
    upstream_roots: RootCertStore,
    handshake_timeout: Duration,
    lifetime: Duration,
) -> Result<TlsBridgeResult, TlsInterceptError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let upstream_name = ServerName::try_from(upstream_name.to_owned())
        .map_err(|_| TlsInterceptError::InvalidUpstreamName)?;
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.certificate_der)],
            PrivatePkcs8KeyDer::from(leaf.private_key_der.to_vec()).into(),
        )
        .map_err(|_| TlsInterceptError::InvalidLeafMaterial)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(upstream_roots)
        .with_no_client_auth();
    let downstream = TlsAcceptor::from(Arc::new(server)).accept(client);
    let verified_upstream =
        TlsConnector::from(Arc::new(client_config)).connect(upstream_name, upstream);
    let (mut downstream, mut verified_upstream) = tokio::time::timeout(handshake_timeout, async {
        let upstream = verified_upstream
            .await
            .map_err(|_| TlsInterceptError::UpstreamVerification)?;
        let downstream = downstream
            .await
            .map_err(|_| TlsInterceptError::DownstreamHandshake)?;
        Ok::<_, TlsInterceptError>((downstream, upstream))
    })
    .await
    .map_err(|_| TlsInterceptError::HandshakeTimeout)??;
    let (client_to_upstream_bytes, upstream_to_client_bytes) = tokio::time::timeout(
        lifetime,
        tokio::io::copy_bidirectional(&mut downstream, &mut verified_upstream),
    )
    .await
    .map_err(|_| TlsInterceptError::LifetimeExceeded)?
    .map_err(|_| TlsInterceptError::Transport)?;
    Ok(TlsBridgeResult {
        client_to_upstream_bytes,
        upstream_to_client_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CaManager;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;

    fn upstream_tls() -> (rcgen::CertifiedKey<rcgen::KeyPair>, ServerConfig) {
        let identity =
            rcgen::generate_simple_self_signed(vec!["upstream.dev.test".into()]).unwrap();
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )
            .unwrap();
        (identity, server)
    }

    async fn downstream_client(
        stream: tokio::io::DuplexStream,
        ca_pem: &[u8],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
        let mut roots = RootCertStore::empty();
        let certificate = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem))
            .next()
            .unwrap()
            .unwrap();
        roots.add(certificate).unwrap();
        TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
        .connect(
            ServerName::try_from("client.dev.test".to_string()).unwrap(),
            stream,
        )
        .await
    }

    #[tokio::test]
    async fn bridges_plaintext_only_when_both_tls_peers_are_verified() {
        let (identity, upstream_config) = upstream_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(Arc::new(upstream_config))
                .accept(socket)
                .await
                .unwrap();
            let mut request = [0; 7];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"inspect");
            tls.write_all(b"verified").await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let (ca_pem, leaf) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let mut upstream_roots = RootCertStore::empty();
        upstream_roots.add(identity.cert.der().clone()).unwrap();
        let upstream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (bridge_side, client_side) = tokio::io::duplex(16 * 1024);
        let bridge = tokio::spawn(bridge_verified_tls(
            bridge_side,
            upstream,
            "upstream.dev.test",
            leaf,
            upstream_roots,
            Duration::from_secs(2),
            Duration::from_secs(2),
        ));
        let mut client = downstream_client(client_side, ca_pem.as_bytes())
            .await
            .unwrap();
        client.write_all(b"inspect").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"verified");
        let result = bridge.await.unwrap().unwrap();
        assert_eq!(result.client_to_upstream_bytes, 7);
        assert_eq!(result.upstream_to_client_bytes, 8);
        upstream_server.await.unwrap();
    }

    async fn assert_upstream_rejected(trust_certificate: bool, upstream_name: &str) {
        let (identity, upstream_config) = upstream_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = TlsAcceptor::from(Arc::new(upstream_config))
                .accept(socket)
                .await;
        });
        let (ca_pem, leaf) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let mut roots = RootCertStore::empty();
        if trust_certificate {
            roots.add(identity.cert.der().clone()).unwrap();
        }
        let upstream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (bridge_side, client_side) = tokio::io::duplex(16 * 1024);
        let upstream_name = upstream_name.to_owned();
        let bridge = tokio::spawn(async move {
            bridge_verified_tls(
                bridge_side,
                upstream,
                &upstream_name,
                leaf,
                roots,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
        });
        let client =
            tokio::spawn(async move { downstream_client(client_side, ca_pem.as_bytes()).await });
        assert_eq!(
            bridge.await.unwrap(),
            Err(TlsInterceptError::UpstreamVerification)
        );
        assert!(client.await.unwrap().is_err());
        upstream_server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_an_untrusted_upstream_certificate() {
        assert_upstream_rejected(false, "upstream.dev.test").await;
    }

    #[tokio::test]
    async fn rejects_an_upstream_certificate_for_a_different_host() {
        assert_upstream_rejected(true, "other.dev.test").await;
    }
}
