use crate::{authorize, Action, CaStatus, DestinationClass, IssuedLeaf, PolicyError};
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsReadinessState {
    Disabled,
    MissingCa,
    ExpiredCa,
    ClientTrustUnverified,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInspectionReadiness {
    pub state: TlsReadinessState,
    pub can_inspect_development: bool,
    pub verified_host: Option<String>,
    pub proof_expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsInspectionDenied {
    NotReady(TlsReadinessState),
    ProductionReadOnly,
    DestinationUnclassified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTrustError {
    InspectionDisabled,
    InvalidLeafMaterial,
    HandshakeTimeout,
    ClientRejectedCertificate,
}

#[derive(Debug)]
struct TlsClientTrustProof {
    issuer_fingerprint_sha256: String,
    verified_host: String,
    expires_at: u64,
}

#[derive(Debug, Default)]
pub struct TlsInspectionGate {
    opted_in: bool,
    trust_proof: Option<TlsClientTrustProof>,
}

impl TlsInspectionGate {
    pub fn set_opt_in(&mut self, enabled: bool) {
        if self.opted_in != enabled {
            self.trust_proof = None;
        }
        self.opted_in = enabled;
    }

    pub async fn verify_client_trust<C>(
        &mut self,
        client: C,
        leaf: IssuedLeaf,
        handshake_timeout: Duration,
    ) -> Result<(), TlsTrustError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.opted_in {
            return Err(TlsTrustError::InspectionDisabled);
        }
        self.trust_proof = None;
        self.trust_proof = Some(client_trust_handshake(client, leaf, handshake_timeout).await?);
        Ok(())
    }

    pub fn readiness(&self, ca: &CaStatus) -> TlsInspectionReadiness {
        self.readiness_at(ca, unix_millis())
    }

    fn readiness_at(&self, ca: &CaStatus, now: u64) -> TlsInspectionReadiness {
        let state = if !self.opted_in {
            TlsReadinessState::Disabled
        } else if ca.state != "ready" || ca.fingerprint_sha256.is_none() || ca.expires_at.is_none()
        {
            TlsReadinessState::MissingCa
        } else if ca.expires_at.is_some_and(|expires| expires <= now) {
            TlsReadinessState::ExpiredCa
        } else if self.trust_proof.as_ref().is_none_or(|proof| {
            Some(&proof.issuer_fingerprint_sha256) != ca.fingerprint_sha256.as_ref()
                || proof.expires_at <= now
        }) {
            TlsReadinessState::ClientTrustUnverified
        } else {
            TlsReadinessState::Ready
        };
        let proof = (state == TlsReadinessState::Ready)
            .then_some(self.trust_proof.as_ref())
            .flatten();
        TlsInspectionReadiness {
            state,
            can_inspect_development: state == TlsReadinessState::Ready,
            verified_host: proof.map(|proof| proof.verified_host.clone()),
            proof_expires_at: proof.map(|proof| proof.expires_at),
        }
    }

    pub fn authorize(
        &self,
        ca: &CaStatus,
        destination: DestinationClass,
    ) -> Result<(), TlsInspectionDenied> {
        let readiness = self.readiness(ca);
        if readiness.state != TlsReadinessState::Ready {
            return Err(TlsInspectionDenied::NotReady(readiness.state));
        }
        authorize(destination, Action::InspectTls).map_err(|error| match error {
            PolicyError::ProductionReadOnly => TlsInspectionDenied::ProductionReadOnly,
            PolicyError::DestinationUnclassified => TlsInspectionDenied::DestinationUnclassified,
        })
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Completes a real downstream TLS handshake. Success proves that this client
/// accepted a leaf issued by the current CA; the proof is scoped to that CA,
/// host and leaf lifetime and cannot be constructed by callers.
async fn client_trust_handshake<C>(
    client: C,
    leaf: IssuedLeaf,
    handshake_timeout: Duration,
) -> Result<TlsClientTrustProof, TlsTrustError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let proof = TlsClientTrustProof {
        issuer_fingerprint_sha256: leaf.issuer_fingerprint_sha256.clone(),
        verified_host: leaf.host.clone(),
        expires_at: leaf.expires_at,
    };
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.certificate_der)],
            PrivatePkcs8KeyDer::from(leaf.private_key_der.to_vec()).into(),
        )
        .map_err(|_| TlsTrustError::InvalidLeafMaterial)?;
    tokio::time::timeout(
        handshake_timeout,
        TlsAcceptor::from(Arc::new(server)).accept(client),
    )
    .await
    .map_err(|_| TlsTrustError::HandshakeTimeout)?
    .map_err(|_| TlsTrustError::ClientRejectedCertificate)?;
    Ok(proof)
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
    async fn readiness_requires_opt_in_current_ca_and_real_client_trust() {
        let (ca_pem, leaf, status) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let (server_side, client_side) = tokio::io::duplex(16 * 1024);
        let mut gate = TlsInspectionGate::default();
        assert_eq!(gate.readiness(&status).state, TlsReadinessState::Disabled);
        gate.set_opt_in(true);
        assert_eq!(
            gate.readiness(&status).state,
            TlsReadinessState::ClientTrustUnverified
        );
        let verification = gate.verify_client_trust(server_side, leaf, Duration::from_secs(2));
        let client_connection = downstream_client(client_side, ca_pem.as_bytes());
        let (verification, client) = tokio::join!(verification, client_connection);
        verification.unwrap();
        drop(client.unwrap());
        let readiness = gate.readiness(&status);
        assert_eq!(readiness.state, TlsReadinessState::Ready);
        assert!(readiness.can_inspect_development);
        assert_eq!(readiness.verified_host.as_deref(), Some("client.dev.test"));
        assert_eq!(
            gate.readiness_at(&status, readiness.proof_expires_at.unwrap())
                .state,
            TlsReadinessState::ClientTrustUnverified
        );
        assert_eq!(
            gate.authorize(&status, DestinationClass::Development),
            Ok(())
        );
        assert_eq!(
            gate.authorize(&status, DestinationClass::Production),
            Err(TlsInspectionDenied::ProductionReadOnly)
        );
        assert_eq!(
            gate.authorize(&status, DestinationClass::Unknown),
            Err(TlsInspectionDenied::DestinationUnclassified)
        );
        let mut rotated = status.clone();
        rotated.fingerprint_sha256 = Some("rotated-ca".into());
        assert_eq!(
            gate.readiness(&rotated).state,
            TlsReadinessState::ClientTrustUnverified
        );

        gate.set_opt_in(false);
        gate.set_opt_in(true);
        assert_eq!(
            gate.readiness(&status).state,
            TlsReadinessState::ClientTrustUnverified
        );
    }

    #[tokio::test]
    async fn readiness_rejects_changed_or_expired_ca_and_failed_trust_handshake() {
        let (_ca_pem, leaf, mut status) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let (server_side, client_side) = tokio::io::duplex(16 * 1024);
        let mut gate = TlsInspectionGate::default();
        gate.set_opt_in(true);
        let verification = gate.verify_client_trust(server_side, leaf, Duration::from_secs(2));
        let untrusted = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        ));
        let client_connection = untrusted.connect(
            ServerName::try_from("client.dev.test".to_string()).unwrap(),
            client_side,
        );
        let (verification, client) = tokio::join!(verification, client_connection);
        assert!(client.is_err());
        assert!(matches!(
            verification,
            Err(TlsTrustError::ClientRejectedCertificate)
        ));
        assert_eq!(
            gate.readiness(&status).state,
            TlsReadinessState::ClientTrustUnverified
        );
        status.expires_at = Some(1);
        assert_eq!(
            gate.readiness_at(&status, 2).state,
            TlsReadinessState::ExpiredCa
        );
        status.state = "absent".into();
        assert_eq!(
            gate.readiness_at(&status, 2).state,
            TlsReadinessState::MissingCa
        );

        let (_, leaf, _) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let (server_side, _client_side) = tokio::io::duplex(1024);
        let mut disabled = TlsInspectionGate::default();
        assert_eq!(
            disabled
                .verify_client_trust(server_side, leaf, Duration::from_secs(2))
                .await,
            Err(TlsTrustError::InspectionDisabled)
        );
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
        let (ca_pem, leaf, _) = CaManager::ephemeral_leaf_for_test("client.dev.test");
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
        let (ca_pem, leaf, _) = CaManager::ephemeral_leaf_for_test("client.dev.test");
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
