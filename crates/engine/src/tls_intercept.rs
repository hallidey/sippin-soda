use crate::{authorize, Action, CaStatus, DestinationClass, IssuedLeaf, PolicyError};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    ClientMismatch,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsClientIdentity {
    id: String,
    name: String,
}

impl TlsClientIdentity {
    pub fn new(id: &str, name: &str) -> Result<Self, String> {
        let id = Self::validate_id(id)?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
            return Err("Client profile names must contain 1-80 visible characters.".into());
        }
        Ok(Self {
            id,
            name: name.into(),
        })
    }

    pub fn validate_id(id: &str) -> Result<String, String> {
        let id = id.trim();
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("Client profile IDs must use 1-64 letters, numbers, '-' or '_'.".into());
        }
        Ok(id.into())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInspectionReadiness {
    pub state: TlsReadinessState,
    pub can_inspect_development: bool,
    pub verified_host: Option<String>,
    pub verified_client: Option<TlsClientIdentity>,
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
    client: TlsClientIdentity,
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
        identity: TlsClientIdentity,
        handshake_timeout: Duration,
    ) -> Result<tokio_rustls::server::TlsStream<C>, TlsTrustError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.opted_in {
            return Err(TlsTrustError::InspectionDisabled);
        }
        self.trust_proof = None;
        let (proof, stream) =
            client_trust_handshake(client, leaf, identity, handshake_timeout).await?;
        self.trust_proof = Some(proof);
        Ok(stream)
    }

    pub fn readiness(&self, ca: &CaStatus, client_id: &str) -> TlsInspectionReadiness {
        self.readiness_at(ca, client_id, unix_millis())
    }

    fn readiness_at(&self, ca: &CaStatus, client_id: &str, now: u64) -> TlsInspectionReadiness {
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
        } else if self
            .trust_proof
            .as_ref()
            .is_some_and(|proof| proof.client.id() != client_id)
        {
            TlsReadinessState::ClientMismatch
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
            verified_client: proof.map(|proof| proof.client.clone()),
            proof_expires_at: proof.map(|proof| proof.expires_at),
        }
    }

    pub fn authorize(
        &self,
        ca: &CaStatus,
        client_id: &str,
        destination: DestinationClass,
    ) -> Result<(), TlsInspectionDenied> {
        let readiness = self.readiness(ca, client_id);
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
/// host, selected client profile and leaf lifetime and cannot be constructed
/// by callers.
async fn client_trust_handshake<C>(
    client: C,
    leaf: IssuedLeaf,
    identity: TlsClientIdentity,
    handshake_timeout: Duration,
) -> Result<(TlsClientTrustProof, tokio_rustls::server::TlsStream<C>), TlsTrustError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let proof = TlsClientTrustProof {
        issuer_fingerprint_sha256: leaf.issuer_fingerprint_sha256.clone(),
        verified_host: leaf.host.clone(),
        client: identity,
        expires_at: leaf.expires_at,
    };
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.certificate_der)],
            PrivatePkcs8KeyDer::from(leaf.private_key_der.to_vec()).into(),
        )
        .map_err(|_| TlsTrustError::InvalidLeafMaterial)?;
    let stream = tokio::time::timeout(
        handshake_timeout,
        TlsAcceptor::from(Arc::new(server)).accept(client),
    )
    .await
    .map_err(|_| TlsTrustError::HandshakeTimeout)?
    .map_err(|_| TlsTrustError::ClientRejectedCertificate)?;
    Ok((proof, stream))
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
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth(),
    );
    bridge_verified_tls_with_config(
        client,
        upstream,
        upstream_name,
        leaf,
        client_config,
        handshake_timeout,
        lifetime,
    )
    .await
}

pub(crate) fn platform_tls_client_config() -> Result<Arc<ClientConfig>, String> {
    ClientConfig::builder()
        .with_platform_verifier()
        .map(|builder| Arc::new(builder.with_no_client_auth()))
        .map_err(|_| "Cannot initialize platform TLS certificate verification.".into())
}

pub(crate) async fn bridge_verified_tls_with_config<C>(
    client: C,
    upstream: tokio::net::TcpStream,
    upstream_name: &str,
    leaf: IssuedLeaf,
    client_config: Arc<ClientConfig>,
    handshake_timeout: Duration,
    lifetime: Duration,
) -> Result<TlsBridgeResult, TlsInterceptError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let established = establish_verified_tls_with_config(
        client,
        upstream,
        upstream_name,
        leaf,
        client_config,
        handshake_timeout,
    )
    .await?;
    let (downstream_reader, downstream_writer) = tokio::io::split(established.downstream);
    let (upstream_reader, upstream_writer) = tokio::io::split(established.upstream);
    let transfer = async {
        tokio::try_join!(
            copy_with_flush(downstream_reader, upstream_writer),
            copy_with_flush(upstream_reader, downstream_writer),
        )
    };
    let (client_to_upstream_bytes, upstream_to_client_bytes) =
        tokio::time::timeout(lifetime, transfer)
            .await
            .map_err(|_| TlsInterceptError::LifetimeExceeded)?
            .map_err(|_| TlsInterceptError::Transport)?;
    Ok(TlsBridgeResult {
        client_to_upstream_bytes,
        upstream_to_client_bytes,
    })
}

pub(crate) struct VerifiedTls<C> {
    pub(crate) downstream: tokio_rustls::server::TlsStream<C>,
    pub(crate) upstream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

pub(crate) async fn establish_verified_tls_with_config<C>(
    client: C,
    upstream: tokio::net::TcpStream,
    upstream_name: &str,
    leaf: IssuedLeaf,
    client_config: Arc<ClientConfig>,
    handshake_timeout: Duration,
) -> Result<VerifiedTls<C>, TlsInterceptError>
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
    let downstream = TlsAcceptor::from(Arc::new(server)).accept(client);
    let verified_upstream = TlsConnector::from(client_config).connect(upstream_name, upstream);
    let (downstream, upstream) = tokio::time::timeout(handshake_timeout, async {
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
    Ok(VerifiedTls {
        downstream,
        upstream,
    })
}

async fn copy_with_flush<R, W>(mut reader: R, mut writer: W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            writer.shutdown().await?;
            return Ok(transferred);
        }
        writer.write_all(&buffer[..count]).await?;
        writer.flush().await?;
        transferred += count as u64;
    }
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

    #[test]
    fn client_identity_is_canonical_and_bounded() {
        let identity = TlsClientIdentity::new(" browser-1 ", " Development browser ").unwrap();
        assert_eq!(identity.id(), "browser-1");
        assert_eq!(identity.name(), "Development browser");
        assert!(TlsClientIdentity::new("browser/1", "Browser").is_err());
        assert!(TlsClientIdentity::new("browser-1", "\n").is_err());
        assert!(TlsClientIdentity::new("browser-1", &"é".repeat(81)).is_err());
    }

    #[tokio::test]
    async fn readiness_requires_opt_in_current_ca_and_real_client_trust() {
        let (ca_pem, leaf, status) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let identity = TlsClientIdentity::new("browser-1", "Development browser").unwrap();
        let (server_side, client_side) = tokio::io::duplex(16 * 1024);
        let mut gate = TlsInspectionGate::default();
        assert_eq!(
            gate.readiness(&status, identity.id()).state,
            TlsReadinessState::Disabled
        );
        gate.set_opt_in(true);
        assert_eq!(
            gate.readiness(&status, identity.id()).state,
            TlsReadinessState::ClientTrustUnverified
        );
        let verification =
            gate.verify_client_trust(server_side, leaf, identity.clone(), Duration::from_secs(2));
        let client_connection = downstream_client(client_side, ca_pem.as_bytes());
        let (verification, client) = tokio::join!(verification, client_connection);
        drop(verification.unwrap());
        drop(client.unwrap());
        let readiness = gate.readiness(&status, identity.id());
        assert_eq!(readiness.state, TlsReadinessState::Ready);
        assert!(readiness.can_inspect_development);
        assert_eq!(readiness.verified_host.as_deref(), Some("client.dev.test"));
        assert_eq!(readiness.verified_client.as_ref(), Some(&identity));
        assert_eq!(
            gate.readiness(&status, "different-client").state,
            TlsReadinessState::ClientMismatch
        );
        assert_eq!(
            gate.readiness_at(&status, identity.id(), readiness.proof_expires_at.unwrap())
                .state,
            TlsReadinessState::ClientTrustUnverified
        );
        assert_eq!(
            gate.authorize(&status, identity.id(), DestinationClass::Development),
            Ok(())
        );
        assert_eq!(
            gate.authorize(&status, identity.id(), DestinationClass::Production),
            Err(TlsInspectionDenied::ProductionReadOnly)
        );
        assert_eq!(
            gate.authorize(&status, identity.id(), DestinationClass::Unknown),
            Err(TlsInspectionDenied::DestinationUnclassified)
        );
        let mut rotated = status.clone();
        rotated.fingerprint_sha256 = Some("rotated-ca".into());
        assert_eq!(
            gate.readiness(&rotated, identity.id()).state,
            TlsReadinessState::ClientTrustUnverified
        );

        gate.set_opt_in(false);
        gate.set_opt_in(true);
        assert_eq!(
            gate.readiness(&status, identity.id()).state,
            TlsReadinessState::ClientTrustUnverified
        );
    }

    #[tokio::test]
    async fn readiness_rejects_changed_or_expired_ca_and_failed_trust_handshake() {
        let (_ca_pem, leaf, mut status) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let identity = TlsClientIdentity::new("runtime-1", "Test runtime").unwrap();
        let (server_side, client_side) = tokio::io::duplex(16 * 1024);
        let mut gate = TlsInspectionGate::default();
        gate.set_opt_in(true);
        let verification =
            gate.verify_client_trust(server_side, leaf, identity.clone(), Duration::from_secs(2));
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
            gate.readiness(&status, identity.id()).state,
            TlsReadinessState::ClientTrustUnverified
        );
        status.expires_at = Some(1);
        assert_eq!(
            gate.readiness_at(&status, identity.id(), 2).state,
            TlsReadinessState::ExpiredCa
        );
        status.state = "absent".into();
        assert_eq!(
            gate.readiness_at(&status, identity.id(), 2).state,
            TlsReadinessState::MissingCa
        );

        let (_, leaf, _) = CaManager::ephemeral_leaf_for_test("client.dev.test");
        let (server_side, _client_side) = tokio::io::duplex(1024);
        let mut disabled = TlsInspectionGate::default();
        assert!(matches!(
            disabled
                .verify_client_trust(server_side, leaf, identity, Duration::from_secs(2))
                .await,
            Err(TlsTrustError::InspectionDisabled)
        ));
    }

    #[tokio::test]
    async fn bridges_large_persistent_round_trip_only_when_both_tls_peers_are_verified() {
        const REQUEST_BYTES: usize = 128 * 1024;
        let (identity, upstream_config) = upstream_tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(Arc::new(upstream_config))
                .accept(socket)
                .await
                .unwrap();
            let mut request = vec![0; REQUEST_BYTES];
            tls.read_exact(&mut request).await.unwrap();
            assert!(request.iter().all(|byte| *byte == 0x5a));
            tls.write_all(b"verified").await.unwrap();
            tls.flush().await.unwrap();
            let mut remainder = Vec::new();
            tls.read_to_end(&mut remainder).await.unwrap();
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
        client.write_all(&vec![0x5a; REQUEST_BYTES]).await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"verified");
        client.shutdown().await.unwrap();
        let result = bridge.await.unwrap().unwrap();
        assert_eq!(result.client_to_upstream_bytes, REQUEST_BYTES as u64);
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

    #[derive(Clone)]
    struct BenchmarkIdentity {
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
    }

    #[derive(Clone, Copy)]
    struct BenchmarkConfig {
        payload_bytes: usize,
        samples: usize,
        concurrency: usize,
    }

    struct BenchmarkModeResult {
        wall_time: Duration,
        samples: Vec<Duration>,
        peak_memory_bytes: u64,
    }

    fn benchmark_setting(name: &str, default: usize, min: usize, max: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| (*value >= min) && (*value <= max))
            .unwrap_or(default)
    }

    fn benchmark_config() -> BenchmarkConfig {
        BenchmarkConfig {
            payload_bytes: benchmark_setting("SIPPIN_BENCH_PAYLOAD_MIB", 1, 1, 64) * 1024 * 1024,
            samples: benchmark_setting("SIPPIN_BENCH_SAMPLES", 20, 3, 500),
            concurrency: benchmark_setting("SIPPIN_BENCH_CONCURRENCY", 4, 1, 64),
        }
    }

    fn benchmark_identity(host: &str) -> BenchmarkIdentity {
        let identity = rcgen::generate_simple_self_signed(vec![host.into()]).unwrap();
        BenchmarkIdentity {
            certificate: identity.cert.der().clone(),
            private_key: identity.signing_key.serialize_der(),
        }
    }

    async fn echo_server(
        listener: TcpListener,
        tls: Option<Arc<ServerConfig>>,
        payload_bytes: usize,
    ) {
        let (socket, _) = listener.accept().await.unwrap();
        if let Some(tls) = tls {
            let mut stream = TlsAcceptor::from(tls).accept(socket).await.unwrap();
            let mut payload = vec![0; payload_bytes];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        } else {
            let mut stream = socket;
            let mut payload = vec![0; payload_bytes];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        }
    }

    async fn pass_through_sample(payload: Arc<Vec<u8>>) -> Duration {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(echo_server(listener, None, payload.len()));
        let mut upstream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut tunnel, mut client) = tokio::io::duplex(payload.len().max(16 * 1024));
        let proxy = tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut tunnel, &mut upstream)
                .await
                .unwrap()
        });
        let started = std::time::Instant::now();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(echoed, *payload);
        drop(client);
        proxy.abort();
        server.abort();
        let _ = proxy.await;
        let _ = server.await;
        elapsed
    }

    async fn tls_sample(
        payload: Arc<Vec<u8>>,
        upstream_identity: BenchmarkIdentity,
        downstream_identity: BenchmarkIdentity,
    ) -> Duration {
        let upstream_server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![upstream_identity.certificate.clone()],
                PrivatePkcs8KeyDer::from(upstream_identity.private_key.clone()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(echo_server(
            listener,
            Some(Arc::new(upstream_server)),
            payload.len(),
        ));
        let upstream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (bridge_side, client_side) = tokio::io::duplex(payload.len().max(16 * 1024));
        let mut upstream_roots = RootCertStore::empty();
        upstream_roots
            .add(upstream_identity.certificate.clone())
            .unwrap();
        let leaf = IssuedLeaf {
            certificate_der: downstream_identity.certificate.to_vec(),
            private_key_der: zeroize::Zeroizing::new(downstream_identity.private_key.clone()),
            issuer_fingerprint_sha256: "benchmark-only".into(),
            host: "client.dev.test".into(),
            expires_at: u64::MAX,
        };
        let bridge = tokio::spawn(bridge_verified_tls(
            bridge_side,
            upstream,
            "upstream.dev.test",
            leaf,
            upstream_roots,
            Duration::from_secs(10),
            Duration::from_secs(60),
        ));
        let mut downstream_roots = RootCertStore::empty();
        downstream_roots
            .add(downstream_identity.certificate.clone())
            .unwrap();
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(downstream_roots)
                .with_no_client_auth(),
        ));
        let started = std::time::Instant::now();
        let mut client = connector
            .connect(
                ServerName::try_from("client.dev.test".to_string()).unwrap(),
                client_side,
            )
            .await
            .unwrap();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(echoed, *payload);
        drop(client);
        bridge.abort();
        server.abort();
        let _ = bridge.await;
        let _ = server.await;
        elapsed
    }

    async fn measure_mode<F, Fut>(config: BenchmarkConfig, sample: F) -> BenchmarkModeResult
    where
        F: Fn() -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Duration> + Send + 'static,
    {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use sysinfo::{get_current_pid, ProcessRefreshKind, ProcessesToUpdate, System};

        for _ in 0..2 {
            sample().await;
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let sampler_stopped = stopped.clone();
        let sampler_peak = peak.clone();
        let sampler = tokio::spawn(async move {
            let pid = get_current_pid().unwrap();
            let mut system = System::new();
            while !sampler_stopped.load(Ordering::Relaxed) {
                system.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[pid]),
                    true,
                    ProcessRefreshKind::nothing().with_memory(),
                );
                if let Some(process) = system.process(pid) {
                    sampler_peak.fetch_max(process.memory(), Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let wall_started = std::time::Instant::now();
        let mut durations = Vec::with_capacity(config.samples);
        let mut completed = 0;
        while completed < config.samples {
            let batch = (config.samples - completed).min(config.concurrency);
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..batch {
                let sample = sample.clone();
                tasks.spawn(sample());
            }
            while let Some(result) = tasks.join_next().await {
                durations.push(result.unwrap());
            }
            completed += batch;
        }
        let wall_time = wall_started.elapsed();
        stopped.store(true, Ordering::Relaxed);
        sampler.await.unwrap();
        BenchmarkModeResult {
            wall_time,
            samples: durations,
            peak_memory_bytes: peak.load(Ordering::Relaxed),
        }
    }

    fn percentile(samples: &[Duration], percentile: usize) -> f64 {
        let mut micros = samples
            .iter()
            .map(|sample| sample.as_secs_f64() * 1_000_000.0)
            .collect::<Vec<_>>();
        micros.sort_by(f64::total_cmp);
        let rank = (micros.len() * percentile).div_ceil(100);
        micros[rank.saturating_sub(1).min(micros.len() - 1)]
    }

    fn benchmark_report(
        config: BenchmarkConfig,
        result: &BenchmarkModeResult,
    ) -> serde_json::Value {
        let transferred = (config.payload_bytes as f64) * (config.samples as f64) * 2.0;
        serde_json::json!({
            "wallMs": result.wall_time.as_secs_f64() * 1000.0,
            "p50Micros": percentile(&result.samples, 50),
            "p95Micros": percentile(&result.samples, 95),
            "throughputMiBPerSecond": transferred / result.wall_time.as_secs_f64() / 1024.0 / 1024.0,
            "peakProcessMiB": result.peak_memory_bytes as f64 / 1024.0 / 1024.0,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "run explicitly with npm run benchmark:tls"]
    async fn tls_transport_benchmark() {
        let config = benchmark_config();
        let payload = Arc::new(vec![0x5a; config.payload_bytes]);
        let pass_payload = payload.clone();
        let pass_through = measure_mode(config, move || {
            let payload = pass_payload.clone();
            async move { pass_through_sample(payload).await }
        })
        .await;
        let upstream_identity = benchmark_identity("upstream.dev.test");
        let downstream_identity = benchmark_identity("client.dev.test");
        let tls = measure_mode(config, move || {
            let payload = payload.clone();
            let upstream = upstream_identity.clone();
            let downstream = downstream_identity.clone();
            async move { tls_sample(payload, upstream, downstream).await }
        })
        .await;
        let mut system = sysinfo::System::new_all();
        system.refresh_cpu_all();
        let report = serde_json::json!({
            "schemaVersion": 1,
            "hardware": {
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "logicalCpus": std::thread::available_parallelism().map(usize::from).unwrap_or(1),
                "cpu": system.cpus().first().map(|cpu| cpu.brand()).unwrap_or("unknown"),
                "totalMemoryMiB": system.total_memory() as f64 / 1024.0 / 1024.0,
            },
            "workload": {
                "payloadBytesEachDirection": config.payload_bytes,
                "samples": config.samples,
                "concurrency": config.concurrency,
                "tlsIncludesHandshake": true,
                "connectionTeardownIncluded": false,
            },
            "passThrough": benchmark_report(config, &pass_through),
            "verifiedTlsBridge": benchmark_report(config, &tls),
            "tlsP50OverheadPercent": (percentile(&tls.samples, 50) / percentile(&pass_through.samples, 50) - 1.0) * 100.0,
        });
        println!("SIPPIN_TLS_BENCHMARK={report}");
    }
}
