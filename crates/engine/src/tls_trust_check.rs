use crate::{
    CaStatus, EnginePhase, EngineStatus, IssuedLeaf, TlsClientIdentity, TlsInspectionGate,
    TlsInspectionReadiness, TlsReadinessState, TlsTrustError,
};
use serde::Serialize;
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time::timeout};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsTrustCheckState {
    Idle,
    Waiting,
    Verified,
    Failed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsTrustCheckStatus {
    pub state: TlsTrustCheckState,
    pub client: Option<TlsClientIdentity>,
    pub url: Option<String>,
    pub expires_at: Option<u64>,
    pub verified_at: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsInspectionPreflightState {
    ProxyStopped,
    ClientAuthenticationRequired,
    Disabled,
    MissingCa,
    ExpiredCa,
    ClientTrustUnverified,
    ClientMismatch,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInspectionPreflight {
    pub state: TlsInspectionPreflightState,
    pub can_enable_development: bool,
    pub https_inspection_active: bool,
    pub client_profile_id: Option<String>,
    pub verified_client: Option<TlsClientIdentity>,
    pub proof_expires_at: Option<u64>,
}

impl TlsTrustCheckStatus {
    fn idle() -> Self {
        Self {
            state: TlsTrustCheckState::Idle,
            client: None,
            url: None,
            expires_at: None,
            verified_at: None,
            error: None,
        }
    }
}

struct RunningCheck(JoinHandle<()>);

pub struct TlsTrustCheckManager {
    status: Arc<Mutex<TlsTrustCheckStatus>>,
    gate: Arc<Mutex<Option<TlsInspectionGate>>>,
    running: tokio::sync::Mutex<Option<RunningCheck>>,
}

impl Default for TlsTrustCheckManager {
    fn default() -> Self {
        Self {
            status: Arc::new(Mutex::new(TlsTrustCheckStatus::idle())),
            gate: Arc::new(Mutex::new(None)),
            running: tokio::sync::Mutex::new(None),
        }
    }
}

impl TlsTrustCheckManager {
    pub fn status(&self) -> TlsTrustCheckStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn readiness(&self, ca: &CaStatus, client_id: &str) -> Option<TlsInspectionReadiness> {
        self.gate
            .lock()
            .unwrap()
            .as_ref()
            .map(|gate| gate.readiness(ca, client_id))
    }

    pub fn preflight(&self, ca: &CaStatus, proxy: &EngineStatus) -> TlsInspectionPreflight {
        if proxy.phase != EnginePhase::Running {
            return TlsInspectionPreflight::blocked(
                TlsInspectionPreflightState::ProxyStopped,
                None,
            );
        }
        let Some(client_id) = proxy.client_profile_id.as_deref() else {
            return TlsInspectionPreflight::blocked(
                TlsInspectionPreflightState::ClientAuthenticationRequired,
                None,
            );
        };
        if ca.state != "ready" || ca.fingerprint_sha256.is_none() || ca.expires_at.is_none() {
            return TlsInspectionPreflight::blocked(
                TlsInspectionPreflightState::MissingCa,
                Some(client_id),
            );
        }
        if ca
            .expires_at
            .is_some_and(|expires| expires <= unix_millis())
        {
            return TlsInspectionPreflight::blocked(
                TlsInspectionPreflightState::ExpiredCa,
                Some(client_id),
            );
        }
        let Some(readiness) = self.readiness(ca, client_id) else {
            return TlsInspectionPreflight::blocked(
                TlsInspectionPreflightState::ClientTrustUnverified,
                Some(client_id),
            );
        };
        let state = match readiness.state {
            TlsReadinessState::Disabled => TlsInspectionPreflightState::Disabled,
            TlsReadinessState::MissingCa => TlsInspectionPreflightState::MissingCa,
            TlsReadinessState::ExpiredCa => TlsInspectionPreflightState::ExpiredCa,
            TlsReadinessState::ClientTrustUnverified => {
                TlsInspectionPreflightState::ClientTrustUnverified
            }
            TlsReadinessState::ClientMismatch => TlsInspectionPreflightState::ClientMismatch,
            TlsReadinessState::Ready => TlsInspectionPreflightState::Ready,
        };
        TlsInspectionPreflight {
            state,
            can_enable_development: state == TlsInspectionPreflightState::Ready,
            https_inspection_active: proxy.https_inspection
                && state == TlsInspectionPreflightState::Ready,
            client_profile_id: Some(client_id.into()),
            verified_client: readiness.verified_client,
            proof_expires_at: readiness.proof_expires_at,
        }
    }

    pub async fn start(
        &self,
        leaf: IssuedLeaf,
        client: TlsClientIdentity,
        valid_for: Duration,
    ) -> Result<TlsTrustCheckStatus, String> {
        if !(Duration::from_secs(5)..=Duration::from_secs(120)).contains(&valid_for) {
            return Err("TLS trust checks must last between 5 and 120 seconds.".into());
        }
        self.cancel_running().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| "Cannot open the local TLS trust-check endpoint.")?;
        let address = listener
            .local_addr()
            .map_err(|_| "Cannot read the local TLS trust-check address.")?;
        let expires_at = unix_millis().saturating_add(valid_for.as_millis() as u64);
        let waiting = TlsTrustCheckStatus {
            state: TlsTrustCheckState::Waiting,
            client: Some(client.clone()),
            url: Some(format!("https://localhost:{}/", address.port())),
            expires_at: Some(expires_at),
            verified_at: None,
            error: None,
        };
        *self.status.lock().unwrap() = waiting.clone();
        *self.gate.lock().unwrap() = None;

        let status = self.status.clone();
        let gate_store = self.gate.clone();
        let proof_expires_at = leaf.expires_at;
        let task = tokio::spawn(async move {
            let outcome = run_check(listener, leaf, client.clone(), valid_for).await;
            let next = match outcome {
                Ok(gate) => {
                    *gate_store.lock().unwrap() = Some(gate);
                    TlsTrustCheckStatus {
                        state: TlsTrustCheckState::Verified,
                        client: Some(client.clone()),
                        url: None,
                        expires_at: Some(proof_expires_at),
                        verified_at: Some(unix_millis()),
                        error: None,
                    }
                }
                Err(CheckFailure::Expired) => TlsTrustCheckStatus {
                    state: TlsTrustCheckState::Expired,
                    client: Some(client.clone()),
                    url: None,
                    expires_at: None,
                    verified_at: None,
                    error: Some("The local trust check expired before it completed.".into()),
                },
                Err(CheckFailure::Rejected) => TlsTrustCheckStatus {
                    state: TlsTrustCheckState::Failed,
                    client: Some(client),
                    url: None,
                    expires_at: None,
                    verified_at: None,
                    error: Some(
                        "The client rejected the local CA certificate. Configure trust for that client, then retry."
                            .into(),
                    ),
                },
            };
            *status.lock().unwrap() = next;
        });
        *self.running.lock().await = Some(RunningCheck(task));
        Ok(waiting)
    }

    pub async fn cancel(&self) -> TlsTrustCheckStatus {
        self.cancel_running().await;
        *self.gate.lock().unwrap() = None;
        let idle = TlsTrustCheckStatus::idle();
        *self.status.lock().unwrap() = idle.clone();
        idle
    }

    async fn cancel_running(&self) {
        if let Some(running) = self.running.lock().await.take() {
            running.0.abort();
            let _ = running.0.await;
        }
    }
}

impl TlsInspectionPreflight {
    fn blocked(state: TlsInspectionPreflightState, client_id: Option<&str>) -> Self {
        Self {
            state,
            can_enable_development: false,
            https_inspection_active: false,
            client_profile_id: client_id.map(String::from),
            verified_client: None,
            proof_expires_at: None,
        }
    }
}

enum CheckFailure {
    Expired,
    Rejected,
}

async fn run_check(
    listener: TcpListener,
    leaf: IssuedLeaf,
    client: TlsClientIdentity,
    valid_for: Duration,
) -> Result<TlsInspectionGate, CheckFailure> {
    let (socket, _) = timeout(valid_for, listener.accept())
        .await
        .map_err(|_| CheckFailure::Expired)?
        .map_err(|_| CheckFailure::Rejected)?;
    let mut gate = TlsInspectionGate::default();
    gate.set_opt_in(true);
    let mut tls = gate
        .verify_client_trust(socket, leaf, client, Duration::from_secs(10))
        .await
        .map_err(|error| match error {
            TlsTrustError::HandshakeTimeout => CheckFailure::Expired,
            _ => CheckFailure::Rejected,
        })?;
    const BODY: &[u8] = b"Sippin Soda verified that this client trusts the local development CA. HTTPS inspection is still disabled.\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        BODY.len()
    );
    tls.write_all(headers.as_bytes())
        .await
        .map_err(|_| CheckFailure::Rejected)?;
    tls.write_all(BODY)
        .await
        .map_err(|_| CheckFailure::Rejected)?;
    tls.flush().await.map_err(|_| CheckFailure::Rejected)?;
    tls.shutdown().await.map_err(|_| CheckFailure::Rejected)?;
    Ok(gate)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CaManager;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{
        rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
        TlsConnector,
    };

    fn port(status: &TlsTrustCheckStatus) -> u16 {
        status
            .url
            .as_deref()
            .unwrap()
            .trim_start_matches("https://localhost:")
            .trim_end_matches('/')
            .parse()
            .unwrap()
    }

    fn client() -> TlsClientIdentity {
        TlsClientIdentity::new("browser-1", "Development browser").unwrap()
    }

    #[tokio::test]
    async fn verifies_one_trusted_client_and_returns_a_local_confirmation() {
        let (ca_pem, leaf, ca_status) = CaManager::ephemeral_leaf_for_test("localhost");
        let manager = TlsTrustCheckManager::default();
        let identity = client();
        let waiting = manager
            .start(leaf, identity.clone(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(waiting.state, TlsTrustCheckState::Waiting);
        assert_eq!(waiting.client.as_ref(), Some(&identity));
        assert_eq!(
            manager
                .preflight(&ca_status, &EngineStatus::default())
                .state,
            TlsInspectionPreflightState::ProxyStopped
        );
        let socket = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port(&waiting)))
            .await
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(
                rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem.as_bytes()))
                    .next()
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        tokio::task::yield_now().await;
        assert_eq!(manager.status().state, TlsTrustCheckState::Verified);
        assert!(manager
            .readiness(&ca_status, identity.id())
            .is_some_and(|readiness| readiness.can_inspect_development));
        assert!(manager
            .readiness(&ca_status, "other-client")
            .is_some_and(|readiness| !readiness.can_inspect_development));
        let mut proxy = EngineStatus {
            phase: EnginePhase::Running,
            ..Default::default()
        };
        assert_eq!(
            manager.preflight(&ca_status, &proxy).state,
            TlsInspectionPreflightState::ClientAuthenticationRequired
        );
        proxy.client_profile_id = Some("other-client".into());
        assert_eq!(
            manager.preflight(&ca_status, &proxy).state,
            TlsInspectionPreflightState::ClientMismatch
        );
        proxy.client_profile_id = Some(identity.id().into());
        let mut missing_ca = ca_status.clone();
        missing_ca.state = "absent".into();
        assert_eq!(
            manager.preflight(&missing_ca, &proxy).state,
            TlsInspectionPreflightState::MissingCa
        );
        let mut expired_ca = ca_status.clone();
        expired_ca.expires_at = Some(1);
        assert_eq!(
            manager.preflight(&expired_ca, &proxy).state,
            TlsInspectionPreflightState::ExpiredCa
        );
        let preflight = manager.preflight(&ca_status, &proxy);
        assert_eq!(preflight.state, TlsInspectionPreflightState::Ready);
        assert!(preflight.can_enable_development);
        assert!(!preflight.https_inspection_active);
        assert_eq!(preflight.verified_client.as_ref(), Some(&identity));
        proxy.https_inspection = true;
        assert!(
            manager
                .preflight(&ca_status, &proxy)
                .https_inspection_active
        );
        assert!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port(&waiting)))
                .await
                .is_err()
        );
        manager.cancel().await;
    }

    #[tokio::test]
    async fn rejected_client_closes_the_check_without_readiness() {
        let (_, leaf, ca_status) = CaManager::ephemeral_leaf_for_test("localhost");
        let manager = TlsTrustCheckManager::default();
        let identity = client();
        let waiting = manager
            .start(leaf, identity.clone(), Duration::from_secs(5))
            .await
            .unwrap();
        let socket = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port(&waiting)))
            .await
            .unwrap();
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        ));
        assert!(connector
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .is_err());
        timeout(Duration::from_secs(1), async {
            while manager.status().state == TlsTrustCheckState::Waiting {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let status = manager.status();
        assert_eq!(status.state, TlsTrustCheckState::Failed);
        assert!(status.url.is_none());
        assert!(manager.readiness(&ca_status, identity.id()).is_none());
        manager.cancel().await;
    }

    #[tokio::test]
    async fn cancellation_and_timeout_clear_readiness() {
        let (_, leaf, ca_status) = CaManager::ephemeral_leaf_for_test("localhost");
        let manager = TlsTrustCheckManager::default();
        let identity = client();
        manager
            .start(leaf, identity.clone(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(manager.cancel().await.state, TlsTrustCheckState::Idle);
        assert!(manager.readiness(&ca_status, identity.id()).is_none());

        let (_, leaf, _) = CaManager::ephemeral_leaf_for_test("localhost");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        assert!(matches!(
            run_check(listener, leaf, client(), Duration::from_millis(10)).await,
            Err(CheckFailure::Expired)
        ));
    }
}
