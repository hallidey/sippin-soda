use crate::{authorize, Action, DestinationClass};
use keyring::{Entry, Error as KeyringError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SERVICE: &str = "io.sippin-soda.desktop";
const ACCOUNT: &str = "local-ca-v1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaStatus {
    pub state: String,
    pub fingerprint_sha256: Option<String>,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub installed_by_app: bool,
    pub https_inspection: bool,
}

impl CaStatus {
    fn absent() -> Self {
        Self {
            state: "absent".into(),
            fingerprint_sha256: None,
            created_at: None,
            expires_at: None,
            installed_by_app: false,
            https_inspection: false,
        }
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredCa {
    certificate_pem: String,
    private_key_pem: String,
    fingerprint_sha256: String,
    created_at: u64,
    expires_at: u64,
}

pub struct IssuedLeaf {
    pub certificate_der: Vec<u8>,
    // Consumed only by the engine's TLS terminator; never exposed through IPC.
    pub(crate) private_key_der: Zeroizing<Vec<u8>>,
    pub(crate) issuer_fingerprint_sha256: String,
    pub host: String,
    pub expires_at: u64,
}

pub struct CaManager {
    lifecycle: Mutex<()>,
}

impl Default for CaManager {
    fn default() -> Self {
        Self {
            lifecycle: Mutex::new(()),
        }
    }
}

impl CaManager {
    #[cfg(test)]
    pub(crate) fn ephemeral_leaf_for_test(host: &str) -> (String, IssuedLeaf, CaStatus) {
        let ca = generate_ca().unwrap();
        let certificate = ca.certificate_pem.clone();
        let leaf = issue_leaf_from_ca(&ca, host, DestinationClass::Development).unwrap();
        let status = status_from(&ca);
        (certificate, leaf, status)
    }

    fn entry(&self) -> Result<Entry, String> {
        Entry::new(SERVICE, ACCOUNT)
            .map_err(|_| "The operating-system credential store is unavailable.".into())
    }

    fn load(&self) -> Result<Option<StoredCa>, String> {
        let entry = self.entry()?;
        let secret = match entry.get_secret() {
            Ok(secret) => Zeroizing::new(secret),
            Err(KeyringError::NoEntry) => return Ok(None),
            Err(_) => return Err("Cannot read the local CA from the credential store.".into()),
        };
        serde_json::from_slice(&secret)
            .map(Some)
            .map_err(|_| "The stored local CA is invalid; remove and regenerate it.".into())
    }

    pub fn status(&self) -> Result<CaStatus, String> {
        let _guard = self
            .lifecycle
            .lock()
            .map_err(|_| "Local CA lifecycle lock failed.")?;
        let Some(ca) = self.load()? else {
            return Ok(CaStatus::absent());
        };
        Ok(status_from(&ca))
    }

    pub fn generate(&self, consent: bool) -> Result<CaStatus, String> {
        if !consent {
            return Err("Explicit consent is required before generating a local CA.".into());
        }
        let _guard = self
            .lifecycle
            .lock()
            .map_err(|_| "Local CA lifecycle lock failed.")?;
        if self.load()?.is_some() {
            return Err(
                "A local CA already exists. Remove it before generating a replacement.".into(),
            );
        }
        let ca = generate_ca()?;
        let serialized = Zeroizing::new(
            serde_json::to_vec(&ca).map_err(|_| "Cannot prepare the CA for secure storage.")?,
        );
        self.entry()?
            .set_secret(&serialized)
            .map_err(|_| "Cannot save the local CA in the credential store.")?;
        Ok(status_from(&ca))
    }

    pub fn certificate_pem(&self) -> Result<Vec<u8>, String> {
        let _guard = self
            .lifecycle
            .lock()
            .map_err(|_| "Local CA lifecycle lock failed.")?;
        self.load()?
            .map(|ca| ca.certificate_pem.as_bytes().to_vec())
            .ok_or_else(|| "Generate the local CA before exporting its certificate.".into())
    }

    pub fn remove(&self, confirmed: bool) -> Result<CaStatus, String> {
        if !confirmed {
            return Err(
                "Explicit confirmation is required before removing local CA material.".into(),
            );
        }
        let _guard = self
            .lifecycle
            .lock()
            .map_err(|_| "Local CA lifecycle lock failed.")?;
        match self.entry()?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(CaStatus::absent()),
            Err(_) => Err("Cannot remove the local CA from the credential store.".into()),
        }
    }

    pub fn issue_leaf(
        &self,
        host: &str,
        destination: DestinationClass,
    ) -> Result<IssuedLeaf, String> {
        authorize(destination, Action::InspectTls)
            .map_err(|_| "TLS certificates can be issued only for Development destinations.")?;
        let _guard = self
            .lifecycle
            .lock()
            .map_err(|_| "Local CA lifecycle lock failed.")?;
        let ca = self
            .load()?
            .ok_or("Generate the local CA before issuing a host certificate.")?;
        issue_leaf_from_ca(&ca, host, destination)
    }
}

fn status_from(ca: &StoredCa) -> CaStatus {
    CaStatus {
        state: "ready".into(),
        fingerprint_sha256: Some(ca.fingerprint_sha256.clone()),
        created_at: Some(ca.created_at),
        expires_at: Some(ca.expires_at),
        installed_by_app: false,
        https_inspection: false,
    }
}

fn generate_ca() -> Result<StoredCa, String> {
    let now = OffsetDateTime::now_utc();
    let expires = now + Duration::days(5 * 365);
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|_| "Cannot initialize local CA parameters.")?;
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Sippin Soda local development");
    name.push(DnType::CommonName, "Sippin Soda Local Development CA");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = now - Duration::minutes(5);
    params.not_after = expires;
    let key = KeyPair::generate().map_err(|_| "Cannot generate the local CA key.")?;
    let certificate = params
        .self_signed(&key)
        .map_err(|_| "Cannot self-sign the local CA certificate.")?;
    let fingerprint = Sha256::digest(certificate.der())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Ok(StoredCa {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
        fingerprint_sha256: fingerprint,
        created_at,
        expires_at: (expires.unix_timestamp() as u64) * 1000,
    })
}

fn issue_leaf_from_ca(
    ca: &StoredCa,
    host: &str,
    destination: DestinationClass,
) -> Result<IssuedLeaf, String> {
    authorize(destination, Action::InspectTls)
        .map_err(|_| "TLS certificates can be issued only for Development destinations.")?;
    let host = normalize_leaf_host(host)?;
    let ca_key = KeyPair::from_pem(&ca.private_key_pem)
        .map_err(|_| "The stored local CA private key is invalid.")?;
    let issuer = Issuer::from_ca_cert_pem(&ca.certificate_pem, ca_key)
        .map_err(|_| "The stored local CA certificate is invalid.")?;
    let now = OffsetDateTime::now_utc();
    let ca_expiry = OffsetDateTime::from_unix_timestamp((ca.expires_at / 1000) as i64)
        .map_err(|_| "The stored local CA expiry is invalid.")?;
    let expires = std::cmp::min(now + Duration::hours(24), ca_expiry);
    if expires <= now {
        return Err("The local CA has expired; remove and regenerate it.".into());
    }
    let mut params = CertificateParams::new(vec![host.clone()])
        .map_err(|_| "Cannot initialize host certificate parameters.")?;
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Sippin Soda local development");
    name.push(DnType::CommonName, host.clone());
    params.distinguished_name = name;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = now - Duration::minutes(5);
    params.not_after = expires;
    let leaf_key = KeyPair::generate().map_err(|_| "Cannot generate the host private key.")?;
    let certificate = params
        .signed_by(&leaf_key, &issuer)
        .map_err(|_| "Cannot sign the host certificate with the local CA.")?;
    Ok(IssuedLeaf {
        certificate_der: certificate.der().to_vec(),
        private_key_der: Zeroizing::new(leaf_key.serialize_der()),
        issuer_fingerprint_sha256: ca.fingerprint_sha256.clone(),
        host,
        expires_at: (expires.unix_timestamp() as u64) * 1000,
    })
}

fn normalize_leaf_host(host: &str) -> Result<String, String> {
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let valid_name = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || (host.parse::<std::net::IpAddr>().is_err() && !valid_name)
    {
        return Err(
            "Host certificates require a valid DNS name or IP address without a port.".into(),
        );
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::{generate_ca, issue_leaf_from_ca, CaManager, IssuedLeaf, StoredCa};
    use crate::DestinationClass;
    use std::{io::Cursor, sync::Arc};
    use tokio::{net::TcpListener, time::timeout};
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
            ClientConfig, RootCertStore, ServerConfig,
        },
        TlsAcceptor, TlsConnector,
    };

    #[test]
    fn generated_ca_has_public_certificate_private_key_and_stable_metadata() {
        let ca = generate_ca().unwrap();
        assert!(ca
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca.private_key_pem.contains("PRIVATE KEY"));
        assert_eq!(ca.fingerprint_sha256.split(':').count(), 32);
        assert!(ca.expires_at > ca.created_at);
    }

    #[test]
    fn lifecycle_mutations_require_explicit_confirmation_before_storage_access() {
        let manager = CaManager::default();
        assert!(manager.generate(false).is_err());
        assert!(manager.remove(false).is_err());
    }

    #[test]
    fn leaf_issuance_is_development_only_and_host_scoped() {
        let ca = generate_ca().unwrap();
        let leaf = issue_leaf_from_ca(&ca, "API.Dev.Test.", DestinationClass::Development).unwrap();
        assert_eq!(leaf.host, "api.dev.test");
        assert!(!leaf.certificate_der.is_empty());
        assert!(!leaf.private_key_der.is_empty());
        assert!(leaf.expires_at > ca.created_at);
        assert!(issue_leaf_from_ca(&ca, "api.test", DestinationClass::Production).is_err());
        assert!(issue_leaf_from_ca(&ca, "api.test", DestinationClass::Unknown).is_err());
        assert!(
            issue_leaf_from_ca(&ca, "https://api.test", DestinationClass::Development).is_err()
        );
        assert!(issue_leaf_from_ca(&ca, "*.dev.test", DestinationClass::Development).is_err());
    }

    async fn tls_handshake_succeeds(ca: &StoredCa, leaf: IssuedLeaf, server_name: &str) -> bool {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.certificate_der)],
                PrivatePkcs8KeyDer::from(leaf.private_key_der.to_vec()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
        });

        let mut roots = RootCertStore::empty();
        let ca_der = rustls_pemfile::certs(&mut Cursor::new(ca.certificate_pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        roots.add(ca_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let name = ServerName::try_from(server_name.to_owned()).unwrap();
        let client_result = timeout(
            std::time::Duration::from_secs(2),
            TlsConnector::from(Arc::new(client_config)).connect(name, stream),
        )
        .await;
        let _ = server.await;
        matches!(client_result, Ok(Ok(_)))
    }

    #[tokio::test]
    async fn issued_leaf_is_trusted_only_for_its_subject_alt_name() {
        let ca = generate_ca().unwrap();
        let matching =
            issue_leaf_from_ca(&ca, "api.dev.test", DestinationClass::Development).unwrap();
        assert!(tls_handshake_succeeds(&ca, matching, "api.dev.test").await);

        let mismatching =
            issue_leaf_from_ca(&ca, "api.dev.test", DestinationClass::Development).unwrap();
        assert!(!tls_handshake_succeeds(&ca, mismatching, "other.dev.test").await);
    }
}
