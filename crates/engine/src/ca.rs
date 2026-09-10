use keyring::{Entry, Error as KeyringError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
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

#[cfg(test)]
mod tests {
    use super::{generate_ca, CaManager};

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
}
