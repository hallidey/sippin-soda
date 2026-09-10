//! UI-independent network engine and development policies.
mod ca;
mod proxy;
pub use ca::*;
pub use proxy::*;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePhase {
    Stopped,
    Running,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub phase: EnginePhase,
    pub listen_address: SocketAddr,
    pub captures: usize,
    pub https_inspection: bool,
    pub production_protection: bool,
    pub evicted_captures: u64,
    pub rejected_connections: u64,
}

impl Default for EngineStatus {
    fn default() -> Self {
        Self {
            phase: EnginePhase::Stopped,
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            captures: 0,
            https_inspection: false,
            production_protection: true,
            evicted_captures: 0,
            rejected_connections: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Observe,
    InspectTls,
    Replay,
    Modify,
    InjectFault,
}

/// Destination classification is supplied by the future routing layer.
/// Unknown destinations fail closed for active operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationClass {
    Development,
    Production,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    ProductionReadOnly,
    DestinationUnclassified,
}

pub fn authorize(destination: DestinationClass, action: Action) -> Result<(), PolicyError> {
    if action == Action::Observe {
        return Ok(());
    }
    match destination {
        DestinationClass::Development => Ok(()),
        DestinationClass::Production => Err(PolicyError::ProductionReadOnly),
        DestinationClass::Unknown => Err(PolicyError::DestinationUnclassified),
    }
}

/// Preserve header names for inspection while removing credential values.
/// This is only the initial header policy, not full session redaction.
pub fn redact_header(name: &str, value: &str) -> String {
    if [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
    ]
    .iter()
    .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
    {
        "[REDACTED]".into()
    } else {
        value.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_and_unknown_destinations_reject_all_active_operations() {
        for action in [
            Action::InspectTls,
            Action::Replay,
            Action::Modify,
            Action::InjectFault,
        ] {
            assert_eq!(
                authorize(DestinationClass::Production, action),
                Err(PolicyError::ProductionReadOnly)
            );
            assert_eq!(
                authorize(DestinationClass::Unknown, action),
                Err(PolicyError::DestinationUnclassified)
            );
            assert_eq!(authorize(DestinationClass::Development, action), Ok(()));
        }
    }

    #[test]
    fn observation_does_not_require_active_operation_permission() {
        for destination in [
            DestinationClass::Production,
            DestinationClass::Development,
            DestinationClass::Unknown,
        ] {
            assert_eq!(authorize(destination, Action::Observe), Ok(()));
        }
    }

    #[test]
    fn credential_header_matching_is_case_insensitive() {
        for name in [
            "AUTHORIZATION",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Api-Key",
        ] {
            assert_eq!(redact_header(name, "secret"), "[REDACTED]");
        }
        assert_eq!(
            redact_header("Content-Type", "application/json"),
            "application/json"
        );
    }

    #[test]
    fn initial_status_never_claims_a_running_proxy() {
        let status = EngineStatus::default();
        assert!(status.listen_address.ip().is_loopback());
        assert_eq!(status.phase, EnginePhase::Stopped);
        assert!(!status.https_inspection);
        assert!(status.production_protection);
        assert_eq!(status.captures, 0);
    }
}
