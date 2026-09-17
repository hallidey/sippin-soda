#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use sippin_soda_engine::{
    BodyExportPreview, BodyPage, CaManager, CaStatus, DestinationClass, EnginePhase, JsonStatus,
    ProxyClientAuth, ProxyConfig, ProxyEngine, ProxyTlsInterception, ResponseRuleConfig,
    SearchStep, Snapshot, TlsClientIdentity, TlsInspectionPreflight, TlsTrustCheckManager,
    TlsTrustCheckStatus,
};
use std::{sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BodyExportResult {
    path: String,
    bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartProxyOptions {
    port: u16,
    capture_bodies: bool,
    disk_budget_gib: u32,
    request_redaction_paths: Vec<String>,
    development_hosts: Vec<String>,
    production_hosts: Vec<String>,
    client_profile_id: Option<String>,
    client_token: Option<String>,
    enable_https_inspection: bool,
    break_on_responses: bool,
    #[serde(default)]
    response_rules: Vec<ResponseRuleConfig>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionCheckResult {
    proxy_address: String,
    http_status: u16,
}

async fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut head = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "The local connection check could not read HTTP data.".to_string())?;
        if read == 0 {
            return Err("The local connection check ended before HTTP headers arrived.".into());
        }
        head.extend_from_slice(&buffer[..read]);
        if head.len() > 16 * 1024 {
            return Err("The local connection check received oversized HTTP headers.".into());
        }
    }
    Ok(head)
}

fn response_status(head: &[u8]) -> Result<u16, String> {
    let first_line = head
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or("The proxy returned an invalid HTTP response.")?;
    let first_line = std::str::from_utf8(first_line)
        .map_err(|_| "The proxy returned a non-UTF-8 HTTP status line.")?;
    first_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| "The proxy returned an invalid HTTP status line.".into())
}

async fn run_proxy_connection_check(
    engine: &ProxyEngine,
    client_profile_id: Option<String>,
    client_token: Option<String>,
) -> Result<ConnectionCheckResult, String> {
    let snapshot = engine.snapshot();
    if snapshot.status.phase != EnginePhase::Running {
        return Err("Start the proxy before running the connection check.".into());
    }
    match (
        snapshot.status.client_profile_id.as_deref(),
        client_profile_id.as_deref(),
        client_token.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(expected), Some(profile), Some(token))
            if expected == profile && !token.is_empty() => {}
        (Some(_), _, _) => {
            return Err(
                "The current proxy authentication password is unavailable. Restart the proxy and try again."
                    .into(),
            )
        }
        (None, _, _) => {
            return Err("This proxy run does not use client authentication.".into())
        }
    }

    let origin = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "The connection check could not reserve a local test endpoint.")?;
    let origin_address = origin
        .local_addr()
        .map_err(|_| "The connection check could not read its local endpoint.")?;
    let origin_task = tauri::async_runtime::spawn(async move {
        let (mut connection, _) = timeout(Duration::from_secs(20), origin.accept())
            .await
            .map_err(|_| "The proxy did not reach the local test endpoint in time.".to_string())?
            .map_err(|_| {
                "The local test endpoint could not accept the proxy connection.".to_string()
            })?;
        let request = read_http_head(&mut connection).await?;
        let expected = b"GET /__sippin_connection_check HTTP/1.1";
        if !request.starts_with(expected) {
            return Err("The local test endpoint received an unexpected request.".into());
        }
        connection
            .write_all(
                b"HTTP/1.1 204 No Content\r\nX-Sippin-Soda-Diagnostic: ok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .map_err(|_| "The local test endpoint could not return its response.".to_string())?;
        Ok::<(), String>(())
    });

    let proxy_address = snapshot.status.listen_address;
    let check = timeout(Duration::from_secs(20), async {
        let mut connection = TcpStream::connect(proxy_address)
            .await
            .map_err(|_| "The desktop process could not connect to the running proxy.".to_string())?;
        let authorization = match (client_profile_id, client_token) {
            (Some(profile), Some(token)) => format!(
                "Proxy-Authorization: Basic {}\r\n",
                BASE64_STANDARD.encode(format!("{profile}:{token}"))
            ),
            _ => String::new(),
        };
        let request = format!(
            "GET http://{origin_address}/__sippin_connection_check HTTP/1.1\r\nHost: {origin_address}\r\n{authorization}Connection: close\r\n\r\n"
        );
        connection
            .write_all(request.as_bytes())
            .await
            .map_err(|_| "The desktop process could not send the proxy test request.".to_string())?;
        let response = read_http_head(&mut connection).await?;
        response_status(&response)
    })
    .await
    .map_err(|_| "The proxy connection check timed out.".to_string())?;

    let http_status = match check {
        Ok(status) => status,
        Err(error) => {
            origin_task.abort();
            return Err(error);
        }
    };
    origin_task
        .await
        .map_err(|_| "The local test endpoint stopped unexpectedly.".to_string())??;
    if http_status == 407 {
        return Err("The proxy rejected the temporary client credentials.".into());
    }
    Ok(ConnectionCheckResult {
        proxy_address: proxy_address.to_string(),
        http_status,
    })
}

#[tauri::command]
async fn test_proxy_connection(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    client_profile_id: Option<String>,
    client_token: Option<String>,
) -> Result<ConnectionCheckResult, String> {
    run_proxy_connection_check(engine.inner(), client_profile_id, client_token).await
}

#[tauri::command]
fn engine_snapshot(engine: tauri::State<'_, Arc<ProxyEngine>>) -> Snapshot {
    engine.snapshot()
}

#[tauri::command]
async fn start_proxy(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    ca: tauri::State<'_, Arc<CaManager>>,
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
    options: StartProxyOptions,
) -> Result<Snapshot, String> {
    if !(1..=1024).contains(&options.disk_budget_gib) {
        return Err("Disk budget must be between 1 and 1024 GiB.".into());
    }
    let client_auth = match (options.client_profile_id, options.client_token) {
        (None, None) => None,
        (Some(profile_id), Some(token)) => Some(ProxyClientAuth::new(&profile_id, &token)?),
        _ => return Err("Proxy client profile and token must be configured together.".into()),
    };
    let tls_interception = if options.enable_https_inspection {
        let profile_id = client_auth
            .as_ref()
            .map(ProxyClientAuth::profile_id)
            .ok_or("HTTPS inspection requires client profile authentication.")?;
        let ca_worker = ca.inner().clone();
        let ca_status = tauri::async_runtime::spawn_blocking(move || ca_worker.status())
            .await
            .map_err(|_| "HTTPS inspection CA worker failed.".to_string())??;
        if !trust_check
            .readiness(&ca_status, profile_id)
            .is_some_and(|readiness| readiness.can_inspect_development)
        {
            return Err(
                "Verify CA trust with this client profile before enabling HTTPS inspection.".into(),
            );
        }
        Some(ProxyTlsInterception::platform(
            ca.inner().clone(),
            trust_check.inner().clone(),
            profile_id,
        )?)
    } else {
        None
    };
    engine
        .start(ProxyConfig {
            port: options.port,
            capture_bodies: options.capture_bodies,
            body_disk_budget: u64::from(options.disk_budget_gib) * 1024 * 1024 * 1024,
            request_redaction_paths: options.request_redaction_paths,
            development_hosts: options.development_hosts,
            production_hosts: options.production_hosts,
            client_auth,
            tls_interception,
            break_on_responses: options.break_on_responses,
            response_rules: options.response_rules,
            ..Default::default()
        })
        .await
}

#[tauri::command]
fn resolve_response_breakpoint(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    status: Option<u16>,
    body: Option<String>,
    content_type: Option<String>,
) -> Result<Snapshot, String> {
    engine.resolve_response_breakpoint(id, status, body, content_type)
}

#[tauri::command]
async fn response_body_page(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    offset: u64,
    length: usize,
) -> Result<BodyPage, String> {
    engine.response_body_page(id, offset, length).await
}

#[tauri::command]
async fn request_body_page(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    offset: u64,
    length: usize,
) -> Result<BodyPage, String> {
    engine.request_body_page(id, offset, length).await
}

#[tauri::command]
async fn search_request_body(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    needle: String,
    start: u64,
    end: u64,
) -> Result<SearchStep, String> {
    engine.search_request_body(id, needle, start, end).await
}

#[tauri::command]
async fn request_json_view(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    start: bool,
    cancel: bool,
) -> Result<JsonStatus, String> {
    engine.request_json_view(id, start, cancel)
}

#[tauri::command]
async fn request_json_page(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    offset: u64,
    length: usize,
) -> Result<BodyPage, String> {
    engine.request_json_page(id, offset, length).await
}

#[tauri::command]
async fn search_response_body(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    needle: String,
    start: u64,
    end: u64,
) -> Result<SearchStep, String> {
    engine.search_response_body(id, needle, start, end).await
}

#[tauri::command]
async fn response_json_view(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    start: bool,
    cancel: bool,
) -> Result<JsonStatus, String> {
    engine.response_json_view(id, start, cancel)
}

#[tauri::command]
async fn response_json_page(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    offset: u64,
    length: usize,
) -> Result<BodyPage, String> {
    engine.response_json_page(id, offset, length).await
}

#[tauri::command]
async fn stop_proxy(engine: tauri::State<'_, Arc<ProxyEngine>>) -> Result<Snapshot, String> {
    Ok(engine.stop().await)
}

#[tauri::command]
fn clear_traffic(engine: tauri::State<'_, Arc<ProxyEngine>>) -> Snapshot {
    engine.clear()
}

#[tauri::command]
async fn replay_capture(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
) -> Result<Snapshot, String> {
    engine.replay(id).await
}

#[tauri::command]
fn body_export_preview(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    direction: String,
) -> Result<BodyExportPreview, String> {
    engine.body_export_preview(id, &direction)
}

#[tauri::command]
async fn export_body(
    app: tauri::AppHandle,
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    id: u64,
    direction: String,
    acknowledge_unredacted: bool,
) -> Result<Option<BodyExportResult>, String> {
    let preview = engine.body_export_preview(id, &direction)?;
    if !preview.redacted && !acknowledge_unredacted {
        return Err("Confirm that the unredacted response was reviewed before exporting.".into());
    }
    let selected = app
        .dialog()
        .file()
        .set_title("Export captured body")
        .set_file_name(&preview.suggested_file_name)
        .add_filter("Body files", &["bin", "json", "txt"])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let destination = selected
        .into_path()
        .map_err(|_| "The selected destination is not a local filesystem path.")?;
    let bytes = engine
        .export_body(id, &direction, destination.clone())
        .await?;
    Ok(Some(BodyExportResult {
        path: destination.to_string_lossy().into_owned(),
        bytes,
    }))
}

#[tauri::command]
async fn ca_status(ca: tauri::State<'_, Arc<CaManager>>) -> Result<CaStatus, String> {
    let ca = ca.inner().clone();
    tauri::async_runtime::spawn_blocking(move || ca.status())
        .await
        .map_err(|_| "Local CA status worker failed.".to_string())?
}

#[tauri::command]
async fn generate_local_ca(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    ca: tauri::State<'_, Arc<CaManager>>,
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
    consent: bool,
) -> Result<CaStatus, String> {
    engine.stop().await;
    trust_check.cancel().await;
    let ca = ca.inner().clone();
    tauri::async_runtime::spawn_blocking(move || ca.generate(consent))
        .await
        .map_err(|_| "Local CA generation worker failed.".to_string())?
}

#[tauri::command]
async fn remove_local_ca(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    ca: tauri::State<'_, Arc<CaManager>>,
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
    confirmed: bool,
) -> Result<CaStatus, String> {
    engine.stop().await;
    trust_check.cancel().await;
    let ca = ca.inner().clone();
    tauri::async_runtime::spawn_blocking(move || ca.remove(confirmed))
        .await
        .map_err(|_| "Local CA removal worker failed.".to_string())?
}

#[tauri::command]
async fn export_local_ca(
    app: tauri::AppHandle,
    ca: tauri::State<'_, Arc<CaManager>>,
) -> Result<Option<String>, String> {
    let ca = ca.inner().clone();
    let certificate = tauri::async_runtime::spawn_blocking(move || ca.certificate_pem())
        .await
        .map_err(|_| "Local CA export worker failed.".to_string())??;
    let selected = app
        .dialog()
        .file()
        .set_title("Export Sippin Soda public CA certificate")
        .set_file_name("sippin-soda-local-ca.pem")
        .add_filter("PEM certificate", &["pem", "crt"])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let destination = selected
        .into_path()
        .map_err(|_| "The selected destination is not a local filesystem path.")?;
    std::fs::write(&destination, certificate)
        .map_err(|_| "Cannot write the public CA certificate to the selected file.")?;
    Ok(Some(destination.to_string_lossy().into_owned()))
}

#[tauri::command]
fn tls_trust_check_status(
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
) -> TlsTrustCheckStatus {
    trust_check.status()
}

#[tauri::command]
async fn tls_inspection_preflight(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    ca: tauri::State<'_, Arc<CaManager>>,
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
) -> Result<TlsInspectionPreflight, String> {
    let proxy_status = engine.snapshot().status;
    let ca = ca.inner().clone();
    let ca_status = tauri::async_runtime::spawn_blocking(move || ca.status())
        .await
        .map_err(|_| "TLS inspection preflight worker failed.".to_string())??;
    Ok(trust_check.preflight(&ca_status, &proxy_status))
}

#[tauri::command]
async fn start_tls_trust_check(
    ca: tauri::State<'_, Arc<CaManager>>,
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
    client_id: String,
    client_name: String,
) -> Result<TlsTrustCheckStatus, String> {
    let client = TlsClientIdentity::new(&client_id, &client_name)?;
    let ca = ca.inner().clone();
    let leaf = tauri::async_runtime::spawn_blocking(move || {
        ca.issue_leaf("localhost", DestinationClass::Development)
    })
    .await
    .map_err(|_| "TLS trust-check certificate worker failed.".to_string())??;
    trust_check
        .start(leaf, client, Duration::from_secs(60))
        .await
}

#[tauri::command]
async fn cancel_tls_trust_check(
    trust_check: tauri::State<'_, Arc<TlsTrustCheckManager>>,
) -> Result<TlsTrustCheckStatus, String> {
    Ok(trust_check.cancel().await)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(ProxyEngine::default()))
        .manage(Arc::new(CaManager::default()))
        .manage(Arc::new(TlsTrustCheckManager::default()))
        .setup(|app| {
            let handle = app.handle().clone();
            let engine = app.state::<Arc<ProxyEngine>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                let mut revision = engine.revision();
                loop {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let latest = engine.revision();
                    if latest != revision {
                        revision = latest;
                        let _ = handle.emit("engine-changed", revision);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engine_snapshot,
            start_proxy,
            test_proxy_connection,
            stop_proxy,
            clear_traffic,
            replay_capture,
            request_body_page,
            search_request_body,
            request_json_view,
            request_json_page,
            body_export_preview,
            export_body,
            ca_status,
            generate_local_ca,
            remove_local_ca,
            export_local_ca,
            tls_trust_check_status,
            tls_inspection_preflight,
            start_tls_trust_check,
            cancel_tls_trust_check,
            response_body_page,
            search_response_body,
            response_json_view,
            response_json_page,
            resolve_response_breakpoint
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Sippin Soda desktop")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                let engine = app.state::<Arc<ProxyEngine>>();
                let trust_check = app.state::<Arc<TlsTrustCheckManager>>();
                tauri::async_runtime::block_on(engine.stop());
                tauri::async_runtime::block_on(trust_check.cancel());
                engine.clear();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn connection_check_traverses_the_running_proxy() {
        let engine = ProxyEngine::default();
        let port = available_port();
        engine
            .start(ProxyConfig {
                port,
                ..Default::default()
            })
            .await
            .unwrap();

        let result = run_proxy_connection_check(&engine, None, None)
            .await
            .unwrap();

        assert_eq!(result.proxy_address, format!("127.0.0.1:{port}"));
        assert_eq!(result.http_status, 204);
        assert!(engine
            .snapshot()
            .traffic
            .iter()
            .any(|capture| capture.target.contains("/__sippin_connection_check")));
        engine.stop().await;
    }

    #[tokio::test]
    async fn connection_check_uses_the_ephemeral_client_credential() {
        let engine = ProxyEngine::default();
        let port = available_port();
        let profile = "first-run-client";
        let token = "temporary-connection-check-token";
        engine
            .start(ProxyConfig {
                port,
                client_auth: Some(ProxyClientAuth::new(profile, token).unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();

        let result =
            run_proxy_connection_check(&engine, Some(profile.to_string()), Some(token.to_string()))
                .await
                .unwrap();

        assert_eq!(result.http_status, 204);
        assert!(engine
            .snapshot()
            .traffic
            .iter()
            .any(|capture| capture.client_profile_id.as_deref() == Some(profile)));
        engine.stop().await;
    }

    #[test]
    fn connection_check_rejects_invalid_status_lines() {
        assert_eq!(
            response_status(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap(),
            204
        );
        assert!(response_status(b"not-http\r\n\r\n").is_err());
    }
}
