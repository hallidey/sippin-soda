#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use sippin_soda_engine::{
    BodyExportPreview, BodyPage, CaManager, CaStatus, DestinationClass, JsonStatus,
    ProxyClientAuth, ProxyConfig, ProxyEngine, ProxyTlsInterception, SearchStep, Snapshot,
    TlsClientIdentity, TlsInspectionPreflight, TlsTrustCheckManager, TlsTrustCheckStatus,
};
use std::{sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

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
            ..Default::default()
        })
        .await
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
            stop_proxy,
            clear_traffic,
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
            response_json_page
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
