#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sippin_soda_engine::{BodyPage, JsonStatus, ProxyConfig, ProxyEngine, SearchStep, Snapshot};
use std::{sync::Arc, time::Duration};
use tauri::{Emitter, Manager};

#[tauri::command]
fn engine_snapshot(engine: tauri::State<'_, Arc<ProxyEngine>>) -> Snapshot {
    engine.snapshot()
}

#[tauri::command]
async fn start_proxy(
    engine: tauri::State<'_, Arc<ProxyEngine>>,
    port: u16,
    capture_bodies: bool,
    disk_budget_gib: u32,
) -> Result<Snapshot, String> {
    if !(1..=1024).contains(&disk_budget_gib) {
        return Err("Disk budget must be between 1 and 1024 GiB.".into());
    }
    engine
        .start(ProxyConfig {
            port,
            capture_response_bodies: capture_bodies,
            body_disk_budget: u64::from(disk_budget_gib) * 1024 * 1024 * 1024,
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

fn main() {
    tauri::Builder::default()
        .manage(Arc::new(ProxyEngine::default()))
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
                tauri::async_runtime::block_on(engine.stop());
                engine.clear();
            }
        });
}
