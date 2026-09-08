#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sippin_soda_engine::{ProxyConfig, ProxyEngine, Snapshot};
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
) -> Result<Snapshot, String> {
    engine
        .start(ProxyConfig {
            port,
            ..Default::default()
        })
        .await
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
            clear_traffic
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Sippin Soda desktop")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                let engine = app.state::<Arc<ProxyEngine>>();
                tauri::async_runtime::block_on(engine.stop());
            }
        });
}
