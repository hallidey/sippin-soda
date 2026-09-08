#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[tauri::command]
fn engine_status() -> sippin_soda_engine::EngineStatus {
    sippin_soda_engine::EngineStatus::default()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![engine_status])
        .run(tauri::generate_context!())
        .expect("failed to run Sippin Soda desktop");
}
