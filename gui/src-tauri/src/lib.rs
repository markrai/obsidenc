mod obsidenc_ipc;

use obsidenc_ipc::{decrypt_vault, encrypt_vault, ObsidencState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(ObsidencState::default())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![encrypt_vault, decrypt_vault])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
