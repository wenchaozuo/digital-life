mod storage;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let storage = storage::StorageService::initialize(app.handle())
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(storage);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            storage::initialize_storage,
            storage::save_life_identity,
            storage::get_current_life_identity,
            storage::get_life_identity,
            storage::update_life_identity_base_info,
            storage::save_persona_template,
            storage::get_persona_template,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
